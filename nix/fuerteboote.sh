# fuerteboote: key setup, integrity checks and signing around nixpkgs' install-grub.pl.
#
# Trust model: everything GRUB reads from /boot gets a detached GPG signature
# (GRUB runs with check_signatures=enforce), and everything the firmware loads
# (GRUB itself, kernels) gets an Authenticode signature from the sbctl db key.
# We only sign content we can trace back to the Nix store or that
# install-grub.pl rewrote during this run; anything else is restored first.

STATE=/var/lib/fuerteboote
export GNUPGHOME=$STATE/gnupg
PUBKEY=$STATE/pubkey.gpg
MANIFEST=$STATE/signed-kernels
DB_CERT=/var/lib/sbctl/keys/db/db.pem

shopt -s nullglob

log() { echo "fuerteboote: $*" >&2; }
die() {
  log "error: $*"
  exit 1
}

sb_signed() { sbverify --cert "$DB_CERT" "$1" >/dev/null 2>&1; }

ensure_keys() {
  if [[ ! -e $DB_CERT ]]; then
    [[ ${GSB_AUTO_GENERATE_KEYS:-0} == 1 ]] ||
      die "no Secure Boot keys found ($DB_CERT). Run 'sbctl create-keys' or set boot.loader.grub.secureBoot.autoGenerateKeys = true."
    log "generating Secure Boot keys with sbctl"
    sbctl create-keys
    [[ -e $DB_CERT ]] || die "sbctl create-keys did not create $DB_CERT"
  fi
  if [[ ! -s $PUBKEY ]]; then
    log "generating the GRUB GPG signing key"
    install -d -m 700 "$STATE" "$GNUPGHOME"
    # GRUB only verifies RSA/DSA. No passphrase: signing runs unattended on every rebuild.
    gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
      --quick-gen-key "GRUB Secure Boot ($(uname -n)) <root@localhost>" rsa4096 sign never
    gpg --batch --export >"$PUBKEY.tmp"
    mv "$PUBKEY.tmp" "$PUBKEY"
  fi
}

# prepare BOOT_PATH EFI_BINARY...
# Runs inside install-grub.pl before grub-install. Forces a fresh grub-install
# when the installed GRUB image is not ours, so we never sign a foreign binary.
cmd_prepare() {
  local boot=$1 efi reinstall=0
  shift
  ensure_keys
  cmp -s "$PUBKEY" "$boot/grub/secureboot-pubkey.gpg" || reinstall=1
  for efi in "$@"; do
    sb_signed "$efi" || reinstall=1
  done
  if ((reinstall)); then
    log "forcing grub-install for $boot"
    rm -f "$boot/grub/state"
  fi
}

TO_SIGN=()

# Copy SRC over DST when they differ (DST was modified outside of NixOS).
restore() {
  if ! cmp -s "$1" "$2"; then
    log "warning: $2 does not match $1, restoring it"
    cp "$1" "$2.tmp"
    mv "$2.tmp" "$2"
  fi
}

# Sign unsigned PE images (e.g. memtest86 from extraFiles) so the firmware accepts them.
sb_sign_if_unsigned_pe() {
  [[ $(head -c2 "$1") == MZ ]] || return 0
  if sbverify --list "$1" 2>&1 | grep -q 'No signature table'; then
    sbctl sign "$1" >/dev/null
  fi
}

collect_kernels() {
  local boot=$1 toplevel=$2 sys s k p name f src hash
  declare -A src_of kind_of
  for sys in "$toplevel" /nix/var/nix/profiles/system-*-link /nix/var/nix/profiles/system-profiles/*-link; do
    for s in "$sys" "$sys"/specialisation/*; do
      for k in kernel initrd xen.gz; do
        [[ -e $s/$k ]] || continue
        p=$(readlink -f "$s/$k")
        # Same naming as copyToKernelsDir in install-grub.pl.
        name=${p#/nix/store/}
        name=${name//\//-}
        src_of[$name]=$p
        kind_of[$name]=$k
      done
    done
  done

  local manifest_new=$MANIFEST.new
  : >"$manifest_new"
  for f in "$boot"/kernels/*; do
    name=${f##*/}
    case $name in *.sig | *.tmp) continue ;; esac
    if [[ $name == *-secrets ]]; then
      # install-grub.pl regenerates initrd secrets on every run.
      TO_SIGN+=("$f")
      continue
    fi
    src=${src_of[$name]:-}
    [[ -n $src ]] || die "$f does not belong to any system generation, refusing to sign it"
    if [[ ${kind_of[$name]} == kernel ]]; then
      hash=$(sha256sum <"$f" | cut -d' ' -f1)
      # Ours and signed with the current db key (the key may have been rotated).
      if ! grep -qxF "$hash $name" "$MANIFEST" 2>/dev/null || ! sb_signed "$f"; then
        sbctl sign -o "$f.tmp" "$src" >/dev/null
        mv "$f.tmp" "$f"
        hash=$(sha256sum <"$f" | cut -d' ' -f1)
      fi
      echo "$hash $name" >>"$manifest_new"
    else
      restore "$src" "$f"
    fi
    TO_SIGN+=("$f")
  done
  mv "$manifest_new" "$MANIFEST"
}

# GRUB modules, fonts and translations must be byte-identical to the GRUB package.
collect_grub_files() {
  local boot=$1 libdir=$2 share=$3 f src lang
  for f in "$boot/grub/${libdir##*/}"/*; do
    src=$libdir/${f##*/}
    # core.efi, load.cfg and *.sig have no counterpart; GRUB never reads them at runtime.
    [[ -e $src ]] || continue
    restore "$src" "$f"
    TO_SIGN+=("$f")
  done
  for f in "$boot"/grub/fonts/*.pf2; do
    src=$share/${f##*/}
    [[ -e $src ]] || continue
    restore "$src" "$f"
    TO_SIGN+=("$f")
  done
  for f in "$boot"/grub/locale/*.mo; do
    lang=${f##*/}
    lang=${lang%.mo}
    src=$share/../locale/$lang/LC_MESSAGES/grub.mo
    [[ -e $src ]] || continue
    restore "$src" "$f"
    TO_SIGN+=("$f")
  done
}

# EFI binaries on the ESP (Windows Boot Manager, other loaders) chainloaded by
# os-prober entries. The firmware checks their Authenticode signature at
# LoadImage; GRUB's check_signatures additionally requires a detached .sig.
collect_esp() {
  local esp=$1 f
  [[ -d $esp/EFI ]] || return 0
  while IFS= read -r -d '' f; do
    TO_SIGN+=("$f")
  done < <(find "$esp/EFI" -type f -iname '*.efi' -print0)
}

gpg_sign_all() {
  local f
  for f in "${TO_SIGN[@]}"; do
    gpg --batch --yes --quiet --digest-algo SHA256 --detach-sign -o "$f.sig.tmp" "$f"
    mv "$f.sig.tmp" "$f.sig"
  done
}

# Remove signatures whose file is gone or that we did not produce in this run.
prune_sigs() {
  local f
  declare -A keep
  for f in "${TO_SIGN[@]}"; do keep[$f.sig]=1; done
  while IFS= read -r -d '' f; do
    [[ -n ${keep[$f]:-} ]] || rm -f "$f"
  done < <(find "$@" -type f -name '*.sig' -print0 2>/dev/null)
}

# sign BOOT_PATH ESP GRUB_LIBDIR GRUB_SHAREDIR TOPLEVEL EFI_BINARY...
# Runs after install-grub.pl. Extra files (relative to the ESP) come from $GSB_EXTRA_FILES.
cmd_sign() {
  local boot=$1 esp=$2 libdir=$3 share=$4 toplevel=${5:-/nix/var/nix/profiles/system} f
  shift 5
  [[ -s $PUBKEY ]] || die "missing $PUBKEY"

  for f in "$@"; do
    [[ -e $f ]] || die "GRUB image $f not found"
    # cmd_prepare forced a reinstall if it was not ours, so an unsigned image is fresh from grub-install.
    sb_signed "$f" || sbctl sign "$f" >/dev/null
    sb_signed "$f" || die "failed to sign $f"
  done

  collect_kernels "$boot" "$toplevel"
  collect_grub_files "$boot" "$libdir" "$share"

  # Files install-grub.pl rewrites from the Nix store on every run.
  local cfg=$boot/grub/grub.cfg
  [[ -e $cfg ]] || die "$cfg not found"
  # grubenv changes at runtime (savedefault, grub-reboot) so it cannot carry a
  # signature: read it unsigned, but only the variables the NixOS menu uses.
  # shellcheck disable=SC2016 # literal GRUB script, not shell expansions
  sed -i -E \
    -e 's|if \[ -s \$prefix/grubenv \]; then|if true; then|' \
    -e 's|^([[:space:]]*)load_env[[:space:]]*$|\1load_env --skip-sig saved_entry next_entry|' \
    "$cfg"
  # With --disable-cli, GRUB denies every entry that is not --unrestricted, before
  # even asking for a password (normal/auth.c). NixOS leaves specialisations, older
  # generations and os-prober/extra entries restricted, so unlock them all.
  sed -i -E '/--unrestricted/! s/^([[:space:]]*)(menuentry|submenu)([[:space:]])/\1\2 --unrestricted\3/' "$cfg"
  TO_SIGN+=("$cfg")
  for f in "$boot"/background.* "$boot/converted-font.pf2"; do
    [[ $f == *.sig || ! -e $f ]] || TO_SIGN+=("$f")
  done
  if [[ -d $boot/theme ]]; then
    while IFS= read -r -d '' f; do TO_SIGN+=("$f"); done < <(find "$boot/theme" -type f ! -name '*.sig' -print0)
  fi

  local rel
  while IFS= read -r rel; do
    [[ -n $rel && -e $esp/$rel ]] || continue
    sb_sign_if_unsigned_pe "$esp/$rel"
    TO_SIGN+=("$esp/$rel")
  done <<<"${GSB_EXTRA_FILES:-}"

  collect_esp "$esp"

  gpg_sign_all
  prune_sigs "$boot/grub" "$boot/kernels" "$boot/theme" "$esp/EFI"
  find "$boot" "$esp" -maxdepth 1 -type f -name '*.sig' -print0 | while IFS= read -r -d '' f; do
    [[ -e ${f%.sig} ]] || rm -f "$f"
  done
  cp "$PUBKEY" "$boot/grub/secureboot-pubkey.gpg"
  sync
  log "signed ${#TO_SIGN[@]} files in $boot"
}

# sign-esp ESP: re-sign ESP EFI binaries (e.g. after a Windows update replaced bootmgfw.efi).
cmd_sign_esp() {
  local f
  collect_esp "$1"
  for f in "${TO_SIGN[@]}"; do
    gpg --batch --quiet --verify "$f.sig" "$f" 2>/dev/null && continue
    log "re-signing $f"
    gpg --batch --yes --quiet --digest-algo SHA256 --detach-sign -o "$f.sig.tmp" "$f"
    mv "$f.sig.tmp" "$f.sig"
  done
}

# enroll SBCTL_ARGS...: enroll keys if the firmware is in Setup Mode.
cmd_enroll() {
  local var=/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c
  if [[ ! -e $var ]]; then
    log "no EFI variables available, skipping key enrollment"
    return 0
  fi
  # 4 bytes of attributes, then the value.
  if [[ $(od -An -t u1 -j 4 -N 1 "$var" | tr -d ' ') != 1 ]]; then
    log "firmware is not in Setup Mode, skipping key enrollment"
    return 0
  fi
  log "enrolling Secure Boot keys: sbctl enroll-keys $*"
  sbctl enroll-keys "$@"
}

# check-enrolled: warn when Secure Boot is on but our db certificate is not in the
# firmware's db, i.e. the next boot would refuse GRUB (first activation on a machine
# that already runs Secure Boot with only the vendor keys).
cmd_check_enrolled() {
  local efi=/sys/firmware/efi/efivars
  local sb=$efi/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
  local db=$efi/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
  [[ -e $sb && $(od -An -t u1 -j 4 -N 1 "$sb" | tr -d ' ') == 1 ]] || return 0
  local cert
  cert=$(openssl x509 -in "$DB_CERT" -outform DER | od -An -v -t x1 | tr -d ' \n')
  if [[ ! -e $db || $(od -An -v -t x1 "$db" | tr -d ' \n') != *"$cert"* ]]; then
    log "WARNING: Secure Boot is enabled but your db key ($DB_CERT) is not enrolled in the firmware."
    log "WARNING: the firmware will refuse to start GRUB at the next boot. Before rebooting, either"
    log "WARNING: enroll the keys (firmware Setup Mode, then 'sbctl enroll-keys --microsoft') or disable Secure Boot."
  fi
}

cmd=${1:-}
shift || true
case $cmd in
  prepare) cmd_prepare "$@" ;;
  sign) cmd_sign "$@" ;;
  sign-esp) cmd_sign_esp "$@" ;;
  enroll) cmd_enroll "$@" ;;
  check-enrolled) cmd_check_enrolled ;;
  *) die "usage: fuerteboote {prepare|sign|sign-esp|enroll|check-enrolled} ..." ;;
esac
