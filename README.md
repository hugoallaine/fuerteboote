# fuerteboote

UEFI Secure Boot for **GRUB** on NixOS: keep your GRUB themes, fonts, os-prober
and the rest of `boot.loader.grub.*`, with the whole boot chain verified.

*Fuerte* is Spanish for "strong", a nod to its systemd-boot cousin
[lanzaboote](https://github.com/nix-community/lanzaboote).

## Supported versions

| Component | Supported | Notes |
|---|---|---|
| GRUB | **≥ 2.14** | `--disable-cli` is required for security and only exists since 2.14; older versions are rejected at evaluation time. |
| NixOS / nixpkgs | **nixos-unstable** (26.11 pre-release, tested 2026-11-07), NixOS ≥ 26.11 | NixOS 25.11 and 26.05 ship GRUB 2.12. On 26.05, taking GRUB from unstable works (same `install-grub.pl`): `nixpkgs.overlays = [ (_: _: { grub2 = pkgs-unstable.grub2; }) ];` |
| sbctl | 0.18 (tested) | Keys in `/var/lib/sbctl`. |
| Platform | x86_64 UEFI (tested) | i386-efi and arm64-efi are wired but untested. BIOS boot is not supported. |
| Real hardware | 1 x86_64 UEFI laptop (2026-11-09) | NixOS 26.05 + GRUB 2.14 from unstable, automatic enrollment with `--microsoft`, os-prober dual boot with Windows, minegrub-world-sel theme, older generations, `fwsetup` entry. |

## Usage

```nix
# flake.nix
inputs.fuerteboote.url = "github:hugoallaine/fuerteboote";

# configuration.nix
imports = [ inputs.fuerteboote.nixosModules.default ];
boot.loader.grub.secureBoot.enable = true;
# Optional: enroll the keys automatically when the firmware is in Setup Mode.
boot.loader.grub.secureBoot.autoEnrollKeys.enable = true;
```

Requires `boot.loader.grub.efiSupport = true` and `boot.loader.grub.device = "nodev"`.

### First activation

1. `nixos-rebuild switch`: generates the keys (sbctl + a GPG key) and signs everything.
2. Enroll the keys:
   - automatic: set `autoEnrollKeys.enable = true`, put the firmware in Setup Mode, rebuild;
   - manual: put the firmware in Setup Mode, run `sudo sbctl enroll-keys --microsoft`.
3. Reboot and enable Secure Boot in the firmware if it is not already on.

If Secure Boot is already enabled when you activate the module (e.g. a machine that
came with Windows), do not reboot before step 2: the firmware does not know your key
yet and would refuse GRUB. Every rebuild prints a warning in that situation.

Keep `--microsoft` (the default of `autoEnrollKeys.extraArgs`): GPU and NIC option
ROMs and Windows are signed by Microsoft; enrolling without it can leave you without
display or unbootable.

### Options

| Option | Default | |
|---|---|---|
| `secureBoot.enable` | `false` | |
| `secureBoot.autoGenerateKeys` | `true` | Run `sbctl create-keys` on first install if no keys exist. Never enrolls. |
| `secureBoot.autoEnrollKeys.enable` | `false` | Enroll on rebuild when the firmware is in Setup Mode. |
| `secureBoot.autoEnrollKeys.extraArgs` | `[ "--microsoft" ]` | Passed to `sbctl enroll-keys`. |

## How it works

The module plugs into the stock nixpkgs GRUB installer (`install-grub.pl`) through
`extraGrubInstallArgs`, `extraPrepareConfig` and `extraInstallCommands`, so every
GRUB option NixOS generates keeps working: themes, fonts, splash, os-prober,
specialisations, older generations, initrd secrets, `extraEntries`, `extraFiles`,
`savedefault`, `grub-reboot`, removable installs.

| What | Verified by | Signed with |
|---|---|---|
| GRUB EFI image | firmware (db) | sbctl db key |
| Kernel | firmware (db: GRUB ≥ 2.12 boots kernels through `LoadImage`) | sbctl db key |
| PE images in `extraFiles` (e.g. memtest86+) | firmware (db) | sbctl db key, if not already signed |
| grub.cfg, initrds, initrd secrets, theme, fonts, modules, locales | GRUB `check_signatures=enforce` | GPG key embedded in the GRUB image |
| Chainloaded EFI (Windows via os-prober) | firmware (db) **and** GRUB GPG | vendor + GPG key |

Details:

- GRUB is installed with `pgp gcry_rsa gcry_sha256 gcry_sha512` built in, the GPG
  public key embedded (`--pubkey`), `--disable-shim-lock` (no shim) and `--disable-cli`.
- **The GRUB shell and entry editor are always disabled.** `check_signatures` can be
  switched off from the shell, and a GRUB password does not help: `superusers` is
  defined in `grub.cfg`, so a tampered `grub.cfg` fails to load and leaves an
  unauthenticated shell. For the same reason `boot.loader.grub.users` is rejected.
- With `--disable-cli`, GRUB 2.14 refuses every menu entry that is not `--unrestricted`.
  The module adds `--unrestricted` to all entries of the generated `grub.cfg`
  (specialisations, "All configurations", os-prober, `extraEntries`) before signing it.
- Files are only signed when they can be traced to the Nix store or were rewritten by
  the installer during the same run. Kernels, initrds and GRUB modules modified on
  `/boot` are restored from the store before signing; a GRUB image not signed by
  your key triggers a fresh `grub-install`.
- `grubenv` changes at runtime and cannot be signed: it is read with
  `load_env --skip-sig saved_entry next_entry`, i.e. only those two variables, which
  can only select an existing (signed) entry.
- With `useOSProber`, a boot-time service re-signs the EFI binaries of the ESP, so a
  Windows update that replaces `bootmgfw.efi` does not break the Windows entry.
- Keys: `/var/lib/sbctl` (Secure Boot, sbctl) and `/var/lib/fuerteboote` (GPG,
  RSA 4096, no passphrase because signing runs unattended). Both root only.
  If the GPG key is lost, a new one is generated and GRUB is reinstalled with it.

### Why RSA and not Ed25519/ECDSA?

GRUB's detached-signature verifier (`grub-core/commands/pgp.c`, GRUB 2.14) only knows
OpenPGP algorithms 1/3 (RSA) and 17 (DSA). There is no ECC support upstream.
It is not a performance problem: GRUB only verifies the files it reads at boot, and
RSA verification is as fast as ECDSA (OpenSSL on the test machine: RSA-4096 verify
42 µs, ECDSA P-256 verify 44 µs). Signing about 400 files takes about 1 s per rebuild.
The Secure Boot keys (db/KEK/PK) are sbctl's and independent of this choice.

## Security

### Threat model

This module protects against someone with access to the machine **while it is off**
(stolen laptop, "evil maid", disk taken out) who modifies what boots: GRUB, its
configuration, modules, theme, kernels, initrds. With the checklist below, such changes
stop the boot instead of running.

It does **not** protect against:

- an attacker who is already root on the running system (they can read the keys and sign anything);
- firmware vulnerabilities, DMA attacks, hardware implants;
- anything the checklist leaves out (an unencrypted disk alone defeats it, see
  the `limit-unencrypted-root` test).

### Checklist for real protection

Secure Boot is only as strong as its weakest step. All of these are needed:

1. **Encrypt the root filesystem** (LUKS2: `boot.initrd.luks.devices`), and swap.
   Without it, the Nix store and the signing keys can be modified or copied from the
   disk. The module prints a warning when no encrypted root is configured.
   Tested: `luks-root` (works with LUKS), `limit-unencrypted-root` (without it, a
   modified store runs at boot).
2. **Set a firmware (UEFI) administrator password.** Otherwise anyone can disable
   Secure Boot, reset the keys or boot from a USB stick in the firmware setup. If the
   firmware allows it, also disable booting from external devices.
3. **Use keys that never signed anything else.** The firmware accepts *any* binary
   signed with your db key, forever. If the key comes from an earlier sbctl, lanzaboote
   or hand-signing setup, an old signed bootloader that does not check signatures (a
   plain GRUB, an old systemd-boot) can be put back on the ESP and bypass everything.
   `sbctl list-files` shows what sbctl itself signed. When in doubt, rotate:

   ```sh
   sudo sbctl rotate-keys            # new PK/KEK/db, enrolled without Setup Mode;
                                     # Microsoft/OEM entries are kept, the old sbctl
                                     # certificate is removed from the firmware
   sudo rm -rf /var/tmp/sbctl        # rotate-keys backs the OLD private keys up here
   sudo nixos-rebuild boot           # re-signs GRUB and every kernel with the new key
   sudo reboot
   sudo sbctl status                 # Secure Boot: ✓ Enabled
   ```

   Tested: `db-key-rotation` (rotation with Secure Boot on, rebuild, reboot, and the
   previous GRUB image signed with the old key is refused by the firmware). On a new
   install, the keys created by `autoGenerateKeys` are fresh.
4. **Protect and back up the keys.** `/var/lib/sbctl` (Secure Boot) and
   `/var/lib/fuerteboote` (GPG) are root-only on the encrypted root. Keep an
   encrypted offline backup of `/var/lib/sbctl` (losing it means re-enrolling new keys);
   never put them in a Git repository or the Nix store.
5. **Keep the revocation list (dbx) up to date**: `services.fwupd.enable = true`, then
   `fwupdmgr update`. The module signs fwupd's EFI binary so capsule updates keep
   working (tested: `fwupd`). Keep the Microsoft certificates (`--microsoft`, the
   default) unless you know your hardware does not need them.
6. **Update NixOS regularly.** The module uses the GRUB of *your* nixpkgs: GRUB security
   fixes reach you through `nixos-rebuild` with an updated nixpkgs.
7. **Avoid `boot.initrd.secrets` for anything sensitive.** They are written next to the
   kernels on `/boot` (the ESP, unencrypted): signed, but readable by anyone with the disk.
8. **TPM2 auto-unlock** (`systemd-cryptenroll`), if you use it: bind to PCR 7 and add a
   PIN (`--tpm2-with-pin=yes`). Not tested with this module.
9. Optional: remove old generations (`nix-collect-garbage -d`) to retire old kernels; they
   stay signed and bootable otherwise.
10. **Check the result** after rebooting: `sbctl status` must show
    `Secure Boot: ✓ Enabled` and `Setup Mode: ✓ Disabled`.

## Tested

Every scenario below is a NixOS VM test (QEMU + OVMF with Secure Boot, KVM) run by
`nix flake check`:

| Test | Scenario |
|---|---|
| `auto-enroll` | Keys generated and enrolled during the first install, boot with Secure Boot enforced, graphical theme, initrd secrets, every file on `/boot` signed, idempotent rebuilds (also with `NIXOS_INSTALL_BOOTLOADER=1`), a specialisation booted once through `next_entry` (`grub-reboot`) then back to the default |
| `manual-enroll` | Keys generated, not enrolled; `sbctl enroll-keys --microsoft` by hand; reboot with Secure Boot enforced |
| `removable` | `efiInstallAsRemovable`, no NVRAM entry, firmware boots `\EFI\BOOT\BOOTX64.EFI` |
| `os-prober` | os-prober detects a "Windows Boot Manager" (the EDK2 shell signed with db), its GPG signature is invalidated (Windows update) and restored by the boot service, GRUB chainloads it; an EFI binary not signed for the firmware is refused |
| `savedefault-rollback` | `default = "saved"`, `savedefault` writes `grubenv`, an entry of "All configurations" (older generation) boots, a bogus `next_entry` falls back to the default |
| `memtest` | `boot.loader.grub.memtest86` (`extraFiles` PE image) is signed for the firmware and GPG, GRUB starts it and memtest86+ code runs |
| `self-heal` | Kernel, initrd and a GRUB module modified on `/boot`, rebuild restores them, reboot works |
| `key-rotation` | GPG key deleted, rebuild generates a new one and reinstalls GRUB, reboot works |
| `db-key-rotation` | A rebuild warns when Secure Boot is on but the db key is not enrolled (the next boot would fail); `sbctl rotate-keys` with Secure Boot on, rebuild re-signs GRUB and kernels, reboot works, a GRUB signed with the old key is refused |
| `tamper-grub-cfg` | `set check_signatures=no` appended to `grub.cfg`: no userspace starts |
| `tamper-initrd` | Modified initrd: rejected, no userspace starts |
| `tamper-module` | Modified `normal.mod`: no userspace starts |
| `tamper-kernel-unsigned` | Kernel without Authenticode signature but with a valid GPG signature: refused by the firmware |
| `tamper-grub-unsigned` | GRUB image without Authenticode signature: refused by the firmware |
| `luks-root` | Root on LUKS, passphrase in the initrd, Secure Boot enforced |
| `limit-unencrypted-root` | Documents the main limit: with an unencrypted root, a modified Nix store runs at boot |
| `fwupd` | fwupd's EFI capsule loader is signed with the db key |
| `eval-*` | Valid configuration evaluates; GRUB 2.12, `boot.loader.grub.users`, `check_signatures` in the GRUB config, BIOS device and `efiSupport = false` are rejected; the "no encrypted root" warning appears without LUKS and not with it |

Continuous integration (`.github/workflows/`): every push runs each check in its own
job on GitHub's free runners (KVM enabled), and a daily job moves the test pin to the
latest nixos-unstable, runs everything, commits the update only if all tests pass, and
opens an issue otherwise.

```sh
nix flake check -L                                   # everything
nix build .#checks.x86_64-linux.os-prober -L         # one test
```

## Limits

- **Encrypt your root filesystem** (see [Security](#security)). Secure Boot protects
  `/boot`; the Nix store on disk is not verified, and the kernel command line points
  into it (`init=/nix/store/...`).
- **No GRUB shell, no entry editor, no GRUB users.** Recovery goes through the firmware
  boot menu or a USB stick.
- Rollback: older generations stay signed and bootable (same as lanzaboote).
- Microsoft keys: anything signed by Microsoft (e.g. other distributions' shim) can be
  booted from the firmware menu or an os-prober entry; that is how Secure Boot with the
  Microsoft CA works, not something this module adds.
- os-prober: Windows works. Other Linux distributions found by os-prober boot their own
  kernels, which are not signed with your db key, so those entries are refused; chainload
  their `shimx64.efi` with `extraEntries` instead (not tested).
- `extraEntries` that load files outside of `/boot`, or files not listed in `extraFiles`,
  have no signature and are refused.
- The kernel is not put in lockdown mode: NixOS kernel modules are not signed.
- memtest86+ 8.10 starts but then page-faults on OVMF (QEMU), **with or without**
  Secure Boot (checked with a control VM without this module): an upstream issue, not
  a signing one. Not checked on real hardware.
- Not tested: `/boot` separate from the ESP (`efiSysMountPoint`), mirrored boots, ZFS
  `/boot`, encrypted `/boot` (`enableCryptodisk`), an actual fwupd capsule update (only
  the signing is tested), TPM2 unlocking, real hardware.
- The module relies on details of nixpkgs' `install-grub.pl` (`/boot/kernels` layout,
  `load_env` lines, EFI binary path). A nixpkgs change there breaks it; the VM tests
  catch that.
