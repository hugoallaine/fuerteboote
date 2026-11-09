{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkOption
    types
    ;

  cfg = config.boot.loader.grub;
  sb = cfg.secureBoot;
  state = "/var/lib/fuerteboote";

  # Must be the same derivation grub.nix hands to install-grub.pl, so that the
  # modules installed in /boot can be compared byte for byte.
  realGrub =
    if cfg.zfsSupport then
      pkgs.grub2.override {
        zfsSupport = true;
        zfs = cfg.zfsPackage;
      }
    else
      pkgs.grub2;
  grubEfi = realGrub.override { efiSupport = true; };
  target = grubEfi.grubTarget;

  efiNames =
    {
      "x86_64-efi" = {
        grub = "grubx64.efi";
        removable = "BOOTX64.EFI";
      };
      "i386-efi" = {
        grub = "grubia32.efi";
        removable = "BOOTIA32.EFI";
      };
      "arm64-efi" = {
        grub = "grubaa64.efi";
        removable = "BOOTAA64.EFI";
      };
    }
    .${target} or (throw "fuerteboote: unsupported GRUB target ${target}");

  # Mirrors the ESP / bootloader-id logic of grub.nix for each mirrored boot.
  boots = map (
    args:
    let
      esp = if args.efiSysMountPoint == null then args.path else args.efiSysMountPoint;
      bootloaderId =
        if args.efiBootloaderId == null then
          "${config.system.nixos.distroName}${lib.replaceStrings [ "/" ] [ "-" ] esp}"
        else
          args.efiBootloaderId;
    in
    {
      inherit (args) path;
      inherit esp;
      efiBinary =
        if cfg.efiInstallAsRemovable then
          "${esp}/EFI/BOOT/${efiNames.removable}"
        else
          "${esp}/EFI/${bootloaderId}/${efiNames.grub}";
    }
  ) cfg.mirroredBoots;

  efiBinaries = lib.escapeShellArgs (map (b: b.efiBinary) boots);

  tool = pkgs.writeShellApplication {
    name = "fuerteboote";
    runtimeInputs = with pkgs; [
      coreutils
      diffutils
      findutils
      gnugrep
      gnupg
      gnused
      openssl
      sbctl
      sbsigntool
    ];
    text = builtins.readFile ./fuerteboote.sh;
  };
in
{
  options.boot.loader.grub.secureBoot = {
    enable = mkEnableOption ''
      UEFI Secure Boot for GRUB. GRUB is signed with your sbctl keys, kernels are
      signed for the firmware, and GRUB verifies a detached GPG signature for
      every file it reads (config, initrds, theme, fonts, modules)
    '';

    autoGenerateKeys = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Create Secure Boot keys with {command}`sbctl create-keys` on the first
        bootloader installation if none exist. This does not enroll them in the
        firmware; see {option}`boot.loader.grub.secureBoot.autoEnrollKeys.enable`
        or run {command}`sbctl enroll-keys --microsoft` yourself in Setup Mode.
      '';
    };

    autoEnrollKeys = {
      enable = mkEnableOption ''
        enrolling the keys automatically when the firmware is in Setup Mode.
        Enrolling keys without the Microsoft certificates can make machines whose
        option ROMs (e.g. GPUs) are signed by Microsoft unbootable; keep
        `--microsoft` in {option}`extraArgs` unless you know what you are doing
      '';
      extraArgs = mkOption {
        type = types.listOf types.str;
        default = [ "--microsoft" ];
        example = [
          "--microsoft"
          "--firmware-builtin"
        ];
        description = "Arguments passed to {command}`sbctl enroll-keys`.";
      };
    };
  };

  config = mkIf (cfg.enable && sb.enable) {
    assertions = [
      {
        assertion = cfg.efiSupport;
        message = "boot.loader.grub.secureBoot requires boot.loader.grub.efiSupport = true.";
      }
      {
        assertion = lib.all (b: b.devices == [ "nodev" ]) cfg.mirroredBoots;
        message = ''boot.loader.grub.secureBoot is UEFI only: set boot.loader.grub.device = "nodev".'';
      }
      {
        # --disable-cli appeared in GRUB 2.14; without it the GRUB shell can turn
        # check_signatures off (see the comment on extraGrubInstallArgs).
        assertion = lib.versionAtLeast grubEfi.version "2.14";
        message = "boot.loader.grub.secureBoot requires GRUB >= 2.14 (nixpkgs has ${grubEfi.version}); use nixos-unstable or NixOS >= 26.11.";
      }
      {
        # --disable-cli makes GRUB refuse any authentication, so users can never log in.
        assertion = cfg.users == { };
        message = "boot.loader.grub.secureBoot is incompatible with boot.loader.grub.users: the GRUB shell and editor are always disabled, and GRUB cannot authenticate users in that mode.";
      }
      {
        assertion = !cfg.forcei686;
        message = "boot.loader.grub.secureBoot does not support boot.loader.grub.forcei686.";
      }
      {
        # grub.cfg is signed as generated: a check_signatures line in it would be signed too.
        assertion =
          !lib.any (lib.hasInfix "check_signatures") [
            cfg.extraConfig
            cfg.extraEntries
            cfg.extraPerEntryConfig
            cfg.extraPrepareConfig
          ];
        message = "boot.loader.grub.secureBoot: do not set check_signatures in the GRUB configuration, it would disable signature checks.";
      }
    ];

    # Secure Boot only protects /boot: an unencrypted root lets anyone with the disk
    # change the Nix store (init= points into it) or copy the signing keys.
    warnings =
      lib.optional
        (
          config.boot.initrd.luks.devices == { }
          && !lib.any (fs: fs.encrypted.enable) (lib.attrValues config.fileSystems)
        )
        ''
          boot.loader.grub.secureBoot: no encrypted root filesystem (boot.initrd.luks.devices) found.
          Without one, anyone with access to the disk can modify the Nix store or steal the
          signing keys, which defeats Secure Boot. Ignore this if you use another encryption
          (e.g. ZFS native encryption). See the Security section of the fuerteboote README.
        '';

    # Kernels must live on /boot so they can be signed and get a .sig next to them.
    boot.loader.grub.copyKernels = true;

    boot.loader.grub.extraGrubInstallArgs = [
      # pgp and its crypto must be built in: they verify every module loaded later.
      "--modules=pgp gcry_rsa gcry_sha256 gcry_sha512"
      "--pubkey=${state}/pubkey.gpg"
      "--disable-shim-lock"
      # check_signatures can be turned off from the GRUB shell. A password is not
      # enough: `superusers` is set in grub.cfg, so a tampered grub.cfg fails to
      # load and leaves an unauthenticated shell (normal/auth.c).
      "--disable-cli"
    ];

    boot.loader.grub.extraPrepareConfig = ''
      GSB_AUTO_GENERATE_KEYS=${if sb.autoGenerateKeys then "1" else "0"} \
        ${lib.getExe tool} prepare @bootPath@ ${efiBinaries}
    '';

    boot.loader.grub.extraInstallCommands = lib.concatMapStrings (b: ''
      GSB_EXTRA_FILES=${lib.escapeShellArg (lib.concatStringsSep "\n" (lib.attrNames cfg.extraFiles))} \
        ${lib.getExe tool} sign ${
          lib.escapeShellArgs [
            b.path
            b.esp
            "${grubEfi}/lib/grub/${target}"
            "${grubEfi}/share/grub"
          ]
        } "''${1:-}" ${lib.escapeShellArg b.efiBinary}
    '') boots
    + lib.optionalString sb.autoEnrollKeys.enable ''
      ${lib.getExe tool} enroll ${lib.escapeShellArgs sb.autoEnrollKeys.extraArgs}
    ''
    + ''
      ${lib.getExe tool} check-enrolled
    '';

    # Windows updates replace bootmgfw.efi, which invalidates its GPG signature.
    systemd.services.fuerteboote-esp = mkIf cfg.useOSProber {
      description = "Re-sign EFI binaries on the ESP for GRUB Secure Boot";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      unitConfig.ConditionPathExists = "${state}/pubkey.gpg";
      serviceConfig.Type = "oneshot";
      script = lib.concatMapStrings (b: "${lib.getExe tool} sign-esp ${lib.escapeShellArg b.esp}\n") boots;
    };

    # fwupd applies UEFI capsule updates through its own EFI binary, which the firmware
    # only runs if signed (same approach as nixpkgs' Limine module).
    systemd.services.fwupd-efi = mkIf config.services.fwupd.enable {
      description = "Sign fwupd EFI app for GRUB Secure Boot";
      wantedBy = [ "fwupd.service" ];
      partOf = [ "fwupd.service" ];
      before = [ "fwupd.service" ];
      # /run/fwupd-efi is populated by the fwupd module.
      after = [ "systemd-tmpfiles-setup.service" ];
      unitConfig.ConditionPathExists = "/var/lib/sbctl/keys/db/db.key";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = ''
        for efi in ${config.services.fwupd.package.fwupd-efi}/libexec/fwupd/efi/fwupd*.efi; do
          ${lib.getExe pkgs.sbctl} sign -o "/run/fwupd-efi/$(basename "$efi").signed" "$efi"
        done
      '';
    };
    services.fwupd.uefiCapsuleSettings = mkIf config.services.fwupd.enable {
      DisableShimForSecureBoot = true;
    };

    environment.systemPackages = [
      pkgs.sbctl
      tool
    ];
  };
}
