{ pkgs, module }:

let
  inherit (pkgs) lib;

  efivar = name: "/sys/firmware/efi/efivars/${name}-8be4df61-93ca-11d2-aa0d-00e098032b8c";
  dbCert = "/var/lib/sbctl/keys/db/db.pem";
  gpgHome = "/var/lib/fuerteboote/gnupg";
  shell = "${pkgs.edk2-uefi-shell}/shell.efi";

  baseConfig =
    { pkgs, ... }:
    {
      imports = [ module ];
      virtualisation = {
        useBootLoader = true;
        useEFIBoot = true;
      };
      boot.loader = {
        timeout = 1;
        efi.canTouchEfiVariables = lib.mkDefault true;
        grub = {
          enable = true;
          efiSupport = true;
          device = "nodev";
          secureBoot = {
            enable = true;
            autoEnrollKeys.enable = lib.mkDefault true;
          };
          # Mirror GRUB's output (and errors) on the serial console, keeping gfxterm/themes.
          extraConfig = ''
            serial --unit=0 --speed=115200
            terminal_output --append serial
          '';
        };
      };
      environment.systemPackages = with pkgs; [
        sbsigntool
        gnupg
        grub2
      ];
    };

  prelude = ''
    import time
    from datetime import timedelta

    def efi_byte(name):
        return machine.succeed(f"od -An -t u1 -j 4 -N 1 {name}").strip()

    def assert_secure_boot(expected):
        t.assertEqual(efi_byte("${efivar "SecureBoot"}"), expected)

    def boot():
        machine.wait_for_unit("multi-user.target")

    def reboot():
        machine.shutdown()
        machine.start()
        boot()

    def rebuild():
        return machine.succeed("/run/current-system/bin/switch-to-configuration boot 2>&1")

    def next_entry(title):
        machine.succeed(f"grub-editenv /boot/grub/grubenv set next_entry='{title}'")

    def wait_console(regex, minutes=5):
        machine.wait_for_console_text(regex, timeout=timedelta(minutes=minutes))

    def assert_no_userspace():
        """Cold boot and check that the firmware starts GRUB but nothing reaches userspace.

        GRUB's errors are not on the serial console, so we assert the outcome. A rejected
        initrd still lets the signed kernel start (and panic without a root fs); what must
        never happen is running an init. The console log restarts empty with each start.
        """
        machine.crash()
        machine.start()
        wait_console("grubx64.efi|BOOTX64.EFI")
        time.sleep(90)
        t.assertNotIn("as init process", machine.get_console_log(), "tampered system ran userspace")
  '';

  mkTest =
    {
      name,
      config ? { },
      testScript,
    }:
    pkgs.testers.runNixOSTest {
      name = "fuerteboote-${name}";
      nodes.machine = {
        imports = [
          baseConfig
          config
        ];
      };
      testScript =
        if builtins.isFunction testScript then { nodes, ... }@args: prelude + testScript args else prelude + testScript;
    };

  evalSystem =
    config:
    pkgs.nixos {
      imports = [
        module
        config
      ];
      fileSystems."/" = {
        device = "/dev/vda";
        fsType = "ext4";
      };
      boot.loader.grub = {
        enable = true;
        efiSupport = lib.mkDefault true;
        device = lib.mkDefault "nodev";
        secureBoot.enable = true;
      };
    };

  # Evaluation-only checks: the module must reject unsupported setups, and accept a valid one
  # (so that a rejection is not caused by an unrelated evaluation error).
  evalCheck =
    name: shouldSucceed: config:
    let
      result = builtins.tryEval (evalSystem config).config.system.build.toplevel.drvPath;
    in
    assert lib.assertMsg (result.success == shouldSucceed) "eval-${name}: expected success = ${lib.boolToString shouldSucceed}";
    pkgs.runCommand "fuerteboote-eval-${name}" { } "touch $out";

  # The "no encrypted root" warning must appear exactly when there is no encrypted root.
  evalWarns =
    name: shouldWarn: config:
    let
      warns = lib.any (lib.hasInfix "no encrypted root filesystem") (evalSystem config).config.warnings;
    in
    assert lib.assertMsg (warns == shouldWarn) "eval-${name}: expected warning = ${lib.boolToString shouldWarn}";
    pkgs.runCommand "fuerteboote-eval-${name}" { } "touch $out";

  attacks = {
    grub-cfg = "echo 'set check_signatures=no' >> /boot/grub/grub.cfg";
    initrd = "for f in /boot/kernels/*-initrd; do echo garbage >> $f; done";
    module = "echo garbage >> /boot/grub/x86_64-efi/normal.mod";
    # Valid GPG signature, no Authenticode signature: only the firmware can catch it.
    kernel-unsigned = "for f in /boot/kernels/*-bzImage; do sbattach --remove $f; GNUPGHOME=${gpgHome} gpg --batch --yes --detach-sign -o $f.sig $f; done";
    grub-unsigned = "sbattach --remove /boot/EFI/NixOS-boot/grubx64.efi";
  };
in
{
  # First install inside the image build: keys are generated and enrolled, then the
  # machine boots with Secure Boot enforced, a graphical theme, initrd secrets and a
  # specialisation booted once through grubenv (grub-reboot).
  auto-enroll = mkTest {
    name = "auto-enroll";
    config =
      { pkgs, ... }:
      {
        boot.loader.grub.theme = "${pkgs.nixos-grub2-theme}";
        boot.initrd.secrets."/etc/initrd-secret" = pkgs.writeText "initrd-secret" "s3cret";
        specialisation.alt.configuration = {
          boot.initrd.kernelModules = [ "loop" ];
          environment.etc."specialisation-name".text = "alt";
        };
      };
    testScript = ''
      import re

      boot()
      assert_secure_boot("1")

      with subtest("GRUB, kernels and config are signed"):
          print(machine.succeed("find /boot -name '*.sig' | sort"))
          machine.succeed("sbverify --cert ${dbCert} /boot/EFI/NixOS-boot/grubx64.efi")
          machine.succeed("for k in /boot/kernels/*-bzImage; do sbverify --cert ${dbCert} $k; done")
          machine.succeed("for f in /boot/kernels/*; do case $f in *.sig) ;; *) test -e $f.sig ;; esac; done")
          machine.succeed("test -e /boot/grub/grub.cfg.sig -a -e /boot/theme/theme.txt.sig")
          machine.succeed("ls /boot/kernels/*-secrets.sig")
          machine.succeed("grep -q 'load_env --skip-sig saved_entry next_entry' /boot/grub/grub.cfg")
          machine.succeed("gpg --homedir ${gpgHome} --verify /boot/grub/grub.cfg.sig /boot/grub/grub.cfg")
          machine.fail("test -e /boot/grub/grubenv.sig")

      with subtest("Rebuilding is idempotent"):
          machine.succeed("NIXOS_INSTALL_BOOTLOADER=1 /run/current-system/bin/switch-to-configuration boot")
          out = rebuild()
          t.assertNotIn("forcing grub-install", out)

      with subtest("Specialisation boots once through next_entry"):
          cfg = machine.succeed("cat /boot/grub/grub.cfg")
          m = re.search(r'menuentry --unrestricted "([^"]*alt[^"]*)"', cfg)
          assert m, "no specialisation entry in grub.cfg"
          title = m.group(1)
          next_entry(title)
          reboot()
          assert_secure_boot("1")
          t.assertEqual(machine.succeed("cat /etc/specialisation-name").strip(), "alt")
          reboot()
          machine.fail("test -e /etc/specialisation-name")
    '';
  };

  # Keys are generated but not enrolled; the user enrolls them by hand.
  manual-enroll = mkTest {
    name = "manual-enroll";
    config.boot.loader.grub.secureBoot.autoEnrollKeys.enable = false;
    testScript = ''
      boot()
      assert_secure_boot("0")
      t.assertEqual(efi_byte("${efivar "SetupMode"}"), "1")
      print(machine.succeed("sbctl enroll-keys --microsoft 2>&1"))
      reboot()
      assert_secure_boot("1")
      # The check the README tells users to do.
      status = machine.succeed("sbctl status")
      print(status)
      t.assertRegex(status, r"Setup Mode:\s+✓ Disabled")
      t.assertRegex(status, r"Secure Boot:\s+✓ Enabled")
    '';
  };

  # No NVRAM boot entry: the firmware falls back to \EFI\BOOT\BOOTX64.EFI.
  removable = mkTest {
    name = "removable";
    config.boot.loader = {
      efi.canTouchEfiVariables = false;
      grub.efiInstallAsRemovable = true;
    };
    testScript = ''
      boot()
      assert_secure_boot("1")
      machine.succeed("sbverify --cert ${dbCert} /boot/EFI/BOOT/BOOTX64.EFI")
      reboot()
      assert_secure_boot("1")
    '';
  };

  # os-prober finds a "Windows Boot Manager" (the EDK2 UEFI shell in disguise).
  os-prober = mkTest {
    name = "os-prober";
    config = {
      boot.loader.grub.useOSProber = true;
      system.extraDependencies = [ pkgs.edk2-uefi-shell ];
    };
    testScript = ''
      import re

      bootmgfw = "/boot/EFI/Microsoft/Boot/bootmgfw.efi"
      boot()
      machine.succeed("mkdir -p /boot/EFI/Microsoft/Boot && touch /boot/EFI/Microsoft/Boot/BCD")
      machine.succeed(f"sbctl sign -o {bootmgfw} ${shell}")
      rebuild()
      cfg = machine.succeed("cat /boot/grub/grub.cfg")
      m = re.search(r"menuentry --unrestricted '(Windows Boot Manager[^']*)'", cfg)
      assert m, "os-prober did not add a Windows entry"
      title = m.group(1)

      with subtest("A Windows update invalidates the signature; the boot service re-signs it"):
          machine.succeed(f"echo stale > {bootmgfw}.sig")
          reboot()
          machine.succeed(f"gpg --homedir ${gpgHome} --verify {bootmgfw}.sig {bootmgfw}")

      with subtest("GRUB chainloads the Authenticode-signed Windows entry"):
          next_entry(title)
          machine.shutdown()
          machine.start()
          wait_console("UEFI Interactive Shell")
          machine.crash()
          machine.start()
          boot()

      with subtest("An EFI binary not signed for the firmware is refused"):
          machine.succeed(f"cp ${shell} {bootmgfw} && systemctl restart fuerteboote-esp.service")
          next_entry(title)
          machine.shutdown()
          machine.start()
          wait_console("grubx64.efi")
          time.sleep(60)
          t.assertNotIn("UEFI Interactive Shell", machine.get_console_log())
    '';
  };

  # savedefault + rollback: every entry must be bootable (GRUB 2.14 denies entries that are
  # not --unrestricted when the CLI is disabled), including "All configurations".
  savedefault-rollback = mkTest {
    name = "savedefault-rollback";
    config.boot.loader.grub.default = "saved";
    testScript = ''
      import re

      boot()
      assert_secure_boot("1")
      machine.succeed("grep -q -- --disable-cli /boot/grub/state")
      machine.fail("grep -E '^[[:space:]]*(menuentry|submenu) ' /boot/grub/grub.cfg | grep -v -- --unrestricted")

      with subtest("savedefault writes grubenv"):
          machine.succeed("grub-editenv /boot/grub/grubenv list | grep -q saved_entry=")

      with subtest("An entry from 'All configurations' boots"):
          cfg = machine.succeed("cat /boot/grub/grub.cfg")
          m = re.search(r'menuentry --unrestricted "(NixOS - Configuration 1 [^"]*)"', cfg)
          assert m, "no 'Configuration 1' entry in grub.cfg"
          next_entry("NixOS - All configurations>" + m.group(1))
          reboot()
          assert_secure_boot("1")
          t.assertIn("Configuration 1", machine.succeed("grub-editenv /boot/grub/grubenv list"))

      with subtest("A bogus grubenv entry falls back to the default"):
          next_entry("does-not-exist")
          reboot()
          assert_secure_boot("1")
    '';
  };

  # extraFiles holding an unsigned PE image (memtest86+) gets signed for the firmware.
  memtest = mkTest {
    name = "memtest";
    config.boot.loader.grub.memtest86.enable = true;
    testScript = ''
      boot()
      machine.succeed("sbverify --cert ${dbCert} /boot/memtest.bin")
      machine.succeed("gpg --homedir ${gpgHome} --verify /boot/memtest.bin.sig /boot/memtest.bin")
      next_entry("Memtest86+")
      machine.shutdown()
      machine.start()
      # memtest86+ prints this from its own code, so the firmware accepted and ran it.
      # (memtest86+ 8.10 then page-faults on OVMF, with or without Secure Boot.)
      wait_console("Trying to terminate EFI services")
    '';
  };

  # Files modified on /boot behind NixOS' back are restored from the store.
  self-heal = mkTest {
    name = "self-heal";
    testScript = ''
      boot()
      machine.succeed(
          "for f in /boot/kernels/*-initrd /boot/kernels/*-bzImage /boot/grub/x86_64-efi/normal.mod; do echo garbage >> $f; done"
      )
      out = rebuild()
      t.assertIn("restoring", out)
      reboot()
      assert_secure_boot("1")
    '';
  };

  # Losing the GPG key: a new one is generated and GRUB is reinstalled with it.
  key-rotation = mkTest {
    name = "key-rotation";
    testScript = ''
      boot()
      old = machine.succeed("sha256sum /boot/grub/secureboot-pubkey.gpg")
      machine.succeed("rm -rf /var/lib/fuerteboote")
      out = rebuild()
      t.assertIn("forcing grub-install", out)
      t.assertNotEqual(old, machine.succeed("sha256sum /boot/grub/secureboot-pubkey.gpg"))
      reboot()
      assert_secure_boot("1")
    '';
  };

  # Recommended procedure for reused keys, with Secure Boot enforced: `sbctl rotate-keys`
  # (no Setup Mode needed), rebuild, reboot. A binary signed with the old key (here the
  # previous GRUB image) must then be refused by the firmware.
  db-key-rotation = mkTest {
    name = "db-key-rotation";
    testScript = ''
      grub = "/boot/EFI/NixOS-boot/grubx64.efi"
      not_enrolled = "Secure Boot is enabled but your db key"
      boot()
      assert_secure_boot("1")

      with subtest("Warn before rebooting when the db key is not enrolled"):
          t.assertNotIn(not_enrolled, rebuild())
          machine.succeed("mv /var/lib/sbctl /root/sbctl-enrolled && sbctl create-keys")
          t.assertIn(not_enrolled, rebuild())
          machine.succeed("rm -rf /var/lib/sbctl && mv /root/sbctl-enrolled /var/lib/sbctl")
          t.assertNotIn(not_enrolled, rebuild())

      machine.succeed(f"cp {grub} /root/grub-old-key.efi")
      old = machine.succeed("cat ${dbCert}")
      print(machine.succeed("sbctl rotate-keys 2>&1"))
      t.assertNotEqual(old, machine.succeed("cat ${dbCert}"))
      # rotate-keys backs the old private keys up there.
      machine.succeed("rm -rf /var/tmp/sbctl")
      rebuild()
      machine.succeed(f"sbverify --cert ${dbCert} {grub}")
      machine.succeed("for k in /boot/kernels/*-bzImage; do sbverify --cert ${dbCert} $k; done")
      reboot()
      assert_secure_boot("1")

      with subtest("A binary signed with the old key is refused"):
          machine.succeed(f"cp /root/grub-old-key.efi {grub}", "sync")
          assert_no_userspace()
    '';
  };

  # Demonstrates the README's first limit: Secure Boot does not protect the Nix store.
  # With an unencrypted disk, an attacker can add a systemd unit to the system's store
  # path (simulated here at runtime; offline it is the same write) and it runs at boot.
  limit-unencrypted-root = mkTest {
    name = "limit-unencrypted-root";
    testScript = ''
      boot()
      units = machine.succeed("readlink -f /etc/systemd/system").strip()
      machine.succeed("mount -o remount,rw /nix/store")
      machine.succeed(
          f"printf '[Service]\nType=oneshot\nExecStart=/bin/sh -c \"echo STORE-TAMPERED > /dev/ttyS0\"\n' > {units}/evil.service",
          f"ln -s ../evil.service {units}/multi-user.target.wants/evil.service",
          "sync",
      )
      machine.crash()
      machine.start()
      wait_console("STORE-TAMPERED")
    '';
  };

  # The recommended setup: root on LUKS, unlocked in the initrd, with Secure Boot enforced.
  luks-root = mkTest {
    name = "luks-root";
    config =
      { lib, pkgs, ... }:
      {
        virtualisation = {
          emptyDiskImages = [ 512 ];
          # Booting off the encrypted disk requires an available init script.
          mountHostNixStore = true;
        };
        environment.systemPackages = [ pkgs.cryptsetup ];
        specialisation.boot-luks.configuration = {
          boot.initrd.luks.devices = lib.mkVMOverride { cryptroot.device = "/dev/vdb"; };
          virtualisation.rootDevice = "/dev/mapper/cryptroot";
        };
      };
    testScript =
      { nodes, ... }:
      ''
        boot()
        machine.succeed("echo -n supersecret | cryptsetup luksFormat -q --iter-time=1 /dev/vdb -")
        machine.succeed("echo -n supersecret | cryptsetup luksOpen -q /dev/vdb cryptroot")
        machine.succeed("mkfs.ext4 /dev/mapper/cryptroot")
        machine.succeed("${nodes.machine.specialisation.boot-luks.configuration.system.build.toplevel}/bin/switch-to-configuration boot")
        machine.succeed("sync")
        machine.crash()
        machine.start()
        wait_console("Please enter passphrase for disk cryptroot")
        machine.send_console("supersecret\n")
        boot()
        assert_secure_boot("1")
        t.assertIn("/dev/mapper/cryptroot on / type ext4", machine.succeed("mount"))
      '';
  };

  # fwupd's EFI capsule loader is signed so firmware updates keep working.
  fwupd = mkTest {
    name = "fwupd";
    config.services.fwupd.enable = true;
    testScript = ''
      boot()
      # fwupd is D-Bus activated; starting it pulls in the signing service.
      machine.succeed("systemctl start fwupd.service")
      machine.wait_for_unit("fwupd-efi.service")
      machine.succeed("for f in /run/fwupd-efi/*.signed; do sbverify --cert ${dbCert} $f; done")
      machine.succeed("ls /run/fwupd-efi/*.signed")
    '';
  };

  eval-ok = evalCheck "ok" true { };
  eval-grub-2_12 = evalCheck "grub-2_12" false {
    nixpkgs.overlays = [ (_: prev: { grub2 = prev.grub2.overrideAttrs { version = "2.12"; }; }) ];
  };
  eval-users = evalCheck "users" false { boot.loader.grub.users.root.password = "x"; };
  eval-check-signatures = evalCheck "check-signatures" false {
    boot.loader.grub.extraConfig = "set check_signatures=no";
  };
  eval-warn-unencrypted = evalWarns "warn-unencrypted" true { };
  eval-no-warn-luks = evalWarns "no-warn-luks" false {
    boot.initrd.luks.devices.cryptroot.device = "/dev/vda2";
  };
  eval-bios = evalCheck "bios" false { boot.loader.grub.device = "/dev/vda"; };
  eval-no-efi = evalCheck "no-efi" false { boot.loader.grub.efiSupport = false; };
}
# Modifying anything GRUB or the firmware loads must keep the system from reaching userspace.
// lib.mapAttrs' (
  name: cmd:
  lib.nameValuePair "tamper-${name}" (mkTest {
    name = "tamper-${name}";
    testScript = ''
      boot()
      assert_secure_boot("1")
      machine.succeed("${cmd}", "sync")
      assert_no_userspace()
    '';
  })
) attacks
