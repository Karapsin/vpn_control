from pathlib import Path
import hashlib
import tempfile
import unittest
from unittest.mock import patch

from prepare_linux_install_vm import BASE, IMAGE, SHA256, capture_base_image, guest_configuration, image_spec, qemu_command, seed_command


class LinuxInstallVmPlanTest(unittest.TestCase):
    def test_distro_bootstrap_preserves_locked_user_and_absent_desktop_dependency(self):
        for distro in ("ubuntu", "fedora", "arch"):
            config = guest_configuration(distro, "client-public", "host-public", "private-test-fixture")
            self.assertFalse(config["ssh_pwauth"])
            self.assertTrue(config["users"][0]["lock_passwd"])
            self.assertEqual(["client-public"], config["users"][0]["ssh_authorized_keys"])
            self.assertEqual(["sudo" if distro == "ubuntu" else "wheel"], config["users"][0]["groups"])
            self.assertEqual(distro == "arch", config["package_upgrade"])
            self.assertNotIn("xdg-utils", config["packages"])
            self.assertEqual("ssh" if distro == "ubuntu" else "sshd", config["runcmd"][0][-1])
        with self.assertRaises(ValueError):
            guest_configuration("untrusted", "client", "public", "private")

    def test_each_cloud_distribution_has_separate_pinned_identity(self):
        fedora = image_spec("fedora")
        self.assertIn("/releases/44/Cloud/x86_64/images/", fedora["base"])
        self.assertEqual("28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f", fedora["sha256"])
        arch = image_spec("arch")
        self.assertEqual("https://geo.mirror.pkgbuild.com/images/v20260901.583572/", arch["base"])
        self.assertEqual("e3e688f97a71b265ce202905a504253f60f3680cf57d011a45411c43bedfa930", arch["sha256"])
        self.assertEqual(3, len({image_spec(value)["sha256"] for value in ("ubuntu", "fedora", "arch")}))
        with self.assertRaises(ValueError):
            image_spec("untrusted")

    def test_selected_distribution_controls_captured_filename_and_verification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(b"synthetic-fedora-cloud-image")
            target = root / "target"
            target.mkdir()
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with patch("prepare_linux_install_vm.image_spec", return_value={"base": "https://example.invalid/",
                       "image": "fedora.qcow2", "sha256": digest}) as selected:
                image, actual = capture_base_image(target, "/never-executed", source, "fedora")
            selected.assert_called_once_with("fedora")
            self.assertEqual("fedora.qcow2", image.name)
            self.assertEqual(digest, actual)
            self.assertEqual(0o400, image.stat().st_mode & 0o777)

    def test_existing_clean_cloud_image_is_copied_and_reverified_without_changing_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "pinned-base.img"
            source.write_bytes(b"synthetic-cloud-image")
            destination = root / "new-task"
            destination.mkdir()
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            with patch("prepare_linux_install_vm.SHA256", digest):
                image, actual = capture_base_image(destination, "/never-executed", source)
            self.assertEqual(digest, actual)
            self.assertEqual(source.read_bytes(), image.read_bytes())
            self.assertNotEqual(source.stat().st_ino, image.stat().st_ino)
            self.assertEqual(0o400, image.stat().st_mode & 0o777)

    def test_changed_or_installed_task_disk_cannot_be_used_as_clean_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "task.qcow2"
            source.write_bytes(b"mutated-or-installed-disk")
            destination = root / "new-task"
            destination.mkdir()
            with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                capture_base_image(destination, "/never-executed", source)
            self.assertEqual(b"mutated-or-installed-disk", source.read_bytes())

    def test_linux_kvm_uses_default_bios_and_no_other_vm_or_shared_host_paths(self):
        directory = Path("/tmp/vpn-install-kvm")
        command = qemu_command(directory, "/usr/bin/qemu-system-x86_64", None, 2307, "kvm")
        self.assertEqual("kvm", command[command.index("-accel") + 1])
        self.assertEqual("host", command[command.index("-cpu") + 1])
        self.assertFalse(any("pflash" in value or "libvirt" in value for value in command))
        drives = [command[index + 1] for index, value in enumerate(command) if value == "-drive"]
        self.assertEqual(2, len(drives))
        self.assertTrue(all(str(directory) in value for value in drives))
        self.assertIn("user,id=network,hostfwd=tcp:127.0.0.1:2307-:22", command)

    def test_linux_seed_uses_existing_xorriso_and_cidata_with_metadata_at_root(self):
        directory = Path("/tmp/vpn-install-kvm")
        self.assertEqual(["/usr/bin/xorriso", "-as", "mkisofs", "-output", str(directory / "seed.iso"),
                          "-volid", "CIDATA", "-rational-rock", "-joliet", str(directory / "seed")],
                         seed_command("/usr/bin/xorriso", directory, True))

    def test_only_localhost_user_network_and_task_disks(self):
        directory = Path("/tmp/vpn-install-test")
        command = qemu_command(directory, "/usr/bin/qemu-system-x86_64", Path("/opt/qemu/code.fd"), 2307)
        self.assertIn("user,id=network,hostfwd=tcp:127.0.0.1:2307-:22", command)
        self.assertNotIn("-virtfs", command)
        self.assertNotIn("-fsdev", command)
        self.assertFalse(any("tap," in value or "bridge," in value for value in command))
        drives = [command[index + 1] for index, value in enumerate(command) if value == "-drive"]
        self.assertEqual(4, len(drives))
        self.assertTrue(all(str(directory) in value or "readonly=on,file=/opt/qemu/code.fd" in value for value in drives))

    def test_unsafe_key_value_paths_and_ports_rejected(self):
        for path, port in (("/tmp/task,other=bad", 2307), ("/tmp/task\nnext", 2307), ("/tmp/task", 22)):
            with self.assertRaises(ValueError):
                qemu_command(Path(path), "qemu", Path("/firmware"), port)

    def test_cloud_image_is_date_pinned_official_amd64(self):
        self.assertEqual("https://cloud-images.ubuntu.com/noble/20260826/", BASE)
        self.assertEqual("noble-server-cloudimg-amd64.img", IMAGE)
        self.assertEqual("d0fe84bb5f80853425fa6be28e2c106f30104c3cfe8611933f2e65c9b63f0e30", SHA256)


if __name__ == "__main__":
    unittest.main()
