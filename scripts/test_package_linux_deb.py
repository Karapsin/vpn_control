import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from package_linux_deb import package, package_arguments, verify_postinst


REPO = Path(__file__).resolve().parents[1]
TEMPLATE = (REPO / 'desktopApp/packaging/linux/postinst').read_text()


def control_archive(body, duplicate=False, symlink=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as archive:
        for _ in range(2 if duplicate else 1):
            entry = tarfile.TarInfo('./postinst')
            entry.mode = 0o755
            entry.size = len(body.encode())
            if symlink:
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/outside/maintainer-hook'
                entry.size = 0
            archive.addfile(entry, io.BytesIO(body.encode()) if not symlink else None)
    return stream.getvalue()


def custom_hook():
    return TEMPLATE.replace('APPLICATION_PACKAGE', 'vpn-control').replace('DESKTOP_COMMANDS_INSTALL',
        'xdg-desktop-menu install /opt/vpn-control/lib/vpn-control-vpn-control.desktop')


class LinuxDebPackageTest(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'Linux shell validation requires a POSIX shell')
    def test_smoke_rejects_noncanonical_fixture_version_before_removing_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = root / 'packages'
            packages.mkdir()
            evidence = root / 'evidence'
            evidence.mkdir()
            retained = evidence / 'prior-check.log'
            retained.write_text('preserved prior package evidence')
            for version in ('2.01.4', '2.1.20', 'not-a-version'):
                with self.subTest(version=version):
                    result = subprocess.run(['bash', str(REPO / 'scripts/test_linux_desktop_package.sh'),
                                             str(packages), str(evidence), version],
                                            capture_output=True, text=True)
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn('Expected package version must be canonical', result.stderr)
                    self.assertEqual('preserved prior package evidence', retained.read_text())

    def test_explicit_command_preserves_image_metadata_and_one_effective_resource_directory(self):
        command = package_arguments(Path('/jdk'), Path('/prepared image'), Path('/output'), Path('/resources'),
                                    'vpn-control', 'vpn-control', '2.1.4',
                                    {'vendor': 'Kardinal', 'description': 'Desktop VPN Control client',
                                     'maintainer': 'kardinal', 'category': 'Network', 'menu_group': 'Network', 'release': '1'})
        self.assertEqual(1, command.count('--resource-dir'))
        self.assertEqual('/resources', command[command.index('--resource-dir') + 1])
        self.assertEqual('/prepared image', command[command.index('--app-image') + 1])
        self.assertNotIn('--input', command)
        self.assertEqual('2.1.4', command[command.index('--app-version') + 1])
        self.assertEqual('kardinal', command[command.index('--linux-deb-maintainer') + 1])

    def test_default_or_truncated_emitted_hook_cannot_pass_archive_verification(self):
        default = '#!/bin/sh\nset -e\ncase "$1" in\nconfigure)\nxdg-desktop-menu install /opt/vpn-control/lib/vpn-control-vpn-control.desktop\n;;\nesac\n'
        for body in (default, custom_hook().replace('mkdir -m 0755', 'true # omitted creation'),
                     custom_hook().replace('xdg-desktop-menu install ', '# registration omitted ')):
            with self.assertRaises(ValueError):
                verify_postinst(control_archive(body), TEMPLATE, 'vpn-control')
        self.assertEqual(custom_hook(), verify_postinst(control_archive(custom_hook()), TEMPLATE, 'vpn-control'))

    def test_duplicate_or_linked_control_hook_is_rejected(self):
        for options in ({'duplicate': True}, {'symlink': True}):
            with self.assertRaisesRegex(ValueError, 'exactly one'):
                verify_postinst(control_archive(custom_hook(), **options), TEMPLATE, 'vpn-control')

    def test_failed_emitted_hook_verification_preserves_previous_package_and_failure_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'image'
            (image / 'bin').mkdir(parents=True)
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (62).to_bytes(2, 'little')
            (image / 'bin/vpn-control').write_bytes(header)
            resources = root / 'resources'
            resources.mkdir()
            (resources / 'postinst').write_text(TEMPLATE)
            destination = root / 'deb'
            destination.mkdir()
            previous = destination / 'vpn-control_2.1.4-1_amd64.deb'
            previous.write_bytes(b'previous generated package')

            def run(command, **kwargs):
                if command[0].endswith('/jpackage'):
                    output = Path(command[command.index('--dest') + 1])
                    (output / previous.name).write_bytes(b'new package with broken hook')
                    return subprocess.CompletedProcess(command, 0)
                if '-f' in command:
                    return subprocess.CompletedProcess(command, 0,
                        stdout=b'Package: vpn-control\nVersion: 2.1.4-1\nArchitecture: amd64\n')
                return subprocess.CompletedProcess(command, 0, stdout=control_archive('#!/bin/sh\nexit 0\n'))

            with patch('platform.system', return_value='Linux'), patch('platform.machine', return_value='x86_64'):
                with self.assertRaisesRegex(RuntimeError, 'retained generated evidence'):
                    package(Path('/jdk'), image, destination, resources, 'vpn-control', 'vpn-control', '2.1.4', {}, run_command=run)
            self.assertEqual(b'previous generated package', previous.read_bytes())
            retained = list(root.glob('.vpn-deb-*'))
            self.assertEqual(1, len(retained))
            self.assertEqual(b'new package with broken hook', (retained[0] / previous.name).read_bytes())

    def test_gradle_public_task_uses_verified_prepared_image_packaging(self):
        build = (REPO / 'desktopApp/build.gradle.kts').read_text()
        linux = build.split('if (hostOs.isLinux && targetFormat == TargetFormat.Deb) {', 1)[1].split('if (hostOs.isWindows', 1)[0]
        self.assertNotIn('freeArgs.addAll("--resource-dir"', linux)
        self.assertIn('scripts/package_linux_deb.py', linux)
        self.assertIn('createDistributable', linux)
        self.assertIn('inputs.dir(debResources)', linux)


if __name__ == '__main__':
    unittest.main()
