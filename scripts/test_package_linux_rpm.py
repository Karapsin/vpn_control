import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from package_linux_rpm import desktop_lifecycle_template, package, package_arguments, package_layout_template, verify_emitted_scripts, verify_package_layout


# Captured from the JDK 17 template and the actual 467fed base/target RPMs.
JDK_LIFECYCLE = """%post
DESKTOP_COMMANDS_INSTALL

%preun
UTILITY_SCRIPTS
DESKTOP_COMMANDS_UNINSTALL

%clean
"""
JDK_INSTALL = ('install -d -m 755 %{buildroot}APPLICATION_DIRECTORY\n'
               'cp -r %{_sourcedir}APPLICATION_DIRECTORY/* %{buildroot}APPLICATION_DIRECTORY\n')


def scriptlets(template):
    emitted = template.replace('DESKTOP_COMMANDS_INSTALL', 'xdg-desktop-menu install fixture.desktop')
    emitted = emitted.replace('DESKTOP_COMMANDS_UNINSTALL', 'xdg-desktop-menu uninstall fixture.desktop')
    emitted = emitted.replace('UTILITY_SCRIPTS', '')
    parts = re.split(r'(?m)^%(posttrans|post|preun|clean)\n', emitted)
    return dict(zip(parts[1::2], parts[2::2]))


class LinuxRpmPackageTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith('linux'), 'Actual GNU RPM buildroot staging')
    def test_restrictive_build_umask_stages_a_readable_application_without_changing_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source/opt/vpn-control'
            (source / 'bin').mkdir(parents=True)
            (source / 'lib').mkdir()
            (source / 'bin/vpn-control').write_text('inert executable, never run')
            (source / 'lib/data.jar').write_text('inert data, never loaded')
            (source / 'lib/legal-link').symlink_to('data.jar')
            for path in (source, source / 'bin', source / 'lib', source / 'bin/vpn-control'):
                path.chmod(0o700)
            (source / 'lib/data.jar').chmod(0o600)
            script = package_layout_template(JDK_INSTALL).replace('%{_sourcedir}', str(root / 'source'))
            script = script.replace('%{buildroot}', str(root / 'buildroot')).replace('APPLICATION_DIRECTORY', '/opt/vpn-control')
            result = subprocess.run(['/bin/sh', '-c', 'set -eu\numask 077\n' + script], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            staged = root / 'buildroot/opt/vpn-control'
            for path in (staged, staged / 'bin', staged / 'lib', staged / 'bin/vpn-control'):
                self.assertEqual(0o755, path.stat().st_mode & 0o7777, str(path))
            self.assertEqual(0o644, (staged / 'lib/data.jar').stat().st_mode & 0o7777)
            self.assertTrue((staged / 'lib/legal-link').is_symlink())
            self.assertEqual(0o700, (source / 'bin').stat().st_mode & 0o7777)
            self.assertEqual(0o600, (source / 'lib/data.jar').stat().st_mode & 0o7777)

    def test_emitted_rpm_cannot_hide_inaccessible_or_writable_application_modes(self):
        metadata = ('/opt/vpn-control\t40755\troot\troot\n'
                    '/opt/vpn-control/bin\t40755\troot\troot\n'
                    '/opt/vpn-control/bin/vpn-control\t100755\troot\troot\n'
                    '/opt/vpn-control/lib/data.jar\t100644\troot\troot\n'
                    '/opt/vpn-control/lib/legal-link\t120777\troot\troot\n')
        verify_package_layout(metadata, 'vpn-control')
        for changed in (metadata.replace('40755', '40700'), metadata.replace('40755', '40775'),
                        metadata.replace('100644', '100600'), metadata.replace('100644', '100664'),
                        metadata.replace('100755', '100644'), metadata.replace('\troot\troot', '\tbuilder\troot'),
                        metadata + metadata):
            with self.assertRaises(ValueError):
                verify_package_layout(changed, 'vpn-control')

    def test_effective_resource_directory_and_package_identity_are_explicit(self):
        arguments = package_arguments(Path('/jdk'), Path('/prepared image'), Path('/output'), Path('/resource'),
                                      'vpn-control', 'vpn-control', '2.1.4',
                                      {'license_type': 'MIT', 'vendor': 'Kardinal', 'release': '1'}, True)
        self.assertEqual(1, arguments.count('--resource-dir'))
        self.assertEqual('/prepared image', arguments[arguments.index('--app-image') + 1])
        self.assertEqual('rpm', arguments[arguments.index('--type') + 1])
        self.assertEqual('MIT', arguments[arguments.index('--linux-rpm-license-type') + 1])
        self.assertNotIn('--input', arguments)

    def test_changed_upstream_script_slots_require_explicit_review(self):
        for template in (JDK_LIFECYCLE.replace('%post\n', '%post -p /bin/bash\n'),
                         JDK_LIFECYCLE + JDK_LIFECYCLE,
                         JDK_LIFECYCLE + '\nDESKTOP_COMMANDS_INSTALL\n'):
            with self.assertRaisesRegex(ValueError, 'Review changed JDK'):
                desktop_lifecycle_template(template)

    def test_emitted_default_or_unguarded_scripts_are_rejected(self):
        original = scriptlets(JDK_LIFECYCLE)
        fixed = scriptlets(desktop_lifecycle_template(JDK_LIFECYCLE))
        verify_emitted_scripts('(none)', fixed['posttrans'], fixed['preun'])
        for post, posttrans, preun in (
                (original['post'], '', original['preun']),
                ('', fixed['posttrans'], original['preun']),
                ('', fixed['posttrans'].replace('xdg-desktop-menu install ', '# omitted '), fixed['preun']),
                ('', fixed['posttrans'], 'xdg-desktop-menu uninstall fixture.desktop\n' + fixed['preun'])):
            with self.assertRaises(ValueError):
                verify_emitted_scripts(post, posttrans, preun)

    def test_failed_generated_script_verification_preserves_previous_package_and_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / 'image'
            (image / 'bin').mkdir(parents=True)
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (62).to_bytes(2, 'little')
            (image / 'bin/vpn-control').write_bytes(header)
            java_home = root / 'jdk'
            (java_home / 'jmods').mkdir(parents=True)
            with zipfile.ZipFile(java_home / 'jmods/jdk.jpackage.jmod', 'w') as module:
                module.writestr('classes/jdk/jpackage/internal/resources/template.spec', JDK_INSTALL + JDK_LIFECYCLE)
            destination = root / 'output'
            destination.mkdir()
            previous = destination / 'vpn-control-2.1.4-1.x86_64.rpm'
            previous.write_bytes(b'previous verified package')

            def run(command, **kwargs):
                if command[0].endswith('/jpackage'):
                    output = Path(command[command.index('--dest') + 1])
                    (output / previous.name).write_bytes(b'new package with bad scripts')
                    return subprocess.CompletedProcess(command, 0)
                query = command[command.index('--qf') + 1]
                body = (b'vpn-control\n2.1.4\n1\nx86_64\n' if '%{NAME}' in query else b'(none)')
                return subprocess.CompletedProcess(command, 0, stdout=body)

            with patch('platform.system', return_value='Linux'), patch('platform.machine', return_value='x86_64'):
                with self.assertRaisesRegex(RuntimeError, 'retained generated evidence'):
                    package(java_home, image, destination, 'vpn-control', 'vpn-control', '2.1.4', {}, run_command=run)
            self.assertEqual(b'previous verified package', previous.read_bytes())
            retained = list(root.glob('.vpn-rpm-*'))
            self.assertEqual(1, len(retained))
            self.assertEqual(b'new package with bad scripts', (retained[0] / previous.name).read_bytes())

    def test_gradle_public_rpm_task_uses_verified_prepared_image(self):
        build = (Path(__file__).resolve().parents[1] / 'desktopApp/build.gradle.kts').read_text()
        linux = build.split('if (hostOs.isLinux && targetFormat == TargetFormat.Rpm) {', 1)[1].split('if (hostOs.isWindows', 1)[0]
        self.assertNotIn('freeArgs.addAll("--resource-dir"', linux)
        self.assertIn('scripts/package_linux_rpm.py', linux)
        self.assertIn('createDistributable', linux)
        self.assertIn('linuxRpmLicenseType', linux)

    @unittest.skipUnless(os.name == 'posix', 'POSIX RPM scriptlet lifecycle')
    def test_replacement_registration_survives_old_unconditional_uninstall(self):
        # RPM runs the old package's preun after the new package's post. A
        # posttrans registration also repairs upgrades from already published
        # packages whose preun unconditionally removes the replacement entry.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = root / 'registered.desktop'
            command = root / 'xdg-desktop-menu'
            command.write_text('#!/bin/sh\ncase "$1" in\n'
                               'install) : > "$FIXTURE_ENTRY" ;;\n'
                               'uninstall) rm -f "$FIXTURE_ENTRY" ;;\nesac\n')
            command.chmod(0o700)
            old = scriptlets(JDK_LIFECYCLE)
            current = scriptlets(desktop_lifecycle_template(JDK_LIFECYCLE))

            def run(body, count):
                body = body.replace('/usr/share/desktop-directories', str(root / 'desktop-directories'))
                result = subprocess.run(['/bin/sh', '-c', body, 'rpm-scriptlet', str(count)],
                                        env={**os.environ, 'PATH': str(root) + os.pathsep + os.defpath,
                                             'FIXTURE_ENTRY': str(entry)}, capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr)

            run(old['post'], 1)
            self.assertTrue(entry.exists())
            run(current.get('post', ''), 2)
            run(old['preun'], 1)
            run(current.get('posttrans', ''), 2)
            self.assertTrue(entry.exists(), 'RPM replacement lost the desktop menu entry')
            run(current['preun'], 1)
            self.assertTrue(entry.exists(), 'A later upgrade must preserve desktop registration')
            run(current['preun'], 0)
            self.assertFalse(entry.exists(), 'Actual final removal must unregister the entry')


if __name__ == '__main__':
    unittest.main()
