import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform.startswith('linux'), 'Production Arch installer uses GNU filesystem tools')
class ArchUpdatePermissionsTest(unittest.TestCase):
    def test_shared_build_modes_become_private_install_authority_without_changing_inputs(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/install_arch_desktop_update.sh'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'bundle'
            app = source / 'app'
            (app / 'bin').mkdir(parents=True)
            (app / 'lib').mkdir()
            (app / 'bin/vpn-control').write_text('#!/bin/sh\nexit 0\n')
            (source / 'sing-box').write_text('#!/bin/sh\nexit 0\n')
            (app / 'lib/data.jar').write_bytes(b'fixture bytes, never loaded')
            (app / 'lib/legal-link').symlink_to('data.jar')
            for path in (app, app / 'bin', app / 'lib', app / 'bin/vpn-control', source / 'sing-box'):
                path.chmod(0o775)
            (app / 'lib/data.jar').chmod(0o664)
            parent = root / 'existing user directory'
            parent.mkdir(mode=0o770)
            parent.chmod(0o770)
            installed = parent / 'vpn-control'
            result = subprocess.run(['bash', str(script), str(source)], capture_output=True, text=True,
                                    env={**os.environ, 'VPN_CONTROL_INSTALL_DIR': str(installed),
                                         'VPN_CONTROL_ICON_PATH': str(root / 'icons/fixture.png'),
                                         'VPN_CONTROL_SKIP_CAPABILITY': 'true', 'VPN_CONTROL_SKIP_OWNERSHIP': 'true'})
            self.assertEqual(0, result.returncode, result.stderr)
            for path in (installed, installed / 'bin', installed / 'lib', installed / 'bin/vpn-control',
                         installed / 'bin/sing-box'):
                self.assertEqual(0o755, stat.S_IMODE(path.stat().st_mode), str(path))
            self.assertEqual(0o644, stat.S_IMODE((installed / 'lib/data.jar').stat().st_mode))
            self.assertTrue((installed / 'lib/legal-link').is_symlink())
            self.assertEqual('data.jar', os.readlink(installed / 'lib/legal-link'))
            self.assertEqual(b'fixture bytes, never loaded', (installed / 'lib/legal-link').read_bytes())
            self.assertEqual(0o770, stat.S_IMODE(parent.stat().st_mode))
            self.assertEqual(0o775, stat.S_IMODE(app.stat().st_mode))
            self.assertEqual(0o664, stat.S_IMODE((app / 'lib/data.jar').stat().st_mode))


if __name__ == '__main__':
    unittest.main()
