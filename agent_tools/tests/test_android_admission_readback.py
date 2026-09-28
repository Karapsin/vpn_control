"""Fake-executable coverage for the fixed Android readback boundary."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import android_admission_readback as admission


class AndroidAdmissionReadbackTest(unittest.TestCase):
    def test_nested_password_profile_uses_key_authenticated_connection_host(self):
        profile = {"adb":"/remote/adb", "cli":"/remote/vpn-control", "serial":"emulator-5554",
                   "expectedAvd":"owned-api35", "api":35}
        configured = SimpleNamespace(android_devices={"api35":profile}, fixture_transfer_root="/private/fixtures",
                                     password="nested-gateway-credential")
        config = SimpleNamespace(hosts={"archlinux":configured})
        with mock.patch.object(admission.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(admission.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
             mock.patch.object(admission.ssh_transport, "build_ssh_argv", return_value=["ssh"]), \
             mock.patch.object(admission.android_observation, "_run_probe", return_value=(0,b'{}')):
            result = admission.readback(".", "archlinux", "api35",
                "ad399bdd-25cb-4f71-857e-34ad18ae0399")
        self.assertEqual("unknown", result["outcome"])

    def test_rejects_unconfigured_or_malformed_identity_before_ssh(self):
        with mock.patch.object(admission.ssh_transport, "load_config") as config:
            with self.assertRaisesRegex(ValueError, "UUID"):
                admission.readback(".", "archlinux", "api35", "bad")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                admission.readback(".", "archlinux", "api35",
                    "ad399bdd-25cb-4f71-857e-34ad18ae0399", "ABC")
        config.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "fake executables require POSIX")
    def test_readback_retains_private_matching_backup_and_rejects_wrong_uid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            adb = root / "adb"
            cli = root / "vpn-control"
            called = root / "cli-called"
            fixture = root / "fixture"
            fixture.mkdir(mode=0o700)
            adb.write_text("""#!/usr/bin/env python3
import os,sys
a=sys.argv[1:]; tail=a[3:] if a[:3]==['-s','emulator-5554','shell'] else []
if tail[:1]==['-T']: tail=tail[1:]
if tail==['id','-u']: print(os.environ.get('READBACK_UID','2000'))
elif tail==['getprop','ro.build.version.sdk']: print('35')
elif tail==['getprop','ro.kernel.qemu.avd_name']: print('owned-api35')
elif tail==['getprop','ro.boot.qemu.avd_name']: print('owned-api35')
elif tail==['getprop','ro.product.cpu.abi']: print('x86_64')
elif tail==['dumpsys','package','com.kardinal.vpncontrol']: print(' versionName=2.1.19 versionCode=16800 ')
elif tail==['pm','path','com.kardinal.vpncontrol']: print('package:/data/app/test/base.apk')
elif tail==['sha256sum','/data/app/test/base.apk']: print('a'*64+'  /data/app/test/base.apk')
elif a[-2:]==['reverse','--list']: pass
else: sys.exit(3)
""")
            cli.write_text("""#!/usr/bin/env python3
import json,sys,os
from pathlib import Path
Path(os.environ['READBACK_CALLED']).write_text('yes')
a=sys.argv[1:]
if a[-1]=='status': data={'runtimeRunning':False,'runtimeObservation':'stopped'}
elif a[-2:]==['operations','list']: data={'scope':'android-provider-operations','operations':[]}
elif a[-2:]==['routing','show']: data={'routing':{'type':'vpn_control_routing_rules','version':7,'rules':{'direct_domain_suffixes':[]}}}
elif 'export' in a:
    target=Path(a[a.index('--output')+1]); target.write_text(json.dumps({'type':'vpn_control_routing_rules','version':7,'rules':{'direct_domain_suffixes':[]}})); sys.exit(0)
else: sys.exit(3)
print(json.dumps({'ok':True,'final':True,'code':'OK',
    'controllerId':os.environ.get('READBACK_OP_OWNER','owner') if a[-2:]==['operations','list'] else 'owner',
    'operationId':None,'configurationRevision':4,'data':data}))
""")
            adb.chmod(0o700)
            cli.chmod(0o700)
            correlation = "ad399bdd-25cb-4f71-857e-34ad18ae0399"
            command = [sys.executable, "-c", "exec(" + repr(admission._remote_probe()) + ")",
                str(adb), str(cli), "emulator-5554", "owned-api35", "35", str(fixture),
                correlation, "a" * 64, "10"]
            env = {**os.environ, "READBACK_CALLED": str(called), "PATH": str(root) + os.pathsep + os.environ.get("PATH", "")}
            denied = subprocess.run(command, capture_output=True, text=True,
                env={**env, "READBACK_UID":"0"}, timeout=15)
            self.assertEqual(0, denied.returncode, denied.stderr)
            self.assertEqual("device_identity", json.loads(denied.stdout)["reason"])
            self.assertFalse(called.exists())
            accepted = subprocess.run(command, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            result = json.loads(accepted.stdout)
            self.assertTrue(result["admitted"], result)
            backup = Path(result["backup"]["path"])
            self.assertEqual(0o600, backup.stat().st_mode & 0o777)
            self.assertEqual(4, result["guard"]["configurationRevision"])
            self.assertEqual("a" * 64, result["package"]["baseSha256"])
            self.assertNotIn("direct_domain_suffixes", accepted.stdout)
            status_command = [sys.executable, "-c", "exec(" + repr(admission._remote_status()) + ")",
                str(adb), str(cli), "emulator-5554", "owned-api35", "35", str(fixture), correlation, "10"]
            observed = subprocess.run(status_command, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(0, observed.returncode, observed.stderr)
            observed_value = json.loads(observed.stdout)
            self.assertEqual("backup_present", observed_value["stage"])
            self.assertEqual("owner", observed_value["controllerId"])
            self.assertEqual(result["backup"]["sha256"], observed_value["backup"]["sha256"])
            missing_command = status_command.copy()
            missing_command[-2] = "ff1fe927-6693-4c1d-8b7f-c84002e23d7e"
            missing = subprocess.run(missing_command, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual("absent", json.loads(missing.stdout)["stage"])
            changed = command.copy()
            changed[-3] = "be2fe9f4-a827-4452-bdb2-83daa9fcfb50"
            replaced = subprocess.run(changed, capture_output=True, text=True,
                env={**env, "READBACK_OP_OWNER":"replacement"}, timeout=15)
            self.assertEqual(0, replaced.returncode, replaced.stderr)
            self.assertEqual("readback_or_backup_unknown", json.loads(replaced.stdout)["reason"])
            self.assertTrue((fixture / "android-readback-be2fe9f4-a827-4452-bdb2-83daa9fcfb50" / "routing.json").exists())


if __name__ == "__main__":
    unittest.main()
