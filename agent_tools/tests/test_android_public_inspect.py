"""Fake public CLI coverage for bounded read-only Android comparisons."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from agent_tools import android_public_inspect as inspection


class AndroidPublicInspectTest(unittest.TestCase):
    def test_ssh_exit_255_reports_authentication_failure_without_mutation(self):
        config=SimpleNamespace(hosts={"archlinux":SimpleNamespace(android_devices={"api29":object()},transport="nested")})
        profile={"adb":"adb","cli":"cli","serial":"emulator-5554","expectedAvd":"owned-api29","api":29}
        probe=inspection.ssh_transport.ProbeResult("archlinux",inspection.ssh_transport.ProbeStatus.AUTHENTICATION_FAILED)
        with mock.patch.object(inspection.ssh_transport,"load_config",return_value=config), \
             mock.patch.object(inspection.ssh_transport,"connection_host",return_value=SimpleNamespace(password=None)), \
             mock.patch.object(inspection.android_observation,"_profile",return_value=profile), \
             mock.patch.object(inspection.ssh_transport,"build_ssh_argv",return_value=["ssh"]), \
             mock.patch.object(inspection.android_observation,"_run_probe",return_value=(255,b"")), \
             mock.patch.object(inspection.ssh_transport,"probe",return_value=probe) as ssh_probe:
            result=inspection.inspect(".","archlinux","api29","b20b3b85-cbbc-4f04-ad83-97a8b71a26be","a"*64,"owner",0)
        self.assertEqual("authentication_failed",result["reason"])
        self.assertFalse(result["nativeMutationAllowed"])
        self.assertFalse(result["replayAllowed"])
        self.assertEqual({"tool":"ssh_workflow","action":"connection-recover","host":"archlinux"},
                         result["recoveryHint"])
        ssh_probe.assert_called_once()

    def test_invalid_identity_rejected_before_transport(self):
        with mock.patch.object(inspection.ssh_transport,"load_config") as load:
            with self.assertRaisesRegex(ValueError,"UUID"):
                inspection.inspect(".","archlinux","api29","bad","a"*64,"owner",0)
            with self.assertRaisesRegex(ValueError,"package hash"):
                inspection.inspect(".","archlinux","api29","6ee97311-c6bc-4e9b-96eb-6a16dbec7648","bad","owner",0)
        load.assert_not_called()

    @unittest.skipUnless(os.name=="posix","fake executables require POSIX")
    def test_fixed_reads_bind_owner_and_return_digests_without_private_fields(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); adb=root/"adb"; cli=root/"control.py"; writes=root/"writes"
            adb.write_text('''#!/usr/bin/env python3
import sys
a=sys.argv[1:]; tail=a[3:] if a[:3]==['-s','emulator-5554','shell'] else []
if tail[:1]==['-T']: tail=tail[1:]
if tail==['id','-u']: print('2000')
elif tail==['getprop','ro.build.version.sdk']: print('29')
elif tail==['getprop','ro.kernel.qemu.avd_name']: print('owned-api29')
elif tail==['getprop','ro.boot.qemu.avd_name']: pass
elif tail==['getprop','ro.product.cpu.abi']: print('x86_64')
elif tail==['pm','path','com.kardinal.vpncontrol']: print('package:/data/app/test/base.apk')
elif tail==['sha256sum','/data/app/test/base.apk']: print('a'*64+'  /data/app/test/base.apk')
else: sys.exit(4)
''')
            cli.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
a=sys.argv[1:]
if a[-1]=='status': data={'runtimeRunning':False,'runtimeObservation':'stopped','secret':'private-status'}
elif a[-1]=='stats': data={'bytesIn':0,'secret':'private-stats'}
elif a[-2:]==['source','show']: data={'mode':'current-locations','subscriptionId':None,'secret':'private-source'}
elif a[-2:]==['settings','show']: data={'language':'en','secret':'private-settings'}
elif a[-2:]==['operations','list']: data={'operations':[]}
else: Path(os.environ['INSPECT_WRITES']).write_text('bad'); sys.exit(4)
print(json.dumps({'ok':True,'final':True,'code':'OK','controllerId':os.environ.get('INSPECT_OWNER','owner'),
 'configurationRevision':2,'data':data}))
''')
            adb.chmod(0o700); cli.chmod(0o700)
            args=[str(adb),str(cli),"emulator-5554","owned-api29","29","a"*64,"owner","2"]
            cmd=[sys.executable,"-c","exec("+repr(inspection._remote_source())+")",*args]
            env={**os.environ,"INSPECT_WRITES":str(writes)}
            good=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual(0,good.returncode,good.stderr)
            result=json.loads(good.stdout)
            self.assertTrue(result["admitted"],result)
            self.assertEqual("current-locations",result["snapshots"]["source"]["mode"])
            self.assertEqual("none",result["snapshots"]["source"]["selectionState"])
            self.assertEqual(0,result["operationCount"])
            self.assertNotIn("private-",good.stdout)
            self.assertFalse(writes.exists())
            wrong=subprocess.run(cmd,capture_output=True,text=True,env={**env,"INSPECT_OWNER":"replacement"},timeout=10)
            self.assertEqual("owner_or_response_changed",json.loads(wrong.stdout)["reason"])
            self.assertFalse(writes.exists())


if __name__=="__main__": unittest.main()
