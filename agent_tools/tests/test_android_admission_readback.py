"""Fake-executable coverage for the fixed Android readback boundary."""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import android_admission_readback as admission


class AndroidAdmissionReadbackTest(unittest.TestCase):
    def test_async_status_rechecks_private_backup_bytes_and_collect_binds_local_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            correlation = "ad399bdd-25cb-4f71-857e-34ad18ae0399"
            intent = {"host":"archlinux","device":"api35","correlationId":correlation,
                      "expectedBaseSha256":"a"*64,"serial":"emulator-5554",
                      "expectedAvd":"owned-api35","api":35,"fixtureRoot":str(root)}
            admission._save_async_intent(root,intent)
            job = root/("android-readback-job-"+correlation)
            job.mkdir(mode=0o700)
            def private(path, value):
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            private(job/"intent.json",intent)
            private(job/"identity.json",{"pid":1234,"startTicks":12})
            backup_dir = root/("android-readback-"+correlation)
            backup_dir.mkdir(mode=0o700)
            backup_path = backup_dir/"routing.json"
            backup_bytes = b'{"type":"vpn_control_routing_rules","version":7,"rules":{}}'
            backup_path.write_bytes(backup_bytes)
            backup_path.chmod(0o600)
            digest = hashlib.sha256(backup_bytes).hexdigest()
            result = {"admitted":True,"package":{"baseSha256":"a"*64},
                "device":{"uid":"2000","avd":"owned-api35","api":35},
                "guard":{"controllerId":"owner","configurationRevision":4,
                         "backupSha256":digest,"backupSize":len(backup_bytes)},
                "backup":{"path":str(backup_path),"sha256":digest,"size":len(backup_bytes),
                          "type":"vpn_control_routing_rules","version":7,"rulesValid":True}}
            private(job/"result.json",{"state":"complete","result":result})
            command = [sys.executable,"-c","exec("+repr(admission._ASYNC_STATUS)+")",
                       str(root),correlation,json.dumps(intent)]
            done = subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertEqual(0,done.returncode,done.stderr)
            observed = json.loads(done.stdout)
            self.assertEqual("complete",observed["state"])
            with mock.patch.object(admission,"async_status",return_value=observed):
                self.assertTrue(admission.async_collect(root,correlation)["ok"])
            backup_path.write_bytes(b"tampered")
            altered = subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertEqual("unknown",json.loads(altered.stdout)["state"])

    def test_async_submit_kills_unreleased_worker_when_proc_identity_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o700)
            correlation = "ad399bdd-25cb-4f71-857e-34ad18ae0399"
            intent = {"correlationId":correlation}
            injection = '''
class FakeProcess:
 pid=999999999
 def kill(self): pathlib.Path(root,"killed").write_text("yes")
 def wait(self,timeout): pathlib.Path(root,"waited").write_text(str(timeout))
subprocess.Popen=lambda *args,**kwargs: FakeProcess()
'''
            source = admission._ASYNC_SUBMIT.replace("parent=pathlib.Path(root)", injection + "\nparent=pathlib.Path(root)")
            command = [sys.executable,"-c","exec("+repr(source)+")",str(parent),correlation,
                       json.dumps(intent),base64.urlsafe_b64encode(b"pass\n").decode()]
            completed = subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertEqual(0,completed.returncode,completed.stderr)
            self.assertEqual({"state":"unknown","correlationId":correlation,
                              "reason":"identity_unavailable","cleanupConfirmed":True},
                             json.loads(completed.stdout))
            self.assertEqual("yes",(parent/"killed").read_text())
            self.assertFalse((parent/("android-readback-job-"+correlation)/"release").exists())

    def test_collect_rejects_unbound_terminal_receipt(self):
        correlation = "ad399bdd-25cb-4f71-857e-34ad18ae0399"
        malformed = {"state":"complete", "correlationId":correlation,
            "receipt":{"result":{"admitted":True,"guard":{},"backup":{}}}}
        with mock.patch.object(admission,"async_status",return_value=malformed):
            self.assertFalse(admission.async_collect(".",correlation)["ok"])

    def test_async_intent_precedes_submission_and_duplicate_start_never_replays(self):
        correlation = "ad399bdd-25cb-4f71-857e-34ad18ae0399"
        profile = {"adb":"/remote/adb", "cli":"/remote/vpn-control", "serial":"emulator-5554",
                   "expectedAvd":"owned-api35", "api":35}
        configured = SimpleNamespace(android_devices={"api35":profile}, fixture_transfer_root="/private/fixtures",
                                     password="nested-gateway-credential")
        config = SimpleNamespace(hosts={"archlinux":configured})
        def safe_command(_config, _host, _timeout, command):
            self.assertTrue(all("\n" not in part and "\r" not in part for part in command))
            return ["ssh"]
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(admission.ssh_transport, "load_config", return_value=config), \
             mock.patch.object(admission.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
             mock.patch.object(admission.ssh_transport, "build_ssh_argv", side_effect=safe_command), \
             mock.patch.object(admission.android_observation, "_run_probe", return_value=(0,
                 json.dumps({"state":"submitted","correlationId":correlation,"identity":{"pid":1,"startTicks":1}}).encode())) as remote:
            first = admission.async_start(temporary,"archlinux","api35",correlation,"a"*64)
            self.assertEqual("submitted", first["state"])
            self.assertIsNotNone(admission._load_async_intent(temporary,correlation))
            with self.assertRaises(FileExistsError):
                admission.async_start(temporary,"archlinux","api35",correlation,"a"*64)
            remote.assert_called_once()

    def test_stream_probe_retains_completed_stage_on_timeout(self):
        # The previous readback lost all step evidence when the SSH command timed out.
        script = "import json,time; print(json.dumps({'stage':'uid','ok':True,'elapsedMs':1}),flush=True); time.sleep(5)"
        start = time.monotonic()
        code, stages, timed_out = admission._run_stream_probe([sys.executable,"-c",script], 1)
        self.assertTrue(timed_out)
        self.assertIsNone(code)
        self.assertEqual(["uid"],[item["stage"] for item in stages])
        self.assertLess(time.monotonic()-start, 4)

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
import json,sys,os,time
from pathlib import Path
Path(os.environ['READBACK_CALLED']).write_text('yes')
a=sys.argv[1:]
if a[-1]=='status': data={'runtimeRunning':False,'runtimeObservation':'stopped'}
elif a[-2:]==['operations','list']: data={'scope':'android-provider-operations','operations':[]}
elif a[-2:]==['routing','show']:
    if os.environ.get('READBACK_FORBID_SHOW')=='1': sys.exit(71)
    time.sleep(float(os.environ.get('READBACK_ROUTING_DELAY','0')))
    data={'routing':{'type':'vpn_control_routing_rules','version':7,'rules':{'ignore_rules':False,'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':[]}}}
elif 'export' in a:
    target=Path(a[a.index('--output')+1]); target.write_text(json.dumps({'type':'vpn_control_routing_rules','version':7,'rules':{'ignore_rules':False,'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':[]}}))
    if os.environ.get('READBACK_EXPORT_STDOUT')=='1': print('unexpected')
    print(json.dumps({'ok':True,'final':True,'code':'OK','controllerId':'owner','operationId':None,
        'configurationRevision':4,'data':{'format':'json','bytes':target.stat().st_size}}))
    sys.exit(0)
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
            accepted = subprocess.run(command, capture_output=True, text=True,
                env={**env,"READBACK_FORBID_SHOW":"1"}, timeout=15)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            result = json.loads(accepted.stdout)
            self.assertTrue(result["admitted"], result)
            backup = Path(result["backup"]["path"])
            self.assertEqual(0o600, backup.stat().st_mode & 0o777)
            self.assertEqual(4, result["guard"]["configurationRevision"])
            self.assertEqual("a" * 64, result["package"]["baseSha256"])
            self.assertNotIn("direct_domain_suffixes", accepted.stdout)
            unexpected = command.copy()
            unexpected[-3] = "1dfd0d41-dca3-4c78-970d-d8c1df65bd35"
            failed_export = subprocess.run(unexpected,capture_output=True,text=True,
                env={**env,"READBACK_EXPORT_STDOUT":"1"},timeout=15)
            self.assertEqual("readback_export_response_unknown",json.loads(failed_export.stdout)["reason"])
            preflight_command = [sys.executable, "-c", "exec(" + repr(admission._remote_preflight()) + ")",
                str(adb), str(cli), "emulator-5554", "owned-api35", "35", "30"]
            preflight = subprocess.run(preflight_command, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(0, preflight.returncode, preflight.stderr)
            stages = [json.loads(line) for line in preflight.stdout.splitlines()]
            self.assertEqual(12, len(stages), stages)
            self.assertTrue(all(step["ok"] for step in stages), stages)
            self.assertEqual("routing", stages[-1]["stage"])
            # The large native routing response exceeded the earlier 12-second
            # generic step deadline; the extended routing budget preserves it.
            delayed = subprocess.run(preflight_command, capture_output=True, text=True,
                env={**env,"READBACK_ROUTING_DELAY":"13"}, timeout=25)
            self.assertEqual(0, delayed.returncode, delayed.stderr)
            delayed_stages = [json.loads(line) for line in delayed.stdout.splitlines()]
            self.assertEqual(12, len(delayed_stages), delayed_stages)
            self.assertTrue(delayed_stages[-1]["ok"])
            status_command = [sys.executable, "-c", "exec(" + repr(admission._remote_status()) + ")",
                str(adb), str(cli), "emulator-5554", "owned-api35", "35", str(fixture), correlation, "10"]
            observed = subprocess.run(status_command, capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(0, observed.returncode, observed.stderr)
            observed_value = json.loads(observed.stdout)
            self.assertEqual("backup_present", observed_value["stage"])
            self.assertEqual("owner", observed_value["controllerId"])
            self.assertEqual(4, observed_value["configurationRevision"])
            self.assertTrue(observed_value["backup"]["formatValid"])
            self.assertEqual(0, observed_value["backup"]["domainCount"])
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
            self.assertEqual("readback_guard_unknown", json.loads(replaced.stdout)["reason"])
            self.assertTrue((fixture / "android-readback-be2fe9f4-a827-4452-bdb2-83daa9fcfb50" / "routing.json").exists())
            if sys.platform != "linux":
                return  # The detached worker's generation identity uses Linux /proc.
            async_corr = "c8b3c6b7-5e30-4f21-a02f-453c385ae57b"
            async_intent = {"host":"archlinux","device":"api35","correlationId":async_corr,
                            "expectedBaseSha256":"a"*64,"serial":"emulator-5554",
                            "expectedAvd":"owned-api35","api":35,"fixtureRoot":str(fixture)}
            async_args = [str(adb),str(cli),"emulator-5554","owned-api35","35",
                          str(fixture),async_corr,"a"*64,"60"]
            worker = admission._async_worker_source(admission._remote_probe(),async_args)
            submit_command = [sys.executable,"-c","exec("+repr(admission._ASYNC_SUBMIT)+")",
                              str(fixture),async_corr,json.dumps(async_intent),
                              base64.urlsafe_b64encode(worker.encode()).decode()]
            submitted = subprocess.run(submit_command,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual(0,submitted.returncode,submitted.stderr)
            self.assertEqual("submitted",json.loads(submitted.stdout)["state"])
            status_command = [sys.executable,"-c","exec("+repr(admission._ASYNC_STATUS)+")",
                              str(fixture),async_corr,json.dumps(async_intent,sort_keys=True,separators=(",",":"))]
            deadline = time.monotonic()+10
            while True:
                observed = subprocess.run(status_command,capture_output=True,text=True,env=env,timeout=5)
                self.assertEqual(0,observed.returncode,observed.stderr)
                status_value = json.loads(observed.stdout)
                if status_value["state"] == "complete" or time.monotonic()>deadline: break
                time.sleep(.05)
            self.assertEqual("complete",status_value["state"],status_value)
            self.assertEqual("a"*64,status_value["receipt"]["result"]["package"]["baseSha256"])
            duplicate = subprocess.run(submit_command,capture_output=True,text=True,env=env,timeout=5)
            self.assertNotEqual(0,duplicate.returncode)


if __name__ == "__main__":
    unittest.main()
