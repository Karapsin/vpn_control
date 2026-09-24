"""Pure/fake-executable regression tests for bounded Android observation."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, SOURCE / f"{name}.py")
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    assert spec.loader; spec.loader.exec_module(module); return module
transport = load("ssh_transport")
observation = load("android_observation")

class AndroidObservationTest(unittest.TestCase):
    profile = {"adb": "/remote/tools/adb", "cli": "/remote/tools/vpn-control", "serial": "emulator-5554", "expectedAvd": "api35", "api": 35}
    def setUp(self):
        self.transport_patch = mock.patch.object(observation.ssh_transport, "load_config",
            side_effect=lambda root: self.ssh_config(root))
        self.transport_patch.start()
    def tearDown(self):
        self.transport_patch.stop()
    def ssh_config(self, root):
        host = transport.SshHost(alias="android", host="127.0.0.1", port=22, user="u",
            identity_file=Path("/tmp/key"), known_hosts_file=Path("/tmp/known"))
        return transport.SshConfig(root=root, hosts={"android": host})
    def config(self, root):
        # Inventory loading is covered by ssh_transport tests.  Observation
        # tests use the validated in-memory configuration above so their pure
        # parsing behavior remains portable to Windows.
        return root
    def payload(self, **changes):
        value = {"baseline":{"uid":"2000","sdk":"35","kernelAvd":"api35","bootAvd":"api35","proxy":{name:{"state":"null","value":"null"} for name in observation._PROXY_FIELDS}}, "admitted":True,
                 "status":{"ok":True,"code":"OK","final":True,"controllerId":"owner","operationId":None}, "operations":{"ok":True,"code":"OK","final":True,"controllerId":"owner","operationId":None,"operationCount":0}}
        value.update(changes); return json.dumps(value).encode()
    def test_all_proxy_fields_and_consistent_owner_are_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.config(root)
            with mock.patch.object(observation, "_run_probe", return_value=(0,self.payload())):
                result=observation.observe(root,"android",self.profile)
        self.assertEqual("available",result["outcome"]); self.assertEqual(set(observation._PROXY_FIELDS),set(result["baseline"]["proxy"]))
    def test_owner_replacement_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.config(root); payload=json.loads(self.payload()); payload["operations"]["controllerId"]="replacement"
            with mock.patch.object(observation,"_run_probe",return_value=(0,json.dumps(payload).encode())): result=observation.observe(root,"android",self.profile)
        self.assertEqual(("unknown","owner_replaced"),(result["outcome"],result["reason"]))
    def test_unsuccessful_but_well_typed_cli_envelope_is_not_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.config(root); payload=json.loads(self.payload()); payload["status"]["ok"]=False; payload["status"]["code"]="CONNECTIVITY"
            with mock.patch.object(observation,"_run_probe",return_value=(0,json.dumps(payload).encode())): result=observation.observe(root,"android",self.profile)
        self.assertEqual((False,"unavailable","cli_unsuccessful"),(result["available"],result["outcome"],result["reason"]))
    def test_malformed_data_envelope_remains_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.config(root); payload=json.loads(self.payload()); payload["operations"]["operationCount"] = None
            with mock.patch.object(observation,"_run_probe",return_value=(0,json.dumps(payload).encode())): result=observation.observe(root,"android",self.profile)
        self.assertEqual(("unknown","cli_observation_failed"),(result["outcome"],result["reason"]))
    def test_transport_and_unknown_cli_outcomes_are_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); self.config(root)
            with mock.patch.object(observation,"_run_probe",side_effect=RuntimeError("transport_unavailable")): transport_result=observation.observe(root,"android",self.profile)
            with mock.patch.object(observation,"_run_probe",return_value=(0,self.payload(status=None))): cli_result=observation.observe(root,"android",self.profile)
        self.assertEqual("transport_unavailable",transport_result["reason"]); self.assertEqual("cli_observation_failed",cli_result["reason"])
    def test_pure_observation_remains_usable_when_windows_inventory_loading_is_unsupported(self):
        # ssh_transport itself rejects native Windows private-inventory reads.
        # The MCP owner supplies the validated profile/configuration; this
        # parser must still classify a bounded observer result on Windows.
        with mock.patch.object(observation.os, "name", "nt"), mock.patch.object(observation, "_remote_probe", return_value="print('fixed')"), mock.patch.object(observation, "_run_probe", return_value=(0, self.payload())):
            result = observation.observe(Path("/workspace"), "android", self.profile)
        self.assertEqual((True, "available"), (result["available"], result["outcome"]))
    def test_invalid_profile_rejects_before_transport(self):
        with mock.patch.object(observation.ssh_transport,"load_config") as config:
            with self.assertRaisesRegex(observation.AndroidObservationError,"serial"): observation.observe(".","android",{**self.profile,"serial":"device"})
            with self.assertRaisesRegex(observation.AndroidObservationError,"packaged"):
                observation.observe(".","android",{**self.profile,"cli":"/remote/tools/adapter.py"})
        config.assert_not_called()
    @unittest.skipUnless(os.name == "posix", "fixed remote probe uses POSIX fake executables")
    def test_wrong_uid_avd_or_api_reject_before_public_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adb = root / "adb"; cli = root / "vpn-control"; called = root / "cli-called"
            adb.write_text("#!/usr/bin/env python3\nimport sys\nprint('1000' if sys.argv[-2:]==['id','-u'] else '35' if sys.argv[-1]=='ro.build.version.sdk' else 'api35' if sys.argv[-1].endswith('avd_name') else 'null')\n")
            cli.write_text("#!/bin/sh\ntouch \"" + str(called) + "\"\nexit 9\n")
            adb.chmod(0o700); cli.chmod(0o700)
            with mock.patch.object(sys, "argv", ["probe", str(adb), str(cli), "emulator-5554", "api35", "35", "2"]), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit): exec(observation._remote_probe(), {})
            self.assertFalse(called.exists())
    @unittest.skipUnless(os.name == "posix", "fixed remote probe uses POSIX fake executables")
    def test_remote_probe_uses_canonical_pinned_adb_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adb = root / "adb"; cli = root / "vpn-control"; evidence = root / "evidence"
            adb.write_text("#!/usr/bin/env python3\nimport sys\nword=sys.argv[-1]\nprint('2000' if sys.argv[-2:]==['id','-u'] else '35' if word=='ro.build.version.sdk' else 'api35' if word.endswith('avd_name') else 'null')\n")
            cli.write_text("#!/usr/bin/env python3\nimport json,os,shutil,sys\nopen(" + repr(str(evidence)) + ", 'w').write(shutil.which('adb') or '')\nprint(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':'owner','data':{'operations':[]}}))\n")
            adb.chmod(0o700); cli.chmod(0o700)
            stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["probe", str(adb), str(cli), "emulator-5554", "api35", "35", "2"]), contextlib.redirect_stdout(stdout): exec(observation._remote_probe(), {})
            self.assertTrue(os.path.samefile(adb, evidence.read_text()))
            self.assertEqual("owner", json.loads(stdout.getvalue())["status"]["controllerId"])
    @unittest.skipUnless(os.name == "posix", "fixed remote probe uses POSIX fake executables")
    def test_arbitrary_proxy_value_is_categorical_and_does_not_leak(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adb = root / "adb"; cli = root / "vpn-control"
            adb.write_text("#!/usr/bin/env python3\nimport sys\nword=sys.argv[-1]\nprint('2000' if sys.argv[-2:]==['id','-u'] else '35' if word=='ro.build.version.sdk' else 'api35' if word.endswith('avd_name') else 'http://user:secret@example.test:8080')\n")
            cli.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':'owner','data':{'operations':[]}}))\n")
            adb.chmod(0o700); cli.chmod(0o700); stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["probe", str(adb), str(cli), "emulator-5554", "api35", "35", "2"]), contextlib.redirect_stdout(stdout): exec(observation._remote_probe(), {})
            result = json.loads(stdout.getvalue()); self.assertEqual({"state":"set"}, result["baseline"]["proxy"]["http_proxy"])
            self.assertNotIn("secret", stdout.getvalue())
    @unittest.skipUnless(os.name == "posix", "fixed remote probe uses POSIX fake executables")
    def test_loopback_proxy_is_preserved_by_actual_remote_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adb = root / "adb"; cli = root / "vpn-control"
            adb.write_text("#!/usr/bin/env python3\nimport sys\nword=sys.argv[-1]\nprint('2000' if sys.argv[-2:]==['id','-u'] else '35' if word=='ro.build.version.sdk' else 'api35' if word.endswith('avd_name') else '127.0.0.1:45390')\n")
            cli.write_text("#!/usr/bin/env python3\nimport json\nprint(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':'owner','data':{'operations':[]}}))\n")
            adb.chmod(0o700); cli.chmod(0o700); stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["probe", str(adb), str(cli), "emulator-5554", "api35", "35", "2"]), contextlib.redirect_stdout(stdout): exec(observation._remote_probe(), {})
            self.assertEqual({"state":"loopback","value":"127.0.0.1:45390"}, json.loads(stdout.getvalue())["baseline"]["proxy"]["http_proxy"])
    @unittest.skipUnless(os.name == "posix", "fixed remote probe uses POSIX fake executables")
    def test_nonzero_public_cli_keeps_its_bounded_json_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); adb = root / "adb"; cli = root / "vpn-control"
            adb.write_text("#!/usr/bin/env python3\nimport sys\nword=sys.argv[-1]\nprint('2000' if sys.argv[-2:]==['id','-u'] else '35' if word=='ro.build.version.sdk' else 'api35' if word.endswith('avd_name') else 'null')\n")
            cli.write_text("#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps({'ok':False,'code':'CONNECTIVITY','final':True,'controllerId':'owner','data':{'operations':[]}}))\nraise SystemExit(1)\n")
            adb.chmod(0o700); cli.chmod(0o700); stdout = io.StringIO()
            with mock.patch.object(sys, "argv", ["probe", str(adb), str(cli), "emulator-5554", "api35", "35", "2"]), contextlib.redirect_stdout(stdout): exec(observation._remote_probe(), {})
            result = json.loads(stdout.getvalue()); self.assertFalse(result["status"]["ok"]); self.assertEqual("CONNECTIVITY", result["operations"]["code"])

if __name__ == "__main__": unittest.main()
