"""Causal regressions for CP117 owner-liveness observation."""

import base64
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import TestCase, mock

from agent_tools import windows_msi_owner_liveness as liveness


class OwnerLivenessTests(TestCase):
    def test_absence_requires_complete_census_and_runtime_off(self):
        absent = {"version": 1, "state": "absent", "ownerProcesses": "none", "installerProcesses": "none",
                  "consentProcesses": "none", "runtimeProcesses": "none", "stateLeaves": "none", "runtimeOff": True}
        result = liveness._project(json.dumps(absent).encode(), "a" * 40)
        self.assertEqual(result["state"], "absent")
        for changed in ({"ownerProcesses": "one"}, {"installerProcesses": "one"}, {"consentProcesses": "many"},
                        {"runtimeProcesses": "one", "runtimeOff": False}, {"stateLeaves": "one"}, {"runtimeOff": False}):
            with self.subTest(changed=changed):
                self.assertEqual(liveness._project(json.dumps({**absent, **changed}).encode(), "a" * 40), liveness._UNKNOWN)

    def test_static_source_and_qga_binding_precede_remote_census(self):
        descriptor = ("windows-cp117", "/private/qga.sock", 100, 200, "S-1-5-21-1-2-3-1002")
        intent = {"environment": descriptor[0], "socketPath": descriptor[1], "pid": 100, "startTicks": 200,
                  "expectedSid": descriptor[4], "request": {"correlationId": liveness._CORRELATION, "sourceSha": "a" * 40},
                  "pair": {"sourceSha": "a" * 40, "baseVersion": "2.1.19", "baseCliSha256": "c" * 64}}
        raw = b'{"version":1,"state":"blocked","ownerProcesses":"none","installerProcesses":"none","consentProcesses":"none","runtimeProcesses":"none","stateLeaves":"one","runtimeOff":true}'
        with (mock.patch.object(liveness.base, "_private_intent", return_value=intent),
              mock.patch.object(liveness.base, "_descriptor", return_value=(object(), SimpleNamespace(), descriptor)),
              mock.patch.object(liveness.base, "_stage_artifact_readonly", return_value=(intent["pair"], 1)),
              mock.patch.object(liveness.base, "_remote", return_value=raw) as remote):
            self.assertEqual(liveness.observe(Path.cwd(), {"host": "archlinux"})["state"], "blocked")
            intent["startTicks"] = 201
            self.assertEqual(liveness.observe(Path.cwd(), {"host": "archlinux"}), liveness._UNKNOWN)
            self.assertEqual(remote.call_count, 1)

    def test_guest_census_is_read_only_and_rejects_truncated_output(self):
        script = liveness._LIVENESS_PS
        for required in ("vpn-control.exe", "vpn-control-cli.exe", "msiexec.exe", "consent.exe", "sing-box.exe",
                         "vpn-control.lock", "activation.port", "Get-CimInstance Win32_Process"):
            self.assertIn(required, script)
        self.assertNotIn("Start-Process", script)
        self.assertNotIn("Stop-Process", script)
        compile(liveness._REMOTE, "owner-liveness-remote", "exec")
        stub = '''import base64,json,sys
def live(*args):return True
def decode(value):return value.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if 'Stop-Process' in script or 'Get-CimInstance Win32_Process' not in script:raise ValueError('unexpected script')
  return {'pid':42}
 if command=='guest-exec-status':return {'exited':True,'exitcode':0,'out-truncated':True,'out-data':''}
 raise ValueError('unexpected QGA action')
'''
        program = stub + liveness._REMOTE[len(liveness.base._QGA):]
        run = subprocess.run([sys.executable, "-c", program, "/private/qga.sock", "100", "200",
                              "S-1-5-21-1-2-3-1002", "c" * 64], capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(run.stdout), {"version": 1, "state": "unknown"})

    def test_blocked_census_and_input_do_not_authorize_action_or_expose_identity(self):
        value = {"version": 1, "state": "blocked", "ownerProcesses": "ambiguous", "installerProcesses": "none",
                 "consentProcesses": "none", "runtimeProcesses": "none", "stateLeaves": "none", "runtimeOff": True}
        result = liveness._project(json.dumps(value).encode(), "a" * 40)
        self.assertEqual(result["state"], "blocked")
        self.assertFalse(result["nativeActionAllowed"])
        self.assertNotIn("pid", result)
        self.assertNotIn("path", result)
        with self.assertRaises(liveness.WindowsMsiOwnerLivenessError):
            liveness.observe(Path.cwd(), {"host": "archlinux", "launch": True})
