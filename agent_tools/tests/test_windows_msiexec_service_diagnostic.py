"""Read-only CP117 Windows Installer service classification regressions."""

import base64
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import TestCase, mock

from agent_tools import windows_msiexec_service_diagnostic as diagnostic


class ServiceDiagnosticTests(TestCase):
    def test_terminal_pass_with_persistent_service_is_a_candidate_not_readiness(self):
        observed = {"state": "observed", "process": "exact", "service": "bound-running",
                    "commandShape": "service-switch", "otherInstallers": "none",
                    "transaction": "none-observed", "classification": "service-idle-candidate"}
        self.assertEqual(diagnostic._project(json.dumps(observed).encode())["classification"],
                         "service-idle-candidate")
        self.assertFalse(diagnostic._project(json.dumps(observed).encode())["readinessAdmitted"])
        self.assertEqual(diagnostic._project(json.dumps(dict(observed, commandLine="secret")).encode()),
                         diagnostic._UNKNOWN)
        active = dict(observed, otherInstallers="one", transaction="evidence-present",
                      classification="active-transaction-evidence")
        self.assertEqual(diagnostic._project(json.dumps(active).encode())["classification"],
                         "active-transaction-evidence")
        poisoned = dict(active, classification="service-idle-candidate")
        self.assertEqual(diagnostic._project(json.dumps(poisoned).encode()), diagnostic._UNKNOWN)

    def test_workflow_binds_fixed_correlation_source_and_qemu_generation(self):
        intent = {"environment": "windows-cp117", "socketPath": "/private/qga.sock",
                  "pid": 100, "startTicks": 200, "expectedSid": "S-1-5-21-1-2-3-1002",
                  "request": {"correlationId": diagnostic._CORRELATION, "sourceSha": "a" * 40},
                  "pair": {"sourceSha": "a" * 40, "baseVersion": "2.1.19"}}
        descriptor = ("windows-cp117", "/private/qga.sock", 100, 200, "S-1-5-21-1-2-3-1002")
        terminal = {"state": "terminal", "result": "PASSED", "stage": "READBACK", "exitCode": 0,
                    "sourceSha": "a" * 40, "baseArtifactId": "sha256-" + "b" * 64,
                    "installedVersion": "2.1.19"}
        intent["request"]["baseMsiArtifactId"] = terminal["baseArtifactId"]
        raw = b'{"state":"observed","process":"exact","service":"bound-running",' \
              b'"commandShape":"service-switch","otherInstallers":"none",' \
              b'"transaction":"none-observed","classification":"service-idle-candidate"}'
        with (mock.patch.object(diagnostic.base, "_private_intent", return_value=intent),
              mock.patch.object(diagnostic.base, "_descriptor", return_value=(object(), SimpleNamespace(), descriptor)),
              mock.patch.object(diagnostic.base, "status", return_value=terminal),
              mock.patch.object(diagnostic.base, "_remote", return_value=raw) as remote):
            result = diagnostic.workflow(Path.cwd(), "status", {"host": "archlinux"})
            self.assertEqual(result["classification"], "service-idle-candidate")
            self.assertEqual(result["correlationId"], diagnostic._CORRELATION)
            self.assertEqual(result["sourceSha"], "a" * 40)
            remote.assert_called_once()
            intent["startTicks"] = 201
            self.assertEqual(diagnostic.workflow(Path.cwd(), "status", {"host": "archlinux"}),
                             diagnostic._UNKNOWN)
            self.assertEqual(remote.call_count, 1)

    def test_fixed_identity_and_preflight_are_no_effect(self):
        self.assertIn("2026-09-30T03:16:29.4825590Z", diagnostic._PROCESS_PS)
        self.assertIn("ProcessId=1932", diagnostic._PROCESS_PS)
        self.assertIn("msiserver", diagnostic._PROCESS_PS)
        self.assertNotIn("Stop-Process", diagnostic._PROCESS_PS)
        self.assertNotIn("sc.exe", diagnostic._PROCESS_PS)
        self.assertIn("Parser]::ParseInput", diagnostic._preflight_script())
        self.assertLess(len(base64.b64encode(diagnostic._preflight_script().encode("utf-16le"))), 30000)
        compile(diagnostic._REMOTE, "_REMOTE", "exec")
        for bad in ({"host": "other"}, {"host": "archlinux", "pid": 1932}):
            with self.assertRaises(diagnostic.ServiceDiagnosticError):
                diagnostic.workflow(Path.cwd(), "status", bad)
        with self.assertRaises(diagnostic.ServiceDiagnosticError):
            diagnostic.workflow(Path.cwd(), ["status"], {"host": "archlinux"})

    def test_fake_qga_projection_never_returns_raw_command_or_pid(self):
        observed = {"state": "observed", "process": "exact", "service": "bound-running",
                    "commandShape": "service-switch", "otherInstallers": "none",
                    "transaction": "none-observed", "classification": "service-idle-candidate"}
        stub = '''import base64,json,sys
def live(*args):return True
def decode(raw):return raw.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if 'ProcessId=1932' not in script or '2026-09-30T03:16:29.4825590Z' not in script:raise ValueError('unbound process')
  if 'Stop-Process' in script or 'Restart-Service' in script:raise ValueError('effect command')
  return {'pid':100}
 if command=='guest-exec-status':
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(OUTPUT).decode()}
 raise ValueError('unexpected QGA action')
'''.replace("OUTPUT", repr(json.dumps(observed).encode()))
        program = stub + diagnostic._REMOTE[len(diagnostic.base._QGA):]
        run = subprocess.run([sys.executable, "-c", program, "/private/qga.sock", "100", "200"],
                             capture_output=True, timeout=10, check=False)
        self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
        self.assertEqual(json.loads(run.stdout), observed)
        self.assertEqual(diagnostic._project(run.stdout)["classification"], "service-idle-candidate")
