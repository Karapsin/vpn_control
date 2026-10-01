"""Fixed, read-only CP117 owner identity census."""

import base64
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest import TestCase, mock

from agent_tools import windows_msi_owner_census as census


class OwnerCensusTests(TestCase):
    def test_absent_or_mismatched_owner_cannot_supply_identity(self):
        descriptor = ("windows-cp117", "/private/cp117.qga", 100, 200, "S-1-5-21-1-2-3-1002")
        intent = {"environment": descriptor[0], "socketPath": descriptor[1], "pid": 100,
                  "startTicks": 200, "expectedSid": descriptor[4],
                  "request": {"correlationId": census._BASE_CORRELATION, "sourceSha": "a" * 40,
                              "baseMsiArtifactId": "sha256-" + "b" * 64},
                  "pair": {"sourceSha": "a" * 40, "baseVersion": "2.1.19",
                           "baseCliSha256": "c" * 64}}
        product = {"state": "blocked", "installedVersion": "2.1.19", "productCount": 1}
        target = SimpleNamespace(fixture_transfer_root=Path("/private/transfer"))
        with (mock.patch.object(census.base, "_private_intent", return_value=intent),
              mock.patch.object(census.base, "_stage_artifact_readonly", return_value=(intent["pair"], 123)),
              mock.patch.object(census.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(census.base, "readiness", return_value=product),
              mock.patch.object(census.base, "_remote", return_value=json.dumps({"state": "unknown"}).encode())):
            self.assertEqual(census.workflow(Path.cwd(), {"host": "archlinux"})["state"], "unknown")
        intent["startTicks"] = 201
        with (mock.patch.object(census.base, "_private_intent", return_value=intent),
              mock.patch.object(census.base, "_stage_artifact_readonly", return_value=(intent["pair"], 123)),
              mock.patch.object(census.base, "_descriptor", return_value=(object(), target, descriptor)),
              mock.patch.object(census.base, "_remote") as remote):
            self.assertEqual(census.workflow(Path.cwd(), {"host": "archlinux"})["state"], "unknown")
            remote.assert_not_called()

    def test_exact_observation_and_poisoned_public_output(self):
        value = {"version": 1, "state": "observed",
                 "controllerId": "11111111-1111-4111-8111-111111111111",
                 "parentPid": 5000, "parentStartedAtUtc": "2026-09-30T03:45:00.0000000Z",
                 "childPid": 5520, "childStartedAtUtc": "2026-09-30T03:45:01.0000000Z",
                 "installedCliSha256": "c" * 64, "runtimeRunning": False}
        result = census._project(json.dumps(value).encode(), "a" * 40, "c" * 64)
        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["sourceSha"], "a" * 40)
        self.assertEqual(result["childPid"], 5520)
        self.assertNotIn("path", result)
        for poison in (dict(value, controllerId="invalid"), dict(value, parentPid=5520),
                       dict(value, runtimeRunning=True), dict(value, rawCommand="secret")):
            self.assertEqual(census._project(json.dumps(poison).encode(), "a" * 40, "c" * 64),
                             census._UNKNOWN)

    def test_fixed_guest_probe_is_read_only_and_parseable(self):
        script = census._CENSUS_PS
        self.assertIn("$stateAcl.GetAccessRules", script)
        self.assertIn("$directoryAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')", script)
        self.assertIn("$rule.IdentityReference.Value -notin $directoryAllowedSids", script)
        self.assertIn("$rule.IdentityReference.Value -ceq $sid", script)
        self.assertIn("[Security.AccessControl.FileSystemRights]::CreateFiles", script)
        self.assertIn("Get-CimInstance Win32_Process", script)
        self.assertIn("--controller-id $controller", script)
        self.assertIn("status 2>$null", script)
        self.assertNotIn("Stop-Process", script)
        self.assertNotIn(" quit ", script)
        self.assertNotIn(" updates install ", script)
        self.assertIn("Parser]::ParseInput", census._preflight_script())
        self.assertLess(len(base64.b64encode(census._preflight_script().encode("utf-16le"))), 30000)
        compile(census._REMOTE, "_REMOTE", "exec")
        with self.assertRaises(census.WindowsMsiOwnerCensusError):
            census.workflow(Path.cwd(), {"host": "archlinux", "controllerId": "caller-claim"})

    def test_directory_allows_only_trusted_windows_maintenance_aces(self):
        """RED→GREEN: CP117's SYSTEM/Administrators directory ACEs no longer block the census."""
        script = census._CENSUS_PS
        self.assertIn("$directoryAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')", script)
        self.assertIn("if($rule.IdentityReference.Value -notin $directoryAllowedSids) { throw 'STATE_ACL' }", script)
        self.assertIn("if($rule.IdentityReference.Value -ceq $sid) {", script)
        # The original user alone must still supply the directory capabilities.
        owner_gate = script.split("if($rule.IdentityReference.Value -ceq $sid) {", 1)[1]
        self.assertIn("ListDirectory", owner_gate)
        self.assertIn("CreateFiles", owner_gate)
        # Lock and endpoint files allow only owner plus fixed Windows maintenance identities.
        file_acl = script.split("foreach($path in @($lockPath,$endpointPath))", 1)[1]
        self.assertIn("$fileAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')", file_acl)
        self.assertIn("if($rule.IdentityReference.Value -notin $fileAllowedSids) { throw 'STATE_ACL' }", file_acl)
        self.assertIn("if($rule.IdentityReference.Value -ceq $sid) {", file_acl)
        self.assertNotIn("directoryAllowedSids", file_acl)

    def test_lock_and_endpoint_allow_only_trusted_windows_aces(self):
        """RED→GREEN: normal SYSTEM/Admin entries cannot block owner-private CP117 files."""
        script = census._CENSUS_PS
        file_acl = script.split("foreach($path in @($lockPath,$endpointPath))", 1)[1]
        self.assertIn("$fileAllowedSids=@($sid,'S-1-5-18','S-1-5-32-544')", file_acl)
        self.assertIn("if($rule.IdentityReference.Value -notin $fileAllowedSids) { throw 'STATE_ACL' }", file_acl)
        owner_gate = file_acl.split("if($rule.IdentityReference.Value -ceq $sid) {", 1)[1]
        self.assertIn("ReadData", owner_gate)
        # The fixed allow list still rejects every other nonzero Allow ACE.
        self.assertNotIn("-notin $fileAllowedSids){$ownerRead", file_acl)

    def test_fake_qga_rejects_untrusted_directory_acl_and_terminal_failures(self):
        """The actual remote observer cannot promote a failed guest proof."""
        for kind in ("untrusted-state-dacl", "truncated", "malformed"):
            with self.subTest(kind=kind):
                stub = '''import base64,json,sys
def live(*args):return True
def decode(value):return value.decode()
def call(sock,command,args):
 if command=='guest-exec':
  script=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if "'S-1-5-18','S-1-5-32-544'" not in script or '$stateCreate' not in script:raise ValueError('directory ACL guard absent')
  return {'pid':42}
 if command=='guest-exec-status':
  if args!={'pid':42}:raise ValueError('foreign status pid')
  if KIND=='untrusted-state-dacl':return {'exited':True,'exitcode':1,'out-data':base64.b64encode(b'{"version":1,"state":"unknown"}').decode()}
  if KIND=='truncated':return {'exited':True,'exitcode':0,'out-truncated':True,'out-data':''}
  return {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'bad-json').decode()}
 raise ValueError('unexpected QGA effect')
'''.replace("KIND", repr(kind))
                program = stub + census._REMOTE[len(census.base._QGA):]
                run = subprocess.run([sys.executable, "-c", program, "/private/cp117.qga", "100", "200",
                                      "S-1-5-21-1-2-3-1002", "c" * 64],
                                     capture_output=True, timeout=10, check=False)
                self.assertEqual(run.returncode, 0, run.stderr.decode(errors="replace"))
                self.assertEqual(json.loads(run.stdout), {"version": 1, "state": "unknown"})
