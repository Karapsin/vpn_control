from __future__ import annotations

import base64
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_tools import windows_cp117_c32_absence as absence


C32 = "c32cb108-4d48-407e-9153-40774559ba50"
DESC = ("windows-cp117", "/private/c32.qga", 77, 88, "S-1-5-21-1-2-3-1002")
RECORD = {"correlationId": C32, "environment": DESC[0], "socketPath": DESC[1], "qemuPid": DESC[2],
          "startTicks": DESC[3], "expectedSid": DESC[4], "sourceSha": "a" * 40,
          "baseMsiArtifactId": "sha256-" + "b" * 64, "routeNonce": "a" * 43,
          "sha256": "b" * 64, "length": 1, "artifactPath": "/private/base.msi"}
INTENT = {"leaseId": C32, "request": {"correlationId": C32, "sourceSha": "a" * 40,
          "baseMsiArtifactId": "sha256-" + "b" * 64, "expectedCurrentVersion": "2.1.17"},
          "pair": {"baseArtifactId": "sha256-" + "b" * 64, "baseVersion": "2.1.19", "baseCliSha256": "c" * 64,
                   "baseAppJarSha256": "d" * 64, "baseHelperSha256": "e" * 64,
                   "baseAppJarName": "desktopApp-test.jar"},
          "environment": DESC[0], "socketPath": DESC[1],
          "pid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4]}
RECEIPT = {"baseTask": "absent", "transferTask": "absent", "guestLeaf": "absent",
           "baseMsi": "absent", "correlationProcess": "absent"}
PRODUCT = {"version": "2.1.19", "productCode": "{11111111-1111-1111-1111-111111111111}",
           "installLocation": "C:\\Users\\vpncp117\\AppData\\Local\\vpn-control\\", "hive": "HKCU"}
PRIOR = {**PRODUCT, "version": "2.1.17"}
PAYLOAD = {"version": 1, "correlationId": C32, "stage": "READBACK", "result": "PASSED", "exitCode": 0,
           "originalSid": DESC[4], "sessionId": 1, "limited": True, "msiSha256": "b" * 64,
           "installedVersion": "2.1.19", "cliSha256": "c" * 64, "jarSha256": "d" * 64,
           "helperSha256": "e" * 64, "priorProducts": [PRIOR], "installedProducts": [PRODUCT]}


class C32AbsenceTests(unittest.TestCase):
    def _observe(self, payload):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", return_value=payload) as remote:
            result = absence.observe(Path(directory), object(), target, DESC)
        return result, remote

    def test_red_task_inventory_failure_never_promotes_absence(self):
        result, _remote = self._observe(json.dumps({"state": "unknown"}).encode())
        self.assertEqual("unknown", result["state"])

    def test_green_exact_absence_is_bounded_and_uses_stop_enumeration(self):
        result, remote = self._observe(json.dumps({"state": "observed", "receipt": RECEIPT}).encode())
        self.assertEqual({"state": "observed", **RECEIPT, "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}, result)
        script = absence._script(C32)
        self.assertIn("Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop", script)
        self.assertIn("VpnControlMcpTransfer", script)
        self.assertNotIn("SilentlyContinue", script)
        self.assertEqual((DESC[1], str(DESC[2]), str(DESC[3])), remote.call_args.args[2][:3])

    def test_malformed_or_extra_remote_output_is_unknown(self):
        for payload in (
            json.dumps({"state": "observed", "receipt": {**RECEIPT, "path": "leak"}}).encode(),
            json.dumps({"state": "observed", "receipt": {**RECEIPT, "baseTask": "maybe"}}),
            json.dumps({"state": "observed", "receipt": RECEIPT, "extra": True}).encode(),
            "not-json",
        ):
            with self.subTest(payload=payload):
                result, _remote = self._observe(payload)
                self.assertEqual("unknown", result["state"])

    def test_generation_or_historical_binding_mismatch_prevents_remote_read(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        bad = {**RECORD, "qemuPid": 99}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=bad), \
             patch.object(absence.base, "_remote") as remote:
            result = absence.observe(Path(directory), object(), target, DESC)
        self.assertEqual("unknown", result["state"])
        remote.assert_not_called()

    def test_script_rejects_nonfixed_correlation_and_uses_valid_subexpressions(self):
        with self.assertRaises(ValueError):
            absence._script("a32cb108-4d48-407e-9153-40774559ba50")
        script = absence._script(C32)
        self.assertIn("$leafState=$(if(", script)
        self.assertIn("$processState=$(if(", script)

    def test_qga_wrapper_rejects_exit_truncation_and_malformed_inventory(self):
        body = "import base64,json,sys,time" + absence._REMOTE.split("import base64,json,sys,time", 1)[1]

        def run(status):
            calls = iter(({"pid": 12}, status))
            scope = {"live": lambda *_: True, "call": lambda *_: next(calls),
                     "decode": lambda raw: raw.decode("utf-8")}
            output = io.StringIO()
            with patch.object(sys, "argv", ["remote", "/qga", "77", "88", "encoded"]), contextlib.redirect_stdout(output):
                exec(body, scope)
            return json.loads(output.getvalue())

        valid = base64.b64encode(json.dumps(RECEIPT).encode()).decode()
        self.assertEqual({"state": "observed", "receipt": RECEIPT}, run({"exited": True, "exitcode": 0, "out-data": valid,
                                                                                "out-truncated": False, "err-truncated": False}))
        for status in (
            {"exited": True, "exitcode": 1, "out-data": valid, "out-truncated": False, "err-truncated": False},
            {"exited": True, "exitcode": 0, "out-data": valid, "out-truncated": True, "err-truncated": False},
            {"exited": True, "exitcode": 0, "out-data": base64.b64encode(b'{"baseTask":"absent"}').decode(), "out-truncated": False, "err-truncated": False},
        ):
            with self.subTest(status=status):
                self.assertEqual({"state": "unknown"}, run(status))

    def test_retained_payload_requires_exact_readback_and_historical_products(self):
        self.assertTrue(absence._valid_retained_payload(PAYLOAD, INTENT))
        for changed in ({"stage": "INSTALL"}, {"exitCode": False}, {"limited": False},
                        {"installedProducts": []}, {"helperSha256": "0" * 64}):
            with self.subTest(changed=changed):
                self.assertFalse(absence._valid_retained_payload({**PAYLOAD, **changed}, INTENT))

    def test_retained_terminal_never_exposes_or_promotes_malformed_receipt(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        parsed = json.dumps({"state": "observed", "phase": "ast", "strict": "passed", "diagnostic": "passed"}).encode()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", side_effect=(parsed, json.dumps({"state": "observed", "receipt": PAYLOAD}).encode())):
            self.assertEqual({"state": "retained-terminal", "replayAllowed": False,
                              "nativeActionAllowed": False, "productAction": False},
                             absence.retained_terminal(Path(directory), object(), target, DESC))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", side_effect=(parsed, json.dumps({"state": "observed", "receipt": {**PAYLOAD, "stage": "INSTALL"}}).encode())):
            self.assertEqual("unknown", absence.retained_terminal(Path(directory), object(), target, DESC)["state"])

    def test_retained_diagnostic_projects_only_known_guard_codes(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        parsed = b'{"state":"observed","phase":"ast","strict":"passed","diagnostic":"passed"}'
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", side_effect=(parsed, b'{"guard":"TASK"}')):
            self.assertEqual({"state": "diagnosed", "guard": "runtime-error", "replayAllowed": False,
                              "nativeActionAllowed": False, "productAction": False, "phase": "transport"},
                             absence.diagnose_retained(Path(directory), object(), target, DESC))
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", side_effect=(parsed, b'{"state":"observed","guard":"TASK","phase":"task"}')):
            self.assertEqual({"state": "diagnosed", "guard": "TASK", "replayAllowed": False,
                              "nativeActionAllowed": False, "productAction": False, "phase": "task"},
                             absence.diagnose_retained(Path(directory), object(), target, DESC))

    def test_retained_diagnostic_script_shares_terminal_guards_without_receipt_output(self):
        source = absence._retained_script(INTENT, diagnostic=True)
        self.assertIn("throw 'RESULT_JSON'", source)
        self.assertIn("'TASK_INFO'", source)
        task_guards = ("TASK_COUNT", "TASK_STATE", "TASK_ACTION_COUNT", "TASK_EXEC", "TASK_TRIGGER_COUNT")
        for guard in task_guards:
            self.assertIn("throw '" + guard + "'", source)
        self.assertLess(source.index("throw 'TASK_COUNT'"), source.index("throw 'TASK_STATE'"))
        self.assertLess(source.index("throw 'TASK_STATE'"), source.index("throw 'TASK_ACTION_COUNT'"))
        self.assertLess(source.index("throw 'TASK_ACTION_COUNT'"), source.index("throw 'TASK_EXEC'"))
        self.assertLess(source.index("throw 'TASK_EXEC'"), source.index("throw 'TASK_TRIGGER_COUNT'"))
        self.assertNotIn("if($tasks.Count -ne 1 -or", source)
        self.assertIn("$triggers=@($task.Triggers)", source)
        self.assertIn(absence._trigger_guard_powershell(), source)
        self.assertNotIn("throw 'TASK_TRIGGER_NULL'", source)
        self.assertIn("'runtime-error'", source)
        self.assertIn("$phase='task'", source)
        self.assertIn("$phase='result'", source)
        self.assertIn("Parent.Parent))){if(-not ($node -is [IO.DirectoryInfo])", source)
        self.assertNotIn("Parent.Parent)){if(-not $node.PSIsContainer", source)
        self.assertNotIn("@{result=$result}|ConvertTo-Json", source)

    def test_parser_gate_prevents_terminal_or_diagnostic_observer_after_ast_failure(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        failed = b'{"state":"observed","phase":"ast","strict":"failed","diagnostic":"failed"}'
        for action in (absence.retained_terminal, absence.diagnose_retained):
            with self.subTest(action=action.__name__), tempfile.TemporaryDirectory() as directory, \
                 patch.object(absence.base, "_private_intent", return_value=INTENT), \
                 patch.object(absence.transfer, "_intent", return_value=RECORD), \
                 patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
                 patch.object(absence.base, "_remote", return_value=failed) as remote:
                result = action(Path(directory), object(), target, DESC)
            self.assertNotEqual("retained-terminal", result["state"])
            self.assertEqual(1, remote.call_count)
            self.assertEqual(absence._RETAINED_PARSE_REMOTE, remote.call_args.args[1])

    def test_retained_diagnostic_qga_wrapper_forwards_only_recognized_guard(self):
        body = "import base64,json,sys,time" + absence._RETAINED_DIAG_REMOTE.split("import base64,json,sys,time", 1)[1]

        def run(payload):
            calls = iter(({"pid": 12}, {"exited": True, "exitcode": 0,
                                       "out-data": base64.b64encode(payload).decode(),
                                       "out-truncated": False, "err-truncated": False}))
            scope = {"live": lambda *_: True, "call": lambda *_: next(calls),
                     "decode": lambda raw: raw.decode("utf-8")}
            output = io.StringIO()
            with patch.object(sys, "argv", ["remote", "/qga", "77", "88", "encoded"]), contextlib.redirect_stdout(output):
                exec(body, scope)
            return json.loads(output.getvalue())

        self.assertEqual({"state": "observed", "guard": "TASK", "phase": "task"},
                         run(b'{"guard":"TASK","phase":"task"}'))
        for guard in ("TASK_COUNT", "TASK_STATE", "TASK_ACTION_COUNT", "TASK_EXEC", "TASK_TRIGGER_NULL", "TASK_TRIGGER_COUNT"):
            with self.subTest(guard=guard):
                self.assertEqual({"state": "observed", "guard": guard, "phase": "task"},
                                 run(json.dumps({"guard": guard, "phase": "task"}).encode()))
        for guard in ("RESULT_UTF8_BOM", "RESULT_UTF16_LE", "RESULT_UTF16_BE", "RESULT_JSON"):
            with self.subTest(guard=guard):
                self.assertEqual({"state": "observed", "guard": guard, "phase": "result"},
                                 run(json.dumps({"guard": guard, "phase": "result"}).encode()))
        self.assertEqual({"state": "unknown", "phase": "json-shape"}, run(b'{"guard":"TASK"}'))
        self.assertEqual({"state": "unknown", "phase": "json-shape"},
                         run(b'{"guard":"not-a-guard","phase":"task"}'))

    def test_windows_trigger_guard_accepts_only_empty_or_single_null(self):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("requires Windows PowerShell")
        fixed = absence._trigger_guard_powershell()
        old = "if($triggers.Count -eq 1 -and $null -eq $triggers[0]){throw 'TASK_TRIGGER_NULL'};if($triggers.Count -ne 0){throw 'TASK_TRIGGER_COUNT'}"
        script = r'''function Classify([object[]]$items,[string]$guard){$triggers=@($items);try{Invoke-Expression $guard;'accepted'}catch{$_.Exception.Message}}
$old='@OLD@';$fixed='@FIXED@'
[Console]::Out.WriteLine(('old-null='+(Classify -items ([object[]]@($null)) -guard $old)))
[Console]::Out.WriteLine(('fixed-empty='+(Classify -items ([object[]]@()) -guard $fixed)))
[Console]::Out.WriteLine(('fixed-null='+(Classify -items ([object[]]@($null)) -guard $fixed)))
[Console]::Out.WriteLine(('fixed-real='+(Classify -items ([object[]]@([pscustomobject]@{x=1})) -guard $fixed)))
[Console]::Out.WriteLine(('fixed-mixed='+(Classify -items ([object[]]@($null,[pscustomobject]@{x=1})) -guard $fixed)))
'''.replace("@OLD@", old.replace("'", "''")).replace("@FIXED@", fixed.replace("'", "''"))
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, check=True, timeout=15)
        self.assertEqual(["old-null=TASK_TRIGGER_NULL", "fixed-empty=accepted", "fixed-null=accepted",
                          "fixed-real=TASK_TRIGGER_COUNT", "fixed-mixed=TASK_TRIGGER_COUNT"],
                         result.stdout.splitlines())

    def test_windows_result_decoder_accepts_only_utf8_with_optional_bom(self):
        powershell = shutil.which("powershell.exe")
        if powershell is None:
            self.skipTest("requires Windows PowerShell")
        fixed = absence._result_decode_powershell()
        old = "$result=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json -ErrorAction Stop"
        script = r'''function Classify([byte[]]$input,[string]$decoder){$bytes=$input;try{Invoke-Expression $decoder;[string]$result.value}catch{'rejected'}}
$old='@OLD@';$fixed='@FIXED@';$text=[Text.Encoding]::UTF8.GetBytes('{"value":"ok"}');$bom=[byte[]](0xEF,0xBB,0xBF)+$text;$utf16=[Text.Encoding]::Unicode.GetBytes('{"value":"ok"}');$malformed=[byte[]](0xC3,0x28)
[Console]::Out.WriteLine(('old-bom='+(Classify -input $bom -decoder $old)))
[Console]::Out.WriteLine(('fixed-bom='+(Classify -input $bom -decoder $fixed)))
[Console]::Out.WriteLine(('fixed-plain='+(Classify -input $text -decoder $fixed)))
[Console]::Out.WriteLine(('fixed-malformed='+(Classify -input $malformed -decoder $fixed)))
[Console]::Out.WriteLine(('fixed-utf16='+(Classify -input $utf16 -decoder $fixed)))
'''.replace("@OLD@", old.replace("'", "''")).replace("@FIXED@", fixed.replace("'", "''"))
        result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, text=True, check=True, timeout=15)
        self.assertEqual(["old-bom=rejected", "fixed-bom=ok", "fixed-plain=ok",
                          "fixed-malformed=rejected", "fixed-utf16=rejected"], result.stdout.splitlines())

    def test_retained_diagnostic_qga_wrapper_classifies_terminal_and_truncation(self):
        body = "import base64,json,sys,time" + absence._RETAINED_DIAG_REMOTE.split("import base64,json,sys,time", 1)[1]

        def run(status):
            calls = iter(({"pid": 12}, status))
            scope = {"live": lambda *_: True, "call": lambda *_: next(calls),
                     "decode": lambda raw: raw.decode("utf-8")}
            output = io.StringIO()
            with patch.object(sys, "argv", ["remote", "/qga", "77", "88", "encoded"]), contextlib.redirect_stdout(output):
                exec(body, scope)
            return json.loads(output.getvalue())

        valid = base64.b64encode(b'{"guard":"TASK","phase":"task"}').decode()
        for status in (
            {"exited": True, "exitcode": 1, "out-data": valid, "out-truncated": False, "err-truncated": False},
            {"exited": True, "exitcode": 0, "out-data": valid, "out-truncated": True, "err-truncated": False},
        ):
            with self.subTest(status=status):
                self.assertEqual({"state": "unknown", "phase": "terminal"}, run(status))

    def test_red_parse_retained_exposes_existing_prospective_script_failure_only(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", return_value=b'{"strict":"failed","diagnostic":"failed"}') as remote:
            self.assertEqual({"state": "unknown", "phase": "transport", "strict": "failed", "diagnostic": "failed"},
                             absence.parse_retained(Path(directory), object(), target, DESC))
        parse_script = remote.call_args.args[2][3]
        self.assertIn("Parser]::ParseInput", parse_script)
        self.assertIn("function Parse-Only", parse_script)
        self.assertIn("diagnostic=(Parse-Only $diagnostic)", parse_script)
        self.assertIn("GzipStream", parse_script)
        self.assertLessEqual(len(parse_script), 30000)

    def test_parse_retained_qga_wrapper_forwards_only_script_booleans(self):
        body = "import base64,json,sys,time" + absence._RETAINED_PARSE_REMOTE.split("import base64,json,sys,time", 1)[1]

        def run(payload, *, exitcode=0):
            calls = iter(({"pid": 12}, {"exited": True, "exitcode": exitcode,
                                       "out-data": base64.b64encode(payload).decode(),
                                       "out-truncated": False, "err-truncated": False}))
            scope = {"live": lambda *_: True, "call": lambda *_: next(calls),
                     "decode": lambda raw: raw.decode("utf-8")}
            output = io.StringIO()
            with patch.object(sys, "argv", ["remote", "/qga", "77", "88", "encoded"]), contextlib.redirect_stdout(output):
                exec(body, scope)
            return json.loads(output.getvalue())

        self.assertEqual({"state": "observed", "phase": "ast", "strict": "passed", "diagnostic": "failed"},
                         run(b'{"strict":"passed","diagnostic":"failed"}'))
        self.assertEqual({"state": "unknown", "phase": "transport", "strict": "failed", "diagnostic": "failed"},
                         run(b'{"strict":"passed","diagnostic":"failed","extra":true}'))
        self.assertEqual({"state": "unknown", "phase": "transport", "strict": "failed", "diagnostic": "failed"},
                         run(b'{"strict":"passed","diagnostic":"passed"}', exitcode=1))

    def test_parse_retained_uses_bounded_plain_command_transport(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()

        def remote(_config, program, args, _input, _timeout):
            self.assertEqual(absence._RETAINED_PARSE_REMOTE, program)
            self.assertEqual((DESC[1], str(DESC[2]), str(DESC[3])), args[:3])
            self.assertLessEqual(len(args[3]), 30000)
            self.assertIn("GzipStream", args[3])
            self.assertNotIn("-EncodedCommand", program)
            return b'{"state":"observed","phase":"ast","strict":"failed","diagnostic":"failed"}'

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(absence.transfer, "_intent", return_value=RECORD), \
             patch.object(absence.transfer, "_guest_dispatch_marker", return_value={"bound": True}), \
             patch.object(absence.base, "_remote", side_effect=remote):
            self.assertEqual({"state": "observed", "phase": "ast", "strict": "failed", "diagnostic": "failed"},
                             absence.parse_retained(Path(directory), object(), target, DESC))


    def test_post_retirement_requires_fixed_terminal_and_exact_preserved_leaf(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        post = {"state": "observed", "baseTask": "absent", "guestLeaf": "present",
                "transferTask": "absent", "baseMsi": "absent", "correlationProcess": "absent"}
        parsed = b'{"state":"observed","phase":"ast","strict":"passed","diagnostic":"passed"}'
        receipt = json.dumps({"state": "observed", "receipt": PAYLOAD}).encode()
        from agent_tools import windows_cp117_c32_retained_task_retire as retire
        terminal = {"state": "terminal", "retirementCorrelationId": retire._RETIREMENT,
                    "task": "VpnControlMcpBase-" + C32}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence, "_admit", return_value=({}, "/route")), \
             patch.object(absence, "observe", return_value=post), \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(retire, "status", return_value=terminal), \
             patch.object(absence.base, "_remote", side_effect=(parsed, receipt)):
            self.assertEqual("post-retirement-terminal",
                             absence.post_retirement_terminal(Path(directory), object(), target, DESC)["state"])

    def test_post_retirement_rejects_task_absence_without_terminal_or_exact_leaf(self):
        target = type("Target", (), {"fixture_transfer_root": Path("/private")})()
        post = {"state": "observed", "baseTask": "absent", "guestLeaf": "present",
                "transferTask": "absent", "baseMsi": "absent", "correlationProcess": "absent"}
        from agent_tools import windows_cp117_c32_retained_task_retire as retire
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence, "_admit", return_value=({}, "/route")), \
             patch.object(absence, "observe", return_value=post), \
             patch.object(retire, "status", return_value={"state": "unknown"}), \
             patch.object(absence.base, "_remote") as remote:
            self.assertEqual("unknown", absence.post_retirement_terminal(Path(directory), object(), target, DESC)["state"])
            remote.assert_not_called()
        # A foreign or malformed original receipt also cannot be promoted.
        parsed = b'{"state":"observed","phase":"ast","strict":"passed","diagnostic":"passed"}'
        foreign = {**PAYLOAD, "correlationId": "foreign"}
        terminal = {"state": "terminal", "retirementCorrelationId": retire._RETIREMENT,
                    "task": "VpnControlMcpBase-" + C32}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(absence, "_admit", return_value=({}, "/route")), \
             patch.object(absence, "observe", return_value=post), \
             patch.object(absence.base, "_private_intent", return_value=INTENT), \
             patch.object(retire, "status", return_value=terminal), \
             patch.object(absence.base, "_remote", side_effect=(parsed, json.dumps({"state": "observed", "receipt": foreign}).encode())):
            self.assertEqual("unknown", absence.post_retirement_terminal(Path(directory), object(), target, DESC)["state"])


if __name__ == "__main__":
    unittest.main()
