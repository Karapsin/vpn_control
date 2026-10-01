"""Deterministic regression coverage for the CP117 package-mode attribute repair."""
import json
import stat
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from agent_tools import windows_fixture_package_mode_repair as repair


SERVER = "2c438d90-9a77-4acd-b4d7-ab354b85a04a"
REPAIR = "4b1b7e18-b08e-4ca5-90e5-56d967a6dd0f"
STAGE = "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"
SOURCE = "a" * 40
SHA = "b" * 64
REQUEST = {"serverCorrelationId": SERVER, "repairCorrelationId": REPAIR}
GEN = ("windows-cp117", "/qga", 123, 456, "S-1-5-21-1-2-3-1002")
BINDING = {"stageCorrelationId": STAGE, "targetMsiSha256": SHA, "targetLeaf": "VpnControl.msi",
           "guestGeneration": {"socketPath": "/qga", "qemuPid": 123, "startTicks": 456}}


class PackageModeRepairTests(TestCase):
    def _record(self):
        return {"version": 1, "request": REQUEST, **BINDING}

    def _server_intent(self, *, request=None):
        return {"request": request or {"host":"archlinux", "leaseId":"11111111-1111-4111-8111-111111111111",
            "stageCorrelationId":STAGE, "serverCorrelationId":SERVER, "sourceSha":SOURCE,
            "fixtureReceiptArtifactId":"sha256-" + "c" * 64, "baseMsiArtifactId":"sha256-" + "d" * 64,
            "targetMsiArtifactId":"sha256-" + SHA}, "socketPath":"/qga", "qemuPid":123,
            "startTicks":456, "targetMsiSha256":SHA}

    def _bound_patches(self, *, stage_request=None):
        server_request = self._server_intent()["request"]
        stage_request = stage_request or {"host":"archlinux", "correlationId":STAGE, "sourceSha":SOURCE,
            "fixtureReceiptArtifactId":"sha256-" + "c" * 64, "baseMsiArtifactId":"sha256-" + "d" * 64,
            "targetMsiArtifactId":"sha256-" + SHA}
        staged = {"request":stage_request, "fileHashes":{"packages/target/VpnControl.msi":SHA}}
        pair = {"targetMsiSha256":SHA}
        static = {"state":"observed", "serverCorrelationId":SERVER, "import":"ok", "certificate":"ok",
                  "resources":"failed", "resourceGate":"package-mode", "replayAllowed":False}
        task = {"state":"observed", "task":"ready", "lastResult":1, "ready":"absent", "stateContent":"empty",
                "stageAcl":"expected", "stateAcl":"expected", "replayAllowed":False}
        return mock.patch.multiple(repair.server, _read_intent=mock.DEFAULT, diagnose_static=mock.DEFAULT,
                                   diagnose_status=mock.DEFAULT), staged, pair, static, task

    def test_start_writes_private_intent_before_response_loss_and_never_replays(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(repair, "_bound", return_value=(BINDING, object(), GEN)), \
             mock.patch.object(repair, "_syntax", return_value="valid"), \
             mock.patch.object(repair, "_observe", return_value=None):
            result = repair.start(temp, REQUEST)
            self.assertEqual(result, repair._unknown(REPAIR))
            record = repair._read(Path(temp), REPAIR)
            self.assertEqual(record, self._record())
            self.assertEqual(stat.S_IMODE(repair._path(Path(temp), REPAIR).stat().st_mode), 0o600)
            self.assertEqual(repair.start(temp, REQUEST), repair._unknown(REPAIR))

    def test_invalid_guest_powershell_syntax_rejects_before_intent(self):
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(repair, "_bound", return_value=(BINDING, object(), GEN)), \
             mock.patch.object(repair, "_syntax", return_value="invalid"), \
             mock.patch.object(repair, "_observe") as observe:
            with self.assertRaisesRegex(repair.WindowsFixturePackageModeRepairError, "script is not admitted"):
                repair.start(temp, REQUEST)
            self.assertFalse(repair._path(Path(temp), REPAIR).exists())
            observe.assert_not_called()

    def test_exact_owner_and_stage_binding_are_required_before_intent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ctx, staged, pair, static, task = self._bound_patches(
                stage_request={"host":"archlinux", "correlationId":STAGE, "sourceSha":"f" * 40,
                    "fixtureReceiptArtifactId":"sha256-" + "c" * 64, "baseMsiArtifactId":"sha256-" + "d" * 64,
                    "targetMsiArtifactId":"sha256-" + SHA})
            with ctx as values, \
                 mock.patch.object(repair.server, "_request", side_effect=lambda value: dict(value)), \
                 mock.patch.object(repair.stage, "_read_intent", return_value=staged), \
                 mock.patch.object(repair.public, "_admit_pair", return_value=pair), \
                 mock.patch.object(repair.stage, "status", return_value={"state":"staged-not-server-ready", "targetMsiSha256":SHA}), \
                 mock.patch.object(repair.base, "_descriptor", return_value=(object(), object(), GEN)):
                values["_read_intent"].return_value = self._server_intent()
                values["diagnose_static"].return_value = static
                values["diagnose_status"].return_value = task
                with self.assertRaisesRegex(repair.WindowsFixturePackageModeRepairError, "stage intent"):
                    repair._bound(root, REQUEST)
            self.assertFalse(repair._path(root, REPAIR).exists())

    def test_status_rejects_attribute_or_hash_mismatch_and_does_not_mutate(self):
        for observed in ({"version":1,"file":"present","reparse":"absent","hash":"mismatch","readOnly":"set","mutation":"none"},
                         {"version":1,"file":"present","reparse":"absent","hash":"exact","readOnly":"absent","mutation":"none"}):
            with self.subTest(observed=observed), tempfile.TemporaryDirectory() as temp, \
                 mock.patch.object(repair, "_bound", return_value=(BINDING, object(), GEN)), \
                 mock.patch.object(repair, "_observe", return_value=observed) as observe:
                repair._reserve(Path(temp), self._record())
                self.assertEqual(repair.status(temp, {"repairCorrelationId":REPAIR}), repair._unknown(REPAIR))
                observe.assert_called_once_with(mock.ANY, GEN, self._record(), False)

    def test_status_accepts_repaired_attribute_after_original_failure_gate_clears(self):
        observed = {"version":1,"file":"present","reparse":"absent","hash":"exact",
                    "readOnly":"set","mutation":"none"}
        with tempfile.TemporaryDirectory() as temp, \
             mock.patch.object(repair, "_bound", return_value=(BINDING, object(), GEN)) as bound, \
             mock.patch.object(repair, "_observe", return_value=observed):
            repair._reserve(Path(temp), self._record())
            self.assertEqual("repaired", repair.status(temp, {"repairCorrelationId":REPAIR})["state"])
            bound.assert_called_once_with(Path(temp).resolve(), REQUEST, require_failure=False)

    def test_remote_accepts_missing_optional_truncation_flags_but_requires_exact_hash_and_attribute(self):
        output = {"version":1,"file":"present","reparse":"absent","hash":"exact","readOnly":"set","mutation":"none"}
        with mock.patch.object(repair.base, "_remote", return_value=json.dumps({"state":"observed", "result":output})) as remote:
            self.assertEqual(repair._observe(object(), GEN, self._record(), False), output)
        self.assertIsInstance(remote.call_args.args[2][3], str)
        compile(repair._REMOTE, "package-mode-repair-qga", "exec")

    def test_wrong_registered_target_hash_rejects_without_qga(self):
        intent = {"fileHashes":{"packages/target/VpnControl.msi":"0" * 64}}
        with self.assertRaisesRegex(repair.WindowsFixturePackageModeRepairError, "target MSI"):
            repair._target(intent, SHA)


if __name__ == "__main__":
    import unittest
    unittest.main()
