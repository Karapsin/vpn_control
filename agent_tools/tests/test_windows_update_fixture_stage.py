"""Fast admission checks for the data-only CP117 update fixture stage."""
from __future__ import annotations

import json
import io
import hashlib
import ast
import base64
from contextlib import redirect_stdout
import fcntl
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

from agent_tools import windows_update_fixture_stage as stage


CORR = "11111111-1111-4111-8111-111111111111"
LEASE = "22222222-2222-4222-8222-222222222222"
OLD = "33333333-3333-4333-8333-333333333333"
OLD_LEASE = "44444444-4444-4444-8444-444444444444"
SOURCE = "a" * 40
SID = "S-1-5-21-1-2-3-1002"
REQUEST = {"host": "archlinux", "correlationId": CORR, "sourceSha": SOURCE,
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "baseMsiArtifactId": "sha256-" + "c" * 64,
           "targetMsiArtifactId": "sha256-" + "d" * 64}
HASHES = {"fixture-receipt.json": "b" * 64,
          "packages/target/vpn-control-2.2.0.msi": "d" * 64,
          "server/prepare_desktop_update_fixture.py": "e" * 64,
          "server/fixture_environment.py": "f" * 64,
          "server/macos_packaging_jdk_preflight.py": "1" * 64}
STATE_ACL = {"stage": stage._GUEST + "\\mcp-update-fixture-" + CORR + "\\server-state",
             "protected": True,
             "acl": [{"sid": sid, "rights": 0x1F01FF, "type": "Allow", "inherited": False,
                      "inheritance": 3, "propagation": 0}
                     for sid in ("S-1-5-18", "S-1-5-32-544", SID)]}
LAYOUT = '''
def serve(directory):
    if stage.name == "content":
        state = stage.parent / "server-state"
        ready = state / "ready.json"
        receipt = directory / "fixture-receipt.json"
        require_windows_private_acl(stage)
        require_windows_private_acl(state)
        event_root = state if windows else directory
        probe_events_path(event_root)
        write_private_ready_json(ready, {})
'''


class WindowsUpdateFixtureStageTest(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32" and shutil.which("powershell.exe"),
                         "Windows PowerShell filesystem attributes required")
    def test_generated_stage_marks_verified_target_msi_read_only(self):
        """Execute the generated extraction tail against real Windows file attributes."""
        with tempfile.TemporaryDirectory() as temporary:
            content = Path(temporary) / "content"
            target = content / "packages" / "target" / "vpn-control-2.2.0.msi"
            receipt = content / "fixture-receipt.json"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"signed-msi")
            receipt.write_bytes(b"receipt")
            hashes = {"packages/target/vpn-control-2.2.0.msi": hashlib.sha256(target.read_bytes()).hexdigest(),
                      "fixture-receipt.json": hashlib.sha256(receipt.read_bytes()).hexdigest()}
            script = stage._stage_script(CORR, SID, hashes, "2" * 64)
            tail = script[script.index(" $files=@(Get-ChildItem"):script.index(" $aclReceipt=(&")]
            prelude = ("$ErrorActionPreference='Stop';$content='" + str(content).replace("'", "''") +
                       "';$expected=@{};" + "".join("$expected['" + name + "']='" + digest + "';"
                                                for name, digest in hashes.items()))
            completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                                        prelude + tail], capture_output=True, text=True, check=False)
            try:
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual(hashes["packages/target/vpn-control-2.2.0.msi"],
                                 hashlib.sha256(target.read_bytes()).hexdigest())
                self.assertEqual(0, target.stat().st_mode & 0o222)
                self.assertNotEqual(0, receipt.stat().st_mode & 0o222)
            finally:
                target.chmod(0o666)

    def _run_remote_status(self, receipt, call):
        body = stage._REMOTE_STATUS[stage._REMOTE_STATUS.index("root,env,lease,corr,"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / "windows-cp117"
            leaf = environment / "windows-update-fixture-stage" / CORR
            leaf.mkdir(parents=True, mode=0o700)
            for directory in (root, environment, leaf.parent, leaf):
                os.chmod(directory, 0o700)
            binding = {"correlationId": CORR, "socketPath": "/qga", "pid": 42,
                       "startTicks": 99, "leaseId": LEASE, "sourceSha": SOURCE,
                       "sourceFingerprint": "a" * 64, "bundleSha256": "2" * 64,
                       "expectedSid": SID,
                       "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                       "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                       "targetMsiArtifactId": REQUEST["targetMsiArtifactId"]}
            for name, value in (("binding.json", binding), ("dispatch.json", {"pid": 7})):
                path = leaf / name
                path.write_text(json.dumps(value)); os.chmod(path, 0o600)
            output = io.StringIO()
            args = [str(root), "windows-cp117", LEASE, CORR, "/qga", "42", "99", SID,
                    SOURCE, "a" * 64, "2" * 64, REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"]]
            namespace = {"json": json, "os": os, "stat": stat,
                         "sys": type("Args", (), {"argv": ["remote", *args]})(),
                         "live": lambda *_: True, "call": call, "read": lambda *_: receipt,
                         "decode": lambda raw: raw.decode("utf-8")}
            with redirect_stdout(output):
                try:
                    exec(compile(ast.parse(body), "stage-status-remote", "exec"), namespace)
                except SystemExit as exited:
                    self.assertEqual(0, exited.code)
        return json.loads(output.getvalue())

    def _run_remote_diagnostic(self, names, call, read):
        """Run the generated remote observer against a private fake host leaf."""
        body = stage._REMOTE_DIAGNOSTIC[stage._REMOTE_DIAGNOSTIC.index("import time\n"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / "windows-cp117"
            group = environment / "windows-update-fixture-stage"
            leaf = group / CORR
            leaf.mkdir(parents=True, mode=0o700)
            for directory in (root, environment, group, leaf):
                os.chmod(directory, 0o700)
            binding = {"correlationId": CORR, "socketPath": "/qga", "pid": 42,
                       "startTicks": 99, "leaseId": LEASE, "sourceSha": SOURCE,
                       "sourceFingerprint": "a" * 64, "bundleSha256": "2" * 64,
                       "expectedSid": SID,
                       "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                       "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                       "targetMsiArtifactId": REQUEST["targetMsiArtifactId"]}
            (leaf / "binding.json").write_text(json.dumps(binding))
            os.chmod(leaf / "binding.json", 0o600)
            if "dispatch" in names:
                (leaf / "dispatch.json").write_text('{"pid":7}')
                os.chmod(leaf / "dispatch.json", 0o600)
            output = io.StringIO()
            args = [str(root), "windows-cp117", LEASE, CORR, "/qga", "42", "99", SID,
                    SOURCE, "a" * 64, "2" * 64, "1", REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"]]
            namespace = {"os": os, "stat": stat, "json": json, "base64": base64,
                         "time": __import__("time"), "sys": type("Args", (), {"argv": ["remote", *args]})(),
                         "live": lambda *_: True, "call": call, "read": read,
                         "decode": lambda raw: raw.decode("utf-8")}
            with redirect_stdout(output):
                with self.assertRaises(SystemExit) as exited:
                    exec(compile(ast.parse(body), "stage-diagnostic-remote", "exec"), namespace)
            self.assertEqual(0, exited.exception.code)
        return json.loads(output.getvalue())

    def test_request_is_exact_and_canonical(self):
        self.assertEqual(REQUEST, stage._request(REQUEST))
        for bad in ({**REQUEST, "correlationId": "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"},
                    {**REQUEST, "secret": "must-not-accept"},
                    {**REQUEST, "host": "localhost"}):
            with self.subTest(bad=bad), self.assertRaises(stage.WindowsUpdateFixtureStageError):
                stage._request(bad)

    def test_source_module_inventory_rejects_new_local_import(self):
        class Result:
            def __init__(self, out):
                self.stdout = out; self.returncode = 0
        imports = ("from fixture_environment import x\nfrom macos_packaging_jdk_preflight import y\nimport secret_local\n" + LAYOUT).encode()
        def run(argv, **_):
            if "ls-tree" in argv:
                return Result("prepare_desktop_update_fixture.py\nfixture_environment.py\nmacos_packaging_jdk_preflight.py\nsecret_local.py\n")
            name = argv[-1].split("/")[-1]
            return Result(imports if name == "prepare_desktop_update_fixture.py" else b"pass\n")
        with patch.object(stage.subprocess, "run", side_effect=run):
            with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError, "inventory changed"):
                stage._modules(Path("."), SOURCE)

    def test_source_module_inventory_accepts_exact_declared_siblings(self):
        class Result:
            def __init__(self, out):
                self.stdout = out; self.returncode = 0
        imports = ("from fixture_environment import x\nfrom macos_packaging_jdk_preflight import y\n" + LAYOUT).encode()
        def run(argv, **_):
            if "ls-tree" in argv:
                return Result("prepare_desktop_update_fixture.py\nfixture_environment.py\nmacos_packaging_jdk_preflight.py\n")
            name = argv[-1].split("/")[-1]
            return Result(imports if name == "prepare_desktop_update_fixture.py" else b"pass\n")
        with patch.object(stage.subprocess, "run", side_effect=run):
            self.assertEqual(set(stage._modules(Path("."), SOURCE)), set(stage._MODULES))

    def test_source_layout_rejects_in_stage_ready_public_event_root(self):
        tree = stage.ast.parse("def serve(directory):\n ready = directory / 'ready.json'\n"
                               " probe_events_path(directory)\n write_private_ready_json(ready,{})\n")
        with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError, "layout is unavailable"):
            stage._require_split_server_layout(tree)

    def test_bundle_contains_only_registered_receipt_target_and_exact_source_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "fixture-receipt.json"; receipt.write_bytes(b'{"schemaVersion":1}')
            target = root / "vpn-control-2.2.0.msi"; target.write_bytes(b"signed-msi")
            request = {**REQUEST, "fixtureReceiptArtifactId": "sha256-" + hashlib.sha256(receipt.read_bytes()).hexdigest()}
            pair = {"targetMsiSha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "targetMsiSize": target.stat().st_size}
            def location(_root, kind_id, *_):
                return receipt if kind_id == request["fixtureReceiptArtifactId"] else target
            modules = {name: ("# " + name + "\n").encode() for name in stage._MODULES}
            with patch.object(stage.public, "_verified_location", side_effect=location), \
                 patch.object(stage, "_modules", return_value=modules):
                stream, hashes, size, digest = stage._bundle(root, request, pair)
            try:
                with stage.zipfile.ZipFile(stream) as archive:
                    self.assertEqual(set(hashes), set(archive.namelist()))
                    self.assertEqual(b"signed-msi", archive.read("packages/target/vpn-control-2.2.0.msi"))
                stream.seek(0)
                self.assertEqual(size, len(stream.read()))
                stream.seek(0)
                self.assertEqual(digest, hashlib.sha256(stream.read()).hexdigest())
            finally:
                stream.close()

    def test_bundle_archives_verified_open_bytes_even_if_paths_are_swapped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "fixture-receipt.json"; original = b'{"schemaVersion":1}'
            receipt.write_bytes(original)
            target = root / "vpn-control-2.2.0.msi"; target.write_bytes(b"signed-msi")
            request = {**REQUEST, "fixtureReceiptArtifactId": "sha256-" + hashlib.sha256(original).hexdigest()}
            pair = {"targetMsiSha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "targetMsiSize": target.stat().st_size}
            opened = stage._open_registered
            def swap_after_open(path, maximum):
                stream = opened(path, maximum)
                if path == receipt:
                    receipt.rename(root / "old-receipt.json")
                    receipt.write_bytes(b"swapped receipt")
                if path == target:
                    target.rename(root / "old-target.msi")
                    target.write_bytes(b"swapped target")
                return stream
            modules = {name: b"pass\n" for name in stage._MODULES}
            with patch.object(stage.public, "_verified_location",
                              side_effect=lambda _root, artifact, *_: receipt if artifact == request["fixtureReceiptArtifactId"] else target), \
                 patch.object(stage, "_modules", return_value=modules), \
                 patch.object(stage, "_open_registered", side_effect=swap_after_open):
                stream, hashes, _, _ = stage._bundle(root, request, pair)
            try:
                with stage.zipfile.ZipFile(stream) as archive:
                    self.assertEqual(original, archive.read("fixture-receipt.json"))
                    self.assertEqual(b"signed-msi", archive.read("packages/target/vpn-control-2.2.0.msi"))
                    self.assertEqual(hashlib.sha256(original).hexdigest(), hashes["fixture-receipt.json"])
            finally:
                stream.close()

    def test_stage_script_is_data_only_and_requires_rx_stage_acl(self):
        script = stage._stage_script(CORR, SID, HASHES, "2" * 64)
        self.assertIn("STAGED_NOT_SERVER_READY", script)
        self.assertIn("FILE_HASH", script)
        self.assertIn("ReadAndExecute", script)
        self.assertNotIn("serve_forever", script)
        self.assertNotIn("msiexec", script)
        self.assertNotIn("trustStore", script)
        self.assertIn("server-state", stage._create_script(CORR, SID))
        self.assertIn("ReadAndExecute", stage._create_script(CORR, SID))

    def test_create_checks_all_ancestors_and_new_paths_for_reparse(self):
        script = stage._create_script(CORR, SID)
        # DirectoryInfo.Parent does not preserve provider-added PSIsContainer;
        # each ancestor must therefore be fetched again before its type check.
        self.assertIn("$item=Get-Item -LiteralPath $current -Force -ErrorAction Stop", script)
        self.assertIn("$parent=Split-Path -Parent $current", script)
        self.assertNotIn("$item=$item.Parent", script)
        self.assertIn("ReparsePoint", script)
        self.assertLess(script.index("SafeAncestors (Split-Path -Parent $root)"),
                        script.index("[IO.Directory]::CreateDirectory($root"))
        self.assertLess(script.index("[IO.Directory]::CreateDirectory((Join-Path $root 'server-state')"),
                        script.rindex("SafeAncestors (Join-Path $root 'server-state')"))

    def test_existing_intent_is_not_replayed(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value={"request": REQUEST}), \
             patch.object(stage.public, "_admit_pair") as pair, \
             patch.object(stage.base, "_remote") as remote:
            result = stage.start(temporary, REQUEST)
        self.assertEqual({"state": "unknown", "correlationId": CORR, "replayAllowed": False}, result)
        pair.assert_not_called(); remote.assert_not_called()

    def test_native_start_fails_closed_without_shared_cp117_lease(self):
        pair = {"sourceFingerprint": "a" * 64, "targetMsiSha256": "d" * 64}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=None), \
             patch.object(stage.public, "_admit_pair", return_value=pair), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage, "_bundle", return_value=(io.BytesIO(b"bundle"), HASHES, 6, "2" * 64)), \
             patch.object(stage.base, "_verified_active_campaign", side_effect=stage.WindowsUpdateFixtureStageError("CP117_CROSS_ROUTE_LEASE_UNAVAILABLE")), \
             patch.object(stage.base, "_remote") as remote:
            with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError,
                                        "CP117_CROSS_ROUTE_LEASE_UNAVAILABLE"):
                stage.start(temporary, REQUEST)
        remote.assert_not_called()

    def test_stage_claim_requires_exact_campaign_and_remote_role_guard(self):
        config = object()
        target = type("Host", (), {"fixture_transfer_root": Path("/fixture")})()
        descriptor = ("windows-cp117", "/qga", 42, 99, SID)
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage.base, "_verified_active_campaign", return_value=LEASE) as verified, \
             patch.object(stage.campaign_lease, "claim_role", return_value={"state": "role-active"}) as claim:
            self.assertEqual(LEASE, stage._require_cross_route_lease(
                Path(temporary), REQUEST, config, target, descriptor))
            verified.assert_called_once()
            claim.assert_not_called()

    def test_lost_stage_role_claim_never_submits_guest_job(self):
        pair = {"sourceFingerprint": "a" * 64, "targetMsiSha256": "d" * 64}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=None), \
             patch.object(stage.public, "_admit_pair", return_value=pair), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage, "_bundle", return_value=(io.BytesIO(b"bundle"), HASHES, 6, "2" * 64)), \
             patch.object(stage, "_require_cross_route_lease", return_value=LEASE), \
             patch.object(stage, "_reserve", return_value=Path(temporary) / "bundle.zip") as reserve, \
             patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(stage.campaign_lease, "claim_role", return_value={"state": "unknown"}) as claim, \
             patch.object(stage.base, "_remote") as remote:
            self.assertEqual(stage.start(temporary, REQUEST)["state"], "unknown")
            reserve.assert_called_once(); claim.assert_called_once(); remote.assert_not_called()

    def test_prior_stage_history_blocks_before_claiming_shared_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / stage._GROUP
            directory.mkdir(parents=True, mode=0o700)
            (directory / "old.json").write_text("{}")
            with patch.object(stage.base, "_descriptor", return_value=(object(), object(), None)), \
                 patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None):
                with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError, "history is unknown"):
                    stage._closed_stage_history(Path(temporary), LEASE)

    def test_prior_stage_requires_remote_confirmed_closed_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / stage._GROUP
            directory.mkdir(parents=True, mode=0o700)
            prior = {"request": {**REQUEST, "correlationId": OLD}, "leaseId": OLD_LEASE,
                     "sourceFingerprint": "a" * 64, "bundleSha256": "b" * 64,
                     "fileHashes": {}}
            path = directory / (OLD + ".json")
            path.write_text(json.dumps(prior)); os.chmod(path, 0o600)
            descriptor = ("windows-cp117", "/qga", 42, 99, SID)
            expected = stage.base._campaign_identity({**prior["request"], "correlationId": OLD_LEASE}, descriptor)
            closed = {"state": "closed", "identity": expected}
            prior.update({"environment":descriptor[0],"socketPath":descriptor[1],"pid":descriptor[2],"startTicks":descriptor[3],"expectedSid":descriptor[4]})
            path.write_text(json.dumps(prior))
            with patch.object(stage.base, "_descriptor", return_value=(object(), object(), descriptor)), \
                 patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
                 patch.object(stage.public, "_admit_pair", return_value={"sourceFingerprint":"a" * 64}), \
                 patch.object(stage.campaign_lease, "_closed", return_value=closed) as read_closed, \
                 patch.object(stage.campaign_lease, "_remote_confirm", return_value=False) as confirm:
                with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError, "active or unknown"):
                    stage._closed_stage_history(root, LEASE)
                confirm.return_value = True
                stage._closed_stage_history(root, LEASE)
                self.assertEqual(read_closed.call_args.args[1], OLD_LEASE)
                self.assertTrue(path.exists())
                with self.assertRaisesRegex(stage.WindowsUpdateFixtureStageError, "active or unknown"):
                    stage._closed_stage_history(root, OLD_LEASE)
            self.assertLess(stage._REMOTE_START.index("closed_path="),
                            stage._REMOTE_START.index("stage=os.path.join(group,corr);os.mkdir"))

    def test_rebased_successor_proves_old_closed_history_without_bypassing_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / stage._GROUP
            directory.mkdir(parents=True, mode=0o700)
            prior = {"request": {**REQUEST, "correlationId": OLD}, "leaseId": OLD_LEASE,
                     "sourceFingerprint": "a" * 64, "bundleSha256": "b" * 64, "fileHashes": {}}
            (directory / (OLD + ".json")).write_text(json.dumps(prior)); os.chmod(directory / (OLD + ".json"), 0o600)
            descriptor = ("windows-cp117", "/qga", 42, 99, SID)
            expected = stage.base._campaign_identity({**prior["request"], "correlationId": OLD_LEASE}, descriptor)
            closed = {"state": "closed", "identity": expected}
            prior.update({"environment":descriptor[0],"socketPath":descriptor[1],"pid":descriptor[2],"startTicks":descriptor[3],"expectedSid":descriptor[4]})
            (directory / (OLD + ".json")).write_text(json.dumps(prior))
            successor = {"identity": {"leaseId": LEASE}}
            config, target = object(), object()
            with patch.object(stage.base, "_descriptor", return_value=(config, target, descriptor)), \
                 patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
                 patch.object(stage.public, "_admit_pair", return_value={"sourceFingerprint":"a" * 64}), \
                 patch.object(stage.campaign_lease, "_closed", return_value=closed), \
                 patch.object(stage.campaign_lease, "_remote_confirm", return_value=False), \
                 patch.object(stage.campaign_lease, "_active", return_value=successor), \
                 patch("agent_tools.windows_cp117_campaign_status._remote_closed_proof", return_value=True) as successor_proof:
                self.assertEqual("confirmed", stage._closed_stage_history_detail(root, LEASE))
                successor_proof.assert_called_once_with(config, target, closed, successor["identity"])
                successor_proof.return_value = False
                self.assertEqual("remote-status-mismatch", stage._closed_stage_history_detail(root, LEASE))

    def test_prior_history_rejects_closed_identity_mismatching_stage_request_before_remote_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); directory = root / stage._GROUP; directory.mkdir(parents=True, mode=0o700)
            descriptor = ("windows-cp117", "/qga", 42, 99, SID)
            prior = {"request": {**REQUEST, "correlationId": OLD}, "leaseId": OLD_LEASE,
                     "sourceFingerprint": "a" * 64, "bundleSha256": "b" * 64, "fileHashes": {},
                     "environment":descriptor[0],"socketPath":descriptor[1],"pid":descriptor[2],"startTicks":descriptor[3],"expectedSid":descriptor[4]}
            (directory / (OLD + ".json")).write_text(json.dumps(prior)); os.chmod(directory / (OLD + ".json"), 0o600)
            with patch.object(stage.base, "_descriptor", return_value=(object(), object(), descriptor)), \
                 patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
                 patch.object(stage.public, "_admit_pair", return_value={"sourceFingerprint":"a" * 64}), \
                 patch.object(stage.campaign_lease, "_closed", return_value={"identity":{"leaseId":"wrong"}}), \
                 patch.object(stage.campaign_lease, "_remote_confirm") as remote:
                self.assertEqual("history-record-invalid", stage._closed_stage_history_detail(root, LEASE))
                remote.assert_not_called()

    def test_bundle_write_failure_never_claims_stage_role(self):
        pair = {"sourceFingerprint": "a" * 64, "targetMsiSha256": "d" * 64}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real_open = os.open
            def interrupted_intent(path, flags, *args, **kwargs):
                if Path(path) == stage._intent_path(root, CORR):
                    raise OSError("injected intent write failure")
                return real_open(path, flags, *args, **kwargs)
            with patch.object(stage, "_read_intent", return_value=None), \
                 patch.object(stage.public, "_admit_pair", return_value=pair), \
                 patch.object(stage.base, "_descriptor", return_value=descriptor), \
                 patch.object(stage, "_bundle", return_value=(io.BytesIO(b"bundle"), HASHES, 6, "2" * 64)), \
                 patch.object(stage, "_require_cross_route_lease", return_value=LEASE), \
                 patch.object(stage, "_closed_stage_history"), \
                 patch.object(stage.os, "open", side_effect=interrupted_intent), \
                 patch.object(stage.campaign_lease, "claim_role") as claim, \
                 patch.object(stage.base, "_remote") as remote:
                with self.assertRaisesRegex(OSError, "injected intent"):
                    stage.start(root, REQUEST)
            self.assertTrue((root / stage._GROUP / (CORR + ".zip")).exists())
            claim.assert_not_called(); remote.assert_not_called()

    def test_remote_stage_journals_are_private_under_umask022(self):
        namespace = {"json": json, "os": os, "stat": stat}
        exec(compile(ast.parse(stage._PRIVATE_REMOTE_JSON), "stage-remote-json", "exec"), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            old = os.umask(0o022)
            try:
                unsafe = Path(temporary) / "old.json"
                with unsafe.open("x") as stream: json.dump({"pid": 1}, stream)
                self.assertEqual(stat.S_IMODE(unsafe.stat().st_mode), 0o644)
                for name in ("binding.json", "dispatch.json"):
                    path = Path(temporary) / name
                    namespace["save_private_json"](str(path), {"pid": 1})
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    with self.assertRaises(FileExistsError):
                        namespace["save_private_json"](str(path), {"pid": 2})
            finally: os.umask(old)
        self.assertEqual(stage._REMOTE_START.count("save_private_json(os.path.join("), 2)
        self.assertIn("stat.S_IMODE(info.st_mode)!=0o600", stage._REMOTE_STATUS)

    def test_remote_history_blocks_wrong_closed_binding_before_guest_effect(self):
        source = stage._REMOTE_START
        body = source[source.index("root,env,lease,corr,sock,pid,ticks,sid,size_text,"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            environment = root / "windows-cp117"
            group = environment / "windows-update-fixture-stage"
            old_job = group / OLD
            old_job.mkdir(parents=True, mode=0o700)
            campaign = environment / "windows-cp117-campaign"
            campaign.mkdir(mode=0o700)
            for path in (root, environment, group, old_job, campaign): os.chmod(path, 0o700)
            binding = {"correlationId": OLD, "leaseId": OLD_LEASE, "sourceSha": SOURCE,
                       "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                       "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                       "targetMsiArtifactId": REQUEST["targetMsiArtifactId"],
                       "socketPath": "/qga", "pid": 42, "startTicks": 99}
            old_binding = old_job / "binding.json"
            old_binding.write_text(json.dumps(binding)); os.chmod(old_binding, 0o600)
            closed = {"state": "closed", "server": "stopped", "credentials": "cleaned",
                      "identity": {"leaseId": OLD_LEASE, "sourceSha": SOURCE,
                                   "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"],
                                   "baseMsiArtifactId": REQUEST["baseMsiArtifactId"],
                                   "targetMsiArtifactId": "sha256-" + "0" * 64,
                                   "socketPath": "/qga", "qemuPid": 42, "startTicks": 99}}
            closed_path = campaign / (OLD_LEASE + ".closed.json")
            closed_path.write_text(json.dumps(closed)); os.chmod(closed_path, 0o600)
            args = [str(root), "windows-cp117", LEASE, CORR, "/qga", "42", "99", SID,
                    "1", "2" * 64, base64.b64encode(b"create").decode(),
                    base64.b64encode(b"stage").decode(), SOURCE, "a" * 64,
                    REQUEST["fixtureReceiptArtifactId"], REQUEST["baseMsiArtifactId"],
                    REQUEST["targetMsiArtifactId"]]
            calls = []
            namespace = {"os": os, "stat": stat, "json": json, "hashlib": hashlib,
                         "base64": base64, "fcntl": fcntl, "uuid": uuid,
                         "time": __import__("time"), "sys": type("Args", (), {"argv": ["remote", *args]})(),
                         "live": lambda *_: True, "require_campaign_role": lambda *_: None,
                         "call": lambda *items: calls.append(items) or (_ for _ in ()).throw(OSError("stop"))}
            exec(compile(ast.parse(stage._PRIVATE_REMOTE_JSON), "stage-private-json", "exec"), namespace)
            output = io.StringIO()
            with redirect_stdout(output): exec(compile(body, "stage-remote-body", "exec"), namespace)
            self.assertEqual(json.loads(output.getvalue())["state"], "unknown")
            self.assertFalse((group / CORR).exists())
            self.assertEqual(calls, [])
            closed["identity"]["targetMsiArtifactId"] = REQUEST["targetMsiArtifactId"]
            closed_path.write_text(json.dumps(closed)); os.chmod(closed_path, 0o600)
            output = io.StringIO()
            with redirect_stdout(output): exec(compile(body, "stage-remote-body", "exec"), namespace)
            self.assertEqual(json.loads(output.getvalue())["state"], "unknown")
            self.assertTrue((group / CORR / "binding.json").exists())
            self.assertEqual(len(calls), 1)

    def test_stage_role_finishes_only_after_exact_terminal_receipt(self):
        intent = {"request": REQUEST, "leaseId": LEASE}
        result = {"version": 1, "correlationId": CORR, "code": "STAGED_NOT_SERVER_READY"}
        identity = {"leaseId": LEASE, "sourceSha": SOURCE}
        current = {"identity": identity, "state": "role-active", "server": "stopped",
                   "role": "stage", "correlationId": CORR}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(stage.base, "_campaign_identity", return_value=identity), \
             patch.object(stage.campaign_lease, "_active", return_value=current) as active, \
             patch.object(stage.campaign_lease, "_remote_confirm", return_value=True), \
             patch.object(stage.campaign_lease, "finish_role", return_value={"state": "active"}) as finish:
            self.assertTrue(stage._complete_stage_lease(Path(temporary), intent, result,
                            object(), object(), ("windows-cp117", "/qga", 42, 99, SID)))
            expected_digest = hashlib.sha256(json.dumps(result, sort_keys=True,
                                         separators=(",", ":")).encode()).hexdigest()
            self.assertEqual(finish.call_args.args[1:6],
                             (LEASE, "stage", CORR, expected_digest, "succeeded"))
            active.return_value = {**current, "correlationId": "33333333-3333-4333-8333-333333333333"}
            finish.reset_mock()
            self.assertFalse(stage._complete_stage_lease(Path(temporary), intent, result,
                             object(), object(), ("windows-cp117", "/qga", 42, 99, SID)))
            finish.assert_not_called()
            active.return_value = {**current, "role": "credentials",
                                   "correlationId": "33333333-3333-4333-8333-333333333333"}
            self.assertTrue(stage._complete_stage_lease(Path(temporary), intent, result,
                            object(), object(), ("windows-cp117", "/qga", 42, 99, SID)))
            finish.assert_not_called()

    def test_lost_remote_response_keeps_unknown_no_replay(self):
        pair = {"sourceFingerprint": "a" * 64, "targetMsiSha256": "d" * 64}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=None), \
             patch.object(stage.public, "_admit_pair", return_value=pair), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage, "_require_cross_route_lease", return_value=LEASE), \
             patch.object(stage, "_bundle", return_value=(io.BytesIO(b"bundle"), HASHES, 6, "2" * 64)), \
             patch.object(stage, "_reserve", return_value=Path(temporary) / "bundle.zip") as reserve, \
             patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
             patch.object(stage.campaign_lease, "claim_role", return_value={"state": "role-active"}), \
             patch.object(stage.base, "_remote", return_value=None) as remote:
            result = stage.start(temporary, REQUEST)
        self.assertEqual("unknown", result["state"])
        self.assertFalse(result["replayAllowed"])
        reserve.assert_called_once(); remote.assert_called_once()

    def test_status_rejects_changed_guest_or_file_hash(self):
        intent = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117", "socketPath": "/qga",
                  "pid": 42, "startTicks": 99, "expectedSid": SID, "sourceFingerprint": "a" * 64,
                  "bundleSha256": "2" * 64, "fileHashes": HASHES}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        observed = {"state": "observed", "correlationId": CORR, "result":
                    {"version": 1, "correlationId": CORR, "code": "STAGED_NOT_SERVER_READY",
                     "bundleSha256": "2" * 64, "files": {**HASHES, "fixture-receipt.json": "0" * 64},
                     "acl": {}, "rootAcl": {}, "stateAcl": STATE_ACL}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=intent), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_remote", return_value=json.dumps(observed).encode()):
            self.assertEqual("unknown", stage.status(temporary, {"correlationId": CORR})["state"])
        changed = {**intent, "startTicks": 100}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=changed), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_remote") as remote:
            self.assertEqual("unknown", stage.status(temporary, {"correlationId": CORR})["state"])
            remote.assert_not_called()

    def test_status_reports_only_staged_not_server_ready(self):
        intent = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117", "socketPath": "/qga",
                  "pid": 42, "startTicks": 99, "expectedSid": SID, "sourceFingerprint": "a" * 64,
                  "bundleSha256": "2" * 64, "fileHashes": HASHES}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        observed = {"state": "observed", "correlationId": CORR, "result":
                    {"version": 1, "correlationId": CORR, "code": "STAGED_NOT_SERVER_READY",
                     "bundleSha256": "2" * 64, "files": HASHES, "acl": {},
                     "rootAcl": {}, "stateAcl": STATE_ACL}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=intent), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_remote", return_value=json.dumps(observed).encode()), \
             patch.object(stage, "_complete_stage_lease", return_value=True), \
             patch.object(stage, "validate_stage_acl_receipt") as acl:
            result = stage.status(temporary, {"correlationId": CORR})
        self.assertEqual("staged-not-server-ready", result["state"])
        self.assertFalse(result["serverReady"])
        self.assertEqual(2, acl.call_count)

    def test_remote_status_uses_valid_durable_receipt_before_consumed_qga_status(self):
        receipt = {"version": 1, "correlationId": CORR, "code": "STAGED_NOT_SERVER_READY"}
        result = self._run_remote_status(
            json.dumps(receipt).encode(),
            lambda *_: self.fail("durable receipt must not query consumed status"))
        self.assertEqual({"state": "observed", "correlationId": CORR, "result": receipt}, result)

    def test_remote_status_fails_closed_for_missing_or_invalid_receipt(self):
        calls = []
        missing = self._run_remote_status(
            None,
            lambda *_: calls.append("status") or {"exited": True, "exitcode": 0,
                                                    "out-truncated": False, "err-truncated": False})
        self.assertEqual({"state": "unknown", "correlationId": CORR}, missing)
        self.assertEqual(["status"], calls)
        invalid = self._run_remote_status(
            b"{", lambda *_: self.fail("invalid receipt must not query QGA status"))
        self.assertEqual({"state": "unknown", "correlationId": CORR}, invalid)

    def test_status_rejects_partial_durable_receipt_before_completing_stage_lease(self):
        intent = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117",
                  "socketPath": "/qga", "pid": 42, "startTicks": 99, "expectedSid": SID,
                  "sourceFingerprint": "a" * 64, "bundleSha256": "2" * 64,
                  "fileHashes": HASHES}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        forged = {"state": "observed", "correlationId": CORR,
                  "result": {"version": 1, "correlationId": CORR,
                             "code": "STAGED_NOT_SERVER_READY", "bundleSha256": "2" * 64}}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=intent), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_remote", return_value=json.dumps(forged).encode()), \
             patch.object(stage, "_complete_stage_lease") as complete:
            self.assertEqual({"state": "unknown", "correlationId": CORR, "replayAllowed": False},
                             stage.status(temporary, {"correlationId": CORR}))
        complete.assert_not_called()

    def test_diagnostic_preserves_unknown_stage_and_identifies_remote_absence(self):
        """A lost 131MB QGA stream must be diagnosable without replaying it."""
        intent = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117",
                  "socketPath": "/qga", "pid": 42, "startTicks": 99, "expectedSid": SID,
                  "sourceFingerprint": "a" * 64, "bundleSha256": "2" * 64,
                  "bundleSize": 131218059, "fileHashes": HASHES}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        remote = {"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                  "phase": "remote-stage-absent"}
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=intent), \
             patch.object(stage.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64}), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_verified_claimed_campaign") as campaign, \
             patch.object(stage.base, "_remote", return_value=json.dumps(remote).encode()) as submit:
            result = stage.diagnose(temporary, {"correlationId": CORR})
        self.assertEqual({"state": "unknown", "correlationId": CORR, "binding": "exact",
                          "phase": "remote-stage-absent", "replayAllowed": False,
                          "nativeActionAllowed": False}, result)
        campaign.assert_called_once()
        submit.assert_called_once()

    def test_diagnostic_rejects_unbound_remote_receipt_projection(self):
        intent = {"request": REQUEST, "leaseId": LEASE, "environment": "windows-cp117",
                  "socketPath": "/qga", "pid": 42, "startTicks": 99, "expectedSid": SID,
                  "sourceFingerprint": "a" * 64, "bundleSha256": "2" * 64,
                  "bundleSize": 1, "fileHashes": HASHES}
        descriptor = (object(), type("Host", (), {"fixture_transfer_root": Path("/fixture")})(),
                      ("windows-cp117", "/qga", 42, 99, SID))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(stage, "_read_intent", return_value=intent), \
             patch.object(stage.public, "_admit_pair", return_value={"sourceFingerprint": "a" * 64}), \
             patch.object(stage.base, "_descriptor", return_value=descriptor), \
             patch.object(stage.base, "_verified_claimed_campaign"), \
             patch.object(stage.base, "_remote", return_value=json.dumps({
                 "state": "diagnosed", "correlationId": CORR, "binding": "exact",
                 "phase": "receipt-complete", "receipt": "unbound"}).encode()):
            result = stage.diagnose(temporary, {"correlationId": CORR})
        self.assertEqual("qga-protocol", result["phase"])
        self.assertFalse(result["replayAllowed"])

    def test_remote_diagnostic_executes_missing_stage_group_as_absent(self):
        """The remote probe must not turn a missing pre-transfer group into protocol loss."""
        body = stage._REMOTE_DIAGNOSTIC[stage._REMOTE_DIAGNOSTIC.index("import time\n"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / "windows-cp117"
            environment.mkdir(mode=0o700)
            os.chmod(root, 0o700)
            output = io.StringIO()
            args = [str(root), "windows-cp117", LEASE, CORR, "/qga", "42", "99", SID,
                    SOURCE, "a" * 64, "2" * 64, "1", REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"]]
            namespace = {"os": os, "stat": stat, "json": json, "base64": base64,
                         "time": __import__("time"), "sys": type("Args", (), {"argv": ["remote", *args]})(),
                         "live": lambda *_: True,
                         "call": lambda *_: self.fail("missing group must not call QGA"),
                         "read": lambda *_: self.fail("missing group must not read guest files"),
                         "decode": lambda raw: raw.decode("utf-8")}
            with redirect_stdout(output):
                with self.assertRaises(SystemExit) as exited:
                    exec(compile(ast.parse(body), "stage-diagnostic-remote", "exec"), namespace)
            self.assertEqual(0, exited.exception.code)
        self.assertEqual({"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                          "phase": "remote-stage-absent"}, json.loads(output.getvalue()))

    def test_remote_diagnostic_requires_explicit_nontruncated_guest_status(self):
        self.assertGreaterEqual(stage._REMOTE_DIAGNOSTIC.count("item.get('out-truncated') is not False"), 1)
        self.assertGreaterEqual(stage._REMOTE_DIAGNOSTIC.count("process.get('out-truncated') is not False"), 1)

    def test_remote_diagnostic_has_finite_read_only_failure_subphases(self):
        cases = (
            ("guest-stage-probe-failed", set(), lambda *_: (_ for _ in ()).throw(OSError())),
            ("dispatch-status-unknown", {"dispatch"}, lambda *_: {"exited": None}),
            ("result-read-failed", {"dispatch"}, lambda *_: {"exited": True, "exitcode": 0,
                                                            "out-truncated": False, "err-truncated": False}),
            ("receipt-invalid", {"dispatch"}, lambda *_: {"exited": True, "exitcode": 0,
                                                          "out-truncated": False, "err-truncated": False}),
        )
        for expected, names, call in cases:
            with self.subTest(phase=expected):
                if expected == "result-read-failed":
                    read = lambda *_: (_ for _ in ()).throw(OSError())
                elif expected == "dispatch-status-unknown":
                    read = lambda *_: None
                else:
                    read = lambda *_: b"{"
                result = self._run_remote_diagnostic(names, call, read)
                self.assertEqual({"state": "diagnosed", "correlationId": CORR,
                                  "binding": "exact", "phase": expected}, result)

    def test_remote_diagnostic_uses_receipt_before_consumed_dispatch_status(self):
        receipt = json.dumps({"correlationId": CORR, "code": "UNKNOWN"}).encode()
        result = self._run_remote_diagnostic(
            {"dispatch"}, lambda *_: self.fail("receipt must precede QGA status"), lambda *_: receipt)
        self.assertEqual({"state": "diagnosed", "correlationId": CORR,
                          "binding": "exact", "phase": "receipt-present-unverified"}, result)

    def test_remote_diagnostic_classifies_invalid_host_layout_without_raw_detail(self):
        body = stage._REMOTE_DIAGNOSTIC[stage._REMOTE_DIAGNOSTIC.index("import time\n"):]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = root / "windows-cp117"
            environment.mkdir(mode=0o700)
            group = environment / "windows-update-fixture-stage"
            group.write_text("not-a-directory")
            os.chmod(root, 0o700); os.chmod(environment, 0o700); os.chmod(group, 0o600)
            output = io.StringIO()
            args = [str(root), "windows-cp117", LEASE, CORR, "/qga", "42", "99", SID,
                    SOURCE, "a" * 64, "2" * 64, "1", REQUEST["fixtureReceiptArtifactId"],
                    REQUEST["baseMsiArtifactId"], REQUEST["targetMsiArtifactId"]]
            namespace = {"os": os, "stat": stat, "json": json, "base64": base64,
                         "time": __import__("time"), "sys": type("Args", (), {"argv": ["remote", *args]})(),
                         "live": lambda *_: True, "call": lambda *_: self.fail("no QGA"),
                         "read": lambda *_: self.fail("no receipt read"),
                         "decode": lambda raw: raw.decode("utf-8")}
            with redirect_stdout(output):
                with self.assertRaises(SystemExit):
                    exec(compile(ast.parse(body), "stage-diagnostic-layout", "exec"), namespace)
        self.assertEqual({"state": "diagnosed", "correlationId": CORR, "binding": "exact",
                          "phase": "remote-layout-invalid"}, json.loads(output.getvalue()))

    def test_remote_guest_stage_program_assigns_conditional_before_hashtable(self):
        """PS5 rejects stage=if(...) inside a hashtable literal.

        The lost extraction response exercised this read-only diagnostic path,
        so keep the generated guest program parseable without rerunning the
        extraction dispatch.
        """
        program = stage._REMOTE_DIAGNOSTIC
        self.assertNotIn("stage=if($ok)", program)
        self.assertIn("$state=if($ok){'full'}else{'partial'}", program)
        self.assertIn("@{version=1;stage=$state}", program)
        self.assertLess(program.index("$state=if($ok){'full'}else{'partial'}"),
                        program.index("@{version=1;stage=$state}"))

    def test_private_server_state_acl_rejects_recipient_read_only(self):
        bad = {**STATE_ACL, "acl": [dict(item) for item in STATE_ACL["acl"]]}
        bad["acl"][-1]["rights"] = 0x1200A9
        with self.assertRaises(stage.WindowsUpdateFixtureStageError):
            stage._validate_state_acl(bad, SID, STATE_ACL["stage"])


if __name__ == "__main__":
    unittest.main()
