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
import stat
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
        self.assertIn("$item=$item.Parent", script)
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
            closed = {"state": "closed", "identity": {"leaseId": OLD_LEASE}}
            with patch.object(stage.base, "_descriptor", return_value=(object(), object(), None)), \
                 patch.object(stage.base, "_campaign_remote", return_value=lambda *_: None), \
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

    def test_private_server_state_acl_rejects_recipient_read_only(self):
        bad = {**STATE_ACL, "acl": [dict(item) for item in STATE_ACL["acl"]]}
        bad["acl"][-1]["rights"] = 0x1200A9
        with self.assertRaises(stage.WindowsUpdateFixtureStageError):
            stage._validate_state_acl(bad, SID, STATE_ACL["stage"])


if __name__ == "__main__":
    unittest.main()
