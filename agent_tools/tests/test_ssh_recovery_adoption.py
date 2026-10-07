"""Causal local-only tests for nested SSH recovery adoption."""
import json
import hashlib
import os
import stat
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_connection_recovery as recovery
from agent_tools import ssh_recovery_adoption as adoption
from agent_tools import ssh_transport


def inventory(old: str) -> dict:
    return {"schemaVersion": 1, "hosts": {
        "gateway": {"host": "gateway.example", "user": "user", "port": 22,
                    "identityFile": "/tmp/key", "knownHostsFile": "/tmp/known"},
        "nested": {"host": "nested.example", "user": "user", "port": 22,
                   "identityFile": "/tmp/key", "knownHostsFile": "/remote/known",
                   "transport": "nested", "gateway": "gateway", "remoteHostAlias": "target",
                   "remoteControlPath": old},
    }}


class RecoveryAdoptionTest(unittest.TestCase):
    def write(self, root: Path, value: dict) -> None:
        path = root / ssh_transport.CONFIG_FILENAME
        path.write_text(json.dumps(value), encoding="utf-8"); os.chmod(path, 0o600)

    def ready_intent(self, root: Path, control: str) -> None:
        target = ssh_transport.load_config(root).hosts["nested"]
        recovery._create_intent(root, "nested", target, "a" * 32, control)
        recovery._update_intent(root, "nested", target, "a" * 32, "ready", control)

    def test_adopts_ready_recovery_after_configured_socket_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = "/remote/original/m"; new = "/remote/original/r-aaaaaaaaaaaaaaa/m"
            self.write(root, inventory(old)); self.ready_intent(root, new)
            with mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")):
                result = adoption.adopt(root, "nested", 5)
            self.assertEqual({"state": "ready", "nextAction": "configured-probe", "replayAllowed": False}, result)
            config = ssh_transport.load_config(root)
            self.assertEqual(new, str(config.hosts["nested"].remote_control_path))
            # The next configured probe uses the adopted socket and can pass.
            with mock.patch.object(recovery, "_socket_state", return_value="ready") as probe:
                self.assertEqual("ready", recovery._socket_state(config, config.hosts["nested"], config.hosts["nested"].remote_control_path, 5))
            probe.assert_called_once()

    def test_gateway_change_during_second_probe_never_adopts_wrong_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = "/remote/original/m"; new = "/remote/original/r-aaaaaaaaaaaaaaa/m"
            self.write(root, inventory(old)); self.ready_intent(root, new)
            calls = []
            def probe(*args):
                calls.append(args)
                if len(calls) == 2:
                    changed = inventory(old); changed["hosts"]["gateway"]["host"] = "foreign.example"
                    self.write(root, changed)
                    return "ready"
                return "absent"
            with mock.patch.object(recovery, "_socket_state", side_effect=probe):
                self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def test_foreign_pending_or_socket_race_fails_without_replacing_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = "/remote/original/m"; self.write(root, inventory(old))
            self.ready_intent(root, "/remote/original/r-aaaaaaaaaaaaaaa/m")
            with mock.patch.object(recovery, "_socket_state", side_effect=("absent", "unknown")):
                self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))
            with mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")), \
                    mock.patch.object(adoption._Snapshot, "guard", side_effect=ValueError("race")):
                self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def test_rejects_symlink_inventory_and_never_creates_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / "real.json"; target.write_text(json.dumps(inventory("/remote/original/m")))
            os.chmod(target, 0o600); (root / ssh_transport.CONFIG_FILENAME).symlink_to(target)
            self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertFalse((root / adoption._RECEIPTS).exists())

    def test_existing_exact_generation_fence_is_a_no_replay_crash_barrier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); old = "/remote/original/m"; new = "/remote/original/r-aaaaaaaaaaaaaaa/m"
            self.write(root, inventory(old)); self.ready_intent(root, new)
            target = ssh_transport.load_config(root).hosts["nested"]
            intent = recovery._read_intent(root, "nested", target)
            assert intent is not None
            adoption._create_receipt(root, "nested", old, new, intent, "pending")
            with mock.patch.object(recovery, "_socket_state", side_effect=AssertionError("must not probe or mutate")):
                self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def fixture(self, directory):
        root = Path(directory).resolve()
        old = "/remote/original/m"; new = "/remote/original/r-aaaaaaaaaaaaaaa/m"
        self.write(root, inventory(old)); self.ready_intent(root, new)
        target = ssh_transport.load_config(root).hosts["nested"]
        return root, old, new, recovery._intent_path(root, "nested", target)

    def assert_no_replace(self, root, action):
        with mock.patch.object(adoption.os, "replace", wraps=os.replace) as replacement, \
                mock.patch.object(recovery, "_socket_state", side_effect=action):
            self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
        replacement.assert_not_called()

    def test_full_generation_body_and_intent_races_reject_before_effect(self):
        for attack in ("ctime", "same_inode_bytes", "hardlink", "intent_bytes", "intent_symlink", "parent"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, intent_path = self.fixture(directory)
                config_path = root / ssh_transport.CONFIG_FILENAME
                info = config_path.stat(); calls = []
                def probe(*args):
                    calls.append(args)
                    if len(calls) == 2:
                        if attack == "ctime":
                            os.chmod(config_path, 0o400); os.chmod(config_path, 0o600)
                        elif attack == "same_inode_bytes":
                            changed = inventory(old); changed["hosts"]["gateway"]["host"] = "foreign.example"
                            self.write(root, changed)
                            os.utime(config_path, ns=(info.st_atime_ns, info.st_mtime_ns))
                        elif attack == "hardlink":
                            os.link(config_path, root / "hardlink")
                        elif attack == "intent_bytes":
                            value = json.loads(intent_path.read_text()); value["state"] = "unknown"
                            intent_path.write_text(json.dumps(value))
                        elif attack == "intent_symlink":
                            saved = intent_path.with_suffix(".saved"); intent_path.rename(saved); intent_path.symlink_to(saved)
                        else:
                            saved = intent_path.parent.with_name("old-recovery")
                            intent_path.parent.rename(saved); intent_path.parent.mkdir(mode=0o700)
                        return "ready"
                    return "absent"
                self.assert_no_replace(root, probe)
                self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def test_inventory_is_strict_before_actual_loader_or_probes(self):
        for attack in ("symlink", "hardlink", "mode", "short_read"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, _ = self.fixture(directory)
                path = root / ssh_transport.CONFIG_FILENAME
                if attack == "symlink":
                    saved = root / "saved"; path.rename(saved); path.symlink_to(saved)
                elif attack == "hardlink":
                    os.link(path, root / "link")
                elif attack == "mode":
                    os.chmod(path, 0o644)
                original_read = os.read
                def read(fd, size):
                    data = original_read(fd, size)
                    return data[:-1] if attack == "short_read" else data
                with mock.patch.object(adoption.os, "read", side_effect=read), \
                        mock.patch.object(ssh_transport, "load_config", side_effect=AssertionError("loader before strict admission")), \
                        mock.patch.object(recovery, "_socket_state", side_effect=AssertionError("probe before strict admission")):
                    self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])

    def test_intent_has_exact_schema_correlation_and_named_generation(self):
        for attack in ("correlation", "path", "host", "extra", "duplicate", "mode", "hardlink", "symlink", "legacy_only"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, path = self.fixture(directory)
                value = json.loads(path.read_text())
                if attack == "correlation": value["correlationId"] = "z" * 32
                elif attack == "path": value["controlPath"] = new + "/../m"
                elif attack == "host": value["host"] = "foreign"
                elif attack == "extra": value["extra"] = "secret"
                if attack in {"correlation", "path", "host", "extra"}:
                    path.write_text(json.dumps(value))
                elif attack == "duplicate": path.write_text(json.dumps(value)[:-1] + ',"state":"ready"}')
                elif attack == "mode": os.chmod(path, 0o644)
                elif attack == "hardlink": os.link(path, path.with_suffix(".link"))
                elif attack == "symlink":
                    saved = path.with_suffix(".saved"); path.rename(saved); path.symlink_to(saved)
                else: path.rename(path.parent / "nested.json")
                with mock.patch.object(recovery, "_socket_state", side_effect=AssertionError("must not probe")):
                    self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])

    def test_pending_file_creation_failure_preserves_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory)
            before = (root / ssh_transport.CONFIG_FILENAME).read_bytes()
            with mock.patch.object(adoption, "_write_receipt", side_effect=OSError("receipt failure")):
                self.assert_no_replace(root, ("absent", "ready"))
            self.assertEqual(before, (root / ssh_transport.CONFIG_FILENAME).read_bytes())

    def test_pending_directory_fsync_failure_is_no_effect_and_no_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory)
            receipts = root / adoption._RECEIPTS; receipts.mkdir(parents=True, mode=0o700)
            with adoption._Directory(receipts) as receipt_dir, adoption._ConfigLock(receipt_dir):
                pass
            receipt_inode = receipts.stat().st_ino; fsync = os.fsync
            def fail_directory(fd):
                info = os.fstat(fd)
                if stat.S_ISDIR(info.st_mode) and info.st_ino == receipt_inode:
                    raise OSError("directory fsync failure")
                return fsync(fd)
            with mock.patch.object(adoption.os, "fsync", side_effect=fail_directory):
                self.assert_no_replace(root, ("absent", "ready"))
            self.assertEqual(1, len(list(receipts.glob("*.pending.json"))))
            self.assert_no_replace(root, AssertionError("pending forbids replay"))
            self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def test_post_pending_race_keeps_barrier_and_never_replaces(self):
        for attack in ("config", "intent", "pending", "pending_bytes", "parent"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, intent_path = self.fixture(directory)
                write_receipt = adoption._write_receipt
                def raced(directory, name, value):
                    pin = write_receipt(directory, name, value)
                    if attack == "config": self.write(root, inventory(old))
                    elif attack == "intent": intent_path.write_bytes(intent_path.read_bytes() + b" ")
                    elif attack == "pending": os.chmod(directory.path / name, 0o644)
                    elif attack == "pending_bytes": (directory.path / name).write_bytes(b'{"state":"foreign"}')
                    else:
                        directory.path.rename(directory.path.with_name("old-adoption"))
                        directory.path.mkdir(mode=0o700)
                    return pin
                with mock.patch.object(adoption, "_write_receipt", side_effect=raced):
                    self.assert_no_replace(root, ("absent", "ready"))
                self.assertEqual(old, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))

    def test_terminal_or_symlink_pending_blocks_before_probe(self):
        for kind in ("pending", "adopted", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, old, new, path = self.fixture(directory)
                intent = json.loads(path.read_text())
                adoption._create_receipt(root, "nested", old, new, intent, "adopted" if kind == "adopted" else "pending")
                if kind == "symlink":
                    pending = next((root / adoption._RECEIPTS).glob("*.pending.json"))
                    pending.unlink(); pending.symlink_to(root / "missing")
                self.assert_no_replace(root, AssertionError("existing barrier forbids probe"))

    def test_candidate_actual_schema_and_graph_validation_rejects_before_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory)
            original = adoption._json; source = (root / ssh_transport.CONFIG_FILENAME).read_bytes(); count = 0
            def invalid_candidate(body):
                nonlocal count
                result = original(body)
                if body == source:
                    count += 1
                    # Initial validation, route hash, then actual candidate edit.
                    if count == 3: result["hosts"]["gateway"]["port"] = True
                return result
            with mock.patch.object(adoption, "_json", side_effect=invalid_candidate):
                self.assert_no_replace(root, ("absent", "ready"))
            self.assertFalse(list((root / adoption._RECEIPTS).glob("*.pending.json")))
        for mutation in ("unknown", "duplicate", "graph", "schema"):
            raw = inventory("/remote/original/m")
            if mutation == "unknown": raw["hosts"]["gateway"]["unknown"] = 1
            elif mutation == "graph": raw["hosts"]["nested"]["gateway"] = "nested"
            elif mutation == "schema": raw["schemaVersion"] = True
            body = json.dumps(raw).encode()
            if mutation == "duplicate": body = body[:-1] + b',"schemaVersion":1}'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                adoption._validate_candidate(body)

    def test_success_preserves_every_other_private_field_and_fsyncs_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory)
            value = inventory(old); value["hosts"]["gateway"]["password"] = "private-password"
            value["nativeBaselines"] = {"private": {"opaque": "retained"}}
            self.write(root, value)
            with mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")), \
                    mock.patch.object(adoption.os, "fsync", wraps=os.fsync) as sync:
                result = adoption.adopt(root, "nested")
            self.assertEqual("ready", result["state"])
            self.assertNotIn("private-password", json.dumps(result))
            value["hosts"]["nested"]["remoteControlPath"] = new
            self.assertEqual(value, json.loads((root / ssh_transport.CONFIG_FILENAME).read_bytes()))
            receipts = root / adoption._RECEIPTS
            self.assertEqual(1, len(list(receipts.glob("*.pending.json"))))
            self.assertEqual(1, len(list(receipts.glob("*.adopted.json"))))
            self.assertGreater(sync.call_count, 5)
            for path in receipts.glob("*.json"):
                self.assertNotIn("private-password", path.read_text())

    def test_terminal_failure_leaves_pending_and_reports_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory)
            writer = adoption._write_receipt
            def fail_terminal(directory, name, value):
                if name.endswith(".adopted.json"): raise OSError("terminal creation failure")
                return writer(directory, name, value)
            with mock.patch.object(recovery, "_socket_state", side_effect=("absent", "ready")), \
                    mock.patch.object(adoption, "_write_receipt", side_effect=fail_terminal):
                self.assertEqual("unknown", adoption.adopt(root, "nested")["state"])
            self.assertEqual(new, str(ssh_transport.load_config(root).hosts["nested"].remote_control_path))
            self.assertEqual(1, len(list((root / adoption._RECEIPTS).glob("*.pending.json"))))
            self.assert_no_replace(root, AssertionError("unknown adoption is not replayable"))

    def test_named_root_parent_change_and_candidate_source_race_reject(self):
        for attack in ("root", "loader", "candidate"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                parent = Path(directory).resolve(); root = parent / "repo"; root.mkdir(mode=0o700)
                root, old, new, _ = self.fixture(root)
                validator = adoption._validate_candidate; calls = 0
                def raced(body, config_root=None):
                    nonlocal calls
                    result = validator(body, config_root); calls += 1
                    if (attack == "loader" and calls == 1) or (attack == "candidate" and calls == 3):
                        self.write(root, inventory(old))
                    return result
                def probe(*args):
                    if str(args[2]) == new:
                        if attack == "root":
                            root.rename(parent / "old-repo"); root.mkdir(mode=0o700)
                        return "ready"
                    return "absent"
                with mock.patch.object(adoption, "_validate_candidate", side_effect=raced), \
                        mock.patch.object(recovery, "_read_intent", side_effect=AssertionError("upstream reader is forbidden")):
                    self.assert_no_replace(root, probe)

    def test_unrelated_config_edit_cannot_hide_same_route_pending_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, intent_path = self.fixture(directory)
            adoption._create_receipt(root, "nested", old, new, json.loads(intent_path.read_text()), "pending")
            value = inventory(old); value["nativeBaselines"] = {"unrelated": {"generation": "new"}}
            self.write(root, value)
            self.assert_no_replace(root, AssertionError("same route is already fenced"))

    def test_legacy_and_changed_route_fences_do_not_allow_consumed_intent_replay(self):
        for mode in ("legacy", "route"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root, old, new, path = self.fixture(directory)
                intent = json.loads(path.read_text())
                if mode == "legacy":
                    receipts = root / adoption._RECEIPTS; receipts.mkdir(parents=True, mode=0o700)
                    key = hashlib.sha256(json.dumps(["nested", old, new, intent["correlationId"]], separators=(",", ":")).encode()).hexdigest()
                    record = receipts / (key + ".pending.json")
                    record.write_text("{}"); os.chmod(record, 0o600)
                else:
                    with adoption._Directory(root) as source_dir, adoption._Snapshot(source_dir, ssh_transport.CONFIG_FILENAME) as source:
                        config = adoption._validate_candidate(source.body, root)
                        route_sha = adoption._route_sha(source.body, config, "nested")
                        key = adoption._route_key("nested", old, new, intent["correlationId"], route_sha)
                        with adoption._receipt_directory(source_dir) as receipts:
                            adoption._write_receipt(receipts, key + ".pending.json", {
                                "host": "nested", "oldControlPath": old, "controlPath": new,
                                "correlationId": intent["correlationId"], "state": "unknown"})
                    value = inventory(old); value["hosts"]["gateway"]["port"] = 2222
                    self.write(root, value)
                self.assert_no_replace(root, AssertionError("consumed intent is never fresh"))

    def test_final_terminal_absence_hook_drift_rejects_before_replace(self):
        for attack in ("gateway", "intent", "pending", "candidate", "lock"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, intent_path = self.fixture(directory)
                exists = adoption._exists; fired = []
                def final_check(receipts, name):
                    result = exists(receipts, name)
                    candidates = list(root.glob(".ssh-adopt-*"))
                    if name.endswith(".adopted.json") and candidates and not fired:
                        fired.append(attack)
                        if attack == "gateway":
                            value = inventory(old); value["hosts"]["gateway"]["host"] = "foreign.example"
                            self.write(root, value)
                        elif attack == "intent": intent_path.write_bytes(intent_path.read_bytes() + b" ")
                        elif attack == "pending":
                            path = next(receipts.path.glob("*.pending.json")); path.write_bytes(path.read_bytes() + b" ")
                        elif attack == "candidate": candidates[0].write_bytes(b'{"changed":true}')
                        else: (receipts.path / adoption._ConfigLock.name).write_bytes(b"changed-lock\n")
                    return result
                with mock.patch.object(adoption, "_exists", side_effect=final_check):
                    self.assert_no_replace(root, ("absent", "ready"))
                self.assertEqual([attack], fired)

    def test_cooperative_lock_contention_blocks_second_adopter_before_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root, old, new, _ = self.fixture(directory); calls = []; nested_results = []
            def probe(*args):
                calls.append(args)
                if len(calls) == 1:
                    nested_results.append(adoption.adopt(root, "nested"))
                    return "absent"
                return "ready"
            with mock.patch.object(recovery, "_socket_state", side_effect=probe):
                self.assertEqual("ready", adoption.adopt(root, "nested")["state"])
            self.assertEqual(2, len(calls))
            self.assertEqual([adoption._unknown()], nested_results)

    def test_cooperative_lock_has_strict_private_named_generation(self):
        for attack in ("symlink", "hardlink", "mode", "body"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as directory:
                root, old, new, _ = self.fixture(directory)
                with adoption._Directory(root) as source_dir, adoption._receipt_directory(source_dir) as receipts:
                    with adoption._ConfigLock(receipts):
                        pass
                    lock_path = receipts.path / adoption._ConfigLock.name
                    if attack == "symlink":
                        saved = root / "old-lock"; lock_path.rename(saved); lock_path.symlink_to(saved)
                    elif attack == "hardlink": os.link(lock_path, root / "lock-link")
                    elif attack == "mode": os.chmod(lock_path, 0o644)
                    else: lock_path.write_bytes(b"foreign-lock\n")
                self.assert_no_replace(root, AssertionError("invalid ownership lock prohibits probe"))


if __name__ == "__main__":
    unittest.main()
