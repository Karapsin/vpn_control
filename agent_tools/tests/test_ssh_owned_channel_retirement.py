"""Finite historical admission, real source-view custody and no-replay fence."""
import ast
from contextlib import closing
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import socket
import shutil
import sys
import tempfile
import types
import unittest
import uuid
import re
import time
import base64
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures/owned_channel_retirement"


def _retained_mcp_pair():
    """Retained exact CURRENT_MCP source and its guard-free BEFORE_MCP derivation."""
    current = (FIXTURE.parent / "windows_native_packet_recipe/mcp_server.source").read_bytes()
    function = next(node for node in ast.parse(current).body if isinstance(node, ast.FunctionDef) and node.name == "_ssh_workflow_impl")
    guard = next(node for node in ast.walk(function) if isinstance(node, ast.If) and ast.unparse(node.test) == "os.name != 'posix'")
    lines = current.splitlines(keepends=True)
    return b"".join(lines[:guard.lineno - 1] + lines[guard.end_lineno:]), current


@unittest.skipUnless(os.name == "posix", "POSIX private channel coordinator")
class OwnedChannelRetirementTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import ssh_owned_channel_retirement as subject
        self.subject = subject
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-channel-retire-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def test_authentic_original_records_and_all_capsule_members_are_bound(self):
        subject = self.subject
        provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
        records = {}
        for name, digest in (("intent", subject.INTENT_SHA), ("ready", subject.READY_SHA)):
            raw = (FIXTURE / (name + ".json")).read_bytes()
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertEqual({"sha256": digest, "bytes": len(raw), "role": provenance["records"][name]["role"]}, provenance["records"][name])
            records[name] = json.loads(raw)
        self.assertEqual(subject.CORRELATION, records["intent"]["correlationId"])
        self.assertEqual(subject.READY_SHA, provenance["records"]["ready"]["sha256"])
        self.assertEqual(set(subject.direct.source_catalog(records["intent"]["version"])), set(records["intent"]["directSourcePins"]))
        self.assertEqual(records["intent"]["sourceSha256"], records["intent"]["directSourcePins"]["ssh_fresh_nested_channel.py"])
        self.assertTrue(subject.channel._master_shape(records["ready"]["result"]["master"]))
        # Input identities are rejected before opening any repository/private file.
        for host, corr in (("other", subject.CORRELATION), ("archlinux", "0" * 32)):
            with self.assertRaisesRegex(ValueError, "retirement_identity"):
                with subject._original(self.root, host, corr, str(uuid.uuid4())):
                    self.fail("identity must not enter")

    def test_exact_guard_only_historical_mcp_data_transition(self):
        subject = self.subject
        # BEFORE_MCP/CURRENT_MCP are authentic historical records, not the live
        # merged MCP; the retained exact source keeps this data edge reproducible.
        before, current = _retained_mcp_pair()
        self.assertEqual(subject.CURRENT_MCP, hashlib.sha256(current).hexdigest())
        self.assertEqual(subject.BEFORE_MCP, hashlib.sha256(before).hexdigest())
        subject._mcp_data_transition(before, current)
        for old, new in ((before + b"\n", current), (before, current + b"\n"), (current, before)):
            with self.assertRaisesRegex(ValueError, "retirement_mcp_source"):
                subject._mcp_data_transition(old, new)

    def _view(self):
        subject = self.subject
        directory = subject.private.Directory(self.root)
        self.addCleanup(directory.close)
        capsules = {}
        for name in subject.direct._SOURCE_NAMES:
            raw = (ROOT / "agent_tools" / name).read_bytes()
            # Historical MCP is deliberately untrusted data. The real loader
            # must reject this import without executing even one statement.
            if name == "mcp_server.py":
                raw = ("from pathlib import Path\nPath(" + repr(str(self.root / "EXECUTED")) + ").touch()\n").encode()
            capsules[name] = types.SimpleNamespace(body=raw, digest=hashlib.sha256(raw).hexdigest())
        return subject._source_view(directory, capsules)

    def test_real_capsule_namespace_and_historical_mcp_import_refusal(self):
        subject = self.subject
        view, expected = self._view()
        self.assertNotIn(str(view / "mcp_server.py"), expected)
        with closing(subject.loader.SourceSession(view, "ssh_direct_nested_channel", expected_sources=expected)) as session:
            self.assertEqual(str(view / "ssh_direct_nested_channel.py"), session.module.__file__)
            self.assertNotEqual((ROOT / "agent_tools/ssh_direct_nested_channel.py").stat().st_ino,
                                (view / "ssh_direct_nested_channel.py").stat().st_ino)
            native = session.load("ssh_fresh_nested_channel")
            self.assertEqual(subject.channel._REMOTE, native._REMOTE)
            for name, (path, raw) in session.cache.items():
                self.assertEqual(Path(path).read_bytes(), raw)
                self.assertEqual(subject.private._generation(Path(path).stat()), session.held.files[path][1])
            with self.assertRaisesRegex(ValueError, "expected_source_bytes_changed"):
                session.load("mcp_server")
            self.assertFalse((self.root / "EXECUTED").exists())
            session.guard()

    def test_capsule_replacement_is_rejected_by_real_held_generations(self):
        subject = self.subject
        view, expected = self._view()
        with closing(subject.loader.SourceSession(view, "ssh_direct_nested_channel", expected_sources=expected)) as session:
            path = view / "ssh_direct_nested_channel.py"
            replacement = view / "replacement"
            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600)
            replacement.replace(path)
            with self.assertRaises(ValueError):
                session.guard()

    def test_exclusive_selection_fence_blocks_real_shared_admission(self):
        subject = self.subject
        with subject.private.Directory(self.root) as directory:
            with subject.selection._Lock(directory):
                script = "import fcntl,os,sys;f=os.open(sys.argv[1],os.O_RDONLY);fcntl.flock(f,fcntl.LOCK_SH|fcntl.LOCK_NB)"
                child = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(self.root / "selection.lock")],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                self.assertNotEqual(0, child.returncode)
                self.assertIn(b"BlockingIOError", child.stderr)

    def test_real_config_lock_handoff_allows_authentic_status_lock(self):
        subject = self.subject
        with subject.private.Directory(self.root) as directory:
            with subject.private.InventoryLock(directory) as original:
                with self.assertRaises(BlockingIOError):
                    subject.private.InventoryLock(directory)
                subject.private.fcntl.flock(original.snapshot.fd, subject.private.fcntl.LOCK_UN)
                with subject.private.InventoryLock(directory) as status:
                    status.guard(); original.guard()
                original.guard()

    def test_single_exit_claim_blocks_every_later_uuid_after_lost_ack(self):
        subject = self.subject
        operation = self.root / str(uuid.uuid4()); operation.mkdir(mode=0o700)
        with subject.private.Directory(operation) as output:
            with subject._claim_exit(output, operation.name):
                pass
        first = (self.root / (subject.CORRELATION + ".exit-intent.json")).read_bytes()
        # A lost collector acknowledgment cannot turn a new ID into another exit.
        other = self.root / str(uuid.uuid4()); other.mkdir(mode=0o700)
        with subject.private.Directory(other) as output:
            with self.assertRaises(FileExistsError):
                with subject._claim_exit(output, other.name):
                    self.fail("second exit claim")
        self.assertEqual(first, (self.root / (subject.CORRELATION + ".exit-intent.json")).read_bytes())

    def test_real_original_child_terminal_dual_eof_capture_and_positive_absence(self):
        subject = self.subject
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time;time.sleep(30)"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.addCleanup(process.wait)
        with self.assertRaisesRegex(ValueError, "retirement_local_owner_present"):
            subject._local_absent(process.pid)
        process.terminate(); process.communicate(timeout=5)
        subject._local_absent(process.pid)
        capture = subject.channel._collect([sys.executable, "-I", "-B", "-c",
            "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write('Ω'.encode());sys.stderr.buffer.write(b'raw');raise SystemExit(7)"], b"{}", 5)
        self.assertTrue(capture["complete"])
        self.assertEqual({"stdout": True, "stderr": True}, capture["eof"])
        self.assertEqual(7, capture["returnCode"])
        self.assertEqual(("Ω".encode(), b"raw"), (capture["stdout"], capture["stderr"]))
        with subject.private.Directory(self.root) as output:
            subject._capture(output, "actual-child", capture)
        self.assertEqual(capture["stdout"], (self.root / "actual-child.stdout").read_bytes())
        subject._local_absent(capture["pid"])

    def _native(self, *, active_unix=False, tcp_state="01", birth=123, missing_ready=False,
                action="observe", exit_code=0, subject=None, default_config=False, correlation=None):
        """Unchanged current native body, private inert Linux facts and real child.

        Native route facts are the declared seam; the production host admission,
        snapshot/census/parser/claim code and actual child EOF collector execute.
        This is a routine logic fixture, never a native acceptance receipt.
        """
        subject = subject or self.subject
        # /tmp is the modeled Linux root's own path, so the real root stays outside it:
        # short enough for the AF_UNIX bind, and never remapped into itself on Linux.
        short = tempfile.TemporaryDirectory(prefix="r-", dir="/var/tmp")
        self.addCleanup(short.cleanup)
        native = Path(short.name).resolve()
        corr = correlation or subject.CORRELATION; stage = native / "tmp" / ("vpn-channel-" + corr)
        stage.mkdir(parents=True, mode=0o700)
        sock = socket.socket(socket.AF_UNIX)
        self.addCleanup(sock.close)
        sock.bind(str(stage / "m")); (stage / "m").chmod(0o600)
        proc = native / "proc"; (proc / "net").mkdir(parents=True)
        (proc / "sys/kernel/random").mkdir(parents=True)
        boot = "00000000-0000-0000-0000-000000000001"
        (proc / "sys/kernel/random/boot_id").write_text(boot + "\n")
        actor = proc / "98765"; (actor / "fd").mkdir(parents=True)
        (actor / "stat").write_bytes(b"98765 (ssh) " + b" ".join([b"S"] + [b"0"] * 18 + [str(birth).encode()]) + b"\n")
        for index, inode in enumerate((444, 666, *((555,) if active_unix else ()))):
            (actor / "fd" / str(index)).symlink_to("socket:[%d]" % inode)
        table = b"Num       RefCount Protocol Flags    Type St Inode Path\n00000000: 00000002 00000000 00010000 0001 01 444 " + ("/tmp/vpn-channel-" + corr + "/m").encode() + b"\n"
        if active_unix:
            table += b"00000000: 00000003 00000000 00000000 0001 03 555\n"
        (proc / "net/unix").write_bytes(table)
        (proc / "net/tcp").write_text("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: 0100007F:1234 0200007F:0016 " + tcp_state + " 0:0 0:0 0 0 0 666\n")
        (proc / "net/tcp6").write_text("  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")
        home = native / "home/fixture"; (home / ".ssh").mkdir(parents=True, mode=0o700)
        config_path = home / ".ssh/config"
        config_path.write_text("Host fixture\n HostName example.test\n"); config_path.chmod(0o600)
        master = {"actor": {"pid": 98765, "startTicks": 123, "uid": os.getuid()},
                  "socket": list(subject.private._generation((stage / "m").stat())),
                  "directory": list(subject.private._directory_identity(stage.stat())),
                  "listenerInode": "444", "gatewayBoot": boot}
        ready = {"state": "ready", "correlationId": corr, "controlPath": "/tmp/vpn-channel-" + corr + "/m",
                 "arch": {"uid": 1000, "boot": boot}, "master": master}
        intent = {"correlationId": corr, "gatewayBoot": boot, "gatewayUid": os.getuid(),
                  "sourceSha256": "a" * 64, "configPin": {"fixture": "config"}, "effectiveRoute": {"fixture": "route"}}
        for name, value in (("intent", intent), ("ready", ready)):
            path = stage / (name + ".json"); path.write_text(json.dumps(value)); path.chmod(0o600)
        if missing_ready:
            (stage / "ready.json").unlink()
        request = {"operationId": str(uuid.uuid4()), "action": action, "ready": ready,
                   "sourceSha256": "a" * 64, "config": "" if default_config else str(config_path), "profile": "fixture"}
        def mapped(path):
            value = os.fspath(path)
            return str(native / value[1:]) if value.startswith(("/proc", "/tmp")) else value
        # Linux native facts are the declared seam. Shared Mac /tmp ancestor
        # timestamps must not become Linux config mutations. Keep real ancestor
        # structure and every owned native directory/config leaf fully strict.
        outside = {(info.st_dev, info.st_ino): info for info in (path.stat() for path in native.parents)}
        def observed(info):
            previous = outside.get((info.st_dev, info.st_ino))
            if previous is None or not __import__("stat").S_ISDIR(info.st_mode): return info
            return types.SimpleNamespace(**{name: getattr(info if name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid") else previous, name)
                for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")})
        facade = types.SimpleNamespace(**vars(os))
        for name in ("open", "stat", "lstat", "listdir", "readlink", "mkdir"):
            original = getattr(os, name)
            if name in ("stat", "lstat"):
                setattr(facade, name, lambda path, *args, _original=original, **kwargs: observed(_original(mapped(path), *args, **kwargs)))
            else:
                setattr(facade, name, lambda path, *args, _original=original, **kwargs: _original(mapped(path), *args, **kwargs))
        facade.fstat = lambda fd: observed(os.fstat(fd))
        facade.path = types.SimpleNamespace(**vars(os.path))
        facade.path.lexists = lambda path: os.path.lexists(mapped(path))
        class NativePath:
            def __new__(cls, path):
                return Path(mapped(path))
            @staticmethod
            def home():
                return home
        calls = []
        def inner(argv, timeout):
            calls.append(argv)
            collector = (lambda argv, payload, timeout: subject._fixed546_capture(argv, None, timeout, input_allowed=False)) if corr == getattr(subject, "THIRD_CORRELATION", None) else subject.channel._collect
            capture = collector([sys.executable, "-I", "-B", "-c",
                "import sys;sys.stdin.buffer.read();sys.stderr.write('Exit request sent.\\n');raise SystemExit(" + str(exit_code) + ")"], b"{}", timeout)
            if exit_code == 0:
                (stage / "m").unlink(); shutil.rmtree(actor)
                (proc / "net/unix").write_bytes(table.splitlines(keepends=True)[0])
            return capture
        namespace = {"json": json, "sys": types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode()))),
                     "os": facade, "Path": NativePath, "stat": __import__("stat"),
                     "re": re, "time": time, "base64": base64, "hashlib": hashlib,
                     "generation": lambda info: list(subject.private._generation(info)),
                     "reject_pairs": subject.transport._reject_duplicate_keys,
                     "effective_route": lambda *args: intent["effectiveRoute"], "inner": inner}
        exec(compile(subject.channel._guard_program, "unchanged-native-route-guards", "exec"), namespace)
        # Real owner/no-follow ancestry/descriptor/name/bytes guard on a real
        # private file. Only the native home getter and ssh-G route facts are
        # seams; no local home or guessed gateway path is used by production.
        intent["configPin"] = namespace["file_pin"](config_path, body=True)
        (stage / "intent.json").write_text(json.dumps(intent))
        namespace["effective_route"] = lambda *args: intent["effectiveRoute"]
        def execute():
            stream = io.StringIO()
            namespace["sys"].stdin.buffer = io.BytesIO(json.dumps(request).encode())
            try:
                with mock.patch("sys.stdout", stream):
                    exec(compile(subject._PROBE, "unchanged-owned-retirement-body", "exec"), namespace)
            finally:
                for _, fd, _, _ in namespace.get("held", ()):
                    os.close(fd)
                if "directory_fd" in namespace:
                    os.close(namespace.pop("directory_fd"))
            return json.loads(stream.getvalue())
        execute.request = request
        execute.config_path = config_path
        return execute, calls, native

    def test_unchanged_native_probe_accepts_exact_idle_master_without_effect(self):
        execute, calls, _ = self._native()
        result = execute()
        self.assertEqual("ready", result["state"])
        self.assertTrue(result["unixListenerOnly"])
        self.assertEqual([], calls)

    def test_unchanged_native_probe_rejects_active_unnamed_mux_and_tcp_forwarder(self):
        for facts, reason in (({"active_unix": True}, "mux_client_active"), ({"tcp_state": "0A"}, "forwarding_socket")):
            execute, calls, _ = self._native(**facts)
            with self.assertRaisesRegex(ValueError, reason):
                execute()
            self.assertEqual([], calls)

    def test_unchanged_native_probe_rejects_pid_reuse_and_missing_original_ready(self):
        for facts, error in (({"birth": 124}, ValueError), ({"missing_ready": True}, FileNotFoundError)):
            execute, calls, _ = self._native(**facts)
            with self.assertRaises(error):
                execute()
            self.assertEqual([], calls)

    def test_unchanged_native_exit_retains_real_child_eof_and_independent_absence(self):
        execute, calls, native = self._native(action="retire")
        result = execute()
        self.assertEqual("ended", result["state"])
        self.assertTrue(result["independentAbsence"])
        self.assertEqual(1, len(calls))
        self.assertEqual(["-O", "exit", "fixture"], calls[0][-3:])
        self.assertEqual({"stdout": True, "stderr": True}, result["exitCapture"]["eof"])
        self.assertTrue(result["exitCapture"]["complete"])
        self.assertTrue((native / "tmp" / ("vpn-retire-" + self.subject.CORRELATION) / "exit.json").is_file())

    def test_unchanged_native_unknown_exit_cannot_replay_even_with_same_body(self):
        execute, calls, _ = self._native(action="retire", exit_code=255)
        with self.assertRaisesRegex(ValueError, "exit_unknown"):
            execute()
        self.assertEqual(1, len(calls))
        # Reset only stdin to model a later observer; preserve all native facts
        # and the durable correlation-level claim from the original execution.
        with self.assertRaises(FileExistsError):
            execute()
        self.assertEqual(1, len(calls))

    def test_emitted_programme_is_complete_and_bounded(self):
        programme = self.subject._remote_program()
        compile(programme, "owned-retirement-native", "exec")
        self.assertLess(len(programme.encode()), 60000)

    def test_fully_rendered_oversized_command_refuses_before_collector_or_intent(self):
        subject = self.subject
        config = types.SimpleNamespace(hosts={"archlinux": types.SimpleNamespace(
            gateway="gateway", remote_config_file="/home/fixture/.ssh/config", remote_host_alias="fixture")})
        current = types.SimpleNamespace(config=config)
        with subject.private.Directory(self.root) as output:
            context = (self.root, {"sourceSha256": "a" * 64}, {}, current, output, {}, lambda: None, lambda: None)
            with mock.patch.object(subject, "_remote_program", return_value="x" * 60001), \
                    mock.patch.object(subject.transport, "connection_host", return_value=object()), \
                    mock.patch.object(subject.direct, "outer_prefix", return_value=(["/usr/bin/ssh"], "fixture")), \
                    mock.patch.object(subject.channel, "_collect", side_effect=AssertionError("unexpected effect")) as collect:
                with self.assertRaisesRegex(ValueError, "retirement_command_bound"):
                    subject._probe(context, str(uuid.uuid4()), "retire")
                collect.assert_not_called()
            self.assertEqual([], os.listdir(output.fd))

    def test_authentic_none_config_whole_before_probe_is_red_and_current_is_green(self):
        subject = self.subject
        fixture = FIXTURE.parent / "retirement_default_config"
        raw = (fixture / "before.source").read_bytes()
        provenance = json.loads((fixture / "provenance.json").read_bytes())
        self.assertEqual(provenance["beforeSha256"], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType("agent_tools._retirement_before_" + uuid.uuid4().hex)
        before.__package__ = "agent_tools"; before.__file__ = str(fixture / "before.source")
        sys.modules[before.__name__] = before
        self.addCleanup(sys.modules.pop, before.__name__, None)
        exec(compile(raw, before.__file__, "exec"), before.__dict__)
        real_collect = subject.channel._collect
        for owner, fixed in ((before, False), (subject, True)):
            execute, calls, _ = self._native(subject=owner, default_config=True)
            output_path = self.root / uuid.uuid4().hex; output_path.mkdir(mode=0o700)
            current = types.SimpleNamespace(config=types.SimpleNamespace(hosts={"archlinux": types.SimpleNamespace(
                gateway="gateway", remote_config_file=None, remote_host_alias="fixture")}))
            def collect(argv, payload, timeout):
                execute.request["config"] = json.loads(payload)["config"]
                result = execute()
                # Preserve genuine child/dual-EOF plumbing after the complete
                # actual body has parsed and guarded the inert native facts.
                return real_collect([sys.executable, "-I", "-B", "-c", "import sys;sys.stdin.buffer.read();print(" + repr(json.dumps(result)) + ")"], b"{}", timeout)
            with owner.private.Directory(output_path) as output:
                context = (self.root, {"sourceSha256": "a" * 64}, execute.request["ready"], current, output, {}, lambda: None, lambda: None)
                with mock.patch.object(owner.transport, "connection_host", return_value=object()), \
                        mock.patch.object(owner.direct, "outer_prefix", return_value=(["/usr/bin/ssh"], "fixture")), \
                        mock.patch.object(owner.channel, "_collect", side_effect=collect):
                    if fixed:
                        result = owner._probe(context, str(uuid.uuid4()), "observe")
                        self.assertEqual("ready", result["state"])
                    else:
                        with self.assertRaisesRegex(ValueError, "route_parent_unsafe"):
                            owner._probe(context, str(uuid.uuid4()), "observe")
                self.assertEqual([], calls, "neither readonly programme may submit an exit")
        # Explicit config still works through the same real native file guard.
        execute, calls, _ = self._native()
        self.assertEqual("ready", execute()["state"])
        execute.config_path.write_text("Host changed\n")
        with self.assertRaisesRegex(ValueError, "route"):
            execute()
        self.assertEqual([], calls)

    def test_authentic_second_connection_and_unknown_records_stay_exactly_bound(self):
        subject = self.subject
        provenance = json.loads((FIXTURE / "315-provenance.json").read_bytes())
        intent_raw = (FIXTURE / "315-intent.json").read_bytes()
        ready_raw = (FIXTURE / "315-ready.json").read_bytes()
        intent, ready = json.loads(intent_raw), json.loads(ready_raw)
        self.assertEqual(subject.SECOND_INTENT_SHA, hashlib.sha256(intent_raw).hexdigest())
        self.assertEqual(subject.SECOND_READY_SHA, hashlib.sha256(ready_raw).hexdigest())
        self.assertEqual(subject.SECOND_CORRELATION, intent["correlationId"])
        self.assertEqual(intent["correlationId"], ready["result"]["correlationId"])
        self.assertEqual(subject.CURRENT_MCP, intent["directSourcePins"]["mcp_server.py"])
        self.assertNotIn("ssh_owned_channel_retirement.py", intent["directSourcePins"])
        self.assertEqual(subject.SECOND_PROGRAM_RECORDS, provenance["programRecords"])
        records = json.loads((FIXTURE / "315-programs.json").read_bytes())
        for identifier, parts in records.items():
            for name, value in parts.items():
                self.assertEqual(subject.SECOND_PROGRAM_RECORDS[identifier][name],
                                 hashlib.sha256(subject._json(value)).hexdigest())
            self.assertEqual({"operationId": identifier, "sourceClosing": True,
                              "terminalSha256": subject.SECOND_PROGRAM_RECORDS[identifier]["terminal.json"]},
                             parts["owner-closed.json"])
        unknown = records[subject.SECOND_UNKNOWN]["terminal.json"]
        self.assertEqual("unknown", unknown["state"])
        self.assertIsNone(unknown["capture"])
        self.assertEqual("SshConfigError", unknown["errorClass"])
        for correlation in ("0" * 32, str(uuid.uuid4())):
            with self.assertRaisesRegex(ValueError, "retirement_identity"):
                subject._profile(correlation)

    def test_whole_fbac_only_before_rejects_second_probe_and_current_accepts(self):
        subject = self.subject
        raw = (FIXTURE / "fbac-only.before.source").read_bytes()
        provenance = json.loads((FIXTURE / "315-provenance.json").read_bytes())
        self.assertEqual(provenance["helperBeforeSha256"], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType("agent_tools._retirement_fbac_before_" + uuid.uuid4().hex)
        before.__package__ = "agent_tools"; before.__file__ = str(FIXTURE / "fbac-only.before.source")
        sys.modules[before.__name__] = before
        self.addCleanup(sys.modules.pop, before.__name__, None)
        exec(compile(raw, before.__file__, "exec"), before.__dict__)
        real_collect = subject.channel._collect
        for owner, fixed in ((before, False), (subject, True)):
            execute, calls, _ = self._native(subject=owner, correlation=subject.SECOND_CORRELATION)
            current = types.SimpleNamespace(config=types.SimpleNamespace(hosts={"archlinux": types.SimpleNamespace(
                gateway="gateway", remote_config_file=str(execute.config_path), remote_host_alias="fixture")}))
            output_path = self.root / uuid.uuid4().hex; output_path.mkdir(mode=0o700)
            def collect(argv, payload, timeout):
                payload_value = json.loads(payload)
                self.assertEqual(subject.SECOND_CORRELATION, payload_value["ready"]["correlationId"])
                result = execute()
                return real_collect([sys.executable, "-I", "-B", "-c", "import sys;sys.stdin.buffer.read();print(" + repr(json.dumps(result)) + ")"], b"{}", timeout)
            with owner.private.Directory(output_path) as output:
                context = (self.root, {"sourceSha256": "a" * 64}, execute.request["ready"], current, output, {}, lambda: None, lambda: None)
                with mock.patch.object(owner.transport, "connection_host", return_value=object()), \
                        mock.patch.object(owner.direct, "outer_prefix", return_value=(["/usr/bin/ssh"], "fixture")), \
                        mock.patch.object(owner.channel, "_collect", side_effect=collect):
                    if fixed:
                        result = owner._probe(context, str(uuid.uuid4()), "observe")
                        self.assertEqual(subject.SECOND_CORRELATION, result["correlationId"])
                        self.assertEqual("ready", result["state"])
                    else:
                        with self.assertRaisesRegex(ValueError, "retirement_probe_binding"):
                            owner._probe(context, str(uuid.uuid4()), "observe")
                self.assertEqual([], calls)

    def test_second_exit_claim_is_distinct_and_never_replays(self):
        subject = self.subject
        for correlation in (subject.CORRELATION, subject.SECOND_CORRELATION):
            operation = self.root / str(uuid.uuid4()); operation.mkdir(mode=0o700)
            with subject.private.Directory(operation) as output:
                with subject._claim_exit(output, operation.name, correlation):
                    pass
            other = self.root / str(uuid.uuid4()); other.mkdir(mode=0o700)
            with subject.private.Directory(other) as output:
                with self.assertRaises(FileExistsError):
                    with subject._claim_exit(output, other.name, correlation):
                        self.fail("lost acknowledgment must not create another exit")
        for correlation in (subject.CORRELATION, subject.SECOND_CORRELATION):
            self.assertEqual(correlation, json.loads((self.root / (correlation + ".exit-intent.json")).read_bytes())["correlationId"])

    def test_same_native_probe_retires_only_second_owned_control(self):
        subject = self.subject
        execute, calls, _ = self._native(action="retire", correlation=subject.SECOND_CORRELATION)
        result = execute()
        self.assertEqual("ended", result["state"])
        self.assertTrue(result["independentAbsence"])
        self.assertEqual(subject.SECOND_CORRELATION, result["correlationId"])
        self.assertEqual(1, len(calls))
        self.assertEqual("/tmp/vpn-channel-" + subject.SECOND_CORRELATION + "/m", calls[0][calls[0].index("-S") + 1])
        self.assertEqual({"stdout": True, "stderr": True}, result["exitCapture"]["eof"])




def _run_fixed546_carrier_controls(module, run):
    # Actual integrated helper functions run. Only the external SSH peer is a
    # harmless local Python child; historical kill is trapped without a signal.
    import errno, random, selectors, shlex
    FRAGMENT = Path(module.__file__)
    REPO = ROOT
    rows = []
    def sha(raw):
        return hashlib.sha256(raw).hexdigest()
    def save(name, value):
        raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(run / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    def serial(capture):
        return {key: ({"base64": base64.b64encode(value).decode(), "bytes": len(value), "sha256": sha(value)}
                      if isinstance(value, bytes) else value) for key, value in capture.items()}
    def record(name, condition, **facts):
        if not condition:
            save("failure.json", {"case": name, **facts})
            raise AssertionError(name)
        rows.append({"case": name, **facts})
    request = json.dumps({'operationId': str(uuid.uuid4()), 'action': 'observe',
                          'ready': {'correlationId': module._FIXED546}, 'sourceSha256': '0' * 64,
                          'config': '', 'profile': 'inert-only'}, sort_keys=True).encode()
    body = "import json,sys\nr=json.load(sys.stdin)\nassert r['action']=='observe'\nprint('EXACT ACTION ü')\nsys.stderr.write('EXACT STDERR\\n')\n"


    class LocalPeer:
        def __init__(self, delay=0):
            self.children = []
            self.argv = []
            self.delay = delay

        def __call__(self, argv, **kwargs):
            # Sole peer seam: exact rendered gateway loader executes locally.
            command = shlex.split(argv[-1])
            assert command[:4] == ['python3', '-I', '-B', '-c']
            self.argv.append(argv)
            code = ("import time\ntime.sleep(" + repr(self.delay) + ")\n" + command[4])
            child = subprocess.Popen([sys.executable, '-I', '-B', '-c', code], **kwargs)
            self.children.append(child)
            return child


    def invoke(name, packet, *, seconds=3, peer=None, **kwargs):
        peer = LocalPeer() if peer is None else peer
        result = module._fixed546_collect(packet, seconds, _popen=peer, **kwargs)
        save(name + '.json', serial(result))
        record(name + ' one original harmless child naturally reaped',
               len(peer.children) == 1 and peer.children[0].returncode is not None
               and peer.children[0].stdout.closed and peer.children[0].stderr.closed,
               pid=peer.children[0].pid)
        return result


    packet = module._fixed546_transport_packet(['ssh-inert-only'], 'gateway-inert-only', body, request)
    result = invoke('inline', packet)
    record('small source automatically inline and exact gateway source executes',
           packet['sourceTransport'] == 'inline' and result['complete']
           and result['stdout'] == 'EXACT ACTION ü\n'.encode() and result['stderr'] == b'EXACT STDERR\n'
           and result['originalTerminal']['complete'] and result['originalPopenRetained'])

    noise = base64.b64encode(random.Random(546).randbytes(100000)).decode()
    large = body + '\n#' + noise + '\n'
    large_packet = module._fixed546_transport_packet(['ssh-inert-only'], 'gateway-inert-only', large, request)
    result = invoke('source-stream', large_packet)
    record('large source automatically stdin transfers with short command and exact hash',
           large_packet['sourceTransport'] == 'source-stream'
           and large_packet['programmeSha256'] == sha(large.encode()) and result['complete']
           and result['stdout'] == 'EXACT ACTION ü\n'.encode()
           and result['originalTerminal']['forwardedBytes'] == len(large_packet['stdin'])
           and large_packet['wholeArgvBytes'] <= 60000
           and large_packet['inlineCandidateMetrics']['wholeArgvBytes'] > 60000,
           metrics={k: large_packet[k] for k in ('wholeArgvBytes', 'maxArgumentBytes', 'commandBytes')})

    # Actual full argv boundary, including option overhead. This uses no process.
    medium = body + '\n#' + noise[:18000] + '\n'
    base = module._fixed546_transport_packet(['ssh-inert-only', ''], 'gateway-inert-only', medium, request)
    padding = 60000 - base['wholeArgvBytes']
    at = module._fixed546_transport_packet(['ssh-inert-only', 'x' * padding], 'gateway-inert-only', medium, request)
    over = module._fixed546_transport_packet(['ssh-inert-only', 'x' * (padding + 1)], 'gateway-inert-only', medium, request)
    record('actual full argv 60000 permits inline and 60001 automatically streams prelaunch',
           at['sourceTransport'] == 'inline' and at['wholeArgvBytes'] == 60000
           and over['sourceTransport'] == 'source-stream'
           and over['inlineCandidateMetrics']['wholeArgvBytes'] == 60001 and over['wholeArgvBytes'] < 60000)

    result = invoke('timeout-late-eof', large_packet, seconds=.02, peer=LocalPeer(.12))
    record('first timeout remains unknown after same child writer and both late EOFs close',
           not result['complete'] and result['timeout'] and not result['firstCapture']['complete']
           and result['firstCapture']['timeout'] and result['originalTerminal']['complete']
           and result['stdout'] == 'EXACT ACTION ü\n'.encode()
           and result['originalTerminal']['forwardedBytes'] == len(large_packet['stdin'])
           and result['originalTerminal']['stdinClosed'] and result['originalStreamsClosed'])

    for fault in ('truncated', 'hash', 'trailing', 'header'):
        malformed = dict(large_packet)
        raw = large_packet['stdin']
        if fault == 'truncated':
            malformed['stdin'] = raw[:-1]
        elif fault == 'hash':
            malformed['stdin'] = raw[:-1] + bytes([raw[-1] ^ 1])
        elif fault == 'trailing':
            malformed['stdin'] = raw + b'x'
        else:
            malformed['stdin'] = (4097).to_bytes(4, 'big') + raw[4:]
        value = invoke('refusal-' + fault, malformed)
        record('gateway ' + fault + ' source admission refuses before inert action',
               value['returnCode'] != 0 and value['stdout'] == b'' and b'fixed546_' in value['stderr'])

    attempts = []
    def no_handle(argv, **kwargs):
        attempts.append(argv)
        raise OSError(errno.E2BIG, 'inert no returned handle')
    value = module._fixed546_collect(large_packet, _popen=no_handle)
    save('no-handle.json', serial(value))
    record('unexpected OS E2BIG has no handle and never retries or falls back',
           len(attempts) == 1 and not value['complete'] and not value['originalPopenRetained']
           and value['originalTerminal']['creationUnproved']
           and value['primaryError'] == {'errorClass': 'OSError', 'errno': errno.E2BIG})

    original_set_blocking = module.os.set_blocking
    armed = [True]
    def post_start(fd, block):
        if armed[0]:
            armed[0] = False
            raise OSError(errno.EIO, 'inert post Popen setup')
        return original_set_blocking(fd, block)
    module.os.set_blocking = post_start
    try:
        value = invoke('post-popen-setup', packet)
    finally:
        module.os.set_blocking = original_set_blocking
    record('post-Popen setup error keeps original handle drains stderr and closes naturally',
           not value['complete'] and value['originalPopenRetained'] and value['originalTerminal']['complete']
           and value['primaryError']['errorClass'] == 'OSError' and value['stdout'] == b'')

    original_thread_start = module.threading.Thread.start
    def thread_start_refused(self):
        raise RuntimeError('inert thread start refusal')
    module.threading.Thread.start = thread_start_refused
    try:
        value = invoke('unstarted-writer', packet)
    finally:
        module.threading.Thread.start = original_thread_start
    record('unstarted writer closes input and retains original error plus natural terminal',
           not value['complete'] and value['originalTerminal']['complete']
           and value['primaryError']['errorClass'] == 'RuntimeError' and value['stdout'] == b'')

    original_owner_init = module._Fixed546Owner.__init__
    def bounded_owner_init(self, **kwargs):
        kwargs['capture_limit'] = 4
        original_owner_init(self, **kwargs)
    module._Fixed546Owner.__init__ = bounded_owner_init
    try:
        value = invoke('overflow', large_packet)
    finally:
        module._Fixed546Owner.__init__ = original_owner_init
    record('overflow remains unknown with actual full counts and positive EOF',
           not value['complete'] and value['overflow'] and value['originalTerminal']['complete']
           and value['counts']['stdout'] > len(value['stdout']) == 4)

    original_read = module.os.read
    read_fault = [True]
    def once_read_error(fd, count):
        if read_fault[0] and sys._getframe(1).f_code.co_name == 'step':
            read_fault[0] = False
            raise OSError(errno.EIO, 'inert one read refusal')
        return original_read(fd, count)
    module.os.read = once_read_error
    try:
        value = invoke('read-error', packet)
    finally:
        module.os.read = original_read
    record('transient read uncertainty stays unknown after same original full late streams and EOF',
           not value['complete'] and value['readError'] and value['originalTerminal']['complete']
           and value['stdout'] == 'EXACT ACTION ü\n'.encode() and value['stderr'] == b'EXACT STDERR\n')

    original_write = module.os.write
    def partial_write(fd, data):
        if sys._getframe(1).f_code.co_name == 'write':
            return original_write(fd, data[:111])
        return original_write(fd, data)
    module.os.write = partial_write
    try:
        value = invoke('partial-writes', large_packet)
    finally:
        module.os.write = original_write
    record('partial writes forward all exact source and request bytes before positive EOF',
           value['complete'] and value['originalTerminal']['forwardedBytes'] == len(large_packet['stdin'])
           and value['stdout'] == 'EXACT ACTION ü\n'.encode())

    write_fault = [True]
    def once_write_error(fd, data):
        if write_fault[0] and sys._getframe(1).f_code.co_name == 'write':
            write_fault[0] = False
            raise OSError(errno.EIO, 'inert writer refusal')
        return original_write(fd, data)
    module.os.write = once_write_error
    try:
        value = invoke('writer-error', large_packet)
    finally:
        module.os.write = original_write
    record('writer input uncertainty remains unknown and same original terminal closes without action',
           not value['complete'] and value['writeError'] and value['originalTerminal']['complete']
           and value['stdout'] == b'')

    # Exact historical function only. No historical module is imported or executed.
    historical_path = REPO / 'agent_tools/ssh_connection_recovery.py'
    historical_raw = historical_path.read_bytes()
    historical_text = historical_raw.decode()
    node = next(n for n in ast.parse(historical_text).body if isinstance(n, ast.FunctionDef) and n.name == '_bounded_socket_query')
    historical = ast.get_source_segment(historical_text, node)
    save('authentic-before-whole.source', historical_raw)
    save('authentic-before-function.source', historical.encode())
    kill_attempts = []
    children = []


    class NoSignalChild:
        def __init__(self, child):
            self._child = child
        def __getattr__(self, name):
            return getattr(self._child, name)
        def kill(self):
            # A declared safety seam: record the authentic branch without a signal.
            kill_attempts.append(self._child.pid)


    def harmless_child(argv, **kwargs):
        assert argv[0] == sys.executable
        child = subprocess.Popen(argv, **kwargs)
        children.append(child)
        return NoSignalChild(child)


    peer_subprocess = types.SimpleNamespace(Popen=harmless_child, DEVNULL=subprocess.DEVNULL,
        PIPE=subprocess.PIPE, SubprocessError=subprocess.SubprocessError, TimeoutExpired=subprocess.TimeoutExpired)
    scope = {'os': os, 'selectors': selectors, 'subprocess': peer_subprocess, 'time': time, '_SOCKET_CAPTURE_BYTES': 4096}
    exec(compile(historical, str(historical_path) + ':actual-before-function', 'exec'), scope)
    argv = [sys.executable, '-I', '-B', '-c', "import sys,time;time.sleep(.12);sys.stdout.write('LATE OUT\\n');sys.stdout.flush();sys.stderr.write('LATE ERR\\n')"]
    before = scope['_bounded_socket_query'](argv, .02)
    save('authentic-before-timeout.json', serial(before))
    before_red = False
    try:
        assert not kill_attempts and before['eof'] == {'stdout': True, 'stderr': True} and before['stdout'] == b'LATE OUT\n'
    except AssertionError:
        before_red = True
    record('authentic old timeout RED: kill attempted and late streams plus EOF lost; no actual signal',
           before_red and len(kill_attempts) == 1 and before['timeout'] and children[-1].returncode == 0,
           wholeBeforeSha256=sha(historical_raw), functionBeforeSha256=sha(historical.encode()),
           killSafetySeam='record only; no signal sent')

    new_scope = {}
    exec(compile(module._fixed546_inner_source(), 'actual-fixed546-generated-inner', 'exec'), new_scope)
    new_scope['subprocess'] = peer_subprocess
    attempt_count = len(kill_attempts)
    fixed = new_scope['inner'](argv, .02)
    save('fixed-inner-timeout.json', serial(fixed))
    record('fixed546 actual generated inner GREEN: first timeout unknown and original late bytes/dual EOF retained',
           len(kill_attempts) == attempt_count and not fixed['complete'] and fixed['timeout']
           and fixed['originalTerminal']['complete'] and fixed['eof'] == {'stdout': True, 'stderr': True}
           and fixed['stdout'] == b'LATE OUT\n' and fixed['stderr'] == b'LATE ERR\n'
           and fixed['originalStreamsClosed'] and children[-1].returncode == 0)
    fixed = new_scope['inner']([sys.executable, '-I', '-B', '-c', "import sys;print('NOW');sys.stderr.write('ERR\\n');sys.exit(7)"], 3)
    save('fixed-inner-exit7.json', serial(fixed))
    record('fixed546 generated inner immediate known exit preserves both streams and exit7',
           fixed['complete'] and fixed['returnCode'] == 7 and fixed['stdout'] == b'NOW\n'
           and fixed['stderr'] == b'ERR\n' and len(kill_attempts) == attempt_count)

    before_children = len(children)
    bound_refused = False
    try:
        new_scope['inner']([sys.executable, 'x' * 60001], 3)
    except ValueError as error:
        bound_refused = str(error) == 'fixed546_command_bound'
    record('fixed546 generated inner keeps complete 60000 byte command bound before Popen',
           bound_refused and len(children) == before_children)

    save('summary.json', {'schemaVersion': 1, 'sourceSha256': sha(FRAGMENT.read_bytes()),
        'cases': rows, 'caseCount': len(rows), 'networkSubmitted': False, 'nativeAcceptanceClaim': False,
        'signalsSent': 0, 'sshCommandsStarted': 0,
        'seams': ['Exact gateway loader uses a harmless local Python process in place of the outer SSH route.',
                  'Synthetic fixed546 request has no actual gateway/master facts.',
                  'Historical kill method records its call and sends no signal; the real harmless child exits naturally.'],
        'reviewedCarrierSha256': 'a9ef684d2779a9fbf7921254f458e520471ff373f09f71ee5cd8744ccba8f483',
        'evidenceDirectory': str(run)})
    return rows


@unittest.skipUnless(os.name == "posix", "POSIX private channel coordinator")
class Fixed546RetirementTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import ssh_owned_channel_retirement as subject
        self.subject = subject
        self.temporary = tempfile.TemporaryDirectory(prefix="fixed546-retire-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)

    def release(self, owner=None):
        subject = self.subject if owner is None else owner
        ids = set(subject.SECOND_PROGRAM_RECORDS) | {subject.THIRD_UNKNOWN,
            "bd18cb94-e6a2-4003-99d5-9edc792ed05c", "138e8eeb-ca78-40b8-acb0-6f91fb855873",
            "bf8fc478-c548-42c5-955b-b3698b6905c0", "2690c7cd-a4e4-4c0a-832a-1364ab325755"}
        return {"facts": dict(subject._THIRD_FACTS),
                "proofs": {".runtime/inert-only/closure.json": "0" * 64},
                "programRecords": {name: {} for name in ids},
                "baLeafNames": ["intent.json", "owner.json", "child.json", "stdout.private", "stderr.private"]}

    def before(self):
        raw = (FIXTURE / "546-helper.before.source").read_bytes()
        provenance = json.loads((FIXTURE / "546-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeHelperSha256"], hashlib.sha256(raw).hexdigest())
        module = types.ModuleType("agent_tools._546_before_" + uuid.uuid4().hex)
        module.__package__ = "agent_tools"; module.__file__ = str(FIXTURE / "546-helper.before.source")
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        return module

    def test_authentic_546_original_intent_and_ready_are_bound_not_adopted(self):
        subject = self.subject
        provenance = json.loads((FIXTURE / "546-provenance.json").read_bytes())
        records = {}
        for name in ("intent", "ready"):
            raw = (FIXTURE / ("546-" + name + ".json")).read_bytes()
            self.assertEqual(provenance["records"][name]["sha256"], hashlib.sha256(raw).hexdigest())
            records[name] = json.loads(raw)
        self.assertEqual(subject.THIRD_INTENT_SHA, provenance["records"]["intent"]["sha256"])
        self.assertEqual(subject.THIRD_READY_SHA, provenance["records"]["ready"]["sha256"])
        self.assertEqual(subject.THIRD_CORRELATION, records["intent"]["correlationId"])
        self.assertEqual(subject.THIRD_INTENT_SHA, records["ready"]["intent"]["sha256"])
        self.assertEqual(subject.THIRD_ORIGINAL_AUTHORITY, records["intent"]["outerAuthoritySha256"])
        self.assertEqual(1785600, records["ready"]["result"]["master"]["actor"]["pid"])
        self.assertEqual(39465725, records["ready"]["result"]["master"]["actor"]["startTicks"])

    def test_missing_actual_original_closure_or_status_refuses_before_files_or_transport(self):
        subject = self.subject
        for function in (subject.observe_original, subject.retire_owned):
            with mock.patch.object(subject, "_THIRD_ADMISSION", None), \
                    mock.patch.object(subject.private, "ownership", side_effect=AssertionError("must not open")), \
                    mock.patch.object(subject, "_fixed546_collect", side_effect=AssertionError("must not start")):
                with self.assertRaisesRegex(ValueError, "retirement_546_evidence_unavailable"):
                    function(self.root, "archlinux", subject.THIRD_CORRELATION, str(uuid.uuid4()))
        self.assertEqual([], list(self.root.iterdir()))

    def test_authentic_before_profile_red_and_fixed_exact_profile_green_with_declared_inert_release(self):
        subject, before = self.subject, self.before()
        original_admission = subject._THIRD_ADMISSION
        with self.assertRaisesRegex(ValueError, "retirement_identity"):
            before._profile(subject.THIRD_CORRELATION)
        release = self.release()
        with mock.patch.object(subject, "_THIRD_ADMISSION", release):
            self.assertEqual((subject.THIRD_INTENT_SHA, subject.THIRD_READY_SHA, release["programRecords"]),
                             subject._profile(subject.THIRD_CORRELATION))
            for other in ("0" * 32, str(uuid.uuid4())):
                with self.assertRaisesRegex(ValueError, "retirement_identity"):
                    subject._profile(other)
        self.assertIs(original_admission, subject._THIRD_ADMISSION)
        actual = subject._third_release()
        self.assertEqual(11, len(actual["programRecords"]))
        self.assertEqual(170, len(actual["baLeafNames"]))
        self.assertEqual("created-terminal-observed", actual["facts"]["originalGuestCreateState"])
        self.assertTrue(actual["facts"]["originalCaptureScopesAbandoned"])
        self.assertEqual({"intent.json", "owner.json", "child.json", "stdout.private", "stderr.private"},
                         set(actual["programRecords"][subject.THIRD_UNKNOWN]))
        self.assertNotIn("terminal.json", actual["baLeafNames"])
        self.assertNotIn("owner-closed.json", actual["baLeafNames"])
        status_raw = ".runtime/windows-parity-20261019/artifacts/original-pid4120-status-direct-preparation-v1/packet-final/inner-stdout.raw"
        self.assertEqual("5bdeb26bac80cb6391e0015cc738ecf47a5cd35e5015af804306a4f89731ed11", actual["proofs"][status_raw])

    def test_every_lost_closing_fact_is_required_and_never_promoted(self):
        subject = self.subject
        for field in ("originalUnknownPreserved", "originalEofClaimed", "originalSourceClosingClaimed",
                      "originalCaptureCompletion", "originalClosureQualified", "historicalTrustEquivalent",
                      "originalGuestStatusReconciled", "originalGuestCreateState", "originalCaptureScopesAbandoned",
                      "originalLocalActorsAbsent", "hostCustodyDropped", "guestReplayAllowed"):
            release = self.release()
            value = release["facts"][field]
            release["facts"][field] = not value if type(value) is bool else "qualified"
            with mock.patch.object(subject, "_THIRD_ADMISSION", release):
                with self.assertRaisesRegex(ValueError, "retirement_546_evidence_unavailable"):
                    subject._third_release()
        for path in ("/absolute/private.json", "../escape.json", ".runtime/../escape.json", "agent_tools/fixture.json"):
            release = self.release(); release["proofs"] = {path: "0" * 64}
            with mock.patch.object(subject, "_THIRD_ADMISSION", release):
                with self.assertRaisesRegex(ValueError, "retirement_546_evidence_identity"):
                    subject._third_release()

    def test_separate_historical_and_current_authority_exact_one_trust_delta(self):
        subject = self.subject
        # Declared inert historical authority metadata; no key or trust bytes,
        # current config reads, or network facts are replaced with this model.
        rows = [{"path": "/inert/identity", "sha256": "1" * 64, "fingerprint": [1,2,3,4,6,7,8,9]},
                {"path": "/inert/known_hosts", "sha256": subject.THIRD_CURRENT_TRUST, "fingerprint": [9,8,7,6,4,3,2,1]}]
        oldpins = {"/inert/identity": {"sha256": "1" * 64, "generation": [1,2,3,4,5,6,7,8,9]},
                   "/inert/known_hosts": {"sha256": subject.THIRD_ORIGINAL_TRUST, "generation": [7,6,5,4,3,2,1,0,9]}}
        authority = {"files": rows, "fixed": "inert-only"}
        historical = json.loads(json.dumps(authority))
        historical["files"][1].update(sha256=subject.THIRD_ORIGINAL_TRUST, fingerprint=[7,6,5,4,2,1,0,9])
        oldsha, newsha = subject._sha(subject._json(historical)), subject._sha(subject._json(authority))
        current = types.SimpleNamespace(authority=authority, authority_sha=newsha)
        with mock.patch.multiple(subject, THIRD_ORIGINAL_AUTHORITY=oldsha, THIRD_CURRENT_AUTHORITY=newsha):
            value = subject._third_authority(current, {"outerAuthoritySha256": oldsha}, {"connectionPins": oldpins})
            self.assertFalse(value["historicalTrustEquivalent"])
            self.assertFalse(value["historicalTrustBytesAvailable"])
            self.assertEqual(authority, current.authority)
            for bad in ("key", "trust", "generation", "oldbinding", "currentbinding"):
                c = types.SimpleNamespace(authority=json.loads(json.dumps(authority)), authority_sha=newsha)
                original = {"outerAuthoritySha256": oldsha}; pins = json.loads(json.dumps(oldpins))
                if bad == "key": c.authority["files"][0]["sha256"] = "2" * 64
                elif bad == "trust": c.authority["files"][1]["sha256"] = "2" * 64
                elif bad == "generation": pins["/inert/identity"]["generation"][1] += 1
                elif bad == "oldbinding": original["outerAuthoritySha256"] = "0" * 64
                else: c.authority_sha = "0" * 64
                with self.assertRaises(ValueError): subject._third_authority(c, original, {"connectionPins": pins})

    def test_fixed_546_uses_retained_inner_and_historical_bodies_remain_identical(self):
        subject = self.subject
        before = self.before()
        for correlation in (None, subject.CORRELATION, subject.SECOND_CORRELATION):
            self.assertEqual(before._remote_program(), subject._remote_program(correlation))
        source = subject._remote_program(subject.THIRD_CORRELATION)
        compile(source, "whole-fixed546-gateway", "exec")
        self.assertIn("class _Fixed546Owner", source)
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                             and node.func.attr in ("kill", "terminate") for node in ast.walk(tree)))
        self.assertIn(subject._PROBE, source)
        self.assertNotIn("guest-exec", source)

    def publication_context(self):
        subject = self.subject
        root = self.root
        (root / ".rag_index/ssh-direct-nested-channel/hosts/archlinux").mkdir(parents=True, mode=0o700)
        for path in (root / ".rag_index", root / ".rag_index/ssh-direct-nested-channel", root / ".rag_index/ssh-direct-nested-channel/hosts", root / ".rag_index/ssh-direct-nested-channel/hosts/archlinux"):
            path.chmod(0o700)
        journal = root / ".rag_index/ssh-direct-nested-channel/hosts/archlinux"
        authentic_intent = (FIXTURE / "546-intent.json").read_bytes()
        self.assertEqual(subject.THIRD_INTENT_SHA, subject._sha(authentic_intent))
        # Owned publication context only: keep historical profile fixtures exact
        # while binding these executable capsules to current physical sources.
        canonical = Path(subject.direct.__file__).parent
        intent = json.loads(authentic_intent)
        intent["sourceSha256"] = subject._sha((canonical / "ssh_fresh_nested_channel.py").read_bytes())
        intent["remoteSourceSha256"] = subject._sha(subject.channel._REMOTE.encode())
        intent["directSourcePins"] = {name: subject._sha((canonical / name).read_bytes()) for name in subject.direct.source_catalog(intent["version"])}
        original = journal / (subject.THIRD_CORRELATION + ".intent.json")
        original.write_bytes(subject._json(intent)); original.chmod(0o600)
        directory = subject.private.Directory(journal)
        self.addCleanup(directory.close)
        held = subject.private.Snapshot(directory, original.name)
        self.addCleanup(held.close)
        ready = json.loads((FIXTURE / "546-ready.json").read_bytes())["result"]
        ready_path = journal / (subject.THIRD_CORRELATION + ".ready.json")
        ready_path.write_bytes(subject._json({"intent": held.pin(), "result": ready})); ready_path.chmod(0o600)
        ready_held = subject.private.Snapshot(directory, ready_path.name)
        self.addCleanup(ready_held.close)
        for name, digest in {"remote": intent["remoteSourceSha256"], "ssh_fresh_nested_channel.py": intent["sourceSha256"], **intent["directSourcePins"]}.items():
            raw = subject.channel._REMOTE.encode() if name == "remote" else (ROOT / "agent_tools" / name).read_bytes()
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            path = journal / (subject.THIRD_CORRELATION + "." + name + ".source")
            path.write_bytes(raw); path.chmod(0o600)
        output_path = root / "output"; output_path.mkdir(mode=0o700)
        output = subject.private.Directory(output_path); self.addCleanup(output.close)
        raw_held = subject._Held(); self.addCleanup(raw_held.close)
        current = types.SimpleNamespace(held=raw_held, authority={"declaredInertCurrentAuthority": True, "declaredInertCurrentSourceContext": True}, config=types.SimpleNamespace(hosts={"archlinux": types.SimpleNamespace(gateway="inert", remote_config_file="", remote_host_alias="inert")}))
        private_intent = {"operationId": str(uuid.uuid4()), "correlationId": subject.THIRD_CORRELATION,
            "intent": held.pin(), "ready": ready_held.pin(), "currentAuthority": current.authority,
            "trustSeparation": {"historicalTrustEquivalent": False}, "originalUnknownPreserved": True,
            "originalEofClaimed": False, "originalSourceClosingClaimed": False}
        subject._write(output, "intent.json", subject._json(private_intent))
        context = (root, intent, ready, current, output, {}, lambda: (held.guard(), ready_held.guard(), raw_held.finish(), raw_held.final_identity_pass()), lambda: None)
        return context, directory, held, ready_held

    def write_probe(self, context, *, altered=None):
        subject = self.subject
        _, value, ready, _, output, _, _, _ = context
        native = {"state": "ended", "correlationId": subject.THIRD_CORRELATION,
            "gatewayBoot": ready["master"]["gatewayBoot"], "independentAbsence": True}
        request = {"operationId": json.loads((output.path / "intent.json").read_bytes())["operationId"], "action": "observe", "ready": ready,
            "sourceSha256": value["sourceSha256"], "config": "", "profile": "inert"}
        raw = subject._json(native)
        capture = {"pid": 12345, "returnCode": 0, "complete": True,
            "counts": {"stdout": len(raw), "stderr": 0}, "eof": {"stdout": True, "stderr": True},
            "timeout": False, "overflow": False, "readError": False}
        capture["rawStreamSha256"] = {"stdout": subject._sha(raw), "stderr": subject._sha(b"")}
        if altered: capture.update(altered)
        subject._capture(output, "probe", {**capture, "stdout": raw, "stderr": b""})
        body = subject._json(request); subject._write(output, "probe-request.json", body)
        subject._write(output, "submission-intent.json", subject._json({"requestSha256": subject._sha(body), "helperSha256": subject._LOADED_SHA, "loaderSha256": subject.loader._LOADED_SHA,
            "programmeSha256": subject._sha(subject._remote_program(subject.THIRD_CORRELATION).encode()), "action": request["action"], "operationId": request["operationId"],
            "correlationId": subject.THIRD_CORRELATION, "limitBytes": 60000, "wholeArgvBytes": 1234, "maxArgumentBytes": 1000}))
        return native

    def test_real_v2_publication_preserves_original_refs_and_lost_job_without_archive_execution(self):
        subject = self.subject
        context, directory, held, ready_held = self.publication_context()
        native = self.write_probe(context)
        before = {p.name: p.read_bytes() for p in directory.path.iterdir()}
        calls = []
        def status(root, host, correlation, **kwargs):
            calls.append((host, correlation))
            with subject.ExitStack() as stack:
                admitted = subject.channel._retained_v2_terminal(stack, directory, held, json.loads(held.body), host)
                self.assertIsNotNone(admitted); admitted()
            return subject.channel._public("ended", correlationId=correlation)
        with mock.patch.object(subject, "_THIRD_ADMISSION", self.release()), \
                mock.patch.multiple(subject, THIRD_INTENT_SHA=held.digest, THIRD_READY_SHA=ready_held.digest), \
                mock.patch.object(subject.direct, "status", side_effect=status), \
                mock.patch.object(subject.channel, "_collect", side_effect=AssertionError("must not use old transport")), \
                mock.patch.object(subject, "_source_view", side_effect=AssertionError("must not execute archive")):
            result = subject._publish_ended(context, native)
        self.assertEqual("ended", result["state"])
        self.assertEqual([("archlinux", subject.THIRD_CORRELATION)], calls)
        terminal = json.loads((directory.path / (subject.THIRD_CORRELATION + ".terminal.json")).read_bytes())
        self.assertEqual(held.digest, terminal["intentSha256"])
        self.assertEqual(ready_held.digest, terminal["receiptSha256"])
        for name, raw in before.items(): self.assertEqual(raw, (directory.path / name).read_bytes())
        self.assertFalse((self.root / ".rag_index/ssh-program-execution").exists(), "no fabricated original job records")
        proof = json.loads((context[4].path / "terminal-publication-intent.json").read_bytes())
        self.assertFalse(proof["historicalTrustEquivalent"])
        self.assertTrue(proof["originalCaptureScopesAbandoned"])
        self.assertFalse(proof["originalEofClaimed"])
        self.assertFalse(proof["originalSourceClosingClaimed"])

    def test_positive_absence_and_complete_custody_are_both_required_for_publication(self):
        subject = self.subject
        mutations = ({"complete": False}, {"timeout": True}, {"overflow": True}, {"readError": True},
            {"eof": {"stdout": False, "stderr": True}}, {"returnCode": 255}, {"counts": {"stdout": 0, "stderr": 0}})
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                oldroot = self.root; self.root = Path(temporary)
                try:
                    context, directory, held, ready_held = self.publication_context()
                    native = self.write_probe(context, altered=mutation)
                    with mock.patch.object(subject, "_THIRD_ADMISSION", self.release()), \
                            mock.patch.multiple(subject, THIRD_INTENT_SHA=held.digest, THIRD_READY_SHA=ready_held.digest):
                        with self.assertRaisesRegex(ValueError, "retirement_absence_unproved"):
                            subject._publish_ended(context, native)
                    self.assertFalse((directory.path / (subject.THIRD_CORRELATION + ".terminal.json")).exists())
                finally: self.root = oldroot

    def test_whole_fixed_probe_uses_actual_complete_body_and_only_owned_gateway_exit(self):
        subject = self.subject
        native_case = OwnedChannelRetirementTests("runTest"); native_case.setUp()
        self.addCleanup(native_case.doCleanups)
        execute, exit_calls, _ = native_case._native(subject=subject, correlation=subject.THIRD_CORRELATION, action="retire")
        context, directory, held, ready_held = self.publication_context()
        ready = execute.request["ready"]
        context[3].config.hosts["archlinux"].remote_host_alias = "fixture"
        context = (context[0], {**context[1], "sourceSha256": "a" * 64}, ready, *context[3:])
        # Actual full helper producer and payload execute; Linux proc/socket/ssh
        # observations are the declared native seam inherited from _native.
        real_capture = subject._fixed546_capture
        packets = []
        def collect(packet, timeout):
            packets.append(packet)
            self.assertEqual(subject._sha(subject._remote_program(subject.THIRD_CORRELATION).encode()), packet["programmeSha256"])
            execute.request.update(json.loads(packet["stdin"][4:4+int.from_bytes(packet["stdin"][:4], "big")]))
            result = execute()
            code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))"
            return real_capture([sys.executable, "-I", "-B", "-c", code, subject._json(result).hex()], b"inert", 3)
        before = self.before()
        with mock.patch.object(before.transport, "connection_host", return_value=object()), \
                mock.patch.object(before.direct, "outer_prefix", return_value=(["ssh-inert-only"], "gateway-inert-only")), \
                mock.patch.object(before.channel, "_collect", side_effect=AssertionError("before must refuse before transport")):
            with self.assertRaisesRegex(ValueError, "retirement_identity"):
                before._probe(context, str(uuid.uuid4()), "retire")
        with mock.patch.object(subject, "_THIRD_ADMISSION", self.release()), \
                mock.patch.object(subject.transport, "connection_host", return_value=object()), \
                mock.patch.object(subject.direct, "outer_prefix", return_value=(["ssh-inert-only"], "gateway-inert-only")), \
                mock.patch.object(subject, "_fixed546_collect", side_effect=collect), \
                mock.patch.object(subject.channel, "_collect", side_effect=AssertionError("old collector forbidden")):
            result = subject._probe(context, str(uuid.uuid4()), "retire")
        self.assertEqual("ended", result["state"])
        self.assertTrue(result["independentAbsence"])
        self.assertEqual(1, len(packets)); self.assertEqual(1, len(exit_calls))
        self.assertEqual(["-O", "exit", "fixture"], exit_calls[0][-3:])
        self.assertEqual("/tmp/vpn-channel-" + subject.THIRD_CORRELATION + "/m", exit_calls[0][exit_calls[0].index("-S")+1])

    def test_private_empty_stderr_before_is_actual_red_and_current_publication_green(self):
        subject = self.subject
        raw = (FIXTURE / "546-empty-stderr.before.source").read_bytes()
        provenance = json.loads((FIXTURE / "546-private-preparation-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeSha256"], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType("agent_tools._546_empty_before_" + uuid.uuid4().hex)
        before.__package__ = "agent_tools"; before.__file__ = str(FIXTURE / "546-empty-stderr.before.source")
        sys.modules[before.__name__] = before; self.addCleanup(sys.modules.pop, before.__name__, None)
        exec(compile(raw, before.__file__, "exec"), before.__dict__)
        for owner, fixed in ((before, False), (subject, True)):
            with self.subTest(fixed=fixed), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                oldroot = self.root; self.root = Path(temporary)
                try:
                    context, directory, held, ready_held = self.publication_context()
                    native = self.write_probe(context)
                    def status(root, host, correlation, **kwargs):
                        with subject.ExitStack() as stack:
                            admitted = subject.channel._retained_v2_terminal(stack, directory, held, json.loads(held.body), host)
                            self.assertIsNotNone(admitted); admitted()
                        return subject.channel._public("ended", correlationId=correlation)
                    with mock.patch.object(owner, "_THIRD_ADMISSION", self.release(owner)), \
                            mock.patch.multiple(owner, THIRD_INTENT_SHA=held.digest, THIRD_READY_SHA=ready_held.digest), \
                            mock.patch.object(owner.direct, "status", side_effect=status):
                        if fixed:
                            self.assertEqual("ended", owner._publish_ended(context, native)["state"])
                        else:
                            with self.assertRaisesRegex(ValueError, "unsafe private file"):
                                owner._publish_ended(context, native)
                finally: self.root = oldroot

    def test_third_claim_is_once_only_across_operation_uuids(self):
        subject = self.subject
        with mock.patch.object(subject, "_THIRD_ADMISSION", self.release()):
            for index in range(2):
                operation = self.root / str(uuid.uuid4()); operation.mkdir(mode=0o700)
                with subject.private.Directory(operation) as output:
                    if index == 0:
                        with subject._claim_exit(output, operation.name, subject.THIRD_CORRELATION): pass
                    else:
                        with self.assertRaises(FileExistsError):
                            with subject._claim_exit(output, operation.name, subject.THIRD_CORRELATION):
                                self.fail("must not send a second exit")
        claim = json.loads((self.root / (subject.THIRD_CORRELATION + ".exit-intent.json")).read_bytes())
        self.assertFalse(claim["replayAllowed"])
        self.assertEqual(subject.THIRD_CORRELATION, claim["correlationId"])

    def test_empty_binary_raw_stream_has_real_generation_and_replacement_refuses(self):
        subject = self.subject
        path = self.root / "stderr.private"; path.write_bytes(b""); path.chmod(0o600)
        with subject.private.Directory(self.root) as directory:
            current = types.SimpleNamespace(held=subject._Held())
            try:
                part = subject._third_raw_part(current, directory, path.name, subject._sha(b""))
                self.assertEqual(0, part.pin()["size"]); self.assertEqual(b"", part.body)
                replacement = self.root / "replacement"; replacement.write_bytes(b""); replacement.chmod(0o600)
                replacement.replace(path)
                with self.assertRaises(ValueError): part.guard()
            finally: current.held.close()

    def reviewed_before(self):
        raw = (FIXTURE / "546-capture-custody.before.source").read_bytes()
        provenance = json.loads((FIXTURE / "546-capture-custody-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeSha256"], hashlib.sha256(raw).hexdigest())
        module = types.ModuleType("agent_tools._546_custody_before_" + uuid.uuid4().hex)
        module.__package__ = "agent_tools"; module.__file__ = str(FIXTURE / "546-capture-custody.before.source")
        sys.modules[module.__name__] = module; self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        return module

    def test_actual_reviewed_before_accepts_public_raw_mode_red_and_current_refuses(self):
        for owner, fixed in ((self.reviewed_before(), False), (self.subject, True)):
            with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                path = Path(temporary) / "raw"; path.write_bytes(b""); path.chmod(0o644)
                with owner.private.Directory(Path(temporary)) as directory:
                    current = types.SimpleNamespace(held=owner._Held())
                    try:
                        if fixed:
                            with self.assertRaisesRegex(ValueError, "retirement_private_stream_mode"):
                                owner._third_raw_part(current, directory, path.name, owner._sha(b""))
                        else:
                            part = owner._third_raw_part(current, directory, path.name, owner._sha(b""))
                            self.assertEqual(0o644, part.pin()["generation"][2] & 0o7777)
                    finally: current.held.close()

    def test_probe_writer_generation_and_bytes_remain_held_until_publication(self):
        # Use actual whole producer, private writer, binary capture, and real
        # late EOF. Only gateway proc/socket facts and SSH peer are inert seams.
        subject = self.subject
        for owner, fixed in ((self.reviewed_before(), False), (subject, True)):
            for mutation in ("same-bytes-replacement", "metadata-change"):
                with self.subTest(fixed=fixed, mutation=mutation), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                    oldroot = self.root; self.root = Path(temporary)
                    try:
                        native_case = OwnedChannelRetirementTests("runTest"); native_case.setUp()
                        self.addCleanup(native_case.doCleanups)
                        execute, _, _ = native_case._native(subject=subject, correlation=subject.THIRD_CORRELATION, action="observe")
                        # Inert old master is already absent, preserving all
                        # original ready/intent records; no exit is submitted.
                        native = {"state": "ended", "correlationId": subject.THIRD_CORRELATION,
                                  "gatewayBoot": "f0efe38b-5ce1-40f1-a7d6-a2a1e816d1fe", "independentAbsence": True}
                        context, directory, held, ready_held = self.publication_context()
                        operation = json.loads((context[4].path / "intent.json").read_bytes())["operationId"]
                        real_capture = owner._fixed546_capture
                        def collect(packet, timeout):
                            code = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))"
                            return real_capture([sys.executable, "-I", "-B", "-c", code, owner._json(native).hex()], b"inert", 3)
                        with mock.patch.object(owner, "_THIRD_ADMISSION", self.release(owner)), \
                                mock.patch.object(owner.transport, "connection_host", return_value=object()), \
                                mock.patch.object(owner.direct, "outer_prefix", return_value=(["ssh-inert-only"], "gateway-inert-only")), \
                                mock.patch.object(owner, "_fixed546_collect", side_effect=collect):
                            observed = owner._probe(context, operation, "observe")
                        path = context[4].path / "probe.json"
                        raw = path.read_bytes()
                        if mutation == "metadata-change":
                            value = json.loads(raw); value["primaryError"] = {"errorClass": "forged"}; raw = owner._json(value)
                        replacement = context[4].path / "replacement"; replacement.write_bytes(raw); replacement.chmod(0o600); replacement.replace(path)
                        def status(root, host, correlation, **kwargs):
                            return owner.channel._public("ended", correlationId=correlation)
                        with mock.patch.object(owner, "_THIRD_ADMISSION", self.release(owner)), \
                                mock.patch.multiple(owner, THIRD_INTENT_SHA=held.digest, THIRD_READY_SHA=ready_held.digest), \
                                mock.patch.object(owner.direct, "status", side_effect=status):
                            if fixed:
                                with self.assertRaises(ValueError): owner._publish_ended(context, observed)
                                self.assertFalse((directory.path / (subject.THIRD_CORRELATION + ".terminal.json")).exists())
                            else:
                                self.assertEqual("ended", owner._publish_ended(context, observed)["state"])
                    finally: self.root = oldroot

    def test_whole_high_fd_reader_writer_red_and_scalable_outer_inner_green(self):
        import resource, selectors, shlex
        subject = self.subject
        path = FIXTURE / "546-high-fd.before.source"
        raw = path.read_bytes(); provenance = json.loads((FIXTURE / "546-high-fd-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeSha256"], hashlib.sha256(raw).hexdigest())
        before = types.ModuleType("agent_tools._546_highfd_before_" + uuid.uuid4().hex)
        before.__package__ = "agent_tools"; before.__file__ = str(path)
        sys.modules[before.__name__] = before; self.addCleanup(sys.modules.pop, before.__name__, None)
        exec(compile(raw, before.__file__, "exec"), before.__dict__)
        request = json.dumps({"operationId": str(uuid.uuid4()), "action": "observe",
            "ready": {"correlationId": subject.THIRD_CORRELATION}, "sourceSha256": "a" * 64,
            "config": "", "profile": "inert-only"}, sort_keys=True).encode()
        source = "import json,sys\njson.load(sys.stdin)\nprint('EXACT HIGHFD OUT')\nsys.stderr.write('EXACT HIGHFD ERR\\n')\n"
        rescues = []
        def rescue_original(owner):
            # Safety seam only after authentic1433 readiness failure: drain the
            # same original harmless child without a signal, retry, or replay.
            self.assertTrue("ValueError" in owner.read_errors or "ValueError" in owner.writer_errors)
            first = owner.snapshot(); deadline = time.monotonic() + 5
            with selectors.DefaultSelector() as readiness:
                for key in owner.raw:
                    if not owner.eof[key]: readiness.register(getattr(owner.child, key), selectors.EVENT_READ, key)
                while readiness.get_map():
                    self.assertLess(time.monotonic(), deadline, "original harmless child remains owned")
                    for key, _ in readiness.select(.05):
                        try: data = os.read(key.fd, 65536)
                        except (BlockingIOError, InterruptedError): continue
                        if not data: owner.eof[key.data] = True; readiness.unregister(key.fileobj)
                        else: owner.counts[key.data] += len(data); owner.raw[key.data].extend(data)
            if owner.writer is not None and owner.writer.ident is not None:
                owner.writer.join(1); self.assertFalse(owner.writer.is_alive())
            owner.child.wait(timeout=1); owner.child.stdout.close(); owner.child.stderr.close(); owner.closed = True
            rescues.append(first)
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE); desired = 3564
        if soft < desired:
            if hard != resource.RLIM_INFINITY and hard < desired: self.skipTest("hard FD limit cannot reproduce real3308 FD ownership")
            resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
        held = []
        try:
            while not held or held[-1] < 3308: held.append(os.open("/dev/null", os.O_RDONLY))
            self.assertGreaterEqual(max(held), 3308)
            for owner, fixed in ((before, False), (subject, True)):
                children = []
                def peer(argv, **kwargs):
                    command = shlex.split(argv[-1]); self.assertEqual(["python3", "-I", "-B", "-c"], command[:4])
                    child = subprocess.Popen([sys.executable, "-I", "-B", "-c", command[4]], **kwargs)
                    children.append(child); return child
                packet = owner._fixed546_transport_packet(["ssh-inert-only"], "gateway-inert-only", source, request)
                if fixed:
                    result = owner._fixed546_collect(packet, 3, _popen=peer)
                else:
                    with mock.patch.object(owner._Fixed546Owner, "finish_naturally", rescue_original):
                        result = owner._fixed546_collect(packet, .08, _popen=peer)
                self.assertEqual(1, len(children)); self.assertTrue(result["originalTerminal"]["complete"])
                self.assertTrue(result["originalStreamsClosed"])
                self.assertEqual({"stdout": True, "stderr": True}, result["eof"])
                if fixed:
                    self.assertTrue(result["complete"]); self.assertFalse(result["readError"]); self.assertFalse(result["writeError"])
                    self.assertEqual(b"EXACT HIGHFD OUT\n", result["stdout"]); self.assertEqual(b"EXACT HIGHFD ERR\n", result["stderr"])
                    self.assertEqual(len(packet["stdin"]), result["originalTerminal"]["forwardedBytes"])
                else:
                    self.assertFalse(result["complete"]); self.assertTrue(result["readError"]); self.assertTrue(result["writeError"])
                    self.assertEqual(b"", result["stdout"]); self.assertEqual(0, result["originalTerminal"]["forwardedBytes"])
                # Execute the actual emitted complete inner source as well;
                # only the control command is a finite harmless local child.
                scope = {}; exec(compile(owner._fixed546_inner_source(), "actual-highfd-generated-inner", "exec"), scope)
                argv = [sys.executable, "-I", "-B", "-c", "import sys;print('INNER HIGHFD OUT');sys.stderr.write('INNER HIGHFD ERR\\n');sys.exit(7)"]
                if fixed:
                    inner = scope["inner"](argv, 3)
                else:
                    with mock.patch.object(scope["_Fixed546Owner"], "finish_naturally", rescue_original):
                        inner = scope["inner"](argv, .08)
                self.assertTrue(inner["originalTerminal"]["complete"])
                self.assertEqual(b"INNER HIGHFD OUT\n", inner["stdout"]); self.assertEqual(b"INNER HIGHFD ERR\n", inner["stderr"])
                self.assertEqual(7, inner["returnCode"])
                self.assertEqual(fixed, inner["complete"]); self.assertEqual(not fixed, inner["readError"])
            self.assertEqual(2, len(rescues))
        finally:
            for fd in reversed(held): os.close(fd)
            if soft < desired: resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    def test_actual_whole_native_fixture_shared_parent_churn_red_and_current_green(self):
        path = FIXTURE / "546-route-fixture.before.source"
        raw = path.read_bytes(); provenance = json.loads((FIXTURE / "546-route-fixture-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeSha256"], hashlib.sha256(raw).hexdigest())
        old = types.ModuleType("agent_tools.tests._retirement_fixture_before_" + uuid.uuid4().hex)
        old.__package__ = "agent_tools.tests"; old.__file__ = str(path)
        sys.modules[old.__name__] = old; self.addCleanup(sys.modules.pop, old.__name__, None)
        exec(compile(raw, old.__file__, "exec"), old.__dict__)
        # Merged emitted guards bind ancestors structurally, so churn alone no longer
        # reaches a fixture. Preserved pre-structural guards keep the fixture's own
        # cause observable: old fixture RED, current ancestor seam GREEN on the same
        # guards, and the fixed arm on the current guards.
        unfixed_raw = (FIXTURE.parent / "nested_directory_membership/original-ee4-remote.before.source").read_bytes()
        self.assertEqual("6a67cbde6e7c34ce4745801fa58e666557225cc1f6dca803d2a1528d1f047139", hashlib.sha256(unfixed_raw).hexdigest())
        names = self.subject.channel._guard_names
        nodes = [node for node in ast.parse(unfixed_raw).body if isinstance(node, ast.FunctionDef) and node.name in names]
        self.assertEqual(names, {node.name for node in nodes})
        unfixed = "".join(ast.get_source_segment(unfixed_raw.decode(), node) + "\n" for node in nodes)
        current = self.subject.channel._guard_program
        for case_type, guards, fixed in ((old.OwnedChannelRetirementTests, unfixed, False), (OwnedChannelRetirementTests, unfixed, True),
                                         (OwnedChannelRetirementTests, current, True)):
            case = case_type("runTest"); case.setUp(); self.addCleanup(case.doCleanups)
            # The preserved fixture hard-codes dir="/tmp", which Linux remaps into itself.
            real_temporary = tempfile.TemporaryDirectory
            def outside_modeled_tmp(*args, **kwargs):
                if kwargs.get("dir") == "/tmp":
                    kwargs["dir"] = "/var/tmp"
                return real_temporary(*args, **kwargs)
            with mock.patch.object(self.subject.channel, "_guard_program", guards), mock.patch.object(tempfile, "TemporaryDirectory", outside_modeled_tmp):
                execute, calls, _ = case._native(subject=self.subject, correlation=self.subject.THIRD_CORRELATION, action="retire")
            namespace = dict(zip(execute.__code__.co_freevars, (cell.cell_contents for cell in execute.__closure__)))["namespace"]
            original_inner = namespace["inner"]
            def inner_with_owned_shared_churn(argv, timeout):
                result = original_inner(argv, timeout)
                # Create/remove only our unique directory, outside the modeled
                # Linux root, to reproduce real shared-ancestor churn exactly.
                path = execute.config_path.parents[4] / ("retirement-fixture-churn-" + uuid.uuid4().hex)
                path.mkdir(mode=0o700); path.rmdir()
                return result
            namespace["inner"] = inner_with_owned_shared_churn
            if fixed:
                self.assertEqual("ended", execute()["state"])
                self.assertEqual(1, len(calls))
            else:
                with self.assertRaisesRegex(ValueError, "^route(_parent_changed)?$"):
                    execute()
                self.assertEqual(1, len(calls))
        # Existing config mutation control still operates on real bytes/full
        # leaf generations; this fixture correction grants no product exception.
        case = OwnedChannelRetirementTests("runTest"); case.setUp(); self.addCleanup(case.doCleanups)
        execute, calls, _ = case._native(subject=self.subject, correlation=self.subject.THIRD_CORRELATION)
        execute.config_path.write_text("Host changed\n")
        with self.assertRaisesRegex(ValueError, "route"):
            execute()
        self.assertEqual([], calls)

    def test_integrated_automatic_gateway_and_inner_carrier_causal_controls(self):
        rows = _run_fixed546_carrier_controls(self.subject, self.root)
        self.assertEqual(32, len(rows))


def _run_diagnostic_retention_case(label, case_directory):
    """One whole saved diagnostic entry in a clean harmless local process."""
    import builtins, contextlib, copy, importlib, io, traceback
    HERE = Path(case_directory).resolve(); HERE.mkdir(mode=0o700)
    REPO = ROOT
    provenance = json.loads((FIXTURE / 'diagnostic-retention-provenance.json').read_bytes())
    PINS = {('before' if name == 'diagnostic-retention-before.source' else name.removeprefix('diagnostic-retention-').removesuffix('.source')): row['sha256'] for name, row in provenance['entrySources'].items()}
    ENTRY_PATHS = {('before' if name == 'diagnostic-retention-before.source' else name.removeprefix('diagnostic-retention-').removesuffix('.source')): FIXTURE / name for name in provenance['entrySources']}
    TRUST = '/Users/karapsin_de/.ssh/known_hosts'  # Historical entry token; mapped to own inert file, never opened.
    def sha(data): return hashlib.sha256(data).hexdigest()
    def generation(s): return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
    def write(path, raw):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700); path.write_bytes(raw); path.chmod(0o600)
    def jraw(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    def metadata(path): return {'sha256':sha(path.read_bytes()), 'generation':generation(path.stat())}
    SOURCE_BYTES = {name:(REPO/name).read_bytes() for name in provenance['sourceFiles']}
    SOURCE_FREEZE = {'sourceFiles':{name:metadata(REPO/name) for name in provenance['sourceFiles']}}
    CURRENT_WRITER_RAW = (REPO/provenance['canonicalCaptureDependency']['path']).read_bytes()
    assert sha(CURRENT_WRITER_RAW) == provenance['canonicalCaptureDependency']['sha256'], 'diagnostic_current_capture_dependency_requires_review'
    historical = provenance['historicalCaptureDependency']
    HISTORICAL_WRITER_RAW = (FIXTURE/historical['fixture']).read_bytes()
    assert sha(HISTORICAL_WRITER_RAW) == historical['sha256'], 'diagnostic_historical_capture_dependency_requires_review'
    WRITER_RAW = CURRENT_WRITER_RAW if label.startswith('v4-') else HISTORICAL_WRITER_RAW
    REQUEST_RAW = jraw({'operationId':'78405b89-d06a-4cb4-b10b-6fdc207afc5d', 'program':{'language':'python3','source':'pass\n','args':[],'cwd':'/','targetContext':{'kind':'ssh','uid':1000,'principal':'fixture','home':'/inert/fixture','bootId':'00000000-0000-0000-0000-000000000000'}}})
    MANIFEST = {'direct-oversized':{'requestPath':'owned-runtime-request','requestSha256':sha(REQUEST_RAW),'sourceSha256':sha(b'pass\n')}}
    CONFIG_RAW = jraw({'schemaVersion':1,'hosts':{'gateway':{'host':'gateway.invalid','port':22,'user':'fixture','identityFile':'/inert/key','knownHostsFile':'/inert/known'},'archlinux':{'host':'arch.invalid','port':22,'user':'fixture','identityFile':'/inert/nested-key','knownHostsFile':'/inert/nested-known','transport':'nested','gateway':'gateway','remoteHostAlias':'archlinux','remoteConfigFile':'/inert/owned-ssh-config'}}})
    TRUST_RAW = b'INERT TRUST DATA; NO AUTHENTICATION AUTHORITY\n'
    class World:
     def __init__(self,label,kind,shape,fault=None):
      self.label=label;self.kind=kind;self.shape=shape;self.fault=fault;self.case=HERE/label;self.case.mkdir(mode=0o700)
      self.root=self.case/'isolated-root';self.root.mkdir(mode=0o700);self.base=self.root/'.runtime/windows-parity-20261019/program-tool-native/stage-b-b204-native-v1';self.base.mkdir(parents=True,mode=0o700)
      for name,raw in SOURCE_BYTES.items():write(self.root/name,raw)
      write(self.root/'agent_tools/ssh_owned_channel_retirement.py',WRITER_RAW)
      self.trust=self.root/'credentials/known_hosts';write(self.trust,TRUST_RAW);key=self.root/'credentials/inert-key';write(key,b'INERT NONAUTHORITY KEY\n')
      config=json.loads(CONFIG_RAW)
      for entry in config['hosts'].values():
       if entry.get('transport','direct')=='direct':entry['identityFile']=str(key);entry['knownHostsFile']=str(self.trust)
      write(self.root/'.vm-hosts.local.json',jraw(config))
      freeze=copy.deepcopy(SOURCE_FREEZE);freeze['sourceFiles']={name:metadata(self.root/name)for name in SOURCE_BYTES};write(self.base/'source-freeze.json',jraw(freeze))
      manifest=copy.deepcopy(MANIFEST);rp=self.base/'direct-oversized.request.private.json';write(rp,REQUEST_RAW);manifest['direct-oversized']['requestPath']=str(rp);write(self.base/'requests.private.json',jraw(manifest))
      preserve=self.base/'oversized-original-failure-before-diagnosis';preserve.mkdir(mode=0o700)
      write(preserve/'additional-preservation.private.json',jraw({'records':{'config':metadata(self.root/'.vm-hosts.local.json')}}))
      write(preserve/'preservation-manifest.private.json',jraw({'nativeOwnedRecords':{'currentTrustInput':metadata(self.trust)}}))
      self.input_names=[self.root/name for name in SOURCE_BYTES]+[rp,self.root/'.vm-hosts.local.json',self.trust]
      if kind!='before':self.input_names.append(self.root/'agent_tools/ssh_owned_channel_retirement.py')
      self.input_opening={str(p):metadata(p)for p in self.input_names};self.opened={};self.events=[];self.builds=0;self.entry_trace=None;self.mutated=False
      self.pkg='agent_tools';assert not any(n=='agent_tools' or n.startswith('agent_tools.')for n in sys.modules)
      pkg=types.ModuleType(self.pkg);pkg.__path__=[str(self.root/'agent_tools')];pkg.__package__=self.pkg;sys.modules[self.pkg]=pkg
      old=sys.dont_write_bytecode;sys.dont_write_bytecode=True
      try:self.capture=importlib.import_module(self.pkg+'.ssh_owned_channel_retirement');self.program=importlib.import_module(self.pkg+'.ssh_program_execution')
      finally:sys.dont_write_bytecode=old
      assert self.capture._LOADED_SHA==sha(WRITER_RAW)and sys.modules[self.capture.__name__]is self.capture
      if shape=='empty':stdout=b'';stderr=b''
      else:stdout=b'{"state":"inert"}\nraw\x00\xff';stderr='東京 stderr Ω\n'.encode()
      self.capture_data={'stdout':stdout,'stderr':stderr,'complete':True,'returnCode':0,'eof':{'stdout':True,'stderr':True},'overflow':False,'nested':{'raw':{'stdout':{'bytes':len(stdout),'sha256':sha(stdout)},'stderr':{'bytes':len(stderr),'sha256':sha(stderr)}},'items':[{'kind':'same-original','flags':[True,False,None]}]}}
      self.observations={'host':'archlinux','observations':[{'observation':'same-original-inert-boundary','transportSourceSha256':SOURCE_FREEZE['sourceFiles']['agent_tools/ssh_transport.py']['sha256'],'capture':self.capture_data}],'captureFailures':[]}
      world=self
      class Transport:
       @contextlib.contextmanager
       def _private_admission_capture(self):world.events.append(['admission-capture-enter']);yield world.observations;world.events.append(['admission-capture-exit'])
       def load_config(self,root):assert root==world.root;world.events.append(['load-config']);return{'inert':True}
       def argv_byte_sizes(self,argv):assert argv==['never-execute','inert'];return{'wholeArgvBytes':31,'limitBytes':60000}
      scope={'world':self}
      exec(compile("class ChannelUnknown(ValueError):\n def __init__(self,result):self.result=result;super().__init__('inert structured refusal')\ndef build_ssh_argv(self,config,host,timeout,command):\n world.builds+=1\n assert world.builds==1 and host=='archlinux' and timeout==15\n world.events.append(['build-ssh-argv',world.kind])\n if world.kind=='refusal' or world.kind=='before':raise ChannelUnknown({'state':'unknown','replayAllowed':False,'nested':{'stage':'inert-existing-admission','reasons':['same-original']}})\n return ['never-execute','inert']\n",str(self.root/'agent_tools/ssh_transport.py'),'exec'),scope,scope)
      Transport.build_ssh_argv=scope['build_ssh_argv']
      transport=Transport();module=types.SimpleNamespace(_request=self.program._request,remote=self.program.remote,transport=transport)
      owner=types.SimpleNamespace(_module=module,_session=types.SimpleNamespace(guard=lambda:self.events.append(['source-session-guard'])))
      @contextlib.contextmanager
      def request_scope(root):assert root==self.root/'agent_tools';self.events.append(['request-scope-enter']);yield;self.events.append(['request-scope-exit'])
      def adapter(root,name):assert root==self.root/'agent_tools'and name=='ssh_program_execution';self.events.append(['adapter']);return owner
      self.agent_tools=types.ModuleType('agent_tools');self.agent_tools.source_module_loader=types.SimpleNamespace(request_scope=request_scope,adapter=adapter);self.agent_tools.ssh_owned_channel_retirement=self.capture
      self.os=types.ModuleType('os')
      for name in dir(os):setattr(self.os,name,getattr(os,name))
      def mapped(p):return self.trust if str(p)==TRUST else p
      def opened(path,flags,mode=0o777):
       path=Path(mapped(path));assert path.is_relative_to(self.root),('outside-isolated-layout',str(path));fd=os.open(path,flags,mode);self.opened[fd]=str(path);self.events.append(['open',fd,str(path),flags]);return fd
      def closed(fd):
       path=self.opened.pop(fd);os.close(fd);self.events.append(['close',fd,path])
       if fault=='raw-writer-collision'and path.endswith('exception-trace.private.json'):
        write(Path(path).parent/'same-call-observation-0.stdout',b'controlled collision\n')
      self.os.open=opened;self.os.close=closed;self.os.stat=lambda p,**kw:os.stat(mapped(p),**kw)
      self.sys=types.SimpleNamespace(path=[],settrace=lambda callback:setattr(self,'entry_trace',callback))
     def importer(self,name,globals=None,locals=None,fromlist=(),level=0):
      if name=='agent_tools':return self.agent_tools
      if name=='os':return self.os
      if name=='sys':return self.sys
      assert level==0 and name in('pathlib','collections','hashlib','json','traceback'),('undeclared-entry-import',name)
      return builtins.__import__(name,globals,locals,fromlist,level)
     def output_dir(self,version):return self.base/'oversized-original-failure-before-diagnosis'/('same-boundary-diagnostic-v1'if version=='before'else'same-boundary-diagnostic-'+version)
     def cleanup(self):
      leftovers=dict(self.opened)
      for fd in list(self.opened):os.close(fd);self.opened.pop(fd)
      for name in list(sys.modules):
       if name==self.pkg or name.startswith(self.pkg+'.'):sys.modules.pop(name,None)
      return leftovers

    def run(label,version,kind,shape,expected,fault=None):
     origin=ENTRY_PATHS[version];template_raw=origin.read_bytes();assert sha(template_raw)==PINS[version]
     raw=template_raw;derivation=None
     if version=='v4':
      derivation=provenance['currentReaderDerivation']
      old=derivation['oldCaptureSha256'].encode();new=derivation['currentCaptureSha256'].encode()
      assert sha(template_raw)==derivation['templateSha256'] and template_raw.count(old)==derivation['replacementCount']==2
      assert new.decode()==provenance['canonicalCaptureDependency']['sha256']
      raw=template_raw.replace(old,new)
      assert sha(raw)==derivation['renderedSha256'] and len(raw)==derivation['renderedBytes']
     world=World(label,kind,shape,fault);normal=dict(vars(builtins));normal['__import__']=world.importer
     source=world.base/'diagnostic-entry.py'
     source_fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
     try:
      at=0
      while at<len(raw):
       count=os.write(source_fd,raw[at:]);assert count>0;at+=count
      os.fsync(source_fd)
     finally:os.close(source_fd)
     source_opening=metadata(source);source_held=world.capture._Held()
     raw=source_held.read(str(source),sha(raw),tuple(source_opening['generation']),max_bytes=65536)
     held_fd=source_held.files[str(source)][0];source_held.finish();source_held.final_identity_pass()
     namespace={'__name__':'__main__','__file__':str(source),'__builtins__':normal};error=None;stdout=io.StringIO();stderr=io.StringIO();counts={};lines=set();mutation=None
     def tracer(frame,event,arg):
      nonlocal mutation
      filename=frame.f_code.co_filename
      if event=='call'and(filename==str(source)or filename.startswith(str(world.root/'agent_tools'))):
       key=Path(filename).name+'::'+frame.f_code.co_qualname;counts[key]=counts.get(key,0)+1
      if filename==str(source)and event=='line':lines.add(frame.f_lineno)
      if world.entry_trace is not None:world.entry_trace(frame,event,arg)
      if fault=='same-byte-replace'and not world.mutated and event=='return'and frame.f_code.co_name=='_capture'and filename==str(world.root/'agent_tools/ssh_owned_channel_retirement.py'):
       p=world.output_dir(version)/'same-call-observation-0.stdout';before=metadata(p);new=p.with_name('replacement.private');write(new,p.read_bytes());os.replace(new,p);after=metadata(p);assert before['sha256']==after['sha256']and before['generation']!=after['generation'];world.mutated=True;mutation={'before':before,'after':after,'sameBytes':True,'differentGeneration':True}
      return tracer
     prior=sys.gettrace()
     try:
      with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):sys.settrace(tracer);exec(compile(raw,str(source),'exec'),namespace,namespace)
     except BaseException as caught:error={'class':type(caught).__name__,'message':str(caught),'traceback':traceback.format_exc()}
     finally:
      sys.settrace(prior)
      try:
       source_held.finish();source_held.final_identity_pass();source_closing=metadata(source)
       assert source_closing==source_opening and generation(os.fstat(held_fd))==source_closing['generation']
      finally:source_held.close()
     output=world.output_dir(version);files={p.name:{'sha256':sha(p.read_bytes()),'bytes':len(p.read_bytes()),'generation':generation(p.stat())}for p in output.iterdir()if p.is_file()}
     typed=json.loads((output/'result.private.json').read_bytes())if(output/'result.private.json').exists()else None
     index=json.loads((output/'same-call-native-capture-index.private.json').read_bytes())if(output/'same-call-native-capture-index.private.json').exists()else None
     assert world.builds==1, error
     assert all(metadata(Path(p))==old for p,old in world.input_opening.items()),'input mutation'
     if expected=='serialization-red':assert error and error['class']=='TypeError'and 'bytes'in error['message']and typed is None
     elif expected=='empty-red':assert error and error['message']=='unsafe private file'and typed and(output/'exception-trace.private.json').exists()and(output/'raw-retention-failure.private.json').exists()
     elif expected=='exchange-refused':assert error and error['class']=='AssertionError'and typed and index is None and world.mutated
     elif expected=='writer-refused':assert error and error['class']=='FileExistsError'and typed and(output/'exception-trace.private.json').exists()and(output/'raw-retention-failure.private.json').exists()
     else:
      assert error is None,(label,error);assert typed and typed['sourceClosing']is True and index['rawReadbackAndSourceClosing']is True
      assert typed['state']==('current-read-only-build-refused'if kind=='refusal'else'current-read-only-build-succeeded')
      for stream in('stdout','stderr'):assert(output/('same-call-observation-0.'+stream)).read_bytes()==world.capture_data[stream]
      assert json.loads((output/'same-call-observation-0.json').read_bytes())=={k:v for k,v in world.capture_data.items()if k not in('stdout','stderr')}
     if version!='before':assert not world.opened
     if version in('v3','v4'):
      assert counts.get('ssh_direct_nested_channel.py::Guard.__init__',0)>=1
      assert counts.get('ssh_owned_channel_retirement.py::_third_raw_part',0)>=1 or expected=='writer-refused'
     if expected not in('serialization-red',):assert counts.get('ssh_owned_channel_retirement.py::_capture',0)==1
     leftovers=world.cleanup()
     receipt={'schemaVersion':1,'label':label,'source':str(source),'sourceSha256':sha(raw),'sourceUnmodified':True,'sourceOpeningPin':source_opening,'sourceClosingPin':source_closing,'sourceFdNameHashAndFullGenerationClosing':True,'authenticOrigin':{'source':str(origin),'sourceSha256':sha(template_raw)},'templateSha256':sha(template_raw),'templateUnmodified':origin.read_bytes()==template_raw,'exactSourceDerivation':derivation,'initialGlobals':['__name__','__file__','__builtins__'],'partialNamespaceExecution':False,'postExecFunctionReplacement':False,'declaredBoundaryPeers':['agent_tools.source_module_loader admission import peer delegates actual copied canonical _request/remote.command, only transport read-only build is inert','entry os restricts all opens to isolated-root and redirects the one hardcoded trust pathname','entry sys path/trace multiplexer','filesystem same-byte exchange/collision only when named fault enabled'],'isolatedLayout':{'exactCanonicalSourceFiles':len(SOURCE_BYTES),'exactSourceHashes':{name:sha(raw)for name,raw in SOURCE_BYTES.items()},'exactOriginalRequestSha256':sha(REQUEST_RAW),'originalConfigSha256':sha(CONFIG_RAW),'isolatedConfigSha256':sha((world.root/'.vm-hosts.local.json').read_bytes()),'configModification':'Only direct-host identity/known_hosts paths relocated to own harmless fixture credentials; never live authority','trustBytesSha256':sha(TRUST_RAW),'entryHeldInputCount':len(world.input_names),'canonicalCaptureSha256':sha(WRITER_RAW),'canonicalModulesNormallyRegisteredCompleteNamespaces':True},'fault':fault,'expected':expected,'passed':True,'error':error,'typedResult':typed,'captureIndex':index,'outputFiles':files,'stdout':stdout.getvalue(),'stderr':stderr.getvalue(),'entryCoveredLines':sorted(lines),'actualCanonicalFunctionCalls':counts,'inputOpeningAndClosingEqual':True,'entryOpenCloseEvents':world.events,'ownInputFdsLeftByOriginalEntryBeforeHarnessCleanup':len(leftovers),'harnessCleanupOnlyOwnIsolatedDescriptors':list(leftovers.values()),'mutation':mutation,'buildCallCount':world.builds,'programStartCalls':0,'nativeNetworkOrProcessActions':0}
     rp=world.case/'receipt.private.json';write(rp,jraw(receipt));return{'label':label,'passed':True,'expected':expected,'sourceSha256':sha(raw),'entryHeldInputCount':len(world.input_names),'receipt':str(rp),'receiptSha256':sha(rp.read_bytes()),'error':None if error is None else error['class']+': '+error['message']}

    cases = {
        'before-rawbytes-red': ('before','before','nonempty','serialization-red'),
        'v2-empty-readback-red': ('v2','success','empty','empty-red'),
        'v3-samebyte-adoption-red': ('v3','success','nonempty','green','same-byte-replace'),
        'v4-samebyte-replacement-refused': ('v4','success','nonempty','exchange-refused','same-byte-replace'),
        'v4-refusal-empty-green': ('v4','refusal','empty','green'),
        'v4-refusal-nonempty-green': ('v4','refusal','nonempty','green'),
        'v4-success-empty-green': ('v4','success','empty','green'),
        'v4-success-nonempty-green': ('v4','success','nonempty','green'),
        'v4-writer-failure-preserves-result-trace': ('v4','success','nonempty','writer-refused','raw-writer-collision'),
    }
    row = run(label, *cases[label])
    return row


@unittest.skipUnless(os.name == 'posix', 'POSIX physical diagnostic capture ownership')
class DiagnosticRetentionEntryTests(unittest.TestCase):
    def run_case(self, label):
        with tempfile.TemporaryDirectory(prefix='diagnostic-routine-') as temporary:
            result = Path(temporary)/'case'
            # Compile the complete actual test module in a clean local process;
            # the entry itself receives only __name__, __file__ and builtins.
            bootstrap = "from pathlib import Path;import sys,json; p=Path(sys.argv[1]); n={'__name__':'_diagnostic_retention_child','__file__':str(p)};exec(compile(p.read_bytes(),str(p),'exec'),n,n);print(json.dumps(n['_run_diagnostic_retention_case'](sys.argv[2],sys.argv[3]),sort_keys=True))"
            child = subprocess.run([sys.executable,'-I','-B','-c',bootstrap,str(Path(__file__).resolve()),label,str(result)],capture_output=True,timeout=30)
            self.assertEqual(0, child.returncode, child.stderr.decode(errors='replace'))
            row = json.loads(child.stdout); self.assertTrue(row['passed'])
            receipt = json.loads(Path(row['receipt']).read_bytes())
            self.assertTrue(receipt['sourceUnmodified']); self.assertFalse(receipt['partialNamespaceExecution'])
            self.assertEqual(0,receipt['programStartCalls']); self.assertEqual(0,receipt['nativeNetworkOrProcessActions'])
            self.assertEqual(1,receipt['buildCallCount']); self.assertTrue(receipt['inputOpeningAndClosingEqual'])
            if label == 'v3-samebyte-adoption-red':
                self.assertTrue(receipt['mutation']['sameBytes']); self.assertTrue(receipt['mutation']['differentGeneration'])
                self.assertIsNotNone(receipt['captureIndex'])

    def test_diagnostic_before_rawbytes_red(self):
        self.run_case('before-rawbytes-red')

    def test_diagnostic_v2_empty_readback_red(self):
        self.run_case('v2-empty-readback-red')

    def test_diagnostic_v3_samebyte_adoption_red(self):
        self.run_case('v3-samebyte-adoption-red')

    def test_diagnostic_v4_samebyte_replacement_refused(self):
        self.run_case('v4-samebyte-replacement-refused')

    def test_diagnostic_v4_refusal_empty_green(self):
        self.run_case('v4-refusal-empty-green')

    def test_diagnostic_v4_refusal_nonempty_green(self):
        self.run_case('v4-refusal-nonempty-green')

    def test_diagnostic_v4_success_empty_green(self):
        self.run_case('v4-success-empty-green')

    def test_diagnostic_v4_success_nonempty_green(self):
        self.run_case('v4-success-nonempty-green')

    def test_diagnostic_v4_writer_failure_preserves_result_trace(self):
        self.run_case('v4-writer-failure-preserves-result-trace')

@unittest.skipUnless(os.name == "posix", "POSIX private channel coordinator")
class Fixed267RetirementTests(unittest.TestCase):
    def setUp(self):
        from agent_tools import ssh_owned_channel_retirement as subject
        self.subject = subject
        self.temporary = tempfile.TemporaryDirectory(prefix="fixed267-retire-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.intake = json.loads((FIXTURE / "267-program-records-intake.json").read_bytes())
        self.assertEqual("a0c10b8f019aa7e251dac2186e42049756519f5a8a902c060d8c631c4f3d24aa",
                         subject._sha((FIXTURE / "267-program-records-intake.json").read_bytes()))
        admission_raw = (FIXTURE / "267-admission.json").read_bytes()
        provenance = json.loads((FIXTURE / "267-provenance.json").read_bytes())
        self.assertEqual(provenance["admission"]["sha256"], subject._sha(admission_raw))
        self.admission = json.loads(admission_raw)

    def release(self):
        return json.loads(json.dumps(self.admission))

    def before(self):
        raw = (FIXTURE / "267-helper.before.source").read_bytes()
        provenance = json.loads((FIXTURE / "267-provenance.json").read_bytes())
        self.assertEqual(provenance["beforeHelperSha256"], hashlib.sha256(raw).hexdigest())
        module = types.ModuleType("agent_tools._267_before_" + uuid.uuid4().hex)
        module.__package__ = "agent_tools"; module.__file__ = str(FIXTURE / "267-helper.before.source")
        sys.modules[module.__name__] = module
        self.addCleanup(sys.modules.pop, module.__name__, None)
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
        self.assertIs(sys.modules[module.__name__], module)
        self.assertIs(module._profile.__globals__, module.__dict__)
        return module

    def publication_context(self):
        subject = self.subject; correlation = subject.FOURTH_CORRELATION
        journal = self.root / ".rag_index/ssh-direct-nested-channel/hosts/archlinux"
        journal.mkdir(mode=0o700, parents=True)
        for path in (self.root / ".rag_index", journal.parent.parent, journal.parent, journal):
            path.chmod(0o700)
        directory = subject.private.Directory(journal); self.addCleanup(directory.close)
        intent_raw = (FIXTURE / "267-intent.json").read_bytes()
        self.assertEqual(subject.FOURTH_INTENT_SHA, subject._sha(intent_raw))
        # This owned publication context relocates only executable-source pins;
        # the authentic fe252/d834 records remain separately verified fixtures.
        canonical = Path(subject.direct.__file__).parent
        intent = json.loads(intent_raw)
        intent["sourceSha256"] = subject._sha((canonical / "ssh_fresh_nested_channel.py").read_bytes())
        intent["remoteSourceSha256"] = subject._sha(subject.channel._REMOTE.encode())
        intent["directSourcePins"] = {name: subject._sha((canonical / name).read_bytes()) for name in subject.direct.source_catalog(intent["version"])}
        original = journal / (correlation + ".intent.json")
        original.write_bytes(subject._json(intent)); original.chmod(0o600)
        held = subject.private.Snapshot(directory, original.name); self.addCleanup(held.close)
        ready = json.loads((FIXTURE / "267-ready.json").read_bytes())["result"]
        ready_path = journal / (correlation + ".ready.json")
        ready_path.write_bytes(subject._json({"intent": held.pin(), "result": ready})); ready_path.chmod(0o600)
        ready_held = subject.private.Snapshot(directory, ready_path.name); self.addCleanup(ready_held.close)
        capsules = {}
        for name, digest in {"remote": intent["remoteSourceSha256"], **intent["directSourcePins"]}.items():
            raw = subject.channel._REMOTE.encode() if name == "remote" else (canonical / name).read_bytes()
            self.assertEqual(digest, subject._sha(raw))
            path = journal / (correlation + "." + name + ".source")
            path.write_bytes(raw); path.chmod(0o600)
            part = subject.private.Snapshot(directory, path.name); self.addCleanup(part.close)
            capsules[name] = part
        unknown = self.root / ".rag_index/ssh-program-execution" / subject.FOURTH_UNKNOWN
        unknown.mkdir(mode=0o700, parents=True)
        for name in ("terminal.json", "owner-closed.json"):
            path = unknown / name
            path.write_bytes((FIXTURE / ("267-closed-unknown-" + name)).read_bytes()); path.chmod(0o600)
        output_path = self.root / "output"; output_path.mkdir(mode=0o700)
        output = subject.private.Directory(output_path); self.addCleanup(output.close)
        raw_held = subject._Held(); self.addCleanup(raw_held.close)
        current = types.SimpleNamespace(held=raw_held, authority_sha=intent["outerAuthoritySha256"],
            authority={"declaredSameAuthority": True, "declaredInertCurrentSourceContext": True},
            config=types.SimpleNamespace(hosts={"archlinux": types.SimpleNamespace(gateway="inert", remote_config_file="", remote_host_alias="inert")}))
        released = []
        def guard():
            held.guard(); ready_held.guard(); directory.guard(); output.guard()
            raw_held.finish(); raw_held.final_identity_pass()
            for part in capsules.values(): part.guard()
        context = (self.root, intent, ready, current, output, capsules, guard, lambda: released.append(True))
        return context, directory, held, ready_held, released, unknown

    def test_authentic_267_before_refuses_and_current_binds_exact_profile(self):
        subject, before = self.subject, self.before()
        with self.assertRaisesRegex(ValueError, "retirement_identity"):
            before._profile(subject.FOURTH_CORRELATION)
        for name, pin in (("intent", subject.FOURTH_INTENT_SHA), ("ready", subject.FOURTH_READY_SHA)):
            self.assertEqual(pin, subject._sha((FIXTURE / ("267-" + name + ".json")).read_bytes()))
        release = self.release()
        self.assertEqual(release, subject._FOURTH_ADMISSION)
        with mock.patch.object(subject, "_FOURTH_ADMISSION", release):
            self.assertEqual((subject.FOURTH_INTENT_SHA, subject.FOURTH_READY_SHA, release["programRecords"]),
                             subject._profile(subject.FOURTH_CORRELATION))
        old = before._third_release()
        self.assertEqual(17, len(release["programRecords"]))
        self.assertEqual(set(old["programRecords"]) | set(self.intake["newSix"]), set(release["programRecords"]))
        for key, value in old["programRecords"].items(): self.assertEqual(value, release["programRecords"][key])
        for key, value in old["proofs"].items(): self.assertEqual(value, release["proofs"][key])
        self.assertEqual(old["baLeafNames"], release["baLeafNames"])
        self.assertEqual(170, len(release["baLeafNames"]))
        self.assertEqual(39, len(release["closedUnknownLeafNames"][subject.FOURTH_UNKNOWN]))
        unknown = json.loads((FIXTURE / "267-closed-unknown-terminal.json").read_bytes())
        self.assertEqual("unknown", unknown["state"]); self.assertIsNone(unknown["capture"])
        closed = json.loads((FIXTURE / "267-closed-unknown-owner-closed.json").read_bytes())
        self.assertTrue(closed["sourceClosing"])
        self.assertEqual(subject._sha((FIXTURE / "267-closed-unknown-terminal.json").read_bytes()), closed["terminalSha256"])
        self.assertTrue(release["facts"]["original4835CaptureIsNull"])
        self.assertEqual("unknown", release["facts"]["original4835State"])
        self.assertTrue(release["facts"]["original4835SourceClosing"])
        self.assertTrue(release["facts"]["automaticHostSourceStaged"])
        self.assertFalse(release["facts"]["originalCallerProgramLoaderSubmitted"])
        self.assertFalse(release["facts"]["guestStateObserved"])

    def test_267_admission_requires_closed_unknown_facts_members_and_pins(self):
        subject = self.subject
        for function in (subject.observe_original, subject.retire_owned):
            with mock.patch.object(subject, "_FOURTH_ADMISSION", None), \
                    mock.patch.object(subject.private, "ownership", side_effect=AssertionError("must not open")):
                with self.assertRaisesRegex(ValueError, "retirement_267_evidence_unavailable"):
                    function(self.root, "archlinux", subject.FOURTH_CORRELATION, str(uuid.uuid4()))
        for key, value in subject._FOURTH_FACTS.items():
            release = self.release(); release["facts"][key] = not value if type(value) is bool else "unreviewed"
            with self.subTest(fact=key), mock.patch.object(subject, "_FOURTH_ADMISSION", release):
                with self.assertRaisesRegex(ValueError, "retirement_267_evidence_unavailable"):
                    subject._fourth_release()
        for mutation in ("missing-program", "extra-program", "old-pin", "new-record-shape", "new-pin", "ba-scope", "unknown-child", "unknown-duplicate", "old-proof", "missing-proof", "proof-path", "proof-hash"):
            release = self.release()
            if mutation == "missing-program": release["programRecords"].pop(subject.FOURTH_UNKNOWN)
            elif mutation == "extra-program": release["programRecords"][str(uuid.uuid4())] = {}
            elif mutation == "old-pin": release["programRecords"][subject.SECOND_UNKNOWN]["terminal.json"] = "0" * 64
            elif mutation == "new-record-shape": release["programRecords"][subject.FOURTH_UNKNOWN]["child.json"] = "0" * 64
            elif mutation == "new-pin": release["programRecords"][subject.FOURTH_UNKNOWN]["terminal.json"] = "INVALID"
            elif mutation == "ba-scope": release["baLeafNames"] = release["baLeafNames"][:-1]
            elif mutation == "unknown-child": release["closedUnknownLeafNames"][subject.FOURTH_UNKNOWN][-1] = "child.json"
            elif mutation == "unknown-duplicate": release["closedUnknownLeafNames"][subject.FOURTH_UNKNOWN][-1] = release["closedUnknownLeafNames"][subject.FOURTH_UNKNOWN][0]
            elif mutation == "old-proof": release["proofs"][next(iter(subject._third_release()["proofs"]))] = "0" * 64
            elif mutation == "missing-proof": release["proofs"].pop(next(iter(release["proofs"])))
            elif mutation == "proof-path": release["proofs"]["/absolute/private.json"] = "0" * 64
            else: release["proofs"][".runtime/inert-invalid.json"] = "INVALID"
            with self.subTest(mutation=mutation), mock.patch.object(subject, "_FOURTH_ADMISSION", release):
                with self.assertRaisesRegex(ValueError, "retirement_267_evidence_(unavailable|identity)"):
                    subject._fourth_release()
        self.assertEqual([], list(self.root.iterdir()))

    def test_whole_267_probe_authentic_before_refuses_current_fixed_peer_green(self):
        subject, before = self.subject, self.before()
        native_case = OwnedChannelRetirementTests("runTest"); native_case.setUp()
        self.addCleanup(native_case.doCleanups)
        execute, exits, _ = native_case._native(subject=subject, correlation=subject.FOURTH_CORRELATION, action="retire")
        context, _, _, _, _, _ = self.publication_context()
        context[3].config.hosts["archlinux"].remote_host_alias = "fixture"
        context = (context[0], {**context[1], "sourceSha256": "a" * 64}, execute.request["ready"], *context[3:])
        packets = []; real_capture = subject._fixed546_capture
        def collect(packet, timeout):
            packets.append(packet)
            self.assertEqual(subject._sha(subject._remote_program(subject.FOURTH_CORRELATION).encode()), packet["programmeSha256"])
            execute.request.update(json.loads(packet["stdin"][4:4 + int.from_bytes(packet["stdin"][:4], "big")]))
            value = execute()
            command = "import sys;sys.stdin.buffer.read();sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))"
            return real_capture([sys.executable, "-I", "-B", "-c", command, subject._json(value).hex()], b"inert", 3)
        with mock.patch.object(before.transport, "connection_host", return_value=object()), \
                mock.patch.object(before.direct, "outer_prefix", return_value=(["ssh-inert-only"], "gateway-inert-only")), \
                mock.patch.object(before.channel, "_collect", side_effect=AssertionError("before must refuse before transport")):
            with self.assertRaisesRegex(ValueError, "retirement_identity"):
                before._probe(context, str(uuid.uuid4()), "retire")
        with mock.patch.object(subject, "_FOURTH_ADMISSION", self.release()), \
                mock.patch.object(subject.transport, "connection_host", return_value=object()), \
                mock.patch.object(subject.direct, "outer_prefix", return_value=(["ssh-inert-only"], "gateway-inert-only")), \
                mock.patch.object(subject, "_fixed546_collect", side_effect=collect), \
                mock.patch.object(subject.channel, "_collect", side_effect=lambda argv, payload, timeout: real_capture(argv, None, timeout, input_allowed=False)):
            result = subject._probe(context, str(uuid.uuid4()), "retire")
        self.assertEqual("ended", result["state"]); self.assertTrue(result["independentAbsence"])
        self.assertEqual(1, len(packets)); self.assertEqual(1, len(exits))
        self.assertEqual(["-O", "exit", "fixture"], exits[0][-3:])
        self.assertEqual("/tmp/vpn-channel-" + subject.FOURTH_CORRELATION + "/m", exits[0][exits[0].index("-S") + 1])
        self.assertEqual(before._publish_ended.__code__.co_code, subject._publish_ended.__code__.co_code)

    def test_267_same_authority_normal_publication_preserves_unknown_and_claim_once(self):
        subject = self.subject
        context, directory, held, ready_held, released, unknown = self.publication_context()
        self.assertEqual(subject.FOURTH_AUTHORITY, context[3].authority_sha)
        originals = {path: path.read_bytes() for path in directory.path.iterdir()}
        unknowns = {path: path.read_bytes() for path in unknown.iterdir()}
        real_session = subject.loader.SourceSession; sessions = []; status_calls = []
        class SessionPeer:
            def __init__(peer, *args, **kwargs):
                peer.actual = real_session(*args, **kwargs); sessions.append(peer.actual)
                owner = peer.actual
                class DirectPeer:
                    def __getattr__(self, name): return getattr(owner.module, name)
                    def status(self, root, host, correlation, *, _private_capture):
                        self_test.assertEqual([True], released)
                        self_test.assertEqual((context[0], "archlinux", subject.FOURTH_CORRELATION), (root, host, correlation))
                        status_calls.append(correlation)
                        channel = owner.load("ssh_fresh_nested_channel")
                        terminal = {"state": "ended", "correlationId": correlation, "receiptSha256": ready_held.digest,
                            "intentSha256": held.digest, "gatewayBoot": context[2]["master"]["gatewayBoot"]}
                        channel.session._create(directory.path / (correlation + ".terminal.json"), terminal, parent_fd=directory.fd)
                        with subject.ExitStack() as stack:
                            admitted = channel._retained_v2_terminal(stack, directory, held, json.loads(held.body), host)
                            self_test.assertIsNotNone(admitted); admitted()
                        _private_capture({"complete": True, "returnCode": 0, "eof": {"stdout": True, "stderr": True}, "stdout": b"", "stderr": b""})
                        return channel._public("ended", correlationId=correlation)
                peer.module = DirectPeer()
            def guard(peer): return peer.actual.guard()
            def close(peer): return peer.actual.close()
            @property
            def cache(peer): return peer.actual.cache
            @property
            def held(peer): return peer.actual.held
        self_test = self
        with mock.patch.object(subject.loader, "SourceSession", SessionPeer), \
                mock.patch.object(subject, "_third_publish_ended", side_effect=AssertionError("267 must use normal publisher")):
            result = subject._publish_ended(context, {"state": "ended", "independentAbsence": True})
        self.assertEqual("ended", result["state"]); self.assertEqual([subject.FOURTH_CORRELATION], status_calls)
        self.assertEqual(1, len(sessions)); self.assertTrue(sessions[0].closed)
        self.assertTrue((context[4].path / "source-view.json").is_file())
        self.assertFalse((context[4].path / "terminal-publication-intent.json").exists())
        for path, raw in {**originals, **unknowns}.items(): self.assertEqual(raw, path.read_bytes())
        terminal = json.loads((directory.path / (subject.FOURTH_CORRELATION + ".terminal.json")).read_bytes())
        self.assertEqual(held.digest, terminal["intentSha256"]); self.assertEqual(ready_held.digest, terminal["receiptSha256"])
        with mock.patch.object(subject, "_FOURTH_ADMISSION", self.release()):
            for index in range(2):
                operation = self.root / str(uuid.uuid4()); operation.mkdir(mode=0o700)
                with subject.private.Directory(operation) as output:
                    if index == 0:
                        with subject._claim_exit(output, operation.name, subject.FOURTH_CORRELATION): pass
                    else:
                        with self.assertRaises(FileExistsError):
                            with subject._claim_exit(output, operation.name, subject.FOURTH_CORRELATION): self.fail("second exit claim")
        claim = json.loads((self.root / (subject.FOURTH_CORRELATION + ".exit-intent.json")).read_bytes())
        self.assertEqual(subject.FOURTH_CORRELATION, claim["correlationId"]); self.assertFalse(claim["replayAllowed"])

    def test_authentic_before_source_view_lacks_readiness_red_and_current_loads(self):
        subject, before = self.subject, self.before()
        canonical = Path(subject.direct.__file__).parent
        capsules = {name: types.SimpleNamespace(body=(canonical / name).read_bytes(), digest=subject._sha((canonical / name).read_bytes()))
                    for name in subject.direct.source_catalog(2)}
        for owner, fixed in ((before, False), (subject, True)):
            path = self.root / ("current" if fixed else "before"); path.mkdir(mode=0o700)
            with subject.private.Directory(path) as output:
                view, expected = owner._source_view(output, capsules)
            if fixed:
                self.assertEqual(subject._sha((canonical / "readiness.py").read_bytes()), expected[str(view / "readiness.py")])
                with closing(subject.loader.SourceSession(view, "ssh_direct_nested_channel", expected_sources=expected)) as session:
                    self.assertIn(str(view / "readiness.py"), [source for source, _ in session.cache.values()])
                    session.guard()
            else:
                with self.assertRaisesRegex(FileNotFoundError, "readiness.py"):
                    subject.loader.SourceSession(view, "ssh_direct_nested_channel", expected_sources=expected)
        for version in (2, 3): self.assertNotIn("readiness.py", subject.direct.source_catalog(version))

    def test_merged_sources_fail_closed_after_exact_v2_admission_and_authentic_before_refuses_earlier(self):
        # Real legacy Guard, inventory lock, journal and capsule snapshots for a
        # version 2 intent. Only inert credentials and relocated source pins are fixtures.
        subject, before = self.subject, self.before()
        canonical = Path(subject.direct.__file__).parent
        before_mcp, retained_mcp = _retained_mcp_pair()
        first = ("", subject.CORRELATION, ("INTENT_SHA", "READY_SHA"))
        second = ("315-", subject.SECOND_CORRELATION, ("SECOND_INTENT_SHA", "SECOND_READY_SHA"))
        def attempt(owner, prefix, correlation, names, reason, capsule, *, catalog=2, legacy=True):
            with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root = Path(temporary); credentials = root / "credentials"; credentials.mkdir(mode=0o700)
                key, trust = credentials / "inert-key", credentials / "known_hosts"
                for path, raw in ((key, b"INERT NONAUTHORITY KEY\n"), (trust, b"INERT TRUST DATA\n")):
                    path.write_bytes(raw); path.chmod(0o600)
                config = root / subject.transport.CONFIG_FILENAME
                config.write_text(json.dumps({"schemaVersion": 1, "hosts": {
                    "gateway": {"host": "gateway.invalid", "port": 22, "user": "fixture", "identityFile": str(key), "knownHostsFile": str(trust)},
                    "archlinux": {"host": "arch.invalid", "port": 22, "user": "fixture", "identityFile": "/inert/nested-key", "knownHostsFile": "/inert/nested-known",
                                  "transport": "nested", "gateway": "gateway", "remoteHostAlias": "archlinux", "remoteConfigFile": "/inert/owned-ssh-config"}}}))
                config.chmod(0o600)
                journal = root / ".rag_index/ssh-direct-nested-channel/hosts/archlinux"; journal.mkdir(mode=0o700, parents=True)
                for path in (root / ".rag_index", journal.parent.parent, journal.parent): path.chmod(0o700)
                def save(name, raw):
                    path = journal / (correlation + "." + name); path.write_bytes(raw); path.chmod(0o600)
                bodies = {name: capsule.get(name, (canonical / name).read_bytes()) for name in subject.direct.source_catalog(catalog)}
                remote = capsule.get("remote", subject.channel._REMOTE.encode())
                intent = json.loads((FIXTURE / (prefix + "intent.json")).read_bytes())
                self.assertEqual(2, intent["version"])
                with subject.direct.Guard(root, "archlinux", legacy=legacy) as guard, subject.private.Directory(root) as base, \
                        subject.private.Snapshot(base, subject.transport.CONFIG_FILENAME) as inventory:
                    intent.update(inventory=inventory.pin(), outerAuthoritySha256=guard.authority_sha, remoteSourceSha256=subject._sha(remote),
                                  sourceSha256=subject._sha(bodies["ssh_fresh_nested_channel.py"]),
                                  directSourcePins={name: subject._sha(body) for name, body in bodies.items()})
                save("intent.json", subject._json(intent))
                with subject.private.Directory(journal) as directory, subject.private.Snapshot(directory, correlation + ".intent.json") as held:
                    digest, pin = held.digest, held.pin()
                ready = subject._json({"intent": pin, "result": json.loads((FIXTURE / (prefix + "ready.json")).read_bytes())["result"]})
                save("ready.json", ready); save("remote.source", remote)
                for name, body in bodies.items(): save(name + ".source", body)
                with mock.patch.multiple(owner, **{names[0]: digest, names[1]: subject._sha(ready)}), \
                        mock.patch.object(owner.channel, "_collect", side_effect=AssertionError("must not start")):
                    with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                        owner.retire_owned(root, "archlinux", correlation, str(uuid.uuid4()))
                self.assertFalse((root / ".rag_index/ssh-owned-channel-retirement").exists())
        # Whole preserved helper: its non-legacy Guard and v3 catalog compare refuse
        # the exact v2 record before reaching any capsule comparison.
        attempt(before, *first, "retirement_authority", {"mcp_server.py": before_mcp})
        attempt(before, *first, "retirement_source_members", {"mcp_server.py": before_mcp}, legacy=False)
        # Current helper admits that v2 record, then merged sources still refuse.
        attempt(subject, *first, "retirement_mcp_source", {"mcp_server.py": before_mcp})
        attempt(subject, *second, "retirement_mcp_source", {"mcp_server.py": retained_mcp})
        attempt(subject, *first, "retirement_executable_source_changed", {"remote": b"# historical capsule stand-in\n", "mcp_server.py": before_mcp})
        attempt(subject, *first, "retirement_source_members", {"mcp_server.py": before_mcp}, catalog=3)


if __name__ == "__main__":
    unittest.main()
