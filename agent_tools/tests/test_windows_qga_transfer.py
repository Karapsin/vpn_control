"""Retained QGA custody with inert peers and real local AF_UNIX poll controls.

Complete live consumer code runs. Historical fragments are authenticated whole
source from actual callers; they are not current-code substitutes. Real sockets
exist only in owned local temporary directories. No VM, SSH, subprocess, guest
task, installer, or remote connection occurs.
"""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import socket
import threading
import struct
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from agent_tools import windows_qga_transfer as current


FIXTURES = Path(__file__).parent / "fixtures" / "windows_qga_transfer"
HISTORICAL_NAMES = ("v5.before.source", "v10.before.source")
PEER = 4242
PREFIX = "transfer-test"
REAL_WRITE = os.write


class ParkObserved(BaseException):
    """External test tracer stops an otherwise intentionally permanent owner."""


class InertSocket:
    def __init__(self):
        self.input = bytearray()
        self.frames = []
        self.recv_calls = 0
        self.closed = False
        self.after_sync = None
        self.after_reply = None
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, path):
        self.path = path

    def getsockopt(self, *_):
        return struct.pack("3i", PEER, os.geteuid(), 0)

    def send(self, data):
        self.frames.append(bytes(data))
        if data.startswith(b"\xff"):
            nonce = json.loads(data[1:])["arguments"]["id"]
            self.input.extend(b"\xff" + json.dumps({"return": nonce}).encode() + b"\n")
        else:
            self.input.extend(b'{"return":{"answer":7}}\n')
        return len(data)

    def recv(self, size):
        self.recv_calls += 1
        if not self.input:
            raise TimeoutError("inert peer has no further bytes")
        data = bytes(self.input[:size]); del self.input[:size]
        callback = self.after_sync if data.startswith(b"\xff") else self.after_reply
        if callback is not None:
            callback()
        return data

    def close(self):
        self.closed = True


class Runtime:
    def __init__(self, version="current"):
        self.version = version
        self.temp = tempfile.TemporaryDirectory(prefix="retained-qga-test-")
        self.root = Path(self.temp.name).resolve()
        self.held = []
        self.socket = InertSocket()
        self.guard_failure = None
        self.saved = []
        self.save_fault = None
        self.guard_calls = 0
        self.stack = contextlib.ExitStack()
        self.wire = self.open_capture("wire")
        self.partial = self.open_capture("partial")
        socket_api = types.SimpleNamespace(AF_UNIX=1, SOCK_STREAM=1, SOL_SOCKET=1, SO_PEERCRED=17,
                                          socket=lambda *_: self.socket)
        self.clock = types.SimpleNamespace(monotonic=time.monotonic, sleep=lambda _: None)
        self.output = io.StringIO()
        self.sys_api = types.SimpleNamespace(stdout=self.output)
        if version in ("current", "canonical-raw-generation.before.source"):
            if version == "current":
                self.module = current
            else:
                data = (FIXTURES / version).read_bytes()
                expected = json.loads((FIXTURES / "provenance.json").read_text())["sources"][version]["sha256"]
                if hashlib.sha256(data).hexdigest() != expected:
                    raise AssertionError("historical source changed")
                self.module = types.ModuleType("_canonical_before_raw_generation")
                self.module.__file__ = str(FIXTURES / version)
                exec(compile(data, self.module.__file__, "exec"), self.module.__dict__)
            for name, value in (("socket", socket_api), ("time", self.clock), ("sys", self.sys_api)):
                self.stack.enter_context(mock.patch.object(self.module, name, value))
            self.owner = self.module.RetainedQgaOwner(self.root, PREFIX, PEER, self.guard, self.save,
                                                  self.held, self.wire, self.partial)
        else:
            if version not in HISTORICAL_NAMES:
                raise ValueError("finite historical source")
            data = (FIXTURES / version).read_bytes()
            expected = json.loads((FIXTURES / "provenance.json").read_text())["sources"][version]["sha256"]
            if hashlib.sha256(data).hexdigest() != expected:
                raise AssertionError("historical source changed")
            self.ns = {"__name__": "_historical_retained_qga", "__file__": str(FIXTURES / version),
                       "os": os, "sys": self.sys_api, "time": self.clock, "json": json,
                       "hashlib": hashlib, "socket": socket_api, "struct": struct, "secrets": secrets,
                       "root": self.root, "prefix": PREFIX, "held": self.held,
                       "wire": self.wire, "partial_wire": self.partial, "QGA_PEER_PID": PEER,
                       "QGA_GUARD": self.guard, "save": self.save, "require": current._require,
                       "generation": current._generation, "held_hash": current._held_hash,
                       "ARTIFACT": {"transferId": "inert-transfer"}}
            exec(compile(data, self.ns["__file__"], "exec"), self.ns)
            self.ns["HOST_ADMITTED"] = True

    def open_capture(self, name):
        fd = os.open(self.root / name, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.held.append(fd)
        return fd

    def guard(self):
        self.guard_calls += 1
        if self.guard_failure is not None:
            raise self.guard_failure

    def save(self, name, value):
        if self.save_fault is not None:
            self.save_fault(name, value)
        data = value if type(value) is bytes else (json.dumps(value, sort_keys=True) + "\n").encode()
        fd = os.open(self.root / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            offset = 0
            while offset < len(data):
                count = REAL_WRITE(fd, data[offset:])
                if count <= 0:
                    raise AssertionError("test fixture write failed")
                offset += count
        finally:
            os.close(fd)
        self.saved.append(name)

    def new_rpc(self):
        if hasattr(self, "owner"):
            rpc = self.module.RetainedRpc(self.owner, "guest-file-write", {"handle": 8}, time.monotonic() + 20, 1)
            self.owner.current = rpc
        else:
            rpc = self.ns["RetainedRpc"]("guest-file-write", {"handle": 8}, time.monotonic() + 20, 1)
            self.ns["CURRENT_RPC"] = rpc
        rpc.open()
        return rpc

    @property
    def rpc(self):
        return self.owner.current if hasattr(self, "owner") else self.ns["CURRENT_RPC"]

    def call(self):
        if hasattr(self, "owner"):
            return self.owner.call("guest-file-write", {"handle": 8}, time.monotonic() + 20)
        return self.ns["retained_call"]("guest-file-write", {"handle": 8}, time.monotonic() + 20)

    def park(self):
        fn = self.owner.park_original if hasattr(self, "owner") else self.ns["park_original"]
        # A tracing exception is an explicit external test stop after three loop
        # entries, not a fake sleep failure that production is meant to retain.
        tree = ast.parse(Path(fn.__code__.co_filename).read_text())
        loop = next(node for node in ast.walk(tree) if isinstance(node, ast.While)
                    and fn.__code__.co_firstlineno < node.lineno
                    and any(isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and parent.name == "park_original" and node in list(ast.walk(parent))
                            for parent in ast.walk(tree)))
        turns = 0
        previous = sys.gettrace()
        def trace(frame, event, arg):
            nonlocal turns
            if frame.f_code is fn.__code__ and event == "line" and frame.f_lineno == loop.lineno:
                turns += 1
                if turns == 4:
                    raise ParkObserved()
            return trace
        try:
            sys.settrace(trace)
            with contextlib.redirect_stdout(self.sys_api.stdout):
                fn({}, RuntimeError("original unknown"))
        finally:
            sys.settrace(previous)

    def bytes(self, fd):
        os.lseek(fd, 0, os.SEEK_SET)
        return os.read(fd, 1024 * 1024)

    def close(self):
        self.stack.close()
        for fd in list(self.held):
            try: os.close(fd)
            except OSError: pass
        self.held.clear()
        self.temp.cleanup()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires POSIX retained QGA descriptors")
class WindowsQgaTransferTest(unittest.TestCase):
    def assert_short_capture_complete(self, version):
        with Runtime(version) as runtime:
            with mock.patch.object(os, "write", side_effect=lambda fd, data: REAL_WRITE(fd, data[:7])):
                self.assertEqual(runtime.call(), {"answer": 7})
            rpc = runtime.rpc
            self.assertEqual(runtime.bytes(runtime.partial), bytes(rpc.raw), "shared partial wire lost bytes")
            self.assertEqual(runtime.bytes(runtime.wire), b'{"return":{"answer":7}}\n', "parsed wire lost bytes")
            self.assertFalse(runtime.socket.closed)

    def test_partial_capture_writes_preserve_every_byte_red_green(self):
        with self.assertRaisesRegex(AssertionError, "lost bytes"):
            self.assert_short_capture_complete("v5.before.source")
        self.assert_short_capture_complete("current")

    def assert_reply_bound_latches(self, version):
        with Runtime(version) as runtime:
            rpc = runtime.new_rpc()
            runtime.socket.input.extend(b"x" * (262144 + 8192))
            with self.assertRaises(ValueError): rpc.receive_reply(time.monotonic() + 20)
            rpc.unknown = True; rpc.command_sent = True
            reads = runtime.socket.recv_calls
            for _ in range(3): rpc.observe_same_wire(time.monotonic() + 1)
            self.assertEqual(runtime.socket.recv_calls, reads, "unknown observation read beyond refused bound")
            self.assertLessEqual(len(rpc.raw), 262145)
            self.assertEqual(runtime.bytes(rpc.raw_fd), bytes(rpc.raw))
            self.assertIs(runtime.rpc, rpc)
            self.assertFalse(runtime.socket.closed)

    def test_response_cap_retains_offending_byte_and_never_reads_more_red_green(self):
        with self.assertRaisesRegex(AssertionError, "beyond refused bound"):
            self.assert_reply_bound_latches("v5.before.source")
        self.assert_reply_bound_latches("current")

    def assert_original_reply_cursor(self, version, fault):
        with Runtime(version) as runtime:
            rpc = runtime.new_rpc()
            first = b"not-json\n" if fault == "parse" else b'{"return":{"original":true}}\n'
            second = b'{"return":{"wrong-next-line":true}}\n'
            runtime.socket.input.extend(first + second)
            original_fsync = os.fsync
            def fsync(fd):
                if fault == "wire-sync" and fd == runtime.wire: raise OSError("capture fsync failed")
                return original_fsync(fd)
            with mock.patch.object(os, "fsync", side_effect=fsync):
                with self.assertRaises((ValueError, OSError)): rpc.receive_reply(time.monotonic() + 20)
            rpc.unknown = True; rpc.command_sent = True
            reads = runtime.socket.recv_calls
            rpc.observe_same_wire(time.monotonic() + 1)
            self.assertIsNone(rpc.response, "next line replaced the original unclassified reply")
            self.assertEqual(bytes(rpc.buffer), second)
            self.assertEqual(runtime.socket.recv_calls, reads)
            self.assertEqual(rpc.pending_reply, first)
            self.assertFalse(runtime.socket.closed)

    def test_parse_and_capture_failure_never_promote_next_reply_red_green(self):
        for fault in ("parse", "wire-sync"):
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(AssertionError, "replaced the original"):
                    self.assert_original_reply_cursor("v10.before.source", fault)
                self.assert_original_reply_cursor("current", fault)

    def assert_park_retains(self, version, fault):
        with Runtime(version) as runtime:
            rpc = runtime.new_rpc(); rpc.unknown = True; rpc.command_sent = True
            rpc.read_refused = True
            if fault == "journal":
                runtime.save_fault = lambda *_: (_ for _ in ()).throw(FileExistsError("create-only late journal"))
            elif fault == "stdout":
                runtime.sys_api.stdout = mock.Mock(write=mock.Mock(side_effect=BrokenPipeError("closed stdout")))
            elif fault == "fingerprint":
                rpc.response = {"return": {"not-json-serializable"}}
            frames = list(runtime.socket.frames)
            with self.assertRaises(ParkObserved): runtime.park()
            self.assertIs(runtime.rpc, rpc)
            self.assertEqual(runtime.socket.frames, frames)
            self.assertFalse(runtime.socket.closed)
            for fd in runtime.held: os.fstat(fd)

    def test_journal_collision_and_broken_stdout_do_not_unwind_owner_red_green(self):
        for fault, error in (("journal", FileExistsError), ("stdout", BrokenPipeError)):
            with self.subTest(fault=fault):
                with self.assertRaises(error): self.assert_park_retains("v5.before.source", fault)
                self.assert_park_retains("current", fault)

    def test_report_preparation_failure_does_not_unwind_owner_red_green(self):
        with self.assertRaises(TypeError): self.assert_park_retains("v10.before.source", "fingerprint")
        self.assert_park_retains("current", "fingerprint")

    def assert_guard_after_sync(self, version):
        with Runtime(version) as runtime:
            runtime.socket.after_sync = lambda: setattr(runtime, "guard_failure", ValueError("source changed after sync"))
            try: runtime.call()
            except ValueError: pass
            self.assertEqual(len(runtime.socket.frames), 1, "mutation sent after guard changed during sync")
            self.assertTrue(runtime.rpc.unknown)
            self.assertFalse(runtime.socket.closed)

    def test_recheck_guard_after_sync_before_command_red_green(self):
        with self.assertRaisesRegex(AssertionError, "mutation sent"):
            self.assert_guard_after_sync("v10.before.source")
        self.assert_guard_after_sync("current")

    def assert_guard_after_late(self, version):
        with Runtime(version) as runtime:
            rpc = runtime.new_rpc(); rpc.unknown = True; rpc.command_sent = True
            runtime.socket.input.extend(b'{"return":{"late":true}}\n')
            runtime.socket.after_reply = lambda: setattr(runtime, "guard_failure", ValueError("source changed during reply"))
            with self.assertRaisesRegex(ValueError, "source changed during reply"):
                rpc.observe_same_wire(time.monotonic() + 1)
            self.assertFalse(runtime.socket.closed)
            self.assertEqual(runtime.socket.frames, [])

    def test_recheck_guard_after_late_observation_red_green(self):
        with self.assertRaises(AssertionError): self.assert_guard_after_late("v10.before.source")
        self.assert_guard_after_late("current")

    def assert_close_retains_changed(self, version, fault):
        with Runtime(version) as runtime:
            runtime.call(); rpc = runtime.rpc
            def change():
                if fault == "guard": runtime.guard_failure = ValueError("source changed during known publication")
                else:
                    path = runtime.root / rpc.raw_name
                    path.rename(path.with_suffix(".original"))
                    path.write_bytes(bytes(rpc.raw))
            if fault == "named": change()
            else:
                runtime.save_fault = lambda name, _: change() if name.endswith(".known.json") else None
            with self.assertRaises(ValueError): rpc.close_known()
            self.assertFalse(runtime.socket.closed)
            self.assertFalse(rpc.closed)
            os.fstat(rpc.raw_fd); os.fstat(rpc.request_fd)

    def test_named_raw_generation_and_post_publication_guard_red_green(self):
        for fault in ("named", "guard", "closing-named"):
            with self.subTest(fault=fault):
                with self.assertRaises(AssertionError): self.assert_close_retains_changed("v10.before.source", fault)
                self.assert_close_retains_changed("current", fault)

    def assert_same_inode_capture_drift_retains(self, version):
        with Runtime(version) as runtime:
            runtime.call(); rpc = runtime.rpc
            identity = os.fstat(rpc.raw_fd).st_ino
            def mutate(name, _):
                if name.endswith(".known.json"):
                    with (runtime.root / rpc.raw_name).open("r+b") as stream:
                        stream.write(b"!" * len(rpc.raw)); stream.flush(); os.fsync(stream.fileno())
            runtime.save_fault = mutate
            with self.assertRaises(ValueError): rpc.close_known()
            self.assertEqual(os.fstat(rpc.raw_fd).st_ino, identity)
            self.assertFalse(runtime.socket.closed)
            self.assertFalse(rpc.closed)

    def test_same_inode_raw_drift_after_hash_never_releases_owner_red_green(self):
        with self.assertRaises(AssertionError):
            self.assert_same_inode_capture_drift_retains("canonical-raw-generation.before.source")
        self.assert_same_inode_capture_drift_retains("current")

    def test_known_success_closes_only_after_full_capture_and_source_checks(self):
        with Runtime() as runtime:
            self.assertEqual(runtime.call(), {"answer": 7})
            rpc = runtime.rpc
            runtime.owner.finalize_known()
            self.assertTrue(rpc.closed)
            self.assertTrue(runtime.socket.closed)
            self.assertTrue(runtime.owner.finalized)
            self.assertNotIn(rpc.raw_fd, runtime.held)
            self.assertNotIn(rpc.request_fd, runtime.held)
            self.assertTrue(any(name.endswith(".known.json") for name in runtime.saved))

    def test_original_object_exists_before_first_journal_failure_and_no_replay(self):
        with Runtime() as runtime:
            runtime.save_fault = lambda *_: (_ for _ in ()).throw(OSError("first journal failed"))
            with self.assertRaisesRegex(OSError, "first journal failed"): runtime.call()
            original = runtime.rpc
            self.assertIsNotNone(original)
            self.assertTrue(original.unknown)
            self.assertEqual(runtime.socket.frames, [])
            with self.assertRaisesRegex(ValueError, "retained_qga_call_state"): runtime.call()
            self.assertIs(runtime.rpc, original)
            self.assertEqual(runtime.socket.frames, [])

    def test_unadmitted_journal_refuses_before_file_effect_and_bind_once(self):
        with Runtime() as runtime:
            runtime.guard_failure = ValueError("host root not admitted")
            self.assertFalse(runtime.owner.safe_journal(PREFIX + ".unknown.json", {"state": "pending"}))
            self.assertEqual(runtime.saved, [])
            self.assertEqual(runtime.socket.frames, [])
            owner = current.RetainedQgaOwner(runtime.root, PREFIX, PEER, runtime.guard, runtime.save, [], -1, -1)
            self.assertFalse(owner.captures_bound)
            owner.bind_captures(runtime.wire, runtime.partial, guard=runtime.guard)
            with self.assertRaisesRegex(ValueError, "capture_rebind"):
                owner.bind_captures(runtime.wire, runtime.partial, guard=runtime.guard)

    def assert_zero_write_refuses(self, historical=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            if historical:
                data = (FIXTURES / "journal.before.source").read_bytes()
                expected = json.loads((FIXTURES / "provenance.json").read_text())["sources"]["journal.before.source"]["sha256"]
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
                namespace = {"os": os, "json": json, "root": root}
                exec(compile(data, str(FIXTURES / "journal.before.source"), "exec"), namespace)
                invoke = lambda: namespace["save"]("owned.json", {"state": "pending"})
            else:
                invoke = lambda: current.write_journal(root, "owned.json", {"state": "pending"}, guard=lambda: None)
            with mock.patch.object(os, "write", side_effect=[0, RuntimeError("zero write was retried")]) as writer:
                with self.assertRaisesRegex(ValueError, "retained_rpc_capture_write"):
                    invoke()
            self.assertEqual(writer.call_count, 1)
            self.assertEqual((root / "owned.json").read_bytes(), b"")

    def test_zero_write_journal_refuses_instead_of_spinning_red_green(self):
        with self.assertRaisesRegex(RuntimeError, "zero write was retried"):
            self.assert_zero_write_refuses(historical=True)
        self.assert_zero_write_refuses()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "requires inert POSIX caller peers")
class WindowsQgaFactoryCallerTest(unittest.TestCase):
    def fixture(self, name):
        allowed = ("caller-args.before.source", "caller-global.before.source", "namespace-prelude.input.source",
                   "operation-body.input.source", "whole-caller-peer.source", "whole-protocol-peer.source",
                   "native-source-receipt.json")
        if name not in allowed:
            raise ValueError("finite caller fixture")
        data = (FIXTURES / name).read_bytes()
        row = json.loads((FIXTURES / "provenance.json").read_text())["sources"][name]
        self.assertEqual(hashlib.sha256(data).hexdigest(), row["sha256"])
        return data

    @contextlib.contextmanager
    def peers(self):
        with tempfile.TemporaryDirectory(prefix="whole-qga-caller-test-") as temp:
            folder = Path(temp)
            old = folder / "inert-caller-qualification"; old.mkdir()
            recent = folder / "qga-transfer-preparation"; recent.mkdir()
            native = recent / "native-source-sddl-causal-fixture"; native.mkdir()
            (old / "harness.py").write_bytes(self.fixture("whole-caller-peer.source"))
            (recent / "qualify_protocol.py").write_bytes(self.fixture("whole-protocol-peer.source"))
            (native / "native-owner-probe-gates-receipt.json").write_bytes(self.fixture("native-source-receipt.json"))
            prior_path = tuple(sys.path)
            prior_modules = dict(sys.modules)
            try:
                sys.modules.pop("harness", None)
                module = types.ModuleType("_whole_qga_protocol_peer")
                module.__file__ = str(recent / "qualify_protocol.py")
                exec(compile((recent / "qualify_protocol.py").read_bytes(), module.__file__, "exec"), module.__dict__)
                yield folder, sys.modules["harness"], module
            finally:
                sys.path[:] = prior_path
                for name in tuple(sys.modules):
                    if name == "harness" or name.startswith("_vpn_control_windows_qga_") or name.startswith("_vpn_control_windows_artifact_transfer_"):
                        if name in prior_modules: sys.modules[name] = prior_modules[name]
                        else: sys.modules.pop(name, None)

    def test_authentic_missing_rpc_args_is_red_before_any_guest_exec(self):
        with self.peers() as (folder, harness, _):
            path = folder / "original-args.py"; path.write_bytes(self.fixture("caller-args.before.source"))
            result = harness.qualify(path, harness.default_guest_results(path), 0, label="authentic-args-red")
            self.assertEqual(result["error"]["class"], "TypeError")
            self.assertIn("missing 1 required positional argument: 'args'", result["error"]["message"])
            self.assertFalse(any(row["command"] == "guest-exec" for row in result["rpc"]))

    def test_authentic_undefined_initialize_is_red_before_any_guest_exec(self):
        with self.peers() as (folder, harness, _):
            path = folder / "original-global.py"; path.write_bytes(self.fixture("caller-global.before.source"))
            result = harness.qualify(path, harness.default_guest_results(path), 0, label="authentic-global-red")
            self.assertEqual(result["error"]["class"], "NameError")
            self.assertIn("INITIALIZE_SCRIPT", result["error"]["message"])
            self.assertFalse(any(row["command"] == "guest-exec" for row in result["rpc"]))

    def test_actual_factory_complete_python_c_caller_green_with_current_module_and_source(self):
        from agent_tools import windows_artifact_transfer
        prelude = self.fixture("namespace-prelude.input.source").decode()
        body = self.fixture("operation-body.input.source").decode()
        module_bytes = Path(current.__file__).read_bytes()
        original_modules = {name for name in sys.modules if name.startswith(("_vpn_control_windows_qga_", "_vpn_control_windows_artifact_transfer_"))}
        with self.peers() as (folder, harness, peer):
            declarations = harness.literals(prelude)
            # The saved input is an authentic builder input, not an alternate
            # current module. Stale consumed producer bytes refuse qualification.
            self.assertEqual(declarations["EMITTER_SOURCE"], Path(windows_artifact_transfer.__file__).read_bytes())
            caller = current.render_consumer_caller(module_bytes, prelude, body)
            path = folder / "current-factory-caller.py"; path.write_text(caller)
            case = folder / "case"; case.mkdir()
            world = peer.ProtocolWorld(harness.literals(caller), case, "python-c", seed_endpoint_receipt=False)
            try:
                result = peer.execute(path, world, "current-factory-green")
                self.assertIsNone(result["error"])
                self.assertTrue(result["canonicalQgaRegistered"])
                self.assertTrue(result["canonicalModuleRegistered"])
                self.assertTrue(result["pythonCWithoutFile"])
                self.assertEqual(result["initialGlobals"], ["__name__", "__builtins__"])
                self.assertTrue(result["fullSharedWireCaptureVerified"])
                self.assertEqual(result["canonicalQgaRecord"]["sha256"], hashlib.sha256(module_bytes).hexdigest())
                commands = [row["command"] for row in result["rpc"]]
                for command in ("guest-ping", "guest-get-osinfo", "guest-get-users", "guest-exec", "guest-exec-status"):
                    self.assertIn(command, commands)
                self.assertEqual(result["writes"], 0)
                self.assertEqual(result["closes"], 0)
                self.assertFalse(result["realGuestOrNetworkOperations"])
            finally:
                world.harness_cleanup()
        self.assertEqual({name for name in sys.modules if name.startswith(("_vpn_control_windows_qga_", "_vpn_control_windows_artifact_transfer_"))}, original_modules)


# These controls use real local AF_UNIX I/O; no VM or native QGA is contacted.
_POLL_CASE_RECORDS = []
_POLL_PRELUDE = '''import os,stat,time,hashlib
from pathlib import Path
root=TEST_ROOT
prefix='poll-proof'
held=[]
def require(condition,message):
 if not condition:raise ValueError(message)
def structure(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
parentfd=os.open(root.parent,os.O_RDONLY|os.O_DIRECTORY)
parents=[(rootfd,parentfd,root.name,structure(os.fstat(rootfd)))]
def instance_intent():require(structure(os.fstat(rootfd))==parents[0][3],'local_test_root_changed')
def read(name):
 require(name=='qemu-started.json','declared_local_peer_record');return {'pid':os.getpid()}
def process(row):require(row=={'pid':os.getpid()},'declared_local_peer_pid')
def owns(pid,path,listener):require(pid==os.getpid() and listener and stat.S_ISSOCK(os.lstat(path).st_mode),'real_local_peer_socket')
def closing():instance_intent()
'''
_POLL_BODY = '''HOST_ADMITTED=True
initialize_qga_owner(os.getpid())
QGA_MODULE.socket=SOCKET_BOUNDARY.api()
setup_qga_owner()
RESULT=None
ERROR=None
try:RESULT=retained_call('guest-exec-status',{'pid':4120},ADMITTED_DEADLINE)
except BaseException as error:ERROR=error
'''


class _RealPollPeer:
    def __init__(self, root, mode):
        self.mode = mode
        self.frames = []
        self.error = None
        self.stop = threading.Event()
        self.release = threading.Event()
        self.sync_sent = threading.Event()
        self.command_sent = threading.Event()
        self.timeouts = {name: threading.Event() for name in ('sync', 'reply')}
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(root / 'qga.sock'))
        self.listener.listen(1)
        self.listener.settimeout(30)
        self.thread = threading.Thread(target=self.run, name='local-qga-poll-peer')
        self.thread.start()

    def line(self, client):
        data = bytearray()
        while b'\n' not in data:
            block = client.recv(4096)
            if not block:
                return None
            data.extend(block)
        assert data.count(b'\n') == 1 and data.endswith(b'\n')
        self.frames.append(bytes(data))
        return bytes(data)

    def run(self):
        try:
            client, _ = self.listener.accept()
            with client:
                client.settimeout(30)
                sync = self.line(client)
                assert sync.startswith(b'\xff')
                nonce = json.loads(sync[1:])['arguments']['id']
                if self.mode == 'eof':
                    return
                # The peer waits for the actual original recv timeout. This
                # guarantees a >1s delayed SYNC/reply without tight wall-clock
                # upper assertions or synthetic receive results.
                gate = self.release if self.mode == 'expiry' else self.timeouts['sync']
                assert gate.wait(30), 'local peer timeout gate not reached'
                if self.stop.is_set():
                    return
                client.sendall(b'\xff' + json.dumps({'return': nonce}).encode() + b'\n')
                self.sync_sent.set()
                assert self.command_sent.wait(30), 'local command observation not reached'
                if self.stop.is_set():
                    return
                command = self.line(client)
                assert self.mode != 'expiry', 'command sent after original expiry'
                assert json.loads(command) == {'execute': 'guest-exec-status', 'arguments': {'pid': 4120}}
                assert self.timeouts['reply'].wait(30), 'local reply timeout gate not reached'
                if not self.stop.is_set():
                    client.sendall(b'{"return":{"exited":true,"exitcode":0}}\n')
        except BaseException as error:
            self.error = error
        finally:
            self.listener.close()

    def finish(self):
        self.stop.set()
        self.release.set()
        self.command_sent.set()
        for event in self.timeouts.values():
            event.set()
        self.thread.join(35)
        assert not self.thread.is_alive(), 'local peer still pending'
        assert self.error is None, repr(self.error)


class _RealPollBoundary:
    """Observe real I/O; only Darwin SO_PEERCRED metadata is a declared seam."""
    def __init__(self, peer):
        self.peer = peer
        self.connects = 0
        self.instances = []
        self.sent = []

    def socket(self, *args):
        raw = socket.socket(*args)
        outer = self
        class Original:
            phase = 'sync'
            def settimeout(self, value): return raw.settimeout(value)
            def connect(self, path):
                outer.connects += 1
                return raw.connect(path)
            def getsockopt(self, *values):
                if sys.platform == 'darwin':
                    return struct.pack('3i', os.getpid(), os.geteuid(), os.getegid())
                return raw.getsockopt(*values)
            def send(self, data):
                self.phase = 'sync' if data.startswith(b'\xff') else 'reply'
                count = raw.send(data)
                outer.sent.append(bytes(data[:count]))
                if self.phase == 'reply':
                    outer.peer.command_sent.set()
                return count
            def recv(self, size):
                try:
                    return raw.recv(size)
                except TimeoutError:
                    outer.peer.timeouts[self.phase].set()
                    raise
            def close(self): return raw.close()
        result = Original()
        self.instances.append(result)
        return result

    def api(self):
        return types.SimpleNamespace(AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM,
                                     SOL_SOCKET=socket.SOL_SOCKET,
                                     SO_PEERCRED=getattr(socket, 'SO_PEERCRED', 17), socket=self.socket)


@unittest.skipUnless(sys.platform in ('darwin', 'linux') and hasattr(socket, 'AF_UNIX'),
                     'requires local POSIX AF_UNIX sockets')
class WindowsQgaRealPollTest(unittest.TestCase):
    @contextlib.contextmanager
    def case(self, version, mode):
        if version == 'before':
            path = FIXTURES / 'recv-poll.before.source'
            source = path.read_bytes()
            provenance = json.loads((FIXTURES / 'recv-poll.provenance.json').read_text())
            self.assertEqual(provenance['sourceSha256'], '028dacbb4ef679270c10b77a272c687c780fb43c9277a033411b098836b351bb')
            self.assertEqual(hashlib.sha256(source).hexdigest(), provenance['sourceSha256'])
        else:
            self.assertEqual(version, 'current')
            path = Path(current.__file__)
            source = path.read_bytes()
        factory = types.ModuleType('_poll_factory_' + version)
        factory.__file__ = str(path)
        exec(compile(source, str(path), 'exec'), factory.__dict__)
        with tempfile.TemporaryDirectory(prefix='qgap-', dir='/tmp') as folder:
            root = Path(folder).resolve()
            root.chmod(0o700)
            peer = _RealPollPeer(root, mode)
            boundary = _RealPollBoundary(peer)
            ns = {'__name__': '_complete_poll_factory_consumer', 'TEST_ROOT': root,
                  'SOCKET_BOUNDARY': boundary,
                  'ADMITTED_DEADLINE': time.monotonic() + (.2 if mode == 'expiry' else 15)}
            try:
                caller = factory.render_consumer_caller(source, _POLL_PRELUDE, _POLL_BODY)
                exec(compile(caller, '<complete-qga-poll-factory-caller>', 'exec'), ns)
                owner = ns['QGA_OWNER']
                rpc = owner.current
                initial = rpc.snapshot()
                if mode == 'expiry':
                    peer.release.set()
                if ns['ERROR'] is not None and mode != 'eof':
                    self.assertTrue(peer.sync_sent.wait(30))
                    rpc.observe_same_wire(time.monotonic() + 5)
                row = {'version': version, 'mode': mode,
                       'sourceSha256': hashlib.sha256(source).hexdigest(),
                       'callerSha256': hashlib.sha256(caller.encode()).hexdigest(),
                       'initial': initial, 'late': rpc.snapshot(),
                       'registered': ns['QGA_MODULE_RECORD'], 'connections': boundary.connects,
                       'socketInstances': len(boundary.instances)}
                _POLL_CASE_RECORDS.append(row)
                yield ns, row, peer, boundary
            finally:
                peer.finish()
                # Disposal belongs only to this known-terminal local test peer.
                # Production custody is asserted before these test-only closes.
                owner = ns.get('QGA_OWNER')
                if owner is not None:
                    rpc = owner.current
                    if rpc is not None and rpc.client is not None and not rpc.closed:
                        rpc.client.close()
                    for fd in set(owner.held_fds + [owner.wire_fd, owner.partial_wire_fd,
                                                   ns['rootfd'], ns['parentfd']]):
                        try: os.close(fd)
                        except OSError: pass
                    sys.modules.pop(ns['QGA_MODULE'].__name__, None)

    def assert_success(self, ns, row, peer, boundary):
        self.assertIsNone(ns['ERROR'])
        self.assertEqual(ns['RESULT'], {'exited': True, 'exitcode': 0})
        self.assertEqual([json.loads(frame.lstrip(b'\xff'))['execute'] for frame in peer.frames],
                         ['guest-sync-delimited', 'guest-exec-status'])
        self.assertEqual(len(boundary.sent), 2)
        self.assertEqual(row['connections'], 1)
        self.assertEqual(row['socketInstances'], 1)
        self.assertTrue(row['registered']['registered'])
        self.assertTrue(row['registered']['completeNamespaceExecuted'])
        self.assertEqual(row['registered']['sha256'], row['sourceSha256'])
        ns['QGA_OWNER'].finalize_known()
        self.assertTrue(ns['QGA_OWNER'].finalized)

    def test_actual_before_red_current_green_with_real_delayed_sync_and_reply(self):
        with self.case('before', 'delayed') as (ns, row, peer, boundary):
            with self.assertRaises(AssertionError):
                self.assert_success(ns, row, peer, boundary)
            self.assertIsInstance(ns['ERROR'], TimeoutError)
            self.assertEqual(len(boundary.sent), 1)
            self.assertFalse(row['initial']['syncKnown'])
            self.assertTrue(row['late']['syncKnown'])
            self.assertFalse(row['late']['commandSent'])
            self.assertTrue(row['late']['unknown'])
            self.assertTrue(row['late']['originalSocketRetained'])
        with self.case('current', 'delayed') as (ns, row, peer, boundary):
            self.assert_success(ns, row, peer, boundary)
            timing = row['initial']['timing']
            self.assertGreaterEqual(timing['readTimeoutPolls'], 2)
            self.assertGreaterEqual(timing['elapsedSeconds'], 2)
            self.assertEqual({entry['phase'] for entry in timing['readTimeoutTrace']},
                             {'sync-waiting', 'command-waiting'})
            self.assertLessEqual(len(timing['readTimeoutTrace']), 16)

    def test_absolute_expiry_stays_unknown_and_late_sync_cannot_resume_or_retry(self):
        with self.case('current', 'expiry') as (ns, row, peer, boundary):
            self.assertIsInstance(ns['ERROR'], ValueError)
            self.assertEqual(str(ns['ERROR']), 'retained_rpc_deadline')
            self.assertEqual(row['initial']['timing']['deadlineMonotonic'], ns['ADMITTED_DEADLINE'])
            self.assertEqual(row['initial']['timing'], row['late']['timing'])
            self.assertTrue(row['late']['unknown'])
            self.assertTrue(row['late']['syncKnown'])
            self.assertFalse(row['late']['commandSent'])
            self.assertTrue(row['late']['originalSocketRetained'])
            self.assertFalse(row['late']['closed'])
            self.assertEqual((row['connections'], row['socketInstances'], len(boundary.sent)), (1, 1, 1))
            with self.assertRaisesRegex(ValueError, 'retained_qga_call_state'):
                ns['QGA_OWNER'].call('guest-exec-status', {'pid': 4120}, time.monotonic() + 20)
            with self.assertRaisesRegex(ValueError, 'retained_qga_finalize_state'):
                ns['QGA_OWNER'].finalize_known()
            self.assertEqual(len(boundary.sent), 1)
            self.assertEqual(boundary.connects, 1)

    def test_eof_preserves_immediate_failure_without_timeout_poll_or_command(self):
        for version in ('before', 'current'):
            with self.subTest(version=version), self.case(version, 'eof') as (ns, row, peer, boundary):
                self.assertIsInstance(ns['ERROR'], ConnectionError)
                self.assertEqual(str(ns['ERROR']), 'retained_rpc_original_wire_eof')
                self.assertTrue(row['initial']['wireEof'])
                if version == 'current':
                    self.assertEqual(row['initial']['timing']['readTimeoutPolls'], 0)
                self.assertFalse(row['initial']['commandSent'])
                self.assertTrue(row['initial']['unknown'])
                self.assertEqual((row['connections'], row['socketInstances'], len(boundary.sent)), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
