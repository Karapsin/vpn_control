"""Real TCP RFB callers; no Tart, account credential or VM side effects."""
import contextlib
import io
import json
import logging
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from uuid import uuid4

from agent_tools import readiness_tart_vnc as subject


class PortableImportTests(unittest.TestCase):
    def run_import(self, path=None, *, missing="fcntl"):
        root = Path(__file__).resolve().parents[2]
        code = '''import builtins,importlib.util,json,sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from unittest import mock
sys.path.insert(0,ROOT)
original=builtins.__import__
def blocked(name,*args,**kwargs):
 if name==MISSING or name.startswith(MISSING+'.'):raise ImportError('controlled missing optional dependency')
 return original(name,*args,**kwargs)
builtins.__import__=blocked
if SOURCE is None:
 from agent_tools import readiness_tart_vnc as module
else:
 loader=SourceFileLoader('agent_tools._rfb_portability_before',SOURCE)
 spec=importlib.util.spec_from_loader(loader.name,loader)
 module=importlib.util.module_from_spec(spec);sys.modules[loader.name]=module;loader.exec_module(module)
with mock.patch('socket.create_connection',side_effect=AssertionError('no network')),mock.patch('os.dup',side_effect=AssertionError('no credential read')):
 try:
  with module.ProtectedVncSession(port=5901,credential_fd=9,guard=lambda:None):pass
 except module.VncBlocked as error:reason=str(error)
 else:raise AssertionError('unsupported dependency admitted')
print(json.dumps({'imported':True,'reason':reason},sort_keys=True))
'''
        code = "ROOT=" + repr(str(root)) + "\nSOURCE=" + repr(str(path) if path else None) + "\nMISSING=" + repr(missing) + "\n" + code
        return subprocess.run([sys.executable, "-I", "-B", "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, timeout=10)

    def test_complete_module_import_without_fcntl_actual_before_red_current_green(self):
        before = Path(__file__).parent / "fixtures/tart_vnc_portability.before.source"
        import hashlib
        self.assertEqual("5ca7d9313866a25ab9dd1b22841c38bc5c1d6a6d2270f13b65d81f3b1ff04e16", hashlib.sha256(before.read_bytes()).hexdigest())
        red = self.run_import(before)
        self.assertNotEqual(0, red.returncode)
        self.assertIn("ImportError", red.stderr)
        green = self.run_import()
        self.assertEqual(0, green.returncode, green.stderr)
        self.assertEqual({"imported": True, "reason": "vnc_platform_unsupported"}, json.loads(green.stdout))
        self.assertEqual("", green.stderr)

    def test_missing_decrepit_dependency_is_finite_before_credential_or_network(self):
        result = self.run_import(missing="cryptography")
        self.assertEqual(0, result.returncode, result.stderr)
        expected = "vnc_auth_dependency_unavailable" if os.name == "posix" else "vnc_platform_unsupported"
        self.assertEqual({"imported": True, "reason": expected}, json.loads(result.stdout))
        self.assertEqual("", result.stderr)


def read(sock, size):
    result = bytearray()
    while len(result) < size:
        block = sock.recv(size - len(result))
        if not block:
            raise EOFError()
        result.extend(block)
    return bytes(result)


class RfbEndpoint:
    """Finite real-socket fixture, including the complete authentication caller."""
    def __init__(self, *, version=b"RFB 003.008\n", methods=b"\x02", rejected=False,
                 size=(2, 1), name=b"owned fixture", malformed=None, stall=False, require_resize=False):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(2)
        self.port = self.listener.getsockname()[1]
        self.version, self.methods, self.rejected = version, methods, rejected
        self.size, self.name, self.malformed, self.stall = size, name, malformed, stall
        self.events, self.requests, self.responses = [], [], []
        self.require_resize = require_resize
        self.negotiated_encodings = ()
        self.updates = 0
        self.connection = None
        self.closed = threading.Event()
        self.receipt_probe = None
        self.missing_receipt = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            self.connection, _ = self.listener.accept()
            self.connection.settimeout(2)
            sock = self.connection
            if self.stall:
                self.closed.wait(2)
                return
            sock.sendall(self.version)
            if self.version != b"RFB 003.008\n":
                return
            self.requests.append(read(sock, 12))
            sock.sendall(bytes([len(self.methods)]) + self.methods)
            if 2 not in self.methods:
                return
            self.requests.append(read(sock, 1))
            sock.sendall(bytes(range(16)))
            self.responses.append(read(sock, 16))
            if self.rejected:
                sock.sendall(b"\0\0\0\x01" + struct.pack(">I", len(self.name)) + self.name)
                return
            sock.sendall(b"\0\0\0\0")
            self.requests.append(read(sock, 1))
            sock.sendall(struct.pack(">HH", *self.size) + b"\0" * 16 + struct.pack(">I", len(self.name)) + self.name)
            if max(self.size) > 4096 or self.size[0] * self.size[1] > 4_194_304 or len(self.name) > 4096:
                return
            self.requests.append(read(sock, 20))
            encoding_header = read(sock, 4)
            encoding_count = struct.unpack(">H", encoding_header[2:])[0]
            if encoding_header[:2] != b"\x02\x00" or not 1 <= encoding_count <= 16:
                return
            encoding_body = read(sock, encoding_count * 4)
            self.requests.append(encoding_header + encoding_body)
            self.negotiated_encodings = struct.unpack(">" + "i" * encoding_count, encoding_body)
            if self.require_resize and -223 not in self.negotiated_encodings:
                return
            while not self.closed.is_set():
                kind = read(sock, 1)[0]
                if kind == 3:
                    self.requests.append(bytes([kind]) + read(sock, 9))
                    self.updates += 1
                    if self.malformed in {"resize", "resize-overflow", "resize-not-last", "resize-loop"} and (self.updates == 1 or self.malformed == "resize-loop"):
                        width = 5000 if self.malformed == "resize-overflow" else 3 if self.malformed == "resize" else 2
                        count = 2 if self.malformed == "resize-not-last" else 1
                        sock.sendall(struct.pack(">BBH", 0, 0, count) + struct.pack(">HHHHi", 0, 0, width, 1, -223))
                        if self.malformed == "resize":
                            self.size = (width, 1)
                    elif self.malformed == "count":
                        sock.sendall(b"\0\0\xff\xff")
                    elif self.malformed == "rectangle":
                        sock.sendall(b"\0\0\0\x01" + struct.pack(">HHHHi", 0, 0, 3, 1, 0))
                    elif self.malformed == "encoding":
                        sock.sendall(b"\0\0\0\x01" + struct.pack(">HHHHi", 0, 0, 2, 1, 16))
                    elif self.malformed == "incomplete":
                        sock.sendall(b"\0\0\0\x01" + struct.pack(">HHHHi", 0, 0, 1, 1, 0) + b"\0\0\xff\0")
                    elif self.malformed == "truncated":
                        sock.sendall(b"\0\0\0\x01" + struct.pack(">HHHHi", 0, 0, 2, 1, 0) + b"\0")
                        return
                    else:
                        pixels = b"\0\0\xff\0\0\xff\0\0" + (b"\xff\0\0\0" if self.size == (3, 1) else b"")
                        sock.sendall(b"\0\0\0\x01" + struct.pack(">HHHHi", 0, 0, *self.size, 0) + pixels)
                elif kind == 4:
                    data = read(sock, 7)
                    if self.receipt_probe and not self.receipt_probe():
                        self.missing_receipt = True
                    self.events.append(("key", data[0], struct.unpack(">I", data[3:])[0]))
                elif kind == 5:
                    self.events.append(("mouse", *struct.unpack(">BHH", read(sock, 5))))
                else:
                    return
        except (EOFError, OSError):
            pass
        finally:
            if self.connection:
                self.connection.close()

    def wait_events(self, count):
        deadline = time.monotonic() + 1
        while len(self.events) < count and time.monotonic() < deadline:
            time.sleep(.002)
        return self.events

    def close(self):
        self.closed.set()
        if self.connection:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(2.1)


@unittest.skipUnless(os.name == "posix", "protected FD and private journal custody")
class ProtectedVncTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path("/tmp").resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.journal = subject.SecretInputJournal(self.root, str(uuid4()))
        self.auth = b"rfb-only-fixture"

    def endpoint(self, **kwargs):
        endpoint = RfbEndpoint(**kwargs)
        self.addCleanup(endpoint.close)
        return endpoint

    def fd(self, body):
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        os.write(writer, body)
        os.close(writer)
        return reader

    def session(self, endpoint, *, guard=lambda: None, **kwargs):
        return subject.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(self.auth), guard=guard, **kwargs)

    def test_complete_authenticated_caller_captures_without_input_and_public_chords_are_guarded(self):
        endpoint = self.endpoint()
        checks = []
        with self.session(endpoint, guard=lambda: checks.append(True)) as client:
            png = client.capture_png()
            from PIL import Image
            image = Image.open(io.BytesIO(png))
            self.assertEqual((255, 0, 0), image.getpixel((0, 0)))
            self.assertEqual((0, 255, 0), image.getpixel((1, 0)))
            self.assertEqual([], endpoint.events)
            before = len(checks)
            client.key("Space", modifiers=("MacMeta",))
            client.key("q", modifiers=("Control", "MacMeta"))
            client.mouse(1, 0, buttons=1)
            client.type_public("Aλ")
            events = endpoint.wait_events(17)
            self.assertEqual(17, len(events))
            self.assertGreaterEqual(len(checks) - before, 17)
            self.assertEqual([("key", 1, 0xFFE9), ("key", 1, 32), ("key", 0, 32), ("key", 0, 0xFFE9)], events[:4])
            self.assertEqual(("key", 1, 0x010003BB), events[-2])
        self.assertEqual([b"RFB 003.008\n", b"\x02", b"\x01"], endpoint.requests[:3])
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        key = bytes(int(f"{value:08b}"[::-1], 2) for value in self.auth[:8])
        encryptor = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()
        self.assertEqual(encryptor.update(bytes(range(16))) + encryptor.finalize(), endpoint.responses[0])

    def test_desktop_size_complete_before_caller_red_current_green(self):
        import hashlib
        import importlib.util
        from importlib.machinery import SourceFileLoader
        before = Path(__file__).parent / "fixtures/tart_vnc_desktop_size.before.source"
        self.assertEqual("56babf2a0b0c25ab489adee6a02a3846bd47419abfc04ff84357f31c87294a0e", hashlib.sha256(before.read_bytes()).hexdigest())
        loader = SourceFileLoader("agent_tools._rfb_before_desktop_size", str(before))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        original = importlib.util.module_from_spec(spec)
        loader.exec_module(original)
        endpoint = self.endpoint(require_resize=True)
        with self.assertRaises(original.VncBlocked):
            with original.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(self.auth), guard=lambda: None) as client:
                client.capture_png()
        self.assertEqual((0,), endpoint.negotiated_encodings)
        self.assertEqual([], endpoint.events)
        healthy = self.endpoint(require_resize=True, malformed="resize")
        with self.session(healthy) as client:
            from PIL import Image
            image = Image.open(io.BytesIO(client.capture_png()))
            self.assertEqual((3, 1), image.size)
            self.assertEqual((255, 0, 0), image.getpixel((0, 0)))
            self.assertEqual((0, 0, 255), image.getpixel((2, 0)))
        self.assertEqual((0, -223), healthy.negotiated_encodings)
        self.assertEqual(2, healthy.updates)
        self.assertEqual([], healthy.events)

    def test_resize_limits_and_position_fail_closed_without_input(self):
        for mode in ("resize-overflow", "resize-not-last", "resize-loop"):
            with self.subTest(mode=mode):
                endpoint = self.endpoint(require_resize=True, malformed=mode)
                with self.assertRaises(subject.VncBlocked):
                    with self.session(endpoint) as client:
                        client.capture_png()
                self.assertEqual([], endpoint.events)
                self.assertLessEqual(endpoint.updates, 4)

    def test_secret_once_journal_precedes_every_event_and_never_contains_input_or_derived_keys(self):
        endpoint = self.endpoint()
        operation = str(uuid4())
        path = self.root / (operation + ".json")
        endpoint.receipt_probe = path.exists
        secret = "private-fixture-λ"
        group_checks = []
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            with self.session(endpoint) as client:
                result = client.type_secret_from_fd(self.fd(secret.encode()), operation_id=operation,
                                                    journal=self.journal, guard=lambda: group_checks.append(True))
                self.assertEqual("unknown", result["state"])
                self.assertEqual(2 * len(secret), len(endpoint.wait_events(2 * len(secret))))
        self.assertEqual([True] * (1 + 2 * len(secret)), group_checks)
        self.assertFalse(endpoint.missing_receipt)
        record = json.loads(path.read_text())
        self.assertEqual({"schemaVersion", "operationId", "bindingId", "action", "state"}, set(record))
        self.assertNotIn(secret, path.read_text() + output.getvalue())
        self.assertNotIn(str(0x010003BB), path.read_text() + output.getvalue())
        self.assertEqual("", output.getvalue())
        other = self.endpoint()
        with self.session(other) as client:
            with self.assertRaisesRegex(subject.VncBlocked, "vnc_secret_original_unknown"):
                client.type_secret_from_fd(self.fd(secret.encode()), operation_id=operation,
                                           journal=subject.SecretInputJournal(self.root, self.journal.binding_identity), guard=lambda: None)
        self.assertEqual([], other.events)

    def test_atomic_same_operation_admission_has_one_owner_and_preserves_no_replay_after_client_loss(self):
        operation = str(uuid4())
        barrier = threading.Barrier(8)
        results = []
        def admit():
            barrier.wait()
            try:
                results.append(self.journal.begin(operation)["state"])
            except subject.VncBlocked as error:
                results.append(str(error))
        threads = [threading.Thread(target=admit) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(2)
        self.assertEqual(1, results.count("unknown"))
        self.assertEqual(7, results.count("vnc_secret_original_unknown"))
        # A new object/process has no in-memory completion to trust. The durable
        # uncertainty receipt refuses a replacement even if no event was seen.
        renewed = subject.SecretInputJournal(self.root, self.journal.binding_identity)
        with self.assertRaisesRegex(subject.VncBlocked, "vnc_secret_original_unknown"):
            renewed.begin(operation)
        self.assertEqual("unknown", json.loads((self.root / (operation + ".json")).read_text())["state"])

    def test_untrusted_public_input_schema_is_finite_and_causes_no_event(self):
        endpoint = self.endpoint()
        with self.session(endpoint) as client:
            for key, modifiers in (("Enter", ([],)), ("Enter", ("MacMeta", "MacMeta")), ("Enter", ["MacMeta"]), ("unknown", ())):
                with self.assertRaisesRegex(subject.VncBlocked, "vnc_public_key_invalid"):
                    client.key(key, modifiers=modifiers)
            for position in ((True, 0), (2, 0), (-1, 0)):
                with self.assertRaisesRegex(subject.VncBlocked, "vnc_pointer_invalid"):
                    client.mouse(*position)
        self.assertEqual([], endpoint.events)

    def test_binding_change_between_secret_down_and_up_preserves_unknown_without_replay(self):
        endpoint = self.endpoint()
        operation = str(uuid4())
        armed = False
        calls = 0
        def guard():
            nonlocal calls
            if armed:
                calls += 1
                if calls == 4:
                    raise RuntimeError("private provider diagnostic must not escape")
        with self.session(endpoint, guard=guard) as client:
            armed = True
            with self.assertRaisesRegex(subject.VncBlocked, "^vnc_binding_changed$"):
                client.type_secret_from_fd(self.fd(b"no-replay"), operation_id=operation,
                                           journal=self.journal, guard=lambda: None)
        self.assertEqual([("key", 1, ord("n"))], endpoint.wait_events(1))
        self.assertEqual("unknown", json.loads((self.root / (operation + ".json")).read_text())["state"])

    def test_unknown_screen_guard_refuses_before_secret_receipt_or_input(self):
        endpoint = self.endpoint()
        def unknown():
            raise RuntimeError("unrecognized private screen")
        with self.session(endpoint) as client:
            with self.assertRaisesRegex(subject.VncBlocked, "^vnc_binding_changed$"):
                client.type_secret_from_fd(self.fd(b"fixture-secret"), operation_id=str(uuid4()),
                                           journal=self.journal, guard=unknown)
        self.assertEqual([], list(self.root.iterdir()))
        self.assertEqual([], endpoint.events)

    def test_auth_failure_malformed_replies_and_timeout_do_not_echo_credentials_or_server_text(self):
        private = "never-disclose-server-private-input"
        cases = [(dict(rejected=True, name=private.encode()), "vnc_auth_rejected"),
                 (dict(version=b"RFB 003.003\n"), "vnc_protocol_unsupported"),
                 (dict(methods=b"\x01"), "vnc_auth_unsupported"),
                 (dict(methods=b""), "vnc_security_malformed"),
                 (dict(size=(4097, 1)), "vnc_framebuffer_overflow"),
                 (dict(name=b"x" * 4097), "vnc_server_name_overflow"),
                 (dict(stall=True), "vnc_deadline")]
        for options, reason in cases:
            with self.subTest(reason=reason):
                endpoint = self.endpoint(**options)
                with self.assertRaises(subject.VncBlocked) as caught:
                    with self.session(endpoint, timeout=.1):
                        self.fail("unsafe handshake admitted")
                self.assertEqual(reason, str(caught.exception))
                rendered = "".join(traceback.format_exception(caught.exception))
                self.assertNotIn(private, rendered)
                self.assertNotIn(self.auth.decode(), rendered)
                self.assertEqual([], endpoint.events)

    def test_malformed_capture_is_bounded_without_input(self):
        for mode in ("count", "rectangle", "encoding", "incomplete", "truncated"):
            with self.subTest(mode=mode):
                endpoint = self.endpoint(malformed=mode)
                with self.session(endpoint) as client:
                    with self.assertRaises(subject.VncBlocked):
                        client.capture_png()
                self.assertEqual([], endpoint.events)

    def test_credential_overflow_timeout_and_invalid_fd_never_reach_network_or_log(self):
        for body in (b"x" * 257, b"", b"secret\n", b"\xff"):
            endpoint = self.endpoint()
            with self.assertRaises(subject.VncBlocked) as caught:
                with subject.ProtectedVncSession(port=endpoint.port, credential_fd=self.fd(body), guard=lambda: None, timeout=.1):
                    self.fail("invalid credential admitted")
            self.assertNotIn(repr(body), repr(caught.exception))
            self.assertEqual([], endpoint.requests)
        reader, writer = os.pipe()
        self.addCleanup(os.close, reader)
        self.addCleanup(os.close, writer)
        endpoint = self.endpoint()
        with self.assertRaisesRegex(subject.VncBlocked, "credential_deadline"):
            with subject.ProtectedVncSession(port=endpoint.port, credential_fd=reader, guard=lambda: None, timeout=.05):
                self.fail("open credential pipe admitted")
        self.assertEqual([], endpoint.requests)
        for descriptor in (0, 1, 2, True, -1):
            endpoint = self.endpoint()
            with self.assertRaisesRegex(subject.VncBlocked, "credential_fd_invalid"):
                with subject.ProtectedVncSession(port=endpoint.port, credential_fd=descriptor, guard=lambda: None):
                    self.fail("unprotected credential descriptor admitted")

    def test_regular_credential_file_requires_private_mode_and_still_no_path_in_error(self):
        path = self.root / "secret-private-name"
        path.write_bytes(self.auth)
        path.chmod(0o644)
        descriptor = os.open(path, os.O_RDONLY)
        self.addCleanup(os.close, descriptor)
        endpoint = self.endpoint()
        with self.assertRaisesRegex(subject.VncBlocked, "^vnc_credential_fd_invalid$") as caught:
            with subject.ProtectedVncSession(port=endpoint.port, credential_fd=descriptor, guard=lambda: None):
                pass
        self.assertNotIn(str(path), str(caught.exception))
        self.assertEqual([], endpoint.requests)

    def test_invalid_secret_never_reserves_or_sends_and_closed_session_cannot_reenter(self):
        for body in (b"\xff", b"secret\n", b"x" * 1025, b""):
            endpoint = self.endpoint()
            with self.session(endpoint) as client:
                with self.assertRaises(subject.VncBlocked):
                    client.type_secret_from_fd(self.fd(body), operation_id=str(uuid4()),
                                               journal=self.journal, guard=lambda: None)
            self.assertEqual([], endpoint.events)
            self.assertEqual([], list(self.root.iterdir()))
            with self.assertRaisesRegex(subject.VncBlocked, "vnc_session_already_used"):
                client.__enter__()


if __name__ == "__main__":
    unittest.main()
