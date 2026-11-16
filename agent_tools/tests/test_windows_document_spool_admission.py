"""The native mutated-sealed-spool failure of the Windows document row (ade9c4da, 2026-11-16), as offline oracles.

windows-document-acceptance (operation ade9c4da, package 2.2.18 of 60017226, tools of 3e559abd) ended
UNKNOWN, job_exit_unknown:owner-parked, scenario-failure-with-retained-child, errorClass Refused, with
the serve (child 2) running. Its last events: document-spool-mutated, then the honest reference's
exchange, which read one whole 37-byte frame and closed its socket. That frame is
cli-response\\terror\\t1\\tCONFLICT (sha256 cc0f2ba7...): the product read the changed spool bytes, ran
their control-snapshot of a foreign controller and refused it. That is the product defect, fixed in
DesktopControlDocuments.consume and covered by DesktopSealedSpoolIntegrityTest.

The harness defect covered here: the admitted negative was a finished exchange, its evidence already
journaled, yet mutate_sealed_spool kept its writer, payload and spool-folder handles, so close_known
refused and the owner parked its clone. Each oracle runs the real owner main() with the inert guest,
the real Windows-module function and the real client over a socket pair whose far end is a logical
product owner writing a real temporary spool file. RED on the 3e559abd bytes (*.before.source), GREEN
on the fix; the controls keep the park. No process, listener, Win32 call or VM is involved.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from agent_tools import windows_document_client as client_module
from agent_tools import windows_document_native as document_native
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools.tests.test_windows_cli_native_failures import Parked, run_owner
from agent_tools.tests.test_windows_document_acceptance import (CONTEXT, OWNER_ID, TOKEN, DocumentGuest, document_state,
                                                                read_frame)

FIXTURES = Path(__file__).parent / "fixtures/windows_document_spool_admission"
PROVENANCE = FIXTURES / "provenance.json"
NATIVE_SHA256 = "302b52f486df7b6f5818ebf0e8c91a4bf14f9d447c69963cf52081272aeb57eb"
CLIENT_SHA256 = "993c7833bf9933f8347509377f2a7f034facb0b4f42996b75b93561e935be41f"
FOREIGN = "71dff2b2-0915-54f0-9e2f-afe589e3d825"
TRANSFER = "8ad8ac32-754f-487f-b892-964bcbf0a8a2"
ORIGINAL = ("cli\tcontrol-snapshot\t" + client_module.encoded_text(OWNER_ID)).encode()
REPLACEMENT = ("cli\tcontrol-snapshot\t" + client_module.encoded_text(FOREIGN)).encode()
# The native reply: DesktopCliProtocol.encodeResponse(DesktopCliResponse.failure("CONFLICT")), framed as a JSON string.
CONFLICT = "cli-response\terror\t1\t" + client_module.encoded_text("CONFLICT")
NATIVE_REPLY_SHA256 = "cc0f2ba7c0b358866473b781264fc7e7a02ae48be340c52204e4e51e1f4e6c5d"


def _load(test, raw, fixture, digest, name):
    test.assertEqual(digest, hashlib.sha256(raw).hexdigest())
    provenance = json.loads(PROVENANCE.read_bytes())["fixtures"][fixture]
    test.assertEqual((digest, len(raw)), (provenance["sha256"], provenance["sizeBytes"]))
    module = types.ModuleType(name)
    module.__file__ = str(FIXTURES / fixture)
    sys.modules[name] = module
    test.addCleanup(sys.modules.pop, name, None)
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def before(test):
    return (_load(test, (FIXTURES / "document-native-spool.before.source").read_bytes(), "document-native-spool.before.source",
                  NATIVE_SHA256, "_spool_admission_before_native"),
            _load(test, (FIXTURES / "document-client-negative.before.source").read_bytes(),
                  "document-client-negative.before.source", CLIENT_SHA256, "_spool_admission_before_client"))


IDENTITY = {"volumeSerial": 3725115023, "fileIndex": 281474976862346, "attributes": 32}
NATIVE = types.SimpleNamespace(identity=lambda handle, directory=False: dict(IDENTITY))


class Held:
    """windows_document_native.Held as mutate_sealed_spool uses it, over one real temporary file."""

    opened = []
    refuse_close = None

    def __init__(self, native, path, directory=False, write=False, share=1):
        self.native, self.path, self.directory, self.write, self.share = NATIVE, Path(path), directory, write, share
        self.handle, self.closed, self.initial = object(), False, dict(IDENTITY)
        Held.opened.append(self)

    def current(self, stable_content=True):
        if self.closed:
            raise RuntimeError("document-held-inspection-incomplete-or-closed")
        return dict(IDENTITY, sizeBytes=0 if self.directory else self.path.stat().st_size)

    def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
        self.current()
        return self.path.read_bytes()

    def pin(self):
        return {"path": str(self.path), "nativeIdentity": self.current(), "sha256": hashlib.sha256(self.bytes()).hexdigest()}

    def write_exact(self, data):
        if not self.write:
            raise RuntimeError("document-held-write-input")
        with self.path.open("r+b") as output:
            output.write(data)
            output.truncate(len(data))

    def close(self):
        if self.closed:
            raise RuntimeError("document-handle-already-closed")
        if Held.refuse_close is self:
            raise RuntimeError("document-handle-close")
        self.closed = True


class Product:
    """The installed owner's endpoint for one transfer, as DesktopControlDocuments answers it.

    reference: "answer" reads the spool as 2.2.18 does and runs what it finds (a foreign controller's
    snapshot is CONFLICT); "verify" refuses bytes that no longer match the seal by closing; "partial"
    writes part of a frame and closes.
    """

    def __init__(self, payload, reference):
        self.payload, self.reference, self.threads, self.received = payload, reference, [], []

    def connect(self, port):
        mine, theirs = socket.socketpair()
        thread = threading.Thread(target=self.serve, args=(theirs,), daemon=True)
        self.threads.append(thread)
        thread.start()
        return mine

    def serve(self, sock):
        with sock:
            if read_frame(sock) != TOKEN:
                return
            sock.sendall(client_module.wire("AUTHENTICATED"))
            first = read_frame(sock)
            frame = read_frame(sock) if first.startswith(client_module.CONTEXT) else first
            self.received.append(frame)
            if frame.startswith(client_module.TRANSFER):
                action = json.loads(json.loads(frame[len(client_module.TRANSFER):])["command"])
                if action["action"] == "append":
                    with self.payload.open("ab") as spool:
                        spool.write(base64.b64decode(action["bytes"]))
                    sock.sendall(client_module.wire(client_module.dump({"id": TRANSFER, "byteCount": len(ORIGINAL),
                                                                        "sha256": None, "chunkBytes": 65536})))
                elif action["action"] == "seal":
                    sock.sendall(client_module.wire(client_module.dump({"id": TRANSFER, "byteCount": action["byteCount"],
                                                                        "sha256": action["sha256"], "chunkBytes": 65536})))
                return
            held = self.payload.read_bytes()
            if self.reference == "answer":
                identity = client_module.decoded_text(held.decode().split("\t")[2])
                sock.sendall(client_module.wire(CONFLICT if identity != OWNER_ID else "cli-response\tok\t0\t"))
            elif self.reference == "partial":
                sock.sendall(client_module.wire(CONFLICT)[:6])
            elif held != ORIGINAL:
                return  # Fixed product: changed sealed bytes are never run and get no reply.


class SpoolRuns(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        Held.opened, Held.refuse_close = [], None
        self.addCleanup(setattr, Held, "refuse_close", None)

    def run_case(self, native, client, reference, *, refuse=None):
        spool = Path(tempfile.mkdtemp(dir=self.root)) / "vpn-control-transfer-c843a4de-ca79-42e9-9b7c-6abb1d4cbea6"
        spool.mkdir()
        (spool / "payload").write_bytes(b"")
        product = Product(spool / "payload", reference)
        state = {}

        def situation(owner, workspace, identity, harness):
            document_state(owner)
            peer = client.Client({"port": 1, "controllerId": OWNER_ID, "token": TOKEN, "documentTransfers": True},
                                 lambda: None, owner.event, connector=product.connect)
            owner.document_client = peer
            fixture = {"root": Held(None, spool, directory=True, share=7), "payload": Held(None, spool / "payload", share=7),
                       "context": CONTEXT, "manifest": {"id": TRANSFER, "byteCount": 0, "sha256": None, "chunkBytes": 65536}}
            owner.document_spool_fault = state["fixture"] = fixture
            if refuse is not None:
                Held.refuse_close = fixture[refuse]
            with mock.patch.object(native, "Held", Held):
                state["result"] = native.mutate_sealed_spool(owner, peer, client, fixture, ORIGINAL, REPLACEMENT, 7)
            # The CLI cases' own release after a known refusal (windows_document_cli_cases.run).
            fixture["payload"].close(); fixture["root"].close()

        guest = DocumentGuest(Path(tempfile.mkdtemp(dir=self.root)))
        code = None
        try:
            code = run_owner(process_owner, guest, "document-acceptance", situation)
        except Parked:
            pass
        for thread in product.threads:
            thread.join(5)
        return guest, code, state, product

    def quits(self, guest):
        return [row for row in guest.trace if row[0] == "quit"]


class AdmittedSpoolTests(SpoolRuns):
    def closed_known(self, native, client):
        guest, code, state, product = self.run_case(native, client, "answer")
        self.assertEqual((1, [], [(1, "Refused", "document-negative-admitted:mutated-sealed-spool")]),
                         (code, guest.parks, guest.finished))
        self.assertEqual(1, len(self.quits(guest)), "one quit, never replayed")
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))
        fixture = state["fixture"]
        self.assertTrue(all(fixture[name].closed for name in ("writer", "payload", "root")))
        self.assertEqual(1, sum(1 for frame in product.received if frame.startswith(client_module.REFERENCE)),
                         "the honest reference is sent once")
        kinds = [kind for kind, _ in guest.events]
        order = ["document-spool-mutated", "document-exchange", "document-spool-mutation-admitted",
                 "document-spool-admitted-released", "document-known-failure-observers-released", "known-failure-closing",
                 "known-failure-quit-intent", "known-failure-serve-closed", "known-failure-closed"]
        self.assertEqual(order, [kind for kind in kinds if kind in order][-len(order):])
        admitted = dict(guest.events)["document-spool-mutation-admitted"]
        self.assertEqual({"decoded": True, "success": False, "exitCode": 1, "code": "CONFLICT", "bodyBytes": 8,
                          "bodySha256": hashlib.sha256(b"CONFLICT").hexdigest()}, admitted["reply"])
        self.assertEqual({"bytes": 37, "sha256": NATIVE_REPLY_SHA256}, admitted["replyFrame"], "the native frame")
        self.assertTrue(admitted["heldIsReplacement"])
        self.assertEqual(hashlib.sha256(REPLACEMENT).hexdigest(), admitted["heldSha256"])
        self.assertEqual((False, False, False), (admitted["replayAllowed"], admitted["discardPerformed"],
                                                 admitted["pathDeletionPerformed"]))

    def test_an_answered_mutated_spool_closes_as_the_named_known_failure(self):
        native, client = before(self)
        guest, code, state, _ = self.run_case(native, client, "answer")
        # RED, the native signature: the park with the serve running and every spool handle still held.
        self.assertEqual("scenario-failure-with-retained-child", guest.parks[0][0])
        self.assertEqual("Refused", guest.parks[0][1])
        self.assertEqual([], self.quits(guest))
        self.assertFalse(any(state["fixture"][name].closed for name in ("writer", "payload", "root")))
        self.closed_known(document_native, client_module)

    def test_the_fixed_product_closing_without_a_reply_passes_the_adversary(self):
        guest, code, state, _ = self.run_case(document_native, client_module, "verify")
        self.assertEqual((0, []), (code, guest.parks))
        self.assertIn({"label": "mutated-sealed-spool", "observed": "clean-frame-eof"},
                      [value for kind, value in guest.events if kind == "document-negative"])
        self.assertNotIn("document-spool-mutation-admitted", dict(guest.events))
        self.assertEqual(hashlib.sha256(REPLACEMENT).hexdigest(), state["result"]["replacementSha256"])

    def test_a_partial_reply_keeps_every_handle_for_the_park(self):
        guest, code, state, _ = self.run_case(document_native, client_module, "partial")
        self.assertEqual("scenario-failure-with-retained-child", guest.parks[0][0])
        self.assertEqual("Refused", guest.parks[0][1])  # document-negative-partial-frame
        last = [value for kind, value in guest.events if kind == "document-exchange"][-1]
        self.assertEqual(("eof", 6), (last["frames"][-1]["state"], last["frames"][-1]["partialBytes"]))
        self.assertEqual([], self.quits(guest))
        self.assertFalse(any(state["fixture"][name].closed for name in ("writer", "payload", "root")))
        self.assertNotIn("document-spool-mutation-admitted", dict(guest.events))

    def test_a_release_that_cannot_close_its_handle_parks_unknown(self):
        for name in ("payload", "root"):
            with self.subTest(handle=name):
                guest, code, state, _ = self.run_case(document_native, client_module, "answer", refuse=name)
                self.assertEqual("document-spool-admitted-release-unknown", guest.parks[0][0])
                self.assertEqual([], self.quits(guest))
                self.assertIn("document-spool-mutation-admitted", dict(guest.events), "evidence comes first")

    def test_the_reply_record_names_only_a_typed_code(self):
        record = document_native.admitted_reply(client_module, "cli-response\tok\t0\t" + client_module.encoded_text('{"x":1}'))
        self.assertEqual((True, None, 7), (record["success"], record["code"], record["bodyBytes"]))
        self.assertEqual({"decoded": False, "characters": 3}, document_native.admitted_reply(client_module, "odd"))
        self.assertEqual({"decoded": False}, document_native.admitted_reply(client_module, None))


if __name__ == "__main__":
    unittest.main()
