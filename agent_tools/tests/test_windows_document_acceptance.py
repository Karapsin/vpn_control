"""The Windows document family's own oracles: the export relay, the owner's closing, the cold and GUI cases.

Nothing here reaches a VM, a console or Win32. The relay runs over socket pairs, so no listener is
opened; the owner runs with the inert guest of test_windows_cli_native_failures. Each defect oracle
of landed code is RED on its preserved module (fixtures/windows_document_acceptance/*.before.source)
and GREEN on the current one; the review's GUI-exit oracle was RED on unlanded bytes only.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_document_client as client_module
from agent_tools import windows_document_export_race as export_race
from agent_tools import windows_ordinary_process_owner as process_owner

FIXTURES = Path(__file__).parent / "fixtures/windows_document_acceptance"
PROVENANCE = FIXTURES / "provenance.json"
RACE_SHA256 = "a098b1aae0b50eefda4e3f9a436711e228adf6b61d0dc7c4bacc2baced538db1"
OWNER_SHA256 = "2bb86fa358da1742c470d1354065eb3a9d3dcee46b629c689b6baca18b6a011a"
OWNER_ID = "33333333-4444-4555-8666-777777777777"
CONTEXT = "44444444-5555-4666-8777-888888888888"
TRANSFER_ID = "55555555-6666-4777-8888-999999999999"
TOKEN = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
DIGEST = "ab" * 32


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


def before_race(test):
    return _load(test, (FIXTURES / "export-race.before.source").read_bytes(), "export-race.before.source", RACE_SHA256,
                 "_document_before_export_race")


def before_owner(test):
    return _load(test, (FIXTURES / "owner-document-park.before.source").read_bytes(), "owner-document-park.before.source",
                 OWNER_SHA256, "_document_before_owner")


def product_frame(kind, command):
    """A transfer frame as DesktopControlDocuments writes it: the acknowledgement's command is plain text, the others JSON."""
    return client_module.TRANSFER + client_module.fields(OWNER_ID, CONTEXT, kind, "command", command)


def product_read(offset):
    return product_frame("export", client_module.dump({"action": "read", "id": TRANSFER_ID, "offset": offset, "length": 65536}))


def product_ack():
    return product_frame("export", "ack:" + TRANSFER_ID + ":" + DIGEST)


def product_discard():
    return product_frame("export", client_module.dump({"action": "discard", "id": TRANSFER_ID}))


def read_frame(sock):
    def exact(size):
        data = b""
        while len(data) < size:
            part = sock.recv(size - len(data))
            if not part:
                return None
            data += part
        return data
    header = exact(4)
    if header is None:
        return None
    return json.loads(exact(struct.unpack(">I", header)[0]).decode())


class FakeOwnerEndpoint:
    """The installed owner's side of one relayed connection: authenticates, answers the one payload, records it."""

    def __init__(self):
        self.payloads = []
        self.threads = []

    def connect(self, address, timeout=None):
        relay_end, owner_end = socket.socketpair()
        thread = threading.Thread(target=self.serve, args=(owner_end,), daemon=True)
        self.threads.append(thread)
        thread.start()
        return relay_end

    def serve(self, sock):
        with sock:
            try:
                if read_frame(sock) != TOKEN:
                    return
                sock.sendall(client_module.wire("AUTHENTICATED"))
                payload = read_frame(sock)
                if payload is None:
                    return  # The relay closed the connection before any payload reached this owner.
                self.payloads.append(payload)
                if payload == product_ack():
                    sock.sendall(client_module.wire("ACKNOWLEDGED"))
                elif payload == product_discard():
                    sock.sendall(client_module.wire("DISCARDED"))
                else:
                    sock.sendall(client_module.wire(client_module.dump({"id": TRANSFER_ID, "offset": 0, "bytes": ""})))
            except OSError:
                pass  # A peer that closed first is what the relay's own journal records.


def relay_of(module, endpoint):
    """One ExportRelay without its loopback listener: exchange() is exercised on a socket pair."""
    relay = module.ExportRelay.__new__(module.ExportRelay)
    events = []
    relay.owner = types.SimpleNamespace(event=lambda kind, value: events.append((kind, value)))
    relay.client = types.SimpleNamespace(guard=lambda: None, owner=OWNER_ID, _endpoint={"port": 1, "token": TOKEN})
    relay.module = client_module
    relay.barrier, relay.release, relay.stop = threading.Event(), threading.Event(), threading.Event()
    relay.errors, relay.connections, relay.threads = [], [], []
    relay.events = events
    return relay


def relayed(module, frame, endpoint):
    """The installed CLI's one exchange through the relay: token, authentication, its frame, the reply it read."""
    relay = relay_of(module, endpoint)
    cli, relay_end = socket.socketpair()
    relay.connections.append(relay_end)  # As accept() records each accepted connection before its exchange.
    with mock.patch.object(module.socket, "create_connection", endpoint.connect):
        worker = threading.Thread(target=relay.exchange, args=(relay_end,), daemon=True)
        worker.start()
        with cli:
            cli.settimeout(10)
            cli.sendall(client_module.wire(TOKEN))
            authenticated = read_frame(cli)
            cli.sendall(client_module.wire(frame))
            reply = read_frame(cli)
        worker.join(10)
    for thread in endpoint.threads:
        thread.join(10)
    return relay, authenticated, reply


class ExportRaceAckTests(unittest.TestCase):
    """windows_document_export_race.py:52 parsed every transfer command as JSON, but the product's export
    acknowledgement is the plain text ack:<id>:<sha256> (DesktopControlDocuments.downloadExport). In the parent
    race the relay then dropped the ack, so close_known() found an error and the owner parked."""

    def ack_oracle(self, module):
        endpoint = FakeOwnerEndpoint()
        relay, authenticated, reply = relayed(module, product_ack(), endpoint)
        self.assertEqual(([], "AUTHENTICATED", "ACKNOWLEDGED"), ([type(error).__name__ for error in relay.errors], authenticated, reply))
        self.assertEqual([product_ack()], endpoint.payloads, "the original acknowledgement reaches the owner unchanged")
        self.assertFalse(relay.barrier.is_set())

    def test_the_products_plain_text_acknowledgement_is_relayed(self):
        with self.assertRaises(AssertionError):
            self.ack_oracle(before_race(self))  # RED: JSONDecodeError, the ack is dropped and the client reads EOF.
        self.ack_oracle(export_race)

    def classification_oracle(self, module):
        self.assertTrue(module.is_export_read(product_read(0), client_module, OWNER_ID))
        for frame in (product_read(65536), product_discard(), product_ack(),
                      product_frame("response", client_module.dump({"action": "read", "id": TRANSFER_ID, "offset": 0, "length": 1}))):
            self.assertFalse(module.is_export_read(frame, client_module, OWNER_ID))
        self.assertFalse(module.is_export_read("cli\tcontrol-submit\tx", client_module, OWNER_ID))

    def test_only_the_first_export_read_is_the_barrier(self):
        with self.assertRaises(ValueError):
            self.classification_oracle(before_race(self))  # RED: the acknowledgement is not JSON.
        self.classification_oracle(export_race)

    def test_a_transfer_bound_to_another_owner_or_shape_still_refuses(self):
        other = client_module.TRANSFER + client_module.fields("66666666-7777-4888-8999-aaaaaaaaaaaa", CONTEXT, "export", "command", "ack:x")
        for frame in (other, client_module.TRANSFER + client_module.dump({"owner": OWNER_ID, "command": "ack:x"})):
            with self.subTest(frame=frame[:40]), self.assertRaisesRegex(RuntimeError, "document-relay-transfer-binding"):
                export_race.is_export_read(frame, client_module, OWNER_ID)
        with self.assertRaisesRegex(RuntimeError, "document-relay-transfer-binding"):
            export_race.is_export_read(product_frame("export", "") .replace('"command":""', '"command":7'), client_module, OWNER_ID)

    def test_the_first_read_is_held_at_the_barrier_until_release(self):
        endpoint = FakeOwnerEndpoint()
        relay = relay_of(export_race, endpoint)
        cli, relay_end = socket.socketpair()
        relay.connections.append(relay_end)
        with mock.patch.object(export_race.socket, "create_connection", endpoint.connect):
            worker = threading.Thread(target=relay.exchange, args=(relay_end,), daemon=True)
            worker.start()
            with cli:
                cli.settimeout(10)
                cli.sendall(client_module.wire(TOKEN))
                read_frame(cli)
                cli.sendall(client_module.wire(product_read(0)))
                self.assertTrue(relay.barrier.wait(10))
                self.assertEqual([], endpoint.payloads, "nothing reaches the owner before the release")
                relay.release.set()
                self.assertEqual({"id": TRANSFER_ID, "offset": 0, "bytes": ""}, json.loads(read_frame(cli)))
            worker.join(10)
        self.assertEqual(([], [product_read(0)]), (relay.errors, endpoint.payloads))
        self.assertEqual(["document-export-read-barrier"], [kind for kind, _ in relay.events])


# ---- The owner's closing of a known document failure ------------------------------------

from agent_tools import windows_document_cli_cases as document_cases  # noqa: E402
from agent_tools.tests.test_windows_cli_native_failures import Guest, GuestChild, Parked, run_owner  # noqa: E402

DOCUMENT_CASES = r"C:\ProgramData\VpnControlOrdinaryTask-33333333-4444-4555-8666-777777777777\windows_document_cli_cases.py"


class DocumentGuest(Guest):
    """The inert guest with one controller per serve generation: a workspace reopened by a later serve is a new owner."""

    def __init__(self, root, **options):
        super().__init__(root, **options)
        self.generations = {}  # child ordinal -> controller id of that serve
        self.quit_generations = set()

    def serve_of(self, workspace):
        serves = [child for child in self.owner_object.children if child.argv[0] == self.cli
                  and child.argv[1:] == ("--state-dir", workspace, "serve")]
        live = [child for child in serves if child.ordinal not in self.quit_generations]
        return (live or serves or [None])[-1]

    def outcome(self, child):
        if child.argv[-1] == "serve":
            if self.serve_exits and child.ordinal in self.quit_generations:
                return 0, "", "VPN Control headless service is ready.\n"
            return None
        return super().outcome(child)

    def public(self, argv):
        workspace, rest = argv[2], list(argv[3:])
        serve = self.serve_of(workspace)
        controller = None if serve is None or serve.ordinal in self.quit_generations else self.generations[serve.ordinal]
        if rest in (["--json", "status"], ["--json", "--controller-id", controller, "status"]):
            if controller is None:
                return 2, self.envelope("UNAVAILABLE", None), ""
            return 0, self.envelope("OK", controller, {"runtimeRunning": False}), ""
        if rest[:2] == ["--json", "--controller-id"] and rest[3:] == ["quit"]:
            if rest[2] != controller:
                return 2, self.envelope("UNAVAILABLE", None), ""
            self.trace.append(("quit", workspace))
            if self.quit_answer == "busy":
                return 1, self.envelope("BUSY", controller), ""
            self.quits.append(workspace)
            self.quit_generations.add(serve.ordinal)
            return 0, self.envelope("OK", controller, operationId=str(uuid.uuid4())), ""
        raise LookupError("unmodelled public call: " + " ".join(rest))

    def owner(self, module, action, situation):
        owner = super().owner(module, action, situation)
        owner.request["casesPath"] = DOCUMENT_CASES
        owner.by_path[str(Path(DOCUMENT_CASES)).casefold()] = types.SimpleNamespace(
            path=Path(DOCUMENT_CASES), record={"sha256": "0" * 64})
        submit = owner.child

        def child(label, argv, *, new_console=False, owned_desktop=None):
            value = submit(label, argv, new_console=new_console, owned_desktop=owned_desktop)
            if argv[-1] == "serve":
                self.generations[value.ordinal] = "c0ffee00-0000-4000-8000-%012d" % value.ordinal
            return value
        owner.child = child
        closing = situation.close_known if hasattr(situation, "close_known") else document_cases.close_known

        def module_peer(path, name):
            if path == DOCUMENT_CASES:
                return types.SimpleNamespace(configure_launch=lambda owner, workspace: None, run=situation, close_known=closing)
            return types.ModuleType("inert-held-harness")
        owner.module = module_peer
        return owner


class Observer:
    """A held native observer as windows_document_native.Held keeps it: open until closed, once."""

    def __init__(self):
        self.closed = False

    def close(self):
        if self.closed:
            raise RuntimeError("document-handle-already-closed")
        self.closed = True


def document_state(owner, *, sockets=(), secondary=(), relay=None, fixture=None):
    owner.document_client = types.SimpleNamespace(original_sockets=list(sockets), last_exchange={"secondary": list(secondary)})
    owner.document_endpoint_handle, owner.document_workspace_handle = Observer(), Observer()
    if relay is not None:
        owner.document_export_relays = [relay]
    if fixture is not None:
        owner.document_spool_fault = fixture


def oracle_failure(**state):
    def situation(owner, workspace, identity, harness):
        document_state(owner, **state)
        raise RuntimeError("document-known-retry-result-changed")
    return situation


class DocumentKnownFailureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def guest(self, **options):
        return DocumentGuest(Path(tempfile.mkdtemp(dir=self.root)), **options)

    def closed_oracle(self, module):
        guest = self.guest()
        self.assertEqual(1, run_owner(module, guest, "document-acceptance", oracle_failure()))
        self.assertEqual(([], [(1, "RuntimeError", "document-known-retry-result-changed")]), (guest.parks, guest.finished))
        owner = guest.owner_object
        self.assertTrue(all(child.terminal is not None for child in owner.children))
        self.assertTrue(owner.document_endpoint_handle.closed and owner.document_workspace_handle.closed,
                        "the endpoint observer is released before the quit, so the product removes its descriptor")
        kinds = [value for kind, value in guest.events if kind.startswith(("document-known", "known-failure"))]
        self.assertEqual(["document-known-failure-observers-released", "known-failure-closing", "known-failure-quit-intent",
                          "known-failure-serve-closed", "known-failure-closed"],
                         [kind for kind, _ in guest.events if kind.startswith(("document-known", "known-failure"))])
        self.assertEqual(1, len([row for row in guest.trace if row[0] == "quit"]), "one quit, never replayed")
        return kinds

    def test_a_document_oracle_failure_closes_the_serve_and_ends_one(self):
        with self.assertRaisesRegex(Parked, "scenario-failure-with-retained-child"):
            self.closed_oracle(before_owner(self))  # RED: the park, with only the serve running.
        self.closed_oracle(process_owner)

    def parked(self, situation, reason="scenario-failure-with-retained-child"):
        guest = self.guest()
        with self.assertRaises(Parked):
            run_owner(process_owner, guest, "document-acceptance", situation)
        self.assertEqual(reason, guest.parks[0][0])
        self.assertEqual([], [row for row in guest.trace if row[0] == "quit"], "nothing is quit")
        self.assertNotIn("known-failure-closing", dict(guest.events))
        return guest

    def test_anything_in_flight_keeps_every_original_for_the_park(self):
        live_relay = types.SimpleNamespace(stop=threading.Event(), connections=[], thread=types.SimpleNamespace(is_alive=lambda: False))
        stopped = threading.Event()
        stopped.set()
        open_relay = types.SimpleNamespace(stop=stopped, connections=["original socket"], thread=types.SimpleNamespace(is_alive=lambda: False))
        cases = {"socket": {"sockets": ["original socket"]}, "secondary": {"secondary": [OSError("close")]},
                 "relay": {"relay": live_relay}, "relay-connection": {"relay": open_relay},
                 "spool-fixture": {"fixture": {"root": Observer(), "payload": Observer(), "context": CONTEXT}}}
        for name, state in cases.items():
            with self.subTest(case=name):
                guest = self.parked(oracle_failure(**state))
                owner = guest.owner_object
                self.assertFalse(owner.document_endpoint_handle.closed, "observers stay held for the original")

    def test_only_the_modules_own_finite_codes_are_known(self):
        def failing(error):
            def situation(owner, workspace, identity, harness):
                document_state(owner)
                raise error
            return situation
        for error in (RuntimeError("unexpected"), client_module.ClosedFrame(b""), OSError("socket"), ValueError("document-x"), KeyError("document-x"),
                      type("NativeOpenError", (RuntimeError,), {})("document-native-file-open-refused")):
            with self.subTest(error=type(error).__name__):
                self.parked(failing(error))

    def test_a_harness_oracle_on_a_completed_public_call_is_known_too(self):
        def situation(owner, workspace, identity, harness):
            document_state(owner)
            raise AssertionError("CLI exit 1, expected 0; stdoutMetadata={}; stdoutCharacters=0; stderr=''")
        guest = self.guest()
        self.assertEqual(1, run_owner(process_owner, guest, "document-acceptance", situation))
        self.assertEqual([], guest.parks)
        self.assertEqual(1, len([row for row in guest.trace if row[0] == "quit"]))
        self.assertTrue(guest.owner_object.document_endpoint_handle.closed)

    def test_a_case_module_without_close_known_keeps_the_park(self):
        situation = oracle_failure()
        situation.close_known = None  # The responsive cases define none.
        self.parked(situation)

    def test_a_failed_release_is_unknown(self):
        def situation(owner, workspace, identity, harness):
            document_state(owner)
            owner.document_endpoint_handle.closed = None  # Neither open nor closed: a release that cannot be judged.
            owner.document_endpoint_handle.close = lambda: (_ for _ in ()).throw(OSError("close"))
            raise RuntimeError("document-known-retry-result-changed")
        self.parked(situation, "document-known-failure-release-unknown")


def reopen(guest, owner, workspace, identity, *, label="document-cold-serve"):
    """The cold cases' own steps: the original's public quit, its exit, then one more serve on the same workspace."""
    quit_result = owner.invoke(workspace, "--json", "--controller-id", identity, "quit")
    assert quit_result.returncode == 0
    original = next(child for child in owner.children if child.label == "serve")
    guest.clock.now += 1
    assert original.wait()["exitCode"] == 0
    reopened = owner.child(label, [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
    return reopened, guest.generations[reopened.ordinal]


class ReopenedOwnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def guest(self):
        return DocumentGuest(Path(tempfile.mkdtemp(dir=self.root)))

    def passed_oracle(self, module):
        guest = self.guest()

        def situation(owner, workspace, identity, harness):
            reopened, second = reopen(guest, owner, workspace, identity)
            owner.document_reopened_owner = {"child": reopened, "controllerId": second}
        self.assertEqual(0, run_owner(module, guest, "document-acceptance", situation))
        self.assertEqual(([], [(0, "NoneType", "None")]), (guest.parks, guest.finished))
        self.assertTrue(all(child.terminal is not None and child.terminal["exitCode"] == 0 for child in guest.owner_object.children))

    def test_the_owner_closes_the_workspace_a_cold_case_reopened(self):
        with self.assertRaises(Parked):
            self.passed_oracle(before_owner(self))  # RED: the tail asks the gone original owner, the reopened serve stays.
        self.passed_oracle(process_owner)

    def closing_oracle(self, module):
        guest = self.guest()

        def situation(owner, workspace, identity, harness):
            reopened, second = reopen(guest, owner, workspace, identity)
            owner.document_reopened_owner = {"child": reopened, "controllerId": second}
            document_state(owner)
            raise RuntimeError("document-cold-readback")

        def close_known(owner, error, serve, identity):
            known = document_cases.close_known(owner, error, serve, identity)
            reopened = owner.document_reopened_owner
            return None if known is None else (reopened["child"], reopened["controllerId"])
        situation.close_known = close_known
        run_owner(module, guest, "document-acceptance", situation)
        return guest

    def test_a_serve_started_after_the_cases_quit_is_quit_not_awaited(self):
        # RED on the preserved close_known_failure: the earlier quit of the original counts for the reopened serve,
        # which is then only awaited and never quit, so the closing parks after its 120 s.
        guest = self.guest()
        before = before_owner(self)
        owner = guest.owner(before, "document-acceptance", None)
        workspace = guest.root / "workspace"
        owner.child("serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
        first = guest.generations[0]
        reopened, second = reopen(guest, owner, workspace, first)
        with mock.patch.object(before, "time", guest.clock), self.assertRaisesRegex(Parked, "known-failure-case-quit-exit-unknown"):
            before.close_known_failure(owner, workspace, second, reopened, RuntimeError("document-cold-readback"))
        guest = self.closing_oracle(process_owner)
        self.assertEqual(([], 1), (guest.parks, guest.finished[0][0]))
        self.assertEqual(2, len([row for row in guest.trace if row[0] == "quit"]), "the case's quit and the closing's own quit")
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))


# ---- The cold and GUI-owner cases --------------------------------------------------------

from agent_tools import windows_document_cold_cases as cold_cases  # noqa: E402
from agent_tools import windows_scenario_host_job as host_job  # noqa: E402
from agent_tools.tests.test_windows_cli_native_failures import held_harness  # noqa: E402


def export_document(suffixes):
    """The product's export form (RoutingRulesTransfer.writeExport) of the stored rules, with its own timestamp."""
    body = ",".join('\n      "' + value + '"' for value in suffixes)
    return ('{\n  "type": "vpn_control_routing_rules",\n  "version": 7,\n  "exported_at": "2026-11-09T01:02:03.456Z",\n  "rules": {\n'
            '    "ignore_rules": false,\n    "block_quic_udp_443": false,\n    "proxy_packages": [],\n    "direct_domain_suffixes": ['
            + body + ("\n    " if suffixes else "") + ']\n  }\n}').encode("ascii")


class ColdGuest(DocumentGuest):
    """The inert guest whose owners keep routing per workspace, as the product persists it, and whose GUI starts an owner."""

    def __init__(self, root, **options):
        super().__init__(root, **options)
        self.routing, self.imports, self.exports = {}, [], []
        self.export_change = None
        self.gui = str(Path(LAUNCHER_PATH).with_name("vpn-control.exe"))

    def owners(self, workspace):
        return [child for child in self.owner_object.children if (child.argv[0] == self.cli and child.argv[1:] == ("--state-dir", workspace, "serve"))
                or (child.argv[0] == self.gui and child.argv[1:] == ("--state-dir", workspace))]

    def serve_of(self, workspace):
        owners = self.owners(workspace)
        live = [child for child in owners if child.ordinal not in self.quit_generations]
        return (live or owners or [None])[-1]

    def outcome(self, child):
        if child.argv[0] == self.gui:
            return (0, "", "") if child.ordinal in self.quit_generations else None
        return super().outcome(child)

    def public(self, argv):
        workspace, rest = argv[2], list(argv[3:])
        serve = self.serve_of(workspace)
        controller = None if serve is None or serve.ordinal in self.quit_generations else self.generations[serve.ordinal]
        if rest[:3] == ["--json", "--controller-id", controller] and rest[3:5] == ["--if-revision", "43"] and rest[5:7] == ["routing", "import"]:
            raw = Path(rest[8]).read_bytes()
            value = json.loads(raw)
            self.routing[workspace] = host_job.normalized_suffixes(value["rules"]["direct_domain_suffixes"])
            self.imports.append((controller, rest[8]))
            return 0, self.envelope("OK", controller, {"directDomainSuffixes": len(self.routing[workspace])}), ""
        if rest[:3] == ["--json", "--controller-id", controller] and rest[3:6] == ["routing", "export", "--output"]:
            raw = export_document(self.routing.get(workspace, []))
            if self.export_change is not None:
                raw = self.export_change(raw)
            Path(rest[6]).write_bytes(raw)
            self.exports.append((controller, rest[6]))
            return 0, self.envelope("OK", controller, {"bytes": len(raw)}), ""
        return super().public(argv)

    def owner(self, module, action, situation):
        owner = super().owner(module, action, situation)
        submit = owner.child

        def child(label, argv, *, new_console=False, owned_desktop=None):
            value = submit(label, argv, new_console=new_console, owned_desktop=owned_desktop)
            if argv[0] == self.gui:
                self.generations[value.ordinal] = "c0ffee00-0000-4000-8000-%012d" % value.ordinal
            return value
        owner.child = child
        return owner


LAUNCHER_PATH = r"C:\Users\fixture\AppData\Local\vpn-control\vpn-control-cli.exe"


class ColdCaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def run_cold(self, variant, *, change=None, guest_change=None):
        guest = ColdGuest(Path(tempfile.mkdtemp(dir=self.root)))
        operation = "77777777-8888-4999-8aaa-bbbbbbbbbbbb"
        temp = guest.root / "document-temp"
        temp.mkdir()
        large = guest.root / "document-large-routing.json"
        large.write_bytes(host_job.document_input(entries=40))
        legacy = guest.root / "document-legacy-newline.json"
        legacy.write_bytes(host_job.legacy_newline_input())
        source = legacy if variant == "legacy-newline" else large
        suffixes = host_job.normalized_suffixes(host_job.LEGACY_ENTRIES) if variant == "legacy-newline" else \
            ["d%07d.document.invalid" % number for number in range(40)]
        literal = {"schemaVersion": 1, "variant": variant, "operationId": operation, "routingInputPath": str(source),
                   "expectedSemanticSha256": host_job.routing_semantic_sha256(suffixes), "expectedSuffixCount": len(suffixes)}
        if change is not None:
            change(literal)
        raw = (json.dumps(literal, sort_keys=True) + "\n").encode()
        if guest_change is not None:
            guest_change(guest)

        def pin(data, path):
            return types.SimpleNamespace(path=path, record={"sha256": hashlib.sha256(data).hexdigest()}, current=lambda: None,
                                         digest=lambda return_bytes=False, maximum=0: data)

        class Held:
            def __init__(self, native, path, directory=False, write=False, share=1):
                self.path, self.closed = Path(path), False

            def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
                return self.path.read_bytes()

            def close(self):
                self.closed = True
        windows = types.SimpleNamespace(Held=Held)
        harness = types.SimpleNamespace(**held_harness())
        original_owner = guest.owner

        def owner_with_inputs(module, action, situation):
            owner = original_owner(module, action, situation)
            owner.cases_situation = situation
            owner.request["cliPath"] = guest.cli = LAUNCHER_PATH
            guest.gui = str(Path(LAUNCHER_PATH).with_name("vpn-control.exe"))
            owner.request["documentAcceptance"] = {"schemaVersion": 1, "clientPath": "client.py", "windowsPath": "windows.py",
                                                   "racePath": "race.py", "largeRoutingInputPath": str(large), "spoolTempParent": str(temp),
                                                   "contexts": host_job.document_contexts(operation), "endpointPinBeforeObservation": None}
            owner.operation = operation
            owner.pins = [types.SimpleNamespace(directory=True, path=temp, current=lambda: None)]
            owner.by_path.update({str(Path(cold_cases.__file__).with_name(cold_cases.INPUT_LEAF)).casefold(): pin(raw, None),
                                  str(source).casefold(): pin(source.read_bytes(), source),
                                  guest.gui.casefold(): pin(b"MZ", guest.gui)})

            def module_peer(path, name):
                if path == DOCUMENT_CASES:
                    return types.SimpleNamespace(configure_launch=cold_cases.configure_launch, run=cold_cases.run, close_known=cold_cases.close_known)
                if path == "windows.py":
                    return windows
                return harness
            owner.module = module_peer
            return owner
        guest.owner = owner_with_inputs
        with mock.patch.object(cold_cases, "time", guest.clock), mock.patch.object(process_owner, "time", guest.clock):
            try:
                code = run_owner(process_owner, guest, "document-acceptance", None)
            except Parked:
                code = None
        return guest, code

    def test_each_variant_reopens_the_workspace_by_an_independent_owner_and_compares_its_export(self):
        for variant in cold_cases.VARIANTS:
            with self.subTest(variant=variant):
                guest, code = self.run_cold(variant)
                self.assertEqual((0, [], [(0, "NoneType", "None")]), (code, guest.parks, guest.finished))
                owner = guest.owner_object
                owners = guest.owners(str(guest.root / "workspace"))
                self.assertEqual(2, len(owners), "the original serve and one independent owner")
                self.assertEqual(variant == "gui-owner", owners[1].argv[0] == guest.gui)
                self.assertTrue(all(child.terminal is not None and child.terminal["exitCode"] == 0 for child in owner.children))
                first, second = guest.generations[owners[0].ordinal], guest.generations[owners[1].ordinal]
                self.assertEqual([first, second] + ([second] if variant == "gui-owner" else []), [controller for controller, _ in guest.exports][:1]
                                 + [controller for controller, _ in guest.exports][1:])
                self.assertEqual([first] + ([second] if variant == "gui-owner" else []), [controller for controller, _ in guest.imports])
                observed = dict(guest.events)["document-cold-observed"]
                self.assertEqual((variant, second, True, False), (observed["variant"], observed["controllerId"], observed["independentOwner"],
                                                                 observed["nativeAcceptanceComplete"]))
                self.assertEqual(["quit", "quit"], [row[0] for row in guest.trace if row[0] == "quit"], "the cases' quit and the owner's own")
                self.assertEqual(guest.owner_object.environment["TEMP"], str(guest.root / "document-temp"))

    def test_a_legacy_entry_is_many_domains_and_the_cold_read_keeps_them(self):
        guest, code = self.run_cold("legacy-newline")
        self.assertEqual(0, code)
        self.assertEqual(["alpha.legacy.invalid", "beta.legacy.invalid", "gamma.legacy.invalid", "delta.legacy.invalid",
                          "epsilon.legacy.invalid", "zeta.legacy.invalid", "eta.legacy.invalid"],
                         json.loads(Path(guest.exports[-1][1]).read_bytes())["rules"]["direct_domain_suffixes"])

    def test_an_export_that_differs_from_the_recipe_is_a_known_failure_that_closes_the_reopened_owner(self):
        for variant in cold_cases.VARIANTS:
            with self.subTest(variant=variant):
                def guest_change(guest):
                    guest.export_change = lambda raw, guest=guest: raw if len(guest.exports) < 1 else raw.replace(b'"d0000001', b'"d9999999').replace(
                        b'"beta.', b'"beta2.')
                guest, code = self.run_cold(variant, guest_change=guest_change)
                self.assertEqual((1, [], "document-cold-reopened-readback"), (code, guest.parks, guest.finished[0][2]))
                owner = guest.owner_object
                self.assertTrue(all(child.terminal is not None for child in owner.children))
                closing = [kind for kind, _ in guest.events if kind.startswith(("known-failure", "document-gui-owner"))]
                if variant == "gui-owner":
                    self.assertEqual(["document-gui-owner-quit-intent", "document-gui-owner-closed", "known-failure-closing",
                                      "known-failure-closed"], closing)
                else:
                    self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "known-failure-serve-closed",
                                      "known-failure-closed"], closing)
                self.assertEqual(2, len([row for row in guest.trace if row[0] == "quit"]), "one quit for each owner, never replayed")

    def test_a_refused_public_call_closes_what_is_running(self):
        def refuse_import(guest):
            original = guest.public

            def public(argv):
                if "import" in argv:
                    return 1, guest.envelope("INVALID_ARGUMENT", guest.generations[guest.serve_of(argv[2]).ordinal]), ""
                return original(argv)
            guest.public = public
        guest, code = self.run_cold("cold-reopen", guest_change=refuse_import)
        self.assertEqual((1, [], "AssertionError"), (code, guest.parks, guest.finished[0][1]))
        self.assertEqual(1, len([row for row in guest.trace if row[0] == "quit"]), "the closing's one quit of the original")

    def test_a_warm_mismatch_closes_the_original_before_any_reopen(self):
        guest, code = self.run_cold("cold-reopen", change=lambda literal: literal.update(expectedSemanticSha256="0" * 64))
        self.assertEqual((1, [], "document-cold-warm-readback"), (code, guest.parks, guest.finished[0][2]))
        self.assertEqual(1, len(guest.owners(str(guest.root / "workspace"))), "no owner was reopened")

    def test_a_literal_input_naming_another_operation_or_variant_refuses_before_any_effect(self):
        for change in (lambda literal: literal.update(operationId="33333333-4444-4555-8666-777777777777"),
                       lambda literal: literal.update(variant="cache-bytes"), lambda literal: literal.update(extra=True),
                       lambda literal: literal.update(routingInputPath="C:\\Windows\\win.ini")):
            guest, code = self.run_cold("cold-reopen", change=change)
            self.assertEqual((1, [], "document-cold-input-schema"), (code, guest.parks, guest.finished[0][2]))
            self.assertEqual([], guest.imports)

    def test_a_reopened_owner_that_never_answers_parks(self):
        def never_ready(guest):
            guest.serve_exits = True
            original = guest.public

            def public(argv):
                serve = guest.serve_of(argv[2])
                if list(argv[3:]) == ["--json", "status"] and serve is not None and serve.label in ("document-cold-serve", "document-gui-owner"):
                    return 2, guest.envelope("UNAVAILABLE", None), ""
                return original(argv)
            guest.public = public
        guest, code = self.run_cold("cold-reopen", guest_change=never_ready)
        self.assertEqual((None, "document-cold-reopened-owner-readiness-unknown"), (code, guest.parks[0][0]))

    def test_a_gui_owner_that_stays_after_its_acknowledged_quit_parks_within_the_bound(self):
        # On a pass the owner quits the GUI-started controller once. A GUI that then never ends is not awaited until
        # the row deadline: the owner parks after the same 120 s a known failure's closing allows, keeping every original.
        def gui_stays(guest):
            original = guest.outcome
            guest.outcome = lambda child: None if child.argv[0] == guest.gui else original(child)
        guest, code = self.run_cold("gui-owner", guest_change=gui_stays)
        # The real park never returns: only the first one counts.
        self.assertEqual((None, ("document-gui-owner-exit-unknown", None)), (code, guest.parks[0]))
        self.assertEqual(2, len([row for row in guest.trace if row[0] == "quit"]), "the case's quit of the original and one quit of the GUI")
        gui = next(child for child in guest.owner_object.children if child.argv[0] == guest.gui)
        self.assertIsNone(gui.terminal, "the GUI is left exactly as it is for reading the original")


if __name__ == "__main__":
    unittest.main()
