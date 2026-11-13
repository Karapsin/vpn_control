"""The native failure of the Windows document row (2026-11-09), as offline oracles.

windows-document-acceptance (operation 2df348bd, clone be766f0c, package 2.2.17 of 70ed16cc) ended
UNKNOWN, job_exit_unknown:owner-parked, and blocked its clone. Its owner recorded only
scenario-failure-with-retained-child and errorClass PermissionError while its serve ran. The last event
was the large-import readback; the parent race's two folders were left, with no moved folder and no
descriptor. So the harness's own export-race fixture was refused before the product's export child
started (fixtures/windows_document_native_failures/provenance.json names the lines that can raise it):

* the owner's park and known-failure records named only the error class, never the line or the code;
* a harness fixture step the OS refused parked the clone as if the product's state were unknown.

Each oracle runs the real owner main() with the inert guest, and the real race and Windows module over
logical Windows, listener and rename peers on real temporary folders. Each defect is RED on the preserved
f76e02fc bytes (*.before.source) and GREEN on the fix; the controls keep parking or refusing. No process,
listener, Win32 call or VM is involved.
"""
from __future__ import annotations

import contextlib
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock

from agent_tools import windows_document_client as client_module
from agent_tools import windows_document_export_race as export_race
from agent_tools import windows_document_native as document_native
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools.tests.test_windows_cli_native_failures import Clock, Parked, run_owner
from agent_tools.tests.test_windows_document_acceptance import CONTEXT, OWNER_ID, TOKEN, DocumentGuest, document_state

FIXTURES = Path(__file__).parent / "fixtures/windows_document_native_failures"
PROVENANCE = FIXTURES / "provenance.json"
RACE_SHA256 = "182d08b2f839519aeaced8dfeabb79d033bd96c4b1f62dd495fa4322a89b546e"
OWNER_SHA256 = "6f3b9e77d72c89e2167d427eebde0373e90bd00ac725a4f8aadcf0309e1b755d"
NATIVE_SHA256 = "ba23df4d014d0b131e2c7bb7b41b49816df3ca4b13fd8ff1430c293c1729bec9"
SID = "S-1-5-21-3748955661-2212578811-923230929-1004"
NT_OS = types.SimpleNamespace(name="nt", fsync=os.fsync)
REAL_RENAME = os.rename
SECRET = r"C:\Users\fixtureuser\private message text"


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
    return _load(test, (FIXTURES / "export-race-fixture.before.source").read_bytes(), "export-race-fixture.before.source", RACE_SHA256,
                 "_document_native_failure_before_race")


def before_owner(test):
    return _load(test, (FIXTURES / "owner-park-record.before.source").read_bytes(), "owner-park-record.before.source", OWNER_SHA256,
                 "_document_native_failure_before_owner")


def before_native(test):
    return _load(test, (FIXTURES / "document-native-fixture.before.source").read_bytes(), "document-native-fixture.before.source",
                 NATIVE_SHA256, "_document_native_failure_before_native")


def os_error(kind, number, winerror, text=SECRET):
    """An OS refusal as CPython raises it on Windows: errno from the C runtime map, winerror from Win32."""
    error = kind(number, text)
    error.winerror = winerror
    return error


def line_of(path, text):
    lines = [number for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1) if text in line]
    assert len(lines) == 1, (str(path), text, lines)
    return lines[0]


class World:
    """The race's Windows module, its loopback listener and its descriptor as logical peers on real folders."""

    def __init__(self):
        self.held, self.listeners, self.refused_opens = [], [], {}
        self.bind_refusal = self.create_refusal = self.on_create = None
        self.client = types.SimpleNamespace(guard=lambda: None, owner=OWNER_ID, original_sockets=[],
                                            last_exchange={"secondary": []}, transfers={},
                                            _endpoint={"port": 1, "controllerId": OWNER_ID, "token": TOKEN,
                                                       "documentTransfers": True})
        world = self

        class Held:
            """windows_document_native.Held as the cases use it, with its identity from lstat."""

            def __init__(self, native, path, directory=False, write=False, share=1):
                path = Path(path)
                if str(path) in world.refused_opens:
                    raise world.refused_opens[str(path)]
                info = path.lstat()
                self.path, self.directory, self.closed, self.handle = path, directory, False, len(world.held)
                self.access, self.share = 0x20080 if directory else 0x80020000 | (0x40000000 if write else 0), share
                self.open_error = None
                self.identity = {"volumeSerial": info.st_dev, "fileIndex": info.st_ino, "attributes": 16 if directory else 32}
                world.held.append(self)
                if native is not None:  # As the real Held retains itself on the owner's native provider.
                    if not hasattr(native, "document_retained_handles"):
                        native.document_retained_handles = []
                    native.document_retained_handles.append(self)

            def current(self, stable_content=True):
                return dict(self.identity)

            def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
                return self.path.read_bytes()

            def pin(self):
                return {"path": str(self.path), "nativeIdentity": self.current(), "security": {"ownerSid": SID},
                        "sha256": hashlib.sha256(self.path.read_bytes()).hexdigest()}

            def close(self):
                if self.closed:
                    raise RuntimeError("document-handle-already-closed")
                self.closed = True

        class Listener:
            """The relay's loopback listener: it binds, and accepts nothing."""

            def __init__(self, family, kind):
                self.closed = False
                world.listeners.append(self)

            def setsockopt(self, *option):
                pass

            def bind(self, address):
                if world.bind_refusal is not None:
                    raise world.bind_refusal

            def listen(self, backlog):
                pass

            def settimeout(self, seconds):
                pass

            def getsockname(self):
                return ("127.0.0.1", 49152)

            def accept(self):
                threading.Event().wait(0.01)
                raise socket.timeout()

            def close(self):
                self.closed = True

        self.Held = Held
        self.windows = self.provider(document_native)
        self.socket = types.SimpleNamespace(AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM, SOL_SOCKET=1,
                                            SO_EXCLUSIVEADDRUSE=-5, timeout=socket.timeout, socket=Listener)

    def provider(self, native):
        """The Windows module a race is handed: this world's handles and descriptor, that module's own refusal code.

        An unfixed module lacks the later functions; its race never asks for them.
        """
        return types.SimpleNamespace(
            Held=self.Held, NativeOpenError=document_native.NativeOpenError, create_sid_private_new=self.create,
            endpoint_private_acl=lambda native, handle, sid: {"ownerSid": sid, "aces": [], "ownerRead": True,
                                                              "otherPrincipalAllow": False},
            **{name: getattr(native, name, None) for name in ("fixture_refused", "refusal_evidence", "holder_census",
                                                              "rename_differential", "rename_control",
                                                              "root_rename_gate")})

    def create(self, native, path, data, sid):
        if self.on_create is not None:
            self.on_create()
        if self.create_refusal is not None:
            raise self.create_refusal
        with Path(path).open("xb") as output:
            output.write(data)


class RaceGuest(DocumentGuest):
    """The document guest whose export child, when one starts, exits before the relay's barrier."""

    def outcome(self, child):
        if child.label.startswith("document-public-export-race-"):
            return 2, "", ""
        return super().outcome(child)


class ParkWaitClock(Clock):
    """The owner's park waits forever after its record: its first wait ends the run here."""

    def sleep(self, seconds):
        raise Parked("owner-park-wait")


class OwnParkGuest(RaceGuest):
    """The guest whose owner keeps the module's own park, which writes owner-parked.json."""

    def __init__(self, root):
        super().__init__(root)
        self.clock = ParkWaitClock()

    def owner(self, module, action, situation):
        owner = super().owner(module, action, situation)
        del owner.park
        return owner


TRANSFER_LEAF = "vpn-control-transfer-11111111-2222-4333-8444-555555555555"


def retained_transfer(owner):
    """The transfer the row retains for its idle expiry, as the races find it: the serve's private transfer folder in
    the row's spool parent, <operation root>\\document-temp, which configure_launch pinned as owner.document_temp_pin."""
    spool = Path(owner.root) / "document-temp"
    spool.mkdir(exist_ok=True)
    (spool / TRANSFER_LEAF).mkdir(exist_ok=True)
    owner.document_temp_pin = types.SimpleNamespace(directory=True, path=spool, access=0x20080, share=3)
    return spool


def race_situation(world, race, mode="parent"):
    """The CLI cases' own call of one export race, with their client, their two observers and the retained transfer."""
    def situation(owner, workspace, identity, harness):
        document_state(owner)
        owner.document_client = world.client
        owner.request["context"]["ordinarySid"] = SID
        retained_transfer(owner)
        race.run_public_export_race(owner, workspace, identity, world.client, client_module, world.windows, harness, mode)
    return situation


def stop_relays(guest):
    for relay in getattr(guest.owner_object, "document_export_relays", []):
        relay.stop.set()


def quits(guest):
    return [row for row in guest.trace if row[0] == "quit"]


def exports(guest):
    return [child for child in guest.owner_object.children if child.label.startswith("document-public-export-race-")]


class Runs:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()  # The Windows module compares exact resolved paths.

    def run_owner(self, owner_module, situation, *, guest_class=RaceGuest, patches=()):
        guest = guest_class(Path(tempfile.mkdtemp(dir=self.root)))
        code = None
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            try:
                code = run_owner(owner_module, guest, "document-acceptance", situation)
            except Parked:
                pass
        self.addCleanup(stop_relays, guest)
        return guest, code

    def run_race(self, owner_module, race, renames, *, world=None, mode="parent", guest_class=RaceGuest, prepare=None):
        world = world or World()
        clock = Clock()
        # The script answers the probe's renames (an error is raised from the mock, None is a rename that took
        # place); every rename after it, such as the control's and the differential's, is the real one.
        patches = (mock.patch.object(race, "os", NT_OS), mock.patch.object(race, "socket", world.socket),
                   mock.patch.object(race, "time", clock),
                   mock.patch("os.rename", wraps=REAL_RENAME,
                              side_effect=itertools.chain(renames, itertools.repeat(mock.DEFAULT))))
        situation = race_situation(world, race, mode)
        if prepare is not None:
            inner = situation

            def situation(owner, workspace, identity, harness):
                prepare(owner, world)
                inner(owner, workspace, identity, harness)
        guest, code = self.run_owner(owner_module, situation, guest_class=guest_class, patches=patches)
        return guest, world, code

    def closed_known(self, guest, code, reason):
        """The owner's closing of a known failure: exit 1, one quit of its serve, every child terminal."""
        self.assertEqual((1, [], [(1, "RuntimeError", reason)]), (code, guest.parks, guest.finished))
        self.assertEqual(1, len(quits(guest)), "one quit, never replayed")
        self.assertTrue(all(child.terminal is not None for child in guest.owner_object.children))
        self.assertEqual(["known-failure-closing", "known-failure-quit-intent", "known-failure-serve-closed",
                          "known-failure-closed"], [kind for kind, _ in guest.events if kind.startswith("known-failure")])


def refusals(count, winerror=32):
    return [os_error(PermissionError, 13, winerror) for _ in range(count)]


class HarnessFixtureFailureTests(Runs, unittest.TestCase):
    """A harness fixture step the OS refused before the product took part is a known failure, not a park."""

    def test_a_refused_rename_probe_closes_as_the_named_harness_failure(self):
        # RED: the preserved owner and race park over the running serve, exactly as operation 2df348bd did.
        guest, _, code = self.run_race(before_owner(self), before_race(self), refusals(1))
        self.assertEqual((None, ("scenario-failure-with-retained-child", "PermissionError")), (code, guest.parks[0]))
        self.assertEqual(([], []), (quits(guest), exports(guest)))
        self.assertIsNone(next(child for child in guest.owner_object.children if child.label == "serve").terminal)
        # GREEN: six attempts of the harness's own probe, then the named known failure in both modes.
        for mode in ("parent", "destination"):
            with self.subTest(mode=mode):
                guest, world, code = self.run_race(process_owner, export_race, refusals(6), mode=mode)
                self.closed_known(guest, code, "document-race-fixture-refused:rename-away:32")
                probe = dict(guest.events)["document-race-rename-probe"]
                self.assertEqual((mode, False, False, False),
                                 (probe["mode"], probe["renamed"], probe["restored"], probe["productStarted"]))
                self.assertEqual([("rename-away", attempt, "PermissionError", 32, 13) for attempt in range(1, 7)],
                                 [(row["step"], row["attempt"], row["errorClass"], row["winerror"], row["errno"])
                                  for row in probe["attempts"]])
                self.assertEqual([0, 100, 350, 850, 1850, 3850], [row["elapsedMs"] for row in probe["attempts"]])
                self.assertEqual([], exports(guest), "the product's export child never started")
                self.assertFalse(hasattr(guest.owner_object, "document_export_relays"), "no relay listened")
                self.assertTrue(guest.owner_object.document_endpoint_handle.closed)

    def test_a_folder_held_only_briefly_is_renamed_on_a_later_attempt_and_every_attempt_is_recorded(self):
        def renames():
            return [os_error(PermissionError, 13, 32), os_error(PermissionError, 13, 5), None, None]
        guest, _, code = self.run_race(before_owner(self), before_race(self), renames())
        self.assertEqual(("scenario-failure-with-retained-child", []), (guest.parks[0][0], exports(guest)))  # RED
        guest, world, code = self.run_race(process_owner, export_race, renames())
        probe = dict(guest.events)["document-race-rename-probe"]
        self.assertEqual([("rename-away", 1, 32, 0), ("rename-away", 2, 5, 100), ("rename-away", 3, None, 350),
                          ("rename-back", 1, None, 0)],
                         [(row["step"], row["attempt"], row["winerror"], row["elapsedMs"]) for row in probe["attempts"]])
        self.assertEqual((True, True), (probe["renamed"], probe["restored"]))
        # The product's own step is never retried or relaxed: once its child started, any failure parks as before.
        self.assertEqual(1, len(exports(guest)))
        self.assertEqual(("document-public-export-race-unknown", "RuntimeError"), guest.parks[0])
        relay = guest.owner_object.document_export_relays[0]
        self.assertFalse(relay.stop.is_set(), "the relay is kept for the park")
        self.assertFalse(guest.owner_object.document_export_descriptor.closed, "the descriptor is kept for the park")
        self.assertEqual([], quits(guest))

    def test_a_refused_relay_listener_is_closed_and_known(self):
        world = World()
        world.bind_refusal = os_error(PermissionError, 13, 10013)
        guest, _, code = self.run_race(before_owner(self), before_race(self), [None, None], world=world)
        self.assertEqual((None, ("scenario-failure-with-retained-child", "PermissionError")), (code, guest.parks[0]))
        world = World()
        world.bind_refusal = os_error(PermissionError, 13, 10013)
        guest, world, code = self.run_race(process_owner, export_race, [None, None], world=world)
        self.closed_known(guest, code, "document-race-fixture-refused:relay-listen:10013")
        relay, = guest.owner_object.document_export_relays
        self.assertTrue(relay.stop.is_set() and world.listeners[0].closed and relay.thread.ident is None,
                        "stopped, its listener closed, its accept thread never started")
        self.assertEqual([], exports(guest))

    def test_a_refused_descriptor_closes_the_listening_relay_first(self):
        def descriptor_refusal(world, guest_root):
            world.refused_opens[str(guest_root / "document-export-client-parent" / "activation.port")] = \
                document_native.NativeOpenError(32)
        cases = {"document-private-create-new": lambda world, root: setattr(world, "create_refusal",
                                                                             RuntimeError("document-private-create-new")),
                 "document-race-fixture-refused:descriptor-hold:32": descriptor_refusal}
        for reason, change in cases.items():
            with self.subTest(reason=reason):
                world = World()
                guest, _, code = self.run_race(before_owner(self), before_race(self), [None, None], world=world,
                                               prepare=lambda owner, world: change(world, Path(owner.root)))
                self.assertEqual("scenario-failure-with-retained-child", guest.parks[0][0])  # RED: the relay ran on.
                self.assertFalse(guest.owner_object.document_export_relays[0].stop.is_set())
                world = World()
                guest, world, code = self.run_race(process_owner, export_race, [None, None], world=world,
                                                   prepare=lambda owner, world: change(world, Path(owner.root)))
                self.closed_known(guest, code, reason)
                relay, = guest.owner_object.document_export_relays
                self.assertTrue(relay.stop.is_set() and not relay.thread.is_alive() and world.listeners[0].closed)
                self.assertTrue(all(held.closed for held in world.held), "the probe and any descriptor handle")
                self.assertEqual([], exports(guest))

    def test_what_is_not_a_harness_os_refusal_keeps_its_old_end(self):
        # A refusal that is not 5 or 32 is never retried: one attempt, then the named failure.
        guest, _, code = self.run_race(process_owner, export_race, [os_error(FileExistsError, 17, 183)])
        self.closed_known(guest, code, "document-race-fixture-refused:rename-away:183")
        self.assertEqual(1, len(dict(guest.events)["document-race-rename-probe"]["attempts"]))
        # A relay that cannot be closed (something connected) parks with everything kept.
        world = World()
        world.create_refusal = RuntimeError("document-private-create-new")

        def connected(owner, world):
            world.on_create = lambda: owner.document_export_relays[-1].connections.append("original socket")
        guest, _, code = self.run_race(process_owner, export_race, [None, None], world=world, prepare=connected)
        self.assertEqual((None, ("document-race-fixture-closing-unknown", "RuntimeError")), (code, guest.parks[0]))
        self.assertEqual([], quits(guest))
        # A refusal that is not the OS's, such as the owner's native identity check, parks as before.
        world = World()

        def refused_identity(owner, world):
            world.refused_opens[str(Path(owner.root) / "document-race-parent" / "parent")] = \
                process_owner.Refused("native-file-information")
        guest, _, code = self.run_race(process_owner, export_race, [], world=world, prepare=refused_identity)
        self.assertEqual((None, "scenario-failure-with-retained-child"), (code, guest.parks[0][0]))
        self.assertEqual([], quits(guest))

    def persistence_situation(self, world, native):
        def situation(owner, workspace, identity, harness):
            document_state(owner)
            owner.document_client = world.client
            workspace = Path(workspace)
            workspace.mkdir()
            (workspace / "workspace.json").write_bytes(b'{"persisted_state": {}}\n')
            owner.document_workspace_handle = world.Held(None, workspace, directory=True)
            native.persistence_fault(owner, workspace, world.client, client_module, "doc-persist-" + CONTEXT, CONTEXT,
                                     {"configurationRevision": 43}, 8)
        return situation

    def run_persistence(self, owner_module, native, step):
        world, real_open = World(), Path.open

        def refusing_open(path, mode="r", *args, **kwargs):
            if path.name == "workspace-recovery.json" and mode == "xb":
                raise os_error(PermissionError, 13, 5)
            return real_open(path, mode, *args, **kwargs)
        patches = [mock.patch.object(native, "os", NT_OS), mock.patch.object(native, "Held", world.Held)]
        if step == "recovery-create":
            patches.append(mock.patch.object(Path, "open", refusing_open))
        situation = self.persistence_situation(world, native)

        def refusing(owner, workspace, identity, harness):
            names = {"primary-hold": "workspace.json", "recovery-hold": "workspace-recovery.json"}
            if step in names:
                world.refused_opens[str(Path(workspace) / names[step])] = document_native.NativeOpenError(32)
            situation(owner, workspace, identity, harness)
        guest, code = self.run_owner(owner_module, refusing, patches=patches)
        return guest, world, code

    def test_a_refused_persistence_fixture_releases_its_holds_and_closes_known(self):
        for step, code_text in (("primary-hold", "32"), ("recovery-create", "5"), ("recovery-hold", "32")):
            with self.subTest(step=step):
                guest, world, code = self.run_persistence(before_owner(self), before_native(self), step)
                self.assertEqual((None, "scenario-failure-with-retained-child"), (code, guest.parks[0][0]))  # RED
                if step != "primary-hold":
                    self.assertFalse(world.held[1].closed, "RED: the primary stayed held through the park")
                guest, world, code = self.run_persistence(process_owner, document_native, step)
                self.closed_known(guest, code, "document-persistence-fixture-refused:%s:%s" % (step, code_text))
                self.assertTrue(all(held.closed for held in world.held), "nothing of the fixture is held at the quit")
                self.assertFalse(hasattr(guest.owner_object, "document_persistence_fault"))

    def test_a_refused_export_parent_hold_is_known(self):
        def situation_for(native):
            world = World()

            def situation(owner, workspace, identity, harness):
                document_state(owner)
                owner.document_client = world.client
                world.refused_opens[str(owner.root)] = document_native.NativeOpenError(5)
                native.private_export_no_overwrite(owner, workspace, identity, Path(owner.root) / "document export 東京.json",
                                                   harness)
            return situation, [mock.patch.object(native, "os", NT_OS), mock.patch.object(native, "Held", world.Held)]
        situation, patches = situation_for(before_native(self))
        guest, code = self.run_owner(before_owner(self), situation, patches=patches)
        self.assertEqual((None, "scenario-failure-with-retained-child"), (code, guest.parks[0][0]))  # RED
        situation, patches = situation_for(document_native)
        guest, code = self.run_owner(process_owner, situation, patches=patches)
        self.closed_known(guest, code, "document-export-fixture-refused:parent-hold:5")

    def test_fixture_refused_names_only_os_refusals(self):
        refused = document_native.fixture_refused
        self.assertEqual("document-race-fixture-refused:mkdir-parent:183",
                         str(refused("race", "mkdir-parent", os_error(FileExistsError, 17, 183))))
        self.assertEqual("document-race-fixture-refused:probe-open:5",
                         str(refused("race", "probe-open", document_native.NativeOpenError(5))))
        self.assertEqual("document-race-fixture-refused:mkdir-proxy:errno-13",
                         str(refused("race", "mkdir-proxy", PermissionError(13, SECRET))))
        for error in (RuntimeError("document-x"), process_owner.Refused("native-file-information"), ValueError("x")):
            self.assertIs(error, refused("race", "probe-open", error))


class FailureDetailTests(Runs, unittest.TestCase):
    """Every park and known-failure record names the class, the Win32 and errno codes and the failing lines."""

    def test_a_park_names_the_failing_line_and_its_win32_code(self):
        line = "export-race-fixture.before.source:%d" % line_of(FIXTURES / "export-race-fixture.before.source",
                                                       "parent.rename(renamed); renamed.rename(parent)")

        def oracle(owner_module):
            guest, world, code = self.run_race(owner_module, before_race(self), refusals(1), guest_class=OwnParkGuest)
            raw = (guest.root / "owner-parked.json").read_bytes()
            record = json.loads(raw)
            self.assertEqual(("scenario-failure-with-retained-child", "PermissionError"), (record["reason"], record["errorClass"]))
            self.assertIn("failure", record)
            failure = record["failure"]
            self.assertEqual(("PermissionError", 32, 13, None), (failure["errorClass"], failure["winerror"], failure["errno"],
                                                                  failure["cause"]))
            self.assertEqual(line, failure["frames"][-1], "the innermost frame is the native failure's own line")
            self.assertTrue(all(re.fullmatch(r"[^/\\:]+:[0-9]+", frame) for frame in failure["frames"]))
            self.assertLessEqual({frame.rpartition(":")[0] for frame in failure["frames"]},
                                 {"windows_ordinary_process_owner.py", "test_windows_document_native_failures.py",
                                  "export-race-fixture.before.source"}, "no standard-library frame")
            self.assertNotIn(b"private message text", raw)
            self.assertNotIn(b"fixtureuser", raw)
        with self.assertRaises(AssertionError):
            oracle(before_owner(self))  # RED: the native record named only the class.
        oracle(process_owner)

    def test_a_known_failure_records_its_frames_and_the_refused_call(self):
        race_file = Path(export_race.__file__).name

        def oracle(owner_module):
            guest, world, code = self.run_race(owner_module, export_race, refusals(6))
            closing = dict(guest.events)["known-failure-closing"]
            self.assertIn("failure", closing)
            failure = closing["failure"]
            self.assertEqual(("RuntimeError", None, None), (failure["errorClass"], failure["winerror"], failure["errno"]))
            self.assertEqual("%s:%d" % (race_file, line_of(export_race.__file__, "raise known from error")), failure["frames"][-1])
            self.assertEqual({"errorClass": "PermissionError", "winerror": 32, "errno": 13,
                              "frames": ["%s:%d" % (race_file, line_of(export_race.__file__, '"rename-away", parent; rename_probe(')),
                                         "%s:%d" % (race_file, line_of(export_race.__file__, "source.rename(target)"))]},
                             failure["cause"])
            self.assertNotIn("private message text", json.dumps(closing))
        with self.assertRaises(AssertionError):
            oracle(before_owner(self))  # RED: the closing named only the class.
        oracle(process_owner)

    def test_a_raw_capture_park_names_the_streams_own_error(self):
        def oracle(owner_module):
            parks = []
            error = os_error(BrokenPipeError, 32, 109)
            child = types.SimpleNamespace(terminal=None, errors={"stdout": {"errorClass": "BrokenPipeError", "message": SECRET,
                                                                           "error": error}},
                                          owner=types.SimpleNamespace(park=lambda reason, value: parks.append((reason, value))),
                                          process=types.SimpleNamespace(poll=lambda: None), eof={"stdout": False, "stderr": False})
            owner_module.Child.observe(child)
            self.assertEqual([("raw-capture-unknown", error)], parks)
        with self.assertRaises(AssertionError):
            oracle(before_owner(self))  # RED: the park named a dict.
        oracle(process_owner)

    def test_the_record_is_finite_private_and_never_raises(self):
        detail = process_owner.failure_detail

        def deep(count):
            if count:
                return deep(count - 1)
            raise os_error(ConnectionResetError, 54, 10054)
        try:
            deep(30)
        except OSError as error:
            value = detail(error)
        here = Path(__file__).name
        self.assertEqual(process_owner.FAILURE_FRAMES, len(value["frames"]))
        self.assertEqual({here}, {frame.rpartition(":")[0] for frame in value["frames"]})
        self.assertEqual(("ConnectionResetError", 10054, 54), (value["errorClass"], value["winerror"], value["errno"]))
        self.assertNotIn("private message text", json.dumps(value))
        try:
            json.loads("{" + SECRET)  # Raised inside the standard library: only this module's frame is named.
        except ValueError as error:
            value = detail(error)
        self.assertEqual(("JSONDecodeError", 1, None, None), (value["errorClass"], len(value["frames"]), value["winerror"],
                                                              value["cause"]))
        self.assertNotIn("private", json.dumps(value))
        try:
            try:
                raise os_error(PermissionError, 13, 32)
            except OSError as error:
                raise RuntimeError("document-x") from error
        except RuntimeError as error:
            self.assertEqual((32, 1), (detail(error)["cause"]["winerror"], len(detail(error)["cause"]["frames"])))
            self.assertNotIn("cause", detail(error)["cause"], "one level deep")
        try:
            try:
                raise KeyError(SECRET)
            except KeyError:
                raise RuntimeError("while handling")
        except RuntimeError as error:
            self.assertEqual("KeyError", detail(error)["cause"]["errorClass"])
        try:
            try:
                raise KeyError(SECRET)
            except KeyError:
                raise RuntimeError("suppressed") from None
        except RuntimeError as error:
            self.assertIsNone(detail(error)["cause"])
        self.assertEqual({"errorClass": "dict", "winerror": None, "errno": None, "frames": [], "cause": None},
                         detail({"phase": SECRET}))
        self.assertIsNone(detail(None))

        class Hostile(Exception):
            @property
            def winerror(self):
                raise ValueError("no")
        self.assertEqual({"errorClass": "Hostile", "detailUnavailable": "ValueError"}, detail(Hostile()))


if __name__ == "__main__":
    unittest.main()
