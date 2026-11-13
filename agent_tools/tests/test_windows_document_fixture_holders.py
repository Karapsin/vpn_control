"""The second native failure of the Windows document row (2026-11-09), as offline oracles.

windows-document-acceptance (direct run 83484649, clone ea86866f, package 2.2.17 discovery build, the
tools of 9761f1d3) no longer parked: its rename probe was refused on all six attempts over 3.9 s with a
sharing violation, and the row closed as document-race-fixture-refused:rename-away:32. The first run
(2df348bd, another clone) had stopped at the same rename. So nothing was passing by. By the product source
the holder is the product's own serve: every transfer pins each ancestor of its spool folder, the operation
root among them, with LIST_DIRECTORY and read sharing only, and the row retains one transfer for its idle
expiry before the races. A rename by path opens the folder of the new name for write access, which such a
pin refuses, and the probe renamed a direct child of the operation root.

* the race's fixture lay directly in the operation root, where no rename by path can succeed while a
  transfer lives: its positive control could never pass, and a refusal in the race itself would not have
  been the public writer's own;
* a refused fixture step named its code, but not who held the folder, nor where a rename would work.

The world here is that reading as a model: directory opens with their access and sharing, judged as
IoCheckShareAccess judges them, and the kernel's answers to a holder census from the same table. Each
oracle runs the real owner main() and race with the inert guest. Each is RED on the preserved 529cc610
bytes (fixtures/windows_document_fixture_holders/*.before.source), the bytes that ran, and GREEN on the
fix. No process, listener, Win32 call or VM is involved.

The product has since been changed to share writes on those folder pins, and the root control became a
gate on that (RootGateTests, RED on the race and native module of 245b61a7, which let the row pass). The
world models both: folder_share PACKAGE_SHARE as the package that ran, FIXED_SHARE with the fix.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import types
import unittest
from unittest import mock

from agent_tools import windows_document_client as client_module
from agent_tools import windows_document_export_race as export_race
from agent_tools import windows_document_native as document_native
from agent_tools import windows_ordinary_process_owner as process_owner
from agent_tools.tests.test_windows_cli_native_failures import Clock, held_harness
from agent_tools.tests.test_windows_document_acceptance import CONTEXT, DocumentGuest, document_state
from agent_tools.tests.test_windows_document_native_failures import (NT_OS, REAL_RENAME, SID, TRANSFER_LEAF, Runs, World,
                                                                    exports, os_error, quits, retained_transfer)

FIXTURES = Path(__file__).parent / "fixtures/windows_document_fixture_holders"
PROVENANCE = FIXTURES / "provenance.json"
RACE_SHA256 = "c7f8fa9b67804f20e1c0957fff33a468d0a6e3f40af72915251db9523deb6ac9"
NATIVE_SHA256 = "92b31869334d61ff4899c42d34328176bf41718c1d65c12fd87dc328c7e4281b"
OWNER_SHA256 = "565131c840e6ceccbde67bc01981c05a00eafb49663a2767c5f34f3696d97a00"
WORKER, TASK_OWNER, SCANNER = 4321, 4000, 7777
LAUNCHER = "vpn-control-cli.exe"
REFUSED = "document-race-fixture-refused:rename-away:32"
ROOT_REFUSED = "document-race-root-rename-refused:rename-away:32"
OK = {"errorClass": None, "winerror": None, "errno": None}
SHARING = {"errorClass": "PermissionError", "winerror": 32, "errno": 13}
# How the serve's pins share a folder they hold: the 2.2.17 package of runs 2df348bd and 83484649 shared
# read only; the product with the folder-pin fix shares read and write. Neither ever shares delete.
PACKAGE_SHARE, FIXED_SHARE = 1, 3


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
    return _load(test, (FIXTURES / "export-race-root-fixture.before.source").read_bytes(),
                 "export-race-root-fixture.before.source", RACE_SHA256, "_document_holders_before_race")


def before_native(test):
    return _load(test, (FIXTURES / "document-native-no-holders.before.source").read_bytes(),
                 "document-native-no-holders.before.source", NATIVE_SHA256, "_document_holders_before_native")


def before_owner(test):
    return _load(test, (FIXTURES / "owner-pin-modes.before.source").read_bytes(), "owner-pin-modes.before.source",
                 OWNER_SHA256, "_document_holders_before_owner")


def steps(*rows):
    """The recorded steps of one differential variant: a name alone took place, a name with a dict was refused so."""
    return [{"step": row, **OK} if type(row) is str else {"step": row[0], **row[1]} for row in rows]


class PinnedWorld(World):
    """The first world plus Windows' share rules for a rename by path and the kernel's answers to a holder census.

    folder_share is how the product's folder pins share: PACKAGE_SHARE as the package that ran, FIXED_SHARE with
    the folder-pin fix.
    """

    def __init__(self, user_temp, folder_share=PACKAGE_SHARE):
        super().__init__()
        self.folder_share = folder_share
        self.opens, self.processes, self.renames = [], {}, []
        self.os = types.SimpleNamespace(name="nt", fsync=os.fsync, environ={"TEMP": str(user_temp)},
                                        getpid=lambda: WORKER, getppid=lambda: TASK_OWNER)
        world = self

        class Reader:
            """HolderNative's answers, from the same table of opens that the renames are judged by."""

            def __init__(self, native):
                pass

            def holders(self, path):
                if not Path(path).exists():
                    return "open-refused:2", []
                # Every open handle counts, whatever its access; the read's own handle is the worker's.
                return "ok", sorted({row["pid"] for row in world.opens if row["path"] == str(path)} | {WORKER})

            def process(self, pid):
                return dict(world.processes.get(pid, {"image": None, "parentPid": None, "birth": None, "openError": 87}))

        self.Reader = Reader

    def hold(self, path, pid, access="r", share=1, checks=None):
        """One open handle on a folder: its data access (r, w, d; none for attributes only), its sharing bits,
        and for a holder that is only passing by, how many renames it stays for."""
        self.opens.append({"path": str(path), "pid": pid, "access": access, "share": share, "checks": checks})

    def release(self, pid):
        self.opens = [row for row in self.opens if row["pid"] != pid]

    def refused(self, path, access, share):
        """IoCheckShareAccess: the new open's access against each holder's sharing, and theirs against its own.

        A handle with attribute access only is not counted, in either direction.
        """
        bits = {"r": 1, "w": 2, "d": 4}
        return any(row["path"] == str(path) and row["access"]
                   and (any(not row["share"] & bits[kind] for kind in access)
                        or any(not share & bits[kind] for kind in row["access"])) for row in self.opens)

    def rename(self, source, target):
        """MoveFileExW: the old name is opened with DELETE and every sharing, then the folder of the new name
        for write access, sharing read and write. Either open can end in a sharing violation."""
        source, target = Path(source), Path(target)
        refused = self.refused(source, "d", 7) or self.refused(target.parent, "w", 3)
        self.renames.append((source.name, target.parent.name, refused))
        for row in self.opens:
            if row["checks"] is not None:
                row["checks"] -= 1
        self.opens = [row for row in self.opens if row["checks"] is None or row["checks"] > 0]
        if refused:
            raise os_error(PermissionError, 13, 32)
        REAL_RENAME(source, target)

    def admit(self, owner, *, transfer=True):
        """The row as the races find it. The worker, the serve's launcher and its JVM have the operation root
        as their current directory (traverse access, sharing read and write); the task parent and the worker
        pin it with attribute access only. While a transfer lives, the serve's JVM also pins it as
        DesktopWindowsTransferPins does: LIST_DIRECTORY, sharing as folder_share says, and its private
        transfer folder exists in the row's spool parent, <operation root>\\document-temp."""
        root = Path(owner.root)
        serve = next(child for child in owner.children if child.label == "serve")
        jvm = serve.pid + 1
        self.processes.update({
            WORKER: {"image": "python.exe", "parentPid": TASK_OWNER, "birth": "100", "openError": None},
            TASK_OWNER: {"image": "powershell.exe", "parentPid": 900, "birth": "90", "openError": None},
            serve.pid: {"image": LAUNCHER, "parentPid": WORKER, "birth": serve.birth, "openError": None},
            jvm: {"image": LAUNCHER, "parentPid": serve.pid, "birth": "200", "openError": None},
            SCANNER: {"image": "MsMpEng.exe", "parentPid": None, "birth": None, "openError": 5}})
        self.hold(root, TASK_OWNER, "", 3)
        for pid in (WORKER, serve.pid, jvm):
            self.hold(root, pid, "r", 3)
        if transfer:
            self.hold(root, jvm, "r", self.folder_share)
            retained_transfer(owner)
        else:
            spool = root / "document-temp"
            spool.mkdir(exist_ok=True)
            owner.document_temp_pin = types.SimpleNamespace(directory=True, path=spool, access=0x20080, share=3)
        owner.pins = [types.SimpleNamespace(directory=True, path=root, access=0x20080, share=3),
                      types.SimpleNamespace(directory=False, path=root / "worker-request.json", access=0x80020000, share=1)]
        return serve, jvm


class WriterGuest(DocumentGuest):
    """The document guest whose export child is the public writer as the product source has it.

    It pins its destination folder and that folder's ancestors up to the operation root, makes its partial
    there and asks for its first chunk. Once released it publishes by a leaf rename, which reopens no folder,
    or answers PERSISTENCE_FAILED when the name is taken, and exits.
    """

    def __init__(self, root, world):
        super().__init__(root)
        self.world, self.writers = world, {}

    def outcome(self, child):
        if not child.label.startswith("document-public-export-race-"):
            return super().outcome(child)
        relay, destination = self.owner_object.document_export_relay, Path(child.argv[-1])
        writer = self.writers.setdefault(child.ordinal, {})
        if not writer:
            jvm = child.pid + 1
            self.world.processes.update({
                child.pid: {"image": LAUNCHER, "parentPid": WORKER, "birth": child.birth, "openError": None},
                jvm: {"image": LAUNCHER, "parentPid": child.pid, "birth": "300", "openError": None}})
            for folder in (destination.parent, destination.parent.parent, self.root):
                self.world.hold(folder, jvm, "r", self.world.folder_share)
            partial = destination.parent / ".vpn-export-11111111-2222-4333-8444-555555555555.partial"
            partial.write_bytes(b"{}")
            writer.update(jvm=jvm, partial=partial)
            relay.barrier.set()
            return None
        if not relay.release.is_set():
            return None
        self.world.release(writer["jvm"])
        if destination.exists():
            writer["partial"].unlink()
            return 1, self.envelope("PERSISTENCE_FAILED", child.argv[5]), ""
        REAL_RENAME(writer["partial"], destination)
        return 0, self.envelope("OK", child.argv[5], {"bytes": 2}), ""


def race_row(world, race, provider, *, modes=("parent", "destination"), transfer=True, before=None):
    """The CLI cases' two export races in their order, with what the serve holds while a transfer is retained."""
    def situation(owner, workspace, identity, harness):
        document_state(owner)
        owner.document_client = world.client
        owner.request["context"]["ordinarySid"] = SID
        world.admit(owner, transfer=transfer)
        if before is not None:
            before(owner)
        held = held_harness()
        for mode in modes:
            race.run_public_export_race(owner, workspace, identity, world.client, client_module, provider, held, mode)
    return situation


def events(guest, kind):
    return [value for name, value in guest.events if name == kind]


class HolderRuns(Runs):
    def setUp(self):
        super().setUp()
        self.temp = self.root / "user temp"
        self.temp.mkdir()

    def run_world(self, owner_module, race, native, situation_for, *, world=None, folder_share=PACKAGE_SHARE, **options):
        world = world or PinnedWorld(self.temp, folder_share)
        patches = [mock.patch.object(race, "os", NT_OS), mock.patch.object(race, "socket", world.socket),
                   mock.patch.object(race, "time", Clock()), mock.patch("os.rename", world.rename),
                   mock.patch.object(native, "os", world.os), mock.patch.object(native, "Held", world.Held)]
        if hasattr(native, "HolderNative"):
            patches.append(mock.patch.object(native, "HolderNative", world.Reader))
        guest, code = self.run_owner(owner_module, situation_for(world, race, world.provider(native), **options),
                                     guest_class=lambda root: WriterGuest(root, world), patches=patches)
        return guest, world, code

    def base(self):
        return before_owner(self), before_race(self), before_native(self)

    def fixed(self):
        return process_owner, export_race, document_native


class NestedStageTests(HolderRuns, unittest.TestCase):
    """The race's fixture has a stage of its own, where only the public writer's pins can refuse a rename."""

    def test_the_probe_passes_in_its_stage_while_the_serve_pins_the_operation_root(self):
        # RED: the bytes that ran, with the transfer the row retains: the native record of run 83484649.
        guest, world, code = self.run_world(*self.base(), race_row)
        self.assertEqual((1, [], [(1, "RuntimeError", REFUSED)]), (code, guest.parks, guest.finished))
        probe, = events(guest, "document-race-rename-probe")
        self.assertEqual([("rename-away", attempt, 32, 13) for attempt in range(1, 7)],
                         [(row["step"], row["attempt"], row["winerror"], row["errno"]) for row in probe["attempts"]])
        self.assertEqual([0, 100, 350, 850, 1850, 3850], [row["elapsedMs"] for row in probe["attempts"]])
        self.assertEqual({("document-race-parent", guest.root.name, True)}, set(world.renames),
                         "each attempt renamed a direct child of the operation root")
        self.assertEqual([], exports(guest))
        # The same bytes pass when no transfer lives: the serve's pin is what refuses them.
        guest, world, code = self.run_world(*self.base(), race_row, transfer=False)
        self.assertEqual((0, [], [0, 1]), (code, guest.parks, [child.terminal["exitCode"] for child in exports(guest)]))
        # GREEN: with the transfer retained, both probes pass at once and both races run to their ends (with a
        # product whose pins share writes: RootGateTests shows the row on the package that ran).
        guest, world, code = self.run_world(*self.fixed(), race_row, folder_share=FIXED_SHARE)
        self.assertEqual((0, [], [(0, "NoneType", "None")]), (code, guest.parks, guest.finished))
        probes = events(guest, "document-race-rename-probe")
        self.assertEqual([("parent", True, True), ("destination", True, True)],
                         [(row["mode"], row["renamed"], row["restored"]) for row in probes])
        self.assertEqual([[("rename-away", 1, None), ("rename-back", 1, None)]] * 2,
                         [[(row["step"], row["attempt"], row["winerror"]) for row in probe["attempts"]] for probe in probes])
        self.assertEqual([{"win32Error": 32, "positiveRenameBeforeProduct": True, "harnessParentHandleHeld": False}],
                         events(guest, "document-parent-race-refused"), "refused by the public writer's own pin")
        self.assertEqual(1, len(events(guest, "document-racing-destination-created")))
        self.assertEqual([("parent", "OK"), ("destination", "PERSISTENCE_FAILED")],
                         [(row["mode"], row["code"]) for row in events(guest, "document-public-export-race-complete")])
        self.assertEqual([0, 1], [child.terminal["exitCode"] for child in exports(guest)])
        self.assertEqual(1, len(quits(guest)), "the pass's own quit")
        probe_renames = [row for row in world.renames if row[0] in ("parent", "moved")]
        self.assertTrue(all(folder.startswith("document-race-") for _, folder, _ in probe_renames),
                        "no probe or race rename has the operation root as the folder of its new name")
        self.assertEqual([False, False, True, False, False], [refused for _, _, refused in probe_renames],
                         "the two parent probes pass, the race's own rename is refused, the destination probes pass")

    def test_the_stage_keeps_the_fixture_out_of_every_folder_the_serve_pins(self):
        guest, world, code = self.run_world(*self.fixed(), race_row, folder_share=FIXED_SHARE)
        root = guest.root
        for mode in ("parent", "destination"):
            stage = root / ("document-race-" + mode)
            self.assertEqual(["parent"], sorted(path.name for path in stage.iterdir()))
            self.assertTrue((stage / "parent" / "routing 東京 export.json").is_file())
            self.assertEqual(["activation.port"], sorted(path.name for path in (root / ("document-export-client-" + mode)).iterdir()))
        self.assertEqual([], sorted(path.name for path in root.iterdir() if "control" in path.name or "differential" in path.name))

class RootGateTests(HolderRuns, unittest.TestCase):
    """The root control is a gate on the product: while the serve holds its transfer, the root takes renames.

    The serve pins its spool parent and every ancestor, the operation root among them, while a transfer lives.
    The 2.2.17 package pinned them with read sharing only, so every rename by path into them failed, by any
    program. RED on the bytes before the gate (245b61a7): the control was recorded and the row went on, so a
    package that refused every rename into the root passed the row (exit 0), and one with no live transfer
    passed it too, having shown nothing.
    """

    def test_the_root_gate_ends_the_row_known_when_the_serve_refuses_renames_into_the_operation_root(self):
        guest, world, code = self.run_world(*self.fixed(), race_row)  # the package that ran: read sharing only
        self.assertEqual((1, [], [(1, "RuntimeError", ROOT_REFUSED)]), (code, guest.parks, guest.finished))
        probe, = events(guest, "document-race-rename-probe")
        self.assertEqual((True, True), (probe["renamed"], probe["restored"]), "the stage's own probe passed first")
        self.assertEqual([{"fixture": "race", "token": "race-parent", "leaf": guest.root.name, "controlError": None,
                           "steps": steps("mkdir", ("rename-away", SHARING), "rmdir")}],
                         events(guest, "document-fixture-rename-control"))
        serve = next(child for child in guest.owner_object.children if child.label == "serve")
        census, = events(guest, "document-fixture-holder-census")
        self.assertEqual(("race", "rename-control", "control", 32, None),
                         (census["fixture"], census["step"], census["moment"], census["winerror"], census["censusError"]))
        self.assertEqual([{"role": "parent", "leaf": guest.root.name, "status": "ok", "holderCount": 4, "holders": [
            {"pid": TASK_OWNER, "image": "powershell.exe", "role": "task-owner", "child": None, "parentPid": 900, "openError": None},
            {"pid": WORKER, "image": "python.exe", "role": "worker", "child": None, "parentPid": TASK_OWNER, "openError": None},
            {"pid": serve.pid, "image": LAUNCHER, "role": "serve", "child": serve.ordinal, "parentPid": WORKER, "openError": None},
            {"pid": serve.pid + 1, "image": LAUNCHER, "role": "serve-child", "child": serve.ordinal, "parentPid": serve.pid,
             "openError": None}]}], census["targets"])
        handles = census["harnessHandles"]
        self.assertEqual((0, 1, [{"path": str(guest.root), "access": 0x20080, "share": 3}]),
                         (handles["retainedOpen"], handles["directoryPinCount"], handles["directoryPins"]))
        self.assertNotIn("command", json.dumps(census).lower())
        self.assertEqual([{"fixture": "race", "token": "race-parent", "leaf": guest.root.name, "spoolKnown": True,
                           "transfersBefore": 1, "transfersAfter": 1, "transferHeldThroughout": True, "passed": False,
                           "code": ROOT_REFUSED}], events(guest, "document-fixture-rename-gate"))
        self.assertEqual([], exports(guest), "the product's race never started")
        self.assertEqual(1, len(quits(guest)), "the known failure's closing quit the serve")
        self.assertEqual([], [path.name for path in guest.root.iterdir() if "control" in path.name])

    def test_the_root_gate_passes_while_the_serve_holds_its_transfer_and_shares_writes(self):
        guest, world, code = self.run_world(*self.fixed(), race_row, folder_share=FIXED_SHARE)
        self.assertEqual((0, [], [(0, "NoneType", "None")]), (code, guest.parks, guest.finished))
        self.assertEqual([steps("mkdir", "rename-away", "rename-back", "rmdir")] * 2,
                         [row["steps"] for row in events(guest, "document-fixture-rename-control")])
        self.assertEqual([("race-" + mode, 1, 1, True, True, None) for mode in ("parent", "destination")],
                         [(row["token"], row["transfersBefore"], row["transfersAfter"], row["transferHeldThroughout"],
                           row["passed"], row["code"]) for row in events(guest, "document-fixture-rename-gate")])
        self.assertEqual([], events(guest, "document-fixture-holder-census"))
        self.assertEqual([("parent", "OK"), ("destination", "PERSISTENCE_FAILED")],
                         [(row["mode"], row["code"]) for row in events(guest, "document-public-export-race-complete")])
        self.assertEqual([(name + suffix, guest.root.name, False) for name in ("document-race-parent-control",
                          "document-race-destination-control") for suffix in ("", "-moved")],
                         [row for row in world.renames if "control" in row[0]], "renamed away and back into the root")

    def test_a_root_that_renames_without_a_live_transfer_proves_nothing(self):
        for share in (PACKAGE_SHARE, FIXED_SHARE):
            with self.subTest(folder_share=share):
                guest, world, code = self.run_world(*self.fixed(), race_row, transfer=False, folder_share=share)
                self.assertEqual((1, [], [(1, "RuntimeError", "document-race-root-control-without-transfer")]),
                                 (code, guest.parks, guest.finished))
                self.assertEqual([steps("mkdir", "rename-away", "rename-back", "rmdir")],
                                 [row["steps"] for row in events(guest, "document-fixture-rename-control")])
                gate, = events(guest, "document-fixture-rename-gate")
                self.assertEqual((0, 0, False, False), (gate["transfersBefore"], gate["transfersAfter"],
                                                        gate["transferHeldThroughout"], gate["passed"]))
                self.assertEqual(([], []), (events(guest, "document-fixture-holder-census"), exports(guest)))

    def test_a_transfer_that_ended_during_the_control_proves_nothing(self):
        def end_transfer(owner):
            original = document_native.rename_control

            def control(*args):
                try:
                    return original(*args)
                finally:
                    (Path(owner.root) / "document-temp" / TRANSFER_LEAF).rmdir()
            patch = mock.patch.object(document_native, "rename_control", control)
            patch.start()
            self.addCleanup(patch.stop)
        guest, world, code = self.run_world(*self.fixed(), race_row, folder_share=FIXED_SHARE, before=end_transfer)
        self.assertEqual("document-race-root-control-without-transfer", guest.finished[0][2])
        self.assertEqual((1, 0, False), tuple(events(guest, "document-fixture-rename-gate")[0][key] for key in (
            "transfersBefore", "transfersAfter", "transferHeldThroughout")))

    def test_a_control_step_failing_otherwise_is_its_own_known_failure(self):
        def taken(owner):
            (Path(owner.root) / "document-race-parent-control").mkdir()
        guest, world, code = self.run_world(*self.fixed(), race_row, folder_share=FIXED_SHARE, before=taken)
        self.assertEqual((1, [], [(1, "RuntimeError", "document-race-root-control-failed:mkdir:errno-17")]),
                         (code, guest.parks, guest.finished))
        self.assertTrue((guest.root / "document-race-parent-control").is_dir(), "a folder it did not make stays")
        self.assertEqual(([], []), (events(guest, "document-fixture-holder-census"), exports(guest)))


class RefusalEvidenceTests(HolderRuns, unittest.TestCase):
    """A fixture step refused as held names who holds it; a refused rename also shows where a rename works."""

    def scanner(self, checks=None):
        def before(owner):
            self.world.hold(Path(owner.root) / "document-race-parent", SCANNER, "r", 1, checks)
        return before

    def run_scanned(self, modules, *, checks=None, transfer=True, modes=("parent",), folder_share=PACKAGE_SHARE):
        self.world = PinnedWorld(self.temp, folder_share)
        return self.run_world(*modules, race_row, world=self.world, modes=modes, transfer=transfer,
                              before=self.scanner(checks))

    def test_a_refused_rename_names_its_holders_at_the_first_refusal_and_at_the_last(self):
        guest, world, code = self.run_scanned(self.base(), transfer=False)
        self.assertEqual((1, REFUSED, []), (code, guest.finished[0][2], events(guest, "document-fixture-holder-census")),
                         "RED: the unfixed bytes are refused the same way and name no holder")
        guest, world, code = self.run_scanned(self.fixed())
        self.assertEqual((1, [], [(1, "RuntimeError", REFUSED)]), (code, guest.parks, guest.finished))
        census = [row for row in events(guest, "document-fixture-holder-census") if row["step"] == "rename-away"]
        self.assertEqual([("race", "first-refusal", 32, None), ("race", "refusal", 32, None)],
                         [(row["fixture"], row["moment"], row["winerror"], row["censusError"]) for row in census])
        worker = {"pid": WORKER, "image": "python.exe", "role": "worker", "child": None, "parentPid": TASK_OWNER, "openError": None}
        for row in census:
            self.assertEqual([
                {"role": "refused", "leaf": "parent", "status": "ok", "holderCount": 1, "holders": [worker]},
                {"role": "parent", "leaf": "document-race-parent", "status": "ok", "holderCount": 2, "holders": [
                    worker, {"pid": SCANNER, "image": "MsMpEng.exe", "role": "other", "child": None, "parentPid": None,
                             "openError": 5}]}], row["targets"])
        order = [kind for kind, _ in guest.events if kind.startswith(("document-fixture", "document-race-rename"))]
        self.assertEqual(["document-fixture-holder-census", "document-race-rename-probe", "document-fixture-holder-census",
                          "document-fixture-rename-differential"], order, "the first census is taken before any wait")

    def test_a_holder_that_was_only_passing_is_named_and_the_probe_goes_on(self):
        guest, world, code = self.run_scanned(self.fixed(), checks=2, folder_share=FIXED_SHARE)
        self.assertEqual((0, []), (code, guest.parks))
        probe, = events(guest, "document-race-rename-probe")
        self.assertEqual([("rename-away", 1, 32), ("rename-away", 2, 32), ("rename-away", 3, None), ("rename-back", 1, None)],
                         [(row["step"], row["attempt"], row["winerror"]) for row in probe["attempts"]])
        census = [row for row in events(guest, "document-fixture-holder-census") if row["step"] == "rename-away"]
        self.assertEqual(["first-refusal"], [row["moment"] for row in census])
        self.assertEqual([WORKER, SCANNER], [holder["pid"] for holder in census[0]["targets"][1]["holders"]])
        self.assertEqual([], events(guest, "document-fixture-rename-differential"))

    def test_the_differential_tells_the_folder_of_the_new_name_from_the_probes_handle_and_the_place(self):
        refused = steps("mkdir", ("rename-away", SHARING), "rmdir")
        refused_held = steps("mkdir", "held-open", "held-current", "held-close", ("rename-away", SHARING), "rmdir")
        renamed = steps("mkdir", "rename-away", "rename-back", "rmdir")
        renamed_held = steps("mkdir", "held-open", "held-current", "held-close", "rename-away", "rename-back", "rmdir")
        for transfer in (True, False):
            with self.subTest(transfer=transfer):
                guest, world, code = self.run_scanned(self.fixed(), transfer=transfer)
                differential, = events(guest, "document-fixture-rename-differential")
                self.assertEqual(("race", "rename-away", None), (differential["fixture"], differential["step"],
                                                                 differential["differentialError"]))
                root = [{"held": False, "steps": refused}, {"held": True, "steps": refused_held}] if transfer else \
                    [{"held": False, "steps": renamed}, {"held": True, "steps": renamed_held}]
                self.assertEqual([
                    {"location": "sibling", "leaf": "document-race-parent",
                     "variants": [{"held": False, "steps": refused}, {"held": True, "steps": refused_held}]},
                    {"location": "operation-root", "leaf": guest.root.name, "variants": root},
                    {"location": "user-temp", "available": True, "container": steps("mkdir", "rmdir"),
                     "variants": [{"held": False, "steps": renamed}, {"held": True, "steps": renamed_held}]}],
                    differential["locations"])
                # Everything made for it is gone again, and nothing of the product was touched.
                self.assertEqual([], list(self.temp.iterdir()))
                self.assertEqual(["parent"], sorted(path.name for path in (guest.root / "document-race-parent").iterdir()))
                self.assertEqual([], [path.name for path in guest.root.iterdir() if "differential" in path.name])
                self.assertEqual([], exports(guest))
        # RED: the unfixed bytes journal no differential.
        guest, world, code = self.run_world(*self.base(), race_row)
        self.assertEqual((1, []), (code, events(guest, "document-fixture-rename-differential")))

    def test_a_differential_never_removes_a_folder_it_did_not_make(self):
        self.world = PinnedWorld(self.temp)

        def before(owner):
            self.scanner()(owner)
            (Path(owner.root) / "document-race-parent-differential-plain").mkdir()
        guest, world, code = self.run_world(*self.fixed(), race_row, world=self.world, modes=("parent",), before=before)
        differential, = events(guest, "document-fixture-rename-differential")
        self.assertEqual([{"step": "mkdir", "errorClass": "FileExistsError", "winerror": None, "errno": 17}],
                         differential["locations"][1]["variants"][0]["steps"])
        self.assertTrue((guest.root / "document-race-parent-differential-plain").is_dir())

    def test_the_differential_never_uses_a_temp_folder_inside_the_operation_root(self):
        self.world = PinnedWorld(self.temp)

        def before(owner):
            self.scanner()(owner)
            spool = Path(owner.root) / "document-temp"
            spool.mkdir(exist_ok=True)
            self.world.os.environ["TEMP"] = str(spool)  # As the product's own children are given it.
        guest, world, code = self.run_world(*self.fixed(), race_row, world=self.world, modes=("parent",), before=before)
        differential, = events(guest, "document-fixture-rename-differential")
        self.assertEqual({"location": "user-temp", "available": False, "container": [], "variants": []},
                         differential["locations"][2])
        self.assertEqual([TRANSFER_LEAF], [path.name for path in (guest.root / "document-temp").iterdir()],
                         "nothing of its own beside the product's transfer folder")

    def persistence(self, world, race, provider, *, refusal, leaf="workspace.json"):
        def situation(owner, workspace, identity, harness):
            document_state(owner)
            owner.document_client = world.client
            world.admit(owner)
            workspace = Path(workspace)
            workspace.mkdir()
            (workspace / "workspace.json").write_bytes(b'{"persisted_state": {}}\n')
            owner.document_workspace_handle = world.Held(owner.native, workspace, directory=True)
            world.hold(workspace / leaf, SCANNER, "w", 3)
            # The module under test refuses with its own class, as its real Held does.
            world.refused_opens[str(workspace / leaf)] = self.native.NativeOpenError(refusal)
            self.native.persistence_fault(owner, workspace, world.client, client_module, "doc-persist-" + CONTEXT, CONTEXT,
                                          {"configurationRevision": 43}, 8)
        return situation

    def test_every_fixture_refused_as_held_gets_its_census_and_no_other_refusal_does(self):
        self.native = before_native(self)
        guest, world, code = self.run_world(before_owner(self), before_race(self), self.native, self.persistence, refusal=32)
        self.assertEqual((1, "document-persistence-fixture-refused:primary-hold:32", []),
                         (code, guest.finished[0][2], events(guest, "document-fixture-holder-census")))  # RED: no holder named.
        self.native = document_native
        guest, world, code = self.run_world(*self.fixed(), self.persistence, refusal=32)
        self.assertEqual((1, "document-persistence-fixture-refused:primary-hold:32"), (code, guest.finished[0][2]))
        census, = events(guest, "document-fixture-holder-census")
        self.assertEqual(("persistence", "primary-hold", "refusal", 32), (census["fixture"], census["step"], census["moment"],
                                                                           census["winerror"]))
        self.assertEqual([("refused", "workspace.json", "ok", [WORKER, SCANNER]), ("parent", "workspace", "ok", [WORKER])],
                         [(row["role"], row["leaf"], row["status"], [holder["pid"] for holder in row["holders"]])
                          for row in census["targets"]])
        self.assertEqual([{"path": str(guest.root / "workspace"), "directory": True, "access": 0x20080, "share": 1}],
                         census["harnessHandles"]["retained"], "the workspace observer the harness itself still held")
        self.assertEqual([], events(guest, "document-fixture-rename-differential"), "only a refused rename gets one")
        # The census is taken before the fixture releases anything: the primary it held is still in it.
        guest, world, code = self.run_world(*self.fixed(), self.persistence, refusal=32, leaf="workspace-recovery.json")
        census, = events(guest, "document-fixture-holder-census")
        self.assertEqual((1, "document-persistence-fixture-refused:recovery-hold:32", "recovery-hold"),
                         (code, guest.finished[0][2], census["step"]))
        self.assertEqual([("workspace", True, 0x20080, 1), ("workspace.json", False, 0x80020000, 1)],
                         [(Path(row["path"]).name, row["directory"], row["access"], row["share"])
                          for row in census["harnessHandles"]["retained"]])
        self.assertTrue(all(held.closed for held in world.held), "and released before the known failure closes the row")
        # A refusal that no other handle explains (not found) is named by its code alone.
        guest, world, code = self.run_world(*self.fixed(), self.persistence, refusal=2)
        self.assertEqual((1, "document-persistence-fixture-refused:primary-hold:2", []),
                         (code, guest.finished[0][2], events(guest, "document-fixture-holder-census")))


class Export:
    """One logical kernel export: its argtypes and restype may be set; it is only called here."""

    def __init__(self, function):
        self.function = function

    def __call__(self, *arguments):
        return self.function(*arguments)


class Kernel:
    """kernel32 and ntdll as HolderNative calls them: answers from tables, into the caller's own buffers."""

    INVALID = ctypes.c_void_p(-1).value

    def __init__(self, files, processes, names=None):
        self.files, self.processes, self.names = files, processes, names or {}
        self.calls, self.open, self.count = [], {}, 100
        self.k = types.SimpleNamespace(CreateFileW=Export(self.create), CloseHandle=Export(self.close),
                                       OpenProcess=Export(self.open_process),
                                       QueryFullProcessImageNameW=Export(self.image), GetProcessTimes=Export(self.times))
        self.n = types.SimpleNamespace(NtQueryInformationFile=Export(self.pids), NtQueryInformationProcess=Export(self.basic),
                                       NtQuerySystemInformation=Export(self.named))

    def handle(self, subject):
        self.count += 4
        self.open[self.count] = subject
        return self.count

    def create(self, path, access, share, security, disposition, flags, template):
        self.calls.append(("CreateFileW", path, access, share, disposition, flags))
        return self.INVALID if self.files.get(path) is None else self.handle(path)

    def close(self, handle):
        self.calls.append(("CloseHandle", self.open.pop(handle)))
        return 1

    def pids(self, handle, block, buffer, length, information):
        self.calls.append(("NtQueryInformationFile", self.open[handle], information))
        answer = self.files[self.open[handle]]
        if type(answer) is int:
            return answer
        data = struct.pack("<I4x%dQ" % len(answer), len(answer), *answer)
        assert len(data) <= length and len(block) == 16
        ctypes.memmove(buffer, data, len(data))
        return 0

    def open_process(self, access, inherit, pid):
        self.calls.append(("OpenProcess", access, inherit, pid))
        return self.handle(pid) if pid in self.processes else None

    def image(self, handle, flags, buffer, size):
        buffer.value = self.processes[self.open[handle]][0]
        return 1

    def basic(self, handle, information, buffer, length, returned):
        assert (information, length) == (0, 48)
        pid = self.open[handle]
        data = struct.pack("<i4xQQi4xQQ", 259, 0, 0, 8, pid, self.processes[pid][1])
        ctypes.memmove(buffer, data, len(data))
        return 0

    def times(self, handle, creation, *others):
        birth = self.processes[self.open[handle]][2]
        creation._obj.dwLowDateTime, creation._obj.dwHighDateTime = birth & 0xFFFFFFFF, birth >> 32
        return 1

    def named(self, information, pointer, length, returned):
        record = pointer.contents
        self.calls.append(("NtQuerySystemInformation", information, record.pid))
        name = self.names.get(record.pid)
        if information != 88 or name is None:
            return -1073741811
        assert (len(name) + 1) * ctypes.sizeof(ctypes.c_wchar) <= record.maximum + ctypes.sizeof(ctypes.c_wchar)
        (ctypes.c_wchar * (len(name) + 1)).from_address(record.buffer).value = name
        record.length = len(name) * ctypes.sizeof(ctypes.c_wchar)
        return 0


class HolderNativeTests(unittest.TestCase):
    """The census's own native reads, over logical kernel exports: what it asks for, and what it makes of the answers."""

    ROOT = r"C:\Users\fixtureuser\AppData\Local\VpnControlOrdinary-83484649"
    IMAGE = r"C:\Users\fixtureuser\AppData\Local\vpn-control\vpn-control-cli.exe"

    def setUp(self):
        if not hasattr(document_native, "HolderNative"):
            self.fail("the unfixed Windows module reads no holders")
        patch = mock.patch.object(ctypes, "get_last_error", lambda: 5, create=True)
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_holders_of_one_exact_path_are_read_with_every_sharing_and_the_handle_closed(self):
        kernel = Kernel({self.ROOT: [4321, 5008, 5009]}, {})
        self.assertEqual(("ok", [4321, 5008, 5009]), document_native.HolderNative(kernel).holders(self.ROOT))
        self.assertEqual([("CreateFileW", self.ROOT, 0x80, 7, 3, 0x02200000), ("NtQueryInformationFile", self.ROOT, 47),
                          ("CloseHandle", self.ROOT)], kernel.calls)
        self.assertEqual((wintypes.HANDLE, ctypes.c_long), (kernel.k.OpenProcess.restype, kernel.n.NtQueryInformationFile.restype))

    def test_a_refused_open_or_query_is_a_status_not_an_error(self):
        kernel = Kernel({}, {})
        self.assertEqual(("open-refused:5", []), document_native.HolderNative(kernel).holders(self.ROOT))
        self.assertEqual([("CreateFileW", self.ROOT, 0x80, 7, 3, 0x02200000)], kernel.calls, "nothing was queried or closed")
        kernel = Kernel({self.ROOT: -1073741820}, {})
        self.assertEqual(("query-refused:0xc0000004", []), document_native.HolderNative(kernel).holders(self.ROOT))
        self.assertEqual({}, kernel.open, "the handle is closed after a refused query too")

    def test_a_process_this_token_may_open_gives_its_image_leaf_parent_and_birth(self):
        kernel = Kernel({}, {5009: (self.IMAGE, 5008, 134387166885747844)})
        self.assertEqual({"image": "vpn-control-cli.exe", "parentPid": 5008, "birth": "134387166885747844", "openError": None},
                         document_native.HolderNative(kernel).process(5009))
        self.assertEqual([("OpenProcess", 0x1000, False, 5009), ("CloseHandle", 5009)], kernel.calls)

    def test_a_process_it_may_not_open_still_gives_its_image_leaf_and_nothing_else(self):
        names = {1234: r"\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"}
        kernel = Kernel({}, {}, names)
        reader = document_native.HolderNative(kernel)
        self.assertEqual({"image": "MsMpEng.exe", "parentPid": None, "birth": None, "openError": 5}, reader.process(1234))
        self.assertEqual({"image": None, "parentPid": None, "birth": None, "openError": 5}, reader.process(4))
        self.assertEqual([("OpenProcess", 0x1000, False, 1234), ("NtQuerySystemInformation", 88, 1234),
                          ("OpenProcess", 0x1000, False, 4), ("NtQuerySystemInformation", 88, 4)], kernel.calls)
        self.assertEqual({}, kernel.open)

    def test_the_pid_list_is_bounded_by_its_own_buffer(self):
        self.assertEqual([7, 9], document_native.process_ids(struct.pack("<I4xQQ", 2, 7, 9)))
        self.assertEqual([], document_native.process_ids(struct.pack("<I4x", 0)))
        with self.assertRaisesRegex(RuntimeError, "document-census-pid-count"):
            document_native.process_ids(struct.pack("<I4xQ", 2, 7))


class CensusRecordTests(unittest.TestCase):
    """What a census records of the PIDs it was given: roles by PID and birth, bounds, and never an exception."""

    def setUp(self):
        if not hasattr(document_native, "holder_census"):
            self.fail("the unfixed Windows module takes no census")

    def owner(self, children=()):
        journal = []
        owner = types.SimpleNamespace(native=types.SimpleNamespace(), children=list(children), pins=[],
                                      event=lambda kind, value: journal.append((kind, value)))
        return owner, journal

    def child(self, ordinal, pid, birth, argv, live=True):
        return types.SimpleNamespace(ordinal=ordinal, pid=pid, birth=birth, argv=argv, terminal=None if live else {"exitCode": 0})

    def census(self, owner, pids, facts):
        reader = type("Reader", (), {"__init__": lambda self, native: None, "holders": lambda self, path: ("ok", list(pids)),
                                     "process": lambda self, pid: dict(facts[pid])})
        system = types.SimpleNamespace(getpid=lambda: WORKER, getppid=lambda: TASK_OWNER)
        with mock.patch.object(document_native, "HolderNative", reader), mock.patch.object(document_native, "os", system):
            return document_native.holder_census(owner, "race", "rename-away", "refusal", 32, [("parent", Path("/x/root"))])

    def fact(self, parent=None, birth=None, image=LAUNCHER):
        return {"image": image, "parentPid": parent, "birth": birth, "openError": None}

    def test_a_role_needs_the_known_pid_and_its_birth_or_a_live_known_parent(self):
        serve = self.child(2, 5008, "20", ("cli", "--state-dir", "w", "serve"))
        first = self.child(4, 5016, "40", ("cli", "--state-dir", "w", "--json", "status"), live=False)
        ended = self.child(7, 5028, "70", ("cli", "--state-dir", "w", "--json", "status"), live=False)
        live = self.child(9, 5036, "90", ("cli", "--state-dir", "p", "routing", "export"))
        again = self.child(12, 5016, "120", ("cli", "--state-dir", "p", "routing", "export"))
        owner, journal = self.owner([serve, first, ended, live, again])
        facts = {5008: self.fact(WORKER, "20"), 5009: self.fact(5008, "21"), 5016: self.fact(WORKER, "120"),
                 5028: self.fact(1, "999"), 5029: self.fact(5028, "71"), 5036: self.fact(WORKER, "90"),
                 5037: self.fact(5036, "91"), 6000: self.fact(5009, "1"), WORKER: self.fact(TASK_OWNER, "5", "python.exe")}
        value = self.census(owner, list(facts), facts)
        self.assertEqual({5008: ("serve", 2), 5009: ("serve-child", 2), 5016: ("cli-child", 12), 5028: ("other", None),
                          5029: ("other", None), 5036: ("cli-child", 9), 5037: ("cli-child-child", 9), 6000: ("other", None),
                          WORKER: ("worker", None)},
                         {row["pid"]: (row["role"], row["child"]) for row in value["targets"][0]["holders"]},
                         "a live child takes the PID an ended one had; a reused PID of another birth, the child of an "
                         "ended child and a grandchild are none of ours")
        self.assertEqual([("document-fixture-holder-census", value)], journal)

    def test_the_record_is_bounded_and_names_what_failed_inside_it(self):
        owner, journal = self.owner()
        pids = list(range(10000, 10070))
        value = self.census(owner, pids, {pid: self.fact() for pid in pids})
        self.assertEqual((70, document_native.CENSUS_HOLDERS), (value["targets"][0]["holderCount"], len(value["targets"][0]["holders"])))
        value = self.census(owner, [1], {})
        self.assertEqual(("KeyError", []), (value["censusError"], value["targets"]))
        self.assertEqual(2, len(journal), "a census that failed inside is still journaled")
        owner.native.document_retained_handles = [
            types.SimpleNamespace(path=Path("/x/%d" % index), directory=True, access=0x20080, share=1, closed=index % 2 == 1,
                                  open_error=None) for index in range(80)]
        handles = self.census(owner, [], {})["harnessHandles"]
        self.assertEqual((80, 40, document_native.CENSUS_HANDLES), (handles["retainedTotal"], handles["retainedOpen"],
                                                                     len(handles["retained"])))


class HeldModeTests(Runs, unittest.TestCase):
    """The harness's own observers record the access they were opened with, which the census reports."""

    def modes(self, module):
        opened = []
        native = types.SimpleNamespace(
            k=types.SimpleNamespace(CreateFileW=lambda path, access, share, *rest: opened.append((access, share)) or 21),
            identity=lambda handle, directory=False: {"volumeSerial": 1, "fileIndex": 2, "attributes": 16},
            security=lambda handle: {"ownerSid": SID})
        with mock.patch.object(module, "os", NT_OS):
            held = [module.Held(native, self.root, directory=True, share=3), module.Held(native, self.root / "payload"),
                    module.Held(native, self.root / "payload", write=True, share=7)]
        return [(value.access, value.share) for value in held], opened, native

    def test_an_observer_names_the_access_and_sharing_of_its_own_handle(self):
        with self.assertRaises(AttributeError):
            self.modes(before_native(self))  # RED: the unfixed observer kept its sharing only.
        expected = [(0x20080, 3), (0x80020000, 1), (0xC0020000, 7)]
        modes, opened, native = self.modes(document_native)
        self.assertEqual((expected, expected), (modes, opened))
        handles = document_native.harness_handles(types.SimpleNamespace(native=native, pins=[]))
        self.assertEqual((3, expected), (handles["retainedOpen"], [(row["access"], row["share"]) for row in handles["retained"]]))


class PinModeTests(unittest.TestCase):
    """The owner's pins record the access and sharing they were opened with, which the census reports."""

    IDENTITY = {"volumeSerial": 1, "fileIndex": 2, "attributes": 16}

    def pin(self, module, directory):
        opened = []
        record = {"path": "/x/root", "security": {"ownerSid": SID, "sddl": "O:"}, "sha256": hashlib.sha256(b"").hexdigest(),
                  "nativeIdentity": dict(self.IDENTITY) if directory else {**self.IDENTITY, "sizeBytes": 0}}
        native = types.SimpleNamespace(
            k=types.SimpleNamespace(CreateFileW=lambda path, access, share, *rest: opened.append((access, share)) or 11,
                                    CloseHandle=lambda handle: 1),
            identity=lambda handle, directory=False: record["nativeIdentity"], security=lambda handle: record["security"],
            read_blocks=lambda handle: iter(()))
        with mock.patch.object(module, "absolute", Path):
            pin = module.Pin(native, record, directory=directory)
        return (pin.access, pin.share), opened[0]

    def test_a_pin_names_the_access_and_sharing_of_its_own_handle(self):
        with self.assertRaises(AttributeError):
            self.pin(before_owner(self), True)  # RED: the unfixed pin kept neither.
        self.assertEqual(((0x20080, 3), (0x20080, 3)), self.pin(process_owner, True))
        self.assertEqual(((0x80020000, 1), (0x80020000, 1)), self.pin(process_owner, False))


if __name__ == "__main__":
    unittest.main()
