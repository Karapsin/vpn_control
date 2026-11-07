"""The durable job's stages, journals and exit rules over one shared fake guest agent.

The fake models the wire, not Windows: nothing here proves a PowerShell behaviour. The
flat journals are judged by the real host_work classifier, and the real emitter and
planner build and read every program and request.
"""
import ast
import base64
from contextlib import nullcontext
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_bundle as bundles
from agent_tools import native_scenario_execution as execution
from agent_tools import native_scenario_windows as driver
from agent_tools import windows_artifact_transfer as emitter
from agent_tools import windows_ordinary_task as planner
from agent_tools import windows_scenario_host_job as job
from agent_tools.tests.test_readiness_windows_guest import facts
from agent_tools.tests.test_windows_idle_receipt_classes import Receipts, current_source

ROOT = Path(__file__).resolve().parents[2]


def powershell_binary(which=shutil.which):
    """The guest always runs Windows PowerShell 5.1, so its parser goes first where it exists."""
    return which("powershell.exe") or which("powershell") or which("pwsh")


POWERSHELL = powershell_binary()
SID = "S-1-5-21-1-2-3-1000"
MACHINE = "33333333-4444-4555-8666-777777777777"
USER = "recovery"
PROFILE = "C:\\Users\\recovery"
RAW_GUID = "A1B2C3D4-0000-4000-8000-000000000001"
BOOT_IDENTIFIER = "11111111-2222-4333-8444-555555555555"
FILETIME = "134368653065000000"
TOKEN = ["S-1-5-18", "0", "1", "1", "True", "True"]
OS_OWNER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
BUNDLE_FILES = ("agent_tools/windows_scenario_host_job.py", "agent_tools/windows_ordinary_task.py", "agent_tools/windows_ordinary_process_owner.py",
                "agent_tools/windows_ordinary_task_owner.ps1", "agent_tools/windows_artifact_transfer.py", "agent_tools/readiness_windows_guest.py",
                "agent_tools/windows_scenario_publisher.ps1.template", "agent_tools/windows_scenario_system_run.ps1.template",
                "agent_tools/windows_scenario_qualification_child.ps1")


def out_data(value):
    return base64.b64encode(base64.b64encode(gzip.compress(json.dumps(value).encode(), mtime=0))).decode()


def program_input(source):
    found = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", source)
    return None if found is None else json.loads(gzip.decompress(base64.b64decode(found[1])))


class FakeQga:
    """The one fake guest agent peer of these tests: an effect happens, then its reply may be lost."""

    def __init__(self):
        self.calls = []
        self.programs = []
        self.files = {}
        self.pending = {}
        self.handles = {}
        self.next_pid = 4000
        self.next_index = 100
        self.polls_before_exit = 1
        self.lose = lambda command, kind, ordinal: None
        self.session_flags = 1
        self.run_changes = {}
        self.run_state = None
        self.run_code = "RUN_SYNTHETIC_CODE"
        self.program_exit = {}
        self.status_file = None
        self.write_sizes = []

    def count(self, command):
        return sum(1 for name, _ in self.calls if name == command)

    def kinds(self):
        return [kind for kind, _ in self.programs]

    def rpc(self, command, arguments, budget=8):
        self.calls.append((command, arguments))
        kind = None
        handler = getattr(self, "_" + command.replace("-", "_"))
        result = handler(arguments)
        if command == "guest-exec":
            kind = self.programs[-1][0]
        failure = self.lose(command, kind, self.count(command))
        if failure is not None:
            raise failure
        return result

    def _guest_ping(self, arguments):
        return {}

    def _guest_exec(self, arguments):
        if arguments["path"] != job.POWERSHELL_PATH or arguments["arg"] != list(job.GUEST_ARGUMENTS) or arguments["capture-output"] is not True:
            raise AssertionError("guest-exec shape changed")
        source = base64.b64decode(arguments["input-data"]).decode("ascii")
        self.next_pid += 1
        pid = self.next_pid
        m = program_input(source)
        if m is None:
            kind, terminal = "context", self._context()
        elif "taskName" in m:
            kind, terminal = "system-run", self._system_run(m, pid)
        else:
            kind, terminal = m["action"], self._publisher(m, pid)
        if kind in self.program_exit:
            terminal = {"exited": True, "exitcode": self.program_exit[kind], "err-data": base64.b64encode(b"refused").decode()}
        self.programs.append((kind, source))
        self.pending[pid] = {"polls": self.polls_before_exit, "terminal": terminal}
        return {"pid": pid}

    def _guest_exec_status(self, arguments):
        row = self.pending.get(arguments["pid"])
        if row is None:
            raise ValueError()  # The agent no longer tracks this pid.
        if row["polls"] > 0:
            row["polls"] -= 1
            return {"exited": False}
        del self.pending[arguments["pid"]]
        return row["terminal"]

    def _guest_file_open(self, arguments):
        path, mode = arguments["path"], arguments["mode"]
        if mode == "wb":
            self.files[path] = b""
        elif path not in self.files:
            raise ValueError()
        self.next_index += 1
        self.handles[self.next_index] = {"path": path, "offset": 0}
        return self.next_index

    def _guest_file_write(self, arguments):
        raw = base64.b64decode(arguments["buf-b64"])
        self.write_sizes.append(len(raw))
        path = self.handles[arguments["handle"]]["path"]
        self.files[path] += raw
        return {"count": len(raw), "eof": False}

    def _guest_file_read(self, arguments):
        row = self.handles[arguments["handle"]]
        raw = self.files[row["path"]][row["offset"]:row["offset"] + arguments["count"]]
        row["offset"] += len(raw)
        return {"count": len(raw), "buf-b64": base64.b64encode(raw).decode(), "eof": row["offset"] >= len(self.files[row["path"]])}

    def _guest_file_close(self, arguments):
        del self.handles[arguments["handle"]]
        return {}

    def _context(self):
        value = facts()
        value["machine"] = MACHINE.upper()
        value["session"]["Flags"] = self.session_flags
        return {"exited": True, "exitcode": 0, "out-data": out_data({
            "sessionFacts": value, "machineGuid": RAW_GUID, "hardwareUuid": MACHINE.upper(), "bootIdentifier": BOOT_IDENTIFIER,
            "bootFileTimeUtc": FILETIME, "profileRoot": PROFILE, "systemToken": TOKEN})}

    def _actor(self, pid):
        return {"pid": pid, "birthFileTimeUtc": "134368653065000001", "sessionId": 0, "path": job.POWERSHELL_PATH, "principalSid": "S-1-5-18",
                "is64BitProcess": True, "powerShellMajor": 5, "powerShellEdition": "Desktop", "tokenElevation": 1, "tokenElevationType": 1,
                "boot": {"lastBootUpTimeFileTimeUtc": FILETIME, "machineGuid": RAW_GUID, "hardwareUuid": MACHINE.upper()}}

    def _pin(self, path, *, directory=False, raw=b"", security=None):
        self.next_index += 1
        identity = {"volumeSerial": 7, "fileIndex": self.next_index, "attributes": 16 if directory else 32}
        if directory:
            return {"path": path, "nativeIdentity": identity, "security": security or {"ownerSid": "S-1-5-18", "sddl": "O:SYD:P(A;;FA;;;SY)"}}
        identity.update(sizeBytes=len(raw), links=1, creationFileTime=FILETIME, lastWriteFileTime=FILETIME)
        return {"path": path, "nativeIdentity": identity, "sha256": hashlib.sha256(raw).hexdigest(),
                "security": security or {"ownerSid": "S-1-5-18", "sddl": "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + SID + ")"}}

    def _publisher(self, m, pid):
        reply = {"schemaVersion": 1, "operationId": m["operationId"], "kernelBootIdentifier": m["kernelBootIdentifier"], "systemToken": m["systemToken"],
                 "allHeldAndNamedPinsClosing": True, "productOperation": False, "taskOperation": False, "bootstrapOpening": self._actor(pid),
                 "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        action = m["action"]
        if action == "initialize":
            def directory(path, rights):
                return self._pin(path, directory=True, security={"ownerSid": "S-1-5-18", "sddl": "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + rights + ";;;" + SID + ")"})
            pins = [self._pin(path, directory=True) for path in m["existingDirectories"]]
            pins.append(directory(m["workspace"], "0x1200a9"))
            pins.extend(directory(m["workspace"] + "\\" + name, "0x1200a9") for name in m["subfolders"])
            pins.append(directory(m["operationRoot"], "0x1301bf"))
            reply.update(state="ordinary-publication-initialized", workspace=m["workspace"], operationRoot=m["operationRoot"], createNew=True, directoryPins=pins)
        elif action == "endpoints":
            created = []
            for target in m["targets"]:
                if target["path"] in self.files:
                    raise AssertionError("endpoint created twice")
                self.files[target["path"]] = b""
                created.append({"schemaVersion": 1, "state": "ordinary-publication-created", "operationId": m["operationId"], "role": target["role"],
                                "filePin": self._pin(target["path"]), "expectedBytes": target["bytes"], "expectedSha256": target["sha256"],
                                "createNew": True, "heldReadOnly": True, "writeOpenError": 32, "deleteOpenError": 32})
            reply.update(state="ordinary-publication-created-set", endpoints=created)
        elif action == "verify":
            verified = []
            for target in m["targets"]:
                raw = self.files[target["path"]]
                if hashlib.sha256(raw).hexdigest() != target["sha256"]:
                    return {"exited": True, "exitcode": 1, "err-data": base64.b64encode(b"PUB_FILE_HASH_OR_SIZE").decode()}
                identity = dict(target["endpointPin"]["nativeIdentity"], sizeBytes=len(raw))
                verified.append({"schemaVersion": 1, "state": "ordinary-publication-verified", "operationId": m["operationId"], "role": target["role"],
                                 "filePin": {"path": target["path"], "nativeIdentity": identity, "security": target["endpointPin"]["security"], "sha256": target["sha256"]},
                                 "heldPhysicalRead": True})
            reply.update(state="ordinary-publication-verified-set", verified=verified)
        elif action == "read-pins":
            reply.update(state="ordinary-publication-read-pins", filePins=[self._pin(path, raw=b"exe", security={
                "ownerSid": OS_OWNER, "sddl": "O:" + OS_OWNER + "D:P(A;;FA;;;" + OS_OWNER + ")(A;;FRFX;;;BU)"}) for path in m["readPaths"]])
        elif action == "evidence-zip":
            path = m["workspace"] + "\\evidence-" + str(m["evidenceNumber"]) + ".zip"
            raw = b"PK" + b"evidence" * 40000
            self.files[path] = raw
            reply.update(state="ordinary-evidence-zip", zipPath=path, zipBytes=len(raw), zipSha256=hashlib.sha256(raw).hexdigest(), entries=5)
        else:
            raise AssertionError("closed publisher action")
        return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}

    def _system_run(self, m, pid):
        pin = m["taskRequestPin"]
        request = json.loads(self.files[pin["path"]])
        if hashlib.sha256(self.files[pin["path"]]).hexdigest() != pin["sha256"] or request["bootstrap"]["mode"] != m["mode"]:
            raise AssertionError("request pin differs from the published bytes")
        if m["taskXml"].startswith("<?xml") or planner.policy_fields(m["taskXml"])["Arguments"] != m["taskArguments"]:
            raise AssertionError("task policy differs")
        reply = {"schemaVersion": 1, "operationId": m["operationId"], "productOperation": False, "bootstrapOpening": self._actor(pid),
                 "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        if self.run_state is not None:
            reply.update(state=self.run_state, code=self.run_code, parkedFiles=["owner-parked.json"], taskDeleted=False)
        else:
            def stream(name, text):
                return {"name": name, "bytes": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}
            reply.update({"state": "task-finished", "taskName": m["taskName"], "instanceGuid": "{guid}", "enginePid": 900, "ownerPid": 901,
                          "ownerBirthFileTimeUtc": "134368653065000002", "ownerExitCode": 7, "lastTaskResult": 7, "terminalExitCode": 7,
                          "commandLineMatched": True, "workerEvents": 0, "taskDeleted": True, "polls": 2, "statusFailures": 0, "parkedFiles": [],
                          "sourceClosing": True,
                          "events": [{"name": "task-event-00000" + str(i) + "-" + kind + ".json", "bytes": 9, "sha256": "0" * 64, "kind": kind}
                                     for i, kind in enumerate(("submission-intent", "submitted", "terminal"))],
                          "rawStreams": [stream("stdout", "stdout|scenario-ok"), stream("stderr", "stderr|scenario-ok")]})
            reply.update(self.run_changes)
        return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}


class FakeRuntime:
    """The host seam: flat create-only journals over real files, no process, no socket."""

    def __init__(self, root, qga):
        self.root = root
        self.qga = qga
        self.pid = 777
        self.clock = 0.0
        self.emitted = []
        self.reads = 0

    def rpc(self, command, arguments, budget=8):
        return self.qga.rpc(command, arguments, budget=budget)

    def save(self, name, value):
        with open(self.root / name, "x", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
        (self.root / name).chmod(0o600)

    def sleep(self, seconds):
        self.clock += seconds

    def monotonic(self):
        return self.clock

    def emit(self, line):
        self.emitted.append(json.loads(line))

    def open_wires(self, data):
        pass

    def after_read(self):
        self.reads += 1

    def admission(self):
        return nullcontext()


def bundle_files():
    files = {}
    for relative in BUNDLE_FILES:
        files[relative] = (ROOT / relative).read_bytes()
    return files


class Base(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.vm = self.work / "vm"
        self.vm.mkdir(mode=0o700)
        self.machine_data = self.work / "home/.cache/vpn-control-windows-scenarios" / MACHINE
        self.qga = FakeQga()
        self.rt = FakeRuntime(self.vm, self.qga)
        self.files = bundle_files()

    def plan(self, operation=None, **changes):
        operation = operation or str(uuid.uuid4())
        row = json.loads(json.dumps(driver.RECIPES["windows-ordinary-qualification"]))
        return {"schemaVersion": 1, "operationId": operation, "scenarioId": "windows-ordinary-qualification", "machine": MACHINE, "bundleHash": "a" * 64,
                "user": USER, "dataDirectory": str(self.machine_data / operation), "row": row, "stopAfter": None,
                "files": {path: {"sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)} for path, raw in self.files.items()}, **changes}

    def run_job(self, **changes):
        plan = self.plan(**changes)
        self.addCleanup(self.forget_modules, plan["operationId"])
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan)

    @staticmethod
    def forget_modules(operation):
        import sys
        for name in [name for name in sys.modules if name.endswith(operation.replace("-", ""))]:
            del sys.modules[name]

    def receipt(self, plan):
        path = Path(plan["dataDirectory"]) / "scenario-receipt.json"
        return json.loads(path.read_bytes()) if path.exists() else None

    def fence(self, plan, suffix):
        return self.vm / ("direct-guest-" + plan["operationId"] + suffix)

    def classify(self):
        receipts = Receipts(self.vm)
        return receipts.run(current_source())


class CompleteJobTests(Base):
    def test_complete_qualification_passes_and_every_journal_closes(self):
        plan, code, receipt = self.run_job()
        self.assertEqual(0, code)
        self.assertEqual({"schemaVersion": 1, "operationId": plan["operationId"], "scenarioExit": 0, "failure": None}, self.rt.emitted[-1])
        self.assertEqual(["context", "initialize", "endpoints", "verify", "read-pins", "endpoints", "verify", "system-run", "evidence-zip"], self.qga.kinds())
        self.assertEqual(("passed", "receipt", 0, 9), (receipt["result"], receipt["stage"], receipt["exitCode"], receipt["guestPrograms"]))
        self.assertEqual("vpn-control.windows-ordinary-qualification.receipt", receipt["schema"])
        self.assertEqual((7, 3, True, False), (receipt["task"]["ownerExitCode"], receipt["task"]["events"], receipt["task"]["taskDeleted"], receipt["task"]["parked"]))
        self.assertEqual((2, 0), (receipt["task"]["polls"], receipt["task"]["statusFailures"]))
        self.assertEqual({"ordinarySid": SID, "ordinarySessionId": 2, "profileRoot": PROFILE, "bootFileTimeUtc": FILETIME, "bootIdentifier": BOOT_IDENTIFIER,
                          "hardwareUuid": MACHINE.upper(), "machineGuid": RAW_GUID}, receipt["context"], "the raw identity, as a first proof reads it")
        self.assertEqual({"exited": True, "exitcode": 0}, json.loads(self.fence(plan, ".terminal.json").read_bytes()))
        self.assertEqual({"schemaVersion": 1, "operationId": plan["operationId"], "exitCode": 0, "fenceAnchored": True},
                         json.loads((Path(plan["dataDirectory"]) / "job-exit.json").read_bytes()))
        result = self.classify()
        self.assertEqual([], result["unresolved"])
        self.assertEqual(10, result["terminalCount"])
        # Three flat entries per program and for the fence; every name is one host_work classifies.
        self.assertEqual(30, len(list(self.vm.iterdir())))
        self.assertTrue(all(re.fullmatch(r"direct-guest-[0-9a-f-]{36}\.(?:intent|ack|terminal)\.json", path.name) for path in self.vm.iterdir()))

    def test_requests_are_the_planner_output_and_reach_the_guest_exactly(self):
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"]
        workspace = "C:\\ProgramData\\VpnControlOrdinaryTask-" + plan["operationId"]
        request = json.loads(self.qga.files[root + "\\bootstrap-request.json"])
        self.assertEqual({"mode": "qualification", "qualificationSourcePath": workspace + "\\windows_scenario_qualification_child.ps1",
                          "qualificationArguments": ["-Value", "scenario-ok"]}, request["bootstrap"])
        self.assertEqual({job.POWERSHELL_PATH, workspace + "\\windows_ordinary_task_owner.ps1", workspace + "\\windows_scenario_qualification_child.ps1"},
                         {pin["path"] for pin in request["filePins"]})
        self.assertEqual(self.files["agent_tools/windows_scenario_qualification_child.ps1"], self.qga.files[workspace + "\\windows_scenario_qualification_child.ps1"])
        self.assertEqual(self.files["agent_tools/windows_ordinary_task_owner.ps1"], self.qga.files[workspace + "\\windows_ordinary_task_owner.ps1"])
        # Raw for the guest, lowercase canonical for the planner.
        self.assertEqual(RAW_GUID.lower(), request["context"]["machineGuid"])
        self.assertEqual(MACHINE, request["context"]["deploymentId"])
        planner.validate_closure(request)

    def test_stop_after_ends_early_without_a_task_and_says_so(self):
        for stop, kinds in (("context", ["context"]), ("publish", ["context", "initialize", "endpoints", "verify", "read-pins"])):
            with self.subTest(stop=stop):
                self.qga.programs.clear()
                plan, code, receipt = self.run_job(stopAfter=stop)
                self.assertEqual(0, code)
                self.assertEqual(kinds, self.qga.kinds())
                self.assertEqual((stop, stop), (receipt["stoppedAfter"], receipt["stage"]))
                self.assertTrue(self.fence(plan, ".terminal.json").exists())

    def test_status_file_is_read_between_polls_without_a_vm_root_entry(self):
        self.qga.polls_before_exit = 3
        self.qga.files["placeholder"] = b""
        original = self.qga._system_run

        def with_status(m, pid):
            self.qga.files[m["workspace"] + "\\scenario-status.json"] = json.dumps({"poll": 2, "lastEventOrdinal": 1, "pendingKinds": [], "parkedFiles": []}).encode()
            return original(m, pid)
        self.qga._system_run = with_status
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        self.assertEqual(2, json.loads((Path(plan["dataDirectory"]) / "status.json").read_bytes())["poll"])
        self.assertEqual(30, len(list(self.vm.iterdir())))
        self.assertEqual(5, self.rt.reads, "only the five evidence reads may truncate the wire files, never a status read")

    def test_a_missed_status_write_is_tolerated_and_reported(self):
        self.qga.run_changes = {"polls": 9, "statusFailures": 4}
        _, code, receipt = self.run_job()
        self.assertEqual(0, code)
        self.assertEqual((9, 4), (receipt["task"]["polls"], receipt["task"]["statusFailures"]))


class JournalRuleTests(Base):
    def job(self, **changes):
        plan = self.plan(**changes)
        self.addCleanup(self.forget_modules, plan["operationId"])
        instance = job.Job(self.rt, plan, self.files)
        instance.data.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        instance.data.mkdir(mode=0o700)
        instance.owns_data = True
        return instance

    def test_journal_is_saved_before_the_guest_exec_and_the_terminal_before_decoding(self):
        instance = self.job()
        seen = {}
        original = self.qga._guest_exec

        def exec_after_intent(arguments):
            seen["names"] = sorted(path.name for path in self.vm.iterdir())
            return original(arguments)
        self.qga._guest_exec = exec_after_intent
        terminal, pid = instance.guest_program("sample", job.wrap_output("[pscustomobject]@{a=1}"))
        prefix = "direct-guest-" + str(uuid.uuid5(uuid.UUID(instance.op), "sample"))
        self.assertEqual([prefix + ".intent.json"], seen["names"])
        self.assertEqual({prefix + suffix for suffix in (".intent.json", ".ack.json", ".terminal.json")}, {path.name for path in self.vm.iterdir()})
        self.assertEqual(pid, json.loads((self.vm / (prefix + ".ack.json")).read_bytes())["ack"]["pid"])
        self.assertEqual(terminal, json.loads((self.vm / (prefix + ".terminal.json")).read_bytes()))

    def test_an_existing_intent_means_never_guest_exec_again(self):
        instance = self.job()
        instance.guest_program("sample", job.wrap_output("[pscustomobject]@{a=1}"))
        with self.assertRaisesRegex(job.Unknown, "guest_program_intent_exists:sample"):
            instance.guest_program("sample", job.wrap_output("[pscustomobject]@{a=1}"))
        self.assertEqual(1, self.qga.count("guest-exec"))

    def test_sources_outside_the_stdin_route_are_refused_before_any_journal(self):
        instance = self.job()
        for source, reason in (("\ufeffa", "guest_source_bom"), ("caf\u00e9", "guest_source_ascii"), ("a" * 79184, "guest_source_bound"), ("", "guest_source_bound")):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                instance.guest_program("sample", source)
        self.assertEqual([], list(self.vm.iterdir()))
        self.assertEqual(0, self.qga.count("guest-exec"))
        instance.guest_program("largest", "a" * 79183)
        self.assertEqual(1, self.qga.count("guest-exec"))

    def test_lost_guest_exec_reply_never_resubmits_and_ends_unknown(self):
        self.qga.lose = lambda command, kind, ordinal: TimeoutError("collection-deadline") if kind == "system-run" else None
        plan, code, receipt = self.run_job()
        self.assertEqual(3, code)
        self.assertEqual(1, self.qga.kinds().count("system-run"))
        self.assertEqual("system-run", self.qga.kinds()[-1], "a lost ack ends the job: no other SYSTEM program goes in")
        self.assertEqual(("unknown", "run", "guest_exec_reply_lost:system-run"), (receipt["result"], receipt["stage"], receipt["failure"]))
        self.assertEqual({"schemaVersion": 1, "operationId": plan["operationId"], "scenarioExit": 3, "failure": "guest_exec_reply_lost:system-run"}, self.rt.emitted[-1])
        self.assertFalse(self.fence(plan, ".terminal.json").exists())
        reasons = {row["receipt"]: row["reason"] for row in self.classify()["unresolved"]}
        self.assertEqual("original_guest_work_unresolved", reasons["direct-guest-" + plan["operationId"] + ".intent.json"])
        self.assertIn("direct-guest-" + str(uuid.uuid5(uuid.UUID(plan["operationId"]), "system-run")) + ".intent.json", reasons)

    def test_lost_terminal_reply_ends_unknown_with_one_guest_exec(self):
        losses = []

        def lose(command, kind, ordinal):
            if command == "guest-exec-status" and not losses and self.qga.programs[-1][0] == "context" and not self.qga.pending:
                losses.append(ordinal)
                return TimeoutError("collection-deadline")
            return None
        self.qga.lose = lose
        plan, code, receipt = self.run_job()
        self.assertEqual(3, code)
        self.assertEqual(["context"], self.qga.kinds())
        self.assertEqual("guest_exec_status_lost:context", receipt["failure"])
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_lost_terminal_after_publishing_sends_no_other_program(self):
        losses = []

        def lose(command, kind, ordinal):
            if command == "guest-exec-status" and not losses and self.qga.programs[-1][0] == "system-run" and not self.qga.pending:
                losses.append(ordinal)
                return TimeoutError("collection-deadline")
            return None
        self.qga.lose = lose
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "guest_exec_status_lost:system-run", "run"), (code, receipt["failure"], receipt["stage"]))
        self.assertEqual("system-run", self.qga.kinds()[-1])
        self.assertIsNone(receipt["evidence"])
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_run_program_past_its_deadline_gets_no_other_program_beside_it(self):
        original = self.qga._system_run

        def forever(m, pid):
            self.qga.polls_before_exit = 10 ** 9
            return original(m, pid)
        self.qga._system_run = forever
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "guest_program_deadline:system-run", "run"), (code, receipt["failure"], receipt["stage"]))
        self.assertEqual("system-run", self.qga.kinds()[-1])
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_lost_running_status_is_only_a_read_miss(self):
        losses = []

        def lose(command, kind, ordinal):
            if command == "guest-exec-status" and len(losses) < 2 and self.qga.programs[-1][0] == "initialize":
                if self.qga.pending:
                    losses.append(ordinal)
                    return OSError("reset")
            return None
        self.qga.lose = lose
        self.qga.polls_before_exit = 4
        _, code, _ = self.run_job()
        self.assertEqual(0, code)
        self.assertEqual(2, len(losses))

    def test_program_deadline_ends_unknown_and_stops_nothing(self):
        self.qga.polls_before_exit = 10 ** 9
        plan, code, receipt = self.run_job()
        self.assertEqual(3, code)
        self.assertEqual("guest_program_deadline:context", receipt["failure"])
        self.assertEqual(["context"], self.qga.kinds())
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_an_unknown_outcome_leaves_the_fence_open_and_only_a_copy_follows_a_returned_program(self):
        for state in ("owner-parked", "deadline", "post-launch-unknown"):
            with self.subTest(state=state):
                # A fresh guest and clone per case: one UNKNOWN blocks every later job by design.
                self.setUp()
                self.qga.run_state = state
                plan, code, receipt = self.run_job()
                self.assertEqual(3, code)
                self.assertEqual(state, receipt["failure"])
                self.assertEqual("run", receipt["stage"])
                self.assertFalse(self.fence(plan, ".terminal.json").exists())
                self.assertIn("direct-guest-" + plan["operationId"] + ".intent.json", {row["receipt"] for row in self.classify()["unresolved"]})
                self.assertEqual(3, json.loads((Path(plan["dataDirectory"]) / "job-exit.json").read_bytes())["exitCode"])
                self.assertEqual(["system-run", "evidence-zip"], self.qga.kinds()[-2:], "that program returned, so one read-only copy may follow")
                self.assertEqual(False, receipt["task"]["taskDeleted"])

    def test_a_guest_state_outside_the_closed_list_is_unknown_and_crosses_as_a_word(self):
        self.qga.run_state = "C:\\Users\\private-account\\state"
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "system_run_state_unrecognized"), (code, receipt["failure"]))
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_nonzero_system_run_exit_is_unknown_not_a_refusal(self):
        self.qga.program_exit["system-run"] = 1
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "system_run_unreadable"), (code, receipt["failure"]))
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_host_error_before_the_fence_is_a_refusal_and_blocks_nothing(self):
        original = self.rt.open_wires

        def full(data):
            raise OSError("disk full")
        self.rt.open_wires = full
        plan, code, receipt = self.run_job()
        self.assertEqual((2, "host_prepare:OSError", "failed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual({"schemaVersion": 1, "operationId": plan["operationId"], "exitCode": 2, "fenceAnchored": False},
                         json.loads((Path(plan["dataDirectory"]) / "job-exit.json").read_bytes()))
        self.assertEqual([], list(self.vm.iterdir()))
        self.assertEqual(0, self.qga.count("guest-exec"))
        self.rt.open_wires = original
        self.assertEqual(0, self.run_job()[1])

    def test_a_partly_saved_fence_intent_still_blocks_the_next_job(self):
        original = self.rt.save

        def partial(name, value):
            original(name, value)
            raise OSError("disk full")
        self.rt.save = partial
        first, code, receipt = self.run_job()
        self.assertEqual((2, "host_prepare:OSError"), (code, receipt["failure"]))
        self.assertTrue(self.fence(first, ".intent.json").exists())
        self.rt.save = original
        plan, code, receipt = self.run_job()
        self.assertEqual((2, "prior_fence_open"), (code, receipt["failure"]))
        self.assertEqual(0, self.qga.count("guest-exec"))

    def test_an_unexpected_host_error_is_unknown(self):
        original = self.rt.save

        def fail_after_ack(name, value):
            if name.endswith(".ack.json") and self.qga.count("guest-exec"):
                raise OSError("disk full")
            original(name, value)
        self.rt.save = fail_after_ack
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "unexpected:OSError"), (code, receipt["failure"]))
        self.assertFalse(self.fence(plan, ".terminal.json").exists())


class KnownFailureTests(Base):
    def assert_known_failure(self, plan, code, receipt, failure):
        self.assertEqual((1, "failed", failure), (code, receipt["result"], receipt["failure"]))
        self.assertEqual({"exited": True, "exitcode": 1}, json.loads(self.fence(plan, ".terminal.json").read_bytes()))
        self.assertEqual([], self.classify()["unresolved"])

    def test_wrong_task_outcomes_are_known_failures_and_close_the_fence(self):
        for changes, failure in (({"ownerExitCode": 0, "terminalExitCode": 0, "lastTaskResult": 0}, "task_exit_code"),
                                 ({"taskDeleted": False}, "task_not_deleted"),
                                 ({"commandLineMatched": False}, "task_command_line"),
                                 ({"events": []}, "task_events"),
                                 ({"rawStreams": []}, "task_stdout")):
            with self.subTest(failure=failure):
                self.setUp()
                self.qga.run_changes = changes
                plan, code, receipt = self.run_job()
                self.assert_known_failure(plan, code, receipt, failure)
                self.assertEqual("evidence-zip", self.qga.kinds()[-1], "a known failure still keeps its evidence")

    @staticmethod
    def owner_events(*kinds):
        return [{"name": "task-event-00000" + str(i) + "-" + kind + ".json", "bytes": 9, "sha256": "0" * 64, "kind": kind} for i, kind in enumerate(kinds)]

    def test_an_owner_that_left_its_child_outcome_open_is_unknown_and_blocks_the_next_job(self):
        for kinds, exit_code in ((("submission-intent",), None), (("submission-intent", "submitted"), None),
                                 (("submission-intent", "submitted"), -1073741510), (("submission-intent", "submitted", "pending"), 7)):
            with self.subTest(kinds=kinds, exit_code=exit_code):
                self.setUp()
                self.qga.run_changes = {"ownerExitCode": exit_code, "terminalExitCode": None, "lastTaskResult": None, "rawStreams": [], "events": self.owner_events(*kinds)}
                plan, code, receipt = self.run_job()
                self.assertEqual((3, "unknown", "task_child_outcome_unknown"), (code, receipt["result"], receipt["failure"]))
                self.assertFalse(self.fence(plan, ".terminal.json").exists())
                self.assertIn("direct-guest-" + plan["operationId"] + ".intent.json", {row["receipt"] for row in self.classify()["unresolved"]})
                count = self.qga.count("guest-exec")
                self.qga.run_changes = {}
                _, code, receipt = self.run_job()
                self.assertEqual((2, "prior_job_exit_unknown"), (code, receipt["failure"]))
                self.assertEqual(count, self.qga.count("guest-exec"))

    def test_an_owner_that_proved_no_child_started_is_a_known_failure(self):
        for kinds, exit_code in ((("refused-before-native-start",), 1), (("refused-before-native-start",), None),
                                 (("submission-intent", "refused-before-native-start"), 1), ((), None)):
            with self.subTest(kinds=kinds, exit_code=exit_code):
                self.setUp()
                self.qga.run_changes = {"ownerExitCode": exit_code, "terminalExitCode": None, "lastTaskResult": 1, "rawStreams": [], "commandLineMatched": False, "events": self.owner_events(*kinds)}
                plan, code, receipt = self.run_job()
                self.assert_known_failure(plan, code, receipt, "task_exit_code")

    def test_a_known_terminal_with_a_lost_owner_exit_stays_a_known_failure(self):
        self.qga.run_changes = {"ownerExitCode": None}
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "task_exit_code")

    def test_guest_exception_text_stays_in_the_private_index(self):
        self.qga.run_state = "refused-before-launch"
        self.qga.run_code = "Access to the path 'C:\\Users\\private-account\\x' is denied."
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "refused_before_launch:unclassified")
        data = Path(plan["dataDirectory"])
        self.assertIn("private-account", (data / "system-run-index.json").read_text(), "the raw message is kept for reading the original")
        raw = (data / "scenario-receipt.json").read_bytes()
        self.assertNotIn(b"private-account", raw)
        self.assertEqual("refused_before_launch:unclassified", self.rt.emitted[-1]["failure"])
        summary = driver.NativeScenarioWindowsDriver(ROOT, lambda value: ROOT)._summary(
            types.SimpleNamespace(correlation_id=plan["operationId"], scenario_id=plan["scenarioId"]), raw, {"operationId": plan["operationId"], "exitCode": 1})
        projected = execution.ScenarioExecutor._project_collection(summary)
        self.assertEqual("refused_before_launch:unclassified", projected["windows"]["failure"])
        self.assertNotIn("private-account", json.dumps(projected))

    def test_only_closed_guest_codes_cross(self):
        for value in ("RUN_BOOT_WAIT", "TASK_PIN_DIGEST_CHANGED", "TOKEN_TASK_XML", "PUB_ACTION", "RUN_A1_B2"):
            self.assertEqual(value, job.guest_code(value))
        for value in ("RUN_", "RUN_lower", "OTHER_CODE", "DOMAIN_USER", "RUN_A B", "C:\\Users\\x", "RUN_A\n", "RUN_" + "A" * 81, "", None, 7, ["RUN_A"]):
            self.assertEqual("unclassified", job.guest_code(value), repr(value))

    def test_a_publisher_that_returned_undecodable_output_is_a_known_failure(self):
        original = self.qga._publisher

        def corrupt(m, pid):
            result = original(m, pid)
            return {"exited": True, "exitcode": 0, "out-data": base64.b64encode(base64.b64encode(b"not gzip")).decode()} if m["action"] == "initialize" else result
        self.qga._publisher = corrupt
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "publisher_refused:publish-initialize")

    def test_refused_before_launch_is_a_known_failure(self):
        self.qga.run_state = "refused-before-launch"
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "refused_before_launch:RUN_SYNTHETIC_CODE")

    def test_a_boot_refusal_of_the_run_program_is_known_and_any_other_nonzero_exit_is_not(self):
        refusal = {"exited": True, "exitcode": 3, "out-data": base64.b64encode(json.dumps({"state": "refused-before-file-effects", "code": "GUEST_BOOT_OR_ACTOR_MISMATCH", "fileEffects": False}).encode()).decode()}
        self.assertTrue(job.refused_before_effects(refusal))
        for terminal in ({"exited": True, "exitcode": 1, "out-data": refusal["out-data"]}, {"exited": True, "exitcode": 3}, {"exited": True, "exitcode": 3, "out-data": "not base64!"},
                         {"exited": True, "exitcode": 3, "out-data": base64.b64encode(b'{"state":"refused-before-file-effects","fileEffects":true}').decode()}):
            self.assertFalse(job.refused_before_effects(terminal))
        original = self.qga._system_run
        self.qga._system_run = lambda m, pid: (original(m, pid), refusal)[1]
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "system_run_refused_before_file_effects")

    def test_a_program_that_cannot_be_rendered_never_reaches_the_guest(self):
        real = job.MAX_SOURCE_BYTES
        original = job.check_source

        def narrow(source):
            # The context program passes; the first publisher program is over the bound.
            if "Add-Type -AssemblyName System.IO.Compression" in source:
                raise ValueError("guest_source_bound")
            return original(source)
        with mock.patch.object(job, "check_source", narrow):
            plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "guest_source_refused:guest_source_bound")
        self.assertEqual(["context"], self.qga.kinds())
        self.assertEqual(79183, real)

    def test_a_failed_publisher_program_is_a_known_failure(self):
        self.qga.program_exit["endpoints"] = 1
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "publisher_refused:publish-endpoints-1")
        self.assertEqual(1, self.qga.kinds().count("endpoints"))

    def test_a_changed_write_is_refused_by_verify_and_never_rewritten(self):
        original = self.qga._guest_file_write

        def corrupt(arguments):
            result = original(arguments)
            path = self.qga.handles[arguments["handle"]]["path"]
            self.qga.files[path] = self.qga.files[path][:-1] + b"X"
            return result
        self.qga._guest_file_write = corrupt
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "publisher_refused:publish-verify-1")
        self.assertEqual(1, self.qga.kinds().count("verify"))

    def test_a_lost_file_write_reply_is_never_written_twice(self):
        self.qga.lose = lambda command, kind, ordinal: TimeoutError() if command == "guest-file-write" else None
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "guest_file_push_lost")
        self.assertEqual(1, self.qga.count("guest-file-write"))

    def test_missing_evidence_turns_a_pass_into_a_known_failure(self):
        self.qga.lose = lambda command, kind, ordinal: TimeoutError() if command == "guest-file-read" and self.qga.kinds()[-1] == "evidence-zip" else None
        plan, code, receipt = self.run_job()
        self.assert_known_failure(plan, code, receipt, "evidence_read_lost")
        self.assertIsNone(receipt["evidence"])

    def test_evidence_bytes_are_kept_on_the_host_and_named_by_their_hash(self):
        plan, code, receipt = self.run_job()
        raw = (Path(plan["dataDirectory"]) / receipt["evidence"]["name"]).read_bytes()
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest(), 5), (receipt["evidence"]["bytes"], receipt["evidence"]["sha256"], receipt["evidence"]["entries"]))
        self.assertEqual(0, code)
        self.assertGreater(self.rt.reads, 1, "each 65,536-byte read lets the host truncate its wire files")


class AdmissionTests(Base):
    def prior(self, *, exit_code=0, fence=None, anchored=True, record=True):
        """A prior job as its files say; ``fence`` is the terminal, or None for none."""
        operation = str(uuid.uuid4())
        data = self.machine_data / operation
        data.mkdir(parents=True, mode=0o700)
        if record:
            (data / "job-exit.json").write_text(json.dumps({"schemaVersion": 1, "operationId": operation, "exitCode": exit_code, "fenceAnchored": anchored}))
        if anchored:
            self.rt.save("direct-guest-" + operation + ".intent.json", {"operationId": operation})
            self.rt.save("direct-guest-" + operation + ".ack.json", {"operationId": operation, "ack": {"pid": 5}, "replayAllowed": False})
            if fence is not None:
                self.rt.save("direct-guest-" + operation + ".terminal.json", fence)
        return operation

    def assert_refused(self, reason):
        before = {path.name for path in self.vm.iterdir()}
        plan, code, receipt = self.run_job()
        self.assertEqual((2, reason, "failed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual(0, self.qga.count("guest-exec"))
        self.assertEqual(before, {path.name for path in self.vm.iterdir()}, "a refused job anchors nothing")
        self.assertEqual({"schemaVersion": 1, "operationId": plan["operationId"], "exitCode": 2, "fenceAnchored": False},
                         json.loads((Path(plan["dataDirectory"]) / "job-exit.json").read_bytes()))

    def test_a_new_job_refuses_while_a_prior_exit_is_unknown(self):
        self.prior(exit_code=3)
        self.assert_refused("prior_job_exit_unknown")

    def test_a_new_job_refuses_while_a_prior_job_left_no_exit(self):
        self.prior(record=False)
        self.assert_refused("prior_job_exit_unknown")

    def test_a_new_job_refuses_while_a_prior_fence_is_open(self):
        self.prior(exit_code=0)
        self.assert_refused("prior_fence_open")

    def test_a_terminal_without_an_integer_exit_does_not_close_a_prior_fence(self):
        self.prior(exit_code=0, fence={"exited": True})
        self.assert_refused("prior_fence_open")

    def test_a_prior_anchored_job_with_its_fence_gone_refuses(self):
        operation = str(uuid.uuid4())
        data = self.machine_data / operation
        data.mkdir(parents=True, mode=0o700)
        (data / "job-exit.json").write_text(json.dumps({"schemaVersion": 1, "operationId": operation, "exitCode": 0, "fenceAnchored": True}))
        self.assert_refused("prior_job_fence_missing")

    def test_a_real_unknown_job_blocks_the_next_one(self):
        self.qga.run_state = "owner-parked"
        _, code, _ = self.run_job()
        self.assertEqual(3, code)
        count = self.qga.count("guest-exec")
        self.qga.run_state = None
        plan, code, receipt = self.run_job()
        self.assertEqual((2, "prior_job_exit_unknown"), (code, receipt["failure"]))
        self.assertEqual(count, self.qga.count("guest-exec"))
        self.assertFalse(self.fence(plan, ".intent.json").exists())

    def test_closed_prior_jobs_admit_the_next_one(self):
        for exit_code in (0, 1):
            self.prior(exit_code=exit_code, fence={"exited": True, "exitcode": exit_code})
        self.prior(exit_code=2, anchored=False)
        _, code, _ = self.run_job()
        self.assertEqual(0, code)

    def test_a_refused_job_does_not_block_the_next_one(self):
        self.qga.session_flags = 0
        plan, code, receipt = self.run_job()
        self.assertEqual((2, "session_not_active:locked", "context"), (code, receipt["failure"], receipt["stage"]))
        self.assertEqual({"exited": True, "exitcode": 2}, json.loads(self.fence(plan, ".terminal.json").read_bytes()))
        self.assertEqual(["context"], self.qga.kinds())
        self.qga.session_flags = 1
        self.assertEqual(0, self.run_job()[1])

    def test_vm_root_entry_bound_is_the_start_fence_margin(self):
        for number in range(3501):
            (self.vm / ("filler-" + str(number))).touch()
        self.assert_refused("vm_root_entry_bound")

    def test_vm_root_at_the_bound_still_admits(self):
        for number in range(3500):
            (self.vm / ("filler-" + str(number))).touch()
        self.assertEqual(0, self.run_job()[1])

    def test_an_unreachable_agent_refuses_before_any_fence(self):
        self.qga.lose = lambda command, kind, ordinal: TimeoutError() if command == "guest-ping" else None
        self.assert_refused("guest_agent_unavailable")

    def test_a_second_job_of_one_operation_touches_nothing(self):
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        count = self.qga.count("guest-exec")
        before = {path.name: path.stat().st_mtime_ns for path in self.vm.iterdir()}
        receipt = (Path(plan["dataDirectory"]) / "scenario-receipt.json").read_bytes()
        again = job.run_job(self.rt, plan, self.files)
        self.assertEqual(2, again)
        self.assertEqual("job_already_exists", self.rt.emitted[-1]["failure"])
        self.assertEqual(count, self.qga.count("guest-exec"))
        self.assertEqual(before, {path.name: path.stat().st_mtime_ns for path in self.vm.iterdir()})
        self.assertEqual(receipt, (Path(plan["dataDirectory"]) / "scenario-receipt.json").read_bytes())

    def test_changed_bundle_bytes_are_refused_before_any_guest_effect(self):
        plan = self.plan()
        self.addCleanup(self.forget_modules, plan["operationId"])
        files = dict(self.files)
        files["agent_tools/windows_scenario_qualification_child.ps1"] = b"changed"
        self.assertEqual(2, job.run_job(self.rt, plan, files))
        self.assertEqual("bundle_bytes_changed", self.rt.emitted[-1]["failure"])
        self.assertEqual(0, len(self.qga.calls))


class ChunkTests(Base):
    def test_chunks_add_no_vm_root_entries_and_one_push_line_per_file(self):
        plan = self.plan()
        instance = job.Job(self.rt, plan, self.files)
        instance.data.mkdir(parents=True, mode=0o700)
        raw = random.Random(7).randbytes(32768 * 40 + 11)
        before = sorted(path.name for path in self.vm.iterdir())
        instance.push_file("C:\\ProgramData\\target.bin", raw)
        self.assertEqual(before, sorted(path.name for path in self.vm.iterdir()))
        self.assertEqual(raw, self.qga.files["C:\\ProgramData\\target.bin"])
        self.assertEqual(41, len(self.qga.write_sizes))
        self.assertEqual(32768, max(self.qga.write_sizes))
        lines = (instance.data / "push.jsonl").read_text().splitlines()
        self.assertEqual([{"path": "C:\\ProgramData\\target.bin", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "chunks": 41}],
                         [json.loads(line) for line in lines])


class DecodeTests(unittest.TestCase):
    @staticmethod
    def terminal(stdout):
        return {"exited": True, "exitcode": 0, "out-data": base64.b64encode(base64.b64encode(stdout)).decode()}

    def test_a_good_reply_decodes(self):
        self.assertEqual({"a": 1}, job.decode_stdout(self.terminal(gzip.compress(b'{"a":1}', mtime=0))))

    def test_undecodable_gzip_is_a_value_error_like_every_other_bad_reply(self):
        good = gzip.compress(b'{"a":1}' * 200, mtime=0)
        flipped = good[:len(good) // 2] + bytes([good[len(good) // 2] ^ 0xff]) + good[len(good) // 2 + 1:]
        for name, raw in (("not-gzip", b"not gzip"), ("truncated", good[:-6]), ("flipped", flipped), ("empty-member", good[:10])):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "guest_output_gzip"):
                job.decode_stdout(self.terminal(raw))


class ClosedDoorTests(unittest.TestCase):
    OPERATION = "11111111-1111-4111-8111-111111111111"
    ROOT_PATH = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + OPERATION
    WORKSPACE = "C:\\ProgramData\\VpnControlOrdinaryTask-" + OPERATION
    OWNER = WORKSPACE + "\\windows_ordinary_task_owner.ps1"
    CHILD = WORKSPACE + "\\windows_scenario_qualification_child.ps1"

    def build(self):
        from agent_tools.tests.test_windows_ordinary_task import pin
        row = json.loads(json.dumps(driver.RECIPES["windows-ordinary-qualification"]))
        context = {"deploymentId": MACHINE, "ordinarySid": SID, "ordinarySessionId": 2, "profileRoot": PROFILE, "localAppData": PROFILE + "\\AppData\\Local",
                   "machineGuid": RAW_GUID.lower(), "bootIdentifier": BOOT_IDENTIFIER, "bootFileTimeUtc": FILETIME}
        owner_raw = (ROOT / "agent_tools/windows_ordinary_task_owner.ps1").read_bytes()
        owner = pin(self.OWNER, size=len(owner_raw), digest=hashlib.sha256(owner_raw).hexdigest())
        child = pin(self.CHILD, size=259, digest="1" * 64)
        engine = pin(job.POWERSHELL_PATH)
        directories = [pin(path, directory=True) for path in job.ancestors([self.WORKSPACE, self.ROOT_PATH, job.POWERSHELL_PATH])]
        directories += [pin(self.WORKSPACE, directory=True), pin(self.ROOT_PATH, directory=True)]
        common = planner.common_request(context, self.OPERATION, self.ROOT_PATH, [engine, owner, child], directories, [], row["rawStreamLimitBytes"])
        request = planner.bootstrap_request(common, "qualification", qualificationSourcePath=self.CHILD, qualificationArguments=["-Value", "scenario-ok"])
        raw = planner.data(request)
        request_pin = pin(self.ROOT_PATH + "\\bootstrap-request.json", size=len(raw), digest=hashlib.sha256(raw).hexdigest())
        task = planner.render_task(request, owner, request_pin)
        expected = {"operationId": self.OPERATION, "operationRoot": self.ROOT_PATH, "context": dict(context),
                    "files": {item["path"]: item["sha256"] for item in (engine, owner, child)},
                    "directories": [item["path"] for item in directories], "child": self.CHILD, "owner": self.OWNER,
                    "ownerSha256": owner["sha256"], "requestSha256": request_pin["sha256"]}
        return row, request, task, expected

    def test_the_built_requests_pass(self):
        row, request, task, expected = self.build()
        job.assert_closed(row, {"worker": None, "bootstrap": request}, expected)
        job.assert_closed(row, {"worker": None, "bootstrap": request, "task": task}, expected)

    def test_assert_closed_refuses_mutated_requests(self):
        def request_change(change):
            def apply(row, request, task, expected):
                change(request)
            return apply

        def task_change(change):
            def apply(row, request, task, expected):
                change(task)
            return apply
        cases = {
            "free-arguments": request_change(lambda r: r["bootstrap"].update(qualificationArguments=["-Value", "other"])),
            "extra-argument": request_change(lambda r: r["bootstrap"]["qualificationArguments"].append("-Extra")),
            "other-source": request_change(lambda r: r["bootstrap"].update(qualificationSourcePath=self.OWNER)),
            "other-mode": request_change(lambda r: r["bootstrap"].update(mode="python-install")),
            "worker-argv": request_change(lambda r: r["bootstrap"].update(qualificationArgv=["cmd.exe"])),
            "cases-path": request_change(lambda r: r.update(casesPath=self.CHILD)),
            "worker-action": request_change(lambda r: r.update(action="qualification")),
            "python-runtime": request_change(lambda r: r.update(pythonRuntime={})),
            "extra-file-pin": request_change(lambda r: r["filePins"].append(dict(r["filePins"][0], path="C:\\Windows\\System32\\cmd.exe"))),
            "changed-file-hash": request_change(lambda r: r["filePins"][1].update(sha256="2" * 64)),
            "extra-directory": request_change(lambda r: r["directoryPins"].append(dict(r["directoryPins"][0], path="C:\\Other"))),
            "tree": request_change(lambda r: r["treePins"].append({"role": "installed-app", "root": "C:\\App", "files": []})),
            "other-operation": request_change(lambda r: r.update(operationId=str(uuid.uuid4()))),
            "other-root": request_change(lambda r: r.update(operationRoot=PROFILE + "\\AppData\\Local\\Other")),
            "other-limit": request_change(lambda r: r.update(rawStreamLimitBytes=64 * 1024 * 1024)),
            "other-context": request_change(lambda r: r["context"].update(ordinarySessionId=9)),
            "worker-request": lambda row, request, task, expected: expected.update(_worker=True),
            "task-name": task_change(lambda t: t.update(taskName="Other")),
            "task-allowed": task_change(lambda t: t.update(nativeActionAllowed=True)),
            "task-argv": task_change(lambda t: t["argv"].__setitem__(6, self.CHILD)),
            "task-exe": task_change(lambda t: t["argv"].__setitem__(0, "C:\\Windows\\System32\\cmd.exe")),
            "task-user": task_change(lambda t: t["policyExpected"].update(UserId="S-1-5-18")),
            "task-request": task_change(lambda t: t.update(requestSha256="3" * 64)),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                row, request, task, expected = self.build()
                change(row, request, task, expected)
                worker = {"action": "windows-public-update"} if "_worker" in expected else None
                requests = {"worker": worker, "bootstrap": request, "task": task}
                with self.assertRaisesRegex(job.KnownFailure, "requests_not_closed"):
                    job.assert_closed(row, requests, expected)

    def test_evidence_regex_refuses_activation_port(self):
        pattern = re.compile(job.EVIDENCE_NAME)
        for name in ("task-event-000000-submission-intent.json", "event-000012-update-ready.json", "child-3.stdout.raw", "task-child.stdout.raw",
                     "task-child.stderr.raw", "owner-parked.json", "task-owner-parked.json", "python-install.log", "python-install_000_core.log", "msi-install.log"):
            self.assertIsNotNone(pattern.fullmatch(name), name)
        for name in ("activation.port", "workspace\\activation.port", "event-1\\activation.port", "child-activation.port", "task-event-1.json.port",
                     "bootstrap-request.json", "worker-request.json", "secret.key", "../event-1.json", "event-1/activation.port", "windows_ordinary_task_owner.ps1", ""):
            self.assertIsNone(pattern.fullmatch(name), name)

    def test_the_guest_program_uses_exactly_the_tested_evidence_names(self):
        template = (ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text(encoding="ascii")
        self.assertEqual(1, template.count("$allowed='\\A@@EVIDENCE_NAME@@\\z'"))
        self.assertNotIn("-Recurse", template)
        self.assertNotIn("'", job.EVIDENCE_NAME)

    def test_templates_write_only_under_the_operation_roots_and_refuse_other_actions(self):
        publisher = (ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text(encoding="ascii")
        run = (ROOT / "agent_tools/windows_scenario_system_run.ps1.template").read_text(encoding="ascii")
        self.assertIn("throw 'PUB_ACTION'", publisher)
        self.assertEqual(2, publisher.count("Assert-OwnedPath $target.path"))
        self.assertIn("$m.mode -ceq 'qualification'", run)
        for forbidden in ("Stop-Process", "Stop-ScheduledTask", "Remove-Item", ".Terminate(", ".Kill(", "shutdown.exe", "Start-Process", "RunLevel>Highest", "Park-"):
            self.assertNotIn(forbidden, publisher + run, forbidden)
        self.assertNotIn("WaitForExit()", run.split("if($end -ceq 'exited'")[0], "the wait loop keeps polling")
        self.assertNotIn("Guard-Full", run[run.index("while($null -eq $end){"):run.index("if($end -ceq 'exited'")], "no full guard in the wait loop")

    @staticmethod
    def run_template():
        return (ROOT / "agent_tools/windows_scenario_system_run.ps1.template").read_text(encoding="ascii")

    def test_the_status_file_passes_a_real_null_as_the_replace_backup(self):
        # PowerShell turns $null into '' for a .NET string parameter, and File.Replace refuses ''.
        run = self.run_template()
        self.assertIn("[IO.File]::Replace($temporary,$path,[NullString]::Value)", run)
        self.assertNotIn("Replace($temporary,$path,$null)", run)

    def test_a_script_module_cmdlet_gets_its_own_stop_preference(self):
        # Get-ScheduledTask is a CDXML function: the program's Stop preference does not reach it, and any stderr makes the reply unreadable.
        self.assertIn("Get-ScheduledTask -TaskPath '\\' -TaskName $name -ErrorAction Stop", self.run_template())

    def test_an_owner_that_exits_during_its_identity_reads_stays_a_known_outcome(self):
        run = self.run_template()
        identity = run[run.index("$birth=([OrdinaryNativeFacts]::Birth($parent.Handle))"):run.index("try{$running.Refresh()")]
        self.assertLess(identity.index("try{$image=[string]$parent.Path}catch{"), identity.index("if(-not $parent.HasExited){"), "the image is read first, then the process is proven alive")
        self.assertLess(identity.index("if(-not $parent.HasExited){"), identity.index("N ($image -ieq"), "a wrong image stops only a live process")
        self.assertLess(identity.index("N ($image -ieq"), identity.index("Get-CimInstance"))
        self.assertIn("try{$cim=Get-CimInstance Win32_Process -Filter ('ProcessId='+$parent.Id) -OperationTimeoutSec 5", identity)
        self.assertIn("}catch{$line=''}", identity, "a missed read leaves the command line unmatched, a known failure")
        self.assertEqual(2, identity.count("'RUN_OWNER_IDENTITY'"), "birth, then image")

    def test_the_task_is_deleted_only_after_nothing_can_be_left_running(self):
        run = self.run_template()
        closing = run[run.index("if($end -ceq 'exited' -or $end -ceq 'ended'){"):run.index("}else{\n  # A parked owner or a passed row deadline")]
        delete = closing.index("$folder.DeleteTask($name,0)")
        self.assertLess(closing.index("if($end -ceq 'ended'){N ((Count-OperationProcesses) -eq 0) 'RUN_OPERATION_PROCESS_ALIVE'}"), delete)
        self.assertLess(closing.index("N ($rows.Count -eq 0 -or $null -ne $terminal -or $refused) 'RUN_CHILD_OUTCOME_UNKNOWN'"), delete)
        self.assertIn("if($value.kind -ceq 'refused-before-native-start'){$refused=$true}", closing)
        census = run[run.index("function Count-OperationProcesses"):run.index("$r=$null\ntry{")]
        self.assertIn(".Contains($m.operationId)", census)
        self.assertIn("Get-CimInstance Win32_Process", census)

    def test_a_refused_launch_never_follows_a_consumed_launch(self):
        run = self.run_template()
        self.assertLess(run.index("$script:P.launchConsumed=$true"), run.index("$running=$registered.Run($null)"))
        self.assertIn("state=$(if($unknown){'post-launch-unknown'}else{'refused-before-launch'})", run)


class SourceTests(Base):
    def job_with_context(self, **changes):
        plan = self.plan(**changes)
        self.addCleanup(self.forget_modules, plan["operationId"])
        instance = job.Job(self.rt, plan, self.files)
        instance.prepare()
        instance.stage_context()
        return instance

    def rendered(self):
        """Every guest program of the row at its largest declared input."""
        instance = self.job_with_context()
        pin = self.qga._pin("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        directories = [dict(self.qga._pin("C:\\" + "d" * 40 + str(number), directory=True)) for number in range(64)]
        instance.directory_pins = directories
        sources = {}
        original = instance.guest_program

        def capture(label, source, **options):
            sources[label] = source
            raise job.Unknown("captured")
        instance.guest_program = capture
        target = {"role": "r", "path": instance.workspace + "\\" + "f" * 64 + ".py", "bytes": 1, "sha256": "0" * 64, "kind": "data"}
        for action, label, fields in (("initialize", "initialize", {"existingDirectories": job.ancestors([instance.workspace, instance.operation_root, job.POWERSHELL_PATH]), "subfolders": []}),
                                      ("endpoints", "endpoints", {"targets": [dict(target, role="r" + str(i)) for i in range(job.FILE_BATCH)]}),
                                      ("verify", "verify", {"targets": [dict(target, role="r" + str(i), endpointPin=pin) for i in range(job.FILE_BATCH)]}),
                                      ("read-pins", "read-pins", {"readPaths": ["C:\\Python\\Lib\\" + "x" * 60 + str(i) + ".py" for i in range(job.READ_PIN_BATCH)]}),
                                      ("evidence-zip", "evidence", {"evidenceNumber": 1})):
            try:
                instance._publisher(label, action, **fields)
            except job.Unknown:
                pass
        instance.guest_program = original
        context_program = self.qga.programs[0][1]
        instance.rendered_task = {"policyValidatorPowerShell": planner.task_policy_powershell(
            {"UserId": SID, "LogonType": "InteractiveToken", "ExecutionTimeLimit": "PT0S", "MultipleInstancesPolicy": "IgnoreNew", "WorkingDirectory": instance.operation_root,
             "Command": job.POWERSHELL_PATH, "Arguments": "-NoProfile " + "a" * 2000})}
        run = instance._system_run_source({"schemaVersion": 1, "operationId": instance.op, "mode": "qualification", "scenarioId": instance.plan["scenarioId"], "context": instance.context,
                                           "workspace": instance.workspace, "taskName": "t", "taskRequestPin": pin, "taskArguments": "a" * 2000, "deadlineSeconds": 300, "taskXml": "<Task>" + "x" * 8000 + "</Task>"})
        return {"context": context_program, **sources, "run": run}

    def test_sources_are_ascii_and_within_the_largest_proven_bound(self):
        sources = self.rendered()
        self.assertEqual({"context", "initialize", "endpoints", "verify", "read-pins", "evidence", "run"}, set(sources))
        for name, source in sources.items():
            with self.subTest(name=name):
                raw = job.check_source(source)
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                self.assertLessEqual(len(raw), 79183)
                self.assertNotIn("@@", source)
                self.assertIn("$protocolResult= & {", source)
        self.assertIn("-gt 24576", sources["endpoints"])
        self.assertIn("-gt 65536", sources["read-pins"])

    @unittest.skipUnless(POWERSHELL, "PowerShell parser unavailable; hosted Windows and Linux runners have one")
    def test_every_rendered_source_parses(self):
        with tempfile.TemporaryDirectory(prefix="scenario-sources-") as directory:
            for name, source in self.rendered().items():
                path = Path(directory) / (name + ".ps1")
                path.write_text(source, encoding="ascii")
                script = ("$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile('" + str(path).replace("'", "''")
                          + "',[ref]$tokens,[ref]$errors);if(@($errors).Count){$errors|ForEach-Object {[Console]::Error.WriteLine($_.Message)};exit 9}")
                result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
                self.assertEqual(0, result.returncode, name + ": " + result.stderr.decode("utf-8", "replace"))

    @unittest.skipUnless(POWERSHELL, "PowerShell unavailable; hosted Windows and Linux runners have one")
    def test_the_status_file_is_really_replaced_on_every_poll(self):
        template = (ROOT / "agent_tools/windows_scenario_system_run.ps1.template").read_text(encoding="ascii")
        body = template[template.index("function Write-Status("):template.index("function Read-FirstEvent(")]
        with tempfile.TemporaryDirectory(prefix="scenario-status-") as directory:
            script = Path(directory) / "write-status.ps1"
            script.write_text("$ErrorActionPreference='Stop';$m=[pscustomobject]@{workspace='" + directory.replace("'", "''") + "'}\n" + body
                              + "foreach($number in 1,2,3){Write-Status ([ordered]@{poll=$number})}\n", encoding="ascii")
            result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))
            self.assertEqual(3, json.loads((Path(directory) / "scenario-status.json").read_text())["poll"])
            self.assertFalse((Path(directory) / "scenario-status.json.new").exists())

    def test_the_parser_of_the_guest_goes_first(self):
        found = {"powershell.exe": "C:\\ps51\\powershell.exe", "pwsh": "C:\\ps7\\pwsh.exe"}
        self.assertEqual("C:\\ps51\\powershell.exe", powershell_binary(found.get))
        self.assertEqual("/usr/bin/pwsh", powershell_binary({"pwsh": "/usr/bin/pwsh"}.get))
        self.assertIsNone(powershell_binary({}.get))

    def test_templates_and_child_are_exact_ascii_and_kept_out_of_line_ending_conversion(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        for name in ("windows_scenario_publisher.ps1.template", "windows_scenario_system_run.ps1.template", "windows_scenario_qualification_child.ps1"):
            self.assertIn("/agent_tools/" + name + " -text", attributes)
            raw = (ROOT / "agent_tools" / name).read_bytes()
            self.assertNotIn(b"\r", raw)
        for name in ("windows_scenario_publisher.ps1.template", "windows_scenario_system_run.ps1.template"):
            (ROOT / "agent_tools" / name).read_bytes().decode("ascii")
        child = (ROOT / "agent_tools/windows_scenario_qualification_child.ps1").read_bytes()
        self.assertEqual(259, len(child))
        self.assertTrue(child.startswith(b"\xef\xbb\xbf"))
        self.assertEqual("220abad9c02a9e86460980e2f7045cb65671746ccc7a8fd8d099b008009a87f9", hashlib.sha256(child).hexdigest())

    def test_native_slices_come_from_the_current_owner(self):
        owner = (ROOT / "agent_tools/windows_ordinary_task_owner.ps1").read_bytes()
        parts = job.fragments(owner, emitter)
        text = owner.decode("utf-8-sig")
        self.assertIn(parts["NATIVE"].split("public sealed class")[0].rstrip().rsplit("\n'@", 1)[0], text)
        self.assertNotIn("RetainedRawPump", parts["NATIVE"])
        self.assertIn(parts["ASSERTIONS"], text)
        self.assertIn("PinIdentity", parts["ASSERTIONS"])
        self.assertEqual({"NATIVE", "ASSERTIONS", "READONLY", "CREATE_DIRECTORY"}, set(parts))
        self.assertIn("public static class VpnPublisherFile {", parts["READONLY"])
        self.assertNotIn("public static string Identity(", parts["READONLY"])

    def test_publisher_replies_fit_their_bounds_after_compression(self):
        def pin(number):
            rng = random.Random(number)
            return {"path": "C:\\Users\\recovery\\AppData\\Local\\Programs\\Python\\Lib\\pkg%03d\\module_%04d.py" % (number % 40, number),
                    "nativeIdentity": {"attributes": 32, "volumeSerial": 123456789, "fileIndex": rng.getrandbits(60), "sizeBytes": rng.getrandbits(20), "links": 1,
                                       "creationFileTime": str(134000000000000000 + rng.getrandbits(40)), "lastWriteFileTime": str(134000000000000000 + rng.getrandbits(40))},
                    "security": {"ownerSid": "S-1-5-18", "sddl": "O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + SID + ")"},
                    "sha256": hashlib.sha256(str(number).encode()).hexdigest()}

        def encoded(rows):
            return len(base64.b64encode(gzip.compress(json.dumps({"filePins": rows}, separators=(",", ":")).encode())))
        self.assertLessEqual(encoded([pin(i) for i in range(job.FILE_BATCH)]), job.PUBLISHER_OUTPUT_BYTES)
        self.assertLessEqual(encoded([pin(i) for i in range(job.READ_PIN_BATCH)]), job.MAX_STDOUT_BYTES)


class StageShapeTests(unittest.TestCase):
    def test_the_test_inventory_is_the_bundle_inventory(self):
        self.assertEqual(BUNDLE_FILES, bundles._SCENARIOS["windows-scenario-driver"])

    def test_rows_only_name_closed_stages_in_order(self):
        for name, row in driver.RECIPES.items():
            with self.subTest(name=name):
                order = [stage for stage in job.STAGE_ORDER if stage in row["stages"]]
                self.assertEqual(order, list(row["stages"]))
                self.assertEqual(("anchor", "context"), tuple(row["stages"][:2]))
                self.assertEqual(("evidence", "receipt"), tuple(row["stages"][-2:]))

    def test_module_import_needs_only_the_standard_library(self):
        tree = ast.parse((ROOT / "agent_tools/windows_scenario_host_job.py").read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(0, node.level)
                imported.add(node.module.split(".")[0])
        import sys
        self.assertEqual(set(), imported - set(sys.stdlib_module_names))


@unittest.skipUnless(job.fcntl is not None, "flock is POSIX; the job runs on the Linux VM host")
class HostLockTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "intent.json"
        self.path.write_text("{}")

    def holder(self):
        descriptor = os.open(self.path, os.O_RDONLY)
        job.fcntl.flock(descriptor, job.fcntl.LOCK_EX)
        return descriptor

    def test_the_lock_is_held_for_one_exchange_and_released_before_returning(self):
        def during():
            probe = os.open(self.path, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    job.fcntl.flock(probe, job.fcntl.LOCK_EX | job.fcntl.LOCK_NB)
            finally:
                os.close(probe)
            return "reply"
        self.assertEqual("reply", job.locked_exchange(self.path, during))
        probe = os.open(self.path, os.O_RDONLY)
        job.fcntl.flock(probe, job.fcntl.LOCK_EX | job.fcntl.LOCK_NB)
        os.close(probe)

    def test_it_waits_for_a_readiness_holder_and_then_goes_ahead(self):
        descriptor = self.holder()
        ticks = []

        def sleep(seconds):
            ticks.append(seconds)
            if len(ticks) == 3:
                os.close(descriptor)
        self.assertEqual("reply", job.locked_exchange(self.path, lambda: "reply", sleep=sleep, monotonic=lambda: 0.0))
        self.assertEqual(3, len(ticks))

    def test_it_sends_nothing_after_the_wait_bound(self):
        descriptor = self.holder()
        self.addCleanup(os.close, descriptor)
        clock = [0.0]
        performed = []

        def sleep(seconds):
            clock[0] += 60

        with self.assertRaisesRegex(ValueError, "scenario_qga_busy"):
            job.locked_exchange(self.path, lambda: performed.append(1), sleep=sleep, monotonic=lambda: clock[0])
        self.assertEqual([], performed)
        self.assertGreaterEqual(clock[0], job.QGA_LOCK_WAIT_SECONDS)


STUB_DEFINITIONS = r"""
    import json,os,pathlib,time
    root=pathlib.Path(SPEC['root'])
    def require(value,reason):
        if not value:raise ValueError(reason)
    def chain():EVENTS.append('chain')
    def closing():EVENTS.append('closing')
    def instance_intent():EVENTS.append('intent')
    def read(name):return {'qemu-started.json':{'pid':11},'swtpm-started.json':{'pid':12},'mutable-artifacts.json':{'disk.qcow2':[1],'uefi-vars.fd':[1]}}[name]
    def process(row):EVENTS.append('process')
    def owns(pid,path,is_socket=False):EVENTS.append('owns')
    def structure(info):return (1,)
    def private(path):return None
    def save(name,value):
        with open(root/name,'x',encoding='utf-8') as stream:json.dump(value,stream,sort_keys=True)
        (root/name).chmod(0o600)
"""


@unittest.skipUnless(job.fcntl is not None, "the production binding is POSIX; the job runs on the Linux VM host")
class ProductionBindingTests(Base):
    """The real _host_main over stub canonical definitions and the fake agent's call()."""

    def run_program(self, *, hostboot="boot-a", qemu_sockets=True):
        import io
        import sys
        from contextlib import redirect_stdout
        operation = str(uuid.uuid4())
        self.addCleanup(self.forget_modules, operation)
        plan = self.plan(operation)
        spec = {"root": str(self.vm)}
        (self.vm / "intent.json").write_text("{}")
        (self.vm / "qga.sock").touch()
        text = Path(job.__file__).read_text(encoding="utf-8")
        marker = "    _CANONICAL_INSTANCE_DEFINITIONS()\n"
        self.assertEqual(1, text.count(marker))
        payload = gzip.compress(json.dumps({path: base64.b64encode(raw).decode() for path, raw in self.files.items()}).encode(), mtime=0)
        namespace = {"__name__": "__main__"}
        exec(compile(text.replace(marker, STUB_DEFINITIONS), "job", "exec"), namespace)
        events = []
        lock_states = []

        def call(path, command, arguments, _deadline=None):
            namespace["QGA_GUARD"]()
            probe = os.open(self.vm / "intent.json", os.O_RDONLY)
            try:
                try:
                    job.fcntl.flock(probe, job.fcntl.LOCK_EX | job.fcntl.LOCK_NB)
                    lock_states.append("free")
                except BlockingIOError:
                    lock_states.append("held")
            finally:
                os.close(probe)
            os.write(namespace["wire"], b"line\n")
            os.write(namespace["partial_wire"], b"line\n")
            return self.qga.rpc(command, arguments)
        namespace.update(SPEC=spec, SETUP={}, CONTEXT={"hostBootId": "boot-a"}, PLAN=plan, FILES_GZ=base64.b64encode(payload).decode(), EVENTS=events, call=call,
                         wire=-1, partial_wire=-1, QGA_PEER_PID=None, QGA_GUARD=None, _host_boot=lambda: hostboot)
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = namespace["_host_main"]()
        for name in ("wire", "partial_wire"):
            if namespace[name] != -1:
                os.close(namespace[name])
        sys.modules.pop("native_scenario_driver", None)
        return plan, code, json.loads(stream.getvalue().strip().splitlines()[-1]), lock_states, namespace

    def test_the_production_binding_runs_the_whole_job(self):
        plan, code, marker, lock_states, namespace = self.run_program()
        self.assertEqual((0, 0, None), (code, marker["scenarioExit"], marker["failure"]))
        self.assertEqual(11, namespace["QGA_PEER_PID"])
        self.assertEqual({"held"}, set(lock_states), "the flock covers every exchange")
        self.assertEqual(9, self.qga.kinds().__len__())
        self.assertEqual([], self.classify()["unresolved"])
        data = Path(plan["dataDirectory"])
        self.assertTrue((data / "qga.wire").exists())
        self.assertLess((data / "qga.wire").stat().st_size, 200, "evidence reads truncate the wire files")
        self.assertTrue((data / "bundle/agent_tools/windows_ordinary_task.py").exists())

    def test_only_evidence_reads_truncate_the_wire_files(self):
        self.qga.polls_before_exit = 3
        at_evidence = {}
        run_original, publisher_original = self.qga._system_run, self.qga._publisher

        def with_status(m, pid):
            self.qga.files[m["workspace"] + "\\scenario-status.json"] = b'{"poll":1}'
            return run_original(m, pid)

        def before_evidence(m, pid):
            if m["action"] == "evidence-zip":
                at_evidence["wire"] = (self.machine_data / m["operationId"] / "qga.wire").stat().st_size
                at_evidence["calls"] = len(self.qga.calls)
            return publisher_original(m, pid)
        self.qga._system_run, self.qga._publisher = with_status, before_evidence
        _, code, _, _, _ = self.run_program()
        self.assertEqual(0, code)
        self.assertGreater(self.qga.count("guest-file-read"), 8, "the status file really was read while the program ran")
        self.assertEqual(len(b"line\n") * at_evidence["calls"], at_evidence["wire"], "every exchange before the evidence read is still on the wire")

    def test_a_setup_reason_is_a_guards_word_or_a_class_name(self):
        self.assertEqual("instance_host_epoch", job._setup_reason(ValueError("instance_host_epoch")))
        self.assertEqual("ValueError", job._setup_reason(ValueError("Expecting value: line 1 column 1 (char 0)")))
        self.assertEqual("FileNotFoundError", job._setup_reason(FileNotFoundError(2, "No such file", "/home/private/qga.sock")))
        self.assertEqual("JSONDecodeError", job._setup_reason(json.JSONDecodeError("instance", "x", 0)))

    def test_a_changed_host_boot_refuses_before_anything_is_touched(self):
        plan, code, marker, _, _ = self.run_program(hostboot="boot-b")
        self.assertEqual((2, 2, "host_setup:instance_host_epoch"), (code, marker["scenarioExit"], marker["failure"]))
        self.assertEqual([], self.qga.calls)
        self.assertFalse(Path(plan["dataDirectory"]).exists())
        self.assertEqual({"intent.json", "qga.sock"}, {path.name for path in self.vm.iterdir()})


if __name__ == "__main__":
    unittest.main()
