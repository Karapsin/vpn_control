"""The durable job's stages, journals and exit rules over one shared fake guest agent.

The fake models the wire, not Windows: nothing here proves a PowerShell behaviour. The
flat journals are judged by the real host_work classifier, and the real emitter and
planner build and read every program and request.
"""
import ast
import importlib.util
import base64
from contextlib import nullcontext
import datetime
import gzip
import hashlib
import io
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
import zipfile

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
                "agent_tools/windows_scenario_qualification_child.ps1", "agent_tools/windows_disconnected_cli_cases.py",
                "agent_tools/windows_streaming_cli_cases.py", "scripts/test_packaged_cli.py", "scripts/windows_install_admission_diagnostic.py",
                "agent_tools/windows_postboot_source_roles.py", "agent_tools/windows_postboot_action.py", "agent_tools/windows_preboot_action.py",
                "agent_tools/windows_autostart_reboot.py", "agent_tools/windows_lifecycle_cases.py", "agent_tools/windows_runtime_branch_cases.py",
                "agent_tools/windows_lifecycle_runtime_stages.py", "scripts/windows_broker_fixture_observer.py",
                "agent_tools/windows_lifecycle_traffic_worker.py", "scripts/integration/socks_http_fixture.py",
                "agent_tools/windows_runtime_tcp_listeners.ps1", "agent_tools/windows_autostart_snapshot.ps1",
                "agent_tools/windows_autostart_create_highest_fixture.ps1", "agent_tools/windows_autostart_task_start.ps1",
                "agent_tools/windows_postboot_startup_actors.ps1",
                "agent_tools/windows_scenario_proxy.py", "agent_tools/windows_ordinary_dedicated_driver.py",
                "agent_tools/windows_lifecycle_runtime_fixture_worker.py", "scripts/integration/https_subscription_relay_fixture.py",
                "agent_tools/windows_public_updater/update_cases.py", "agent_tools/windows_public_updater/update_receipts.py",
                "agent_tools/windows_public_updater/update_fixture_server.py", "agent_tools/windows_public_updater/native_collector.py",
                "scripts/fixture_environment.py", "scripts/macos_packaging_jdk_preflight.py", "scripts/prepare_desktop_update_fixture.py",
                "agent_tools/windows_system_collector/caller_hold.py", "agent_tools/windows_system_collector/hold_protocol.py",
                "agent_tools/windows_system_collector/collector_contract.py", "agent_tools/windows_system_collector/collector_wrapper.py",
                "agent_tools/windows_system_collector/system_bootstrap_template.ps1",
                "agent_tools/windows_system_collector/release_template.ps1",
                "agent_tools/windows_system_collector/system_collector_worker.py",
                "agent_tools/windows_system_collector/native_primitives.py", "agent_tools/windows_system_collector/ordinary_task_guard.ps1",
                "agent_tools/windows_system_collector/system_collector_native.cs")
PYTHON_ROOT = PROFILE + "\\AppData\\Local\\Programs\\Python\\Python313"
INSTALLED_ROOT = PROFILE + "\\AppData\\Local\\vpn-control"
OLD_CODE = "{11111111-2222-4333-8444-555555555555}"
NEW_CODE = "{66666666-7777-4888-8999-AAAAAAAAAAAA}"
PACKAGE_CODE = "{77777777-8888-4999-8AAA-BBBBBBBBBBBB}"
VERSION = "2.2.15"


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
        # The guest's trees and MSI state: what list-tree, read-pins and msi-registration report.
        self.python_tree = (["DLLs/_ctypes.pyd", "Lib/ctypes/__init__.py", "Lib/json/__init__.py", "Lib/os.py", "Lib/subprocess.py",
                             "Lib/threading.py", "python.exe", "python313.dll"], ["DLLs", "Lib", "Lib/ctypes", "Lib/json"])
        self.trees = {PYTHON_ROOT: self.python_tree}
        self.installed_tree = (["app/vpn-control-cli.cfg", "runtime/bin/java.exe", "vpn-control-cli.exe", "vpn-control.exe"],
                               ["app", "runtime", "runtime/bin"])
        self.registration = []
        self.msi_properties = {"ProductCode": NEW_CODE, "ProductName": "vpn-control", "ProductVersion": VERSION,
                               "UpgradeCode": "{7a5e0a8e-2a7a-4baf-9f2a-5fb2c3529af2}"}
        self.signer_status = "Valid"
        # Return codes of product names the registration reader could not read.
        self.unnamed_codes = []
        # action -> callable(reply): what a real guest might say instead.
        self.reply_changes = {}
        # The DACL form a file the publisher creates and then protects reads back with. Natively (2026-11-08,
        # every worker-request.json pin of eight runs) SetAccessControl's protected DACL reads back auto-inherited.
        self.endpoint_form = "PAI"
        self.install_effect = True
        self.task_exit = None
        self.requests_seen = []
        self.boot_filetime = FILETIME
        self.guest_data = {}  # Bytes an earlier job left in the guest, read by a later one's read-pins.
        self.evidence_factory = None
        # The installed jars that hold the bundled runtime entry, and what the read pins of a path were.
        self.runtime_jars = {"app/desktopApp.jar"}
        self.runtime_bytes = b"MZ bundled sing-box"
        self.read_pin_records = {}
        self.runtime_reply = None

    def file_security(self):
        return {"ownerSid": "S-1-5-18", "sddl": "O:SYD:" + self.endpoint_form + "(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + SID + ")"}

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
        elif path not in self.files and not self.listed(path):
            raise ValueError()
        self.next_index += 1
        self.handles[self.next_index] = {"path": path, "offset": 0}
        return self.next_index

    def listed(self, path):
        """A file of a guest tree: an agent read returns the bytes read-pins hash."""
        return any(path.startswith(root + "\\") and path[len(root) + 1:].replace("\\", "/") in files for root, (files, _) in self.trees.items())

    def _guest_file_write(self, arguments):
        raw = base64.b64decode(arguments["buf-b64"])
        self.write_sizes.append(len(raw))
        path = self.handles[arguments["handle"]]["path"]
        self.files[path] += raw
        return {"count": len(raw), "eof": False}

    def _guest_file_read(self, arguments):
        row = self.handles[arguments["handle"]]
        whole = self.files[row["path"]] if row["path"] in self.files else self.content(row["path"])
        raw = whole[row["offset"]:row["offset"] + arguments["count"]]
        row["offset"] += len(raw)
        return {"count": len(raw), "buf-b64": base64.b64encode(raw).decode(), "eof": row["offset"] >= len(whole)}

    def _guest_file_close(self, arguments):
        del self.handles[arguments["handle"]]
        return {}

    def _context(self):
        value = facts()
        value["machine"] = MACHINE.upper()
        value["session"]["Flags"] = self.session_flags
        return {"exited": True, "exitcode": 0, "out-data": out_data({
            "sessionFacts": value, "machineGuid": RAW_GUID, "hardwareUuid": MACHINE.upper(), "bootIdentifier": BOOT_IDENTIFIER,
            "bootFileTimeUtc": self.boot_filetime, "profileRoot": PROFILE, "systemToken": TOKEN})}

    def _actor(self, pid):
        return {"pid": pid, "birthFileTimeUtc": "134368653065000001", "sessionId": 0, "path": job.POWERSHELL_PATH, "principalSid": "S-1-5-18",
                "is64BitProcess": True, "powerShellMajor": 5, "powerShellEdition": "Desktop", "tokenElevation": 1, "tokenElevationType": 1,
                "boot": {"lastBootUpTimeFileTimeUtc": self.boot_filetime, "machineGuid": RAW_GUID, "hardwareUuid": MACHINE.upper()}}

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
                                "filePin": self._pin(target["path"], security=self.file_security()), "expectedBytes": target["bytes"],
                                "expectedSha256": target["sha256"],
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
            pins = [self._pin(path, raw=self.content(path), security={
                "ownerSid": OS_OWNER, "sddl": "O:" + OS_OWNER + "D:P(A;;FA;;;" + OS_OWNER + ")(A;;FRFX;;;BU)"}) for path in m["readPaths"]]
            self.read_pin_records.update({pin["path"]: pin for pin in pins})
            reply.update(state="ordinary-publication-read-pins", filePins=pins)
        elif action == "runtime-extract":
            app = m["installedRoot"] + "\\app\\"
            if not all(path.startswith(app) and path.endswith(".jar") and "\\" not in path[len(app):] for path in m["jarPaths"]):
                return {"exited": True, "exitcode": 1, "err-data": base64.b64encode(b"PUB_RUNTIME_JAR").decode()}
            found = [path for path in m["jarPaths"] if "app/" + path[len(app):] in self.runtime_jars]
            if len(found) != 1 or m["runtimePath"] != m["workspace"] + "\\sing-box.exe" or m["runtimePath"] in self.files:
                return {"exited": True, "exitcode": 1, "err-data": base64.b64encode(b"PUB_RUNTIME_ENTRY_COUNT").decode()}
            self.files[m["runtimePath"]] = self.runtime_bytes
            # The jar is read through a held pin of the same file the installed tree pinned.
            runtime = {"jarPin": dict(self.read_pin_records[found[0]]), "filePin": self._pin(m["runtimePath"], raw=self.runtime_bytes),
                       "entry": "bin/windows-amd64/sing-box.exe"}
            if self.runtime_reply is not None:
                self.runtime_reply(runtime)
            reply.update(state="ordinary-runtime-extracted", runtime=runtime)
        elif action == "list-tree":
            found = self.trees.get(m["treeRoot"])
            listing = {"present": found is not None, "files": list(found[0]) if found else [], "directories": list(found[1]) if found else []}
            reply.update(state="ordinary-tree-listing", treeRoot=m["treeRoot"], listing=listing)
        elif action == "read-directories":
            reply.update(state="ordinary-publication-read-directories", directoryPins=[self._pin(path, directory=True) for path in m["readDirectories"]])
        elif action == "installer-signer":
            reply.update(state="ordinary-installer-signer", signer={"filePin": self._pin(m["installerPath"], raw=self.files[m["installerPath"]]),
                         "status": self.signer_status, "subject": "CN=Python Software Foundation, O=Python Software Foundation, C=US",
                         "certificateSha256": "c" * 64})
        elif action == "msi-properties":
            reply.update(state="ordinary-msi-properties", package={"filePin": self._pin(m["packagePath"], raw=self.files[m["packagePath"]]),
                                                                   "properties": dict(self.msi_properties)})
        elif action == "msi-registration":
            # Three other products (the Python runtime's) are considered beside any vpn-control row.
            reply.update(state="ordinary-msi-registration", products=[dict(row) for row in self.registration],
                         scan={"considered": len(self.registration) + 3 + len(self.unnamed_codes), "unnamed": len(self.unnamed_codes),
                               "unnamedCodes": list(self.unnamed_codes)})
        elif action == "evidence-zip":
            path = m["workspace"] + "\\evidence-" + str(m["evidenceNumber"]) + ".zip"
            raw = self.evidence_factory(m) if self.evidence_factory is not None else b"PK" + b"evidence" * 40000
            self.files[path] = raw
            reply.update(state="ordinary-evidence-zip", zipPath=path, zipBytes=len(raw), zipSha256=hashlib.sha256(raw).hexdigest(), entries=5)
        else:
            raise AssertionError("closed publisher action")
        change = self.reply_changes.get(action)
        if change is not None:
            change(reply)
        return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}

    def content(self, path):
        """Installed bytes depend on what was installed, so a changed product changes the tree digest."""
        if path in self.guest_data:
            return self.guest_data[path]
        return b"exe:" + str(self.msi_properties["ProductVersion"]).encode() if path.startswith(INSTALLED_ROOT + "\\") else b"exe"

    def install(self, worker):
        if worker["action"] in {"msi-install", "msi-reset"}:
            self.registration = [{"productCode": self.msi_properties["ProductCode"], "context": 2, "productName": "vpn-control",
                                  "version": self.msi_properties["ProductVersion"], "installLocation": INSTALLED_ROOT + "\\",
                                  "packageCode": PACKAGE_CODE}]
            # msiexec /x removes only the package's own files and /i adds its files beside whatever else is there.
            files, directories = self.trees.get(INSTALLED_ROOT, ([], []))
            if worker["action"] == "msi-reset":
                files = [name for name in files if name not in self.installed_tree[0]]
            self.trees[INSTALLED_ROOT] = (sorted({*files, *self.installed_tree[0]}), sorted({*directories, *self.installed_tree[1]}))

    def _system_run(self, m, pid):
        pin = m["taskRequestPin"]
        request = json.loads(self.files[pin["path"]])
        if hashlib.sha256(self.files[pin["path"]]).hexdigest() != pin["sha256"] or request["bootstrap"]["mode"] != m["mode"]:
            raise AssertionError("request pin differs from the published bytes")
        worker = None
        if m["mode"] == "python-worker":
            worker = json.loads(self.files[request["bootstrap"]["workerRequestPath"]])
            if hashlib.sha256(self.files[request["bootstrap"]["workerRequestPath"]]).hexdigest() != request["bootstrap"]["workerRequestSha256"]:
                raise AssertionError("worker request differs from the published bytes")
        self.requests_seen.append({"bootstrap": request, "worker": worker})
        if m["taskXml"].startswith("<?xml") or planner.policy_fields(m["taskXml"])["Arguments"] != m["taskArguments"]:
            raise AssertionError("task policy differs")
        reply = {"schemaVersion": 1, "operationId": m["operationId"], "productOperation": False, "bootstrapOpening": self._actor(pid),
                 "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        if self.run_state is not None:
            reply.update(state=self.run_state, code=self.run_code, parkedFiles=["owner-parked.json"], taskDeleted=False)
        else:
            def stream(name, text):
                return {"name": name, "bytes": len(text), "sha256": hashlib.sha256(text.encode()).hexdigest()}
            exit_code = (7 if m["mode"] == "qualification" else 0) if self.task_exit is None else self.task_exit
            if m["mode"] == "python-install" and exit_code == 0 and self.install_effect:
                self.trees[PYTHON_ROOT] = self.python_tree
            if worker is not None and exit_code == 0 and self.install_effect:
                self.install(worker)
            reply.update({"state": "task-finished", "taskName": m["taskName"], "instanceGuid": "{guid}", "enginePid": 900, "ownerPid": 901,
                          "ownerBirthFileTimeUtc": "134368653065000002", "ownerExitCode": exit_code, "lastTaskResult": exit_code, "terminalExitCode": exit_code,
                          "commandLineMatched": True, "workerEvents": 0, "taskDeleted": True, "polls": 2, "statusFailures": 0, "parkedFiles": [],
                          "sourceClosing": True,
                          "events": [{"name": "task-event-00000" + str(i) + "-" + kind + ".json", "bytes": 9, "sha256": "0" * 64, "kind": kind}
                                     for i, kind in enumerate(("submission-intent", "submitted", "terminal"))],
                          "rawStreams": ([stream("stdout", "stdout|scenario-ok"), stream("stderr", "stderr|scenario-ok")] if m["mode"] == "qualification"
                                         else [stream("stdout", ""), stream("stderr", "")])})
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


class PublisherFunctionOutputTests(unittest.TestCase):
    """A PowerShell function returns everything it does not capture.

    Natively (2026-11-08) the MSI reader's bare COM calls made its result a list, so a
    good package failed as publisher_msi_receipt:package_shape_list before msiexec.
    """

    def test_the_msi_reader_has_no_bare_method_call_statement(self):
        source = (ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text(encoding="ascii")
        body = source[source.index("function Get-MsiProperties"):source.index("function Get-MsiRegistration")]
        self.assertEqual([], re.findall(r"(?:^|[;{])\s*(\$[A-Za-z]+\.[A-Za-z]+\()", body, re.M))


class RegistrationReaderTests(unittest.TestCase):
    """The ordinary user's per-user install must be visible to the SYSTEM reader.

    Natively (2026-11-08) msiexec registered vpn-control 2.2.16 per user, unmanaged, for
    the ordinary SID, and the reader that enumerated each context by that SID and named
    products by ProductName returned no row (installed_product_state:count_0). The reader
    now enumerates every user and context at once and reads InstalledProductName, as the
    natively proven installed-context reader in windows_tertiary_guest_stage does, and it
    counts a name it cannot read instead of dropping that product silently.
    """

    def body(self, source):
        return source[source.index("function Get-MsiRegistration"):source.index("function New-EvidenceZip")]

    def test_the_reader_enumerates_every_user_and_context_and_counts_unread_names(self):
        body = self.body((ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text(encoding="ascii"))
        self.assertIn('MsiEnumProductsExW(null,"S-1-1-0",7,', body)
        self.assertIn("'InstalledProductName'", body)
        self.assertIn("$unnamed=$unnamed+1", body)
        self.assertNotIn("return rc==0&&size<=1024?value.ToString():null", body)

    def test_each_row_carries_the_package_code_of_its_own_registration(self):
        # An update row's inputs bind the base and target registrations by package code, read where the row was found.
        body = self.body((ROOT / "agent_tools/windows_scenario_publisher.ps1.template").read_text(encoding="ascii"))
        self.assertIn("packageCode=[VpnScenarioMsiRegistration]::Info($product.Code,$product.Sid,$product.Context,'PackageCode')", body)


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
                    "directories": [item["path"] for item in directories], "owner": self.OWNER, "ownerSha256": owner["sha256"],
                    "requestSha256": request_pin["sha256"], "bootstrapTrees": [], "pythonRuntime": None, "worker": None,
                    "installedRoot": PROFILE + "\\AppData\\Local\\vpn-control",
                    "bootstrap": job.bootstrap_inputs(row, job.layout(self.OPERATION, context, row))}
        self.assertEqual(self.CHILD, expected["bootstrap"]["qualificationSourcePath"])
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
                     "task-child.stderr.raw", "owner-parked.json", "task-owner-parked.json", "python-install.log", "python-install_000_core.log", "msi-install.log",
                     "msi-uninstall.log"):
            self.assertIsNotNone(pattern.fullmatch(name), name)
        for name in ("activation.port", "workspace\\activation.port", "event-1\\activation.port", "child-activation.port", "task-event-1.json.port",
                     "bootstrap-request.json", "worker-request.json", "secret.key", "../event-1.json", "event-1/activation.port", "windows_ordinary_task_owner.ps1", "",
                     "package.msi", "msi-repair.log", "workspace"):
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
        self.assertIn("@('qualification','python-install','python-worker') -ccontains $m.mode", run)
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
        folders = job.update_subfolders(instance.op, {"update": {"collectorStages": ["before-install", "terminal-actors"]}})
        fixture = instance.workspace + "\\mcp-update-fixture-" + job.fixture_id(instance.op)
        for action, label, fields in (("initialize", "initialize", {"existingDirectories": job.ancestors([instance.workspace, instance.operation_root, job.POWERSHELL_PATH]), "subfolders": []}),
                                      ("initialize", "initialize-update", {"existingDirectories": job.ancestors([instance.workspace, instance.operation_root, job.POWERSHELL_PATH]),
                                                                           "subfolders": [name for name, rights in folders if rights == "0x1200a9"],
                                                                           "privateSubfolders": [name for name, rights in folders if rights == "FA"]}),
                                      ("seal-readonly", "seal-readonly", {"sealPath": fixture + "\\content\\packages\\target\\vpn-control-" + "9" * 40 + ".msi"}),
                                      ("fixture-tls", "fixture-tls", {}),
                                      ("collector-observe", "collector-observe", {"childStdoutLabels": ["one-public-update-install"], "readDisposition": True,
                                                                                  "productWorkspace": instance.workspace + "\\product-workspace"}),
                                      ("endpoints", "endpoints", {"targets": [dict(target, role="r" + str(i)) for i in range(job.FILE_BATCH)]}),
                                      ("verify", "verify", {"targets": [dict(target, role="r" + str(i), endpointPin=pin) for i in range(job.FILE_BATCH)]}),
                                      ("read-pins", "read-pins", {"readPaths": ["C:\\Python\\Lib\\" + "x" * 60 + str(i) + ".py" for i in range(job.READ_PIN_BATCH)]}),
                                      ("read-directories", "read-directories", {"readDirectories": [PYTHON_ROOT + "\\Lib\\" + "x" * 60 + str(i) for i in range(job.DIRECTORY_BATCH)]}),
                                      ("list-tree", "list-tree", {"treeRoot": PYTHON_ROOT}),
                                      ("installer-signer", "installer-signer", {"installerPath": instance.workspace + "\\python-3.13.15-amd64.exe"}),
                                      ("msi-properties", "msi-properties", {"packagePath": instance.workspace + "\\package.msi"}),
                                      ("msi-registration", "msi-registration", {"productName": "vpn-control"}),
                                      ("runtime-extract", "runtime-extract", {"installedRoot": INSTALLED_ROOT, "runtimePath": instance.workspace + "\\sing-box.exe",
                                                                              "jarPaths": [INSTALLED_ROOT + "\\app\\" + "j" * 60 + str(i) + ".jar" for i in range(400)]}),
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
        self.assertEqual({"context", "initialize", "initialize-update", "seal-readonly", "fixture-tls", "collector-observe", "endpoints", "verify", "read-pins",
                          "read-directories", "list-tree", "installer-signer", "msi-properties", "msi-registration", "runtime-extract", "evidence", "run"},
                         set(sources))
        for name, source in sources.items():
            with self.subTest(name=name):
                raw = job.check_source(source)
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                self.assertLessEqual(len(raw), 79183)
                self.assertNotIn("@@", source)
                self.assertIn("$protocolResult= & {", source)
        self.assertIn("-gt 24576", sources["endpoints"])
        self.assertIn("-gt 65536", sources["read-pins"])
        self.assertIn("-gt 65536", sources["read-directories"])
        self.assertIn("-gt 65536", sources["list-tree"])
        self.assertIn("-gt 24576", sources["msi-registration"])
        self.assertIn("-gt 24576", sources["runtime-extract"])

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

        def directory(number):
            rng = random.Random(number)
            return {"path": PYTHON_ROOT + "\\Lib\\site\\pkg%04d" % number,
                    "nativeIdentity": {"attributes": 16, "volumeSerial": 123456789, "fileIndex": rng.getrandbits(60)},
                    "security": {"ownerSid": SID, "sddl": "O:" + SID + "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;" + SID + ")"}}
        self.assertLessEqual(len(base64.b64encode(gzip.compress(json.dumps({"directoryPins": [directory(i) for i in range(job.DIRECTORY_BATCH)]}).encode()))),
                             job.MAX_STDOUT_BYTES)
        names = ["Lib/%s/module_%04d.py" % (["encodings", "email", "asyncio", "json", "tkinter", "idlelib"][i % 6], i) for i in range(job.TREE_FILE_LIMIT)]
        listing = {"listing": {"present": True, "files": names, "directories": ["Lib/d%03d" % i for i in range(300)]}}
        self.assertLessEqual(len(base64.b64encode(gzip.compress(json.dumps(listing).encode()))), job.MAX_STDOUT_BYTES)

    def test_the_planner_pins_the_installer_the_owner_script_pins(self):
        owner = (ROOT / "agent_tools/windows_ordinary_task_owner.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("record.sha256 -cne '" + planner.PYTHON_INSTALLER_SHA256 + "'", owner)
        self.assertIn("stream.Length -ne " + str(planner.PYTHON_INSTALLER_BYTES) + ")", owner)


class FamilyBase(Base):
    """The first family on one fake VM: setup rows, then product rows that name what setup left."""

    def setUp(self):
        super().setUp()
        self.artifacts = self.work / "home/.cache/vpn-control-windows-scenarios/artifacts"
        self.artifacts.mkdir(parents=True, mode=0o700)
        self.msi = random.Random(3).randbytes(job.CHUNK_BYTES * 3 + 5)
        self.packages = {}
        for role, raw in (("basePackage", self.msi), ("targetPackage", self.msi), ("pythonInstaller", random.Random(4).randbytes(40000))):
            digest = hashlib.sha256(raw).hexdigest()
            (self.artifacts / digest).write_bytes(raw)
            (self.artifacts / digest).chmod(0o600)
            self.packages[role] = {"sha256": digest, "bytes": len(raw)}
        # The planner pins the real installer's bytes; this synthetic installer stands in for them in the job's own planner.
        original = job.Job._load
        installer = self.packages["pythonInstaller"]

        def load(instance, name):
            module = original(instance, name)
            if name == "windows_ordinary_task":
                module.PYTHON_INSTALLER_SHA256, module.PYTHON_INSTALLER_BYTES = installer["sha256"], installer["bytes"]
            return module
        patcher = mock.patch.object(job.Job, "_load", load)
        patcher.start()
        self.addCleanup(patcher.stop)

    def family_plan(self, scenario, *, prior=None, operation=None, stop=None):
        row = json.loads(json.dumps(driver.RECIPES[scenario]))
        keys = [key for key in row["artifactKeys"] if key in driver.PACKAGE_KINDS]
        product = {"sourceSha": "a" * 40, "productVersion": VERSION} if "scenarioInput" in row["artifactKeys"] else None
        return self.plan(operation, scenarioId=scenario, row=row, artifactDirectory=str(self.artifacts),
                         packages={key: self.packages[key] for key in keys}, product=product,
                         prior={} if prior is None else {"install": prior}, stopAfter=stop)

    def run_family(self, scenario, **options):
        plan = self.family_plan(scenario, **options)
        self.addCleanup(self.forget_modules, plan["operationId"])
        start = len(self.qga.programs)
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan), [kind for kind, _ in self.qga.programs[start:]]

    def install_base(self):
        plan, code, receipt, _ = self.run_family("windows-msi-base-install")
        self.assertEqual((0, None), (code, receipt["failure"]))
        return plan["operationId"], receipt

    def pins_under(self, request, root):
        return [pin["path"] for pin in request["filePins"] + request["directoryPins"]
                if pin["path"] == root or pin["path"].startswith(root + "\\")]


class PublisherReceiptCheckTests(FamilyBase):
    """A publisher reply that fails a receipt check names that check, only by a finite code."""

    def test_each_failed_package_check_is_named(self):
        def pin(reply):
            return reply["package"]["filePin"]
        cases = (
            ("array", lambda reply: reply.update(package=[{"note": "stray output"}, reply["package"]]), "package_shape_list"),
            ("properties", lambda reply: reply["package"].update(properties=["ProductCode"]), "properties_shape_list"),
            ("links", lambda reply: pin(reply)["nativeIdentity"].update(links=2), "pin_single-link-file-digest"),
            ("path", lambda reply: pin(reply).update(path=pin(reply)["path"] + "x"), "held_path"),
            ("hash", lambda reply: pin(reply).update(sha256="0" * 64), "held_sha256"),
            ("size", lambda reply: pin(reply)["nativeIdentity"].update(sizeBytes=1), "held_size"),
            ("state", lambda reply: reply.update(state="ordinary-other"), "state"),
            ("keys", lambda reply: reply.update(extra=True), "keys"),
        )
        for name, change, check in cases:
            with self.subTest(name=name):
                self.qga.reply_changes = {"msi-properties": change}
                plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
                self.assertEqual((1, "publisher_msi_receipt:" + check), (code, receipt["failure"]))
                self.assertNotIn("system-run", kinds)

    def test_a_signer_reply_names_its_check_too(self):
        del self.qga.trees[PYTHON_ROOT]
        self.qga.reply_changes = {"installer-signer": lambda reply: reply.update(signer=[reply["signer"]])}
        plan, code, receipt, kinds = self.run_family("windows-python-install")
        self.assertEqual((1, "publisher_signer_receipt:signer_shape_list"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_guest_text_never_becomes_the_check_name(self):
        self.assertEqual("ValueError", job.Job._receipt_check(ValueError("C:\\Users\\someone\\package.msi is locked")))
        self.assertEqual("TypeError", job.Job._receipt_check(TypeError("unhashable type: 'dict'")))
        self.assertEqual("KeyError", job.Job._receipt_check(KeyError("properties")))
        self.assertEqual("held_size", job.Job._receipt_check(ValueError("held_size")))


class FamilyJobTests(FamilyBase):
    def test_the_family_runs_in_order_on_one_vm(self):
        del self.qga.trees[PYTHON_ROOT]
        plan, code, receipt, kinds = self.run_family("windows-python-install")
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual(["context", "initialize", "endpoints", "verify", "read-pins", "list-tree", "installer-signer", "endpoints", "verify",
                          "system-run", "list-tree", "evidence-zip"], kinds)
        self.assertEqual({"files": 8, "directories": 4}, receipt["python"])
        bootstrap = self.qga.requests_seen[-1]["bootstrap"]["bootstrap"]
        workspace = job.WORKSPACE_PREFIX + plan["operationId"]
        self.assertEqual({"mode": "python-install", "pythonInstallerPath": workspace + "\\python-3.13.15-amd64.exe", "pythonTargetDir": PYTHON_ROOT,
                          "pythonLogPath": PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"] + "\\python-install.log",
                          "pythonInstallerSignerCertificateSha256": "c" * 64}, bootstrap)

        install, receipt = self.install_base()
        tree = receipt["installed"].pop("treeSha256")
        self.assertRegex(tree, "[0-9a-f]{64}")
        self.assertEqual({"packageSha256": self.packages["basePackage"]["sha256"], "productCode": NEW_CODE, "productVersion": VERSION, "treeFiles": 4,
                          "packageCode": PACKAGE_CODE},
                         receipt["installed"])
        self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"], "setup never claims an installed package")
        seen = self.qga.requests_seen[-1]
        self.assertEqual("msi-install", seen["worker"]["action"])
        self.assertIn(job.MSIEXEC_PATH, {pin["path"] for pin in seen["worker"]["filePins"]})
        self.assertNotIn(job.MSIEXEC_PATH, {pin["path"] for pin in seen["bootstrap"]["filePins"]})
        self.assertEqual([], self.pins_under(seen["bootstrap"], INSTALLED_ROOT))

        for scenario in ("windows-packaged-cli-smoke", "windows-disconnected-cli-config", "windows-streaming-client-interrupt"):
            with self.subTest(scenario=scenario):
                plan, code, receipt, kinds = self.run_family(scenario, prior=install)
                self.assertEqual((0, None), (code, receipt["failure"]))
                self.assertEqual({"installedPackage": True, "packageSha256": self.packages["targetPackage"]["sha256"]}, receipt["windows"])
                self.assertEqual(tree, receipt["installed"]["treeSha256"])
                self.assertNotIn("list-tree", kinds[kinds.index("system-run"):], "a product row installs nothing")
                seen = self.qga.requests_seen[-1]
                self.assertEqual([], self.pins_under(seen["bootstrap"], INSTALLED_ROOT), "installed pins live only in the worker request")
                self.assertEqual(["installed-app", "python-runtime"], sorted(tree_["role"] for tree_ in seen["worker"]["treePins"]))
                self.assertEqual(["python-runtime"], [tree_["role"] for tree_ in seen["bootstrap"]["treePins"]])
                root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"]
                workspace = job.WORKSPACE_PREFIX + plan["operationId"]
                if scenario == "windows-packaged-cli-smoke":
                    self.assertEqual([PYTHON_ROOT + "\\python.exe", "-E", "-s", "-B", workspace + "\\test_packaged_cli.py", "--launcher",
                                      INSTALLED_ROOT + "\\vpn-control-cli.exe", "--expected-version", VERSION], seen["worker"]["qualificationArgv"])
                    self.assertNotIn("casesPath", seen["worker"])
                else:
                    self.assertEqual(scenario.removeprefix("windows-"), seen["worker"]["action"])
                    self.assertEqual(workspace + "\\" + ("windows_disconnected_cli_cases.py" if "disconnected" in scenario else "windows_streaming_cli_cases.py"),
                                     seen["worker"]["casesPath"])
                    self.assertEqual(root + "\\workspace", seen["worker"]["workspace"])
                    self.assertNotIn("qualificationArgv", seen["worker"])
                planner.validate_closure(seen["worker"])
                planner.validate_python_runtime(seen["bootstrap"], seen["bootstrap"]["bootstrap"]["pythonPath"])

        plan, code, receipt, kinds = self.run_family("windows-msi-base-reset")
        self.assertEqual((0, None), (code, receipt["failure"]))
        self.assertEqual("msi-reset", self.qga.requests_seen[-1]["worker"]["action"])
        self.assertEqual(NEW_CODE, self.qga.requests_seen[-1]["worker"]["uninstallProductCode"], "the exact registered product, by its code")
        self.assertEqual(INSTALLED_ROOT, self.qga.requests_seen[-1]["worker"]["uninstallRoot"], "the folder the removal must leave without files")
        self.assertEqual(tree, receipt["installed"]["treeSha256"])
        plan, code, receipt, _ = self.run_family("windows-packaged-cli-smoke", prior=plan["operationId"])
        self.assertEqual((0, True), (code, receipt["windows"]["installedPackage"]))
        self.assertEqual([], self.classify()["unresolved"])
        self.assertTrue(all(re.fullmatch(r"direct-guest-[0-9a-f-]{36}\.(?:intent|ack|terminal)\.json", path.name) for path in self.vm.iterdir()))

    def test_a_large_package_goes_in_chunks_with_no_vm_root_entry_per_chunk(self):
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual(0, code)
        package = job.WORKSPACE_PREFIX + plan["operationId"] + "\\package.msi"
        self.assertEqual(self.msi, self.qga.files[package])
        lines = [json.loads(line) for line in (Path(plan["dataDirectory"]) / "push.jsonl").read_text().splitlines()]
        self.assertEqual([{"path": package, "bytes": len(self.msi), "sha256": hashlib.sha256(self.msi).hexdigest(), "chunks": 4}],
                         [line for line in lines if line["path"] == package])
        self.assertEqual(3 * (len(kinds) + 1), len(list(self.vm.iterdir())), "three flat journal entries per program and the fence, none per chunk")

    def test_an_unstaged_or_changed_package_is_refused_before_any_guest_effect(self):
        digest = self.packages["basePackage"]["sha256"]
        for change in ("changed", "missing"):
            with self.subTest(change=change):
                if change == "changed":
                    (self.artifacts / digest).write_bytes(b"x" * len(self.msi))
                else:
                    (self.artifacts / digest).unlink()
                plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
                self.assertEqual((2, "artifact_cache_unavailable", []), (code, receipt["failure"], kinds))
                self.assertFalse(self.fence(plan, ".intent.json").exists())
        self.assertEqual(0, self.qga.count("guest-exec"))

    def test_a_base_install_never_takes_files_it_did_not_install_into_its_baseline(self):
        self.qga.trees[INSTALLED_ROOT] = (["runtime-cache.bin"], ["app"])
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual((1, "installed_files_present", None), (code, receipt["failure"], receipt["installed"]))
        self.assertNotIn("system-run", kinds)
        # An empty folder holds nothing the installed-tree digest would count.
        self.qga.trees[INSTALLED_ROOT] = ([], ["app"])
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual((0, None, 4), (code, receipt["failure"], receipt["installed"]["treeFiles"]))

    def test_installer_rows_never_upgrade_or_remove_silently(self):
        self.qga.registration = [{"productCode": OLD_CODE, "context": 2, "productName": "vpn-control", "version": "2.2.13",
                                  "installLocation": INSTALLED_ROOT, "packageCode": PACKAGE_CODE}]
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual((1, "installed_product_state:count_1:considered_4:unnamed_0"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)
        self.qga.registration = []
        plan, code, receipt, kinds = self.run_family("windows-msi-base-reset")
        self.assertEqual((1, "installed_product_state:count_0:considered_3:unnamed_0"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)
        self.qga.registration = [{"productCode": OLD_CODE, "context": 4, "productName": "vpn-control", "version": "2.2.13",
                                  "installLocation": INSTALLED_ROOT, "packageCode": PACKAGE_CODE}]
        plan, code, receipt, kinds = self.run_family("windows-msi-base-reset")
        self.assertEqual((1, "installed_product_state:context_4"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_a_package_naming_another_product_or_version_is_refused_by_its_own_properties(self):
        for name, change in (("version", {"ProductVersion": "2.2.13"}), ("name", {"ProductName": "other"}),
                             ("upgrade", {"UpgradeCode": "{00000000-0000-4000-8000-000000000000}"}), ("code", {"ProductCode": "not-a-code"})):
            with self.subTest(name=name):
                self.qga.msi_properties = {**self.qga.msi_properties, **change}
                plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
                self.assertEqual((1, "msi_package_identity"), (code, receipt["failure"]))
                self.assertNotIn("system-run", kinds)
                self.qga.msi_properties = FakeQga().msi_properties

    def test_python_is_installed_once_per_vm(self):
        plan, code, receipt, kinds = self.run_family("windows-python-install")
        self.assertEqual((1, "python_tree_present"), (code, receipt["failure"]))
        self.assertNotIn("installer-signer", kinds)
        self.assertNotIn("system-run", kinds)

    def test_an_installer_without_the_python_signature_never_runs(self):
        del self.qga.trees[PYTHON_ROOT]
        self.qga.signer_status = "NotSigned"
        plan, code, receipt, kinds = self.run_family("windows-python-install")
        self.assertEqual((1, "python_installer_signer"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_a_registration_read_that_could_not_name_products_says_so(self):
        # Natively the reader saw no vpn-control row after a good per-user install; its
        # count says what it considered and which name reads failed, never which names.
        self.qga.unnamed_codes = [1608, 1605]
        plan, code, receipt, kinds = self.run_family("windows-msi-base-reset")
        self.assertEqual((1, "installed_product_state:count_0:considered_5:unnamed_2_rc_1608"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_a_registration_reply_without_its_scan_is_refused(self):
        self.qga.reply_changes = {"msi-registration": lambda reply: reply.pop("scan")}
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual((1, "publisher_registration_receipt"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_a_registration_row_without_a_package_code_is_refused(self):
        self.qga.registration = [{"productCode": OLD_CODE, "context": 2, "productName": "vpn-control", "version": "2.2.13",
                                  "installLocation": INSTALLED_ROOT, "packageCode": PACKAGE_CODE}]
        self.qga.reply_changes = {"msi-registration": lambda reply: [row.pop("packageCode") for row in reply["products"]]}
        plan, code, receipt, kinds = self.run_family("windows-msi-base-reset")
        self.assertEqual((1, "publisher_registration_receipt"), (code, receipt["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_a_python_install_that_left_no_tree_is_a_known_failure(self):
        del self.qga.trees[PYTHON_ROOT]
        self.qga.install_effect = False
        plan, code, receipt, kinds = self.run_family("windows-python-install")
        self.assertEqual((1, "python_tree_absent", "installed"), (code, receipt["failure"], receipt["stage"]))
        self.assertEqual(["system-run", "list-tree", "evidence-zip"], kinds[-3:])

    def test_an_installer_that_registered_something_else_is_a_known_failure(self):
        self.qga.install_effect = False
        plan, code, receipt, kinds = self.run_family("windows-msi-base-install")
        self.assertEqual((1, "installed_registration_differs:count_0:considered_3:unnamed_0", "installed"),
                         (code, receipt["failure"], receipt["stage"]))
        self.assertIsNone(receipt["installed"])


class ProductAdmissionTests(FamilyBase):
    def assert_refused(self, scenario, reason, prior):
        plan, code, receipt, kinds = self.run_family(scenario, prior=prior)
        self.assertEqual((2, reason, []), (code, receipt["failure"], kinds))
        self.assertFalse(self.fence(plan, ".intent.json").exists(), "a refused job anchors nothing")

    def test_a_product_row_needs_a_passed_install_of_its_own_package(self):
        self.assert_refused("windows-packaged-cli-smoke", "prior_install_unavailable", str(uuid.uuid4()))
        plan, code, _, _ = self.run_family("windows-ordinary-qualification")
        self.assertEqual(0, code)
        self.assert_refused("windows-packaged-cli-smoke", "prior_install_unavailable", plan["operationId"])
        install, _ = self.install_base()
        other = random.Random(9).randbytes(100)
        self.packages["targetPackage"] = {"sha256": hashlib.sha256(other).hexdigest(), "bytes": len(other)}
        self.assert_refused("windows-disconnected-cli-config", "prior_install_other_package", install)

    def test_a_failed_install_is_no_baseline(self):
        self.qga.task_exit = 1
        plan, code, receipt, _ = self.run_family("windows-msi-base-install")
        self.assertEqual(1, code)
        self.qga.task_exit = None
        self.assert_refused("windows-streaming-client-interrupt", "prior_install_unavailable", plan["operationId"])

    def test_the_installed_product_must_still_be_what_setup_left(self):
        install, _ = self.install_base()
        cases = (("tree", lambda: setattr(self.qga, "installed_tree", (self.qga.installed_tree[0] + ["app/extra.jar"], self.qga.installed_tree[1])),
                  "installed_tree_differs"),
                 ("bytes", lambda: self.qga.msi_properties.update(ProductVersion="2.2.16"), "installed_tree_differs"),
                 ("registration", lambda: self.qga.registration[0].update(version="2.2.16"), "installed_registration_differs:version"),
                 ("second", lambda: self.qga.registration.append(dict(self.qga.registration[0], context=4)), "installed_registration_differs:count_2:considered_5:unnamed_0"),
                 ("location", lambda: self.qga.registration[0].update(installLocation="C:\\Other\\"), "installed_registration_differs:location"),
                 ("unset", lambda: self.qga.registration[0].update(installLocation=""), "installed_registration_differs:location_empty"),
                 ("machine", lambda: self.qga.registration[0].update(context=4), "installed_registration_differs:context_4"))
        for name, change, reason in cases:
            with self.subTest(name=name):
                saved = (json.loads(json.dumps(self.qga.registration)), dict(self.qga.msi_properties), self.qga.installed_tree)
                change()
                self.qga.trees[INSTALLED_ROOT] = self.qga.installed_tree
                plan, code, receipt, kinds = self.run_family("windows-packaged-cli-smoke", prior=install)
                self.assertEqual((1, reason), (code, receipt["failure"]))
                self.assertNotIn("system-run", kinds)
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])
                self.qga.registration, self.qga.msi_properties, self.qga.installed_tree = saved
                self.qga.trees[INSTALLED_ROOT] = self.qga.installed_tree

    def test_a_failed_product_run_claims_nothing(self):
        install, _ = self.install_base()
        self.qga.task_exit = 1
        plan, code, receipt, _ = self.run_family("windows-packaged-cli-smoke", prior=install)
        self.assertEqual((1, "task_exit_code"), (code, receipt["failure"]))
        self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])

    def test_a_product_row_stopped_before_its_task_claims_nothing(self):
        # Registration and installed tree match at publish, but no worker ran: no --version under the ordinary token.
        install, _ = self.install_base()
        for stop in ("context", "publish"):
            with self.subTest(stop=stop):
                plan, code, receipt, kinds = self.run_family("windows-packaged-cli-smoke", prior=install, stop=stop)
                self.assertEqual((0, stop, stop), (code, receipt["stoppedAfter"], receipt["stage"]))
                self.assertNotIn("system-run", kinds)
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])


class PinBoundTests(FamilyBase):
    """A product row's worker request holds both trees, so their joint bound is checked before either tree is pinned."""

    def grow(self, python_files, python_directories=0):
        # One PowerShell pin, the worker, harness and diagnostic, 3,708 Python files and 384 installed files are 4,096 pins.
        files, directories = self.qga.python_tree
        self.qga.python_tree = (files + ["Lib/site/m%05d.py" % number for number in range(python_files)],
                                directories + ["Lib/site", *("Lib/site/d%04d" % number for number in range(python_directories))])
        self.qga.trees[PYTHON_ROOT] = self.qga.python_tree
        files, directories = self.qga.installed_tree
        self.qga.installed_tree = (files + ["app/lib%04d.jar" % number for number in range(380)], directories)
        install, _ = self.install_base()
        return self.run_family("windows-packaged-cli-smoke", prior=install)

    def assert_refused_before_any_tree_pin(self, code, receipt, kinds):
        self.assertEqual((1, "worker_pin_bound"), (code, receipt["failure"]))
        self.assertEqual(["read-pins"], [kind for kind in kinds if kind in {"read-pins", "read-directories"}], "only the fixed OS pins were read")
        self.assertNotIn("system-run", kinds)
        self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])

    def test_a_product_row_at_both_planner_bounds_runs(self):
        plan, code, receipt, _ = self.grow(3700, 1000)
        self.assertEqual((0, None), (code, receipt["failure"]))
        worker = self.qga.requests_seen[-1]["worker"]
        self.assertEqual((4096, 1024), (len(worker["filePins"]), len(worker["directoryPins"])))

    def test_one_file_over_the_bound_refuses_before_any_tree_pin(self):
        self.assert_refused_before_any_tree_pin(*self.grow(3701)[1:])

    def test_one_directory_over_the_bound_refuses_before_any_tree_pin(self):
        self.assert_refused_before_any_tree_pin(*self.grow(3700, 1001)[1:])


class WorkerClosedDoorTests(FamilyBase):
    """Every worker row's requests as the job built them from synthetic pins, then mutated: each is refused."""

    def captured(self, scenario, prior=None, calls=None):
        calls = [] if calls is None else calls
        original = job.assert_closed

        def record(row, requests, expected):
            calls.append(json.loads(json.dumps([row, requests, expected])))
            return original(row, requests, expected)
        with mock.patch.object(job, "assert_closed", record):
            plan, code, receipt, _ = self.run_family(scenario, prior=prior)
        self.assertEqual((0, None), (code, receipt["failure"]))
        return plan, calls[-1]

    def assert_refused(self, captured, change):
        row, requests, expected = json.loads(json.dumps(captured))
        change(row, requests, expected)
        with self.assertRaisesRegex(job.KnownFailure, "requests_not_closed"):
            job.assert_closed(row, requests, expected)

    def test_the_built_worker_requests_pass_and_each_mutation_is_refused(self):
        plan, base = self.captured("windows-msi-base-install")
        install = plan["operationId"]
        captures = {"windows-msi-base-install": base}
        for scenario in ("windows-packaged-cli-smoke", "windows-disconnected-cli-config", "windows-streaming-client-interrupt", "windows-msi-base-reset"):
            captures[scenario] = self.captured(scenario, None if scenario.endswith("reset") else install)[1]
        installed_pin = dict(captures["windows-packaged-cli-smoke"][1]["worker"]["filePins"][-1])

        def worker(change):
            return lambda row, requests, expected: change(requests["worker"])

        def both(change):
            def apply(row, requests, expected):
                change(requests["worker"])
                change({"filePins": [], "directoryPins": [], **expected["worker"]})
            return apply
        common = {
            "worker-action": worker(lambda w: w.update(action="msi-install" if w["action"] != "msi-install" else "qualification")),
            "worker-extra-pin": worker(lambda w: w["filePins"].append(dict(w["filePins"][0], path="C:\\Windows\\System32\\cmd.exe"))),
            "worker-changed-hash": worker(lambda w: w["filePins"][0].update(sha256="2" * 64)),
            "worker-tree": worker(lambda w: w["treePins"].pop()),
            "worker-runtime": worker(lambda w: w.update(pythonRuntime=dict(w["pythonRuntime"], root="C:\\Python"))),
            "worker-root": worker(lambda w: w.update(operationRoot=PROFILE + "\\AppData\\Local\\Other")),
            "bootstrap-mode": lambda row, requests, expected: requests["bootstrap"]["bootstrap"].update(mode="qualification"),
            "bootstrap-worker-pin": lambda row, requests, expected: requests["bootstrap"]["bootstrap"].update(workerRequestSha256="3" * 64),
            "bootstrap-tree": lambda row, requests, expected: requests["bootstrap"]["treePins"].clear(),
            "installed-in-bootstrap": lambda row, requests, expected: (requests["bootstrap"]["filePins"].append(installed_pin),
                                                                       expected["files"].update({installed_pin["path"]: installed_pin["sha256"]})),
            "no-worker": lambda row, requests, expected: requests.update(worker=None),
        }
        special = {
            "windows-msi-base-install": {"msi-path": worker(lambda w: w.update(msiPath=w["msiPath"] + ".other")),
                                         "extra-reset-code": worker(lambda w: w.update(uninstallProductCode=OLD_CODE))},
            "windows-msi-base-reset": {"uninstall-code": worker(lambda w: w.update(uninstallProductCode=OLD_CODE)),
                                       "uninstall-log": worker(lambda w: w.update(uninstallLogPath=w["installerLogPath"])),
                                       "uninstall-root": worker(lambda w: w.update(uninstallRoot=PYTHON_ROOT))},
            "windows-packaged-cli-smoke": {"argv-extra": worker(lambda w: w["qualificationArgv"].append("--extra")),
                                           "argv-isolated": worker(lambda w: w["qualificationArgv"].__setitem__(1, "-I")),
                                           "argv-version": worker(lambda w: w["qualificationArgv"].__setitem__(-1, "2.2.13")),
                                           "cases-path": worker(lambda w: w.update(casesPath=w["qualificationArgv"][4]))},
            "windows-disconnected-cli-config": {"cases-path": worker(lambda w: w.update(casesPath=w["harnessPath"])),
                                                "free-argv": worker(lambda w: w.update(qualificationArgv=["cmd.exe"])),
                                                "workspace": worker(lambda w: w.update(workspace=w["workspace"] + "-other"))},
            "windows-streaming-client-interrupt": {"cases-path": worker(lambda w: w.update(casesPath=w["harnessPath"])),
                                                   "action": worker(lambda w: w.update(action="disconnected-cli-config"))},
        }
        for scenario, captured in captures.items():
            job.assert_closed(*captured)
            for name, change in {**common, **special[scenario]}.items():
                with self.subTest(scenario=scenario, change=name):
                    self.assert_refused(captured, change)


AUTHORITY = INSTALLED_ROOT + "\\app\\native\\windows-amd64\\native-helpers.json"


def authority_record(runtime_sha256, **changes):
    """native-helpers.json as scripts/windows_native_helpers.py writes it: the bundled runtime's digest and size."""
    value = {"schemaVersion": 1, "policySha256": "e" * 64, "artifacts": [],
             "runtimeAuthority": {"runtimeSha256": runtime_sha256, "runtimeSizeBytes": 41943040, "authoritySourceSha256": "f" * 64}}
    value.update(changes)
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def iso_boot(filetime):
    """A boot FILETIME as readiness's sessionFacts.boot reports it: LastBootUpTime in UTC, round-trip format."""
    ticks = int(filetime)
    moment = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(seconds=ticks // 10 ** 7)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % (ticks % 10 ** 7)


def without_autostart(events):
    """An owner that failed before it changed autostart: no autostart intent and no checkpoint in its journal."""
    events[:] = [row for row in events if row[0] not in job.AUTOSTART_INTENTS and row[0] != "reboot-checkpoint"]


class RebootFamilyTests(FamilyBase):
    """A reboot pair on one fake VM: the preboot declares the app it left running, readiness-reboot runs, then the postboot."""

    def setUp(self):
        super().setUp()
        files, directories = self.qga.installed_tree
        # The package's own layout: no loose runtime, which ships inside an app jar; its digest is in native-helpers.json.
        native = ["app/native/windows-amd64/" + name for name in ("native-helpers.json", "vpn-control-install-helper.exe",
                                                                   "vpn-control-vpn-broker.exe")]
        self.qga.installed_tree = (sorted([*files, "app/desktopApp.jar", "app/kotlin-stdlib.jar", *native]),
                                   sorted([*directories, "app/native", "app/native/windows-amd64"]))
        self.runtime = hashlib.sha256(b"bundled sing-box.exe").hexdigest()
        self.qga.guest_data[AUTHORITY] = authority_record(self.runtime)
        self.install, _ = self.install_base()
        self.change_rows = None
        self.change_events = None
        self.qga.evidence_factory = self.evidence

    def declared(self, workspace, scenario):
        product = hashlib.sha256(b"exe:" + VERSION.encode()).hexdigest()
        rows = [{"role": role, "pid": 500 + number, "parentPid": 40 if number == 0 else 500 + number - 1,
                 "creationFileTime": str(int(self.qga.boot_filetime) + 1000 + number),
                 "image": workspace + "\\runtime\\tools\\sing-box.exe" if role == "runtime" else INSTALLED_ROOT + "\\vpn-control.exe",
                 "sha256": self.runtime if role == "runtime" else product, "sid": SID, "sessionId": 2}
                for number, role in enumerate(job.DECLARED_ROLES[:5 if scenario == "reconnect" else 4])]
        if self.change_rows is not None:
            self.change_rows(rows)
        return rows

    def evidence(self, m):
        worker = self.qga.requests_seen[-1]["worker"] if self.qga.requests_seen else None
        operation = m["operationId"]
        # A reboot owner's journal. A job whose owner never ran, or no reboot owner, copies none here.
        config = worker.get("postbootAcceptance") if worker is not None and worker["operationId"] == operation else None
        events = [] if config is None else [("owner-started", {"operationId": operation, "pid": 900}),
                                            ("child-started", {"child": 0, "pid": 901}), ("child-started", {"child": 1, "pid": 902})]
        if config is not None and config["phase"] == "preboot-reboot" and config["scenario"] != "query-first":
            # An intent precedes each autostart change and the product's own start.
            events += [("autostart-public-toggle-intent", {"enabled": False}), ("autostart-highest-fixture-intent", {}),
                       ("autostart-public-toggle-intent", {"enabled": True}), ("product-autostart-start-intent", {})]
            events.append(("reboot-checkpoint", {"schemaVersion": 3, "kind": "owned-reboot-checkpoint", "operationId": operation,
                           "scenario": config["scenario"], "deploymentId": MACHINE, "ordinarySid": SID, "oldSessionId": 2,
                           "oldBootFileTimeUtc": self.qga.boot_filetime, "workspace": worker["workspace"],
                           "declaredProduct": self.declared(worker["workspace"], config["scenario"]), "replayAllowed": False}))
        if self.change_events is not None:
            self.change_events(events)
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w") as archive:
            for ordinal, (kind, value) in enumerate(events):
                archive.writestr("event-%06d-%s.json" % (ordinal, kind), json.dumps(
                    {"schemaVersion": 1, "operationId": operation, "ordinal": ordinal, "kind": kind, "value": value}, sort_keys=True))
            archive.writestr("child-0000.stdout.raw", b"")
        return memory.getvalue()

    def run_reboot(self, scenario, *, preboot=None, **options):
        plan = self.family_plan(scenario, prior=self.install, **options)
        if preboot is not None:
            plan["prior"]["preboot"] = preboot
        self.addCleanup(self.forget_modules, plan["operationId"])
        start = len(self.qga.programs)
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan), [kind for kind, _ in self.qga.programs[start:]]

    def submit_reboot(self, receipt, *, action="reboot", boot=None, products=None, known=True):
        """readiness-reboot's own VM-root journal: submitted from the preboot's boot, its idle census knowing the declared app."""
        preboot = receipt["preboot"]
        recovery, operation = hashlib.sha256(uuid.uuid4().bytes).hexdigest(), str(uuid.uuid4())
        count = preboot["declaredProcesses"] if products is None else products
        rows = [{"pid": 4, "name": "System", "session": 0, "knownSystem": True, "self": False}] + [
            {"pid": 500 + number, "name": "sing-box.exe" if number == 4 else "vpn-control.exe", "session": 2, "knownSystem": known, "self": False}
            for number in range(count)]
        before = {"state": "observed", "operationId": operation, "guestAgent": True,
                  "sessionFacts": {"boot": iso_boot(boot or preboot["bootFileTimeUtc"])}, "idleFacts": {"processes": rows}}
        name = "readiness-recovery-" + recovery
        for suffix, value in ((".intent.json", {"action": action, "recoveryId": recovery, "operationId": operation, "before": before,
                                                 "replayAllowed": False}),
                              (".ack.json", {"operationId": operation, "responseObserved": True, "replayAllowed": False}),
                              (".result.json", {**before, "state": "submitted", "guest": "booting", "shutdownAcknowledged": True})):
            (self.vm / (name + suffix)).write_text(json.dumps(value, sort_keys=True) + "\n")
        return recovery, operation

    def new_boot(self, receipt):
        """The guest after a boot: the same clone at a later boot time, the preboot's files in place."""
        preboot = receipt["preboot"]
        with zipfile.ZipFile(io.BytesIO(self.qga.files[job.WORKSPACE_PREFIX + receipt["correlationId"] + "\\evidence-1.zip"])) as archive:
            self.qga.guest_data[preboot["operationRoot"] + "\\" + preboot["checkpointName"]] = archive.read(preboot["checkpointName"])
        self.qga.boot_filetime = str(int(self.qga.boot_filetime) + 600000000)

    def reboot(self, receipt):
        """readiness-reboot: its journal from the preboot's boot, then the guest's new boot."""
        submitted = self.submit_reboot(receipt)
        self.new_boot(receipt)
        return submitted

    def fresh_history(self):
        """Another clone's job history beside the same base install: an open reboot chain stays with the old one."""
        old, self.machine_data = self.machine_data, self.work / ("history-" + str(uuid.uuid4())) / MACHINE
        self.machine_data.mkdir(parents=True, mode=0o700)
        shutil.copytree(old / self.install, self.machine_data / self.install)

    def test_each_pair_declares_its_app_and_its_postboot_needs_a_new_boot(self):
        for name in ("windows-reboot-reconnect", "windows-reboot-explicit-off", "windows-autostart-migration"):
            with self.subTest(name=name):
                scenario = driver.RECIPES[name + ".pre"]["reboot"]["scenario"]
                pre, code, receipt, kinds = self.run_reboot(name + ".pre")
                self.assertEqual((0, None, True), (code, receipt["failure"], receipt["windows"]["installedPackage"]))
                self.assertEqual(["system-run", "evidence-zip", "endpoints", "verify"], kinds[-4:], "the declaration is the last guest effect")
                worker = self.qga.requests_seen[-1]["worker"]
                root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + pre["operationId"]
                self.assertEqual(("windows-preboot-reboot", root + "\\workspace", scenario),
                                 (worker["action"], worker["workspace"], worker["postbootAcceptance"]["scenario"]))
                self.assertEqual(AUTHORITY, worker["postbootAcceptance"]["sourceRoles"]["runtimeAuthority"])
                planner.worker_request({key: worker[key] for key in job._COMMON_FIELDS | {"pythonRuntime"}}, worker["action"],
                                       **{key: worker[key] for key in ("cliPath", "workspace", "productVersion", "postbootAcceptance")})
                allowance = json.loads(self.qga.files[job.WORKSPACE_PREFIX + pre["operationId"] + "\\product-allowance.json"])
                count = 5 if scenario == "reconnect" else 4
                # The runtime is declared by the digest the installed record names, the GUI by its installed file.
                self.assertEqual({row["image"].rsplit("\\", 1)[1]: row["sha256"] for row in allowance["processes"]},
                                 {"vpn-control.exe": hashlib.sha256(b"exe:" + VERSION.encode()).hexdigest(),
                                  **({"sing-box.exe": self.runtime} if scenario == "reconnect" else {})})
                self.assertEqual({"schema": "vpn-control.windows-product-allowance", "schemaVersion": 1, "operationId": pre["operationId"],
                                  "machine": MACHINE, "bootFileTimeUtc": self.qga.boot_filetime, "ordinarySid": SID, "sessionId": 2},
                                 {key: value for key, value in allowance.items() if key != "processes"})
                self.assertEqual(count, len(allowance["processes"]))
                self.assertEqual({"scenario": scenario, "productWorkspace": root + "\\workspace", "operationRoot": root,
                                  "checkpointName": "event-000007-reboot-checkpoint.json", "bootFileTimeUtc": self.qga.boot_filetime,
                                  "declaredProcesses": count},
                                 {key: value for key, value in receipt["preboot"].items() if key not in ("checkpointSha256", "allowanceSha256")})
                self.assertEqual({"phase": "pre", "autostart": "changed", "preboot": None, "readinessReboot": None}, receipt["reboot"])
                # No readiness-reboot yet: the postboot is refused before any guest program.
                post, code, refused, kinds = self.run_reboot(name + ".post", preboot=pre["operationId"])
                self.assertEqual((2, "prior_preboot_reboot_unproven", []), (code, refused["failure"], kinds))
                # Submitted, but the guest has not booted again: refused after its read-only context.
                recovery, operation = self.submit_reboot(receipt)
                post, code, refused, kinds = self.run_reboot(name + ".post", preboot=pre["operationId"])
                self.assertEqual((2, "preboot_boot_not_newer", ["context"]), (code, refused["failure"], kinds))
                self.new_boot(receipt)
                post, code, passed, kinds = self.run_reboot(name + ".post", preboot=pre["operationId"])
                self.assertEqual((0, None, True, None), (code, passed["failure"], passed["windows"]["installedPackage"], passed["preboot"]))
                self.assertEqual({"phase": "post", "preboot": pre["operationId"],
                                  "readinessReboot": {"recoveryId": recovery, "operationId": operation, "shutdownAcknowledged": True}},
                                 {key: value for key, value in passed["reboot"].items() if key != "autostart"})
                self.assertNotIn("declare", passed["stage"])
                worker = self.qga.requests_seen[-1]["worker"]
                config = worker["postbootAcceptance"]
                self.assertEqual(("windows-postboot-final", root + "\\workspace", root + "\\event-000007-reboot-checkpoint.json"),
                                 (worker["action"], worker["workspace"], config["checkpointPath"]))
                self.assertIn(root + "\\workspace", [pin["path"] for pin in worker["directoryPins"]])
                planner.worker_request({key: worker[key] for key in job._COMMON_FIELDS | {"pythonRuntime"}}, worker["action"],
                                       **{key: worker[key] for key in ("cliPath", "workspace", "productVersion", "postbootAcceptance")})
        self.assertEqual([], self.classify()["unresolved"])

    def test_a_declaration_with_any_wrong_fact_is_never_published(self):
        cases = {
            "wrong-hash": lambda rows: rows[0].update(sha256="0" * 64),
            "wrong-sid": lambda rows: rows[1].update(sid="S-1-5-21-9-9-9-1000"),
            "wrong-session": lambda rows: rows[2].update(sessionId=3),
            "owner-child": lambda rows: rows[0].update(parentPid=900),
            "owner-grandchild": lambda rows: rows[0].update(parentPid=902),
            "broken-tree": lambda rows: rows[3].update(parentPid=40),
            "before-this-boot": lambda rows: rows[4].update(creationFileTime=FILETIME),
            "no-runtime": lambda rows: rows.pop(),
            "other-image": lambda rows: rows[1].update(image=INSTALLED_ROOT + "\\vpn-control-cli.exe"),
            "other-runtime-image": lambda rows: rows[4].update(image=INSTALLED_ROOT + "\\sing-box.exe"),
            "runtime-with-the-gui-hash": lambda rows: rows[4].update(sha256=rows[0]["sha256"]),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.fresh_history()  # Each refused declaration leaves its app behind and holds its clone.
                self.change_rows = change
                plan, code, receipt, kinds = self.run_reboot("windows-reboot-reconnect.pre")
                self.assertEqual((1, "product_declaration_refused", "declare", None), (code, receipt["failure"], receipt["stage"], receipt["preboot"]))
                self.assertEqual(["system-run", "evidence-zip"], kinds[-2:])
                self.assertNotIn(job.WORKSPACE_PREFIX + plan["operationId"] + "\\product-allowance.json", self.qga.files)
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])
        self.change_rows = None
        for name, change in {"two-checkpoints": lambda events: events.append(events[-1]),
                             "no-owner-start": lambda events: events.pop(0)}.items():
            with self.subTest(case=name):
                self.fresh_history()
                self.change_events = change
                plan, code, receipt, kinds = self.run_reboot("windows-reboot-explicit-off.pre")
                self.assertEqual((1, "product_declaration_refused"), (code, receipt["failure"]))

    def test_a_postboot_without_its_own_passed_preboot_claims_nothing(self):
        def refused(prior, name="windows-reboot-reconnect.post"):
            plan, code, receipt, kinds = self.run_reboot(name, preboot=prior)
            self.assertEqual((2, "prior_preboot_unavailable", []), (code, receipt["failure"], kinds))
            self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])
            self.assertFalse(self.fence(plan, ".intent.json").exists())
        refused(str(uuid.uuid4()))
        refused(self.install)
        # A preboot that failed before it changed autostart is no preboot, and holds nothing.
        self.qga.task_exit, self.change_events = 1, without_autostart
        failed, code, _, _ = self.run_reboot("windows-reboot-reconnect.pre")
        self.assertEqual(1, code)
        self.qga.task_exit, self.change_events = None, None
        refused(failed["operationId"])
        other, code, receipt, _ = self.run_reboot("windows-reboot-explicit-off.pre")
        self.assertEqual(0, code)
        refused(other["operationId"])
        plan = self.family_plan("windows-reboot-reconnect.post", prior=self.install)
        self.assertEqual(2, job.run_job(self.rt, plan, self.files))
        self.assertEqual("prior_preboot_unavailable", self.receipt(plan)["failure"])

    def test_a_changed_checkpoint_after_the_reboot_is_a_known_failure(self):
        pre, code, receipt, _ = self.run_reboot("windows-reboot-explicit-off.pre")
        self.reboot(receipt)
        key = receipt["preboot"]["operationRoot"] + "\\" + receipt["preboot"]["checkpointName"]
        self.qga.guest_data[key] += b" "
        plan, code, failed, kinds = self.run_reboot("windows-reboot-explicit-off.post", preboot=pre["operationId"])
        self.assertEqual((1, "preboot_checkpoint_changed"), (code, failed["failure"]))
        self.assertNotIn("system-run", kinds)

    def test_the_query_row_runs_the_preboot_action_and_declares_nothing(self):
        plan, code, receipt, kinds = self.run_reboot("windows-query-owner-gui-reconnect")
        self.assertEqual((0, None, None), (code, receipt["failure"], receipt["preboot"]))
        self.assertEqual({"phase": "none", "autostart": "untouched", "preboot": None, "readinessReboot": None}, receipt["reboot"])
        self.assertEqual(["system-run", "evidence-zip"], kinds[-2:])
        worker = self.qga.requests_seen[-1]["worker"]
        self.assertEqual(("windows-preboot-reboot", "query-first"), (worker["action"], worker["postbootAcceptance"]["scenario"]))
        self.assertNotIn(job.WORKSPACE_PREFIX + plan["operationId"] + "\\product-allowance.json", self.qga.files)

    def test_the_runtime_digest_comes_only_from_the_installed_record(self):
        # Before, every reboot row looked for a loose installed sing-box.exe, which the package never has, and failed here.
        layout = self.qga.installed_tree
        cases = {"absent": None, "no-authority": authority_record(self.runtime, runtimeAuthority=None),
                 "short-digest": authority_record("ab" * 16), "duplicate-key": b'{"schemaVersion":1,"schemaVersion":1}\n'}
        for name, raw in cases.items():
            with self.subTest(case=name):
                # A fresh base install whose installed tree already holds this record.
                self.qga.registration, self.qga.trees[INSTALLED_ROOT], self.qga.evidence_factory = [], ([], []), None
                if raw is None:
                    self.qga.installed_tree = ([path for path in layout[0] if not path.endswith("native-helpers.json")], layout[1])
                else:
                    self.qga.installed_tree, self.qga.guest_data[AUTHORITY] = layout, raw
                self.install, _ = self.install_base()
                self.qga.evidence_factory = self.evidence
                plan, code, receipt, kinds = self.run_reboot("windows-reboot-reconnect.pre")
                self.assertEqual((1, "installed_runtime_authority", "publish"), (code, receipt["failure"], receipt["stage"]))
                self.assertNotIn("system-run", kinds)
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])

    def test_only_the_readiness_reboot_from_the_preboot_boot_admits_its_postboot(self):
        pre, code, receipt, _ = self.run_reboot("windows-reboot-reconnect.pre")
        self.assertEqual(0, code)
        self.new_boot(receipt)  # A later boot readiness-reboot never submitted: a crash or a restart.

        def refused():
            plan, code, refused, kinds = self.run_reboot("windows-reboot-reconnect.post", preboot=pre["operationId"])
            self.assertEqual((2, "prior_preboot_reboot_unproven", []), (code, refused["failure"], kinds))
            for path in self.vm.glob("readiness-recovery-*"):
                path.unlink()
        refused()
        cases = {"a-resume": {"action": "resume"}, "another-boot": {"boot": str(int(receipt["preboot"]["bootFileTimeUtc"]) + 10)},
                 "one-declared-process-missing": {"products": receipt["preboot"]["declaredProcesses"] - 1},
                 "a-product-row-the-census-did-not-know": {"known": False}}
        for name, change in cases.items():
            with self.subTest(case=name):
                self.submit_reboot(receipt, **change)
                refused()
        self.submit_reboot(receipt)
        self.submit_reboot(receipt)
        refused()  # Two from one boot: which one rebooted is not known.
        recovery, operation = self.submit_reboot(receipt)
        plan, code, passed, _ = self.run_reboot("windows-reboot-reconnect.post", preboot=pre["operationId"])
        self.assertEqual((0, {"recoveryId": recovery, "operationId": operation, "shutdownAcknowledged": True}),
                         (code, passed["reboot"]["readinessReboot"]))
        self.assertEqual([], self.classify()["unresolved"])

    def test_a_postboot_refuses_a_preboot_that_ran_on_another_install(self):
        pre, code, receipt, _ = self.run_reboot("windows-reboot-explicit-off.pre")
        self.assertEqual(0, code)
        # The same package and version installed again over another layout: another installed tree.
        files, directories = self.qga.installed_tree
        self.qga.installed_tree = (sorted([*files, "app/extra.jar"]), directories)
        reset, code, _, _ = self.run_family("windows-msi-base-reset")
        self.assertEqual(0, code)
        self.reboot(receipt)
        self.install = reset["operationId"]
        plan, code, refused, kinds = self.run_reboot("windows-reboot-explicit-off.post", preboot=pre["operationId"])
        self.assertEqual((2, "prior_preboot_other_install", []), (code, refused["failure"], kinds))

    def test_a_preboot_that_changed_autostart_holds_reboot_rows_until_its_postboot_passes(self):
        def refused(scenario, reason="reboot_chain_open", **options):
            plan, code, refused, kinds = self.run_reboot(scenario, **options)
            self.assertEqual((2, reason, []), (code, refused["failure"], kinds))
        pre, code, receipt, _ = self.run_reboot("windows-reboot-explicit-off.pre")
        self.assertEqual(0, code)
        # Its app runs from the task it registered: another preboot would meet that task while its own serve runs.
        refused("windows-reboot-reconnect.pre")
        refused("windows-query-owner-gui-reconnect")
        self.reboot(receipt)
        post, code, _, _ = self.run_reboot("windows-reboot-explicit-off.post", preboot=pre["operationId"])
        self.assertEqual(0, code)
        refused("windows-reboot-explicit-off.post", "prior_preboot_unavailable", preboot=pre["operationId"])
        # A preboot whose owner never reached autostart leaves nothing behind.
        self.qga.task_exit, self.change_events = 1, without_autostart
        early, code, receipt, _ = self.run_reboot("windows-reboot-reconnect.pre")
        self.assertEqual((1, "untouched"), (code, receipt["reboot"]["autostart"]))
        # One that did is never closed on this clone: a new attempt is a new operation on another clone.
        self.change_events = None
        failed, code, receipt, _ = self.run_reboot("windows-reboot-reconnect.pre")
        self.assertEqual((1, "changed"), (code, receipt["reboot"]["autostart"]))
        self.qga.task_exit = None
        refused("windows-reboot-explicit-off.pre")
        refused("windows-reboot-reconnect.post", "prior_preboot_unavailable", preboot=failed["operationId"])
        plan, code, _, _ = self.run_family("windows-packaged-cli-smoke", prior=self.install)
        self.assertEqual(0, code, "a row that is no reboot row is not held")

    def test_the_traffic_input_is_the_pinned_fixed_body(self):
        value = json.loads(job.traffic_input())
        self.assertEqual(job.UPSTREAM_TOKEN.encode("ascii").hex(), value["expectedBodyHex"])
        from agent_tools import windows_postboot_source_roles as source_roles
        self.assertEqual(source_roles.UPSTREAM_TOKEN, job.UPSTREAM_TOKEN)
        self.assertEqual(job.DECLARED_ROLES, ("guiLauncher", "gui", "controllerLauncher", "controller", "runtime"))


_PROXY_TLS = []


def proxy_tls():
    """One generated key for this module: making it is the slow part, and its own tests live in test_windows_proxy_lifecycle."""
    if not _PROXY_TLS:
        from agent_tools import windows_scenario_proxy as proxy
        _PROXY_TLS.append(proxy.material(random.Random(5).getrandbits, 1793000000))
    return _PROXY_TLS[0]


def proxy_inputs(raw):
    """The literal harness's two constants, read as the dedicated driver reads them: no statement runs."""
    tree = ast.parse(raw.decode("ascii"))
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)}
    if set(values) != {"LIFECYCLE_INPUTS", "SYSTEM_COLLECTOR_CLOSE_HOLD"} or len(tree.body) != 3:
        raise AssertionError("harness is not literal")
    return values


class ProxyFamilyBase(FamilyBase):
    """windows-proxy-lifecycle.<variant> on the same fake VM: an installed base whose app folder holds the runtime's jar."""

    def setUp(self):
        super().setUp()
        files, directories = self.qga.installed_tree
        self.qga.installed_tree = (sorted(files + ["app/desktopApp.jar", "app/skiko-awt.jar"]), directories)
        self.material_calls = []
        loaded = job.Job._load

        def load(instance, name):
            module = loaded(instance, name)
            if name == "windows_scenario_proxy":
                module.material = lambda randbits, now: self.material_calls.append((randbits, now)) or proxy_tls()
            return module
        patcher = mock.patch.object(job.Job, "_load", load)
        patcher.start()
        self.addCleanup(patcher.stop)


class ProxyFamilyTests(ProxyFamilyBase):
    def test_every_proxy_row_runs_on_one_installed_base_and_refuses_each_mutated_request(self):
        install, base = self.install_base()
        tree, tls = base["installed"]["treeSha256"], proxy_tls()
        runtime_sha = hashlib.sha256(self.qga.runtime_bytes).hexdigest()
        captures, original = {}, job.assert_closed

        def record(row, requests, expected):
            captures[row["proxy"]["variant"]] = json.loads(json.dumps([row, requests, expected]))
            return original(row, requests, expected)
        for variant in driver.PROXY_VARIANTS:
            scenario = "windows-proxy-lifecycle." + variant
            with self.subTest(variant=variant):
                with mock.patch.object(job, "assert_closed", record):
                    plan, code, receipt, kinds = self.run_family(scenario, prior=install)
                self.assertEqual((0, None), (code, receipt["failure"]))
                self.assertEqual({"installedPackage": True, "packageSha256": self.packages["targetPackage"]["sha256"]}, receipt["windows"])
                self.assertEqual(tree, receipt["installed"]["treeSha256"], "a proxy row leaves the one base as it found it")
                self.assertLess(kinds.index("runtime-extract"), kinds.index("system-run"))
                self.assertIs(job.secrets.randbits, self.material_calls[-1][0], "the key comes from the host's own CSPRNG")
                seen = self.qga.requests_seen[-1]
                worker, workspace = seen["worker"], job.WORKSPACE_PREFIX + plan["operationId"]
                root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"]
                # The driver's --version probe runs this launcher and expects this admitted version.
                self.assertEqual(("windows-proxy-lifecycle", workspace + "\\windows_lifecycle_cases.py", workspace + "\\proxy-harness.py",
                                  root + "\\workspace", INSTALLED_ROOT + "\\vpn-control-cli.exe", VERSION),
                                 (worker["action"], worker["casesPath"], worker["harnessPath"], worker["workspace"], worker["cliPath"],
                                  worker["productVersion"]))
                pins = {pin["path"]: pin for pin in worker["filePins"]}
                self.assertEqual(runtime_sha, pins[workspace + "\\sing-box.exe"]["sha256"])
                for role, leaf in driver.RECIPES[scenario]["generated"]:
                    self.assertEqual(hashlib.sha256(self.qga.files[workspace + "\\" + leaf]).hexdigest(), pins[workspace + "\\" + leaf]["sha256"])
                for role in ("certificate", "privateKey", "trustStore"):
                    self.assertEqual(tls[role], self.qga.files[workspace + "\\" + dict(driver.RECIPES[scenario]["generated"])[role]])
                inputs = proxy_inputs(self.qga.files[workspace + "\\proxy-harness.py"])["LIFECYCLE_INPUTS"]
                self.assertEqual((variant, "a" * 40, runtime_sha, plan["operationId"], root + "\\workspace\\runtime\\tools\\sing-box.exe"),
                                 (inputs["variant"], inputs["sourceSha"], inputs["runtime"]["runtimeSha256"], inputs["runtime"]["operationId"],
                                  inputs["runtime"]["runtimeImagePath"]))
                self.assertEqual("sha256-" + self.packages["targetPackage"]["sha256"], inputs["runtime"]["installedAdmissionArtifactId"])
                self.assertEqual(variant in driver._PROXY_BRANCH_VARIANTS, "branch" in inputs)
                if "branch" in inputs:
                    self.assertEqual((workspace + "\\sing-box.exe", runtime_sha), (inputs["branch"]["fixtureRuntimeToolPath"], inputs["branch"]["runtimeSha256"]))
                if variant == "gui-pending":
                    self.assertEqual(INSTALLED_ROOT + "\\vpn-control.exe", inputs["gui"]["guiPath"])
                    self.assertIn(inputs["gui"]["guiPath"], pins, "the GUI is the installed tree's own pinned launcher")
                for path in (*inputs["modules"].values(), inputs["runtime"]["fixtureWorkerPath"], inputs["runtime"]["socksSourcePath"],
                             inputs["runtime"]["httpsSourcePath"], inputs["runtime"]["certificatePath"], inputs["runtime"]["trustStorePath"]):
                    self.assertIn(path, pins, "every file the harness names is held by the worker")
                planner.validate_closure(worker)
                self.assertEqual([], self.pins_under(seen["bootstrap"], INSTALLED_ROOT), "installed pins live only in the worker request")
                self.assertNotIn(workspace + "\\proxy-localhost.key", {pin["path"] for pin in seen["bootstrap"]["filePins"]})
        self.assertEqual([], self.classify()["unresolved"])
        self.assertEqual(set(driver.PROXY_VARIANTS), set(captures))
        for variant, captured in captures.items():
            job.assert_closed(*captured)
            for name, change in self.mutations().items():
                with self.subTest(variant=variant, change=name):
                    row, requests, expected = json.loads(json.dumps(captured))
                    change(row, requests, expected)
                    with self.assertRaisesRegex(job.KnownFailure, "requests_not_closed"):
                        job.assert_closed(row, requests, expected)

    def test_a_runtime_that_is_not_the_installed_trees_own_is_a_known_failure(self):
        install, _ = self.install_base()
        cases = (("another-jar-pin", lambda runtime: runtime["jarPin"].update(sha256="0" * 64)),
                 ("jar-outside-the-tree", lambda runtime: runtime["jarPin"].update(path=INSTALLED_ROOT + "\\app\\other.jar")),
                 ("another-target", lambda runtime: runtime["filePin"].update(path=PROFILE + "\\sing-box.exe")),
                 ("another-entry", lambda runtime: runtime.update(entry="bin/windows-amd64/other.exe")))
        for name, change in cases:
            with self.subTest(name=name):
                self.qga.runtime_reply = change
                plan, code, receipt, kinds = self.run_family("windows-proxy-lifecycle.generated", prior=install)
                self.assertEqual((1, "publisher_runtime_receipt"), (code, receipt["failure"]))
                self.assertNotIn("system-run", kinds)
                self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"])
        self.qga.runtime_reply = None
        for jars, reason in (({"app/desktopApp.jar", "app/skiko-awt.jar"}, "publisher_refused:publish-runtime"), (set(), "publisher_refused:publish-runtime")):
            with self.subTest(jars=sorted(jars)):
                self.qga.runtime_jars = jars
                plan, code, receipt, kinds = self.run_family("windows-proxy-lifecycle.find-best-success", prior=install)
                self.assertEqual((1, reason), (code, receipt["failure"]))
                self.assertNotIn("system-run", kinds)

    def test_an_installed_tree_without_a_jar_never_reaches_the_guest_for_its_runtime(self):
        self.qga.installed_tree = (["vpn-control-cli.exe", "vpn-control.exe"], [])
        install, _ = self.install_base()
        plan, code, receipt, kinds = self.run_family("windows-proxy-lifecycle.find-best-cancel", prior=install)
        self.assertEqual((1, "installed_runtime_jar_absent"), (code, receipt["failure"]))
        self.assertNotIn("runtime-extract", kinds)

    def test_a_proxy_row_needs_a_passed_install_of_its_own_package(self):
        foreign = self.run_family("windows-ordinary-qualification")[0]["operationId"]
        for variant in driver.PROXY_VARIANTS:
            scenario = "windows-proxy-lifecycle." + variant
            with self.subTest(variant=variant):
                for prior in (str(uuid.uuid4()), foreign):
                    plan, code, receipt, kinds = self.run_family(scenario, prior=prior)
                    self.assertEqual((2, "prior_install_unavailable", []), (code, receipt["failure"], kinds))
                    self.assertFalse(self.fence(plan, ".intent.json").exists(), "a refused job anchors nothing")
        install, _ = self.install_base()
        other = random.Random(9).randbytes(100)
        self.packages["targetPackage"] = {"sha256": hashlib.sha256(other).hexdigest(), "bytes": len(other)}
        plan, code, receipt, kinds = self.run_family("windows-proxy-lifecycle.large", prior=install)
        self.assertEqual((2, "prior_install_other_package", []), (code, receipt["failure"], kinds))
        self.assertFalse(self.fence(plan, ".intent.json").exists())

    @staticmethod
    def mutations():
        """Each change a caller might try on a built proxy request; every one must be refused."""
        def worker(change):
            return lambda row, requests, expected: change(requests["worker"])

        def pin_named(leaf):
            def change(w):
                next(item for item in w["filePins"] if item["path"].endswith("\\" + leaf)).update(sha256="2" * 64)
            return change
        return {
            "cases-is-harness": worker(lambda w: w.update(casesPath=w["harnessPath"])),
            "harness-is-cases": worker(lambda w: w.update(harnessPath=w["casesPath"])),
            "action": worker(lambda w: w.update(action="windows-public-update")),
            "generic-action": worker(lambda w: w.update(action="disconnected-cli-config")),
            "free-argv": worker(lambda w: w.update(qualificationArgv=["cmd.exe"])),
            "runtime-dropped": worker(lambda w: w["filePins"].remove(next(item for item in w["filePins"] if item["path"].endswith("\\sing-box.exe")))),
            "runtime-changed": worker(pin_named("sing-box.exe")),
            "harness-changed": worker(pin_named("proxy-harness.py")),
            "key-changed": worker(pin_named("proxy-localhost.key")),
            "driver-changed": worker(pin_named("windows_ordinary_dedicated_driver.py")),
            "extra-pin": worker(lambda w: w["filePins"].append(dict(w["filePins"][0], path="C:\\Windows\\System32\\cmd.exe"))),
            "workspace": worker(lambda w: w.update(workspace=w["workspace"] + "-other")),
            "bootstrap-mode": lambda row, requests, expected: requests["bootstrap"]["bootstrap"].update(mode="qualification"),
            "no-worker": lambda row, requests, expected: requests.update(worker=None),
        }


JOB_ID = "88888888-9999-4aaa-8bbb-cccccccccccc"
PRODUCT_OPERATION = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
BASE = "2.2.14"
ADMIN_SID = "S-1-5-21-1-2-3-500"


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


class UpdateQga(FakeQga):
    """The same wire peer, plus what an update row's owner and SYSTEM collector would leave: the owner asks for
    before-install, then terminal-actors once the first stage was served, and its task ends after the release."""

    def __init__(self):
        super().__init__()
        self.collectors, self.releases, self.served = [], [], []
        self.run_pid = None
        self.run_polls = None  # Polls before the SYSTEM run returns; by default it waits on its collectors.
        self.needs = ["before-install", "terminal-actors"]
        self.parked_files = []  # What the run's status names as parked.
        self.verified = {}
        self.disposition = b'{"disposition":"NOT_STARTED"}'
        # The product writes its not-started disposition for its owner alone, and a SYSTEM open without an enabled
        # SeBackupPrivilege is refused: nothing on this route enables it. True only where a test supposes a reader.
        self.system_reads_owner_only = False

    def _guest_exec(self, arguments):
        source = base64.b64decode(arguments["input-data"]).decode("ascii")
        if "$RequestPinBase64=" in source or "$releaseBytes=" in source:
            if arguments["path"] != job.POWERSHELL_PATH or arguments["arg"] != list(job.GUEST_ARGUMENTS):
                raise AssertionError("guest-exec shape changed")
            self.next_pid += 1
            pid = self.next_pid
            kind = "collector-release" if "$releaseBytes=" in source else "collector"
            terminal = self._release(source, pid) if kind == "collector-release" else self._collector(source, pid)
            self.programs.append((kind, source))
            self.pending[pid] = {"polls": 0, "terminal": terminal}
            return {"pid": pid}
        self.admin_requested = "administratorSid=" in source
        ack = super()._guest_exec(arguments)
        if self.programs[-1][0] == "system-run" and (program_input(source) or {}).get("nativeNeeds"):
            self.run_pid = ack["pid"]
            if self.run_polls is not None:
                self.pending[ack["pid"]]["polls"] = self.run_polls
            elif self.needs:
                self.pending[ack["pid"]]["polls"] = 10 ** 6  # The owner waits on its collectors.
        return ack

    def _guest_file_open(self, arguments):
        if arguments["path"].endswith("\\scenario-status.json") and arguments["mode"] == "rb":
            served = [kind for kind, _ in self.programs if kind == "collector"]
            needs = self.needs[:len(served) + 1]
            values = {"before-install": {"jobId": None, "productOperationId": None},
                      "terminal-actors": {"jobId": JOB_ID, "productOperationId": PRODUCT_OPERATION}}
            self.files[arguments["path"]] = json.dumps({"schemaVersion": 1, "poll": len(self.calls), "pendingKinds": [],
                                                        "parkedFiles": list(self.parked_files),
                                                        "uacEvents": ["update-uac-action-pending"] if served else [],
                                                        "nativeNeeds": [{"name": "event", "ordinal": i, "stage": stage,
                                                                         **values.get(stage, {"jobId": None, "productOperationId": None})}
                                                                        for i, stage in enumerate(needs)]}).encode()
        return super()._guest_file_open(arguments)

    def _context(self):
        terminal = super()._context()
        if not self.admin_requested:
            return terminal
        value = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(terminal["out-data"]))))
        value["administratorSid"] = ADMIN_SID
        return {"exited": True, "exitcode": 0, "out-data": out_data(value)}

    def _publisher(self, m, pid):
        action = m["action"]
        if action not in {"initialize", "verify", "fixture-tls", "seal-readonly", "collector-observe"}:
            return super()._publisher(m, pid)
        reply = {"schemaVersion": 1, "operationId": m["operationId"], "kernelBootIdentifier": m["kernelBootIdentifier"], "systemToken": m["systemToken"],
                 "allHeldAndNamedPinsClosing": True, "productOperation": False, "taskOperation": False, "bootstrapOpening": self._actor(pid),
                 "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        if action == "initialize":
            def directory(path, rights, form="P"):
                return self._pin(path, directory=True, security={"ownerSid": "S-1-5-18", "sddl": "O:SYD:" + form + "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;" + rights + ";;;" + SID + ")"})
            pins = [self._pin(path, directory=True) for path in m["existingDirectories"]]
            pins.append(directory(m["workspace"], "0x1200a9"))
            # A protected DACL set at CreateDirectory reads back auto-inherited: the form the collector contract names.
            pins.extend(directory(m["workspace"] + "\\" + name, "0x1200a9", "PAI" if name.startswith("system-collector-") else "P") for name in m["subfolders"])
            pins.extend(directory(m["workspace"] + "\\" + name, "FA") for name in m.get("privateSubfolders", []))
            pins.append(directory(m["operationRoot"], "0x1301bf"))
            reply.update(state="ordinary-publication-initialized", workspace=m["workspace"], operationRoot=m["operationRoot"], createNew=True, directoryPins=pins)
        elif action == "verify":
            terminal = super()._publisher(m, pid)
            for row in json.loads(gzip.decompress(base64.b64decode(base64.b64decode(terminal["out-data"]))))["verified"]:
                self.verified[row["filePin"]["path"]] = row["filePin"]
            return terminal
        elif action == "fixture-tls":
            der = b"0\x82\x01\x00certificate-der"
            text = base64.b64encode(der).decode()
            pem = ("-----BEGIN CERTIFICATE-----\n" + "\n".join(text[at:at + 64] for at in range(0, len(text), 64)) + "\n-----END CERTIFICATE-----\n").encode()
            folder = m["workspace"] + "\\update-tls"
            # New-GeneratedFile protects its files as New-Endpoint does, so they read back in the same form.
            reply.update(state="ordinary-fixture-tls", tls={"certificateDer": text,
                                                            "certificatePin": self._pin(folder + "\\server-cert.pem", raw=pem, security=self.file_security()),
                                                            "privateKeyPin": self._pin(folder + "\\server-key.pem", raw=b"generated key",
                                                                                       security=self.file_security())})
        elif action == "seal-readonly":
            pin = json.loads(json.dumps(self.verified[m["sealPath"]]))
            pin["nativeIdentity"]["attributes"] = 33
            reply.update(state="ordinary-sealed-readonly", filePin=pin)
        else:
            def event(ordinal, kind, value, task=False):
                body = {"schemaVersion": 1, "operationId": m["operationId"], "ordinal": ordinal, "kind": kind, "value": value}
                if task:
                    body.update(ownerPid=901, ownerBirthFileTimeUtc="134368653065000002")
                return base64.b64encode(json.dumps(body).encode()).decode()
            files = {"task-event-000000-submission-intent.json": event(0, "submission-intent", {"mode": "python-worker"}, True),
                     "task-event-000001-submitted.json": event(1, "submitted", {"pid": 902, "birthFileTimeUtc": "134368653065000003",
                                                                                "originalHandleRetained": True}, True),
                     "event-000002-child-intent.json": event(2, "child-intent", {"child": 0, "label": "update-public-serve", "argv": ["cli", "serve"]}),
                     "event-000003-child-started.json": event(3, "child-started", {"child": 0, "pid": 903, "birthFileTimeUtc": "134368653065000004"}),
                     "event-000004-child-intent.json": event(4, "child-intent", {"child": 1, "label": "public-cli", "argv": ["cli", "status"]})}
            dispositions = []
            if "one-public-update-install" in m["childStdoutLabels"]:
                files["event-000009-child-intent.json"] = event(9, "child-intent", {"child": 5, "label": "one-public-update-install", "argv": ["cli"]})
                files["event-000010-child-started.json"] = event(10, "child-started", {"child": 5, "pid": 904, "birthFileTimeUtc": "134368653065000005"})
                files["child-0005.stdout.raw"] = base64.b64encode(json.dumps({"schemaVersion": 1, "ok": False, "code": "CANCELLED", "final": True,
                                                                              "controllerId": "controller-1", "requestId": "request-1",
                                                                              "operationId": PRODUCT_OPERATION}).encode()).decode()
            if m["readDisposition"]:
                # DesktopWindowsExportFile creates it O:<owner>G:<owner>D:P(A;;FA;;;<owner>): no ACE for SYSTEM.
                if not self.system_reads_owner_only:
                    return {"exited": True, "exitcode": 1, "err-data": base64.b64encode(b"Access to the path is denied.").decode()}
                dispositions.append(self._pin(m["productWorkspace"] + "\\.install-not-started-" + "a" * 64 + ".json", raw=self.disposition,
                                              security={"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}))
            reply.update(state="ordinary-collector-observation", observation={"files": files, "dispositions": dispositions})
        return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}

    def _request(self, source, pattern):
        pin = json.loads(base64.b64decode(re.search(pattern, source)[1]))
        return pin, json.loads(self.files[pin["path"]])

    def _collector(self, source, pid):
        pin, request = self._request(source, r"\$RequestPinBase64='([A-Za-z0-9+/=]+)'")
        self.collectors.append(request)
        worker = {"pid": 6000 + len(self.collectors), "birthFileTimeUtc": "134368653065000010", "image": request["pythonRuntime"]["interpreterPath"]}
        hold, caller = request["closeHold"], None
        if hold is not None:
            ordinary = request["ordinaryTask"]["workerActor"]
            ready = {"schemaVersion": 1, "kind": "caller-collector-close-ready", "ordinaryTaskOperationId": request["ordinaryTaskOperationId"],
                     "collectorOperationId": request["operationId"], "sourceSha": hold["sourceSha"], "scope": "update", "stage": hold["stage"],
                     "bootIdentifier": request["context"]["bootIdentifier"],
                     "ordinaryWorker": {"pid": ordinary["pid"], "birthFileTimeUtc": str(ordinary["creationFileTime"]),
                                        **{key: ordinary[key] for key in ("image", "sha256", "sid", "sessionId")}},
                     "callerSourcePin": hold["callerSourcePin"], "collectorRequestSha256": pin["sha256"],
                     "systemActor": {"pid": pid, "birthFileTimeUtc": "134368653065000001"},
                     "collectorChild": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"]},
                     "driverKnownResult": 0, "allOriginalChildrenTerminalAndEof": True}
            raw = encoded(ready)
            caller = {"ready": ready, "sha256": hashlib.sha256(raw).hexdigest(), "originalHandleRetained": True,
                      "nativeFile": {"path": hold["holdReadyPath"], "nativeIdentity": self._pin(hold["holdReadyPath"], raw=raw)["nativeIdentity"],
                                     "security": {"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}}}
        result = {"schemaVersion": 1, "state": "collector-completed", "operationId": request["operationId"],
                  "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "scope": "update",
                  "collectorSourceSha256": request["modules"]["collector"]["sha256"],
                  "workerActor": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"], "image": worker["image"],
                                  "bootIdentifier": request["context"]["bootIdentifier"], "token": {"sid": "S-1-5-18", "sessionId": 0, "elevation": 1}},
                  "publications": [{"stage": request["collectorRequest"]["stage"], "noProductMutation": True}],
                  "closing": {"sourceClosing": True, "files": len(request["filePins"]) + 1, "completeFileDigestSha256": "a" * 64}, "callerHold": caller}
        stdout = json.dumps(result).encode()

        def capture(name, raw):
            return {"name": name, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "base64": base64.b64encode(raw).decode(),
                    "eof": True, "nativeIdentity": {"sizeBytes": len(raw)}}
        proof = {"schemaVersion": 1, "state": "collector-closed", "operationId": request["operationId"],
                 "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "scope": "update",
                 "collectorSourceSha256": request["modules"]["collector"]["sha256"], "requestSha256": pin["sha256"],
                 "requestNativeIdentity": pin["nativeIdentity"],
                 "worker": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"], "image": worker["image"], "sessionId": 0,
                            "exitCode": 0, "bothEof": True, "originalHandleRetained": True},
                 "captures": [capture("stdout", stdout), capture("stderr", b"")], "sourceClosing": True, "productMutation": False,
                 "bootstrapOpening": self._actor(pid), "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        if hold is None and self.run_pid in self.pending and len(self.collectors) == len(self.needs):
            self.pending[self.run_pid]["polls"] = 0
        return {"exited": True, "exitcode": 0, "out-data": out_data(proof)}

    def _release(self, source, pid):
        pin, request = self._request(source, r"\$requestRecord=.*?FromBase64String\('([A-Za-z0-9+/=]+)'\)")
        release = base64.b64decode(re.search(r"\$releaseBytes=\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]+)'\)", source)[1])
        self.releases.append(json.loads(release))
        if self.run_pid in self.pending:
            self.pending[self.run_pid]["polls"] = 0  # The caller's hold is released: its owner finishes.
        proof = {"schemaVersion": 1, "state": "collector-release-published", "operationId": request["operationId"], "requestSha256": pin["sha256"],
                 "releasePath": request["closeHold"]["releasePath"], "releaseSha256": hashlib.sha256(release).hexdigest(),
                 "releaseNativeIdentity": self._pin(request["closeHold"]["releasePath"], raw=release)["nativeIdentity"], "sourceClosing": True,
                 "originalCollectorKnownClosed": True, "productMutation": False, "bootstrapOpening": self._actor(pid), "bootstrapClosing": self._actor(pid),
                 "guestBootClosing": True, "bootstrapActorClosing": True}
        return {"exited": True, "exitcode": 0, "out-data": out_data(proof)}


class UpdateFamilyBase(FamilyBase):
    """One VM: install the target once, which records the tree it leaves, then reset to the older base and update."""

    def setUp(self):
        super().setUp()
        self.qga = UpdateQga()
        self.rt = FakeRuntime(self.vm, self.qga)
        self.base_msi = random.Random(5).randbytes(job.CHUNK_BYTES + 9)
        receipt = {"schemaVersion": 1, "testOnly": True, "productionTrustChanged": False, "sourceFingerprint": "f" * 64,
                   "manifest": {"assets": [{"fileName": "vpn-control-" + VERSION + ".msi", "sha256": self.packages["targetPackage"]["sha256"],
                                            "sizeBytes": self.packages["targetPackage"]["bytes"], "displayVersion": VERSION}]}}
        for role, raw in (("basePackage", self.base_msi), ("fixtureReceipt", json.dumps(receipt).encode())):
            digest = hashlib.sha256(raw).hexdigest()
            (self.artifacts / digest).write_bytes(raw)
            (self.artifacts / digest).chmod(0o600)
            self.packages[role] = {"sha256": digest, "bytes": len(raw)}

    def install(self, scenario, role, version, *, prior=None):
        self.qga.msi_properties["ProductVersion"] = version
        row = json.loads(json.dumps(driver.RECIPES[scenario]))
        plan = self.plan(None, scenarioId=scenario, row=row, artifactDirectory=str(self.artifacts),
                         packages={"basePackage": self.packages[role]}, product={"sourceSha": "a" * 40, "productVersion": version},
                         prior={} if prior is None else {"install": prior})
        self.addCleanup(self.forget_modules, plan["operationId"])
        code = job.run_job(self.rt, plan, self.files)
        self.assertEqual((0, None), (code, self.receipt(plan)["failure"]))
        return plan["operationId"]

    def prepared(self):
        """The target's own install records its tree; the reset leaves the older base the update starts from."""
        target = self.install("windows-msi-base-install", "targetPackage", VERSION)
        base = self.install("windows-msi-base-reset", "basePackage", BASE)
        self.qga.programs.clear()
        self.qga.requests_seen.clear()
        return base, target

    def update_plan(self, variant, base, target, **changes):
        row = json.loads(json.dumps(driver.RECIPES["windows-public-update." + variant]))
        fields = {"scenarioId": "windows-public-update." + variant, "row": row, "artifactDirectory": str(self.artifacts),
                  "packages": {key: self.packages[key] for key in ("targetPackage", "fixtureReceipt")},
                  "product": {"sourceSha": "a" * 40, "productVersion": VERSION, "baseVersion": BASE},
                  "prior": {"install": base, "targetInstall": target}, "administrator": "recoveryadmin"}
        return self.plan(None, **{**fields, **changes})

    def run_update(self, variant, base, target, **changes):
        plan = self.update_plan(variant, base, target, **changes)
        self.addCleanup(self.forget_modules, plan["operationId"])
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan)

    def suppose_collector_inputs(self):
        """A guest that does not exist yet: a request file in the pinned O:SYD:P form and a SYSTEM reader of the product's
        owner-only disposition. The driver refuses uac-denied until both are proved natively; these tests run the
        collector stage engine as if they were."""
        self.qga.endpoint_form = "P"
        self.qga.system_reads_owner_only = True


class UpdateFamilyTests(UpdateFamilyBase):
    def harness(self, plan):
        raw = self.qga.files[job.WORKSPACE_PREFIX + plan["operationId"] + "\\update-harness.py"]
        tree = ast.parse(raw.decode("utf-8"))
        self.assertIsInstance(tree.body[0].value, ast.Constant)
        self.assertEqual(["UPDATE_INPUTS", "SYSTEM_COLLECTOR_CLOSE_HOLD"], [node.targets[0].id for node in tree.body[1:]])
        return [ast.literal_eval(node.value) for node in tree.body[1:]]

    def test_a_no_system_row_runs_the_case_with_its_fixture_and_no_collector(self):
        base, target = self.prepared()
        self.qga.needs = []
        plan, code, receipt = self.run_update("public-ready", base, target)
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual({"installedPackage": False, "packageSha256": None}, receipt["windows"], "no --version ran: no installed-package claim")
        self.assertEqual({"variant": "public-ready", "collectors": {}}, receipt["update"])
        kinds = self.qga.kinds()
        self.assertNotIn("collector", kinds)
        self.assertLess(kinds.index("seal-readonly"), kinds.index("system-run"))
        self.assertLess(kinds.index("fixture-tls"), kinds.index("system-run"))
        worker = self.qga.requests_seen[-1]["worker"]
        self.assertEqual("windows-public-update", worker["action"])
        self.assertEqual(["installed-application", "python-runtime"], sorted(tree["role"] for tree in worker["treePins"]))
        workspace = job.WORKSPACE_PREFIX + plan["operationId"]
        self.assertEqual(workspace + "\\windows_public_updater\\update_cases.py", worker["casesPath"])
        self.assertEqual(workspace + "\\update-harness.py", worker["harnessPath"])
        self.assertEqual(BASE, worker["productVersion"], "the update starts from the installed base")
        planner.validate_closure(worker)
        inputs, hold = self.harness(plan)
        self.assertIsNone(hold)
        from agent_tools.windows_public_updater import update_cases
        pins = {pin["path"].casefold(): types.SimpleNamespace(record=pin) for pin in worker["filePins"]}
        owner = types.SimpleNamespace(request={"context": worker["context"], "productVersion": worker["productVersion"]}, by_path=pins)
        self.assertIs(inputs, update_cases.validate_inputs(owner, inputs))
        sealed = pins[(workspace + "\\mcp-update-fixture-" + job.fixture_id(plan["operationId"]) + "\\content\\packages\\target\\vpn-control-"
                       + VERSION + ".msi").casefold()].record
        self.assertTrue(sealed["nativeIdentity"]["attributes"] & 1, "the served package is pinned read-only")
        self.assertIsNone(inputs["approvingAdminSid"])
        self.assertEqual(json.loads((self.machine_data / target / job.INVENTORY_NAME).read_bytes())["files"], inputs["targetInventory"])
        self.assertEqual(set(self.qga.installed_tree[0]), set(inputs["baseInventory"]))

    def test_a_deny_row_serves_both_collector_stages_inside_the_run_and_releases_the_hold(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        kinds = self.qga.kinds()
        run = kinds.index("system-run")
        self.assertEqual(["collector-observe", "endpoints", "verify", "collector", "collector-observe", "endpoints", "verify", "collector",
                          "collector-release"], kinds[run + 1:run + 10], "both stages run between two polls of the SYSTEM run")
        self.assertEqual(["before-install", "terminal-actors"], [request["collectorRequest"]["stage"] for request in self.qga.collectors])
        first, final = self.qga.collectors
        self.assertIsNone(first["closeHold"])
        self.assertEqual("terminal-actors", final["closeHold"]["stage"])
        owner = first["collectorRequest"]["actors"]["owner"]
        self.assertEqual((903, 134368653065000004), (owner["pid"], owner["creationFileTime"]))
        self.assertEqual({"pid": 902, "creationFileTime": 134368653065000003}, {key: final["ordinaryTask"]["workerActor"][key] for key in ("pid", "creationFileTime")})
        self.assertEqual({}, final["collectorRequest"]["actors"], "a denied prompt starts no installer")
        self.assertEqual(("controller-1", "request-1"), (final["collectorRequest"]["context"]["originControllerId"], final["collectorRequest"]["context"]["originRequestId"]))
        self.assertEqual(MACHINE, first["context"]["hardwareUuid"], "the contract's lowercase form")
        self.assertEqual([job.collector_operation(plan["operationId"], "terminal-actors")], [release["collectorOperationId"] for release in self.qga.releases])
        self.assertEqual({"before-install": {"requestSha256": hashlib.sha256(self.qga.files[first["requestPath"]]).hexdigest(), "released": False},
                          "terminal-actors": {"requestSha256": hashlib.sha256(self.qga.files[final["requestPath"]]).hexdigest(), "released": True}},
                         receipt["update"]["collectors"])
        inputs, hold = self.harness(plan)
        self.assertEqual(ADMIN_SID, inputs["approvingAdminSid"])
        from agent_tools.windows_system_collector import hold_protocol
        self.assertIs(hold, hold_protocol.validate_inputs(hold, ordinary_task_operation_id=plan["operationId"], program_data="C:\\ProgramData"))
        self.assertEqual(final["operationRoot"], hold["collectorRoot"])
        self.assertEqual([], self.classify()["unresolved"])

    def test_the_collector_program_is_the_rendered_template_on_the_stdin_route(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        self.run_update("uac-denied", base, target)
        for kind, source in self.qga.programs:
            if kind in {"collector", "collector-release"}:
                with self.subTest(kind=kind):
                    raw = job.check_source(source)
                    self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                    defined = source.index("public static class VpnHeldProgram")
                    self.assertLess(defined, source.index("[VpnHeldProgram]::Identity("), "the launcher's type exists before the template calls it")
                    self.assertIn("$expectedHardware='" + MACHINE.upper() + "'", source, "the prelude compares what WMI reports")
                    self.assertIn("$protocolResult= & {", source)

    @unittest.skipUnless(POWERSHELL, "PowerShell parser unavailable; hosted Windows and Linux runners have one")
    def test_the_collector_and_release_programs_parse(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        self.run_update("uac-denied", base, target)
        sources = [(kind, source) for kind, source in self.qga.programs if kind in {"collector", "collector-release"}]
        self.assertEqual(["collector", "collector", "collector-release"], [kind for kind, _ in sources])
        with tempfile.TemporaryDirectory(prefix="collector-sources-") as directory:
            for number, (kind, source) in enumerate(sources):
                path = Path(directory) / (kind + "-" + str(number) + ".ps1")
                path.write_text(source, encoding="ascii")
                script = ("$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile('" + str(path).replace("'", "''")
                          + "',[ref]$tokens,[ref]$errors);if(@($errors).Count){$errors|ForEach-Object {[Console]::Error.WriteLine($_.Message)};exit 9}")
                result = subprocess.run([str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                        stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
                self.assertEqual(0, result.returncode, kind + ": " + result.stderr.decode("utf-8", "replace"))

    def test_a_stage_the_row_cannot_serve_ends_unknown_with_the_fence_open(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        self.qga.needs = ["authorization"]
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((3, "collector_stage_unserved:authorization"), (code, receipt["failure"]))
        self.assertFalse(self.fence(plan, ".terminal.json").exists())
        self.assertNotIn("collector", self.qga.kinds())

    def test_a_collector_that_never_returns_is_unknown_and_nothing_follows_it(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        original = self.qga._collector

        def parked(source, pid):
            original(source, pid)
            return {"exited": False}
        self.qga._collector = parked
        self.qga.polls_before_exit = 1
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual(3, code)
        self.assertTrue(receipt["failure"].startswith("collector_stage_failed:before-install") or receipt["failure"].startswith("guest_"), receipt["failure"])
        self.assertEqual(1, self.qga.kinds().count("collector"))
        self.assertNotIn("evidence-zip", self.qga.kinds()[self.qga.kinds().index("system-run"):], "no copy while a program is open")
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_collector_root_in_another_form_refuses_before_any_task(self):
        base, target = self.prepared()
        original = self.qga._publisher

        def plain(m, pid):
            terminal = original(m, pid)
            if m["action"] == "initialize":
                reply = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(terminal["out-data"]))))
                for pin in reply["directoryPins"]:
                    pin["security"]["sddl"] = pin["security"]["sddl"].replace("O:SYD:PAI(", "O:SYD:P(")
                terminal = {"exited": True, "exitcode": 0, "out-data": out_data(reply)}
            return terminal
        self.qga._publisher = plain
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((1, "collector_root_policy"), (code, receipt["failure"]))
        self.assertNotIn("system-run", self.qga.kinds())

    def test_a_published_file_reads_back_auto_inherited_so_a_collector_row_stops_before_its_task(self):
        """The native form. The pinned collector chain takes its request only as O:SYD:P, and the publisher's files read
        back O:SYD:PAI, so the row ends at publish as a known failure: no owner ever waits on a refused request."""
        base, target = self.prepared()
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((1, "collector_file_policy", "publish"), (code, receipt["failure"], receipt["stage"]))
        self.assertNotIn("system-run", self.qga.kinds())
        self.assertTrue(self.fence(plan, ".terminal.json").exists(), "a known failure closes the fence")

    def test_system_cannot_open_the_owner_only_disposition_so_terminal_actors_ends_unknown(self):
        """Even past publish, terminal-actors reads the product's not-started disposition as SYSTEM, and the product
        grants that file to its owner alone. The owner is still waiting on that stage, so the job ends UNKNOWN."""
        base, target = self.prepared()
        self.qga.endpoint_form = "P"  # Supposed: only the reader is missing here.
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((3, "collector_stage_failed:terminal-actors:publisher_refused:collector-observe-terminal-actors"),
                         (code, receipt["failure"]))
        kinds = self.qga.kinds()
        self.assertEqual(1, kinds.count("collector"), "before-install only")
        self.assertNotIn("collector-release", kinds)
        self.assertNotIn("evidence-zip", kinds[kinds.index("system-run"):], "the run is still open")
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_need_beside_a_parked_file_starts_nothing(self):
        """A parked owner is reported and never touched: its status may still name a need it asked for before parking."""
        base, target = self.prepared()
        self.suppose_collector_inputs()
        self.qga.needs, self.qga.parked_files = ["before-install"], ["owner-parked.json"]
        self.qga.run_state, self.qga.run_polls = "owner-parked", 2
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((3, "owner-parked"), (code, receipt["failure"]))
        kinds = self.qga.kinds()
        self.assertEqual(["system-run", "evidence-zip"], kinds[kinds.index("system-run"):], "no collector program for a parked owner")
        self.assertEqual([], self.qga.collectors)
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_need_read_after_the_run_returned_starts_nothing(self):
        """The last status copy is read after the run returned, here at its deadline. A need in it is never served:
        nothing starts for an owner the run has stopped watching."""
        base, target = self.prepared()
        self.suppose_collector_inputs()
        self.qga.needs = ["before-install"]
        self.qga.run_state, self.qga.run_polls = "deadline", 0
        plan, code, receipt = self.run_update("uac-denied", base, target)
        self.assertEqual((3, "deadline"), (code, receipt["failure"]))
        kinds = self.qga.kinds()
        self.assertEqual(["system-run", "evidence-zip"], kinds[kinds.index("system-run"):])
        self.assertEqual([], self.qga.collectors)
        status = json.loads((Path(plan["dataDirectory"]) / "status.json").read_bytes())
        self.assertEqual(["before-install"], [need["stage"] for need in status["nativeNeeds"]], "the copy is still kept for observers")

    def test_the_update_needs_the_target_install_inventory_and_an_older_base(self):
        base, target = self.prepared()
        for prior, reason in (({"install": base, "targetInstall": base}, "target_install_other_package"),
                              ({"install": target, "targetInstall": target}, "prior_install_other_package"),
                              ({"install": base, "targetInstall": str(uuid.uuid4())}, "prior_install_unavailable")):
            with self.subTest(prior=prior):
                plan = self.update_plan("public-ready", base, target, prior=prior)
                self.addCleanup(self.forget_modules, plan["operationId"])
                self.assertEqual(2, job.run_job(self.rt, plan, self.files))
                self.assertEqual(reason, self.rt.emitted[-1]["failure"])
        inventory = self.machine_data / target / job.INVENTORY_NAME
        value = json.loads(inventory.read_bytes())
        value["files"]["vpn-control.exe"]["sha256"] = "0" * 64
        inventory.chmod(0o600)
        inventory.write_bytes(json.dumps(value).encode())
        plan, code, receipt = self.run_update("public-ready", base, target)
        self.assertEqual((2, "target_install_inventory"), (code, self.rt.emitted[-1]["failure"]))

    def test_the_status_copy_names_the_decision_once_its_terminal_exists(self):
        base, target = self.prepared()
        self.suppose_collector_inputs()
        plan = self.update_plan("uac-denied", base, target)
        decision = job.decision_id(plan["operationId"])
        directory = self.vm / "windows-uac" / decision
        directory.mkdir(parents=True, mode=0o700)
        (directory / "input.terminal.json").write_text(json.dumps({"state": "input-ack-only", "operationId": decision, "attempt": 1, "decision": "deny",
                                                                   "prompt": "install-helper", "promptClosed": True, "approvalSucceeded": False,
                                                                   "productOutcomeProved": False, "replayAllowed": False}))
        (directory / "input.terminal.json").chmod(0o600)
        self.addCleanup(self.forget_modules, plan["operationId"])
        self.assertEqual(0, job.run_job(self.rt, plan, self.files))
        status = json.loads((Path(plan["dataDirectory"]) / "status.json").read_bytes())
        self.assertEqual({"state": "input-ack-only", "decision": "deny", "prompt": "install-helper", "promptClosed": True}, status["uacDecision"])
        self.assertEqual(["update-uac-action-pending"], status["uacEvents"])


class TrustStoreTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography verifies the store's MAC and bag here")
    def test_the_store_holds_exactly_the_certificate_and_opens_with_the_fixture_password(self):
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "github.com")])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
                       .not_valid_before(now).not_valid_after(now + datetime.timedelta(hours=1)).sign(key, hashes.SHA256()))
        store = job.java_truststore(certificate.public_bytes(serialization.Encoding.DER), b"0123456789abcdef")
        loaded = pkcs12.load_pkcs12(store, job.TRUSTSTORE_PASSWORD.encode())
        self.assertEqual((None, None, 1), (loaded.key, loaded.cert, len(loaded.additional_certs)))
        self.assertEqual(certificate, loaded.additional_certs[0].certificate)
        self.assertEqual(job.TRUSTSTORE_ALIAS.encode(), loaded.additional_certs[0].friendly_name)
        with self.assertRaises(ValueError):
            pkcs12.load_pkcs12(store, b"other")

    def test_the_store_carries_the_trusted_key_usage_attribute(self):
        store = job.java_truststore(b"0\x03\x02\x01\x00", b"0123456789abcdef")
        # 2.16.840.1.113894.746875.1.1 with anyExtendedKeyUsage: what makes a JVM read the bag as a trust anchor.
        self.assertIn(bytes.fromhex("060c6086480186f966adca7b0101") + bytes.fromhex("3106") + bytes.fromhex("0604551d2500"), store)


class StageShapeTests(unittest.TestCase):
    def test_the_test_inventory_is_the_bundle_inventory(self):
        self.assertEqual(BUNDLE_FILES, bundles._SCENARIOS["windows-scenario-driver"])

    def test_rows_only_name_closed_stages_in_order(self):
        for name, row in driver.RECIPES.items():
            with self.subTest(name=name):
                order = [stage for stage in job.STAGE_ORDER if stage in row["stages"]]
                self.assertEqual(order, list(row["stages"]))
                self.assertEqual(("anchor", "context"), tuple(row["stages"][:2]))
                # Only a reboot preboot declares, after its evidence and before its receipt.
                ending = ("evidence", "declare", "receipt") if (row.get("reboot") or {}).get("phase") == "pre" else ("evidence", "receipt")
                self.assertEqual(ending, tuple(row["stages"][-len(ending):]))

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
