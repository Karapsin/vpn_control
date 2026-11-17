"""The Windows public-update deny and grant tooling: the one request form the SYSTEM collector chain takes, the
backup-privilege reader of the product's owner-only not-started disposition, and the job's discovery of the installer
actors from a SYSTEM process census.

Offline, Win32 is a declared in-memory model of one SYSTEM collector thread's tokens and of a file whose DACL grants
SYSTEM nothing: no guest, process or file of Windows is touched. WindowsReaderTests alone runs on Windows itself
(skipped elsewhere): both readers, Python's backup_open and the publisher's VpnScenarioObserver, open a file only
SYSTEM may read, as the runner's own administrator token.
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import functools
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import windows_scenario_host_job as job
from agent_tools.windows_public_updater import native_collector, update_receipts
from agent_tools.windows_system_collector import collector_contract as contract
from agent_tools.windows_system_collector import collector_wrapper as wrapper
from scripts import windows_broker_fixture_observer as broker_observer

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = ROOT / "agent_tools" / "windows_system_collector"
SYSTEM = "S-1-5-18"
SID = "S-1-5-21-1-2-3-1000"
ADMIN_SID = "S-1-5-21-1-2-3-1001"
SESSION = 2
# A file the publisher creates and then protects with SetAccessControl reads back so natively: every native
# worker-request.json pin did. SYSTEM owner, protected DACL, three explicit ACEs, none inherited.
NATIVE_FORM = "O:SYD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + SID + ")"

BOOT = "6f1c2a3e-1111-4222-8333-944455556666"
OPERATION = "0d5e5c56-7a39-4f43-9d4b-2a1c3d4e5f60"
JOB = "88888888-9999-4aaa-8bbb-cccccccccccc"
PRODUCT_OPERATION = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
LOCAL = "C:\\Users\\recovery\\AppData\\Local"
WORKSPACE = LOCAL + "\\vpn-control-scenarios\\" + OPERATION + "\\workspace"
DISPOSITION = WORKSPACE + "\\.install-not-started-" + "a" * 64 + ".json"
PROTECTED_JOB = "C:\\ProgramData\\vpn-control-install-jobs\\" + JOB
CONTROLLER, REQUEST = "controller-7", "request-7"
INVALID = ctypes.c_void_p(-1).value
SE_BACKUP = (17, 0)
READ_ONLY = (0x80020000, 1, 3, 0x02200000)  # GENERIC_READ|READ_CONTROL, share read, OPEN_EXISTING, backup semantics|no reparse


def disposition(**changes):
    return json.dumps({"disposition": "NOT_STARTED", "jobId": JOB, "controllerId": CONTROLLER, "requestId": REQUEST,
                       "operationId": PRODUCT_OPERATION, **changes}, sort_keys=True).encode()


def deny_request(raw):
    """terminal-actors of the deny row as the job builds it: no installer actor, the product's own not-started record."""
    return {"schemaVersion": 1, "stage": "terminal-actors", "ordinaryTaskOperationId": OPERATION, "sourceSha": "1" * 40,
            "collectorSourceSha256": "2" * 64,
            "context": {"bootIdentifier": BOOT, "ordinarySid": SID, "ordinarySessionId": SESSION, "localAppData": LOCAL,
                        "workspace": WORKSPACE, "approvingAdminSid": ADMIN_SID, "originControllerId": CONTROLLER,
                        "originRequestId": REQUEST},
            "jobId": JOB, "productOperationId": PRODUCT_OPERATION, "actors": {},
            "fileInputs": {"notStartedDisposition": {"path": DISPOSITION, "sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)}},
            "faultBinding": {}, "programData": "C:\\ProgramData", "evidenceRoot": "C:\\ProgramData\\vpn-control-evidence",
            "ordinaryWorkerPid": 4242, "ordinaryWorkerBirth": "133000000000000002", "expectedHelperSha256": None}


class RequestFormTests(unittest.TestCase):
    """Writer and every reader of a collector request agree on one form: the one a published file reads back natively.

    At 70ed16cc the chain demanded O:SYD:P, which no writer of this route produces, so every collector row ended at
    publish with collector_file_policy, and the release program would have refused its own published release."""

    def test_the_contract_takes_the_form_a_published_file_reads_back(self):
        self.assertIsNone(contract.file_policy({"ownerSid": SYSTEM, "sddl": NATIVE_FORM}, SID))

    def test_any_other_form_is_refused(self):
        """SYSTEM-owned, protected, exactly these three explicit ACEs: nothing inherited and nothing more."""
        forms = {"not-auto-inherited": NATIVE_FORM.replace("D:PAI", "D:P"), "unprotected": NATIVE_FORM.replace("D:PAI", "D:AI"),
                 "inherited-ace": NATIVE_FORM.replace("(A;;FA;;;SY)", "(A;ID;FA;;;SY)"), "extra-ace": NATIVE_FORM + "(A;;FA;;;WD)",
                 "ordinary-writes": NATIVE_FORM.replace("0x1200a9", "FA"), "another-ordinary": NATIVE_FORM.replace(SID, ADMIN_SID),
                 "administrators-own": NATIVE_FORM.replace("O:SY", "O:BA")}
        for name, sddl in forms.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "collector-machine-writer-file-policy"):
                contract.file_policy({"ownerSid": SYSTEM, "sddl": sddl}, SID)
        with self.assertRaisesRegex(ValueError, "collector-machine-writer-file-policy"):
            contract.file_policy({"ownerSid": "S-1-5-32-544", "sddl": NATIVE_FORM}, SID)

    def test_every_reader_and_the_job_state_that_one_form(self):
        """The bootstrap admits its request, the release program its request and the release it publishes, and the job
        checks the owner's pin before any task, all against the contract's own form."""
        prefix = NATIVE_FORM[:-len(SID) - 1]
        bootstrap = (COLLECTOR / "system_bootstrap_template.ps1").read_text(encoding="utf-8")
        release = (COLLECTOR / "release_template.ps1").read_text(encoding="utf-8")
        self.assertEqual({"bootstrap": [prefix], "release": [prefix]},
                         {"bootstrap": re.findall(r"^\$requiredFilePolicy='([^']*)'\+\$r\.context\.ordinarySid\+'\)'$", bootstrap, re.M),
                          "release": re.findall(r"^\$required='([^']*)'\+\$request\.context\.ordinarySid\+'\)'$", release, re.M)})
        self.assertIn("$requestRecord.security.sddl -cne $requiredFilePolicy", bootstrap)
        self.assertIn("$requestRecord.security.sddl -cne $required)", release)
        self.assertIn("$publishedSecurity[1] -cne $required", release)
        self.assertEqual(NATIVE_FORM, job.COLLECTOR_FILE_SDDL.format(sid=SID))


# A collector root as the publisher's CreateDirectory with a protected descriptor leaves it: natively every collector root
# of 723417ea read back so, and the seven TUN grant rows on S_D4 (2.2.19) ended at publish against a PAI-only check.
ROOT_ACES = "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + SID + ")"
NATIVE_ROOT = "O:SYD:P" + ROOT_ACES


class RootFormTests(unittest.TestCase):
    """The collector root's DACL: SYSTEM-owned, protected from every inherited ACE, exactly three explicit ACEs.

    The chain demanded the auto-inherited flag as well, which CreateDirectory never writes, so no collector row could
    reach its task. The flag records only how a DACL was written; with or without it the root grants the same."""

    def test_the_contract_takes_the_root_as_created_natively_and_the_same_dacl_auto_inherited(self):
        for sddl in (NATIVE_ROOT, "O:SYD:PAI" + ROOT_ACES):
            with self.subTest(sddl=sddl[:9]):
                self.assertIsNone(contract.root_policy({"ownerSid": SYSTEM, "sddl": sddl}, SID))

    def test_any_other_root_form_is_refused(self):
        forms = {"unprotected": "O:SYD:" + ROOT_ACES, "auto-inherited-unprotected": "O:SYD:AI" + ROOT_ACES,
                 "inherited-ace": NATIVE_ROOT.replace("(A;OICI;FA;;;SY)", "(A;OICIID;FA;;;SY)"),
                 "extra-ace": NATIVE_ROOT + "(A;OICI;FA;;;WD)", "ordinary-writes": NATIVE_ROOT.replace("0x1200a9", "FA"),
                 "another-ordinary": NATIVE_ROOT.replace(SID, ADMIN_SID), "not-inheritable": NATIVE_ROOT.replace("OICI;", ";"),
                 "administrators-own": NATIVE_ROOT.replace("O:SY", "O:BA"), "file-form": NATIVE_FORM}
        for name, sddl in forms.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "collector-machine-writer-operation-root-policy"):
                contract.root_policy({"ownerSid": SYSTEM, "sddl": sddl}, SID)
        for security in ({"ownerSid": "S-1-5-32-544", "sddl": NATIVE_ROOT}, {"ownerSid": SYSTEM, "sddl": NATIVE_ROOT, "extra": 1},
                         {"sddl": NATIVE_ROOT}, None):
            with self.subTest(security=security), self.assertRaisesRegex(ValueError, "collector-machine-writer-operation-root-policy"):
                contract.root_policy(security, SID)

    def test_the_task_guard_the_release_program_and_the_job_state_those_forms(self):
        """The guard inside the SYSTEM collector, the release program and the job before any task take the contract's
        own forms and no other."""
        self.assertEqual(("P", "PAI"), contract.ROOT_FORMS)
        self.assertEqual((NATIVE_ROOT, "O:SYD:PAI" + ROOT_ACES), contract.root_sddls(SID))
        self.assertEqual(list(contract.root_sddls(SID)), [form["sddl"] for form in job.collector_root_forms(SID)])
        self.assertEqual({SYSTEM}, {form["ownerSid"] for form in job.collector_root_forms(SID)})
        aces = ROOT_ACES[:-len(SID) - 1]
        guard = (COLLECTOR / "ordinary_task_guard.ps1").read_text(encoding="utf-8")
        release = (COLLECTOR / "release_template.ps1").read_text(encoding="utf-8")
        self.assertEqual([aces], re.findall(r"^ \$aces='([^']*)'\+\$script:C\.request\.context\.ordinarySid\+'\)'$", guard, re.M))
        self.assertEqual([aces], re.findall(r"^\$rootAces='([^']*)'\+\$request\.context\.ordinarySid\+'\)'$", release, re.M))
        self.assertEqual([("O:SYD:P", "O:SYD:PAI")], re.findall(r"^ \$forms=@\(\('([^']*)'\+\$aces\),\('([^']*)'\+\$aces\)\)$", guard, re.M))
        self.assertEqual([("O:SYD:P", "O:SYD:PAI")],
                         re.findall(r"^\$rootForms=@\(\('([^']*)'\+\$rootAces\),\('([^']*)'\+\$rootAces\)\)$", release, re.M))
        self.assertIn("$forms -cnotcontains $root[0].record.security.sddl){throw 'SC_MACHINE_WRITER_ROOT_POLICY'}", guard)
        self.assertIn("$rootForms -cnotcontains $roots[0].record.security.sddl){throw 'ACK_ROOT_MACHINE_POLICY'}", release)
        self.assertNotIn("O:SYD:PAI(A;OICI", guard + release, "no reader keeps a single root form of its own")


# The collector-closed proof the SYSTEM bootstrap returned for before-install of update grant row 72c2fa02 (clone NE2,
# S_Q), exactly as the operator decoded it from that run's qga.wire: the worker published, exited 0 and reported its
# own token in session 0, but the proof's worker.sessionId was null. The job ended UNKNOWN (exit 3)
# collector_stage_failed:before-install:collector-original-child-native-generation.
NATIVE_PROOF = ROOT / "agent_tools/tests/fixtures/windows_system_collector/native-72c2fa02-before-install.proof.json"


def native_proof_request(proof):
    """The request and its pin as far as the child check reads them, each fact taken from the native run itself."""
    result = json.loads(base64.b64decode(proof["captures"][0]["base64"]))
    request = {"operationId": proof["operationId"], "ordinaryTaskOperationId": proof["ordinaryTaskOperationId"], "scope": "update",
               "modules": {"collector": {"sha256": proof["collectorSourceSha256"]}},
               "pythonRuntime": {"interpreterPath": proof["worker"]["image"]}, "rawStreamLimitBytes": job.COLLECTOR_RAW_LIMIT,
               "context": {"bootIdentifier": result["workerActor"]["bootIdentifier"]},
               "filePins": [None] * (result["closing"]["files"] - 1), "closeHold": None}
    return request, {"sha256": proof["requestSha256"], "nativeIdentity": dict(proof["requestNativeIdentity"])}


class CollectorChildSessionTests(unittest.TestCase):
    """The SYSTEM bootstrap's proof of its worker's session, and both readers of it.

    At fd17037c the bootstrap wrote worker.sessionId from Process.SessionId after the worker had exited. Windows
    PowerShell's .NET Framework answers that property from a process snapshot looked up by id, not from the retained
    handle, and an exited process is no longer in it: the native proof carried null, and both readers refused it
    under the generation code. The bootstrap now reads TokenSessionId from the retained handle's token while the
    worker runs, parks under its own reason if it cannot, and a session that is not an integer fails on its own code.
    """

    def validators(self):
        def by_job(request, pin, proof):
            return job.Job._validate_collector_child(types.SimpleNamespace(_keep=lambda *_: None), "before-install", request, pin, proof)

        def by_wrapper(request, pin, proof):
            holder = types.SimpleNamespace(proof=proof, request=request, request_pin=pin, child_raw={}, protocol=None,
                                           n={"prefix": "native", "save": lambda *_: None})
            wrapper.RetainedSystemCollector.validate_child(holder)
            return holder.worker_result
        return {"job": by_job, "wrapper": by_wrapper}

    def native(self, **worker):
        proof = json.loads(NATIVE_PROOF.read_bytes())
        proof["worker"].update(worker)
        return (*native_proof_request(proof), proof)

    def test_the_native_proof_with_no_session_fails_on_its_own_code(self):
        """The native proof as it came back: an unread session, never taken as session 0."""
        request, pin, proof = self.native()
        self.assertIsNone(proof["worker"]["sessionId"])
        for name, validate in self.validators().items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "^collector-original-child-session-unread$"):
                validate(request, pin, proof)

    def test_the_same_native_proof_with_its_worker_in_session_0_is_accepted(self):
        """Nothing else in the native proof fails: its session was the one defect."""
        request, pin, proof = self.native(sessionId=0)
        for name, validate in self.validators().items():
            with self.subTest(name):
                result = validate(request, pin, proof)
                self.assertEqual(0, result["workerActor"]["token"]["sessionId"])
                self.assertEqual("before-install", result["publications"][0]["stage"])

    def test_a_session_that_is_not_an_integer_is_unread_and_another_session_is_another_generation(self):
        cases = {"session-unread": ("0", 0.0, True, False, [0], {}), "native-generation": (1, 2, -1)}
        for code, values in cases.items():
            for value in values:
                request, pin, proof = self.native(sessionId=value)
                for name, validate in self.validators().items():
                    with self.subTest(name, value=value), self.assertRaisesRegex(ValueError, "^collector-original-child-" + code + "$"):
                        validate(request, pin, proof)

    def test_the_bootstrap_reads_the_session_from_the_retained_handle_while_its_worker_runs(self):
        """Closest fast check of the native defect, which only Windows reproduces: once the worker has exited, the
        bootstrap reads its original Process only through members its retained handle or its own fields answer (Id,
        ExitCode, Handle), and the session in the closed record is the one read between Start and Wait-Child from the
        token of that handle, under its own park reason when it cannot be read."""
        lines = (COLLECTOR / "system_bootstrap_template.ps1").read_text(encoding="utf-8").splitlines()
        start = lines.index("if(-not $script:C.process.Start()){throw 'SYSTEM_ORIGINAL_START_FALSE'}")
        wait = lines.index("Wait-Child")
        exited = set(re.findall(r"\$script:C\.process\.([A-Za-z]+)", "\n".join(lines[wait:])))
        self.assertLessEqual(exited, {"Id", "ExitCode", "Handle"}, "a snapshot member of an exited process reads as null")
        read = [number for number, line in enumerate(lines) if "$script:C.childSession=" in line]
        self.assertEqual(1, len(read))
        self.assertLess(start, read[0])
        self.assertLess(read[0], wait)
        self.assertEqual("try{$childToken=[ScFacts]::ProcessToken($script:C.process.Handle);$script:C.childSession=[int]::Parse("
                         "$childToken[1],[Globalization.NumberStyles]::None,[Globalization.CultureInfo]::InvariantCulture)}"
                         "catch{Park-Original 'SC_CHILD_SESSION_UNREAD' $_}", lines[read[0]])
        closed = [line for line in lines if "state='collector-closed'" in line]
        self.assertEqual(1, len(closed))
        self.assertIn(";sessionId=$script:C.childSession;exitCode=$script:C.process.ExitCode;", closed[0])
        # ProcessToken's second value is TokenInformationClass 12, TokenSessionId.
        native = (COLLECTOR / "system_collector_native.cs").read_text(encoding="utf-8")
        self.assertIn("return new string[]{id.User.Value,Scalar(t,12).ToString(),", native)


class Export:
    """One Win32 export of the model: callable, and it keeps the restype and argtypes its caller declares."""

    def __init__(self, body):
        self.body = body

    def __call__(self, *arguments):
        return self.body(*arguments)


def handle_value(handle):
    return handle.value if isinstance(handle, ctypes.c_void_p) else handle


class Win32:
    """kernel32 and advapi32 as one SYSTEM thread of the collector sees them.

    SYSTEM holds SeBackupPrivilege disabled in its process token. ImpersonateSelf gives the thread a copy of that token,
    whose privileges then change alone. A file whose DACL grants SYSTEM nothing opens only for reading, with backup
    semantics, while the opening thread's token has the privilege enabled; a missing path is ERROR_PATH_NOT_FOUND.
    faults names what goes wrong on purpose."""

    def __init__(self, files, *, process_state=1, faults=()):
        self.files = {path: list(entry) for path, entry in files.items()}  # path: [bytes, owner only, file index]
        self.process_state, self.thread_state = process_state, None  # 0 absent, 1 disabled, 2 enabled; None: not impersonating
        self.faults, self.final = set(faults), {}
        self.opened, self.calls, self.serial, self.error = {}, [], 1000, 0
        self.k = types.SimpleNamespace(**{name: Export(getattr(self, name)) for name in
                                          ("GetCurrentThread", "GetCurrentProcess", "CreateFileW", "CloseHandle", "GetFinalPathNameByHandleW")})
        self.a = types.SimpleNamespace(**{name: Export(getattr(self, name)) for name in
                                          ("LookupPrivilegeValueW", "ImpersonateSelf", "RevertToSelf", "OpenThreadToken",
                                           "OpenProcessToken", "AdjustTokenPrivileges", "GetTokenInformation")})

    @contextlib.contextmanager
    def current(self):
        """The thread's last error and WinError, as the code under test reads them through ctypes."""
        def set_last_error(value):
            old, self.error = self.error, value
            return old

        def win_error(code=None):
            error = OSError(code, "Win32 error %s" % code)
            error.winerror = code
            return error
        with mock.patch.object(ctypes, "set_last_error", set_last_error, create=True), \
                mock.patch.object(ctypes, "get_last_error", lambda: self.error, create=True), \
                mock.patch.object(ctypes, "WinError", win_error, create=True):
            yield self

    def handle(self, kind, value):
        self.serial += 1
        self.opened[self.serial] = (kind, value)
        return self.serial

    def GetCurrentThread(self):
        return INVALID - 1

    def GetCurrentProcess(self):
        return INVALID

    def LookupPrivilegeValueW(self, system, name, luid):
        if system is not None or name != "SeBackupPrivilege":
            self.error = 1313
            return 0
        luid._obj.low, luid._obj.high = SE_BACKUP
        return 1

    def ImpersonateSelf(self, level):
        self.calls.append(("impersonate", level))
        self.thread_state = self.process_state
        return 1

    def RevertToSelf(self):
        self.calls.append(("revert",))
        if "revert" in self.faults:
            return 0
        self.thread_state = None
        return 1

    def OpenThreadToken(self, thread, access, as_self, token):
        if self.thread_state is None:
            self.error = 1008
            return 0
        token._obj.value = self.handle("token", "thread")
        return 1

    def OpenProcessToken(self, process, access, token):
        token._obj.value = self.handle("token", "process")
        return 1

    def state(self, token):
        return self.thread_state if self.opened[handle_value(token)][1] == "thread" else self.process_state

    def AdjustTokenPrivileges(self, token, disable_all, privileges, size, previous, returned):
        which, entry = self.opened[handle_value(token)][1], privileges._obj
        enable = entry.attributes == 2
        self.calls.append(("adjust", which, enable))
        if (disable_all or entry.count != 1 or (entry.luid.low, entry.luid.high) != SE_BACKUP or not self.state(token)
                or ("enable" if enable else "disable") in self.faults):
            self.error = 1300  # ERROR_NOT_ALL_ASSIGNED: the call succeeds and assigns nothing.
            return 1
        if which == "thread":
            self.thread_state = 2 if enable else 1
        else:
            self.process_state = 2 if enable else 1
        self.error = 0
        return 1

    def GetTokenInformation(self, token, kind, buffer, size, needed):
        state = self.state(token)
        entries = [((23, 0), 3)] + ([(SE_BACKUP, 2 if state == 2 else 0)] if state else [])  # SeChangeNotifyPrivilege stays on
        raw = len(entries).to_bytes(4, "little") + b"".join(
            low.to_bytes(4, "little") + high.to_bytes(4, "little", signed=True) + attributes.to_bytes(4, "little")
            for (low, high), attributes in entries)
        needed._obj.value = len(raw)
        if kind != 3 or buffer is None or size < len(raw):
            self.error = 122
            return 0
        ctypes.memmove(buffer, raw, len(raw))
        return 1

    def CreateFileW(self, path, access, share, security, disposition_, flags, template):
        self.calls.append(("open", path, access, share, disposition_, flags, self.thread_state))
        if "process-enabled-meanwhile" in self.faults:
            self.process_state = 2  # Another thread of the process enabled it on the process token itself.
        if path not in self.files:
            self.error = 3
            return INVALID
        reads = 0x80000000 | 0x00100000 | 0x00020000 | 0x00000080
        if self.files[path][1] and (self.thread_state != 2 or not flags & 0x02000000 or access & ~reads or disposition_ != 3):
            self.error = 5
            return INVALID
        self.error = 0
        return self.handle("file", path)

    def CloseHandle(self, handle):
        return 1 if self.opened.pop(handle_value(handle), None) else 0

    def GetFinalPathNameByHandleW(self, handle, buffer, size, flags):
        path = self.opened[handle_value(handle)][1]
        text = "\\\\?\\" + self.final.get(path, path)
        buffer.value = text
        return len(text)


class SystemNative:
    """The collector's own Native over the model: the token it runs as and the facts of a file read through its handle."""

    def __init__(self, world):
        self.world, self.k, self.a = world, world.k, world.a

    def boot_identifier(self):
        return BOOT

    def token(self):
        return {"sid": SYSTEM, "elevation": 1}

    def entry(self, handle):
        path = self.world.opened[handle_value(handle)][1]
        return path, self.world.files[path]

    def identity(self, handle, directory=False):
        _, (raw, _, index) = self.entry(handle)
        return {"volumeSerial": 7, "fileIndex": index, "attributes": 0x20, "sizeBytes": len(raw), "links": 1,
                "creationFileTime": "133000000000000000", "lastWriteFileTime": "133000000000000001"}

    def security(self, handle):
        _, (_, owner_only, _) = self.entry(handle)
        return ({"ownerSid": SID, "sddl": "O:" + SID + "G:" + SID + "D:P(A;;FA;;;" + SID + ")"} if owner_only
                else {"ownerSid": SYSTEM, "sddl": "O:SYD:P(A;;FA;;;SY)"})

    def read_blocks(self, handle):
        path, entry = self.entry(handle)
        self.world.calls.append(("read", path, self.world.thread_state))
        yield entry[0]
        if "replaced-while-read" in self.world.faults:
            entry[2] += 1


class CollectionOwner:
    """What collect takes from the SYSTEM collection owner: its Native, its source pins, its guard and its events."""

    def __init__(self, world, request):
        self.native = SystemNative(world)
        self.by_path = {str(Path(native_collector.__file__)).casefold(): types.SimpleNamespace(record={"sha256": request["collectorSourceSha256"]})}
        self.events = []

    def guard(self):
        pass

    def event(self, kind, value):
        self.events.append((kind, value))


class BackupReaderTests(unittest.TestCase):
    """terminal-actors of the deny row reads the product's not-started disposition as SYSTEM.

    The product writes .install-not-started-*.json O:<owner>G:<owner>D:P(A;;FA;;;<owner>): SYSTEM has no ACE, by design,
    and the tool never changes that ACL. At 70ed16cc the collector opened it plainly, which Windows refuses, so a denied
    row's owner waited on terminal-actors until its deadline. Now SeBackupPrivilege is enabled on the thread's own
    impersonation token for one read-only backup open, then disabled and reverted before any byte is read."""

    def world(self, **options):
        raw = disposition()
        return Win32({DISPOSITION: [raw, True, 41]}, **options), raw

    def collect(self, world, request):
        observer = types.SimpleNamespace(WindowsNative=lambda: object(), observe_exit=lambda actors, native: [])
        owner = CollectionOwner(world, request)
        with world.current():
            return native_collector.collect(request, owner, update_receipts, observer), owner

    def test_terminal_actors_reads_the_owner_only_disposition_through_the_backup_privilege_alone(self):
        world, raw = self.world()
        value, owner = self.collect(world, deny_request(raw))
        observations = value["observations"]
        self.assertEqual(json.loads(raw), observations["notStartedDisposition"])
        self.assertEqual({"nativeError": 3, "path": PROTECTED_JOB}, observations["protectedJobAbsence"])
        journal = {"privilege": "SeBackupPrivilege", "scope": "thread-impersonation", "path": DISPOSITION, "access": 0x80020000,
                   "share": 1, "flags": 0x02200000, "processStateBefore": 1, "enabledForOpen": True, "disabledAfterOpen": True,
                   "reverted": True, "openError": 0, "processStateAfter": 1}
        self.assertEqual(journal, observations["notStartedBackupRead"])
        self.assertEqual([("open", DISPOSITION, *READ_ONLY, 2)], [call for call in world.calls if call[0] == "open" and call[1] == DISPOSITION],
                         "one read-only backup open, while the thread's own token has the privilege on")
        self.assertEqual([("read", DISPOSITION, None)], [call for call in world.calls if call[0] == "read"], "read after the revert")
        self.assertEqual([("impersonate", 2), ("adjust", "thread", True), ("adjust", "thread", False), ("revert",)],
                         [call for call in world.calls if call[0] in ("impersonate", "adjust", "revert")], "the process token never")
        self.assertEqual((1, None, {}), (world.process_state, world.thread_state, world.opened), "nothing changed, nothing left open")
        self.assertEqual([("native-collector-backup-read", {"backupRead": journal, "sizeBytes": len(raw),
                                                            "sha256": hashlib.sha256(raw).hexdigest(), "readOnly": True})], owner.events)

    def test_a_privilege_the_thread_could_not_enable_opens_nothing(self):
        world, raw = self.world(faults={"enable"})
        with self.assertRaisesRegex(OSError, "backup-open-refused"):
            self.collect(world, deny_request(raw))
        self.assertEqual([], [call for call in world.calls if call[0] in ("open", "read") and call[1] == DISPOSITION])
        self.assertEqual((1, None, {}), (world.process_state, world.thread_state, world.opened))

    def test_a_privilege_that_was_not_dropped_reads_no_byte_and_keeps_no_handle(self):
        for fault in ("disable", "revert"):
            with self.subTest(fault=fault):
                world, raw = self.world(faults={fault})
                with self.assertRaisesRegex(RuntimeError, "backup-privilege-not-dropped"):
                    self.collect(world, deny_request(raw))
                self.assertEqual([], [call for call in world.calls if call[0] == "read"])
                self.assertEqual({}, world.opened)
                self.assertEqual(1, world.process_state)

    def test_a_process_token_that_changed_meanwhile_is_never_a_read(self):
        world, raw = self.world(faults={"process-enabled-meanwhile"})
        with self.assertRaisesRegex(OSError, "backup-open-refused"):
            self.collect(world, deny_request(raw))
        self.assertEqual([], [call for call in world.calls if call[0] == "read"])
        self.assertEqual({}, world.opened)

    def test_a_token_without_the_privilege_never_impersonates(self):
        world, raw = self.world(process_state=0)
        with self.assertRaisesRegex(ValueError, "backup-privilege-absent"):
            self.collect(world, deny_request(raw))
        self.assertEqual([], [call for call in world.calls if call[0] in ("impersonate", "open")])

    def test_a_disposition_whose_name_bytes_or_generation_changed_is_refused(self):
        cases = (("backup-held-canonical-file", lambda world: world.final.__setitem__(DISPOSITION, WORKSPACE + "\\other.json")),
                 ("native-observation-file-changed", lambda world: world.files[DISPOSITION].__setitem__(0, disposition(extra=1))),
                 ("held-read-generation-changed", lambda world: world.faults.add("replaced-while-read")))
        for reason, change in cases:
            with self.subTest(reason=reason):
                world, raw = self.world()
                change(world)
                with self.assertRaisesRegex(ValueError, reason):
                    self.collect(world, deny_request(raw))
                self.assertEqual(({}, 1, None), (world.opened, world.process_state, world.thread_state))


INSTALLED = LOCAL + "\\vpn-control"
CLI = INSTALLED + "\\vpn-control-cli.exe"
GUI = INSTALLED + "\\vpn-control.exe"
HELPER = INSTALLED + "\\app\\native\\windows-amd64\\vpn-control-install-helper.exe"
HELPER_BYTES = b"MZ install helper"
HELPER_RECORD = {"path": HELPER, "sha256": hashlib.sha256(HELPER_BYTES).hexdigest(), "sizeBytes": len(HELPER_BYTES)}
SERVE, JVM, COORDINATOR, WORKER = 903, 913, 921, 922
SERVE_BIRTH, JVM_BIRTH, COORDINATOR_BIRTH, WORKER_BIRTH = 134368653065000004, 134368653065000006, 134368653065000020, 134368653065000021
OWNER = {"pid": JVM, "creationFileTime": JVM_BIRTH}


def process(pid, parent, birth, image, argv, sid, elevated, image_bytes, parent_row=None):
    """One process as VpnScenarioObserver.Describe reports it through its own handle."""
    return {"pid": pid, "parentPid": parent, "openError": None, "creationFileTime": str(birth), "alive": True, "image": image,
            "argv": list(argv), "token": {"sid": sid, "sessionId": SESSION, "elevated": elevated, "elevationType": 2 if elevated else 1},
            "imageSha256": hashlib.sha256(image_bytes).hexdigest(), "imageSizeBytes": len(image_bytes),
            "parent": parent_row or {"pid": parent, "openError": 87, "alive": None, "creationFileTime": None, "image": None}}


def census():
    """The serve the owner started and the JVM its launcher relaunched into; the job's coordinator, whose parent (the
    owner) the census could not open, and the original-user worker, whose parent is that coordinator."""
    owner = [str(JVM), str(JVM_BIRTH)]
    return [process(SERVE, 902, SERVE_BIRTH, CLI, [CLI, "serve"], SID, 0, b"cli"),
            process(JVM, SERVE, JVM_BIRTH, CLI, [CLI, "serve"], SID, 0, b"cli",
                    {"pid": SERVE, "openError": None, "alive": True, "creationFileTime": str(SERVE_BIRTH), "image": CLI}),
            process(COORDINATOR, JVM, COORDINATOR_BIRTH, HELPER, [HELPER, "install-coordinator", JOB, *owner], ADMIN_SID, 1, HELPER_BYTES),
            process(WORKER, COORDINATOR, WORKER_BIRTH, HELPER, [HELPER, "install-user", JOB, *owner], SID, 0, HELPER_BYTES,
                    {"pid": COORDINATOR, "openError": None, "alive": True, "creationFileTime": str(COORDINATOR_BIRTH), "image": HELPER})]


def gone(pid, parent, **fields):
    """A process the census found by name but could not describe: refused its open, or exited before it."""
    return {"pid": pid, "parentPid": parent, "openError": None, "creationFileTime": None, "alive": None, "image": None, "argv": None,
            "token": None, "imageSha256": None, "imageSizeBytes": None, "parent": None, **fields}


class CensusTests(unittest.TestCase):
    def test_a_described_process_is_live_and_any_other_keeps_only_its_ids(self):
        rows = job.census_rows([*census(), gone(960, 4, openError=5), gone(961, 4, creationFileTime="134368653065000030", alive=False)])
        self.assertEqual([True, True, True, True, False, False], [row["live"] for row in rows])
        self.assertEqual(SERVE_BIRTH, rows[0]["creationFileTime"])
        self.assertEqual([{"pid": 960, "parentPid": 4, "live": False}, {"pid": 961, "parentPid": 4, "live": False}], rows[4:])

    def test_anything_outside_the_closed_shape_is_refused(self):
        first = census()[0]
        cases = {"not-a-list": {}, "over-the-bound": [first] * (job.CENSUS_LIMIT + 1), "extra-field": [{**first, "x": 1}],
                 "pid": [{**first, "pid": 0}], "birth": [{**first, "creationFileTime": "0134"}], "argv": [{**first, "argv": ["a"] * 17}],
                 "image-digest": [{**first, "imageSha256": "A" * 64}], "token": [{**first, "token": {"sid": SID}}],
                 "parent": [{**first, "parent": {**first["parent"], "pid": 1}}], "alive": [{**first, "alive": "yes"}],
                 "open-error": [gone(960, 4, openError="denied")]}
        for name, value in cases.items():
            with self.subTest(name), self.assertRaisesRegex(ValueError, "collector_census_shape"):
                job.census_rows(value)


class OwnerProcessTests(unittest.TestCase):
    """before-install: the process the helper will name as its owner, while it lives."""
    SERVE = {"pid": SERVE, "creationFileTime": SERVE_BIRTH}

    def test_the_controller_is_the_relaunched_child_or_else_the_serve_itself(self):
        rows = job.census_rows(census())
        self.assertEqual({"pid": JVM, "creationFileTime": JVM_BIRTH, "relaunched": True}, job.owner_process(rows, self.SERVE, CLI, SID, SESSION))
        alone = [row for row in rows if row["pid"] != JVM]
        self.assertEqual({"pid": SERVE, "creationFileTime": SERVE_BIRTH, "relaunched": False},
                         job.owner_process(alone, self.SERVE, CLI, SID, SESSION))

    def test_another_serve_or_child_is_refused(self):
        cases = (("collector_owner_serve", lambda rows: rows.pop(0)),
                 ("collector_owner_serve", lambda rows: rows[0].update(creationFileTime=str(SERVE_BIRTH + 1))),
                 ("collector_owner_serve", lambda rows: rows[0].update(image=GUI)),
                 ("collector_owner_serve", lambda rows: rows[0]["token"].update(elevated=1)),
                 ("collector_owner_child", lambda rows: rows.append({**json.loads(json.dumps(rows[1])), "pid": 914})),
                 ("collector_owner_child", lambda rows: rows[1].update(creationFileTime=str(SERVE_BIRTH - 1))),
                 ("collector_owner_child", lambda rows: rows[1]["token"].update(sid=ADMIN_SID)),
                 ("collector_owner_child", lambda rows: rows[1]["token"].update(sessionId=SESSION + 1)))
        for reason, change in cases:
            with self.subTest(reason=reason, change=change):
                rows = census()
                change(rows)
                with self.assertRaisesRegex(ValueError, reason):
                    job.owner_process(job.census_rows(rows), self.SERVE, CLI, SID, SESSION)


class InstallActorTests(unittest.TestCase):
    """authorization: the job's elevated coordinator and its original-user worker, live, from one SYSTEM census."""

    def actors(self, rows):
        return job.install_actors(job.census_rows(rows), helper=HELPER_RECORD, job=JOB, owner=OWNER, administrator_sid=ADMIN_SID,
                                  sid=SID, session=SESSION)

    def test_the_jobs_coordinator_and_worker_are_found_with_their_tokens(self):
        actors, facts = self.actors(census())
        common = {"image": HELPER, "sha256": HELPER_RECORD["sha256"], "sessionId": SESSION}
        self.assertEqual({"coordinator": {"pid": COORDINATOR, "creationFileTime": COORDINATOR_BIRTH, "sid": ADMIN_SID, **common},
                          "worker": {"pid": WORKER, "creationFileTime": WORKER_BIRTH, "sid": SID, **common}}, actors)
        self.assertEqual((ADMIN_SID, 1, 2), tuple(facts["coordinator"][key] for key in ("sid", "elevated", "elevationType")))
        self.assertEqual((SID, 0, 1), tuple(facts["worker"][key] for key in ("sid", "elevated", "elevationType")))
        self.assertEqual((HELPER_RECORD["sha256"], OWNER), (facts["helperSha256"], facts["owner"]))
        self.assertTrue(facts["coordinator"]["argv0MatchesImage"] and facts["worker"]["argv0MatchesImage"])

    def test_parents_are_recorded_never_assumed(self):
        """AppInfo should give the coordinator the owner that asked for it, and the secondary logon service the worker
        its coordinator: the receipt keeps what the census saw, and nothing is refused on it."""
        _, facts = self.actors(census())
        self.assertEqual(({"pid": JVM, "alive": False, "matches": True}, {"pid": COORDINATOR, "alive": True, "matches": True}),
                         (facts["coordinator"]["parent"], facts["worker"]["parent"]))
        rows = census()
        rows[2]["parentPid"] = rows[2]["parent"]["pid"] = 640  # The service host, say.
        rows[3]["parent"]["creationFileTime"] = str(COORDINATOR_BIRTH + 9)  # A live process with the coordinator's id, not it.
        _, facts = self.actors(rows)
        self.assertEqual(({"pid": 640, "alive": False, "matches": False}, {"pid": COORDINATOR, "alive": True, "matches": False}),
                         (facts["coordinator"]["parent"], facts["worker"]["parent"]))

    def test_anything_else_is_refused_with_its_own_reason(self):
        def twin(rows):
            rows.append({**json.loads(json.dumps(rows[2])), "pid": 930})
        cases = (("collector_coordinator_count_0", lambda rows: rows[2].update(alive=False)),
                 ("collector_coordinator_count_2", twin),
                 ("collector_coordinator_identity", lambda rows: rows[2].update(imageSha256="0" * 64)),
                 ("collector_coordinator_identity", lambda rows: rows[2].update(imageSizeBytes=len(HELPER_BYTES) + 1)),
                 ("collector_coordinator_identity", lambda rows: rows[2].update(image=LOCAL + "\\Temp\\vpn-control-install-helper.exe")),
                 ("collector_coordinator_identity", lambda rows: rows[2]["argv"].__setitem__(4, str(JVM_BIRTH + 1))),
                 ("collector_coordinator_token", lambda rows: rows[2]["token"].update(elevated=0)),
                 ("collector_coordinator_token", lambda rows: rows[2]["token"].update(sid=SID)),
                 ("collector_worker_count_0", lambda rows: rows[3]["argv"].__setitem__(2, PRODUCT_OPERATION)),
                 ("collector_worker_identity", lambda rows: rows[3]["argv"].__setitem__(3, str(SERVE))),
                 ("collector_worker_token", lambda rows: rows[3]["token"].update(elevated=1)),
                 ("collector_worker_token", lambda rows: rows[3]["token"].update(sessionId=1)),
                 ("collector_worker_generation", lambda rows: rows[3].update(creationFileTime=str(COORDINATOR_BIRTH))))
        for reason, change in cases:
            with self.subTest(reason=reason, change=change):
                rows = census()
                change(rows)
                with self.assertRaisesRegex(ValueError, reason + "$"):
                    self.actors(rows)


class ReturnedActorTests(unittest.TestCase):
    """returned-cleanup: the owner, and GUI where the case kept one, exactly as the case recorded them."""
    FILES = {"vpn-control.exe": {"sha256": "6" * 64}, "vpn-control-cli.exe": {"sha256": "7" * 64}, "app/x.jar": {"sha256": "8" * 64}}
    NEED = {"jobId": JOB, "productOperationId": PRODUCT_OPERATION}

    def record(self, **actors):
        owner = {"pid": 950, "creationFileTime": 134368653065000090, "image": CLI, "sha256": "7" * 64, "sid": SID, "sessionId": SESSION}
        return {"actors": {"owner": owner, **actors}, "jobId": JOB, "operationId": PRODUCT_OPERATION}

    def returned(self, value):
        return job.returned_actors(value, need=self.NEED, installed=INSTALLED, target_files=self.FILES, sid=SID, session=SESSION)

    def test_the_cases_own_record_of_the_target_install(self):
        gui = {"pid": 951, "creationFileTime": 134368653065000091, "image": GUI, "sha256": "6" * 64, "sid": SID, "sessionId": SESSION}
        for value in (self.record(), self.record(gui=gui)):
            with self.subTest(actors=sorted(value["actors"])):
                self.assertEqual(value["actors"], self.returned(json.loads(json.dumps(value))))

    def test_another_job_actor_image_or_principal_is_refused(self):
        cases = (("collector_returned_actors", lambda value: value.update(jobId=PRODUCT_OPERATION)),
                 ("collector_returned_actors", lambda value: value["actors"].update(tray=value["actors"]["owner"])),
                 ("collector_returned_actors", lambda value: value["actors"].pop("owner")),
                 ("collector_returned_actor", lambda value: value["actors"]["owner"].update(sha256="6" * 64)),
                 ("collector_returned_actor", lambda value: value["actors"]["owner"].update(image=INSTALLED + "\\app\\x.jar", sha256="8" * 64)),
                 ("collector_returned_actor", lambda value: value["actors"]["owner"].update(image=LOCAL + "\\vpn-control-cli.exe")),
                 ("collector_returned_actor", lambda value: value["actors"]["owner"].update(sid=ADMIN_SID)),
                 ("collector_returned_actor", lambda value: value["actors"]["owner"].update(pid=0)))
        for reason, change in cases:
            with self.subTest(reason=reason, change=change):
                value = self.record()
                change(value)
                with self.assertRaisesRegex(ValueError, reason + "$"):
                    self.returned(value)


class PublisherJournalTests(unittest.TestCase):
    """The publisher's own SeBackupPrivilege open, as VpnScenarioObserver.BackupOpen journals it."""
    JOURNAL = {"privilege": "SeBackupPrivilege", "scope": "thread-impersonation", "access": 0x80020000, "share": 1, "flags": 0x02200000,
               "processStateBefore": 1, "enabledForOpen": True, "disabledAfterOpen": True, "reverted": True, "openError": 0,
               "processStateAfter": 1}

    def test_only_a_privilege_dropped_and_reverted_around_one_read_only_backup_open_is_taken(self):
        self.assertEqual(self.JOURNAL, job.backup_journal(dict(self.JOURNAL)))
        self.assertEqual(2, job.backup_journal(dict(self.JOURNAL, processStateBefore=2, processStateAfter=2))["processStateAfter"])
        for change in ({"disabledAfterOpen": False}, {"reverted": False}, {"enabledForOpen": False}, {"processStateAfter": 2},
                       {"processStateBefore": 0, "processStateAfter": 0}, {"openError": 5}, {"access": 0xC0000000}, {"share": 7},
                       {"flags": 0x02000000}, {"scope": "process"}, {"privilege": "SeRestorePrivilege"}, {"path": DISPOSITION}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "collector_backup_read"):
                job.backup_journal(dict(self.JOURNAL, **change))


class InstallHelperTests(unittest.TestCase):
    """The helper a grant's coordinator and worker must run: what the installed build's native-helpers.json declares."""
    PIN = {"path": HELPER, "sha256": HELPER_RECORD["sha256"], "nativeIdentity": {"sizeBytes": len(HELPER_BYTES)}}

    def manifest(self, **changes):
        helper = {"name": "vpn-control-install-helper.exe", "sha256": HELPER_RECORD["sha256"], "sizeBytes": len(HELPER_BYTES),
                  "operations": ["validate-only", "install-user", "install-coordinator"], "machine": "AMD64", "clrHeader": False,
                  "dependentLoadFlags": 2048, **changes}
        broker = dict(helper, name="vpn-control-vpn-broker.exe", operations=["authenticated-runtime-channel"])
        return json.dumps({"schemaVersion": 1, "artifacts": [helper, broker]}, indent=2).encode()

    def test_the_helper_is_the_one_the_installed_build_declares(self):
        raw = self.manifest()
        self.assertEqual(HELPER_RECORD, job.install_helper(raw, hashlib.sha256(raw).hexdigest(), self.PIN))
        with self.assertRaisesRegex(ValueError, "install_helper_manifest_bytes"):
            job.install_helper(raw, "0" * 64, self.PIN)
        for change in ({"sha256": "0" * 64}, {"sizeBytes": 1}, {"operations": ["validate-only"]}, {"machine": "ARM64"},
                       {"clrHeader": True}, {"dependentLoadFlags": 0}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "install_helper_manifest$"):
                raw = self.manifest(**change)
                job.install_helper(raw, hashlib.sha256(raw).hexdigest(), self.PIN)


class Timeline:
    """The guest's processes as a SYSTEM watch sees them: each census is one more tick. A process is live from its first
    tick up to (not including) its last; a held handle reads its own exit. Every open handle is accounted for."""

    def __init__(self, rows, *, clock_step=0.05):
        self.rows, self.tick, self.now, self.step = rows, 0, 0.0, clock_step
        self.open, self.opened, self.argv_reads = {}, [], []

    def live(self, row):
        return row["from"] <= self.tick and (row["until"] is None or self.tick < row["until"])

    def native(self):
        timeline = self

        class Pin:
            def __init__(self, row):
                self.row, self.handle = row, len(timeline.opened) + 1
                timeline.open[self.handle] = row["pid"]
                timeline.opened.append(row["pid"])

            def __enter__(self):
                return self

            def __exit__(self, *_):
                timeline.open.pop(self.handle, None)

            def times(self):
                gone = not timeline.live(self.row)
                return {"creationFileTime": self.row["birth"], "exitFileTime": self.row["birth"] + 500 if gone else 0,
                        "kernelTime100ns": 0, "userTime100ns": 0}

            def wait(self):
                return 258 if timeline.live(self.row) else 0

            def describe(self):
                return {"image": self.row["image"], **self.times(), "token": dict(self.row["token"]),
                        "sha256": self.row["sha256"], "sizeBytes": self.row["size"]}

        class Native:
            def processes(self):
                timeline.tick += 1
                return [{"pid": row["pid"], "parentPid": row["parent"], "name": row["image"].rsplit("\\", 1)[-1]}
                        for row in timeline.rows if timeline.live(row)]

            def open_process(self, pid, access):
                rows = [row for row in timeline.rows if row["pid"] == pid and timeline.live(row)]
                if not rows:
                    raise broker_observer.ProcessAbsent("absent")
                return Pin(rows[0])
        return Native

    def argv(self, native, process):
        self.argv_reads.append(process.row["pid"])
        return list(process.row["argv"])

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += self.step


def watched_rows(changes=None):
    """The serve and its JVM (the controller), then, after the approval, the job's coordinator and its worker, which the
    product's CANCELLED ends: the coordinator a few ticks after the worker reads it."""
    owner = [str(JVM), str(JVM_BIRTH)]
    token = {"sid": SID, "sessionId": SESSION, "elevated": 0, "elevationType": 1}
    rows = [{"pid": SERVE, "parent": 902, "birth": SERVE_BIRTH, "image": CLI, "argv": [CLI, "serve"], "token": token, "sha256": "c" * 64,
             "size": 3, "from": 0, "until": None},
            {"pid": JVM, "parent": SERVE, "birth": JVM_BIRTH, "image": CLI, "argv": [CLI, "serve"], "token": token, "sha256": "c" * 64,
             "size": 3, "from": 0, "until": None},
            {"pid": COORDINATOR, "parent": JVM, "birth": COORDINATOR_BIRTH, "image": HELPER, "argv": [HELPER, "install-coordinator", JOB, *owner],
             "token": {"sid": ADMIN_SID, "sessionId": SESSION, "elevated": 1, "elevationType": 2}, "sha256": HELPER_RECORD["sha256"],
             "size": len(HELPER_BYTES), "from": 4, "until": 9},
            {"pid": WORKER, "parent": COORDINATOR, "birth": WORKER_BIRTH, "image": HELPER, "argv": [HELPER, "install-user", JOB, *owner],
             "token": token, "sha256": HELPER_RECORD["sha256"], "size": len(HELPER_BYTES), "from": 5, "until": 8}]
    for pid, fields in (changes or {}).items():
        next(row for row in rows if row["pid"] == pid).update(fields)
    return rows


def watch_request(**changes):
    """before-install of install-cancelled as the job builds it: the serve, the controller it relaunched into, and the
    installed helper's image whose processes the watch follows."""
    def actor(pid, birth):
        return {"pid": pid, "creationFileTime": birth, "image": CLI, "sha256": "c" * 64, "sid": SID, "sessionId": SESSION}
    value = {"schemaVersion": 1, "stage": "before-install", "ordinaryTaskOperationId": OPERATION, "sourceSha": "1" * 40,
             "collectorSourceSha256": "2" * 64,
             "context": {"bootIdentifier": BOOT, "ordinarySid": SID, "ordinarySessionId": SESSION, "localAppData": LOCAL,
                         "workspace": WORKSPACE, "approvingAdminSid": ADMIN_SID},
             "jobId": None, "productOperationId": None, "actors": {"owner": actor(SERVE, SERVE_BIRTH), "controller": actor(JVM, JVM_BIRTH)},
             "fileInputs": {"cancelWatchHelper": dict(HELPER_RECORD)}, "faultBinding": {}, "programData": "C:\\ProgramData",
             "evidenceRoot": "C:\\ProgramData\\update-evidence-" + OPERATION, "ordinaryWorkerPid": 4242,
             "ordinaryWorkerBirth": "133000000000000002", "expectedHelperSha256": HELPER_RECORD["sha256"]}
    value.update(changes)
    return value


class CancelWatchTests(unittest.TestCase):
    """install-cancelled: the before-install collector publishes the owner it saw, then stays as a read-only SYSTEM watch of
    the installed helper's image and publishes cancel-actors once the cancelled job's coordinator and worker are gone.
    At 9a8db1e5 no stage could see them: they live only from the approval to the product's own CANCELLED."""

    def collect(self, rows, request=None, *, step=0.05):
        timeline = Timeline(rows, clock_step=step)
        observer = types.SimpleNamespace(WindowsNative=timeline.native(), same_path=broker_observer.same_path,
                                         require_identity=broker_observer.require_identity, observe_exit=broker_observer.observe_exit,
                                         ProcessAbsent=broker_observer.ProcessAbsent)
        request = request or watch_request()
        guards = []
        owner = types.SimpleNamespace(native=types.SimpleNamespace(boot_identifier=lambda: BOOT, token=lambda: {"sid": SYSTEM, "elevation": 1}),
                                      by_path={str(Path(native_collector.__file__)).casefold(): types.SimpleNamespace(
                                          record={"sha256": request["collectorSourceSha256"]})},
                                      guard=lambda: guards.append(timeline.tick), event=lambda kind, value: None)
        published = []

        def publish(collection_owner, receipts, root, stage, value):
            raw = update_receipts.encoded(value)
            published.append((stage, json.loads(raw)))
            return {"path": root + "\\" + stage + ".json", "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                    "createOnly": True, "readOnlyProductObservation": True}
        # The watch's clock, pause and argv reader are its own keywords; at 9a8db1e5 there is no watch to give them to, and
        # collect_and_publish publishes before-install alone.
        watch = getattr(native_collector, "watch_cancelled_installer", None)
        seam = {} if watch is None else {"watch": functools.partial(watch, clock=timeline.monotonic, sleep=timeline.sleep,
                                                                    read_argv=timeline.argv)}
        with mock.patch.object(native_collector, "publish_machine_record", publish):
            result = native_collector.collect_and_publish(request, owner, update_receipts, observer, **seam)
        return result, published, timeline, guards

    def test_the_watch_publishes_both_actors_seen_live_and_gone_after_its_before_install_record(self):
        result, published, timeline, guards = self.collect(watched_rows())
        self.assertEqual(["before-install", "cancel-actors"], [stage for stage, _ in published], "before-install first, then the watch")
        before, watched = (value for _, value in published)
        self.assertEqual((SERVE, JVM), (before["observations"]["ordinaryOwner"]["pid"], before["observations"]["controller"]["pid"]))
        self.assertEqual((JOB, None, "cancel-actors"), (watched["jobId"], watched["productOperationId"], watched["stage"]))
        observed = watched["observations"]
        self.assertEqual((True, True, False, JOB, [], 0), (observed["armedBeforeActors"], observed["complete"], observed["timedOut"],
                                                          observed["jobId"], observed["others"], observed["missed"]))
        actors = {row["role"]: row for row in observed["actors"]}
        self.assertEqual({"coordinator": (COORDINATOR, COORDINATOR_BIRTH, ADMIN_SID, 1, JVM), "worker": (WORKER, WORKER_BIRTH, SID, 0, COORDINATOR)},
                         {role: (row["pid"], row["creationFileTime"], row["sid"], row["elevated"], row["parentPid"]) for role, row in actors.items()})
        self.assertTrue(all(row["originalAbsent"] is True and row["reason"] == "same-handle-signaled" and row["exitFileTime"] > row["creationFileTime"]
                            and row["liveWhenSeen"] is True for row in actors.values()))
        self.assertEqual(set(job.CANCEL_ACTOR_FIELDS), set(actors["coordinator"]), "the record's rows are the job's closed shape")
        self.assertEqual({}, timeline.open, "every held handle is closed")
        self.assertEqual("cancel-actors", result["stage"])
        self.assertEqual(watched, result["record"], "the publication carries the record whole")
        self.assertEqual(hashlib.sha256(update_receipts.encoded(watched)).hexdigest(), result["collector"]["sha256"])
        self.assertEqual(timeline.tick, guards[-1], "the collector's own guard ran after the watch's last census")

    def test_the_job_takes_exactly_what_the_watch_publishes(self):
        result, _, _, _ = self.collect(watched_rows())
        actors, facts = job.cancelled_install_actors(result, operation=OPERATION, helper=HELPER_RECORD, owner=OWNER,
                                                     administrator_sid=ADMIN_SID, sid=SID, session=SESSION)
        self.assertEqual({"coordinator": (COORDINATOR, COORDINATOR_BIRTH, ADMIN_SID), "worker": (WORKER, WORKER_BIRTH, SID)},
                         {role: (actor["pid"], actor["creationFileTime"], actor["sid"]) for role, actor in actors.items()})
        self.assertEqual((JOB, True), (facts["jobId"], facts["watch"]["armedBeforeActors"]))
        changed = json.loads(json.dumps(result))
        changed["record"]["observations"]["missed"] = 7  # Bytes other than the ones published.
        with self.assertRaisesRegex(ValueError, "collector_cancel_watch_record"):
            job.cancelled_install_actors(changed, operation=OPERATION, helper=HELPER_RECORD, owner=OWNER, administrator_sid=ADMIN_SID,
                                         sid=SID, session=SESSION)

    def test_a_watch_that_sees_no_actor_ends_at_its_bound_with_nothing_complete(self):
        rows = watched_rows({COORDINATOR: {"from": 10 ** 9}, WORKER: {"from": 10 ** 9}})
        result, published, timeline, _ = self.collect(rows, step=60.0)
        observed = published[-1][1]["observations"]
        self.assertEqual((True, False, None, []), (observed["timedOut"], observed["complete"], observed["jobId"], observed["actors"]))
        self.assertGreaterEqual(observed["watchedSeconds"], native_collector.CANCEL_WATCH_SECONDS)
        with self.assertRaisesRegex(ValueError, "collector_cancel_watch_incomplete"):
            job.cancelled_install_actors(result, operation=OPERATION, helper=HELPER_RECORD, owner=OWNER, administrator_sid=ADMIN_SID,
                                         sid=SID, session=SESSION)

    def test_a_watch_armed_after_an_actor_says_so(self):
        rows = watched_rows({COORDINATOR: {"from": 0}})
        _, published, _, _ = self.collect(rows)
        self.assertFalse(published[-1][1]["observations"]["armedBeforeActors"])

    def test_other_helper_processes_are_recorded_and_an_elevated_one_is_held_to_its_exit(self):
        other = {"pid": 940, "parent": 4, "birth": 134368653065000025, "image": HELPER, "argv": [HELPER, "validate-only"],
                 "token": {"sid": SID, "sessionId": SESSION, "elevated": 0, "elevationType": 1}, "sha256": HELPER_RECORD["sha256"],
                 "size": len(HELPER_BYTES), "from": 3, "until": 4}
        stray = {**other, "pid": 941, "argv": [HELPER, "install-coordinator", JOB, "1", "2"], "from": 6, "until": 12,
                 "token": {"sid": ADMIN_SID, "sessionId": SESSION, "elevated": 1, "elevationType": 2}}
        _, published, timeline, _ = self.collect([*watched_rows(), other, stray])
        observed = published[-1][1]["observations"]
        self.assertEqual({940: (0, None), 941: (1, True)}, {row["pid"]: (row["elevated"], row["originalAbsent"]) for row in observed["others"]})
        self.assertEqual(["coordinator", "worker"], sorted(row["role"] for row in observed["actors"]), "a stray naming another owner is no actor")
        self.assertEqual({}, timeline.open)

    def test_any_other_before_install_publishes_once_and_never_watches(self):
        request = watch_request(fileInputs={}, actors={"owner": watch_request()["actors"]["owner"]}, expectedHelperSha256=None)
        result, published, timeline, _ = self.collect(watched_rows(), request)
        self.assertEqual(["before-install"], [stage for stage, _ in published])
        self.assertEqual("before-install", result["stage"])
        self.assertEqual([], timeline.argv_reads, "no helper process is ever read")


def observer_function():
    """Add-ObserverType exactly as the publisher template carries it."""
    template = (ROOT / "agent_tools" / "windows_scenario_publisher.ps1.template").read_text(encoding="utf-8")
    start = template.index("function Add-ObserverType {")
    return template[start:template.index("\nfunction Read-BackupPin", start)]


def start_census_image(test):
    """A process of an image nothing else on the machine runs: a copy of cmd.exe under a fresh name, which starts ping.
    The census matches processes by image leaf, so a shared image such as python.exe names every interpreter on the
    machine; on the hosted runner one of them is the test runner itself, whose argv is far over the census's bound of 16
    (run 43877068415: PUB_CENSUS_ARGV). Returns the image's path and its process; both go when the test ends."""
    import secrets
    import shutil
    directory = Path(tempfile.mkdtemp()).resolve()
    test.addCleanup(shutil.rmtree, directory, True)
    image = directory / ("vpn-census-" + secrets.token_hex(6) + ".exe")
    shutil.copyfile(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe", image)
    process = subprocess.Popen([str(image), "/d", "/c", "ping -n 30 127.0.0.1 >NUL"], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    test.addCleanup(lambda: (process.kill(), process.wait()))
    return image, process


def refuse_to_this_token(path):
    """Set the file's whole DACL, protected, rather than edit the one it was made with: SYSTEM alone is granted and this
    process's own user is denied. An edit can leave a grant that still admits the runner (icacls /inheritance:r drops only
    ACEs flagged inherited, and a temporary directory made with mode 0o700 grants Administrators): the hosted runner's
    elevated administrator read such a file (run 43877068415). Returns this token's user SID, the ACEs asked for and the
    ACEs Windows then holds, both rendered by Windows."""
    from ctypes import wintypes
    advapi, kernel = ctypes.WinDLL("advapi32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER
    for function, argtypes in (
            (advapi.OpenProcessToken, [wintypes.HANDLE, wintypes.DWORD, pointer(wintypes.HANDLE)]),
            (advapi.GetTokenInformation, [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, pointer(wintypes.DWORD)]),
            (advapi.ConvertSidToStringSidW, [ctypes.c_void_p, pointer(ctypes.c_void_p)]),
            (advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW,
             [wintypes.LPCWSTR, wintypes.DWORD, pointer(ctypes.c_void_p), pointer(wintypes.DWORD)]),
            (advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW,
             [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, pointer(ctypes.c_void_p), pointer(wintypes.DWORD)]),
            (advapi.GetSecurityDescriptorDacl, [ctypes.c_void_p, pointer(wintypes.BOOL), pointer(ctypes.c_void_p), pointer(wintypes.BOOL)]),
            (advapi.GetFileSecurityW, [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, pointer(wintypes.DWORD)]),
            (kernel.CloseHandle, [wintypes.HANDLE])):
        function.argtypes, function.restype = argtypes, wintypes.BOOL
    advapi.SetNamedSecurityInfoW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p,
                                             ctypes.c_void_p, ctypes.c_void_p]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], wintypes.HANDLE
    kernel.LocalFree.argtypes, kernel.LocalFree.restype = [ctypes.c_void_p], ctypes.c_void_p

    def check(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def text(allocated):
        try:
            return ctypes.wstring_at(allocated.value)
        finally:
            kernel.LocalFree(allocated)

    def aces(descriptor):
        rendered = ctypes.c_void_p()
        check(advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, ctypes.byref(rendered), None))
        dacl = text(rendered)
        return dacl[dacl.index("("):]  # The ACEs alone: the control flags before them carry no access.

    token, size = wintypes.HANDLE(), wintypes.DWORD()
    check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
    try:
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        user = ctypes.create_string_buffer(size.value)
        check(advapi.GetTokenInformation(token, 1, user, size, ctypes.byref(size)))
    finally:
        kernel.CloseHandle(token)
    rendered = ctypes.c_void_p()
    check(advapi.ConvertSidToStringSidW(ctypes.c_void_p.from_buffer(user).value, ctypes.byref(rendered)))  # TOKEN_USER.User.Sid
    sid = text(rendered)
    descriptor = ctypes.c_void_p()
    check(advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW("D:P(D;;FA;;;" + sid + ")(A;;FA;;;SY)", 1,
                                                                      ctypes.byref(descriptor), None))
    try:
        present, dacl, defaulted = wintypes.BOOL(), ctypes.c_void_p(), wintypes.BOOL()
        check(advapi.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
        # SE_FILE_OBJECT; DACL_SECURITY_INFORMATION with PROTECTED_DACL_SECURITY_INFORMATION: no ACE is inherited.
        error = advapi.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None)
        if error:
            raise ctypes.WinError(error)
        intended = aces(descriptor)
    finally:
        kernel.LocalFree(descriptor)
    advapi.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(size))
    held = ctypes.create_string_buffer(size.value)
    check(advapi.GetFileSecurityW(str(path), 4, held, size, ctypes.byref(size)))
    return sid, intended, aces(held)


@unittest.skipUnless(os.name == "nt", "Windows itself: a file only SYSTEM may read, opened by the runner's administrator token")
class WindowsReaderTests(unittest.TestCase):
    """Run where Windows runs the tests. The token is the runner's, not SYSTEM's: a token without SeBackupPrivilege
    (an unelevated runner) skips, with that reason, rather than pass."""

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp()).resolve()
        self.path = self.directory / ".install-not-started-test.json"
        self.raw = disposition()
        self.path.write_bytes(self.raw)
        icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
        self.addCleanup(lambda: (subprocess.run([str(icacls), str(self.path), "/reset"], capture_output=True, check=False),
                                 self.path.unlink(missing_ok=True), self.directory.rmdir()))
        sid, intended, held = refuse_to_this_token(self.path)
        self.assertEqual(intended, held, "the file holds exactly the DACL set on it")
        with self.assertRaises(PermissionError, msg="the file is SYSTEM's alone and refused to this token's user " + sid):
            self.path.read_bytes()

    def test_python_backup_open_reads_it_and_leaves_the_process_token_as_it_was(self):
        import msvcrt
        native = types.SimpleNamespace(k=ctypes.WinDLL("kernel32", use_last_error=True), a=ctypes.WinDLL("advapi32", use_last_error=True))
        try:
            handle, journal = native_collector.backup_open(native, str(self.path))
        except ValueError as error:
            if str(error) == "backup-privilege-absent":
                self.skipTest("this runner's token holds no SeBackupPrivilege")
            raise
        with open(msvcrt.open_osfhandle(handle, os.O_RDONLY), "rb") as stream:
            self.assertEqual(self.raw, stream.read())
        self.assertEqual((True, True, True, 0, journal["processStateBefore"]),
                         tuple(journal[key] for key in ("enabledForOpen", "disabledAfterOpen", "reverted", "openError", "processStateAfter")))
        with self.assertRaises(PermissionError, msg="an ordinary open is still refused"):
            self.path.read_bytes()

    def test_the_publisher_backup_open_and_census(self):
        image, process = start_census_image(self)
        script = observer_function() + "\n" + "\n".join((
            "$ErrorActionPreference='Stop'", "Add-ObserverType",
            "try{$o=[VpnScenarioObserver]::BackupOpen($env:VPN_TEST_TARGET)}catch{if($_.Exception.InnerException.Message -ceq "
            "'PUB_BACKUP_PRIVILEGE_ABSENT'){'{\"absent\":true}';exit 0};throw}",
            "$s=[IO.FileStream]::new($o.Handle,[IO.FileAccess]::Read,4096,$false);$b=New-Object byte[] 4096;$n=$s.Read($b,0,4096);$s.Dispose()",
            "$c=@([VpnScenarioObserver]::Census($env:VPN_TEST_IMAGE))",
            "[ordered]@{journal=$o.Journal;text=[Text.Encoding]::UTF8.GetString($b,0,$n);census=$c;"
            "sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}|ConvertTo-Json -Depth 8 -Compress"))
        powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                                 "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))"], input=script.encode("utf-8"),
                                capture_output=True, timeout=120, check=False,
                                env={**os.environ, "VPN_TEST_TARGET": str(self.path), "VPN_TEST_IMAGE": str(image)})
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        value = json.loads(result.stdout)
        if value.get("absent"):
            self.skipTest("this runner's token holds no SeBackupPrivilege")
        job.backup_journal(value["journal"])
        self.assertEqual(self.raw.decode(), value["text"])
        rows = job.census_rows(value["census"])
        self.assertEqual([process.pid], [row["pid"] for row in rows], "the census of the image's leaf names its one process")
        row = rows[0]
        self.assertEqual((True, value["sid"], image.name.lower(), [str(image), "/d", "/c", "ping -n 30 127.0.0.1 >NUL"]),
                         (row["live"], row["token"]["sid"], PureWindowsPath(row["image"]).name.lower(), row["argv"]))
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), row["imageSha256"])


class WindowsHarnessPremiseTests(unittest.TestCase):
    """Run everywhere, over the Windows-only tests' own source: the two premises the hosted runner showed false (run
    43877068415) stay out. A census over the interpreter's image names the test runner, whose argv is over the bound; a
    file's DACL edited with icacls kept a grant that let the elevated runner read the file meant to be SYSTEM's alone."""

    @staticmethod
    def methods():
        import ast
        for module, path in (("test_windows_tun_grant", ROOT / "agent_tools/tests/test_windows_tun_grant.py"),
                             ("test_windows_update_grant_collectors", Path(__file__).resolve())):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    for method in node.body:
                        if isinstance(method, ast.FunctionDef):
                            calls = {call.func.id for call in ast.walk(method) if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)}
                            names = {(name.value.id, name.attr) for name in ast.walk(method)
                                     if isinstance(name, ast.Attribute) and isinstance(name.value, ast.Name)}
                            yield module + "." + node.name + "." + method.name, calls, names, method

    def test_no_census_runs_over_a_shared_image(self):
        census = [(name, names) for name, calls, names, _ in self.methods() if "observer_function" in calls]
        self.assertEqual(3, len(census), [name for name, _ in census])
        for name, names in census:
            with self.subTest(test=name):
                self.assertNotIn(("sys", "executable"), names)

    def test_the_system_alone_file_is_set_whole_and_read_back(self):
        import ast
        setup = {name: method for name, _, _, method in self.methods()}["test_windows_update_grant_collectors.WindowsReaderTests.setUp"]
        statements = [ast.unparse(statement) for statement in setup.body]
        self.assertIn("sid, intended, held = refuse_to_this_token(self.path)", statements)
        read = next(at for at, statement in enumerate(statements) if "self.path.read_bytes()" in statement)
        self.assertLess(statements.index("self.assertEqual(intended, held, 'the file holds exactly the DACL set on it')"), read)


if __name__ == "__main__":
    unittest.main()
