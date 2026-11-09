"""The Windows public-update deny and grant tooling: the one request form the SYSTEM collector chain takes, the
backup-privilege reader of the product's owner-only not-started disposition, and the job's discovery of the installer
actors from a SYSTEM process census.

Offline, Win32 is a declared in-memory model of one SYSTEM collector thread's tokens and of a file whose DACL grants
SYSTEM nothing: no guest, process or file of Windows is touched. WindowsReaderTests alone runs on Windows itself
(skipped elsewhere): both readers, Python's backup_open and the publisher's VpnScenarioObserver, open a file only
SYSTEM may read, as the runner's own administrator token.
"""
from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import windows_scenario_host_job as job
from agent_tools.windows_public_updater import native_collector, update_receipts
from agent_tools.windows_system_collector import collector_contract as contract

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


def observer_function():
    """Add-ObserverType exactly as the publisher template carries it."""
    template = (ROOT / "agent_tools" / "windows_scenario_publisher.ps1.template").read_text(encoding="utf-8")
    start = template.index("function Add-ObserverType {")
    return template[start:template.index("\nfunction Read-BackupPin", start)]


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
        subprocess.run([str(icacls), str(self.path), "/inheritance:r", "/grant:r", "*S-1-5-18:F"], capture_output=True, check=True)
        with self.assertRaises(PermissionError, msg="the file is SYSTEM's alone"):
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
                                env={**os.environ, "VPN_TEST_TARGET": str(self.path), "VPN_TEST_IMAGE": sys.executable})
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        value = json.loads(result.stdout)
        if value.get("absent"):
            self.skipTest("this runner's token holds no SeBackupPrivilege")
        job.backup_journal(value["journal"])
        self.assertEqual(self.raw.decode(), value["text"])
        rows = job.census_rows(value["census"])
        mine = [row for row in rows if row["pid"] == os.getpid()]
        # A venv's python.exe is a launcher whose child runs the base image: the census names processes by image leaf.
        self.assertEqual(1, len(mine), "the census of this interpreter's image leaf finds this process")
        self.assertEqual((True, value["sid"], "python.exe"), (mine[0]["live"], mine[0]["token"]["sid"], Path(mine[0]["image"]).name.lower()))
        self.assertEqual(hashlib.sha256(Path(mine[0]["image"]).read_bytes()).hexdigest(), mine[0]["imageSha256"])


if __name__ == "__main__":
    unittest.main()
