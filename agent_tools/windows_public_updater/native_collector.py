"""Fixed read-only Windows installer actor collector and protected publication.

The sole VM operator executes collect_and_publish once for an explicit stage,
inside an admitted source-bound SYSTEM observer. It does not launch, terminate,
elevate, install, cancel, delete, repair ACLs, select an arbitrary process, or query
Win32_Product. The only write is its own CreateNew machine-protected evidence.
Its only privilege use is SeBackupPrivilege, which SYSTEM holds disabled: enabled
on this thread's own impersonation token for the one backup-semantics read-only
open of the product's owner-only not-started disposition, then dropped and journaled.
The public updater and GUI/controller remain the original ordinary principal.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import time


def require(condition, code):
    if not condition:
        raise ValueError(code)


STAGES = frozenset(("before-install", "authorization", "terminal-actors", "returned-cleanup", "fault-ready"))
# The record a cancel watch publishes after its before-install record; no request ever names it as its own stage.
CANCEL_STAGE = "cancel-actors"
# The watch outlives the prompt the decision answers within 90 s and the coordinator's three-minute precommit deadline.
CANCEL_WATCH_SECONDS = 900
CANCEL_WATCH_POLL_SECONDS = 0.05
CANCEL_WATCH_GUARD_SECONDS = 2.0
# An actor seen, then gone, with no second role after this long is all there will be.
CANCEL_WATCH_SETTLE_SECONDS = 30.0
_INSTALL_ROLES = {"install-coordinator": "coordinator", "install-user": "worker"}


def actor(request, role, receipts, observer, native, *, elevated, sid):
    require(role in request["actors"], "actual-native-actor-input-pending-" + role)
    expected = request["actors"][role]
    return receipts.observe_actor(observer, native, expected, elevated=elevated, sid=sid,
                                  session=request["context"]["ordinarySessionId"])


def bounded_file(owner, receipts, record, maximum):
    require(type(record) is dict and set(record) == {"path", "sha256", "sizeBytes"}
            and type(record["sizeBytes"]) is int and 0 < record["sizeBytes"] <= maximum
            and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]), "exact-native-observation-file")
    lease = receipts.FileObservation(owner, record["path"])
    try:
        raw = lease.read(maximum)
        require(len(raw) == record["sizeBytes"] and hashlib.sha256(raw).hexdigest() == record["sha256"],
                "native-observation-file-changed")
        return raw, lease.opening
    finally:
        lease.close()


BACKUP_PRIVILEGE = "SeBackupPrivilege"
_READ_ACCESS, _READ_SHARE, _BACKUP_FLAGS = 0x80020000, 1, 0x02200000  # GENERIC_READ|READ_CONTROL; share read; backup, no reparse


class _Luid(ctypes.Structure):
    _fields_ = [("low", W.DWORD), ("high", W.LONG)]


class _Privileges(ctypes.Structure):
    _fields_ = [("count", W.DWORD), ("luid", _Luid), ("attributes", W.DWORD)]


def _api(library, name, result, arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, arguments
    return function


def _privilege_state(native, token, luid):
    """0 absent, 1 present and disabled, 2 enabled, in one token's own TokenPrivileges."""
    query = _api(native.a, "GetTokenInformation", W.BOOL, (W.HANDLE, ctypes.c_int, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD)))
    needed = W.DWORD()
    query(token, 3, None, 0, ctypes.byref(needed))
    require(4 <= needed.value <= 65536, "backup-privilege-query-bound")
    buffer = ctypes.create_string_buffer(needed.value)
    require(query(token, 3, buffer, len(buffer), ctypes.byref(needed)), "backup-privilege-query")
    count = int.from_bytes(buffer.raw[:4], "little")
    require(4 + 12 * count <= len(buffer), "backup-privilege-query-shape")
    for index in range(count):
        low, high, attributes = (int.from_bytes(buffer.raw[4 + 12 * index + at:8 + 12 * index + at], "little", signed=at == 4)
                                 for at in (0, 4, 8))
        if (low, high) == (luid.low, luid.high):
            return 2 if attributes & 2 else 1
    return 0


def backup_open(native, path):
    """Open one file its product grants to its owner alone, as SYSTEM, for reading.

    SeBackupPrivilege is enabled on this thread's own impersonation token for this one open with backup semantics and
    read access only, then disabled and reverted before any byte is read; the process token never changes. Every
    transition is returned for the journal. A failed revert is unknown, never a read.
    """
    k, a = native.k, native.a
    lookup = _api(a, "LookupPrivilegeValueW", W.BOOL, (W.LPCWSTR, W.LPCWSTR, ctypes.POINTER(_Luid)))
    impersonate = _api(a, "ImpersonateSelf", W.BOOL, (ctypes.c_int,))
    revert = _api(a, "RevertToSelf", W.BOOL, ())
    current_thread = _api(k, "GetCurrentThread", W.HANDLE, ())
    current_process = _api(k, "GetCurrentProcess", W.HANDLE, ())
    open_thread = _api(a, "OpenThreadToken", W.BOOL, (W.HANDLE, W.DWORD, W.BOOL, ctypes.POINTER(W.HANDLE)))
    open_process = _api(a, "OpenProcessToken", W.BOOL, (W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE)))
    adjust = _api(a, "AdjustTokenPrivileges", W.BOOL, (W.HANDLE, W.BOOL, ctypes.POINTER(_Privileges), W.DWORD, W.LPVOID, W.LPVOID))
    create = _api(k, "CreateFileW", W.HANDLE, (W.LPCWSTR, W.DWORD, W.DWORD, W.LPVOID, W.DWORD, W.DWORD, W.HANDLE))
    close = _api(k, "CloseHandle", W.BOOL, (W.HANDLE,))
    luid = _Luid()
    require(lookup(None, BACKUP_PRIVILEGE, ctypes.byref(luid)), "backup-privilege-lookup")

    def process_state():
        token = W.HANDLE()
        require(open_process(current_process(), 8, ctypes.byref(token)), "backup-process-token")
        try:
            return _privilege_state(native, token, luid)
        finally:
            close(token)
    before = process_state()
    require(before in (1, 2), "backup-privilege-absent")
    journal = {"privilege": BACKUP_PRIVILEGE, "scope": "thread-impersonation", "path": path, "access": _READ_ACCESS,
               "share": _READ_SHARE, "flags": _BACKUP_FLAGS, "processStateBefore": before, "enabledForOpen": False,
               "disabledAfterOpen": False, "reverted": False, "openError": None, "processStateAfter": None}
    handle = None
    require(impersonate(2), "backup-impersonate-self")
    try:
        token = W.HANDLE()
        require(open_thread(current_thread(), 0x28, True, ctypes.byref(token)), "backup-thread-token")
        try:
            ctypes.set_last_error(0)
            enable = _Privileges(1, luid, 2)
            journal["enabledForOpen"] = (bool(adjust(token, False, ctypes.byref(enable), 0, None, None))
                                         and ctypes.get_last_error() == 0 and _privilege_state(native, token, luid) == 2)
            if journal["enabledForOpen"]:
                ctypes.set_last_error(0)
                value = create(path, _READ_ACCESS, _READ_SHARE, None, 3, _BACKUP_FLAGS, None)
                if value in (None, ctypes.c_void_p(-1).value):
                    journal["openError"] = ctypes.get_last_error()
                else:
                    handle, journal["openError"] = value, 0
        finally:
            ctypes.set_last_error(0)
            disable = _Privileges(1, luid, 0)
            journal["disabledAfterOpen"] = (bool(adjust(token, False, ctypes.byref(disable), 0, None, None))
                                            and ctypes.get_last_error() == 0 and _privilege_state(native, token, luid) == 1)
            close(token)
    finally:
        journal["reverted"] = bool(revert())
    if not journal["reverted"] or not journal["disabledAfterOpen"]:
        # This thread may still carry the privilege: no byte of the file is read and the collection ends here.
        if handle is not None:
            close(handle)
        raise RuntimeError("backup-privilege-not-dropped")
    journal["processStateAfter"] = process_state()
    if handle is None or journal["processStateAfter"] != before or not journal["enabledForOpen"]:
        if handle is not None:
            close(handle)
        raise OSError(journal["openError"] or 0, "backup-open-refused")
    return handle, journal


def backup_bounded_file(owner, receipts, record, maximum):
    """One exact owner-only product file through backup_open: its bytes, held identity and the privilege journal."""
    require(type(record) is dict and set(record) == {"path", "sha256", "sizeBytes"}
            and type(record["sizeBytes"]) is int and 0 < record["sizeBytes"] <= maximum
            and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]), "exact-native-observation-file")
    path = str(receipts.canonical_path(record["path"]))
    native = owner.native
    handle, journal = backup_open(native, path)
    try:
        final = _api(native.k, "GetFinalPathNameByHandleW", W.DWORD, (W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD))
        text = ctypes.create_unicode_buffer(32768)
        count = final(handle, text, len(text), 0)
        require(0 < count < len(text) and text.value.startswith("\\\\?\\")
                and text.value[4:].casefold() == path.casefold(), "backup-held-canonical-file")
        opening = {"path": path, "nativeIdentity": native.identity(handle), "security": native.security(handle)}
        raw = bytearray()
        for block in native.read_blocks(handle):
            raw.extend(block)
            require(len(raw) <= maximum, "exact-read-byte-bound")
        require({"path": path, "nativeIdentity": native.identity(handle), "security": native.security(handle)} == opening,
                "held-read-generation-changed")
        require(len(raw) == record["sizeBytes"] and hashlib.sha256(raw).hexdigest() == record["sha256"],
                "native-observation-file-changed")
    finally:
        native.k.CloseHandle(handle)
    owner.event("native-collector-backup-read", {"backupRead": journal, "sizeBytes": len(raw),
                                                 "sha256": hashlib.sha256(raw).hexdigest(), "readOnly": True})
    return bytes(raw), opening, journal


def collect(request, collection_owner, receipts, observer):
    """No writes; returns actual fields for one named current observation stage.

    collection_owner supplies the current admitted SYSTEM Native, source pins,
    ProgramData ancestry pins and original source-closing guard. It is deliberately
    not the ordinary worker Owner, whose token must remain non-elevated.
    """
    required = {"schemaVersion", "stage", "ordinaryTaskOperationId", "sourceSha", "collectorSourceSha256",
        "context", "jobId", "productOperationId", "actors", "fileInputs", "faultBinding",
        "programData", "evidenceRoot", "ordinaryWorkerPid", "ordinaryWorkerBirth", "expectedHelperSha256"}
    require(type(request) is dict and set(request) == required and request["schemaVersion"] == 1
            and request["stage"] in STAGES, "finite-native-collector-request")
    receipts.canonical_uuid(request["ordinaryTaskOperationId"])
    require(request["jobId"] is None or receipts.canonical_uuid(request["jobId"]), "native-job-id")
    require(request["productOperationId"] is None or receipts.canonical_uuid(request["productOperationId"]),
            "native-product-operation-id")
    require(request["context"]["bootIdentifier"] == collection_owner.native.boot_identifier(), "native-collector-boot")
    token = collection_owner.native.token()
    require(token["sid"] == "S-1-5-18" and token["elevation"] == 1,
            "read-only-system-collector-context")
    require(str(Path(__file__)).casefold() in collection_owner.by_path
            and collection_owner.by_path[str(Path(__file__)).casefold()].record["sha256"] == request["collectorSourceSha256"],
            "actual-current-native-collector-source-pin")
    collection_owner.guard()
    native = observer.WindowsNative()
    stage = request["stage"]
    context = request["context"]
    if request["jobId"] is not None:
        input_job = receipts.canonical_path(context["localAppData"]) / "vpn-control-install-inputs" / request["jobId"]
        protected_job = receipts.canonical_path(request["programData"]) / "vpn-control-install-jobs" / request["jobId"]
        expected_leaves = {"workerReady": str(input_job / "worker-ready.json"),
            "workerResult": str(input_job / "worker-result.json"), "protectedReceipt": str(protected_job / "status.json")}
        for role, expected_path in expected_leaves.items():
            if role in request["fileInputs"]:
                require(request["fileInputs"][role]["path"] == expected_path, "exact-current-job-native-leaf-" + role)
        if "notStartedDisposition" in request["fileInputs"]:
            path = receipts.canonical_path(request["fileInputs"]["notStartedDisposition"]["path"])
            require(path.parent == receipts.canonical_path(context["workspace"])
                    and re.fullmatch(r"\.install-not-started-[a-f0-9]{64}\.json", path.name),
                    "current-workspace-not-started-disposition-leaf")
    sid = request["context"]["ordinarySid"]
    observations = {}
    if stage == "before-install":
        observations["ordinaryOwner"] = actor(request, "owner", receipts, observer, native, elevated=0, sid=sid)
        if "gui" in request["actors"]:
            observations["originalGui"] = actor(request, "gui", receipts, observer, native, elevated=0, sid=sid)
        if cancel_watch_binding(request) is not None:
            # The process the helper will name as its owner, live and unelevated as the ordinary user, before any prompt.
            observations["controller"] = actor(request, "controller", receipts, observer, native, elevated=0, sid=sid)
    elif stage == "authorization":
        require(re.fullmatch(r"[a-f0-9]{64}", request["expectedHelperSha256"])
                and request["actors"].get("worker", {}).get("sha256") == request["expectedHelperSha256"]
                and request["actors"].get("coordinator", {}).get("sha256") == request["expectedHelperSha256"]
                and request["actors"]["worker"]["image"].casefold() == request["actors"]["coordinator"]["image"].casefold(),
                "same-actually-admitted-packaged-native-helper")
        admin = request["context"]["approvingAdminSid"]
        require(admin != sid, "scoped-admin-must-not-be-original-ordinary-actor")
        observations["coordinator"] = actor(request, "coordinator", receipts, observer, native, elevated=1, sid=admin)
        observations["originalUserWorker"] = actor(request, "worker", receipts, observer, native, elevated=0, sid=sid)
        raw, identity = bounded_file(collection_owner, receipts, request["fileInputs"]["workerReady"], 4096)
        ready = receipts.worker_ready(raw, request["jobId"], sid, request["actors"]["worker"]["sha256"])
        require(ready["pid"] == request["actors"]["worker"]["pid"]
                and ready["creationFileTime"] == request["actors"]["worker"]["creationFileTime"],
                "worker-ready-to-actual-native-process-join")
        observations["workerReady"] = {"record": ready, "nativeFile": identity}
        observations["nativeInstallerApi"] = "msi.dll:MsiInstallProductW"
        observations["actorExpectations"] = {k: request["actors"][k] for k in ("coordinator", "worker")}
    elif stage == "terminal-actors":
        files = request["fileInputs"]
        if "protectedReceipt" in files:
            raw, identity = bounded_file(collection_owner, receipts, files["protectedReceipt"], 4096)
            receipts.machine_security(identity["security"], False)
            terminal = receipts.receipt(raw, request["jobId"])
            require(terminal["phase"] in receipts.TERMINAL, "native-terminal-protected-job")
            observations["protectedReceipt"] = terminal
            observations["receiptNativeFile"] = identity
        if "workerResult" in files:
            raw, identity = bounded_file(collection_owner, receipts, files["workerResult"], 4096)
            result = json.loads(raw)
            require(type(result) is dict and set(result) == {"version", "jobId", "exitCode"}
                    and result["version"] == 1 and result["jobId"] == request["jobId"]
                    and type(result["exitCode"]) is int and 0 <= result["exitCode"] < 2**32,
                    "actual-original-worker-native-msi-result")
            observations["workerResult"] = result
            observations["workerResultNativeFile"] = identity
        if "notStartedDisposition" in files:
            # The product writes it O:<owner>G:<owner>D:P(A;;FA;;;<owner>): SYSTEM opens it only through backup_open.
            raw, identity, backup = backup_bounded_file(collection_owner, receipts, files["notStartedDisposition"], 4096)
            observations["notStartedBackupRead"] = backup
            disposition = json.loads(raw)
            require(disposition.get("disposition") == "NOT_STARTED" and disposition.get("jobId") == request["jobId"]
                    and disposition.get("controllerId") == context["originControllerId"]
                    and disposition.get("requestId") == context["originRequestId"]
                    and disposition.get("operationId") == request["productOperationId"],
                    "exact-native-not-started-disposition")
            observations["notStartedDisposition"] = disposition
            observations["notStartedNativeFile"] = identity
            missing = str(receipts.canonical_path(request["programData"]) / "vpn-control-install-jobs" / request["jobId"])
            try:
                unexpected = receipts.FileObservation(collection_owner, missing, directory=True)
            except OSError as error:
                require(getattr(error, "winerror", None) in {2, 3}, "protected-absence-is-not-access-denial")
                observations["protectedJobAbsence"] = {"nativeError": error.winerror, "path": missing}
            else:
                unexpected.close()
                raise ValueError("protected-job-exists-despite-not-started-disposition")
        require("protectedReceipt" in observations or "notStartedDisposition" in observations
                or request["faultBinding"].get("kind") == "protected-storage-rejected", "actual-native-terminal-evidence-required")
        if "protectedReceipt" in observations:
            require(set(request["actors"]) == {"coordinator", "worker"}, "exact-original-installer-terminal-actors")
            while True:
                exited = observer.observe_exit(list(request["actors"].values()), native)
                require(all(x.get("originalAbsent") is not None for x in exited), "installer-actor-exit-observation-unknown")
                if all(x["originalAbsent"] is True for x in exited):
                    break
                collection_owner.guard()
                time.sleep(0.25)
            observations["actorExitObservations"] = exited
            observations["actorExpectations"] = request["actors"]
        elif request["actors"]:
            exited = observer.observe_exit(list(request["actors"].values()), native)
            require(all(x.get("originalAbsent") is True for x in exited), "denied-coordinator-original-closure-pending")
            observations["actorExitObservations"] = exited
        if request["faultBinding"].get("kind") == "protected-storage-rejected":
            observations["protectedStorageRefusal"] = _fault_observation(request, collection_owner, receipts, observer, native)
    elif stage == "returned-cleanup":
        require(set(request["actors"]) in ({"owner"}, {"owner", "gui"}), "exact-returned-cleanup-actors")
        exited = observer.observe_exit(list(request["actors"].values()), native)
        require(all(x.get("originalAbsent") is True for x in exited), "returned-actor-cleanup-still-pending")
        observations = {"ownerOriginalAbsent": True, "guiOriginalAbsent": "gui" in request["actors"],
                        "retainedNativeObservations": exited, "actorExpectations": request["actors"]}
    elif stage == "fault-ready":
        observations = _fault_observation(request, collection_owner, receipts, observer, native)
    collection_owner.guard()
    return {"schemaVersion": 1, "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "stage": stage,
        "sourceSha": request["sourceSha"], "collectorSourceSha256": request["collectorSourceSha256"],
        "bootIdentifier": request["context"]["bootIdentifier"], "jobId": request["jobId"],
        "productOperationId": request["productOperationId"], "observations": observations}


def _fault_observation(request, owner, receipts, observer, native):
    binding = request["faultBinding"]
    require(type(binding) is dict and binding.get("kind") in
            {"protected-storage-rejected", "native-install-failed", "participating-copy-lock"}, "finite-actual-fault-kind")
    actual = {"kind": binding["kind"], "binding": binding}
    if binding["kind"] == "participating-copy-lock":
        actual["participatingCopy"] = actor(request, "participatingCopy", receipts, observer, native,
            elevated=0, sid=request["context"]["ordinarySid"])
        require(request["actors"]["participatingCopy"]["image"] == binding["installedCliPath"],
                "participating-copy-actual-installed-launcher")
    elif binding["kind"] == "protected-storage-rejected":
        require(binding["path"] == str(receipts.canonical_path(request["programData"]) / "vpn-control-install-jobs"),
                "exact-owned-protected-storage-fault")
        value = receipts.FileObservation(owner, binding["path"], directory=True)
        try:
            require(value.opening["security"]["ownerSid"] == request["context"]["ordinarySid"],
                    "actual-ordinary-counterfeit-root-owner")
            rejected = False
            try:
                receipts.machine_security(value.opening["security"], True)
            except ValueError:
                rejected = True
            require(rejected, "counterfeit-root-must-actually-fail-product-machine-policy")
            actual["root"] = value.opening
            raw, identity = bounded_file(owner, receipts, binding["canary"], 4096)
            actual["canary"] = {"nativeFile": identity, "sha256": hashlib.sha256(raw).hexdigest()}
        finally:
            value.close()
    else:
        raw, identity = bounded_file(owner, receipts, binding["admittedFailingMsiMetadata"], 2 * 1024 * 1024)
        actual["failingMsiMetadata"] = {"nativeFile": identity, "sha256": hashlib.sha256(raw).hexdigest()}
    return actual


def cancel_watch_binding(request):
    """before-install of a cancelled install: the controller the helper will name and the installed helper's image.

    Present only in that request: the job asks for the watch by naming the helper image beside the controller.
    """
    helper = request["fileInputs"].get("cancelWatchHelper") if type(request["fileInputs"]) is dict else None
    if request["stage"] != "before-install" or helper is None:
        return None
    controller = request["actors"].get("controller")
    require(type(helper) is dict and set(helper) == {"path", "sha256", "sizeBytes"} and type(helper["path"]) is str
            and helper["sha256"] == request["expectedHelperSha256"] and re.fullmatch(r"[a-f0-9]{64}", helper["sha256"])
            and type(helper["sizeBytes"]) is int and helper["sizeBytes"] > 0
            and PureWindowsPath(helper["path"]).name.casefold() == "vpn-control-install-helper.exe"
            and type(controller) is dict and type(controller.get("pid")) is int and controller["pid"] > 0
            and type(controller.get("creationFileTime")) is int and controller["creationFileTime"] > 0, "cancel-watch-binding")
    return {"helper": helper, "controller": {"pid": controller["pid"], "creationFileTime": controller["creationFileTime"]}}


def command_line(native, process):
    """One process's command line through its own handle, split as Windows splits it (CommandLineToArgvW)."""
    query = _api(native.n, "NtQueryInformationProcess", W.LONG, (W.HANDLE, W.ULONG, W.LPVOID, W.ULONG, ctypes.POINTER(W.ULONG)))
    size = 65552
    buffer = ctypes.create_string_buffer(size)
    returned = W.ULONG()
    # ProcessCommandLineInformation: a UNICODE_STRING whose buffer follows it in the same output.
    require(query(process.handle, 60, buffer, size, ctypes.byref(returned)) == 0 and 0 < returned.value <= size,
            "cancel-watch-command-line")
    length = int.from_bytes(buffer.raw[:2], "little")
    address = ctypes.c_void_p.from_buffer(buffer, ctypes.sizeof(ctypes.c_void_p)).value
    require(length % 2 == 0 and 0 < length <= size and address, "cancel-watch-command-line-shape")
    split = _api(ctypes.WinDLL("shell32", use_last_error=True), "CommandLineToArgvW", ctypes.POINTER(W.LPWSTR),
                 (W.LPCWSTR, ctypes.POINTER(ctypes.c_int)))
    free = _api(native.k, "LocalFree", W.HLOCAL, (W.HLOCAL,))
    count = ctypes.c_int()
    argv = split(ctypes.wstring_at(address, length // 2), ctypes.byref(count))
    require(bool(argv) and 1 <= count.value <= 16, "cancel-watch-argv")
    try:
        return [argv[index] for index in range(count.value)]
    finally:
        free(ctypes.cast(argv, W.HLOCAL))


def _canonical_job(receipts, value):
    try:
        return receipts.canonical_uuid(value)
    except (ValueError, TypeError, AttributeError):
        return None


def watch_cancelled_installer(request, collection_owner, receipts, observer, binding, *, clock=time.monotonic, sleep=time.sleep,
                              read_argv=command_line):
    """Read only, as SYSTEM: every process of the installed helper's image from before the install is asked for until the
    cancelled job's two actors are gone, or the bound.

    A process naming the controller as its owner (the product's argv: role, job, owner pid, owner birth) is described once,
    live, through its own handle, which is then kept: its pid cannot be reused while it is held, and its exit is read from
    that same handle. Any other helper process is recorded with its role word, and kept too while it is elevated. Nothing
    is started, stopped, signalled or written; the caller publishes what this returns.
    """
    native = observer.WindowsNative()
    helper, controller = binding["helper"], binding["controller"]
    leaf = PureWindowsPath(helper["path"]).name.casefold()
    owner_argv = [str(controller["pid"]), str(controller["creationFileTime"])]
    started = guarded = clock()
    held, actors, others, missed = {}, [], [], 0
    armed, polls, last_exit, timed_out = None, 0, None, False
    try:
        while True:
            polls += 1
            now = clock()
            if now - guarded >= CANCEL_WATCH_GUARD_SECONDS:
                collection_owner.guard()
                guarded = now
            naming = 0
            for entry in native.processes():
                if entry["name"].casefold() != leaf or entry["pid"] in held:
                    continue
                if any(row["pid"] == entry["pid"] and row.get("held") is False for row in others):
                    continue
                try:
                    process = native.open_process(entry["pid"], 0x101000)
                except OSError:
                    missed += 1  # Gone before it could be opened: counted, never described.
                    continue
                try:
                    described = process.describe()
                    argv = read_argv(native, process)
                    live = process.wait() == 258
                except (OSError, ValueError):
                    process.__exit__(None, None, None)
                    missed += 1
                    continue
                token = described["token"]
                role = (_INSTALL_ROLES.get(argv[1]) if len(argv) == 5 and argv[3:5] == owner_argv
                        and observer.same_path(described["image"], helper["path"]) else None)
                row = {"pid": entry["pid"], "parentPid": entry["parentPid"], "creationFileTime": described["creationFileTime"],
                       "image": described["image"], "sha256": described["sha256"], "sizeBytes": described["sizeBytes"],
                       "sid": token["sid"], "sessionId": token["sessionId"], "elevated": token["elevated"],
                       "elevationType": token["elevationType"], "verb": argv[1] if len(argv) > 1 else None,
                       "liveWhenSeen": live, "seenAfterSeconds": round(clock() - started, 3)}
                if role is not None:
                    naming += 1
                    row.update(role=role, jobId=_canonical_job(receipts, argv[2]),
                               argv0MatchesImage=observer.same_path(argv[0], described["image"]))
                    actors.append(row)
                    held[entry["pid"]] = (process, row)
                elif token["elevated"] == 1:
                    others.append(row)
                    held[entry["pid"]] = (process, row)
                else:
                    row["held"] = False
                    others.append(row)
                    process.__exit__(None, None, None)
            if armed is None:
                armed = naming
            for pid, (process, row) in held.items():
                if "originalAbsent" not in row and process.wait() == 0:
                    row.update(originalAbsent=True, reason="same-handle-signaled", exitFileTime=process.times()["exitFileTime"])
                    last_exit = clock()
            exited = all(row.get("originalAbsent") is True for _, row in held.values())
            roles = {row["role"] for row in actors}
            now = clock()
            if actors and exited and ({"coordinator", "worker"} <= roles or now - last_exit >= CANCEL_WATCH_SETTLE_SECONDS):
                break
            if now - started >= CANCEL_WATCH_SECONDS:
                timed_out = True
                break
            sleep(CANCEL_WATCH_POLL_SECONDS)
        collection_owner.guard()
    finally:
        for process, _ in held.values():
            process.__exit__(None, None, None)
    for _, row in held.values():
        row.setdefault("originalAbsent", False)
        row.setdefault("reason", None)
        row.setdefault("exitFileTime", None)
        row.pop("held", None)
    for row in others:
        row.pop("held", None)
        row.setdefault("originalAbsent", None)
    jobs = {row["jobId"] for row in actors}
    complete = (not timed_out and sorted(row["role"] for row in actors) == ["coordinator", "worker"] and len(jobs) == 1
                and None not in jobs and all(row["originalAbsent"] is True for row in actors))
    return {"helper": helper, "controller": controller, "armedBeforeActors": armed == 0, "actors": actors, "others": others,
            "missed": missed, "jobId": next(iter(jobs)) if complete else None, "complete": complete, "timedOut": timed_out,
            "polls": polls, "watchedSeconds": round(clock() - started, 3)}


def publish_machine_record(owner, receipts, root, stage, value):
    """Create only this operation's machine evidence directory and phase file."""
    require((stage in STAGES or stage == CANCEL_STAGE) and PureWindowsPath(root).name == "update-evidence-" + value["ordinaryTaskOperationId"],
            "one-fixed-machine-evidence-destination")
    native = owner.native
    require(native.token()["sid"] == "S-1-5-18", "machine-evidence-system-writer")
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL)]
    convert = native.a.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes, convert.restype = (W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD)), W.BOOL
    descriptor = W.LPVOID()
    require(convert("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",
                    1, ctypes.byref(descriptor), None), "machine-directory-security-descriptor")
    create_dir = native.k.CreateDirectoryW
    create_dir.argtypes, create_dir.restype = (W.LPCWSTR, ctypes.POINTER(SecurityAttributes)), W.BOOL
    try:
        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        if not create_dir(root, ctypes.byref(attributes)):
            require(ctypes.get_last_error() == 183, "machine-evidence-directory-create")
    finally:
        native.k.LocalFree(descriptor)
    directory = receipts.FileObservation(owner, root, directory=True)
    try:
        receipts.machine_security(directory.opening["security"], True)
        descriptor = W.LPVOID()
        require(convert("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)",
                        1, ctypes.byref(descriptor), None), "machine-file-security-descriptor")
        try:
            attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
            path = str(PureWindowsPath(root) / (stage + ".json"))
            handle = native.k.CreateFileW(path, 0xC0020000, 0, ctypes.byref(attributes), 1, 0x02200000, None)
            require(handle != ctypes.c_void_p(-1).value, "machine-phase-evidence-create-only")
        finally:
            native.k.LocalFree(descriptor)
        try:
            raw = receipts.encoded(value)
            require(len(raw) <= 256 * 1024, "machine-phase-evidence-byte-bound")
            written = W.DWORD()
            write = native.k.WriteFile
            write.argtypes = (W.HANDLE, W.LPVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID)
            buffer = ctypes.create_string_buffer(raw)
            require(write(W.HANDLE(handle), buffer, len(raw), ctypes.byref(written), None)
                    and written.value == len(raw), "machine-phase-evidence-full-write")
            flush = native.k.FlushFileBuffers
            flush.argtypes, flush.restype = (W.HANDLE,), W.BOOL
            require(flush(W.HANDLE(handle)), "machine-phase-evidence-flush")
        finally:
            require(native.k.CloseHandle(W.HANDLE(handle)), "machine-phase-evidence-close")
        require(directory.describe() == directory.opening, "machine-phase-directory-closing")
        owner.guard()
        return {"path": path, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "createOnly": True, "readOnlyProductObservation": True}
    finally:
        directory.close()


def collect_and_publish(request, collection_owner, receipts, observer, *, watch=None):
    value = collect(request, collection_owner, receipts, observer)
    root = str(receipts.canonical_path(request["evidenceRoot"]))
    require(receipts.canonical_path(root).parent == receipts.canonical_path(request["programData"]),
            "machine-evidence-under-current-programdata")
    result = publish_machine_record(collection_owner, receipts, root, request["stage"], value)
    binding = cancel_watch_binding(request)
    if binding is None:
        return {"collector": result, "ordinaryTaskOperationId": request["ordinaryTaskOperationId"],
                "jobId": request["jobId"], "stage": request["stage"], "noProductMutation": True}
    # before-install is published, so the owner may ask for the install it cancels: from here this same process watches.
    observations = (watch or watch_cancelled_installer)(request, collection_owner, receipts, observer, binding)
    record = {**{key: value[key] for key in ("schemaVersion", "ordinaryTaskOperationId", "sourceSha", "collectorSourceSha256",
                                             "bootIdentifier")},
              "stage": CANCEL_STAGE, "jobId": observations["jobId"], "productOperationId": None, "observations": observations}
    watched = publish_machine_record(collection_owner, receipts, root, CANCEL_STAGE, record)
    # One publication for the worker's count: the watch's record, its full value, and the before-install one it followed.
    return {"collector": watched, "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "jobId": observations["jobId"],
            "stage": CANCEL_STAGE, "noProductMutation": True, "record": record,
            "first": {"collector": result, "stage": request["stage"]}}
