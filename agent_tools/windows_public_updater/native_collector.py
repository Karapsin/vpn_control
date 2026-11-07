"""Fixed read-only Windows installer actor collector and protected publication.

The sole VM operator executes collect_and_publish once for an explicit stage,
inside an admitted source-bound SYSTEM observer. It does not launch, terminate,
elevate, install, cancel, delete, repair ACLs, select an arbitrary process, or query
Win32_Product. The only write is its own CreateNew machine-protected evidence.
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
            raw, identity = bounded_file(collection_owner, receipts, files["notStartedDisposition"], 4096)
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


def publish_machine_record(owner, receipts, root, stage, value):
    """Create only this operation's machine evidence directory and phase file."""
    require(stage in STAGES and PureWindowsPath(root).name == "update-evidence-" + value["ordinaryTaskOperationId"],
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


def collect_and_publish(request, collection_owner, receipts, observer):
    value = collect(request, collection_owner, receipts, observer)
    root = str(receipts.canonical_path(request["evidenceRoot"]))
    require(receipts.canonical_path(root).parent == receipts.canonical_path(request["programData"]),
            "machine-evidence-under-current-programdata")
    result = publish_machine_record(collection_owner, receipts, root, request["stage"], value)
    return {"collector": result, "ordinaryTaskOperationId": request["ordinaryTaskOperationId"],
            "jobId": request["jobId"], "stage": request["stage"], "noProductMutation": True}
