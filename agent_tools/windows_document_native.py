"""Windows-only exact-handle fixtures for document acceptance.

No action runs on import. Native is the admitted ordinary Owner's existing Win32
provider. Filesystem actions are restricted to one observed operation/workspace
and exact files, with no recursive removal, process search or process termination.
"""
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import time


def need(value, code):
    if not value:
        raise RuntimeError(code)


def lexical(value):
    p = Path(value)
    need(os.name == "nt" and p.is_absolute() and str(p) == str(p.resolve(strict=False))
         and ".." not in p.parts, "document-exact-windows-path")
    return p


class NativeOpenError(RuntimeError):
    def __init__(self, winerror):
        self.winerror = winerror
        super().__init__("document-native-file-open-refused")


class Held:
    def __init__(self, native, path, directory=False, write=False, share=1):
        self.native, self.path, self.directory = native, lexical(path), directory
        self.share = share
        self.handle, self.initial, self.security = None, None, None
        self.closed = False
        # Retain the exact constructor object before native open or inspection
        # can raise. The existing owner retains Native through its park route.
        if not hasattr(native, "document_retained_handles"):
            native.document_retained_handles = []
        native.document_retained_handles.append(self)
        access = 0x20080 if directory else 0x80020000 | (0x40000000 if write else 0)
        self.handle = native.k.CreateFileW(str(self.path), access, share, None, 3, 0x02200000, None)
        if self.handle == ctypes.c_void_p(-1).value:
            self.open_error = ctypes.get_last_error()  # Capture before any other native call.
            raise NativeOpenError(self.open_error)
        self.open_error = None
        self.initial = native.identity(self.handle, directory)
        self.security = native.security(self.handle)

    def current(self, stable_content=True):
        need(not self.closed and self.initial is not None and self.security is not None,
             "document-held-inspection-incomplete-or-closed")
        current = self.native.identity(self.handle, self.directory)
        stable = ("volumeSerial", "fileIndex", "attributes")
        need(all(current[k] == self.initial[k] for k in stable), "document-held-identity-changed")
        if stable_content:
            need(current == self.initial, "document-held-content-generation-changed")
        need(self.native.security(self.handle) == self.security, "document-held-security-changed")
        # This read-only namespace observation permits the product's already
        # retained READ/WRITE/DELETE access; the original custody handle retains
        # its own stronger sharing policy throughout.
        named = self.native.k.CreateFileW(str(self.path), 0x20080, 7, None, 3, 0x02200000, None)
        need(named != ctypes.c_void_p(-1).value, "document-lexical-file-open")
        try:
            need(self.native.identity(named, self.directory) == current
                 and self.native.security(named) == self.security, "document-lexical-identity-changed")
        finally:
            self.native.k.CloseHandle(named)
        return current

    def bytes(self, maximum=64 * 1024 * 1024, stable_content=True):
        self.current(stable_content)
        blocks, count = [], 0
        for part in self.native.read_blocks(self.handle):
            count += len(part)
            need(count <= maximum, "document-held-read-resource-bound")
            blocks.append(part)
        self.current(stable_content)
        return b"".join(blocks)

    def pin(self):
        value = self.bytes()
        return {"path": str(self.path), "nativeIdentity": self.current(), "security": self.security,
                "sha256": hashlib.sha256(value).hexdigest()}

    def write_exact(self, data):
        need(not self.directory and type(data) is bytes, "document-held-write-input")
        self.current()
        k = self.native.k
        k.WriteFile.argtypes = (W.HANDLE, W.LPCVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID)
        k.FlushFileBuffers.argtypes = (W.HANDLE,)
        need(k.SetFilePointerEx(self.handle, 0, None, 0), "document-held-write-seek")
        count = W.DWORD()
        need(k.WriteFile(self.handle, data, len(data), ctypes.byref(count), None)
             and count.value == len(data) and k.FlushFileBuffers(self.handle), "document-held-write")
        need(self.native.identity(self.handle)["sizeBytes"] == len(data), "document-held-write-length")
        self.current(False)

    def close(self):
        need(not self.closed, "document-handle-already-closed")
        need(self.native.k.CloseHandle(self.handle), "document-handle-close")
        self.closed = True


def admit_created_workspace(owner, workspace):
    """Pin the real post-creation workspace under the prelaunch owned root."""
    owner.guard()
    workspace = lexical(workspace)
    need(workspace == lexical(owner.request["workspace"]) and workspace.parent == lexical(owner.root),
         "document-postcreation-workspace-assigned-scope")
    root_pins = [pin for pin in owner.pins if getattr(pin, "directory", False)
                 and pin.path == lexical(owner.root)]
    need(len(root_pins) == 1, "document-operation-root-original-directory-pin")
    root_pins[0].current()
    held = Held(owner.native, workspace, directory=True, share=3)
    need(held.security["ownerSid"] == owner.request["context"]["ordinarySid"],
         "document-created-workspace-actual-owner")
    owner.document_workspace_handle = held
    owner.event("document-created-workspace-intake", {"path": str(workspace),
        "nativeIdentity": held.current(), "security": held.security,
        "prelaunchWorkspacePinInvented": False, "actualPostCreationObservation": True})
    return held


def create_sid_private_new(native, path, data, sid):
    """Native CREATE_NEW with explicit actual owner SID, not inherited rights."""
    path = lexical(path)
    need(type(data) is bytes and 0 < len(data) <= 4096 and re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)+", sid),
         "document-private-create-input")
    class SecurityAttributes(ctypes.Structure):
        _fields_ = (("length", W.DWORD), ("descriptor", W.LPVOID), ("inherit", W.BOOL))
    a, k = native.a, native.k
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        W.LPCWSTR, W.DWORD, ctypes.POINTER(W.LPVOID), ctypes.POINTER(W.DWORD))
    k.WriteFile.argtypes = (W.HANDLE, W.LPCVOID, W.DWORD, ctypes.POINTER(W.DWORD), W.LPVOID)
    k.FlushFileBuffers.argtypes = (W.HANDLE,)
    descriptor = W.LPVOID()
    need(a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        "O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")", 1, ctypes.byref(descriptor), None),
        "document-private-security-descriptor")
    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
    handle = None
    try:
        handle = k.CreateFileW(str(path), 0x40020080, 1, ctypes.byref(attributes), 1, 0x00200080, None)
        need(handle != ctypes.c_void_p(-1).value, "document-private-create-new")
        endpoint_private_acl(native, handle, sid)
        count = W.DWORD()
        need(k.WriteFile(handle, data, len(data), ctypes.byref(count), None) and count.value == len(data)
             and k.FlushFileBuffers(handle), "document-private-create-write")
        need(native.identity(handle)["sizeBytes"] == len(data), "document-private-create-size")
    finally:
        if handle is not None and handle != ctypes.c_void_p(-1).value:
            need(k.CloseHandle(handle), "document-private-create-close")
        k.LocalFree(descriptor)


def endpoint_private_acl(native, handle, sid):
    """Inspect actual DACL ACEs through Win32; no SDDL string authorization."""
    a = native.a
    a.GetAclInformation.argtypes = (W.LPVOID, W.LPVOID, W.DWORD, ctypes.c_int)
    a.GetAce.argtypes = (W.LPVOID, W.DWORD, ctypes.POINTER(W.LPVOID))
    owner, dacl, descriptor = W.LPVOID(), W.LPVOID(), W.LPVOID()
    code = a.GetSecurityInfo(handle, 1, 5, ctypes.byref(owner), None, ctypes.byref(dacl), None,
                             ctypes.byref(descriptor))
    need(code == 0 and owner.value and dacl.value and descriptor.value, "document-endpoint-dacl")
    try:
        need(native.sid(owner) == sid, "document-endpoint-actual-owner-sid")
        class Size(ctypes.Structure):
            _fields_ = (("count", W.DWORD), ("used", W.DWORD), ("free", W.DWORD))
        size = Size()
        need(a.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2)
             and 1 <= size.count <= 64, "document-endpoint-acl-size")
        rows, owner_read = [], False
        for index in range(size.count):
            ace = W.LPVOID()
            need(a.GetAce(dacl, index, ctypes.byref(ace)) and ace.value, "document-endpoint-ace")
            header = ctypes.string_at(ace, 8)
            kind, flags = header[0], header[1]
            length = int.from_bytes(header[2:4], "little")
            mask = int.from_bytes(header[4:8], "little")
            need(kind in (0, 1) and length >= 16, "document-endpoint-ace-layout")
            principal = native.sid(ctypes.c_void_p(ace.value + 8))
            need(kind != 0 or principal == sid or mask == 0, "document-endpoint-other-principal-grant")
            owner_read |= kind == 0 and principal == sid and bool(mask & 1)
            rows.append({"type": kind, "flags": flags, "mask": mask, "sid": principal})
        need(owner_read, "document-endpoint-owner-read-grant")
        return {"ownerSid": sid, "aces": rows, "ownerRead": True, "otherPrincipalAllow": False}
    finally:
        native.k.LocalFree(descriptor)


def admit_endpoint(owner, workspace, identity, observed_pin, client_module):
    owner.guard()
    workspace = lexical(workspace)
    path = workspace / "activation.port"
    need(observed_pin["path"] == str(path), "document-endpoint-assigned-path")
    held = Held(owner.native, path)
    need(held.pin() == {k: observed_pin[k] for k in ("path", "nativeIdentity", "security", "sha256")},
         "document-actual-endpoint-observation-changed")
    need(held.security["ownerSid"] == owner.request["context"]["ordinarySid"], "document-endpoint-owner-sid")
    descriptor = client_module.load(held.bytes(4096).decode("utf-8", "strict"))
    need(descriptor.get("schemaVersion") == 1 and descriptor.get("controllerId") == identity,
         "document-endpoint-owner-epoch")
    need(endpoint_private_acl(owner.native, held.handle, owner.request["context"]["ordinarySid"])
         == observed_pin["privateAcl"], "document-endpoint-native-private-acl-required")
    endpoint = {k: descriptor[k] for k in ("port", "controllerId", "token", "documentTransfers")}
    source_pins = [owner.by_path[str(Path(value).resolve()).casefold()]
                   for value in (client_module.__file__, __file__)]
    def guard():
        # Full runtime/tree custody closes at entry and scenario boundaries. Each
        # bounded chunk rechecks actual token/boot, both executing source pins,
        # and the exact held/named endpoint; do not rescan thousands of unrelated
        # runtime entries for each 64 KiB frame.
        owner.guard_context()
        owner.document_workspace_handle.current()
        for pin in source_pins: pin.current()
        held.current()
        need(hashlib.sha256(held.bytes(4096)).hexdigest() == observed_pin["sha256"], "document-endpoint-digest")
    client = client_module.Client(endpoint, guard, owner.event)
    owner.document_endpoint_handle = held
    return client


def observe_endpoint(owner, workspace, identity):
    """Actual native intake, including owner SID and every actual DACL ACE."""
    owner.guard()
    held = Held(owner.native, lexical(workspace) / "activation.port")
    pin = held.pin()
    descriptor = json.loads(held.bytes(4096).decode("utf-8", "strict"))
    need(descriptor["controllerId"] == identity and descriptor["documentTransfers"] is True,
         "document-current-endpoint-owner")
    pin["privateAcl"] = endpoint_private_acl(owner.native, held.handle,
                                            owner.request["context"]["ordinarySid"])
    held.close()
    owner.event("document-endpoint-intake", {k: pin[k] for k in ("path", "nativeIdentity", "security", "sha256")})
    return pin


def persistence_fault(owner, workspace, client, module, request_id, context, before_result, setting_value):
    """Block both actual persistence targets with retained no-delete handles.

    The primary is existing committed data. Only the absent recovery leaf may be
    created, then retained as exact empty evidence after a known terminal refusal.
    On any unknown result the shared Owner parks with these objects retained.
    """
    owner.guard()
    workspace = lexical(workspace)
    need(owner.document_workspace_handle.path == workspace, "document-owned-created-workspace-pin")
    owner.document_workspace_handle.current()
    recovery = workspace / "workspace-recovery.json"
    need(not recovery.exists(), "document-recovery-before-absence")
    primary = Held(owner.native, workspace / "workspace.json")
    before = primary.pin()
    with recovery.open("xb") as target:
        target.flush(); os.fsync(target.fileno())
    reserve = Held(owner.native, recovery)
    owner.document_persistence_fault = {"primary": primary, "recovery": reserve}
    try:
        request = module.request_document(client.owner, request_id, "settings.set",
            {"key": "validation.batch-size", "value": str(setting_value)}, before_result["configurationRevision"])
        result = module.load(client.command(request, context, original_request_id=request_id)["body"])
        need(result.get("code") == "PERSISTENCE_FAILED" and result.get("final") is True
             and result.get("configurationRevision") == before_result["configurationRevision"],
             "document-persistence-failure-result")
        need(primary.pin() == before and reserve.bytes() == b"", "document-persistence-beforeimage-changed")
        # Full state readback must remain the same owner/revision/config; the
        # public caller records that independently after this fixture releases.
        owner.event("document-persistence-blocked", {"requestId": request_id,
            "operationId": result.get("operationId"), "code": result["code"],
            "configurationRevision": result["configurationRevision"], "primarySha256": before["sha256"],
            "recoveryNativeIdentity": reserve.current(), "bothTargetsHeldNoDelete": True})
        reserve_pin = reserve.pin()
        reserve.close(); primary.close()
        owner.event("document-recovery-evidence-retained", {"pin": reserve_pin,
            "knownEmptyOwnedLeaf": True, "pathDeletionPerformed": False})
        return result
    except BaseException as error:
        owner.park("document-persistence-fault-unknown", error)


def spool_intake(owner, temp_parent, before_names, context, client):
    """Begin one upload and capture its unique new actual native payload.

    Called only in a dedicated controller temp parent declared in the owner
    launcher. This never scans another process's default TEMP or guesses a spool.
    """
    temp_parent = lexical(temp_parent)
    need(temp_parent in [lexical(x["path"]) for x in owner.request["directoryPins"]],
         "document-owned-temp-parent-pin")
    need(set(before_names) == {p.name for p in temp_parent.iterdir()}, "document-temp-before-membership")
    item = client.begin(context)
    after = {p.name for p in temp_parent.iterdir()}
    added = after - set(before_names)
    need(len(added) == 1 and set(before_names) <= after, "document-exact-one-created-spool")
    leaf = next(iter(added))
    need(leaf.startswith("vpn-control-transfer-") and str(__import__("uuid").UUID(leaf[21:])) == leaf[21:],
         "document-spool-leaf")
    # The product retains DELETE access to its directory for its own cleanup.
    # This observer must share that access rather than create a fixture conflict.
    root = Held(owner.native, temp_parent / leaf, directory=True, share=7)
    need({p.name for p in root.path.iterdir()} == {"payload"}, "document-spool-exact-membership")
    # This observer shares WRITE and DELETE. It cannot manufacture the later
    # writer-sharing refusal which the product itself may enforce.
    payload = Held(owner.native, root.path / "payload", share=7)
    need(payload.bytes() == b"" and payload.security["ownerSid"] ==
         owner.request["context"]["ordinarySid"], "document-spool-initial-private-owner")
    sid = owner.request["context"]["ordinarySid"]
    root_acl = endpoint_private_acl(owner.native, root.handle, sid)
    payload_acl = endpoint_private_acl(owner.native, payload.handle, sid)
    owner.document_spool_fault = {"root": root, "payload": payload, "context": context, "manifest": item}
    owner.event("document-spool-intake", {"root": root.current(), "payload": payload.pin(),
                "rootPrivateAcl": root_acl, "payloadPrivateAcl": payload_acl,
                "context": context, "manifest": item, "discovery": "unique-before-after-owned-temp"})
    return owner.document_spool_fault


def mutate_sealed_spool(owner, client, module, fixture, original_bytes, replacement_bytes, expected_revision):
    """Exact held-file adversary. Mutation is never submitted with a fresh ID.

    Caller supplies a harmless read-only serialized command, not a mutation. If
    the server accepts changed bytes, the observation fails and resources remain
    retained for causal evidence instead of being cleaned away.
    """
    need(len(original_bytes) == len(replacement_bytes) and original_bytes != replacement_bytes,
         "document-spool-same-length-change")
    need(type(expected_revision) is int and expected_revision >= 0, "document-spool-observed-revision")
    need(original_bytes.startswith(b"cli\tcontrol-snapshot\t") and
         replacement_bytes.startswith(b"cli\tcontrol-snapshot\t"), "document-spool-readonly-commands")
    context = fixture["context"]; item = fixture["manifest"]
    need(0 < len(original_bytes) <= module.CHUNK, "document-spool-single-chunk-fixture")
    client.action(context, {"action": "append", "id": item["id"], "offset": 0,
        "bytes": base64.b64encode(original_bytes).decode()})
    sealed = module.manifest(client.action(context, {"action": "seal", "id": item["id"],
        "byteCount": len(original_bytes), "sha256": hashlib.sha256(original_bytes).hexdigest()}))
    payload = fixture["payload"]
    payload.initial = payload.native.identity(payload.handle)
    need(payload.bytes() == original_bytes, "document-spool-sealed-original-bytes")
    original_pin = payload.pin()
    try:
        writer = Held(owner.native, payload.path, write=True, share=7)
    except NativeOpenError as denied:
        need(denied.winerror == 32, "document-spool-writer-not-proven-sharing-denial")
        need(payload.pin() == original_pin and payload.bytes() == original_bytes,
             "document-spool-denial-changed-original")
        response = client.exchange(module.reference(client.owner, context, sealed),
            module.CONTEXT + module.fields(client.owner, context, "snapshot", "command", ""))
        decoded = module.cli_response(client.download(response, context, "snapshot"))
        need(decoded["success"] and decoded["exitCode"] == 0, "document-spool-protected-original-command-failed")
        snapshot = module.load(decoded["body"])
        need(snapshot["controllerId"] == client.owner and snapshot["configurationRevision"] == expected_revision
             and snapshot["runtimeRunning"] is False, "document-spool-protected-original-state")
        owner.event("document-spool-write-open-protected", {"win32Error": denied.winerror,
            "original": original_pin, "sealedManifest": sealed, "writeCallPerformed": False,
            "observerSharesReadWriteDelete": True, "originalSnapshotReadbackSucceeded": True})
        return {"state": "write-open-protected", "manifest": sealed, "originalSha256": original_pin["sha256"]}
    fixture["writer"] = writer
    need(writer.pin() == original_pin, "document-spool-writer-original-file-binding")
    writer.write_exact(replacement_bytes)
    need(payload.bytes(stable_content=False) == replacement_bytes, "document-spool-replacement-not-written")
    owner.event("document-spool-mutated", {"original": original_pin,
        "originalBytesBase64": base64.b64encode(original_bytes).decode(),
        "replacementBytesBase64": base64.b64encode(replacement_bytes).decode(), "sealedManifest": sealed,
        "replacementSha256": hashlib.sha256(replacement_bytes).hexdigest(),
        "heldIdentity": payload.current(False), "sameByteCount": True})
    # The honest original manifest is retained. No forged digest is used here.
    client.negative(module.reference(client.owner, context, sealed),
        module.CONTEXT + module.fields(client.owner, context, "snapshot", "command", ""),
        label="mutated-sealed-spool")
    writer.current(False); writer.close()
    # Caller must release only after independently preserving original/replacement
    # evidence and checking same owner/revision; no cleanup hidden in this action.
    return {"manifest": sealed, "originalSha256": original_pin["sha256"],
            "replacementSha256": hashlib.sha256(replacement_bytes).hexdigest()}


def resource_capacity(owner, client, module, contexts):
    """Exercise the actual fixed transfer count, not disk exhaustion or a fake OOM."""
    need(len(contexts) == 33 and len(set(contexts)) == 33, "document-capacity-contexts")
    values = [client.begin(context) for context in contexts[:32]]
    client.negative(module.transfer(client.owner, contexts[32],
        {"action": "begin", "requestId": contexts[32]}), label="actual-transfer-capacity")
    need(all(value["byteCount"] == 0 for value in values), "document-capacity-before-state")
    for context in contexts[:32]: client.discard(context)
    owner.event("document-capacity-resource-failure", {"admitted": 32, "refused": 1,
                "domainMutations": 0, "allKnownTransfersDiscarded": True})


def principal_refusal(owner, endpoint_path, expected_different_sid):
    """Run this function UNDER the separately admitted different native token.

    No token is read, copied, supplied or spoofed. A denied credential-file open
    is the expected product security boundary, not an authenticated second user.
    The other principal's retained ordinary worker owns its own source/EOF proof.
    """
    current = owner.native.token()
    need(current["sid"] == expected_different_sid and current["sid"] !=
         owner.request["documentOriginalPrincipalSid"], "document-different-real-principal-required")
    path = lexical(endpoint_path)
    handle = owner.native.k.CreateFileW(str(path), 0x80020000, 1, None, 3, 0x02200000, None)
    if handle != ctypes.c_void_p(-1).value:
        owner.native.k.CloseHandle(handle)
        raise RuntimeError("document-other-principal-read-credential")
    error = ctypes.get_last_error()
    need(error == 5, "document-other-principal-not-access-denied")
    owner.event("document-principal-refusal", {"actualToken": current, "win32Error": error,
        "credentialRead": False, "socketOpened": False, "authenticatedCommandSent": False})
    return current


def principal_refusal_powershell(endpoint_path, original_sid, different_sid, session_id):
    """Render a scoped probe for the native operator's distinct admitted token.

    This can run through the existing ordinary/admin scheduled-task mechanism;
    QGA SYSTEM is not silently substituted for the specified account/session.
    The existing native operator still binds boot, executable, task and source.
    """
    sid = r"S-1-[0-9]+(?:-[0-9]+)+"
    need(type(original_sid) is str and type(different_sid) is str and
         re.fullmatch(sid, original_sid) and re.fullmatch(sid, different_sid)
         and original_sid != different_sid and type(session_id) is int and session_id >= 0,
         "document-principal-probe-actual-distinct-inputs")
    path = PureWindowsPath(endpoint_path)
    need(path.is_absolute() and path.name == "activation.port" and ".." not in path.parts,
         "document-principal-probe-exact-endpoint")
    literal = lambda text: "'" + str(text).replace("'", "''") + "'"
    return """$ErrorActionPreference='Stop'
$actual=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$session=(Get-Process -Id $PID).SessionId
if($actual -cne %s -or $actual -ceq %s -or $session -ne %d){throw 'DOCUMENT_DIFFERENT_PRINCIPAL_CONTEXT'}
$denied=$false;$opened=$false;$hresult=$null
try{$file=[IO.File]::Open(%s,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);$opened=$true;$file.Dispose()}
catch [UnauthorizedAccessException]{$hresult=$_.Exception.HResult;$denied=(($hresult -band 0xffff)-eq 5)}
if(-not $denied -or $opened){throw 'DOCUMENT_DIFFERENT_PRINCIPAL_CREDENTIAL_BOUNDARY'}
[ordered]@{state='observed';actualSid=$actual;actualSessionId=$session;accessDenied=$denied;credentialOpened=$opened;credentialBytesRead=0;socketOpened=$false;authenticatedCommandSent=$false;win32Error=5}|ConvertTo-Json -Compress
""" % (literal(different_sid), literal(original_sid), session_id, literal(path))


def private_export_no_overwrite(owner, workspace, identity, destination, harness):
    """Actual installed public export, native ACL, then unlocked no-overwrite."""
    destination = lexical(destination)
    need(destination.parent == lexical(owner.root) and not destination.exists(),
         "document-export-exact-new-owned-leaf")
    parent = Held(owner.native, destination.parent, directory=True, share=3)
    first = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
        "routing", "export", "--output", str(destination)))
    need(first["controllerId"] == identity and first["final"] is True, "document-export-owner-result")
    held = Held(owner.native, destination)
    before = held.pin()
    acl = endpoint_private_acl(owner.native, held.handle, owner.request["context"]["ordinarySid"])
    need(before["nativeIdentity"]["sizeBytes"] == first["data"]["bytes"], "document-export-byte-count")
    held.close()  # Do not mask an overwrite defect by locking the destination.
    refused = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
        "routing", "export", "--output", str(destination)), 1, "PERSISTENCE_FAILED")
    need(refused["controllerId"] == identity, "document-export-refusal-owner")
    check = Held(owner.native, destination)
    need(check.pin() == before and endpoint_private_acl(owner.native, check.handle,
         owner.request["context"]["ordinarySid"]) == acl, "document-existing-export-overwritten")
    check.close(); parent.current(); parent.close()
    owner.event("document-private-no-overwrite-export", {"destination": str(destination),
                "pin": before, "privateAcl": acl, "secondExit": 1, "destinationUnlockedDuringRetry": True})
    return before


def cache_bytes(owner, workspace, subscription_id, expected_cached_locations):
    """Read the actual committed Windows JSON cache, not a summary count.

    Expected canonical location strings must come from the source-pinned fixture
    producer; a caller must not copy the observed cache into expected values.
    """
    need(type(expected_cached_locations) is list and expected_cached_locations
         and all(type(item) is str for item in expected_cached_locations), "document-cache-expected-fixture")
    owner.guard()
    held = Held(owner.native, lexical(workspace) / "workspace.json")
    original = held.pin()
    document = json.loads(held.bytes().decode("utf-8", "strict"))
    subscriptions = document["persisted_state"]["subscriptions"]
    matches = [row for row in subscriptions if row["id"] == subscription_id]
    need(len(matches) == 1 and matches[0]["cached_locations"] == expected_cached_locations,
         "document-committed-cache-bytes")
    actual = matches[0]["cached_locations"]
    newline = "\n".join(actual).encode("utf-8", "strict")
    expected = "\n".join(expected_cached_locations).encode("utf-8", "strict")
    need(newline == expected and hashlib.sha256(newline).digest() == hashlib.sha256(expected).digest(),
         "document-cache-newline-digest")
    held.current(); held.close()
    value = {"subscriptionId": subscription_id, "cacheCount": len(actual), "newlineBytes": len(newline),
             "newlineSha256": hashlib.sha256(newline).hexdigest(), "workspace": original,
             "windowsStoreFormat": "workspace-json-array", "nativeProtobufStore": False}
    owner.event("document-cache-bytes", value)
    return value


def newline_import(owner, workspace, identity, source_pin, expected_profile_history, harness):
    """Exercise installed legacy newline import and actual Windows persistence."""
    owner.guard()
    source = owner.by_path[str(lexical(source_pin["path"])).casefold()]
    need(source.record == source_pin, "document-newline-source-pin")
    raw = source.digest(True, maximum=64 * 1024 * 1024)
    need(b"\n" in raw and raw.decode("utf-8", "strict").splitlines(), "document-newline-fixture")
    before = harness["envelope"](owner.invoke(workspace, "--json", "status"))
    result = harness["envelope"](owner.invoke(workspace, "--json", "--controller-id", identity,
        "--if-revision", str(before["configurationRevision"]), "locations", "import", "--input", source_pin["path"]))
    held = Held(owner.native, lexical(workspace) / "workspace.json")
    document = json.loads(held.bytes().decode("utf-8", "strict"))
    actual = document["persisted_state"]["profile_history"]
    need(actual == expected_profile_history, "document-newline-import-normalized-persistence")
    pin = held.pin(); held.close()
    owner.event("document-windows-newline-compatibility", {"sourceSha256": source_pin["sha256"],
        "normalizedProfileCount": len(actual), "workspace": pin,
        "configurationRevision": result["configurationRevision"],
        "windowsJsonPersistenceObserved": True, "nativeProtobufClaim": False})
    return result
