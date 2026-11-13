"""Windows-only exact-handle fixtures for document acceptance.

No action runs on import. Native is the admitted ordinary Owner's existing Win32
provider. Filesystem actions are restricted to one observed operation/workspace
and exact files, with no recursive removal, process search or process termination.
The evidence of a refused fixture step keeps to that: its holder census reads only
the PIDs the kernel names for one exact file, and its rename differential makes and
removes exact empty folders of its own, one of them in the ordinary user's own temp
folder.
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


def fixture_refused(fixture, step, error):
    """The known failure of a harness fixture step the OS refused before the product took part in it.

    An OSError or a refused native open becomes document-<fixture>-fixture-refused:<step>:<code>,
    a finite code the case module's closing counts as known; anything else is returned unchanged.
    """
    if not isinstance(error, (OSError, NativeOpenError)):
        return error
    winerror, number = getattr(error, "winerror", None), getattr(error, "errno", None)
    code = winerror if type(winerror) is int else "errno-%d" % number if type(number) is int else "none"
    return RuntimeError("document-%s-fixture-refused:%s:%s" % (fixture, step, code))


def release_refused(owner, held, error, fixture, step, subject=None):
    """Close the fixture's own handles that opened, then raise its known failure, or park if one cannot close.

    The evidence of an access-denied or sharing refusal of subject is journaled first, while the
    fixture's handles are still as the refusal found them.
    """
    refusal_evidence(owner, fixture, step, error, subject)
    try:
        for value in held:
            if value is not None and not value.closed:
                value.close()
    except BaseException as closing:
        owner.park("document-" + fixture + "-fixture-closing-unknown", closing)
    known = fixture_refused(fixture, step, error)
    if known is error:
        raise error
    raise known from error


# ---- Evidence of a refused fixture step: who holds it, and where a rename by path works ---------

# Access denied and sharing violation: the two refusals another open handle can cause.
HELD_WIN32 = (5, 32)
CENSUS_PIDS, CENSUS_HOLDERS, CENSUS_HANDLES = 4096, 64, 32
# The responsive row's own work fixture child (windows_document_responsive_cases.FIXTURE_LABEL).
WORK_FIXTURE_LABEL = "owned-document-work-fixture"
# windows_lifecycle_runtime_stages.OwnedData opens a folder for attributes with read and write sharing, and a file
# for reading with read sharing only.
DATA_LEASE_MODES = {True: (0x20080, 3), False: (0x80020000, 1)}


def os_codes(error):
    winerror, number = getattr(error, "winerror", None), getattr(error, "errno", None)
    return winerror if type(winerror) is int else None, number if type(number) is int else None


def process_ids(raw):
    """The PIDs of a FILE_PROCESS_IDS_USING_FILE_INFORMATION: a ULONG count, then pointer-sized IDs."""
    size = ctypes.sizeof(ctypes.c_void_p)
    count = int.from_bytes(raw[:4], "little")
    need(count <= (len(raw) - size) // size, "document-census-pid-count")
    return [int.from_bytes(raw[size * (index + 1):size * (index + 2)], "little") for index in range(count)]


class _ProcessName(ctypes.Structure):
    """SYSTEM_PROCESS_ID_INFORMATION: one PID in, its image name out into the caller's own buffer."""
    _fields_ = [("pid", ctypes.c_void_p), ("length", ctypes.c_ushort), ("maximum", ctypes.c_ushort),
                ("buffer", ctypes.c_void_p)]


class HolderNative:
    """The native reads of a holder census, each over one exact path or one PID the kernel named.

    NtQueryInformationFile(FileProcessIdsUsingFileInformation, class 47) names the PIDs that have one
    file open. Each named PID is then read by itself: its image leaf, parent PID and creation time
    where this ordinary token may open it (PROCESS_QUERY_LIMITED_INFORMATION), else its image leaf
    alone by NtQuerySystemInformation(SystemProcessIdInformation, class 88). No process list is
    walked, no command line is read, and every call writes only into a buffer made here.
    """

    def __init__(self, native):
        self.k, self.n = native.k, native.n
        self.k.OpenProcess.argtypes = (W.DWORD, W.BOOL, W.DWORD)
        self.k.OpenProcess.restype = W.HANDLE
        self.k.QueryFullProcessImageNameW.argtypes = (W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD))
        self.n.NtQueryInformationFile.argtypes = (W.HANDLE, W.LPVOID, W.LPVOID, W.ULONG, ctypes.c_int)
        self.n.NtQueryInformationFile.restype = ctypes.c_long
        self.n.NtQueryInformationProcess.argtypes = (W.HANDLE, ctypes.c_int, W.LPVOID, W.ULONG, W.LPVOID)
        self.n.NtQueryInformationProcess.restype = ctypes.c_long

    def holders(self, path):
        """("ok", PIDs) of the processes that have this exact path open; this read shares everything."""
        handle = self.k.CreateFileW(str(path), 0x80, 7, None, 3, 0x02200000, None)
        if handle == ctypes.c_void_p(-1).value:
            return "open-refused:%d" % ctypes.get_last_error(), []
        try:
            block = ctypes.create_string_buffer(16)
            buffer = ctypes.create_string_buffer(ctypes.sizeof(ctypes.c_void_p) * (CENSUS_PIDS + 1))
            status = self.n.NtQueryInformationFile(handle, block, buffer, len(buffer), 47)
            if status != 0:
                return "query-refused:0x%08x" % (status & 0xFFFFFFFF), []
            return "ok", process_ids(buffer.raw)
        finally:
            self.k.CloseHandle(handle)

    def process(self, pid):
        """One named PID: image leaf, parent PID and creation time, or the image leaf alone if it cannot be opened."""
        facts = {"image": None, "parentPid": None, "birth": None, "openError": None}
        text = ctypes.create_unicode_buffer(1024)
        handle = self.k.OpenProcess(0x1000, False, pid)
        if not handle:
            facts["openError"] = ctypes.get_last_error()
            named = _ProcessName(pid, 0, ctypes.sizeof(text) - ctypes.sizeof(ctypes.c_wchar), ctypes.addressof(text))
            if self.n.NtQuerySystemInformation(88, ctypes.pointer(named), ctypes.sizeof(named), None) == 0:
                facts["image"] = PureWindowsPath(text.value).name or None
            return facts
        try:
            if self.k.QueryFullProcessImageNameW(handle, 0, text, ctypes.byref(W.DWORD(1024))):
                facts["image"] = PureWindowsPath(text.value).name or None
            basic = ctypes.create_string_buffer(48)
            if self.n.NtQueryInformationProcess(handle, 0, basic, len(basic), None) == 0:
                facts["parentPid"] = int.from_bytes(basic.raw[40:48], "little")
            times = [W.FILETIME() for _ in range(4)]
            if self.k.GetProcessTimes(handle, *(ctypes.byref(value) for value in times)):
                facts["birth"] = str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime)
            return facts
        finally:
            self.k.CloseHandle(handle)


def known_processes(owner):
    """The PIDs this harness knows: this worker, its task parent and the children the owner started."""
    known = {os.getppid(): {"role": "task-owner", "child": None, "birth": None, "live": True},
             os.getpid(): {"role": "worker", "child": None, "birth": None, "live": True}}
    for child in getattr(owner, "children", ()):
        live = child.terminal is None
        if type(child.pid) is int and (child.pid not in known or live and known[child.pid]["child"] is not None):
            role = ("serve" if tuple(child.argv[-1:]) == ("serve",)
                    else "work-fixture" if getattr(child, "label", None) == WORK_FIXTURE_LABEL else "cli-child")
            known[child.pid] = {"role": role, "child": child.ordinal, "birth": child.birth, "live": live}
    return known


def holder_role(pid, facts, known):
    """A holder's role: a known PID of the same birth, the direct child of a live known child, or other."""
    entry = known.get(pid)
    if entry is not None and (entry["birth"] is None or facts["birth"] is None or entry["birth"] == facts["birth"]):
        return entry["role"], entry["child"]
    parent = known.get(facts["parentPid"])
    if parent is not None and parent["child"] is not None and parent["live"]:
        # The installed launcher restarts itself: the JVM that does the work is its own child.
        return parent["role"] + "-child", parent["child"]
    return "other", None


def harness_handles(owner):
    """This harness's own handles that are still open: its document observers, the owner's directory pins and the
    data leases of an owned fixture (its folder, its input and what it published)."""
    retained = getattr(owner.native, "document_retained_handles", [])
    opened = [held for held in retained if getattr(held, "open_error", True) is None and not held.closed]
    pins = [pin for pin in getattr(owner, "pins", ()) if getattr(pin, "directory", False)]
    leases = [lease for lease in getattr(owner, "fixture_data_leases", ()) if getattr(lease, "handle", None) is not None]
    return {"dataLeaseCount": len(leases),
            "dataLeases": [{"path": str(lease.path), "directory": bool(lease.directory),
                            "access": DATA_LEASE_MODES[bool(lease.directory)][0],
                            "share": DATA_LEASE_MODES[bool(lease.directory)][1]} for lease in leases[:CENSUS_HANDLES]],
            "retainedTotal": len(retained), "retainedOpen": len(opened),
            "retained": [{"path": str(held.path), "directory": held.directory, "access": getattr(held, "access", None),
                          "share": held.share} for held in opened[:CENSUS_HANDLES]],
            "directoryPinCount": len(pins),
            "directoryPins": [{"path": str(pin.path), "access": getattr(pin, "access", None),
                               "share": getattr(pin, "share", None)} for pin in pins[:CENSUS_HANDLES]]}


def holder_census(owner, fixture, step, moment, winerror, targets):
    """Journal who has each exact target open, and which handles this harness itself still holds.

    targets are (role, path) pairs. The record holds PIDs, image leaf names, roles and counts, and the
    paths, access and share mode of the harness's own handles: no command line and nothing else of
    another process. It is evidence only: it changes nothing, and whatever fails inside it is named in
    the record and never raised.
    """
    value = {"fixture": fixture, "step": step, "moment": moment, "winerror": winerror, "targets": [],
             "harnessHandles": None, "censusError": None}
    try:
        value["harnessHandles"] = harness_handles(owner)
        reader, known, read = HolderNative(owner.native), known_processes(owner), {}
        for role, path in targets:
            status, pids = reader.holders(path)
            holders = []
            for pid in pids[:CENSUS_HOLDERS]:
                if pid not in read:
                    read[pid] = reader.process(pid)
                facts = read[pid]
                name, child = holder_role(pid, facts, known)
                holders.append({"pid": pid, "image": facts["image"], "role": name, "child": child,
                                "parentPid": facts["parentPid"], "openError": facts["openError"]})
            value["targets"].append({"role": role, "leaf": Path(path).name, "status": status,
                                     "holderCount": len(pids), "holders": holders})
    except Exception as failure:
        value["censusError"] = type(failure).__name__
    owner.event("document-fixture-holder-census", value)
    return value


def _attempt(rows, name, action):
    try:
        result = action()
    except Exception as error:
        winerror, number = os_codes(error)
        rows.append({"step": name, "errorClass": type(error).__name__, "winerror": winerror, "errno": number})
        return False, None
    rows.append({"step": name, "errorClass": None, "winerror": None, "errno": None})
    return True, result


def rename_variant(owner, directory, leaf, held):
    """One fresh empty folder of the harness's own, renamed away and back by path and removed again.

    With held, the folder is first opened, inspected and closed exactly as the race's rename probe does.
    Every step is recorded; a folder that already has the name is left alone.
    """
    rows, original, moved = [], Path(directory) / leaf, Path(directory) / (leaf + "-moved")
    if _attempt(rows, "mkdir", original.mkdir)[0]:
        usable = True
        if held:
            usable, probe = _attempt(rows, "held-open", lambda: Held(owner.native, original, directory=True))
            if usable:
                _attempt(rows, "held-current", probe.current)
                usable = _attempt(rows, "held-close", probe.close)[0]
        if usable and _attempt(rows, "rename-away", lambda: original.rename(moved))[0]:
            _attempt(rows, "rename-back", lambda: moved.rename(original))
        _attempt(rows, "rmdir", lambda: (moved if moved.is_dir() and not original.is_dir() else original).rmdir())
    return {"held": held, "steps": rows}


def user_temp(owner):
    """The ordinary user's own temp folder as this worker inherited it, never inside the operation root."""
    root = Path(owner.root)
    for name in ("TEMP", "TMP"):
        value = os.environ.get(name)
        if value and Path(value).is_absolute() and Path(value).is_dir() and root != Path(value) \
                and root not in Path(value).parents:
            return Path(value)
    return None


def rename_differential(owner, fixture, step, token, refused):
    """Where this ordinary context can rename a folder by path: beside the refused one, in the operation root, in its own temp.

    In each place one fresh folder that no handle ever opened, and one opened, inspected and closed as
    the rename probe does, are renamed away and back. It tells the probe's own handle, the folder the new
    name lies in and the location apart. Every step is journaled and each folder made here is removed by
    its exact name. Nothing of the product is touched, nothing is retried and nothing is raised.
    """
    value = {"fixture": fixture, "step": step, "locations": [], "differentialError": None}
    try:
        def variants(directory):
            return [rename_variant(owner, directory, "document-%s-differential-%s" % (token, kind), kind == "held")
                    for kind in ("plain", "held")]
        beside, root = Path(refused).parent, Path(owner.root)
        value["locations"].append({"location": "sibling", "leaf": beside.name, "variants": variants(beside)})
        if beside != root:
            value["locations"].append({"location": "operation-root", "leaf": root.name, "variants": variants(root)})
        temp, rows, inside = user_temp(owner), [], []
        if temp is not None:
            container = temp / ("vpn-control-harness-%s-%s" % (owner.operation, token))
            if _attempt(rows, "mkdir", container.mkdir)[0]:
                inside = variants(container)
                _attempt(rows, "rmdir", container.rmdir)
        value["locations"].append({"location": "user-temp", "available": temp is not None, "container": rows,
                                   "variants": inside})
    except Exception as failure:
        value["differentialError"] = type(failure).__name__
    owner.event("document-fixture-rename-differential", value)
    return value


def rename_control(owner, fixture, token, directory):
    """A recorded control, never a gate: can a fresh direct child of this folder be renamed by path now.

    If the rename is refused as held, the census of the folder is journaled too: the new name would lie
    in it, and its holders decide. The control makes one empty folder of its own and removes it again;
    nothing is raised.
    """
    value = {"fixture": fixture, "token": token, "leaf": Path(directory).name, "steps": [], "controlError": None}
    refusal = None
    try:
        value["steps"] = rename_variant(owner, directory, "document-%s-control" % token, False)["steps"]
        refusal = next((row["winerror"] for row in value["steps"]
                        if row["step"].startswith("rename-") and row["winerror"] in HELD_WIN32), None)
    except Exception as failure:
        value["controlError"] = type(failure).__name__
    owner.event("document-fixture-rename-control", value)
    if refusal is not None:
        holder_census(owner, fixture, "rename-control", "control", refusal, [("parent", Path(directory))])
    return value


def refusal_evidence(owner, fixture, step, error, subject, token=None):
    """The evidence of one fixture step refused as held: the holder census and, with a token, the rename differential."""
    winerror = os_codes(error)[0]
    if subject is None or not isinstance(error, (OSError, NativeOpenError)) or winerror not in HELD_WIN32:
        return
    holder_census(owner, fixture, step, "refusal", winerror,
                  [("refused", Path(subject)), ("parent", Path(subject).parent)])
    if token is not None:
        rename_differential(owner, fixture, step, token, subject)


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
        # A directory observer holds attributes and READ_CONTROL only, so it takes no part in share checks.
        self.access = access = 0x20080 if directory else 0x80020000 | (0x40000000 if write else 0)
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
    # The fixture before the request is the harness's own: an OS refusal there releases what it
    # holds, so the product can persist at the closing's quit, and is a known failure.
    primary = reserve = None
    step, subject = "primary-hold", workspace / "workspace.json"
    try:
        primary = Held(owner.native, subject)
        before = primary.pin()
        step, subject = "recovery-create", recovery
        with recovery.open("xb") as target:
            target.flush(); os.fsync(target.fileno())
        step = "recovery-hold"
        reserve = Held(owner.native, recovery)
    except BaseException as error:
        release_refused(owner, (reserve, primary), error, "persistence", step, subject)
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
    try:
        parent = Held(owner.native, destination.parent, directory=True, share=3)
    except BaseException as error:
        release_refused(owner, (), error, "export", "parent-hold", destination.parent)
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
