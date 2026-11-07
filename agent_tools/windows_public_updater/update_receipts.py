"""Private current Windows public-update observations and one app-lease transition.

No import performs IO. This is not product admission code. The caller must be the
already qualified ordinary Owner, with actual source/runtime/ancestry pins. The
only mutable admission role here is the exact installed-application tree; no
source, Python, package, workspace or unrelated directory lease is retired.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as W
import hashlib
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import time
import uuid


class Refused(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


def canonical_uuid(value):
    require(type(value) is str and str(uuid.UUID(value)) == value, "canonical-uuid")
    return value


def canonical_path(value):
    require(type(value) is str and "\0" not in value, "path-type")
    p = PureWindowsPath(value)
    require(re.fullmatch(r"[A-Za-z]:", p.drive) and p.root == "\\"
            and str(p) == value and all(x not in {".", ".."} and not x.endswith((".", " "))
                                      for x in p.parts[1:]), "canonical-absolute-path")
    return p


def within(value, root):
    p, r = canonical_path(value), canonical_path(root)
    return p == r or r in p.parents


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def preserve(owner, name, value):
    require(re.fullmatch(r"update-[a-z0-9-]+\.json", name), "private-evidence-name")
    raw = encoded(value)
    require(len(raw) <= 16 * 1024 * 1024, "private-evidence-bound")
    path = owner.root / name
    with path.open("xb", buffering=0) as stream:
        offset = 0
        while offset < len(raw):
            count = stream.write(raw[offset:])
            require(type(count) is int and count > 0, "private-evidence-write")
            offset += count
        os.fsync(stream.fileno())
    result = {"name": name, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    owner.event("update-evidence", result)
    return result


_PHASES = {x: x.upper() for x in ("preparing", "authorized", "installing", "succeeded", "failed", "cancelled")}
_PHASES.update(waitingforexit="WAITING_FOR_EXIT", waiting_for_exit="WAITING_FOR_EXIT")
_ORDER = {x: i for i, x in enumerate(("PREPARING", "AUTHORIZED", "WAITING_FOR_EXIT", "INSTALLING", "SUCCEEDED", "FAILED", "CANCELLED"))}
TERMINAL = frozenset(("SUCCEEDED", "FAILED", "CANCELLED"))
CODES = frozenset(("OK", "ACCEPTED", "INVALID_ARGUMENT", "NOT_FOUND", "AMBIGUOUS_LOCATION",
    "READ_ONLY_SOURCE", "BUSY", "CONFLICT", "UNSUPPORTED", "INTERACTION_REQUIRED", "PERMISSION_DENIED",
    "PERSISTENCE_FAILED", "RUNTIME_FAILED", "CANCELLED", "TIMEOUT", "OUTCOME_UNKNOWN", "UNAVAILABLE",
    "INCOMPATIBLE_PROTOCOL"))


def receipt(raw, expected_job):
    require(type(raw) is bytes and 0 < len(raw) <= 4096, "protected-receipt-bound")
    # Match product's complete record grammar; duplicate/additional fields cannot
    # acquire authority through json.loads' last-key-wins behavior.
    pattern = rb'\{"version":1,"jobId":"([a-f0-9-]{36})","sequence":(0|[1-9][0-9]{0,18}),"phase":"([A-Za-z_]+)","code":"([A-Z_]+)"\}'
    match = re.fullmatch(pattern, raw)
    require(match is not None, "protected-receipt-format")
    job, seq, phase, code = [v.decode("ascii") for v in match.groups()]
    canonical_uuid(job)
    require(job == expected_job and int(seq) <= 2**63 - 1, "protected-receipt-identity")
    phase = _PHASES.get(phase.lower())
    require(phase in _ORDER and code in CODES, "protected-receipt-phase-or-code")
    require((phase == "CANCELLED" and code == "CANCELLED")
            or (phase == "FAILED" and code not in {"OK", "ACCEPTED", "CANCELLED"})
            or (phase not in {"FAILED", "CANCELLED"} and code == "OK"), "protected-receipt-code")
    return {"version": 1, "jobId": job, "sequence": int(seq), "phase": phase, "code": code}


class ReceiptTracker:
    def __init__(self, job):
        self.job, self.previous = canonical_uuid(job), None

    def accept(self, raw):
        new = receipt(raw, self.job)
        old = self.previous
        if old is not None and new != old:
            require(old["phase"] not in TERMINAL and new["sequence"] > old["sequence"]
                    and (new["phase"] in TERMINAL or _ORDER[new["phase"]] > _ORDER[old["phase"]]),
                    "protected-receipt-regressed-or-terminal-changed")
        self.previous = new
        return new


def handoff(result, original_controller):
    require(result.returncode == 0 and result.stderr == "", "public-install-client-terminal")
    value = json.loads(result.stdout)
    require(value.get("schemaVersion") == 1 and value.get("ok") is True
            and value.get("code") == "ACCEPTED" and value.get("final") is False
            and value.get("controllerId") == original_controller
            and value.get("data", {}).get("handoffReady") is True, "exact-committed-public-handoff")
    canonical_uuid(value.get("operationId"))
    canonical_uuid(value["data"].get("jobId"))
    require(type(value.get("requestId")) is str and value["requestId"], "handoff-request-id")
    return value


def verify_recovery(accepted, terminal, recovered):
    require(terminal["phase"] in TERMINAL and terminal["jobId"] == accepted["data"]["jobId"],
            "exact-protected-terminal-required")
    require(recovered.get("schemaVersion") == 1 and recovered.get("final") is True
            and recovered.get("operationId") == accepted["operationId"]
            and recovered.get("controllerId") and recovered["controllerId"] != accepted["controllerId"],
            "new-owner-exact-operation-recovery")
    data = recovered.get("data", {})
    require(data.get("jobId") == terminal["jobId"]
            and data.get("originControllerId") == accepted["controllerId"]
            and data.get("originRequestId") == accepted["requestId"]
            and recovered.get("code") == terminal["code"], "recovered-install-correlation")
    return {"jobId": terminal["jobId"], "operationId": accepted["operationId"],
            "originControllerId": accepted["controllerId"], "newControllerId": recovered["controllerId"],
            "terminalCode": terminal["code"]}


_SID = {"SY": "S-1-5-18", "BA": "S-1-5-32-544", "BU": "S-1-5-32-545"}
_RIGHT = {"FA": 0x1f01ff, "FR": 0x120089, "FX": 0x1200a0,
          "GR": 0x80000000, "GX": 0x20000000, "RC": 0x20000,
          "SD": 0x10000, "WD": 0x40000, "WO": 0x80000, "GW": 0x40000000, "GA": 0x10000000}


def machine_security(security, directory):
    """Finite equivalent of the product machine-status trust boundary, fail closed.

    Ancestors are independently held by actual Owner directory pins. These newly
    opened root/job/status objects must have protected machine DACLs. No writable
    ordinary ACE, callback/object ACE or unrestricted DACL is accepted.
    """
    require(type(security) is dict and set(security) == {"ownerSid", "sddl"}
            and security["ownerSid"] in {"S-1-5-18", "S-1-5-32-544"}, "protected-machine-owner")
    sddl = security["sddl"]
    require(type(sddl) is str and "D:P" in sddl, "protected-machine-dacl")
    prefix, _, tail = sddl.partition("D:")
    require(re.fullmatch(r"O:(?:BA|SY|S-1-5-18|S-1-5-32-544)(?:G:[A-Za-z0-9-]+)?", prefix),
            "protected-machine-security-fields")
    flags, _, aces = tail.partition("(")
    require(flags in {"P", "PAI"} and aces, "protected-machine-dacl-flags")
    aces = "(" + aces
    matches = list(re.finditer(r"\(([^()]*)\)", aces))
    require(matches and "".join(m.group(0) for m in matches) == aces, "protected-machine-ace-grammar")
    for match in matches:
        fields = match.group(1).split(";")
        require(len(fields) == 6 and fields[0] in {"A", "D"} and not fields[3] and not fields[4],
                "protected-machine-ace-type")
        kind, flags, rights, _, _, sid = fields
        require(re.fullmatch(r"(?:(?:OI|CI|IO|ID|NP))*", flags) is not None, "protected-machine-ace-flags")
        require(directory or not flags, "protected-status-inheritance")
        if rights.startswith("0x"):
            require(re.fullmatch(r"0x[0-9a-fA-F]{1,8}", rights), "protected-machine-mask")
            mask = int(rights, 16)
        else:
            require(rights and len(rights) % 2 == 0 and
                    all(rights[i:i+2] in _RIGHT for i in range(0, len(rights), 2)), "protected-machine-rights")
            mask = 0
            for i in range(0, len(rights), 2):
                mask |= _RIGHT[rights[i:i+2]]
        sid = _SID.get(sid, sid)
        require(re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+)+", sid), "protected-machine-ace-sid")
        if kind == "A" and "IO" not in flags and sid not in {"S-1-5-18", "S-1-5-32-544"}:
            require(mask & ~0xA01200A9 == 0, "protected-machine-untrusted-writer")
    return True


class FileObservation:
    """One retained Windows file/directory handle, with lexical generation closure."""
    def __init__(self, owner, path, *, directory=False, replaceable=False):
        self.owner, self.path, self.directory = owner, str(canonical_path(path)), directory
        self.native = owner.native
        self.handle = self.native.k.CreateFileW(self.path, 0x20080 if directory else 0x80020000,
            1 | (4 if replaceable else 0), None, 3, 0x02200000, None)
        if self.handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        self.opening = self.describe()
        self._canonical()

    def _canonical(self):
        f = self.native.k.GetFinalPathNameByHandleW
        f.argtypes = (W.HANDLE, W.LPWSTR, W.DWORD, W.DWORD)
        f.restype = W.DWORD
        out = ctypes.create_unicode_buffer(32768)
        n = f(W.HANDLE(self.handle), out, len(out), 0)
        require(0 < n < len(out) and out.value.startswith("\\\\?\\")
                and ntpath.normcase(out.value[4:]) == ntpath.normcase(self.path), "held-canonical-file-link")

    def describe(self):
        return {"path": self.path, "nativeIdentity": self.native.identity(self.handle, self.directory),
                "security": self.native.security(self.handle)}

    def read(self, maximum):
        require(not self.directory, "cannot-read-directory")
        raw = bytearray()
        for block in self.native.read_blocks(self.handle):
            raw.extend(block)
            require(len(raw) <= maximum, "exact-read-byte-bound")
        require(self.describe() == self.opening, "held-read-generation-changed")
        self._canonical()
        return bytes(raw)

    def close(self):
        require(self.handle is not None and self.native.k.CloseHandle(W.HANDLE(self.handle)), "file-observation-close")
        self.handle = None


class ProtectedReceiptCollector:
    """Read one current job repeatedly; never create, cancel, clean or relaunch it."""
    def __init__(self, owner, program_data, job):
        self.owner, self.job, self.tracker, self.observations = owner, canonical_uuid(job), ReceiptTracker(job), 0
        root = str(canonical_path(program_data) / "vpn-control-install-jobs")
        # Existing general ancestors are pinned and admitted by the original
        # task, not inferred from their spelling or a new authored allowlist.
        have = {str(pin.path).casefold() for pin in owner.pins if pin.directory}
        require(all(str(p).casefold() in have for p in canonical_path(program_data).parents)
                and program_data.casefold() in have, "programdata-complete-ancestor-pins")
        self.directories = []
        try:
            for path in (root, str(canonical_path(root) / self.job)):
                item = FileObservation(owner, path, directory=True)
                self.directories.append(item)
                machine_security(item.opening["security"], True)
            self.path = str(canonical_path(root) / self.job / "status.json")
        except BaseException:
            for item in reversed(self.directories):
                item.close()
            raise

    def observe(self):
        self.owner.guard()
        value = FileObservation(self.owner, self.path, replaceable=True)
        try:
            machine_security(value.opening["security"], False)
            raw = value.read(4096)
            result = self.tracker.accept(raw)
            self.observations += 1
            require(self.observations <= 8192, "protected-observation-count")
            self.owner.event("update-protected-receipt", {"receipt": result,
                "nativeFile": value.opening, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                "readOnly": True, "replayAllowed": False})
        finally:
            value.close()
        for directory in self.directories:
            require(directory.describe() == directory.opening, "protected-directory-generation-changed")
            directory._canonical()
        return result

    def terminal(self):
        while True:
            current = self.observe()
            if current["phase"] in TERMINAL:
                return current
            time.sleep(0.5)

    def close_terminal(self):
        require(self.tracker.previous and self.tracker.previous["phase"] in TERMINAL,
                "no-close-of-uncertain-protected-job")
        for directory in reversed(self.directories):
            directory.close()
        self.directories.clear()


def observe_actor(observer, native, expected, *, elevated, sid, session):
    require(type(expected) is dict and set(expected) ==
            {"pid", "creationFileTime", "image", "sha256", "sid", "sessionId"}, "installer-actor-schema")
    require(expected["sid"] == sid and expected["sessionId"] == session, "installer-actor-role-binding")
    with native.open_process(expected["pid"], 0x101000) as process:
        actual = process.describe()
        observer.require_identity(actual, expected)
        require(process.wait() == 258 and actual["token"]["elevated"] == elevated
                and actual["token"]["sessionId"] == session, "installer-actor-live-token")
        return {"pid": expected["pid"], **actual, "readOnly": True}


def worker_ready(raw, job, ordinary_sid, helper_sha256):
    require(type(raw) is bytes and 0 < len(raw) <= 4096, "worker-ready-bound")
    def unique(pairs):
        output = {}
        for key, value in pairs:
            require(key not in output, "worker-ready-duplicate-field")
            output[key] = value
        return output
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {"version", "jobId", "pid", "creationFileTime", "principalSid", "helperSha256"}
            and value["version"] == 2 and value["jobId"] == canonical_uuid(job)
            and type(value["pid"]) is int and 0 < value["pid"] < 2**32
            and type(value["creationFileTime"]) is int and 0 < value["creationFileTime"] < 2**63
            and value["principalSid"] == ordinary_sid and value["helperSha256"] == helper_sha256,
            "original-user-worker-ready-identity")
    return value


class InstalledApplicationLease:
    """Retire only the admitted old app tree after a known committed handoff.

    This class deliberately has no public generic release/pin-management method.
    Actual target native IDs are observed after replacement and hash-checked
    against the complete immutable package-derived expected inventory before a
    single launcher is admitted or the original Owner can finish.
    """
    def __init__(self, owner, root, expected_base, expected_target):
        self.owner, self.root = owner, str(canonical_path(root))
        self.base, self.target = expected_base, expected_target
        self.retired, self.admitted = False, False
        require(not hasattr(owner, "update_application_lease"), "one-app-transition-per-owner")
        owner.update_application_lease = self
        trees = [t for t in owner.request["treePins"] if t.get("role") == "installed-application"]
        require(len(trees) == 1 and trees[0]["root"] == self.root
                and set(trees[0]["files"]) == set(expected_base), "one-exact-installed-app-role")
        self.tree = trees[0]
        # Retire only application payload. A Python/source/request/module lease
        # must never disappear merely because a future binder chose an overlap.
        forbidden = [t["root"] for t in owner.request["treePins"] if t is not self.tree]
        forbidden += [owner.request[k] for k in ("casesPath", "harnessPath", "operationRoot") if k in owner.request]
        runtime = owner.request.get("pythonRuntime", {})
        forbidden += [runtime[k] for k in ("root", "interpreterPath") if k in runtime]
        forbidden += list(getattr(owner, "update_retained_source_paths", ()))
        require(all(not within(x, self.root) and not within(self.root, x) for x in forbidden),
                "installed-app-must-be-disjoint-from-retained-roles")
        self.files = [p for p in owner.pins if not p.directory and within(str(p.path), self.root)]
        self.directories = [p for p in owner.pins if p.directory and within(str(p.path), self.root)]
        actual = {PureWindowsPath(str(p.path)).relative_to(canonical_path(self.root)).as_posix():
                  {"sizeBytes": p.record["nativeIdentity"]["sizeBytes"], "sha256": p.record["sha256"]}
                  for p in self.files}
        require(actual == expected_base and self.directories, "complete-base-app-pin-inventory")
        self.pin_type = type(self.files[0])

    def retire_after_committed_handoff(self, accepted, original_controller):
        require(not self.retired and not self.admitted and accepted.get("controllerId") == original_controller
                and accepted.get("code") == "ACCEPTED" and accepted.get("final") is False
                and accepted.get("data", {}).get("handoffReady") is True,
                "app-retirement-requires-exact-known-handoff")
        canonical_uuid(accepted["data"].get("jobId"))
        canonical_uuid(accepted.get("operationId"))
        owner = self.owner
        owner.guard()
        for pin in self.files:
            pin.digest()
        old = owner.request
        preserve(owner, "update-retired-app-before.json", {"handoff": accepted, "tree": self.tree,
            "filePins": [p.record for p in self.files], "directoryPins": [p.record for p in self.directories]})
        retiring = {id(p) for p in [*self.files, *self.directories]}
        # If any close is uncertain, keep all objects and the original request in
        # this original namespace. There is no exception path that silently edits
        # the guard set or attempts installation again.
        owner.update_retired_original_request = old
        try:
            closing = [*reversed(self.files), *reversed(self.directories)]
            handles = [int(pin.handle) for pin in closing]
            require(len(set(handles)) == len(handles) and all(
                int(other.handle) not in handles for other in owner.pins if id(other) not in retiring),
                "retired-handles-must-not-alias-retained-custody")
            close = owner.native.k.CloseHandle
            close.argtypes, close.restype = (W.HANDLE,), W.BOOL
            self.close_observations = []
            for pin in closing:
                handle = int(pin.handle)
                closed = bool(close(W.HANDLE(handle)))
                self.close_observations.append({"path": str(pin.path), "handle": str(handle), "closeSucceeded": closed})
                require(closed, "original-app-handle-close-failed")
                pin.handle = None
            preserve(owner, "update-retired-app-close.json", self.close_observations)
            owner.pins = [p for p in owner.pins if id(p) not in retiring]
            owner.by_path = {k: p for k, p in owner.by_path.items() if id(p) not in retiring}
            owner.request = {**old,
                "treePins": [t for t in old["treePins"] if t is not self.tree],
                "filePins": [p for p in old["filePins"] if not within(p["path"], self.root)],
                "directoryPins": [p for p in old["directoryPins"] if not within(p["path"], self.root)]}
            self.retired = True
            owner.guard()
            owner.event("update-old-app-lease-retired", {"jobId": accepted["data"]["jobId"],
                "operationId": accepted["operationId"], "fileCount": len(self.files),
                "directoryCount": len(self.directories), "sourcesAndPythonRetained": True,
                "installedTargetAdmitted": False})
        except BaseException as error:
            owner.park("update-app-lease-retirement-unknown", error)

    def admit_observed_target(self, terminal, *, expected_phase="SUCCEEDED"):
        require(self.retired and not self.admitted and terminal["phase"] == expected_phase,
                "target-admission-requires-exact-terminal")
        owner = self.owner
        expected = self.target if expected_phase == "SUCCEEDED" else self.base
        owner.guard()
        paths, directories, folded = {}, [], set()
        for directory, children, files in os.walk(Path(self.root), followlinks=False):
            directories.append(str(Path(directory)))
            for name in [*children, *files]:
                path = Path(directory) / name
                require(not path.lstat().st_file_attributes & 0x400, "installed-tree-reparse")
            for name in files:
                path = Path(directory) / name
                relative = PureWindowsPath(str(path)).relative_to(canonical_path(self.root)).as_posix()
                require(relative.casefold() not in folded, "installed-tree-case-alias")
                folded.add(relative.casefold())
                paths[relative] = str(path)
        require(set(paths) == set(expected), "installed-target-complete-membership")
        self.new_pins = []
        try:
            for directory in directories:
                observation = FileObservation(owner, directory, directory=True)
                try:
                    record = observation.opening
                    require(record["security"]["ownerSid"] in
                            {owner.request["context"]["ordinarySid"], "S-1-5-18", "S-1-5-32-544"},
                            "installed-target-directory-owner")
                    pin = self.pin_type(owner.native, record, directory=True)
                finally:
                    observation.close()
                self.new_pins.append(pin)
            for relative, path in paths.items():
                observation = FileObservation(owner, path)
                try:
                    digest, length = hashlib.sha256(), 0
                    for block in owner.native.read_blocks(observation.handle):
                        length += len(block)
                        digest.update(block)
                    require({"sizeBytes": length, "sha256": digest.hexdigest()} == expected[relative],
                            "installed-target-package-bytes")
                    require(observation.describe() == observation.opening, "installed-target-read-closing")
                    record = {**observation.opening, "sha256": digest.hexdigest()}
                    pin = self.pin_type(owner.native, record)
                finally:
                    observation.close()
                self.new_pins.append(pin)
            # Re-enumerate under the retained complete tree lease. Every expected
            # file is now non-write/delete-shared; no listed-file-only admission.
            actual = {str((Path(d) / n).relative_to(Path(self.root))).replace("\\", "/")
                      for d, _, fs in os.walk(Path(self.root), followlinks=False) for n in fs}
            require(actual == set(expected), "installed-target-membership-closing")
            tree = {"root": self.root, "role": "installed-application", "files": sorted(expected)}
            owner.pins.extend(self.new_pins)
            owner.by_path.update({str(p.path).casefold(): p for p in self.new_pins if not p.directory})
            owner.request = {**owner.request,
                "treePins": [*owner.request["treePins"], tree],
                "filePins": [*owner.request["filePins"], *[p.record for p in self.new_pins if not p.directory]],
                "directoryPins": [*owner.request["directoryPins"], *[p.record for p in self.new_pins if p.directory]]}
            owner.guard()
            for pin in self.new_pins:
                if not pin.directory:
                    pin.digest()
            self.admitted = True
            preserve(owner, "update-target-installed-admission.json", {"receipt": terminal, "tree": tree,
                "files": [p.record for p in self.new_pins if not p.directory],
                "directories": [p.record for p in self.new_pins if p.directory],
                "packageExpectedInventorySha256": hashlib.sha256(encoded(expected)).hexdigest()})
            return tree
        except BaseException as error:
            owner.park("update-target-installed-admission-unknown", error)


def installed_registration(expected, native):
    """Inspect only the exact current recipient registration derived from MSI tables."""
    require(type(expected) is dict and set(expected) == {"productCode", "principalSid", "installContext",
        "displayVersion", "installLocation", "packageCode"}
        and expected["installContext"] in {1, 2}
        and native.token()["sid"] == expected["principalSid"]
        and native.token()["elevation"] == 0, "actual-per-user-msi-registration-context")
    for key in ("productCode", "packageCode"):
        require(type(expected[key]) is str and re.fullmatch(r"\{[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\}", expected[key]),
                "admitted-msi-product-package-code")
    library = ctypes.WinDLL("msi.dll", use_last_error=True, winmode=0x800)
    query = library.MsiGetProductInfoExW
    query.argtypes = (W.LPCWSTR, W.LPCWSTR, W.DWORD, W.LPCWSTR, W.LPWSTR, ctypes.POINTER(W.DWORD))
    query.restype = W.UINT
    actual = {}
    for property_name in ("VersionString", "InstallLocation", "PackageCode", "State"):
        output, count = ctypes.create_unicode_buffer(32768), W.DWORD(32767)
        code = query(expected["productCode"], expected["principalSid"], expected["installContext"],
                     property_name, output, ctypes.byref(count))
        require(code == 0 and count.value < len(output) and len(output.value) == count.value,
                "actual-msi-product-property-" + property_name)
        actual[property_name] = output.value
    require(actual["VersionString"] == expected["displayVersion"] and actual["State"] == "5"
            and actual["PackageCode"].casefold() == expected["packageCode"].casefold()
            and ntpath.normcase(ntpath.normpath(actual["InstallLocation"])) == ntpath.normcase(expected["installLocation"]),
            "actual-installed-msi-registration")
    return {**expected, "api": "msi.dll:MsiGetProductInfoExW", "observed": actual, "readOnly": True}


def select_listener(table, port):
    """Parse the actual IPv4 OWNER_PID_LISTENER table, not an authored PID flag."""
    import socket
    require(type(table) is bytes and 4 <= len(table) <= 512 * 1024, "native-listener-table-bound")
    import struct
    count, = struct.unpack_from("<I", table)
    require(count <= 8192 and len(table) == 4 + count * 24, "native-listener-table-shape")
    matches = []
    for index in range(count):
        state, address, encoded_port, _, _, pid = struct.unpack_from("<6I", table, 4 + index * 24)
        if state == 2 and address == 0x0100007F and socket.ntohs(encoded_port & 0xffff) == port:
            require(0 < pid < 2**32, "native-listener-owner-pid")
            matches.append(pid)
    require(len(matches) == 1, "one-exact-loopback-listener-owner")
    return matches[0]


def listener_pid(port):
    require(type(port) is int and 1 <= port <= 65535, "native-endpoint-port")
    library = ctypes.WinDLL("iphlpapi.dll", use_last_error=True, winmode=0x800)
    query = library.GetExtendedTcpTable
    query.argtypes = (W.LPVOID, ctypes.POINTER(W.DWORD), W.BOOL, W.ULONG, ctypes.c_int, W.ULONG)
    query.restype = W.DWORD
    needed = W.DWORD()
    require(query(None, ctypes.byref(needed), False, 2, 3, 0) == 122
            and 4 <= needed.value <= 512 * 1024, "native-listener-table-size")
    data = ctypes.create_string_buffer(needed.value)
    require(query(data, ctypes.byref(needed), False, 2, 3, 0) == 0
            and 4 <= needed.value <= len(data), "native-listener-table-query")
    return select_listener(data.raw[:needed.value], port)


def endpoint_actor(owner, workspace, endpoint_name, controller, observer):
    """Join this workspace's current private endpoint to a native listener actor.

    The credential remains only in this original ordinary namespace. Returned
    records contain its digest/identity, never its token or request bytes.
    """
    require(endpoint_name in {"activation.port", "frontend.port"}, "finite-product-endpoint-name")
    path = str(canonical_path(str(workspace)) / endpoint_name)
    held = FileObservation(owner, path)
    try:
        endpoint_security = held.opening["security"]
        principal = owner.request["context"]["ordinarySid"]
        require(endpoint_security["ownerSid"] == principal, "original-user-private-endpoint-owner")
        sddl = endpoint_security["sddl"]
        require("D:P" in sddl, "private-endpoint-protected-dacl")
        entries = re.findall(r"\(([^()]*)\)", sddl)
        require(entries and all(len(x.split(";")) == 6 for x in entries), "private-endpoint-ace-shape")
        allow = [x.split(";") for x in entries if x.split(";")[0] == "A"]
        require(allow and all(x[5] == principal for x in allow)
                and all(x.split(";")[0] in {"A", "D"} for x in entries), "private-endpoint-owner-only-allow")
        raw = held.read(4096)
        data = json.loads(raw)
        require(type(data) is dict and data.get("schemaVersion") == 1
                and type(data.get("port")) is int and 1 <= data["port"] <= 65535
                and type(data.get("controllerId")) is str and data["controllerId"]
                and type(data.get("token")) is str and len(data["token"]) >= 40
                and (controller is None or data["controllerId"] == controller),
                "actual-current-workspace-private-endpoint")
        pid = listener_pid(data["port"])
        native = observer.WindowsNative()
        with native.open_process(pid, 0x101000) as process:
            actual = process.describe()
            token = actual["token"]
            require(process.wait() == 258 and token["sid"] == owner.request["context"]["ordinarySid"]
                    and token["sessionId"] == owner.request["context"]["ordinarySessionId"]
                    and token["elevated"] == 0, "endpoint-original-user-live-process")
            pin = owner.by_path.get(actual["image"].casefold())
            require(pin is not None and pin.record["sha256"] == actual["sha256"], "endpoint-current-installed-image")
            actor = {"pid": pid, "creationFileTime": actual["creationFileTime"], "image": actual["image"],
                "sha256": actual["sha256"], "sid": token["sid"], "sessionId": token["sessionId"]}
            closing = process.describe()
            require(listener_pid(data["port"]) == pid and process.wait() == 258
                    and all(closing.get(k) == actual.get(k) for k in
                            ("creationFileTime", "image", "sha256", "sizeBytes", "token"))
                    and held.read(4096) == raw, "endpoint-native-owner-closing")
        return {"workspace": str(workspace), "endpoint": endpoint_name, "controllerId": data["controllerId"],
            "endpointPort": data["port"], "endpointNativeFile": held.opening,
            "endpointSha256": hashlib.sha256(raw).hexdigest(), "actor": actor,
            "nativeApi": "iphlpapi.dll:GetExtendedTcpTable/OWNER_PID_LISTENER", "readOnly": True}
    finally:
        held.close()


def join_ready_handoff(original, current):
    require(original.get("controllerId") == current.get("controllerId")
            and original.get("operationId") == current.get("operationId")
            and original.get("code") == current.get("code") == "ACCEPTED"
            and original.get("final") is False and current.get("final") is False
            and original.get("data", {}).get("handoffReady") is False
            and current.get("data", {}).get("handoffReady") is True,
            "same-accepted-operation-readiness-join")
    canonical_uuid(current.get("operationId"))
    canonical_uuid(current["data"].get("jobId"))
    require(type(original.get("requestId")) is str and original["requestId"], "original-install-request-correlation")
    return {**current, "requestId": original["requestId"]}
