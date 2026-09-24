"""A fixed, non-replayable QGA credential-validity probe for a Windows guest."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import sys
import tempfile
import uuid
import struct
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from native_fixture_qga import QgaObservationError, QgaObservationUnknown, QgaReadOnlyClient

try:  # Keep module import and static fixture tests portable to Windows.
    import fcntl
except ImportError:  # pragma: no cover - exercised by Windows package checks
    fcntl = None  # type: ignore[assignment]

OPERATION = "windows-credential-validity-v1"
PROGRAM = "powershell.exe"
MAX_CREDENTIAL_BYTES = 512
MAX_HELPER_BYTES = 128 * 1024
_JOURNAL_VERSION = 1
_CATEGORIES = frozenset({"none", "invalid-credentials", "account-restricted", "unavailable"})
TRACKED_HELPER_PATH = Path(__file__).with_name("windows_task_admission.ps1")


@dataclass(frozen=True)
class CredentialProbeAdmission:
    """Values read from caller-owned private VM configuration, never from QGA."""
    socket_path: str
    vm_identity: str
    account_name: str
    expected_sid: str
    correlation_id: str
    helper_path: Path
    helper_sha256: str
    credential_path: Path


def _sid(value: object) -> bool:
    return (isinstance(value, str) and value.startswith("S-1-5-21-")
            and len(value.split("-")) == 8 and all(part.isdecimal() for part in value.split("-")[4:]))


def _private_token(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        raise ValueError(f"private {name} rejected")
    return value


def _private_bytes(path: Path) -> bytes:
    """Read an owner-only non-link regular credential file without a pathname race."""
    try:
        _private_ancestors(path)
        before = os.lstat(path)
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077
                or not 0 < before.st_size <= MAX_CREDENTIAL_BYTES):
            raise ValueError("private credential input rejected")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) & 0o077 or opened.st_size != before.st_size):
                raise ValueError("private credential input rejected")
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("private credential input rejected")
            contents = os.read(fd, MAX_CREDENTIAL_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError("private credential input rejected") from error
    if not contents or len(contents) > MAX_CREDENTIAL_BYTES:
        raise ValueError("private credential input rejected")
    return contents


def _private_ancestors(path: Path) -> None:
    """Reject links and writable parent directories before opening private input."""
    parent = os.path.dirname(os.path.abspath(os.fspath(path)))
    # macOS exposes its canonical /private/var hierarchy through the documented
    # /var alias. Do not resolve arbitrary links in a private input's ancestry.
    if sys.platform == "darwin" and (parent == "/var" or parent.startswith("/var/")):
        parent = "/private" + parent
    protected_below = True
    while True:
        info = os.lstat(parent)
        mode = stat.S_IMODE(info.st_mode)
        writable = mode & 0o022
        sticky_root_temporary = info.st_uid == 0 and bool(mode & stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid not in {0, os.getuid()}
                or (writable and not (sticky_root_temporary and protected_below))):
            raise ValueError("private credential input rejected")
        if writable:
            # A sticky root-owned parent is safe only after every descendant
            # between the file and it was already admitted as private.
            protected_below = False
        next_parent = os.path.dirname(parent)
        if next_parent == parent:
            return
        parent = next_parent


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _bootstrap(admission: CredentialProbeAdmission) -> str:
    """The fixed guest program. Helper and credential arrive only on stdin."""
    return """$ErrorActionPreference='Stop'
$operation={operation}; $correlationId={correlation}; $expectedSid={sid}; $accountName={account}; $helperHash={helper_hash}
function Emit([bool]$success,[string]$category) {{ [ordered]@{{operation=$operation;correlationId=$correlationId;expectedSid=$expectedSid;success=$success;errorCategory=$category}} | ConvertTo-Json -Compress }}
function Read-Exact([System.IO.Stream]$stream,[int]$count) {{ $buffer=New-Object byte[] $count; $offset=0; while ($offset -lt $count) {{ $read=$stream.Read($buffer,$offset,$count-$offset); if ($read -le 0) {{ throw 'payload truncated' }}; $offset += $read }}; Write-Output -NoEnumerate $buffer }}
$credential=New-Object Security.SecureString
$credentialBytes=$null; $credentialChars=$null; $helperBytes=$null
try {{
  $stream=[Console]::OpenStandardInput(); $header=Read-Exact $stream 10
  if ([System.Text.Encoding]::ASCII.GetString($header,0,4) -cne 'WCV1') {{ throw 'payload header invalid' }}
  $helperLength=([int]$header[4]*16777216)+([int]$header[5]*65536)+([int]$header[6]*256)+[int]$header[7]
  $credentialLength=([int]$header[8]*256)+[int]$header[9]
  if ($helperLength -lt 1 -or $helperLength -gt {max_helper} -or $credentialLength -lt 1 -or $credentialLength -gt {max_credential}) {{ throw 'payload length invalid' }}
  $helperBytes=Read-Exact $stream $helperLength; $credentialBytes=Read-Exact $stream $credentialLength
  if ($stream.ReadByte() -ne -1) {{ throw 'payload trailing bytes' }}
  $utf8=[System.Text.UTF8Encoding]::new($false,$true); $credentialChars=$utf8.GetChars($credentialBytes)
  foreach ($character in $credentialChars) {{ $credential.AppendChar($character) }}
  $credential.MakeReadOnly()
  $hasher=[Security.Cryptography.SHA256]::Create()
  try {{ $actualHash=([BitConverter]::ToString($hasher.ComputeHash($helperBytes))).Replace('-','').ToLowerInvariant() }} finally {{ $hasher.Dispose() }}
  if ($actualHash -cne $helperHash) {{ throw 'helper hash mismatch' }}
  . ([scriptblock]::Create($utf8.GetString($helperBytes)))
  $admission=[pscustomobject]@{{operation=$operation;accountName=$accountName;expectedAccountSid=$expectedSid;approvedCallerSid='S-1-5-18'}}
  $result=Test-WindowsCredentialValidityAdmission -Admission $admission -Credential $credential
  if ($result.success -eq $true -and $result.errorCategory -eq 'none') {{ Emit $true 'none' }}
  elseif ($result.success -eq $false -and $result.errorCategory -in @('invalid-credentials','account-restricted','unavailable')) {{ Emit $false $result.errorCategory }}
  else {{ Emit $false 'unavailable' }}
}} catch {{ Emit $false 'unavailable' }} finally {{ if ($null -ne $credentialChars) {{ [Array]::Clear($credentialChars,0,$credentialChars.Length) }}; if ($null -ne $credentialBytes) {{ [Array]::Clear($credentialBytes,0,$credentialBytes.Length) }}; $credential.Dispose() }}
""".format(operation=_ps_literal(OPERATION), correlation=_ps_literal(admission.correlation_id), sid=_ps_literal(admission.expected_sid), account=_ps_literal(admission.account_name), helper_hash=_ps_literal(admission.helper_sha256), max_helper=MAX_HELPER_BYTES, max_credential=MAX_CREDENTIAL_BYTES)


def _private_payload(helper_bytes: bytes, secret: bytes) -> bytes:
    if not 0 < len(helper_bytes) <= MAX_HELPER_BYTES or not 0 < len(secret) <= MAX_CREDENTIAL_BYTES:
        raise ValueError("credential probe private payload rejected")
    return struct.pack(">4sIH", b"WCV1", len(helper_bytes), len(secret)) + helper_bytes + secret


def _windows_command_line_length(arguments: list[str]) -> int:
    """Length Windows receives after normal CreateProcess argument quoting."""
    import subprocess
    return len(subprocess.list2cmdline([PROGRAM, *arguments]))


class FixedCredentialProbeClient(QgaReadOnlyClient):
    """The mutation boundary permits just the fixed program and fixed argument list."""
    def _call(self, command: str, arguments: Mapping[str, Any]) -> Any:
        if command not in {"guest-exec", "guest-exec-status"}:
            raise ValueError("fixed credential probe command rejected")
        return self._exchange(command, arguments)

    def _dispatch_admitted_probe(self, admission: CredentialProbeAdmission, helper_bytes: bytes, secret: bytes) -> Mapping[str, Any]:
        """Private dispatch: callers cannot supply guest code, program, argv, cwd, or env."""
        encoded = base64.b64encode(_bootstrap(admission).encode("utf-16le")).decode("ascii")
        arguments = ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
        if _windows_command_line_length(arguments) >= 32767:
            raise ValueError("fixed credential probe command exceeds Windows limit")
        return self._call("guest-exec", {"path": PROGRAM, "arg": arguments, "input-data": base64.b64encode(_private_payload(helper_bytes, secret)).decode("ascii"), "capture-output": True})


class CredentialProbeJournal:
    """Owner-only, fsync'd state for a single non-replayable guest mutation."""
    def __init__(self, directory: Path): self.directory = Path(directory)

    def _ensure_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(self.directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("credential probe journal directory rejected")

    @contextmanager
    def locked(self):
        if os.name != "posix" or fcntl is None:
            raise OSError("credential probe requires POSIX private journal support")
        self._ensure_directory(); path = self.directory / ".credential-probe.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("credential probe journal lock rejected")
            fcntl.flock(fd, fcntl.LOCK_EX); yield
        finally: os.close(fd)

    def _path(self, correlation_id: str) -> Path:
        uuid.UUID(correlation_id); return self.directory / (correlation_id + ".json")

    def read(self, correlation_id: str) -> dict[str, Any] | None:
        path = self._path(correlation_id)
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("credential probe journal rejected")
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try: raw = os.read(fd, 16385)
            finally: os.close(fd)
        except FileNotFoundError: return None
        except OSError as error: raise ValueError("credential probe journal rejected") from error
        if len(raw) > 16384: raise ValueError("credential probe journal rejected")
        try: record = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error: raise ValueError("credential probe journal rejected") from error
        self._validate(record, correlation_id); return record

    def create_intent(self, record: dict[str, Any]) -> bool:
        correlation_id = record["correlationId"]; self._validate(record, correlation_id); self._ensure_directory()
        try: fd = os.open(self._path(correlation_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError: return False
        try:
            os.write(fd, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()); os.fsync(fd)
        finally: os.close(fd)
        self._sync_directory(); return True

    def write(self, record: dict[str, Any]) -> None:
        correlation_id = record["correlationId"]; self._validate(record, correlation_id); self._ensure_directory()
        fd, temporary = tempfile.mkstemp(prefix=".credential-probe-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600); os.write(fd, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()); os.fsync(fd); os.close(fd); fd = -1
            os.replace(temporary, self._path(correlation_id)); self._sync_directory()
        finally:
            if fd >= 0: os.close(fd)
            try: os.unlink(temporary)
            except FileNotFoundError: pass

    def _sync_directory(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY)
        try: os.fsync(fd)
        finally: os.close(fd)

    @staticmethod
    def _validate(record: Any, correlation_id: str) -> None:
        fields = {"journalVersion", "operation", "correlationId", "socketPath", "vmIdentity", "accountName", "expectedSid", "helperSha256", "state", "pid"}
        terminal_fields = fields | {"success", "errorCategory"}
        if (not isinstance(record, dict) or (set(record) != fields and set(record) != terminal_fields)
                or record.get("journalVersion") != _JOURNAL_VERSION or record.get("operation") != OPERATION or record.get("correlationId") != correlation_id):
            raise ValueError("credential probe journal rejected")
        _private_token(record.get("socketPath"), "socket path"); _private_token(record.get("vmIdentity"), "VM identity"); _private_token(record.get("accountName"), "account name")
        helper = record.get("helperSha256")
        if not _sid(record.get("expectedSid")) or not isinstance(helper, str) or len(helper) != 64 or any(c not in "0123456789abcdef" for c in helper): raise ValueError("credential probe journal rejected")
        pid = record.get("pid")
        state = record.get("state")
        if state not in {"intent", "submitted", "unknown", "terminal"} or (pid is not None and (type(pid) is not int or pid < 0)) or (state in {"submitted", "terminal"} and pid is None): raise ValueError("credential probe journal rejected")
        if state == "terminal":
            if type(record.get("success")) is not bool or record.get("errorCategory") not in _CATEGORIES or (record["success"] and record["errorCategory"] != "none") or (not record["success"] and record["errorCategory"] == "none"):
                raise ValueError("credential probe journal rejected")
        elif set(record) != fields:
            raise ValueError("credential probe journal rejected")


class WindowsCredentialValidityProbe:
    def __init__(self, client: FixedCredentialProbeClient, journal_directory: Path):
        if os.name != "posix" or fcntl is None:
            raise OSError("credential probe requires POSIX private journal support")
        self.client, self.journal = client, CredentialProbeJournal(journal_directory)

    @staticmethod
    def _admit(admission: CredentialProbeAdmission, socket_path: str) -> bytes:
        if admission.socket_path != socket_path or not _sid(admission.expected_sid): raise ValueError("credential probe admission rejected")
        _private_token(admission.vm_identity, "VM identity"); _private_token(admission.account_name, "account name"); uuid.UUID(admission.correlation_id)
        if not isinstance(admission.helper_sha256, str) or len(admission.helper_sha256) != 64 or any(c not in "0123456789abcdef" for c in admission.helper_sha256): raise ValueError("credential probe admission rejected")
        try:
            if admission.helper_path.resolve() != TRACKED_HELPER_PATH.resolve():
                raise ValueError("helper path is not the tracked helper")
            before = os.lstat(admission.helper_path)
            if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
                raise ValueError("helper path is unsafe")
            fd = os.open(admission.helper_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd); helper = os.read(fd, MAX_HELPER_BYTES + 1)
            finally: os.close(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or not 0 < len(helper) <= MAX_HELPER_BYTES:
                raise ValueError("helper changed while reading")
        except OSError as error: raise ValueError("credential probe admission rejected") from error
        if hashlib.sha256(helper).hexdigest() != admission.helper_sha256: raise ValueError("credential probe admission rejected")
        return helper

    @staticmethod
    def _record(a: CredentialProbeAdmission, state: str = "intent", pid: int | None = None) -> dict[str, Any]:
        return {"journalVersion": _JOURNAL_VERSION, "operation": OPERATION, "correlationId": a.correlation_id, "socketPath": a.socket_path, "vmIdentity": a.vm_identity, "accountName": a.account_name, "expectedSid": a.expected_sid, "helperSha256": a.helper_sha256, "state": state, "pid": pid}

    @staticmethod
    def _public(record: Mapping[str, Any], duplicate: bool = False) -> dict[str, Any]:
        result = {"state": record["state"], "correlationId": record["correlationId"]}
        if record["pid"] is not None: result["pid"] = record["pid"]
        if record["state"] == "terminal": result.update({"success": record["success"], "errorCategory": record["errorCategory"]})
        if duplicate: result["duplicate"] = True
        return result

    def start(self, admission: CredentialProbeAdmission) -> dict[str, Any]:
        helper = self._admit(admission, self.client.socket_path)
        with self.journal.locked():
            existing = self.journal.read(admission.correlation_id)
            if existing is not None:
                binding = {"socketPath": admission.socket_path, "vmIdentity": admission.vm_identity, "accountName": admission.account_name, "expectedSid": admission.expected_sid, "helperSha256": admission.helper_sha256}
                if any(existing[key] != value for key, value in binding.items()):
                    raise ValueError("credential probe correlation binding rejected")
                return self._public(existing, True)
            # Admit the private input before recording an intent.  An unreadable
            # file is not a guest effect and must not consume this correlation.
            secret = _private_bytes(admission.credential_path)
            record = self._record(admission)
            if not self.journal.create_intent(record):
                secret = b""; return self._public(self.journal.read(admission.correlation_id) or record, True)
            try:
                response = self.client._dispatch_admitted_probe(admission, helper, secret); pid = response.get("pid") if isinstance(response, Mapping) else None
                if type(pid) is not int or pid < 0: raise QgaObservationError("guest-exec returned no usable pid")
            except QgaObservationError:
                record["state"] = "unknown"; self.journal.write(record); return self._public(record)
            finally: secret = b""  # do not retain a host-side secret reference
            record["state"], record["pid"] = "submitted", pid; self.journal.write(record); return self._public(record)

    def status(self, correlation_id: str) -> dict[str, Any]:
        with self.journal.locked():
            record = self.journal.read(correlation_id)
            if record is None: raise ValueError("credential probe has no durable intent")
            if record["state"] == "terminal": return self._public(record)
            if record["state"] == "intent":
                # A crash after durable intent but before an observed response
                # has no PID to observe.  Preserve uncertainty; never re-exec.
                record["state"] = "unknown"; self.journal.write(record); return self._public(record)
            if record["state"] == "unknown" and record["pid"] is None:
                return self._public(record)
            try: value = self.client.guest_exec_status(record["pid"])
            except QgaObservationError:
                record["state"] = "unknown"; self.journal.write(record); return self._public(record)
            if not isinstance(value, Mapping) or value.get("exited") is not True: return self._public(record)
            receipt = _decode_receipt(value.get("out-data"), record["correlationId"], record["expectedSid"])
            if receipt is None:
                record["state"] = "unknown"; self.journal.write(record); return self._public(record)
            record["state"] = "terminal"; record["success"] = receipt["success"]; record["errorCategory"] = receipt["errorCategory"]; self.journal.write(record)
            return self._public(record)


def _decode_receipt(encoded: object, correlation_id: str, expected_sid: str) -> dict[str, Any] | None:
    if not isinstance(encoded, str) or len(encoded) > 8192: return None
    try: value = json.loads(base64.b64decode(encoded, validate=True))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError): return None
    fields = {"operation", "correlationId", "expectedSid", "success", "errorCategory"}
    if (not isinstance(value, dict) or set(value) != fields or value.get("operation") != OPERATION or value.get("correlationId") != correlation_id or value.get("expectedSid") != expected_sid or type(value.get("success")) is not bool or value.get("errorCategory") not in _CATEGORIES or (value["success"] and value["errorCategory"] != "none") or (not value["success"] and value["errorCategory"] == "none")): return None
    return value
