"""Owner-only credentials for native fixtures, addressed by opaque handles.

No public result from this module contains credential bytes. Callers must supply
the complete fixture/account/purpose binding before a secret can be read or made
active. Previous handles remain available for audit after publication.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import uuid
from typing import Iterator

try:
    import fcntl
except ImportError:  # pragma: no cover - fixture operations run on POSIX hosts
    fcntl = None


_HANDLE = re.compile(r"^nc-[0-9a-f]{32}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SID = re.compile(r"^S-1-5-21-(?:[0-9]+-){3}[0-9]+$")


class CredentialStoreError(ValueError):
    """Private store or binding cannot be trusted."""


@dataclass(frozen=True)
class CredentialBinding:
    environment: str
    account_name: str
    expected_sid: str
    purpose: str
    correlation_id: str

    def validate(self) -> None:
        if (not _NAME.fullmatch(self.environment) or not _NAME.fullmatch(self.account_name)
                or not _SID.fullmatch(self.expected_sid) or not _NAME.fullmatch(self.purpose)):
            raise CredentialStoreError("Credential binding is invalid.")
        try:
            parsed = uuid.UUID(self.correlation_id)
        except (ValueError, TypeError) as error:
            raise CredentialStoreError("Credential correlation is invalid.") from error
        if str(parsed) != self.correlation_id:
            raise CredentialStoreError("Credential correlation is invalid.")


class NativeCredentialStore:
    def __init__(self, repo_root: Path | str):
        self.path = Path(repo_root).resolve() / ".runtime" / "native-credentials"

    @staticmethod
    def _private_dir(path: Path, create: bool = False) -> None:
        if create:
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
        try:
            info = os.lstat(path)
        except OSError as error:
            raise CredentialStoreError("Private credential directory is unavailable.") from error
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise CredentialStoreError("Private credential directory is unsafe.")

    @staticmethod
    def _read_file(path: Path, max_bytes: int) -> bytes:
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= max_bytes):
                    raise CredentialStoreError("Private credential file is unsafe.")
                raw = os.read(fd, max_bytes + 1)
                if len(raw) != info.st_size:
                    raise CredentialStoreError("Private credential file changed during read.")
                return raw
            finally:
                os.close(fd)
        except OSError as error:
            raise CredentialStoreError("Private credential file is unavailable.") from error

    @staticmethod
    def _write_exclusive(path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _sync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        if fcntl is None or os.name != "posix":
            raise CredentialStoreError("Private credential store requires POSIX locking.")
        runtime = self.path.parent
        if not runtime.exists():
            try:
                runtime.mkdir(mode=0o700)
            except FileExistsError:
                pass
        try:
            parent_info = os.lstat(runtime)
        except OSError as error:
            raise CredentialStoreError("Runtime directory is unavailable.") from error
        if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
                or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022):
            raise CredentialStoreError("Runtime directory is unsafe.")
        self._private_dir(self.path, create=True)
        lock = self.path / ".lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise CredentialStoreError("Private credential lock is unsafe.")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _item(self, handle: str) -> Path:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise CredentialStoreError("Credential handle is invalid.")
        return self.path / handle

    @staticmethod
    def _active_key(binding: CredentialBinding) -> str:
        stable = {key: getattr(binding, key) for key in
                  ("environment", "account_name", "expected_sid", "purpose")}
        digest = hashlib.sha256(json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return digest + ".json"

    def _metadata(self, handle: str, binding: CredentialBinding) -> dict[str, object]:
        binding.validate()
        item = self._item(handle)
        self._private_dir(item)
        try:
            data = json.loads(self._read_file(item / "metadata.json", 4096))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CredentialStoreError("Credential metadata is invalid.") from error
        if (not isinstance(data, dict) or set(data) != {"schema", "handle", "binding"}
                or data["schema"] != 1 or data["handle"] != handle
                or data["binding"] != asdict(binding)):
            raise CredentialStoreError("Credential binding does not match.")
        return data

    def create(self, binding: CredentialBinding) -> str:
        binding.validate()
        with self._locked():
            handle = "nc-" + uuid.uuid4().hex
            item = self._item(handle)
            item.mkdir(mode=0o700)
            # Guaranteed upper, lower, number and punctuation categories.
            secret = ("V!" + secrets.token_urlsafe(36) + "7a").encode("ascii")
            metadata = {"schema": 1, "handle": handle, "binding": asdict(binding)}
            self._write_exclusive(item / "secret", secret)
            self._write_exclusive(item / "metadata.json", json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode())
            self._sync_dir(item)
            self._sync_dir(self.path)
            return handle

    def read(self, handle: str, binding: CredentialBinding) -> bytes:
        with self._locked():
            self._metadata(handle, binding)
            return self._read_file(self._item(handle) / "secret", 512)

    def status(self, handle: str, binding: CredentialBinding) -> dict[str, object]:
        with self._locked():
            self._metadata(handle, binding)
            self._read_file(self._item(handle) / "secret", 512)
            return {"handle": handle, "binding": asdict(binding), "available": True}

    def publish_active(self, handle: str, binding: CredentialBinding) -> None:
        with self._locked():
            self._metadata(handle, binding)
            self._read_file(self._item(handle) / "secret", 512)
            active_dir = self.path / "active"
            self._private_dir(active_dir, create=True)
            key = self._active_key(binding)
            destination = active_dir / key
            record = {"schema": 1, "handle": handle, "binding": asdict(binding)}
            fd, name = tempfile.mkstemp(prefix=".publish-", dir=active_dir)
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(json.dumps(record, sort_keys=True, separators=(",", ":")).encode())
                    stream.flush(); os.fsync(stream.fileno())
                os.replace(name, destination)
                self._sync_dir(active_dir)
            finally:
                if os.path.exists(name):
                    os.unlink(name)

    def active(self, binding: CredentialBinding) -> str | None:
        binding.validate()
        with self._locked():
            active_dir = self.path / "active"
            if not active_dir.exists():
                return None
            self._private_dir(active_dir)
            key = self._active_key(binding)
            try:
                record = json.loads(self._read_file(active_dir / key, 4096))
            except CredentialStoreError:
                if not (active_dir / key).exists():
                    return None
                raise
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CredentialStoreError("Active credential record is invalid.") from error
            stable = ("environment", "account_name", "expected_sid", "purpose")
            if (not isinstance(record, dict) or set(record) != {"schema", "handle", "binding"}
                    or record["schema"] != 1 or not isinstance(record["binding"], dict)
                    or any(record["binding"].get(key) != getattr(binding, key) for key in stable)):
                raise CredentialStoreError("Active credential binding does not match.")
            try:
                recorded = CredentialBinding(**record["binding"])
            except (TypeError, ValueError) as error:
                raise CredentialStoreError("Active credential binding is invalid.") from error
            self._metadata(record["handle"], recorded)
            return record["handle"]
