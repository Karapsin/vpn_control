"""Shared cooperative ownership for every repository private-inventory writer.

The protocol is an exclusive nonblocking flock on the descriptor-bound private
.rag_index/ssh-recovery-adoption/config.lock. Hold it from source validation
through replacement and directory fsync. All cooperating inventory writers must
use this same protocol. It does not supply atomic CAS against external writers
that ignore the lock. Lock content/path remain compatible with prior adoption.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
from contextlib import contextmanager

if os.name == "posix":
    import fcntl
else:
    fcntl = None

_LIMIT = 1_048_576


def _generation(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info: os.stat_result) -> tuple[int, ...]:
    # File creation legitimately changes directory timestamps/link counts.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


class PresentedPath:
    """Pin the caller's named ancestry as well as its canonical FD ancestry.

    System aliases such as macOS /var may exist initially, but replacing any
    alias or named parent cannot silently redirect or outlive this operation.
    """
    def __init__(self, path: Path):
        self.path = path
        self.pins = []
        for name in (path, *path.parents):
            info = name.lstat()
            if name == path and stat.S_ISLNK(info.st_mode):
                raise ValueError("symlink root")
            link = os.readlink(name) if stat.S_ISLNK(info.st_mode) else None
            self.pins.append((name, _directory_identity(info), link))
        self.canonical = path.resolve(strict=True)
        self.guard()

    def guard(self):
        for name, identity, link in self.pins:
            info = name.lstat()
            if _directory_identity(info) != identity or (os.readlink(name) if stat.S_ISLNK(info.st_mode) else None) != link:
                raise ValueError("presented parent changed")
        if self.path.resolve(strict=True) != self.canonical:
            raise ValueError("presented route changed")


class Directory:
    """Pinned no-follow ancestry; every operation remains relative to its FD."""
    def __init__(self, path: Path):
        self.path = path
        self.chain: list[tuple[int, str | None, tuple[int, ...]]] = []
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("unsafe directory")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            fd = os.open("/", flags)
            self.chain.append((fd, None, _directory_identity(os.fstat(fd))))
            for name in path.parts[1:]:
                fd = os.open(name, flags, dir_fd=self.chain[-1][0])
                self.chain.append((fd, name, _directory_identity(os.fstat(fd))))
            final = os.fstat(self.fd)
            if final.st_uid != os.geteuid() or final.st_mode & 0o022:
                raise ValueError("unsafe private parent")
            self.guard()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self) -> int:
        return self.chain[-1][0]

    def guard(self) -> None:
        for index, (fd, name, identity) in enumerate(self.chain):
            if _directory_identity(os.fstat(fd)) != identity:
                raise ValueError("parent generation changed")
            named = os.stat("/", follow_symlinks=False) if index == 0 else os.stat(
                name, dir_fd=self.chain[index - 1][0], follow_symlinks=False)
            if _directory_identity(named) != identity or not stat.S_ISDIR(named.st_mode):
                raise ValueError("named parent changed")

    def close(self) -> None:
        for fd, _, _ in reversed(self.chain):
            os.close(fd)
        self.chain.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Snapshot:
    """Exact private bytes plus opened/named full generation and parent guards."""
    def __init__(self, directory: Directory, name: str):
        if not isinstance(name, str) or Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("unsafe private filename")
        self.directory = directory
        self.name = name
        self.fd = -1
        directory.guard()
        try:
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
            info = os.fstat(self.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 0 < info.st_size <= _LIMIT):
                raise ValueError("unsafe private file")
            self.generation = _generation(info)
            self.body = os.read(self.fd, _LIMIT + 1)
            if len(self.body) != info.st_size:
                raise ValueError("incomplete private read")
            self.digest = hashlib.sha256(self.body).hexdigest()
            self.guard()
        except BaseException:
            self.close()
            raise

    def guard(self) -> None:
        self.directory.guard()
        if (_generation(os.fstat(self.fd)) != self.generation or
                _generation(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)) != self.generation):
            raise ValueError("private generation changed")
        body = os.pread(self.fd, _LIMIT + 1, 0)
        if len(body) != len(self.body) or hashlib.sha256(body).hexdigest() != self.digest:
            raise ValueError("private bytes changed")
        if _generation(os.fstat(self.fd)) != self.generation:
            raise ValueError("private generation changed during read")
        self.directory.guard()
        if _generation(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)) != self.generation:
            raise ValueError("private named generation changed during read")

    def pin(self) -> dict[str, object]:
        return {"generation": list(self.generation), "size": len(self.body), "sha256": self.digest}

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class InventoryLock:
    """One private, pinned cooperative inventory-adoption ownership lock."""
    name = "config.lock"
    body = b"ssh-recovery-adoption-lock-v1\n"

    def __init__(self, directory: Directory):
        self.snapshot = None
        if fcntl is None:
            raise ValueError("cooperative lock unavailable")
        directory.guard()
        try:
            try:
                fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory.fd)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(self.body); stream.flush(); os.fsync(stream.fileno())
                directory.guard(); os.fsync(directory.fd)
            self.snapshot = Snapshot(directory, self.name)
            if self.snapshot.body != self.body:
                raise ValueError("unsupported ownership lock")
            fcntl.flock(self.snapshot.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.guard()
        except BaseException:
            self.close()
            raise

    def guard(self):
        self.snapshot.guard()

    def pin(self):
        return self.snapshot.pin()

    def close(self):
        if self.snapshot is not None:
            # Closing the pinned descriptor releases the cooperative flock.
            self.snapshot.close()
            self.snapshot = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def lock_directory(root: Directory) -> Directory:
    root.guard()
    parent = root
    opened = []
    try:
        for name in (".rag_index", "ssh-recovery-adoption"):
            try:
                os.mkdir(name, 0o700, dir_fd=parent.fd)
                os.fsync(parent.fd)
            except FileExistsError:
                pass
            child = Directory(parent.path / name)
            opened.append(child)
            parent = child
        root.guard()
        result = opened.pop()
        return result
    finally:
        for directory in reversed(opened):
            directory.close()


@contextmanager
def ownership(root: Path | str):
    """Give a cooperating writer the guarded root and held inventory lock."""
    if os.name != "posix":
        raise ValueError("private inventory ownership is unsupported")
    presented = PresentedPath(Path(root).absolute())
    with Directory(presented.canonical) as directory, lock_directory(directory) as locks, InventoryLock(locks) as lock:
        presented.guard(); lock.guard()
        yield presented, directory, lock
