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
        if (not isinstance(self.name, str) or Path(self.name).name != self.name
                or self.name in {"", ".", ".."}):
            raise ValueError("unsafe private filename")
        if type(self.body) is not bytes or not 0 < len(self.body) <= _LIMIT:
            raise ValueError("unsupported ownership lock")
        directory.guard()
        try:
            try:
                os.stat(self.name, dir_fd=directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                self._initialize(directory)
            self.snapshot = Snapshot(directory, self.name)
            if self.snapshot.body != self.body:
                raise ValueError("unsupported ownership lock")
            fcntl.flock(self.snapshot.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.guard()
        except BaseException:
            self.close()
            raise

    def _initialize(self, directory):
        # Publishing an empty final name lets a concurrent Snapshot mistake
        # ordinary initialization for an unsafe existing file. A hard link is
        # also unsuitable: it temporarily exposes st_nlink == 2. Rename a
        # fully initialized private inode without replacing any existing name.
        temporary = "." + self.name + "." + os.urandom(16).hex() + ".tmp"
        fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory.fd)
        try:
            offset = 0
            while offset < len(self.body):
                count = os.write(fd, self.body[offset:])
                if count <= 0:
                    raise ValueError("incomplete ownership lock write")
                offset += count
            os.fsync(fd); directory.guard()
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size != len(self.body)
                    or _generation(os.stat(temporary, dir_fd=directory.fd, follow_symlinks=False)) != _generation(info)
                    or os.pread(fd, _LIMIT + 1, 0) != self.body):
                raise ValueError("private temporary generation changed")
            try:
                _rename_create_only(directory.fd, temporary, self.name)
            except FileExistsError:
                # Another complete publisher won. The unchanged Snapshot and
                # flock checks below decide whether its named file is usable.
                pass
            else:
                directory.guard()
                if _generation(os.stat(self.name, dir_fd=directory.fd, follow_symlinks=False)) != _generation(os.fstat(fd)):
                    raise ValueError("private published generation changed")
                os.fsync(directory.fd)
        finally:
            try:
                try:
                    named = os.stat(temporary, dir_fd=directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    directory.guard()
                    if _generation(named) != _generation(os.fstat(fd)) or named.st_nlink != 1:
                        raise ValueError("private temporary generation changed")
                    os.unlink(temporary, dir_fd=directory.fd)
            finally:
                os.close(fd)

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


def _rename_create_only(directory_fd, source, destination):
    """Same-directory atomic publication, with no overwrite/link fallback.

    Linux renameat2(2) RENAME_NOREPLACE and Darwin sys/stdio.h RENAME_EXCL
    both reject an existing destination, including unsafe files and symlinks.
    Unsupported coordinators/filesystems refuse instead of weakening this.
    """
    import ctypes
    import errno
    import sys
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = getattr(library, "renameatx_np", None); flag = 4
    elif sys.platform.startswith("linux"):
        function = getattr(library, "renameat2", None); flag = 1
    else:
        function = None; flag = 0
    if function is None:
        raise ValueError("atomic ownership lock publication unavailable")
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    function.restype = ctypes.c_int
    if function(directory_fd, os.fsencode(source), directory_fd, os.fsencode(destination), flag):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, "ownership lock already exists")
        raise OSError(code, "atomic ownership lock publication failed")


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
