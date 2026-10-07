"""FD-first local receipts for a private Windows diagnostic evidence leaf.

Public repository ancestors are identity guarded; only the evidence leaf is
private. This captures original authority, never recovers it from named files.
"""
from pathlib import Path
import hashlib
import os
import re
import stat


def _identity(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)


def _generation(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class AuthorityCapture:
    def __init__(self, root, leaf):
        root = Path(root).absolute()
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,150}', leaf):
            raise ValueError('diagnostic-leaf')
        self.path = root / '.runtime' / 'parity-evidence' / leaf
        self.parents = []
        current = Path(self.path.anchor)
        for part in self.path.parts[1:]:
            current /= part
            s = current.lstat()
            if not stat.S_ISDIR(s.st_mode):
                raise ValueError('diagnostic-ancestry')
            self.parents.append((current, _identity(s)))
        s = self.path.lstat()
        if stat.S_IMODE(s.st_mode) != 0o700 or s.st_uid != os.getuid():
            raise ValueError('diagnostic-private-leaf')
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self._check()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _check(self):
        if self.fd is None:
            raise ValueError('diagnostic-closed')
        for path, identity in self.parents:
            if _identity(path.lstat()) != identity:
                raise ValueError('diagnostic-ancestry-changed')
        if _identity(os.fstat(self.fd)) != self.parents[-1][1]:
            raise ValueError('diagnostic-leaf-changed')

    @staticmethod
    def _name(name):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,150}', name):
            raise ValueError('diagnostic-name')

    @staticmethod
    def _file(s):
        if (not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600
                or s.st_uid != os.getuid() or s.st_nlink != 1):
            raise ValueError('diagnostic-record')

    def create(self, name, raw):
        self._name(name)
        if not isinstance(raw, bytes) or len(raw) > 1048576:
            raise ValueError('diagnostic-bytes')
        self._check()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            offset = 0
            while offset < len(raw):
                count = os.write(fd, raw[offset:])
                if count <= 0:
                    raise ValueError('diagnostic-write')
                offset += count
            os.fsync(fd)
            original = os.fstat(fd)
            self._file(original)
            os.lseek(fd, 0, os.SEEK_SET)
            content = bytearray()
            while len(content) <= len(raw):
                block = os.read(fd, min(65536, len(raw) + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
            if bytes(content) != raw or _generation(os.fstat(fd)) != _generation(original):
                raise ValueError('diagnostic-content-changed')
            named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            if _generation(named) != _generation(original):
                raise ValueError('diagnostic-record-changed')
            self._check()
            return {'sha256': hashlib.sha256(content).hexdigest(),
                    'generation': _generation(original)}
        finally:
            os.close(fd)

    def verify(self, name, pin):
        self._name(name)
        self._check()
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self.fd)
        try:
            initial = os.fstat(fd)
            self._file(initial)
            if _generation(initial) != pin['generation'] or initial.st_size > 1048576:
                raise ValueError('diagnostic-pin-changed')
            chunks = []
            remaining = initial.st_size + 1
            while remaining:
                block = os.read(fd, min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b''.join(chunks)
            if (hashlib.sha256(raw).hexdigest() != pin['sha256']
                    or _generation(os.fstat(fd)) != pin['generation']
                    or _generation(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != pin['generation']):
                raise ValueError('diagnostic-pin-changed')
            self._check()
            return raw
        finally:
            os.close(fd)
