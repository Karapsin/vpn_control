"""Private inventory custody without a content digest or printable snapshot.

The open descriptor, named file, lexical ancestors and exact original bytes are
rechecked. Secret bytes live only in this protected in-memory owner. No receipt,
exception, dataclass representation or hash includes inventory content.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

_EXECUTING_CODE = sys._getframe().f_code


class PrivateConfigError(ValueError):
    pass


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _structure(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


class PrivateConfigCustody:
    __slots__ = ('_fds', '_ancestors', '_file', '_directory', '_name', '_pin', '_raw', '_closed')

    def __repr__(self):
        return '<PrivateConfigCustody>'

    def __deepcopy__(self, memo):
        raise PrivateConfigError('private_config_snapshot_not_serializable')

    def __reduce__(self):
        raise PrivateConfigError('private_config_snapshot_not_serializable')

    def __init__(self, path):
        self._fds=[];self._ancestors=[];self._raw=bytearray();self._closed=False
        path=str(Path(path).absolute());parts=path.split('/')[1:]
        if not path.startswith('/') or not parts or any(part in ('','.','..') for part in parts):
            raise PrivateConfigError('private_config_path')
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._fds.append(fd);self._ancestors.append((None,'/',fd,_structure(os.fstat(fd))))
            for name in parts[:-1]:
                parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                self._fds.append(fd);self._ancestors.append((parent,name,fd,_structure(os.fstat(fd))))
            self._directory=fd;self._name=parts[-1]
            fd=os.open(self._name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self._directory)
            self._file=fd;self._fds.append(fd);info=os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1
                    or not 0<info.st_size<=1048576):
                raise PrivateConfigError('private_config_shape')
            self._pin=_generation(info)
            while len(self._raw)<info.st_size:
                part=os.read(fd,min(65536,info.st_size-len(self._raw)))
                if not part:raise PrivateConfigError('private_config_short')
                self._raw.extend(part)
            if os.read(fd,1):raise PrivateConfigError('private_config_changed')
            self.check()
        except BaseException:
            self.close()
            raise

    def matches_text(self, text):
        """Compare a freshly parsed private read without publishing a digest."""
        self.check()
        return isinstance(text,str) and self._raw==text.encode('utf-8')

    def check(self):
        if self._closed:raise PrivateConfigError('private_config_custody_closed')
        try:
            for parent,name,fd,pin in self._ancestors:
                physical=os.stat('/',follow_symlinks=False) if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
                if _structure(os.fstat(fd))!=pin or _structure(physical)!=pin:
                    raise PrivateConfigError('private_config_ancestry_changed')
            if (_generation(os.fstat(self._file))!=self._pin or
                    _generation(os.stat(self._name,dir_fd=self._directory,follow_symlinks=False))!=self._pin):
                raise PrivateConfigError('private_config_changed')
            offset=0
            while offset<len(self._raw):
                part=os.pread(self._file,min(65536,len(self._raw)-offset),offset)
                if not part or part!=self._raw[offset:offset+len(part)]:
                    raise PrivateConfigError('private_config_changed')
                offset+=len(part)
            if os.pread(self._file,1,len(self._raw)):
                raise PrivateConfigError('private_config_changed')
            if (_generation(os.fstat(self._file))!=self._pin or
                    _generation(os.stat(self._name,dir_fd=self._directory,follow_symlinks=False))!=self._pin):
                raise PrivateConfigError('private_config_changed')
        except OSError:
            raise PrivateConfigError('private_config_changed') from None

    def close(self):
        if self._closed:return
        self._closed=True
        for fd in reversed(self._fds):
            try:os.close(fd)
            except OSError:pass
        self._fds.clear();self._raw.clear()

    def __del__(self):
        try:self.close()
        except BaseException:pass
