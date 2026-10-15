"""Explicit credential-file input, held through one authorized native operation.

No default host/user/attempt path; no credential hashes or output. Only a private
regular file owned by this coordinator may supply a bounded single-line secret.
"""
from __future__ import annotations
import os,stat
from pathlib import Path


def _generation(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


class SecretFile:
    def __init__(self,path):
        if os.name!='posix':raise ValueError('credential_coordinator_unsupported')
        if type(path)is not str or not Path(path).is_absolute() or Path(path).is_symlink() or '..' in Path(path).parts:raise ValueError('credential_path')
        self.path=Path(path).resolve(strict=True);self.parents=[];self.fd=-1;self.raw=None
        try:
            parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);self.parents.append((parent,None,None,os.fstat(parent)))
            for name in self.path.parent.parts[1:]:
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                info=os.fstat(fd);self.parents.append((fd,parent,name,info));parent=fd
            self.fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            info=os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 1<=info.st_size<=512:raise ValueError('credential_metadata')
            self.pin=_generation(info);self.raw=os.read(self.fd,513)
            if len(self.raw)!=info.st_size:raise ValueError('credential_partial')
            text=self.raw.decode('utf8','strict').removesuffix('\n')
            if not text or any(c in text for c in ('\r','\n','\0')):raise ValueError('credential_shape')
            self.text=text;self.guard()
        except BaseException:self.close();raise
    def guard(self):
        for fd,parent,name,before in self.parents:
            named=os.lstat('/') if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
            identity=lambda info:(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)
            if identity(before)!=identity(os.fstat(fd)) or identity(before)!=identity(named):raise ValueError('credential_parent_changed')
        if self.fd<0 or _generation(os.fstat(self.fd))!=self.pin or _generation(os.stat(self.path.name,dir_fd=self.parents[-1][0],follow_symlinks=False))!=self.pin:raise ValueError('credential_changed')
        if os.pread(self.fd,513,0)!=self.raw:raise ValueError('credential_changed')
    def close(self):
        if self.fd>=0:os.close(self.fd);self.fd=-1
        for fd,*_ in reversed(self.parents):os.close(fd)
        self.parents=[];self.raw=None;self.text=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
