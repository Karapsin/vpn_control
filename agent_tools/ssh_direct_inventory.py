"""New direct-channel inventory custody; historical content pins stay historical.

Only file generation and public route identities are serialized. Credential
bytes remain in protected, non-serializable in-memory owners throughout dispatch.
"""
from __future__ import annotations
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import stat
import sys
import types

from . import ssh_transport as transport
from . import ssh_connection_session as session

_EXECUTING_CODE=sys._getframe().f_code
_SOURCE_SHA=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
_HELPER_SHA='efc4b40e1f455444bd80ad3bbb5cb8753cad1d4cf737853010f1bccea32ea040'


def _generation(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _structure(info):return _generation(info)[:5]


class InventoryCustody:
    """Held-byte-verified helper plus one credential-bearing inventory owner."""
    def __repr__(self):return '<InventoryCustody>'
    def __init__(self,path):
        self._fds=[];self._parents=[];self._closed=False;self._private=None
        helper=Path(__file__).with_name('private_config_custody.py').absolute()
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            self._fds.append(fd);self._parents.append((None,'/',fd,_structure(os.fstat(fd))))
            for name in helper.parent.parts[1:]:
                parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
                self._fds.append(fd);self._parents.append((parent,name,fd,_structure(os.fstat(fd))))
            self._helper_parent=fd
            fd=os.open(helper.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
            self._fds.append(fd);self._helper_fd=fd;self._helper_name=helper.name
            info=os.fstat(fd);self._helper_pin=_generation(info)
            if not stat.S_ISREG(info.st_mode)or info.st_uid!=os.getuid()or info.st_nlink!=1 or not 0<info.st_size<=1048576:
                raise ValueError('private_config_helper_shape')
            raw=os.read(fd,info.st_size+1)
            if len(raw)!=info.st_size or hashlib.sha256(raw).hexdigest()!=_HELPER_SHA:
                raise ValueError('private_config_helper_integrity')
            self._helper_raw=raw;self._source_guard()
            module=types.ModuleType('_verified_direct_private_config');module.__file__=str(helper)
            exec(compile(raw,str(helper),'exec',dont_inherit=True),module.__dict__)
            self._path=Path(path).absolute();self._private=module.PrivateConfigCustody(self._path)
            self._pin=_generation(os.stat(self._path,follow_symlinks=False));self.guard()
        except BaseException:
            self.close();raise
    def _source_guard(self):
        if self._closed:raise ValueError('private_config_custody_closed')
        for parent,name,fd,pin in self._parents:
            named=os.stat('/',follow_symlinks=False)if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False)
            if _structure(os.fstat(fd))!=pin or _structure(named)!=pin:raise ValueError('private_config_helper_changed')
        if (_generation(os.fstat(self._helper_fd))!=self._helper_pin or
            _generation(os.stat(self._helper_name,dir_fd=self._helper_parent,follow_symlinks=False))!=self._helper_pin or
            os.pread(self._helper_fd,len(self._helper_raw)+1,0)!=self._helper_raw):
            raise ValueError('private_config_helper_changed')
    def guard(self):
        self._source_guard();self._private.check();self._source_guard()
        raw=Path(__file__).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=_SOURCE_SHA or _EXECUTING_CODE!=compile(raw,__file__,'exec',dont_inherit=True):
            raise ValueError('private_config_helper_changed')
    def load_config(self,root):
        """Parse only the protected held bytes, never a second pathname read."""
        self.guard()
        config=transport._parse_config(root,bytes(self._private._raw))
        self.guard();return config
    def pin(self):
        self.guard()
        return {'custody':'private-generation-v1','generation':list(self._pin),'size':self._pin[6]}
    def close(self):
        if self._closed:return
        if self._private is not None:self._private.close()
        self._closed=True
        for fd in reversed(self._fds):
            try:os.close(fd)
            except OSError:pass
        self._fds.clear()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
    def __del__(self):
        try:self.close()
        except BaseException:pass


class Authority:
    """One protected inventory/key generation and its public route authority."""
    def __init__(self,root,host):
        self._owners=[];self.closed=False
        try:
            root=Path(root).resolve(strict=True)
            self.inventory=InventoryCustody(transport._private_config_path(root));self._owners.append(self.inventory)
            self.config=self.inventory.load_config(root);route=transport._route_hosts(self.config.hosts,host)
            if len(route)<2 or route[-1].transport!='direct' or route[-1].password is not None:raise ValueError('unsupported')
            self.outer=route[-1];files=[]
            key=InventoryCustody(self.outer.identity_file);self._owners.append(key)
            files.append({'path':str(self.outer.identity_file),'generation':key.pin()})
            # Host trust is public and may legitimately use mode 0644.
            raw,pin=session._bytes(self.outer.known_hosts_file,private=False)
            self._trust=(self.outer.known_hosts_file,raw,pin)
            files.append({'path':str(self.outer.known_hosts_file),'sha256':hashlib.sha256(raw).hexdigest(),'fingerprint':pin})
            self.value={'version':2,'host':host,'root':str(root),'sourceSha256':_SOURCE_SHA,
                        'configGeneration':self.inventory.pin(),'files':files,
                        'routeAliases':[entry.alias for entry in route]}
            self.guard()
        except BaseException:self.close();raise
    def guard(self):
        if self.closed:raise ValueError('private_config_custody_closed')
        for owner in self._owners:owner.guard()
        path,raw,pin=self._trust
        current,generation=session._bytes(path,private=False)
        if current!=raw or generation!=pin:raise ValueError('public_trust_changed')
        if asdict(self.inventory.load_config(self.config.root))!=asdict(self.config):raise ValueError('private_config_changed')
        if (_SOURCE_SHA!=hashlib.sha256(Path(__file__).read_bytes()).hexdigest() or
            _EXECUTING_CODE!=compile(Path(__file__).read_bytes(),__file__,'exec',dont_inherit=True)):
            raise ValueError('private_config_helper_changed')
        for owner in self._owners:owner.guard()
    def close(self):
        if self.closed:return
        self.closed=True
        for owner in reversed(self._owners):owner.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()
