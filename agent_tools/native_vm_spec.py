"""Instance-neutral input contract for a fresh Windows test VM.

Paths and byte identities are inputs. Runtime qualification is a separate live
operation; parsing this request never establishes readiness or starts a VM.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
import uuid

class VmSpecError(ValueError):pass

def _exact(value,fields,label):
    if type(value)is not dict or set(value)!=set(fields):raise VmSpecError(label+'_fields')
    return value

def _integer(value,low,high,label):
    if type(value)is not int or not low<=value<=high:raise VmSpecError(label+'_range')
    return value

def _path(value):
    if (type(value)is not str or not value.startswith('/') or len(value.encode())>4096
            or any(ord(c)<32 for c in value) or any(p in ('','.','..') for p in value.split('/')[1:])):
        raise VmSpecError('absolute_path')
    return value

@dataclass(frozen=True)
class VmAsset:
    path:str
    bytes:int
    sha256:str
    @classmethod
    def parse(cls,value):
        _exact(value,('path','bytes','sha256'),'asset')
        if type(value['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['sha256'])is None:raise VmSpecError('asset_digest')
        return cls(_path(value['path']),_integer(value['bytes'],1,8*1024**3,'asset_bytes'),value['sha256'])

@dataclass(frozen=True)
class FreshWindowsVmSpec:
    deployment_id:str
    host:str
    root:str
    memory_mib:int
    cpus:int
    disk_gib:int
    vnc_port:int
    headroom_mib:int
    installer:VmAsset
    drivers:VmAsset
    firmware_code:VmAsset
    firmware_vars:VmAsset
    @classmethod
    def parse(cls,value):
        _exact(value,('deploymentId','host','root','memoryMiB','cpus','diskGiB','vncPort','headroomMiB','assets'),'vm')
        identifier=value['deploymentId']
        try:
            if type(identifier)is not str or str(uuid.UUID(identifier))!=identifier:raise ValueError()
        except (ValueError,AttributeError):raise VmSpecError('deployment_identity') from None
        host=value['host']
        if type(host)is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',host)is None:raise VmSpecError('configured_host')
        root=_path(value['root'])
        if ',' in root:raise VmSpecError('socket_path_delimiter')
        # Long Unix socket names must fail from input, before creating anything.
        if any(len(str(PurePosixPath(root)/name).encode())>=104 for name in ('qmp.sock','qga.sock','swtpm.sock')):raise VmSpecError('socket_path_bound')
        assets=_exact(value['assets'],('installer','drivers','firmwareCode','firmwareVars'),'assets')
        parsed=[VmAsset.parse(assets[name]) for name in ('installer','drivers','firmwareCode','firmwareVars')]
        if len({a.path for a in parsed})!=4:raise VmSpecError('distinct_assets')
        if any(PurePosixPath(root)==PurePosixPath(a.path) or PurePosixPath(root) in PurePosixPath(a.path).parents for a in parsed):raise VmSpecError('asset_inside_new_vm')
        return cls(identifier,host,root,_integer(value['memoryMiB'],4096,16384,'memory'),_integer(value['cpus'],2,16,'cpus'),_integer(value['diskGiB'],64,256,'disk'),_integer(value['vncPort'],5900,65535,'vnc'),_integer(value['headroomMiB'],8192,65536,'headroom'),*parsed)
    def as_dict(self):
        def asset(a):return {'path':a.path,'bytes':a.bytes,'sha256':a.sha256}
        return {'deploymentId':self.deployment_id,'host':self.host,'root':self.root,'memoryMiB':self.memory_mib,'cpus':self.cpus,'diskGiB':self.disk_gib,'vncPort':self.vnc_port,'headroomMiB':self.headroom_mib,'assets':dict(zip(('installer','drivers','firmwareCode','firmwareVars'),map(asset,(self.installer,self.drivers,self.firmware_code,self.firmware_vars))))}
