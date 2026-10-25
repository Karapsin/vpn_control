"""Unexposed private-seed ejection and selected-file reader metadata gates.

No capability is granted here. The fixed ejection primitive must execute inside
the original source-owned selected-manager/VM lock. A zero-reader ROOT witness
and renewed guest admission remain mandatory before bootstrap can close.
"""
import inspect
import hashlib
import json
import re
import stat
import time
import weakref
from pathlib import PurePosixPath
from uuid import UUID,uuid5
from xml.etree import ElementTree as ET

from . import durable_remote_job as jobs
from . import readiness_windows_managed_create as creator
from . import readiness_windows_creator_registry as registry
from . import readiness_windows_remote as packets

_EXECUTING_CODE=inspect.currentframe().f_code
_ORIGINALS=weakref.WeakKeyDictionary()
QUALIFIED_RECOVERIES=frozenset()


def _need(value):
    if not value:raise ValueError('windows_seed_original_unresolved')


def _uuid(value):
    try:return type(value)is str and str(UUID(value))==value
    except (ValueError,TypeError,AttributeError):return False


def _pin(value,n):return type(value)is list and len(value)==n and all(type(item)is int and item>=0 for item in value)


class SeedOriginal:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_seed_original_opaque')
    def __reduce__(self):raise TypeError('windows_seed_original_opaque')
    def as_dict(self):return _body(self)[0]


def original(program,handle,binding):
    """Join the actual minted creator to its immutable local namespace handle."""
    _need(type(program)is jobs.Program and program in creator._CREATE_PROGRAMS and type(handle)is registry.CreatorHandle)
    ref,job,expected=creator._CREATE_PROGRAMS[program];_need(ref()is program)
    record=handle.guard();plan=creator._CREATE_PLANS[program];namespace=creator._CREATE_NAMESPACES[program]
    packets.validate_binding(binding)
    _need(record['plan']==plan and record['namespace']==namespace and record['hostBinding']==expected['binding']
        and registry._scope(binding)==record['scope'])
    rid=hashlib.sha256(b'private-credential-seed-detach-v1').hexdigest();op=str(uuid5(UUID(binding['spec']['deploymentId']),rid))
    body={'schemaVersion':1,'kind':'windows-private-seed-original-v1','binding':binding,'creatorNamespace':namespace,
        'creatorOperationId':plan['operationId'],'creatorExpected':expected,'creatorJob':job,'operationId':op,'recoveryId':rid,
        'seedPath':binding['spec']['root']+'/seed.iso','seedAlias':'ua-vpn-control-credential-seed','ordinarySigninAllowed':False,'replayAllowed':False}
    result=object.__new__(SeedOriginal);_ORIGINALS[result]=(program,handle,json.loads(json.dumps(body)),None);return result


def _literals(source,keys):
    import ast
    found={}
    for node in ast.parse(source).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in keys:
            key=node.targets[0].id;_need(key not in found);found[key]=ast.literal_eval(node.value)
    _need(set(found)==set(keys));return found


def _body(value):
    _need(type(value)is SeedOriginal and value in _ORIGINALS)
    program,handle,body,retained=_ORIGINALS[value];record=handle.guard()
    _need(type(body)is dict and set(body)=={'schemaVersion','kind','binding','creatorNamespace','creatorOperationId','creatorExpected','creatorJob',
        'operationId','recoveryId','seedPath','seedAlias','ordinarySigninAllowed','replayAllowed'})
    _need(type(body['schemaVersion'])is int and body['schemaVersion']==1 and body['kind']=='windows-private-seed-original-v1'
        and body['ordinarySigninAllowed']is False and body['replayAllowed']is False)
    packets.validate_binding(body['binding']);_need(registry._scope(body['binding'])==record['scope'])
    expected=body['creatorExpected'];ns=body['creatorNamespace'];plan=record['plan']
    _need(ns==record['namespace']and expected['binding']==record['hostBinding']and body['creatorOperationId']==plan['operationId']
        and body['creatorJob']==ns['root']+'/'+plan['operationId']and expected['operationId']==plan['operationId']
        and expected['rootGeneration']==ns['generation']and expected['admissionsGeneration']==ns['admissionsGeneration']
        and expected['programSha256']==program.digest and expected['streamLimit']==program.stream_limit and program.purpose=='windows-managed-first-create')
    constants=_literals(program.source,{'PLAN','CREATOR_NAMESPACE','CREATOR_HOST_BINDING','CREATOR_OWNER_SOURCE'})
    owner=constants['CREATOR_OWNER_SOURCE']
    _need(constants['PLAN']==plan and constants['CREATOR_NAMESPACE']==ns and constants['CREATOR_HOST_BINDING']==record['hostBinding']
        and type(owner)is bytes and hashlib.sha256(owner).hexdigest()==ns['marker']['ownerSourceSha256'])
    rid=hashlib.sha256(b'private-credential-seed-detach-v1').hexdigest();machine=body['binding']['spec']['deploymentId']
    _need(body['recoveryId']==rid and body['operationId']==str(uuid5(UUID(machine),rid))and body['seedPath']==body['binding']['spec']['root']+'/seed.iso'
        and body['seedAlias']=='ua-vpn-control-credential-seed')
    if retained is None:
        _need(program in creator._CREATE_PROGRAMS and creator._CREATE_PROGRAMS[program][0]()is program
            and creator._CREATE_PROGRAMS[program][2]==expected)
    else:
        from . import readiness_windows_host_jobs as host
        retained_record,retained_source,_=host._load(retained)
        captured=_literals(retained_source,{'SEED_ORIGINAL','SEED_CREATOR_SOURCE','SEED_CREATOR_OWNER'})
        _need(captured=={'SEED_ORIGINAL':body,'SEED_CREATOR_SOURCE':program.source,'SEED_CREATOR_OWNER':owner}
            and retained_record['operationId']==body['operationId']and retained_record['purpose']=='windows-private-seed-eject')
    return json.loads(json.dumps(body)),program.source,owner


def system_source(setup,machine,nonce):
    """SYSTEM/setup/agent/account/zero interactive users, no private input."""
    from . import readiness_windows_guest as guest
    from .windows_vm_unattend import parse_setup
    setup=parse_setup(setup);_need(_uuid(machine)and _uuid(nonce))
    return "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"+\
        "if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'SYSTEM_REQUIRED'}\n"+\
        "Add-Type -TypeDefinition @'\n"+guest.WTS_NATIVE+"\n'@\n$ExpectedUser="+repr(setup['user'])+"\n$Machine="+repr(machine)+"\n$Nonce="+repr(nonce)+r'''
$computer=Get-CimInstance Win32_ComputerSystemProduct
$os=Get-CimInstance Win32_OperatingSystem
$state=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
$image=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
$user=Get-LocalUser -Name $ExpectedUser
$admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|ForEach-Object {$_.SID.Value})
$users=@(Get-LocalGroupMember -SID 'S-1-5-32-545'|ForEach-Object {$_.SID.Value})
$service=Get-CimInstance Win32_Service -Filter "Name='qemu-ga'"
$ready=Get-Content -LiteralPath (Join-Path $env:ProgramData 'VpnControlFixture\ready.json') -Raw|ConvertFrom-Json
$interactive=0
foreach($session in [SessionFacts]::All()){
 if($session.Id -eq 0){continue}
 $info=[SessionFacts]::Read([UInt32]$session.Id)
 if(-not [String]::IsNullOrEmpty($info.Data.User)){$interactive++}
}
$result=@{nonce=$Nonce;machine=$computer.UUID.ToLowerInvariant();boot=$os.LastBootUpTime.ToUniversalTime().ToString('o');principal='S-1-5-18';account=$user.SID.Value;ordinary=($user.Enabled -and $admins -notcontains $user.SID.Value -and $users -contains $user.SID.Value);setupComplete=($state.SystemSetupInProgress -eq 0 -and $state.OOBEInProgress -eq 0 -and $image.ImageState -eq 'IMAGE_STATE_COMPLETE');agentReady=($service.State -eq 'Running' -and $service.StartMode -eq 'Auto' -and $service.ProcessId -gt 0 -and $ready.state -eq 'ready' -and $ready.principal -eq [Security.Principal.WindowsIdentity]::GetCurrent().Name);interactiveUsers=$interactive}
[Console]::WriteLine(($result|ConvertTo-Json -Compress))
'''


def validate_system(value,machine,nonce):
    _need(type(value)is dict and set(value)=={'nonce','machine','boot','principal','account','ordinary','setupComplete','agentReady','interactiveUsers'}
        and value['nonce']==nonce and value['machine']==machine and value['principal']=='S-1-5-18'
        and value['ordinary']is True and value['setupComplete']is True and value['agentReady']is True
        and type(value['interactiveUsers'])is int and value['interactiveUsers']==0
        and type(value['account'])is str and re.fullmatch(r'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',value['account'])is not None
        and type(value['boot'])is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z',value['boot'])is not None)
    return json.loads(json.dumps(value))


def _seed_graph(raw,seed_path,alias,*,attached):
    """Public XML only; selected seed medium and exact unrelated device graph."""
    from xml.etree import ElementTree as ET
    def need(value):
        if not value:raise ValueError('windows_seed_device_graph_unresolved')
    need(type(raw)is str and 0<len(raw.encode())<=262144);tree=ET.fromstring(raw)
    for node in tree.iter():need(not any('password'in key.lower()or key.lower().startswith('passwd')for key in node.attrib))
    devices=tree.find('devices');need(devices is not None)
    found=[disk for disk in devices.findall('disk')if disk.find('alias')is not None and disk.find('alias').get('name')==alias]
    need(len(found)==1);selected=found[0]
    need(selected.get('device')=='cdrom'and selected.get('type')=='file'and selected.find('readonly')is not None
        and selected.find('target').get('dev')=='sdd'and selected.find('target').get('bus')=='sata')
    sources=selected.findall('source');need(len(sources)<=1)
    if attached:need(len(sources)==1 and sources[0].get('file')==seed_path)
    else:need(not sources or not sources[0].get('file'))
    for disk in devices.findall('disk'):
        if disk is not selected:need(all(item.get('file')!=seed_path for item in disk.findall('source')))
    eject=ET.fromstring(ET.tostring(selected))
    for node in list(eject.findall('source')):eject.remove(node)
    devices.remove(selected)
    return ET.tostring(tree,encoding='unicode'),ET.tostring(eject,encoding='unicode')


def _eject_selected(expected,domain,flags,read,save,guard,system_probe,seed_generation):
    """Fixed primitive for the original durable selected-manager owner only.

    The caller's source-owned guard holds exact VM intent flock, manager peer,
    QEMU generation, original creator packet/source and private seed inode.
    Lost ACK never submits the device update again.
    """
    from xml.etree import ElementTree as ET
    def need(value):
        if not value:raise ValueError('windows_seed_ejection_unresolved')
    prefix='private-seed-'+expected['operationId'];guard()
    need(domain.UUIDString()==expected['binding']['spec']['deploymentId']and domain.name()==expected['binding']['domain'])
    prior=read(prefix+'.intent.json',missing=True)
    if prior is None:
        proof=system_probe();validate_system(proof,expected['binding']['spec']['deploymentId'],proof['nonce'])
        inactive=domain.XMLDesc(flags['inactive']);live=domain.XMLDesc(0)
        # Validate selected artifacts/hardware and public graph before hash.
        digest=creator.validate_canonical_xml(inactive,expected['binding']['spec'],expected['binding']['domain'])
        need(digest==expected['binding']['xmlSha256'])
        plain_i,eject=_seed_graph(inactive,expected['seedPath'],expected['seedAlias'],attached=True)
        plain_l,_=_seed_graph(live,expected['seedPath'],expected['seedAlias'],attached=True)
        intent={'schemaVersion':1,'kind':'windows-private-seed-eject-v1','operationId':expected['operationId'],'machine':expected['binding']['spec']['deploymentId'],
            'creatorOperationId':expected['creatorOperationId'],'seedPath':expected['seedPath'],'seedGeneration':list(seed_generation()),
            'system':proof,'otherInactive':plain_i,'otherLive':plain_l,'eject':eject,'replayAllowed':False}
        guard();save(prefix+'.intent.json',intent)
        # Intent is durable before the only manager effect; an exception never
        # authorizes another update, even if both graphs still show media.
        need(domain.XMLDesc(flags['inactive'])==inactive and domain.XMLDesc(0)==live)
        domain.updateDeviceFlags(eject,flags['live']|flags['config'])
        guard();save(prefix+'.ack.json',{'operationId':expected['operationId'],'replayAllowed':False})
    else:
        intent=prior
        need(intent['kind']=='windows-private-seed-eject-v1'and intent['operationId']==expected['operationId']
            and intent['machine']==expected['binding']['spec']['deploymentId']and intent['creatorOperationId']==expected['creatorOperationId']
            and intent['seedPath']==expected['seedPath']and intent['seedGeneration']==list(seed_generation())and intent['replayAllowed']is False)
    guard()
    inactive,_=_seed_graph(domain.XMLDesc(flags['inactive']),expected['seedPath'],expected['seedAlias'],attached=False)
    live,_=_seed_graph(domain.XMLDesc(0),expected['seedPath'],expected['seedAlias'],attached=False)
    need(inactive==intent['otherInactive']and live==intent['otherLive'])
    fresh=system_probe();validate_system(fresh,intent['machine'],fresh['nonce'])
    need(fresh['boot']==intent['system']['boot']and fresh['account']==intent['system']['account'])
    guard()
    return {'kind':'windows-private-seed-ejected-pending-v1','operationId':expected['operationId'],'machine':intent['machine'],
        'boot':fresh['boot'],'account':fresh['account'],'seedGeneration':intent['seedGeneration'],'readersRequired':True,'ordinarySigninAllowed':False,'replayAllowed':False}


def eject_once(original,domain,flags,read,save,guard,system_probe,seed_generation):
    """Internal primitive: only an actual opaque original, always pending."""
    expected,_,_=_body(original)
    return _eject_selected(expected,domain,flags,read,save,guard,system_probe,seed_generation)


def validate_read_request(value):
    _need(type(value)is dict and set(value)=={'schemaVersion','kind','machine','hostBoot','uid','vmRoot','rootIdentity','seedGeneration','creator','manager','actor','detachment','mutable','managerSocket'}
        and type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['kind']=='windows-private-seed-readers-v1'
        and _uuid(value['machine'])and _uuid(value['hostBoot'])and type(value['uid'])is int and value['uid']>0
        and creator.lifecycle._canonical(value['vmRoot'])and _pin(value['rootIdentity'],5)and value['rootIdentity'][2]==stat.S_IFDIR|0o700
        and value['rootIdentity'][3]==value['uid']and _pin(value['seedGeneration'],9)and value['seedGeneration'][2]==stat.S_IFREG|0o600
        and value['seedGeneration'][3]==value['uid']and value['seedGeneration'][5]==1)
    c=value['creator'];_need(type(c)is dict and set(c)=={'root','rootGeneration','operationId','binding','programSha256','ownerSourceSha256','artifacts'}
        and c['root']==str(PurePosixPath(value['vmRoot']).parent/'.cache/vpn-control-fixture-creators'/value['machine'])
        and _pin(c['rootGeneration'],2)and _uuid(c['operationId'])and creator.lifecycle._digest(c['programSha256'])and creator.lifecycle._digest(c['ownerSourceSha256']))
    b=jobs.MachineBinding.from_dict(c['binding']);_need(b.account==str(value['uid'])and UUID(b.boot)==UUID(value['hostBoot']))
    _need(type(c['artifacts'])is dict and set(c['artifacts'])=={'intent.json','program.py','owner.py','terminal.json'}and all(_pin(row,9)and row[2]==stat.S_IFREG|0o600 and row[3]==value['uid']and row[5]==1 for row in c['artifacts'].values()))
    for name in ('manager','actor'):
        actor=value[name];_need(type(actor)is dict and set(actor)=={'pid','birth','uid','executableGeneration'}and all(type(actor[k])is int and actor[k]>0 for k in ('pid','birth'))
            and actor['uid']==value['uid']and _pin(actor['executableGeneration'],9))
    _need(type(value['mutable'])is dict and set(value['mutable'])=={'disk.qcow2','uefi-vars.fd'}
        and all(_pin(row,5)and row[2]==stat.S_IFREG|0o600 and row[3]==value['uid']for row in value['mutable'].values()))
    wire=value['managerSocket'];_need(type(wire)is dict and set(wire)=={'path','inode','identity'}
        and wire['path']==str(PurePosixPath(value['vmRoot']).parent/'.cache/libvirt/virtqemud-sock')
        and type(wire['inode'])is int and wire['inode']>0 and _pin(wire['identity'],5)
        and stat.S_ISSOCK(wire['identity'][2])and wire['identity'][3]==value['uid'])
    d=value['detachment'];_need(type(d)is dict and set(d)=={'operationId','intentGeneration','boot','account','hostOriginal'}and d['operationId']==str(uuid5(UUID(value['machine']),hashlib.sha256(b'private-credential-seed-detach-v1').hexdigest()))
        and _pin(d['intentGeneration'],9)and type(d['boot'])is str and type(d['account'])is str)
    from . import readiness_windows_host_jobs as host
    h=d['hostOriginal'];_need(type(h)is dict and set(h)=={'namespace','operationId','recoveryId','programSha256','ownerSourceSha256','artifacts'})
    ns=host._namespace(h['namespace']);_need(ns['vmRoot']==value['vmRoot']and ns['binding']['machine']==value['machine']
        and UUID(ns['binding']['boot'])==UUID(value['hostBoot'])and ns['binding']['account']==str(value['uid'])
        and h['operationId']==d['operationId']and h['recoveryId']==hashlib.sha256(b'private-credential-seed-detach-v1').hexdigest()
        and creator.lifecycle._digest(h['programSha256'])and h['ownerSourceSha256']==ns['ownerSourceSha256']
        and type(h['artifacts'])is dict and set(h['artifacts'])=={'intent.json','program.py','owner.py','terminal.json'}
        and all(_pin(row,9)and row[2]==stat.S_IFREG|0o600 and row[3]==value['uid']and row[5]==1 for row in h['artifacts'].values()))
    return json.loads(json.dumps(value,allow_nan=False))


def _fd_names(directory_fd):
    import ctypes,struct,os
    def need(value):
        if not value:raise ValueError('windows_seed_reader_visibility_missing')
    libc=ctypes.CDLL(None,use_errno=True);read=libc.getdents64
    read.argtypes=(ctypes.c_int,ctypes.c_void_p,ctypes.c_size_t);read.restype=ctypes.c_ssize_t
    os.lseek(directory_fd,0,os.SEEK_SET);buffer=ctypes.create_string_buffer(65536);names=[]
    while True:
        count=read(directory_fd,buffer,len(buffer));need(count>=0)
        if count==0:break
        data=buffer.raw[:count];offset=0
        while offset<count:
            need(offset+19<=count);length=struct.unpack_from('=H',data,offset+16)[0]
            need(length>=20 and offset+length<=count)
            name=data[offset+19:offset+length].split(b'\0',1)[0].decode('ascii')
            if name not in {'.','..'}:need(name.isdecimal());names.append(name)
            offset+=length
        need(len(names)<=65536)
    return sorted(names)

def _mapped_inode(base,seed_identity):
    """Proc mapping metadata only; private mapped bytes/paths never leave RAM."""
    import os,re
    with (base/'maps').open('rb')as stream:raw=stream.read(4*1024**2+1)
    if len(raw)>4*1024**2:raise ValueError('windows_seed_reader_visibility_missing')
    found=False
    for line in raw.splitlines():
        fields=line.split(None,5)
        if len(fields)<5 or re.fullmatch(rb'[0-9a-f]+-[0-9a-f]+',fields[0])is None or re.fullmatch(rb'[r-][w-][x-][ps]',fields[1])is None or re.fullmatch(rb'[0-9a-f]+',fields[2])is None or re.fullmatch(rb'[0-9a-f]+:[0-9a-f]+',fields[3])is None or not fields[4].isdigit():raise ValueError('windows_seed_reader_visibility_missing')
        major,minor=(int(part,16)for part in fields[3].split(b':'))
        if (os.makedev(major,minor),int(fields[4]))==tuple(seed_identity[:2]):found=True
    return found


def _regular_file_census(seed_identity,deadline):
    import os,pathlib,time
    def need(value):
        if not value:raise ValueError('windows_seed_reader_visibility_missing')
    def process(pid):
        base=pathlib.Path('/proc')/str(pid);raw=(base/'stat').read_text();words=raw[raw.rfind(')')+2:].split()
        need(len(words)>19);return int(words[19]),words[0],base.stat().st_uid
    rows=[];generations=[];paths=list(pathlib.Path('/proc').iterdir());need(len(paths)<=131072)
    for base in paths:
        if not base.name.isdigit():continue
        need(time.monotonic()<deadline);pid=int(base.name);directory_fd=None
        try:
            birth,state,uid=process(pid)
            if state in {'Z','X'}:continue
            directory_fd=os.open(base/'fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            names=_fd_names(directory_fd);found=False
            for name in names:
                info=os.stat(base/'fd'/name)
                if (info.st_dev,info.st_ino)==tuple(seed_identity[:2]):found=True
            mapped=_mapped_inode(base,seed_identity);found=found or mapped
            after,state_after,uid_after=process(pid)
            need(names==_fd_names(directory_fd)and (after,uid_after)==(birth,uid)and state_after not in {'Z','X'})
            generations.append((pid,birth,uid))
            if found:rows.append({'pid':pid,'birth':birth,'uid':uid})
        except FileNotFoundError:need(not base.exists())
        finally:
            if directory_fd is not None:os.close(directory_fd)
        # PermissionError is never an empty process or empty FD list.
    return sorted(rows,key=lambda row:row['pid']),sorted(generations)

def _observe_seed_readers(request,creator_source,owner_source,detach_source,detach_owner):
    """ROOT metadata only. No seed read, socket connect, signal or power."""
    import ast,json,os,pathlib,stat,time
    def need(value):
        if not value:raise ValueError('windows_seed_reader_visibility_missing')
    def pin(i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
    def structure(i):return pin(i)[:5]
    def process(pid):
        base=pathlib.Path('/proc')/str(pid);raw=(base/'stat').read_text();words=raw[raw.rfind(')')+2:].split()
        need(len(words)>19);return int(words[19]),words[0],base.stat().st_uid
    need(os.geteuid()==0 and os.getuid()==0 and os.environ.get('SUDO_UID')==str(request['uid']))
    deadline=time.monotonic()+20;root=pathlib.Path(request['vmRoot']);seed=root/'seed.iso';held=[]
    def private_read(path,wanted,expected=None):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);held.append(fd);info=os.fstat(fd)
        need(pin(info)==pin(os.lstat(path))==wanted and wanted[3]==request['uid']and wanted[2]==stat.S_IFREG|0o600 and wanted[5]==1 and wanted[6]<=8*1024**2)
        raw=os.read(fd,wanted[6]+1);need(len(raw)==wanted[6]and pin(os.fstat(fd))==pin(os.lstat(path))==wanted)
        if expected is not None:need(raw==expected)
        return raw
    def fence():
        need(time.monotonic()<deadline and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==request['hostBoot'])
        need(structure(os.lstat(root))==request['rootIdentity']and pin(os.lstat(seed))==request['seedGeneration'])
        for name,wanted in request['mutable'].items():need(structure(os.lstat(root/name))==wanted)
        for key,binary in (('manager','/usr/bin/virtqemud'),('actor','/usr/bin/qemu-system-x86_64')):
            row=request[key];birth,state,uid=process(row['pid']);need(birth==row['birth']and state not in {'Z','X'}and uid==row['uid']and pin(os.stat('/proc/'+str(row['pid'])+'/exe'))==row['executableGeneration'])
            need(os.path.realpath('/proc/'+str(row['pid'])+'/exe')==os.path.realpath(binary))
        wire=request['managerSocket'];need(structure(os.lstat(wire['path']))==wire['identity'])
        raw=pathlib.Path('/proc/net/unix').read_text();need(len(raw)<=1024**2)
        listeners=[line.split()for line in raw.splitlines()[1:]]
        need([int(v[6])for v in listeners if len(v)>=8 and v[-1]==wire['path']and v[3:6]==['00010000','0001','01']]==[wire['inode']])
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(parent);ancestors=[]
        for name in root.parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held.append(child);ancestors.append((parent,name,child,structure(os.fstat(child))));parent=child
        fence();c=request['creator'];directory=pathlib.Path(c['root'])
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(parent)
        for name in directory.parts[1:]:
            child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held.append(child);ancestors.append((parent,name,child,structure(os.fstat(child))));parent=child
        need([os.fstat(parent).st_dev,os.fstat(parent).st_ino]==c['rootGeneration'])
        job=directory/c['operationId'];artifacts=c['artifacts']
        private_read(job/'program.py',artifacts['program.py'],creator_source);private_read(job/'owner.py',artifacts['owner.py'],owner_source)
        intent=json.loads(private_read(job/'intent.json',artifacts['intent.json']));terminal=json.loads(private_read(job/'terminal.json',artifacts['terminal.json']))
        need(intent['operationId']==c['operationId']and intent['binding']==c['binding']and intent['purpose']=='windows-managed-first-create'and intent['programSha256']==c['programSha256']
            and terminal['operationId']==c['operationId']and terminal['binding']==c['binding']and terminal['programSha256']==c['programSha256']
            and terminal['generation']==intent['generation']and terminal['exitCode']==0 and terminal['streamsClosed']is True)
        plans=[ast.literal_eval(n.value)for n in ast.parse(creator_source).body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='PLAN']
        need(len(plans)==1 and plans[0]['binding']['spec']['deploymentId']==request['machine']and plans[0]['binding']['spec']['root']==request['vmRoot']and plans[0]['operationId']==c['operationId'])
        name='private-seed-'+request['detachment']['operationId']+'.intent.json'
        detached=json.loads(private_read(root/name,request['detachment']['intentGeneration']))
        need(detached['machine']==request['machine']and detached['creatorOperationId']==c['operationId']and detached['seedGeneration']==request['seedGeneration']
            and detached['system']['boot']==request['detachment']['boot']and detached['system']['account']==request['detachment']['account'])
        # Independently join the actual retained ejection HOST Program. A
        # controller exit0 or a detached-flag DTO cannot close bootstrap.
        h=request['detachment']['hostOriginal'];ns=h['namespace'];j=pathlib.Path(ns['root'])/h['operationId']
        need([os.lstat(ns['root']).st_dev,os.lstat(ns['root']).st_ino]==ns['generation'])
        need([os.lstat(pathlib.Path(ns['root'])/'admissions').st_dev,os.lstat(pathlib.Path(ns['root'])/'admissions').st_ino]==ns['admissionGeneration'])
        private_read(j/'program.py',h['artifacts']['program.py'],detach_source);private_read(j/'owner.py',h['artifacts']['owner.py'],detach_owner)
        detached_intent=json.loads(private_read(j/'intent.json',h['artifacts']['intent.json']))
        detached_terminal=json.loads(private_read(j/'terminal.json',h['artifacts']['terminal.json']))
        need(detached_intent['operationId']==h['operationId']and detached_intent['binding']==ns['binding']
            and detached_intent['purpose']=='windows-private-seed-eject'and detached_intent['programSha256']==h['programSha256']
            and all(detached_terminal[key]==detached_intent[key]for key in ('operationId','binding','programSha256','generation'))
            and detached_terminal['exitCode']==0 and detached_terminal['streamsClosed']is True)
        import types,sys
        module=types.ModuleType('fixed_seed_original_result');sys.modules[module.__name__]=module
        exec(compile(detach_owner,'exact original seed HOST owner','exec'),module.__dict__);module.owner_source=lambda:detach_owner
        status,out,err=module.collect(pathlib.Path(ns['root']),h['operationId'],module.MachineBinding.from_dict(ns['binding']),generation=tuple(ns['generation']))
        need(status['state']=='terminal'and not err);pending=json.loads(out)
        need(pending['kind']=='windows-private-seed-ejected-pending-v1'and pending['operationId']==h['operationId']
            and pending['machine']==request['machine']and pending['boot']==request['detachment']['boot']
            and pending['account']==request['detachment']['account']and pending['seedGeneration']==request['seedGeneration']
            and pending['readersRequired']is True and pending['ordinarySigninAllowed']is False and pending['replayAllowed']is False)
        # getdents64 on an actual held directory avoids a transient self-FD
        # created/closed by listdir. Permission errors never become emptiness.
        # Independently close selected manager socket ownership and selected
        # QEMU disk/NVRAM ownership; no protocol connection or seed read.
        for key in ('manager','actor'):
            row=request[key];base=pathlib.Path('/proc')/str(row['pid']);fd=os.open(base/'fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                names=_fd_names(fd)
                if key=='manager':need(any(os.readlink(base/'fd'/name)=='socket:['+str(request['managerSocket']['inode'])+']'for name in names))
                else:
                    seen=[structure(os.stat(base/'fd'/name))for name in names]
                    need(all(wanted in seen for wanted in request['mutable'].values()))
                    args=(base/'cmdline').read_bytes();need(len(args)<=262144 and request['machine'].encode()in args.split(b'\0'))
                need(names==_fd_names(fd))
            finally:os.close(fd)
        first,actors1=_regular_file_census(request['seedGeneration'],deadline);fence();second,actors2=_regular_file_census(request['seedGeneration'],deadline);fence();need(first==second and actors1==actors2)
        for parent,name,fd,wanted in ancestors:need(structure(os.fstat(fd))==structure(os.stat(name,dir_fd=parent,follow_symlinks=False))==wanted)
        return {'complete':True,'holders':second}
    finally:
        for fd in reversed(held):os.close(fd)


def _canonical_owner():
    """ROOT code authority is current reviewed source, never a retained hash."""
    import ast,types
    from pathlib import Path
    raw=jobs.owner_source();_need(type(raw)is bytes and raw==Path(jobs.__file__).read_bytes())
    compiled=compile(raw,str(Path(jobs.__file__)),'exec',dont_inherit=True)
    functions={node.name for node in ast.parse(raw).body if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
    codes={code.co_name:code for code in compiled.co_consts if isinstance(code,types.CodeType)and code.co_name in functions}
    _need(set(codes)==functions)
    for name in functions:
        actual=getattr(jobs,name,None)
        _need(type(actual)is types.FunctionType and actual.__code__==codes[name])
    return raw


def _reader_original_request(original,request):
    body,source,owner=_body(original);request=validate_read_request(request)
    from . import readiness_windows_host_jobs as host
    detached=original_ejection(original);record,detach_source,detach_owner=host._load(detached)
    h=request['detachment']['hostOriginal']
    _need(all(h[key]==record[key]for key in ('namespace','operationId','recoveryId','programSha256'))and h['ownerSourceSha256']==record['namespace']['ownerSourceSha256'])
    _need(request['machine']==body['binding']['spec']['deploymentId']and request['vmRoot']==body['binding']['spec']['root']
        and request['hostBoot']==body['binding']['context']['hostBootId']and request['creator']['operationId']==body['creatorOperationId']
        and request['creator']['programSha256']==_ORIGINALS[original][0].digest and request['creator']['binding']==body['creatorExpected']['binding']
        and request['creator']['ownerSourceSha256']==body['creatorNamespace']['marker']['ownerSourceSha256']
        and request['creator']['root']==body['creatorNamespace']['root']
        and request['creator']['rootGeneration']==body['creatorNamespace']['generation']==body['creatorExpected']['rootGeneration'])
    canonical=_canonical_owner()
    if owner!=canonical or detach_owner!=canonical:raise ValueError('windows_seed_privileged_owner_version_unqualified')
    return body,source,owner,request,detach_source,detach_owner


def reader_program(original,request,*,validity_ns=30_000_000_000):
    body,source,owner,request,detach_source,detach_owner=_reader_original_request(original,request)
    _need(type(validity_ns)is int and 0<validity_ns<=30_000_000_000)
    raw=inspect.getsource(_fd_names)+'\n'+inspect.getsource(_mapped_inode)+'\n'+inspect.getsource(_regular_file_census)+'\n'+inspect.getsource(_observe_seed_readers)+'\nREQUEST='+repr(request)+'\nCREATOR_SOURCE='+repr(source)+'\nOWNER_SOURCE='+repr(owner)+'\nDETACH_SOURCE='+repr(detach_source)+'\nDETACH_OWNER='+repr(detach_owner)+'\nVALIDITY_NS='+repr(validity_ns)+'''
import json,time
try:
 started=time.monotonic_ns();result=_observe_seed_readers(REQUEST,CREATOR_SOURCE,OWNER_SOURCE,DETACH_SOURCE,DETACH_OWNER);observed=time.monotonic_ns()
 deadline=started+VALIDITY_NS
 if observed>deadline:raise ValueError('windows_seed_reader_visibility_missing')
 result.update(observedNs=observed,deadlineNs=deadline);print(json.dumps(result,sort_keys=True,separators=(',',':')))
except BaseException:
 print('{"complete":false,"holders":[],"observedNs":0,"deadlineNs":0}');raise SystemExit(1)
'''
    compile(raw,'fixed selected private-seed reader metadata','exec');return raw.encode()


_READERS=weakref.WeakKeyDictionary()


def validate_reader_result(value):
    _need(type(value)is dict and set(value)=={'complete','holders','observedNs','deadlineNs'}and value['complete']is True
        and type(value['holders'])is list and len(value['holders'])<=131072
        and all(type(value[k])is int and value[k]>0 for k in ('observedNs','deadlineNs'))
        and value['observedNs']<=value['deadlineNs']<=value['observedNs']+30_000_000_000)
    seen=set()
    for row in value['holders']:
        _need(type(row)is dict and set(row)=={'pid','uid','birth'}and all(type(row[k])is int and row[k]>0 for k in ('pid','birth'))
            and type(row['uid'])is int and row['uid']>=0 and row['pid']not in seen);seen.add(row['pid'])
    return json.loads(json.dumps(value))


class ReaderWitness:
    """Live protected observer only. A retained JSON result is historical."""
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_seed_reader_observer_required')
    def __init_subclass__(cls,**kwargs):raise TypeError('windows_seed_reader_observer_required')
    def __reduce__(self):raise TypeError('windows_seed_reader_observer_required')
    def _state(self):
        _need(type(self)is ReaderWitness and self in _READERS);return _READERS[self]
    @property
    def request(self):return json.loads(self._state()['request'])
    @property
    def result(self):return json.loads(self._state()['result'])
    def validate(self,original):
        state=self._state();_need(state['original']is original and time.monotonic()<state['deadline'])
        _body(original)
        for guard in state['guards']:guard()
        _need(time.monotonic()<state['deadline']);return validate_reader_result(self.result)
    def require_clear(self,original):
        result=self.validate(original)
        if result['holders']:raise ValueError('windows_seed_readers_active')
        return result
    def consume(self,original,operation):
        state=self._state();self.require_clear(original);_need(state['consumedBy']is None and operation==original.as_dict()['operationId'])
        state['consumedBy']=operation
    def guard_dispatch(self,original,admission):
        state=self._state();_need(state['consumedBy']==admission.operation_identity)
        from . import ssh_dispatch_admission
        return ssh_dispatch_admission.add_dispatch_guard(admission,lambda:self.require_clear(original))
    def receipt(self):
        self._state()
        return {'kind':'historical-private-seed-reader-observation-v1','request':self.request,'result':self.result}


from contextlib import contextmanager


@contextmanager
def observe_readers(root,host,original,request,credential_file,*,guard,deadline=None):
    """Protected HOST stdin only; no TPM/guest connection or seed byte reads."""
    import math,subprocess
    from . import ssh_transport as transport
    from . import windows_vm_deploy as deploy
    from .private_credential_file import SecretFile
    body,_,_,request,_,_=_reader_original_request(original,request)
    _need(host==body['binding']['spec']['host'])
    deadline=time.monotonic()+180 if deadline is None else deadline
    _need(type(deadline)in (int,float)and math.isfinite(deadline)and deadline>time.monotonic())
    private_input=None;witness=None;yielded=False
    def remaining():
        value=min(60,deadline-time.monotonic());_need(value>0);return value
    try:
        with transport.admitted_transport(root,host,body['operationId'],deadline=deadline)as admitted:
            with deploy.direct.Guard(root,host=host)as authority:
                guard();_body(original);budget=min(30_000_000_000,max(1,int(remaining()*1_000_000_000)))
                source=reader_program(original,request,validity_ns=budget)
                command=('sudo','-S','-p','','--','python3','-I','-B','-c','exec('+repr(source.decode())+')')
                argv=transport.build_ssh_argv(authority.config,host,60,command=command)
                with SecretFile(str(credential_file))as credential:
                    credential.guard();admitted.revalidate();authority.guard();guard();_body(original)
                    private_input=credential.text.encode()+b'\n'
                    reply=transport.run_ssh(argv,input=private_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining(),cwd=root)
                    credential.guard();streams=(reply.stdout,reply.stderr)
                    _need(all(type(value)is bytes and len(value)<=1024**2 for value in streams)
                        and not any(credential.text.encode()in value for value in streams))
                _need(reply.returncode==0 and not reply.stderr)
                result=validate_reader_result(json.loads(reply.stdout,object_pairs_hook=transport._reject_duplicate_keys))
                admitted.revalidate();authority.guard();guard();_body(original)
                witness=object.__new__(ReaderWitness)
                _READERS[witness]={'original':original,'request':json.dumps(request,sort_keys=True),'result':json.dumps(result,sort_keys=True),
                    'guards':(admitted.revalidate,authority.guard,guard),'deadline':min(deadline,time.monotonic()+30),'consumedBy':None}
                witness.validate(original);private_input=None;yielded=True
                yield witness
    except Exception:
        if yielded:raise
        raise ValueError('windows_seed_reader_observation_unknown')from None
    finally:
        private_input=None
        if witness is not None:_READERS.pop(witness,None)


def _reader_clock_guard(request,result):
    """Execute on selected HOST immediately before and after closure admission."""
    import os,pathlib,time
    def need(value):
        if not value:raise ValueError('windows_seed_reader_witness_expired')
    need(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==request['hostBoot']
        and result['observedNs']<=time.monotonic_ns()<=result['deadlineNs']and result['complete']is True and not result['holders'])
    path=pathlib.Path(request['vmRoot'])/'seed.iso';info=os.lstat(path)
    need([info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]==request['seedGeneration'])


def final_reader_guard_source(original,witness):
    """No dispatch by itself; only a live consumed ROOT witness can compose it."""
    _need(type(witness)is ReaderWitness and witness._state()['consumedBy']==original.as_dict()['operationId'])
    result=witness.require_clear(original);request=witness.request
    source=inspect.getsource(_reader_clock_guard)+'\n_reader_clock_guard('+repr(request)+','+repr(result)+')\n'
    compile(source,'fixed original private-seed reader freshness gate','exec');return source.encode()


_EJECTION_PROGRAMS=weakref.WeakKeyDictionary()
_DETACHMENTS=weakref.WeakKeyDictionary()


def ejection_program(original,expected_actor,host_namespace):
    """Unexposed exact-manager original HOST Program, SYSTEM before any input."""
    from . import readiness_windows_host_jobs as host
    body,creator_source,owner_source=_body(original);binding=body['binding'];_need(_ORIGINALS[original][3]is None)
    _need(binding['provider']=='libvirt-windows'and type(expected_actor)is dict
        and set(expected_actor)=={'pid','startTicks','argv','commandSha256','executableGeneration'}
        and all(type(expected_actor[k])is int and expected_actor[k]>0 for k in ('pid','startTicks'))
        and type(expected_actor['argv'])is list and creator.lifecycle._digest(expected_actor['commandSha256'])
        and _pin(expected_actor['executableGeneration'],9))
    _need(type(host_namespace)is host.NamespaceHandle)
    ns=host_namespace.as_dict();bound=ns['binding']
    _need(ns['vmRoot']==binding['spec']['root']and bound['machine']==binding['spec']['deploymentId']
        and UUID(bound['boot'])==UUID(binding['context']['hostBootId'])
        and bound['target']=='windows-host:'+binding['spec']['host']+':'+binding['spec']['deploymentId'])
    source=packets.program(binding,'observe',body['operationId']).decode()
    marker='        state=machine_state()\n';_need(source.count(marker)==1)
    branch='''        require(PROVIDER=='libvirt-windows'and current_actor==SEED_ACTOR,'windows_seed_actor_changed')
        host_work=_lifecycle_host_work(operator_fd=lock)
        require(host_work['visibilityComplete']is True and host_work['idle']is True,'windows_seed_original_host_work_unknown')
        # This is the lexical original VM intent lock opened and held by the
        # reviewed packet. Never a public descriptor or ownership flag.
        def creator_guard():
            module,intent,owner,actual_source=_channel_identity(SEED_ORIGINAL['creatorJob'],SEED_ORIGINAL['creatorExpected'],SEED_CREATOR_OWNER,live=False)
            require(actual_source==SEED_CREATOR_SOURCE,'windows_seed_creator_source_changed')
            status,out,err=module.collect(pathlib.Path(SEED_ORIGINAL['creatorJob']).parent,SEED_ORIGINAL['creatorOperationId'],
                module.MachineBinding.from_dict(SEED_ORIGINAL['creatorExpected']['binding']),generation=tuple(SEED_ORIGINAL['creatorExpected']['rootGeneration']))
            require(status['state']=='terminal'and status['terminal']['exitCode']==0 and not err,'windows_seed_creator_not_terminal')
            reply=json.loads(out)
            require(reply.get('kind')=='windows-managed-first-create-pending-v1'and reply.get('state')=='postlaunch-observation-required'
                and reply.get('operationId')==SEED_ORIGINAL['creatorOperationId']and reply.get('machine')==SPEC['deploymentId']
                and reply.get('hostBoot')==CONTEXT['hostBootId']and reply.get('uri')==URI and reply.get('domain')==DOMAIN
                and reply.get('xmlSha256')==XML_SHA and reply.get('ordinarySigninAllowed')is False
                and reply.get('seedDetachRequired')is True and reply.get('replayAllowed')is False,'windows_seed_creator_unresolved')
        creator_guard()
        seed_record=read('credential-seed-custody.json')
        require(seed_record['operationId']==SEED_ORIGINAL['creatorOperationId']and seed_record['ordinarySigninAllowed']is False
            and seed_record['detachRequired']is True and seed_record['replayAllowed']is False,'windows_seed_custody_unknown')
        seed_pin=seed_record['files']['seed.iso']
        require(type(seed_pin)is list and len(seed_pin)==9,'windows_seed_custody_unknown')
        def seed_generation():
            row=list(generation(private(root/'seed.iso')))
            require(row==seed_pin,'windows_seed_custody_changed');return row
        def seed_guard():
            epoch();creator_guard();process(manager);process(SEED_ACTOR);seed_generation()
            require(current_actor==SEED_ACTOR and connection.getURI()==URI and domain.UUIDString()==SPEC['deploymentId']
                and domain.name()==DOMAIN and structure(os.lstat(SOCKET_PATH))==socket_pin,'windows_seed_target_changed')
            owns(SEED_ACTOR['pid'],root/'disk.qcow2');owns(SEED_ACTOR['pid'],root/'uefi-vars.fd')
            for name,pin in seed_record['files'].items():
                require(name in {'seed.iso','seed/Autounattend.xml'}and list(generation(private(root/name)))==pin,'windows_seed_custody_changed')
            intent_path=root/('private-seed-'+OPERATION+'.intent.json')
            if not os.path.lexists(intent_path):
                require(creator.validate_canonical_xml(domain.XMLDesc(libvirt.VIR_DOMAIN_XML_INACTIVE),SPEC,DOMAIN)==XML_SHA,'windows_seed_graph_changed')
            else:
                old=read(intent_path.name)
                require(old['operationId']==OPERATION and old['machine']==SPEC['deploymentId']and old['creatorOperationId']==SEED_ORIGINAL['creatorOperationId'],'windows_seed_original_unknown')
                for flags,key in ((libvirt.VIR_DOMAIN_XML_INACTIVE,'otherInactive'),(0,'otherLive')):
                    raw=domain.XMLDesc(flags)
                    try:plain,_=_seed_graph(raw,SEED_ORIGINAL['seedPath'],SEED_ORIGINAL['seedAlias'],attached=False)
                    except ValueError:plain,_=_seed_graph(raw,SEED_ORIGINAL['seedPath'],SEED_ORIGINAL['seedAlias'],attached=True)
                    require(plain==old[key],'windows_seed_graph_changed')
        # The usual RPC/script guard now recognizes only this original CD
        # transition, with every unrelated device graph remaining exact.
        vm_guard=seed_guard
        def system_probe():
            attached=not os.path.lexists(root/('private-seed-'+OPERATION+'.intent.json'))
            nonce=SEED_NONCES[0 if attached else 1]
            label='seed-system-before'if attached else'seed-system-after'
            proof=script(label,SEED_SYSTEM_SOURCES[0 if attached else 1])
            return validate_system(proof,SPEC['deploymentId'],nonce)
        def seed_read(name,missing=False):
            if missing and not os.path.lexists(root/name):return None
            return read(name)
        result=_eject_selected(SEED_ORIGINAL,domain,{'inactive':libvirt.VIR_DOMAIN_XML_INACTIVE,
            'live':libvirt.VIR_DOMAIN_AFFECT_LIVE,'config':libvirt.VIR_DOMAIN_AFFECT_CONFIG},seed_read,save,seed_guard,system_probe,seed_generation)
        seed_guard();print(json.dumps(result));return
'''
    start=source.index(marker);end=source.index('    except BaseException as error:',start)
    source=source[:start]+branch+source[end:]
    nonces=[str(uuid5(UUID(body['operationId']),value))for value in ('system-before','system-after')]
    constants={'SEED_ORIGINAL':body,'SEED_ACTOR':expected_actor,'SEED_NONCES':nonces,
        'SEED_SYSTEM_SOURCES':[system_source(binding['setup'],binding['spec']['deploymentId'],nonce)for nonce in nonces],
        'SEED_CREATOR_SOURCE':creator_source,'SEED_CREATOR_OWNER':owner_source}
    prefix=host.worker_inventory_definitions(host_namespace)+'\n'
    prefix+='import re,json,types\n'+'\n'.join(key+'='+repr(value)for key,value in constants.items())+'\n'
    prefix+=inspect.getsource(creator.host_machine)+'\n'+inspect.getsource(creator._creator_admission)+'\n'+inspect.getsource(creator._channel_identity)+'\n'
    prefix+=inspect.getsource(_need)+'\n'+inspect.getsource(validate_system)+'\n'+inspect.getsource(_seed_graph)+'\n'+inspect.getsource(_eject_selected)+'\n'
    prefix+=inspect.getsource(creator.validate_canonical_xml)+'\ncreator=types.SimpleNamespace(validate_canonical_xml=validate_canonical_xml)\n'
    result=host.sealed_program(jobs.Program('windows-private-seed-eject',(prefix+source).encode(),262144))
    _EJECTION_PROGRAMS[original]=result;return result


def attach_ejection(original,original_job):
    """Retain the actual opaque HOST owner, not a caller success projection."""
    from . import readiness_windows_host_jobs as host
    body,_,_=_body(original);record,source,_=host._load(original_job)
    _need(original in _EJECTION_PROGRAMS);expected=_EJECTION_PROGRAMS[original]
    namespace=record['namespace'];bound=namespace['binding'];binding=body['binding']
    _need(record['operationId']==body['operationId']and record['recoveryId']==body['recoveryId']
        and record['purpose']=='windows-private-seed-eject'and source==expected.source and record['programSha256']==expected.digest
        and namespace['vmRoot']==binding['spec']['root']and bound['machine']==binding['spec']['deploymentId']
        and UUID(bound['boot'])==UUID(binding['context']['hostBootId'])
        and bound['target']=='windows-host:'+binding['spec']['host']+':'+binding['spec']['deploymentId'])
    _DETACHMENTS[original]=original_job;return original_job


def original_ejection(original):
    from . import readiness_windows_host_jobs as host
    _need(type(original)is SeedOriginal and original in _DETACHMENTS)
    result=_DETACHMENTS[original];host._load(result);attach_ejection(original,result);return result


def request_program(original):
    """Pure selected HOST/manager facts after the original ejection terminal.

    No guest call, seed read, detach retry or provider start occurs here.
    Source is derived from the exact retained original owner, never a current
    replacement interpreted as authority for an earlier ejection.
    """
    from . import readiness_windows_host_jobs as host
    body,_,_=_body(original);actual=original_ejection(original);record,raw,owner=host._load(actual)
    source=raw.decode();marker="        result=_eject_selected(SEED_ORIGINAL,domain,{'inactive':libvirt.VIR_DOMAIN_XML_INACTIVE,\n            'live':libvirt.VIR_DOMAIN_AFFECT_LIVE,'config':libvirt.VIR_DOMAIN_AFFECT_CONFIG},seed_read,save,seed_guard,system_probe,seed_generation)\n        seed_guard();print(json.dumps(result));return\n"
    _need(source.count(marker)==1)
    branch='''        seed_guard()
        for flags in (0,libvirt.VIR_DOMAIN_XML_INACTIVE):
            _seed_graph(domain.XMLDesc(flags),SEED_ORIGINAL['seedPath'],SEED_ORIGINAL['seedAlias'],attached=False)
        h=SEED_HOST_ORIGINAL;ns=h['namespace'];module=types.ModuleType('original_seed_facts_owner');sys.modules[module.__name__]=module
        exec(compile(SEED_DETACH_OWNER,'original seed HOST owner','exec'),module.__dict__);module.owner_source=lambda:SEED_DETACH_OWNER
        status,out,err=module.collect(pathlib.Path(ns['root']),h['operationId'],module.MachineBinding.from_dict(ns['binding']),generation=tuple(ns['generation']))
        require(status['state']=='terminal'and status['terminal']['exitCode']==0 and not err,'windows_seed_ejection_not_closed')
        intent=module._intent(pathlib.Path(ns['root'])/h['operationId'],h['operationId'],module.MachineBinding.from_dict(ns['binding']))
        require(intent['purpose']=='windows-private-seed-eject'and intent['programSha256']==h['programSha256']
            and module._read(pathlib.Path(ns['root'])/h['operationId']/'program.py',module.MAX_PROGRAM_BYTES)==SEED_DETACH_SOURCE
            and module._read(pathlib.Path(ns['root'])/h['operationId']/'owner.py',module.MAX_PROGRAM_BYTES)==SEED_DETACH_OWNER,'windows_seed_original_source_changed')
        pending=json.loads(out);require(pending.get('kind')=='windows-private-seed-ejected-pending-v1'and pending.get('operationId')==OPERATION
            and pending.get('machine')==SPEC['deploymentId']and pending.get('readersRequired')is True
            and pending.get('ordinarySigninAllowed')is False and pending.get('seedGeneration')==seed_generation(),'windows_seed_ejection_not_closed')
        artifacts=lambda directory:{name:list(generation(private(pathlib.Path(directory)/name)))for name in ('intent.json','program.py','owner.py','terminal.json')}
        h={**h,'artifacts':artifacts(pathlib.Path(ns['root'])/h['operationId'])}
        c=SEED_ORIGINAL['creatorExpected'];creator={'root':str(pathlib.Path(SEED_ORIGINAL['creatorJob']).parent),'rootGeneration':c['rootGeneration'],
            'operationId':c['operationId'],'binding':c['binding'],'programSha256':c['programSha256'],'ownerSourceSha256':hashlib.sha256(SEED_CREATOR_OWNER).hexdigest(),
            'artifacts':artifacts(SEED_ORIGINAL['creatorJob'])}
        raw_wire=pathlib.Path('/proc/net/unix').read_text();require(len(raw_wire)<=1024**2,'windows_seed_manager_visibility')
        rows=[line.split()for line in raw_wire.splitlines()[1:]]
        wires=[int(v[6])for v in rows if len(v)>=8 and v[-1]==SOCKET_PATH and v[3:6]==['00010000','0001','01']]
        require(len(wires)==1,'windows_seed_manager_visibility')
        actor_projection=lambda row:{'pid':row['pid'],'birth':row['startTicks'],'uid':os.geteuid(),'executableGeneration':row['executableGeneration']}
        request={'schemaVersion':1,'kind':'windows-private-seed-readers-v1','machine':SPEC['deploymentId'],'hostBoot':CONTEXT['hostBootId'],
            'uid':os.geteuid(),'vmRoot':str(root),'rootIdentity':list(structure(private(root,True))),'seedGeneration':seed_generation(),
            'creator':creator,'manager':actor_projection(manager),'actor':actor_projection(current_actor),
            'mutable':{name:list(structure(private(root/name)))for name in ('disk.qcow2','uefi-vars.fd')},
            'managerSocket':{'path':SOCKET_PATH,'inode':wires[0],'identity':list(socket_pin)},
            'detachment':{'operationId':OPERATION,'intentGeneration':list(generation(private(root/('private-seed-'+OPERATION+'.intent.json')))),
                'boot':pending['boot'],'account':pending['account'],'hostOriginal':h}}
        seed_guard();print(json.dumps(request));return
'''
    source=source.replace(marker,branch)
    # Replace only the worker callback. Original status does not pretend to be
    # the old worker or exempt any currently running namespace operation.
    # Original status must not pretend to be the original durable worker.
    call='\n_main()\n';_need(source.endswith(call))
    # observer_inventory_definitions uses its own finite source-global names;
    # its callback can be aliased without replacing any observed original.
    observer=host.observer_inventory_definitions(record['namespace'])
    observer+='\n_seed_pure_host_work=_lifecycle_host_work\ndef _lifecycle_host_work(vm_actor=None,operator_fd=None):\n return _seed_pure_host_work()\n'
    constants={'SEED_HOST_ORIGINAL':{key:record[key]for key in ('namespace','operationId','recoveryId','programSha256')},
        'SEED_DETACH_SOURCE':raw,'SEED_DETACH_OWNER':owner}
    constants['SEED_HOST_ORIGINAL']['ownerSourceSha256']=record['namespace']['ownerSourceSha256']
    source=source[:-len(call)]+'\n'+observer+'\n'+'\n'.join(key+'='+repr(value)for key,value in constants.items())+call
    compile(source,'fixed selected original seed reader request','exec');return source.encode()


def reopen_ejection(handle,original_job):
    """Fresh-agent original-only reconstruction from immutable HOST artifacts.

    This never reenrolls a creator, synthesizes new execution qualifications or
    rebuilds a replacement Program from current source.
    """
    from . import readiness_windows_host_jobs as host
    _need(type(handle)is registry.CreatorHandle and type(original_job)is host.OriginalHostJob)
    record,source,owner=host._load(original_job);handle.guard()
    _need(record['purpose']=='windows-private-seed-eject')
    captured=_literals(source,{'SEED_ORIGINAL','SEED_CREATOR_SOURCE','SEED_CREATOR_OWNER','_LIFECYCLE_HOST_NAMESPACE','_LIFECYCLE_HOST_OWNER'})
    body=captured['SEED_ORIGINAL'];expected=body['creatorExpected']
    _need(captured['_LIFECYCLE_HOST_NAMESPACE']==record['namespace']and captured['_LIFECYCLE_HOST_OWNER']==owner
        and body['operationId']==record['operationId']and body['recoveryId']==record['recoveryId'])
    program=jobs.Program('windows-managed-first-create',captured['SEED_CREATOR_SOURCE'],expected['streamLimit'])
    result=object.__new__(SeedOriginal);_ORIGINALS[result]=(program,handle,json.loads(json.dumps(body)),original_job)
    _body(result)
    # An exact retained source packet supports observation only; it is not a
    # newly minted execution qualification after a source update or restart.
    _EJECTION_PROGRAMS[result]=jobs.Program(record['purpose'],source,record['streamLimit'])
    _DETACHMENTS[result]=original_job;original_ejection(result);return result
