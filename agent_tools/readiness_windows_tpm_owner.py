"""Fixed privileged HOST metadata observation of one selected TPM listener.

No socket is connected, no guest request is made, and no process is signalled.
The unprivileged lineage producer derives the request; root supplies only the
complete kernel FD-holder census that an ordinary nondumpable process hides.
Mutable guest/TPM bytes and credentials are never read or hashed here.
"""
from contextlib import contextmanager
import hashlib
import inspect
import json
import math
from pathlib import PurePosixPath
import re
import subprocess
import stat
import time
import weakref
from uuid import UUID,uuid4

from . import ssh_transport as transport
from . import windows_vm_deploy as deploy
from .private_credential_file import SecretFile


_EXECUTING_CODE=inspect.currentframe().f_code


def _need(value):
    if not value:raise ValueError('windows_tpm_owner_observation_unknown')


def validate_request(value):
    _need(type(value)is dict and set(value)=={'schemaVersion','kind','machine','hostBoot','root','rootIdentity','mutable','qemu','socket'})
    _need(type(value['schemaVersion'])is int and value['schemaVersion']==1 and value['kind']=='windows-tpm-listener-request-v1')
    for key in ('machine','hostBoot'):
        _need(type(value[key])is str and str(UUID(value[key]))==value[key])
    def absolute(path):
        return type(path)is str and path.startswith('/')and str(PurePosixPath(path))==path and '..'not in PurePosixPath(path).parts and not any(ord(c)<32 for c in path)
    def pin(row,n):return type(row)is list and len(row)==n and all(type(x)is int and x>=0 for x in row)
    _need(absolute(value['root'])and _pin_root(value['rootIdentity']))
    _need(type(value['mutable'])is dict and set(value['mutable'])=={'disk.qcow2','uefi-vars.fd'}and all(pin(v,5)and stat.S_ISREG(v[2])and stat.S_IMODE(v[2])==0o600 for v in value['mutable'].values()))
    actor=value['qemu'];_need(type(actor)is dict and set(actor)=={'pid','birth','uid','executableGeneration'}
        and all(type(actor[k])is int and actor[k]>0 for k in ('pid','birth','uid'))and pin(actor['executableGeneration'],9))
    wire=value['socket'];_need(type(wire)is dict and set(wire)=={'path','inode','identity'}and absolute(wire['path'])
        and PurePosixPath(wire['path']).parent==PurePosixPath(value['root']).parent/'.cache/libvirt/qemu/run/swtpm'
        and type(wire['inode'])is int and wire['inode']>0 and pin(wire['identity'],5)and stat.S_ISSOCK(wire['identity'][2]))
    _need(value['rootIdentity'][3]==actor['uid']and all(row[3]==actor['uid']for row in value['mutable'].values())and wire['identity'][3]==actor['uid'])
    return json.loads(json.dumps(value,allow_nan=False,sort_keys=True))


def _pin_root(value):
    import stat
    return (type(value)is list and len(value)==5 and all(type(x)is int and x>=0 for x in value)
            and stat.S_ISDIR(value[2])and stat.S_IMODE(value[2])==0o700)


def validate_result(value):
    _need(type(value)is dict and set(value)=={'complete','holders','observedNs','deadlineNs'}and value['complete']is True
          and type(value['holders'])is list and len(value['holders'])<=32
          and all(type(value[k])is int and value[k]>0 for k in ('observedNs','deadlineNs'))
          and value['observedNs']<=value['deadlineNs']<=value['observedNs']+30_000_000_000)
    seen=set()
    for row in value['holders']:
        _need(type(row)is dict and set(row)=={'pid','uid','birth'}and all(type(row[k])is int and row[k]>0 for k in ('pid','birth'))and type(row['uid'])is int and row['uid']>=0
              and row['pid']not in seen);seen.add(row['pid'])
    return json.loads(json.dumps(value))


def _observe(request):
    import os,pathlib,stat,time
    def need(v):
        if not v:raise ValueError('windows_tpm_owner_observation_unknown')
    def identity(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]
    def generation(info):return identity(info)+[info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
    def birth(pid):
        raw=pathlib.Path('/proc',str(pid),'stat').read_text();words=raw[raw.rindex(')')+2:].split()
        return int(words[19])
    need(os.geteuid()==0 and os.getuid()==0)
    actor=request['qemu'];uid=actor['uid'];need(os.environ.get('SUDO_UID')==str(uid))
    end=time.monotonic()+20;held=[]
    def checked(path,expected):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);held.append(fd)
        need(identity(os.fstat(fd))==expected and identity(os.lstat(path))==expected);return fd
    def fence():
        need(time.monotonic()<end and pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()==request['hostBoot'])
        need(birth(actor['pid'])==actor['birth']and os.stat('/proc/'+str(actor['pid'])).st_uid==uid
             and generation(os.stat('/proc/'+str(actor['pid'])+'/exe'))==actor['executableGeneration'])
        for path,wanted in [(request['root'],request['rootIdentity']),*( (request['root']+'/'+k,v)for k,v in request['mutable'].items())]:
            need(identity(os.lstat(path))==wanted)
        wire=request['socket'];info=os.lstat(wire['path']);need(stat.S_ISSOCK(info.st_mode)and identity(info)==wire['identity'])
        raw=pathlib.Path('/proc/net/unix').read_text();need(len(raw)<=1024**2)
        rows=[line.split()for line in raw.splitlines()[1:]]
        found=[int(v[6])for v in rows if len(v)>=8 and v[-1]==wire['path']and v[3:6]==['00010000','0001','01']]
        need(found==[wire['inode']])
    def census():
        rows=[];processes=list(pathlib.Path('/proc').iterdir());need(len(processes)<=131072)
        for path in processes:
            if not path.name.isdigit():continue
            need(time.monotonic()<end)
            try:
                pid=int(path.name);before=birth(pid);owner=os.stat(path).st_uid
                fds=list((path/'fd').iterdir());need(len(fds)<=8192)
                matched=False
                for fd in fds:
                    try:target=os.readlink(fd)
                    except FileNotFoundError:continue
                    if target=='socket:['+str(request['socket']['inode'])+']':matched=True
                if matched:
                    need(before==birth(pid)and os.stat(path).st_uid==owner)
                    rows.append({'pid':pid,'uid':owner,'birth':before})
            except FileNotFoundError:continue
            # PermissionError and all other missing visibility abort the whole
            # result. Neither an unreadable candidate nor its FDs are skipped.
        return sorted(rows,key=lambda x:x['pid'])
    try:
        # Pin every actual directory ancestor without following a symlink.
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(parent)
        ancestors=[]
        for component in pathlib.PurePosixPath(request['root']).parts[1:]:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held.append(child)
            ancestors.append((parent,component,child,identity(os.fstat(child))));parent=child
        checked(request['root'],request['rootIdentity'])
        for name,wanted in request['mutable'].items():checked(request['root']+'/'+name,wanted)
        fence()
        # Prove the selected original QEMU actually holds both mutable inodes.
        fds=list(pathlib.Path('/proc',str(actor['pid']),'fd').iterdir());need(len(fds)<=8192)
        seen=[]
        for fd in fds:
            try:seen.append(identity(os.stat(fd)))
            except FileNotFoundError:continue
        need(all(row in seen for row in request['mutable'].values()))
        first=census();fence();second=census();fence();need(first==second and len(second)<=32)
        for parent,name,fd,before in ancestors:
            need(identity(os.fstat(fd))==before and identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==before)
        return {'complete':True,'holders':second}
    finally:
        for fd in held:os.close(fd)


def program(request,*,validity_ns=30_000_000_000):
    value=validate_request(request)
    _need(type(validity_ns)is int and 0<validity_ns<=30_000_000_000)
    source=inspect.getsource(_observe)+'\nREQUEST='+repr(value)+'\nVALIDITY_NS='+repr(validity_ns)+'''\nimport json,time
try:
    started=time.monotonic_ns()
    value=_observe(REQUEST)
    observed=time.monotonic_ns()
    deadline=min(started+VALIDITY_NS,observed+30_000_000_000)
    if observed>deadline:raise ValueError('windows_tpm_owner_observation_unknown')
    value.update(observedNs=observed,deadlineNs=deadline)
    print(json.dumps(value,sort_keys=True,separators=(',',':')))
except BaseException:
    print('{"complete":false,"holders":[],"observedNs":0,"deadlineNs":0}')
    raise SystemExit(1)
'''
    compile(source,'fixed selected TPM metadata observer','exec');return source.encode()


_ATTESTATIONS=weakref.WeakKeyDictionary()
_ISSUER=object()
MAX_WITNESS_AGE_SECONDS=30


class WitnessExpired(ValueError):
    def __init__(self):super().__init__('windows_tpm_owner_witness_expired')


class OwnerWitness:
    """Opaque live observer capability; JSON copies convey no authority."""
    __slots__=('__weakref__',)
    def __init__(self,*args,**kwargs):
        raise TypeError('windows_tpm_owner_observer_required')
    def __init_subclass__(cls,**kwargs):raise TypeError('windows_tpm_owner_observer_required')
    def __reduce__(self):raise TypeError('windows_tpm_owner_observer_required')
    def _state(self):
        value=_ATTESTATIONS.get(self);_need(value is not None and value['issuer']is _ISSUER);return value
    @property
    def request(self):return json.loads(self._state()['request'])
    @property
    def result(self):return json.loads(self._state()['result'])
    @property
    def source_sha256(self):return self._state()['sourceSha256']
    def receipt(self):
        value=self._state()
        return {'request':self.request,'result':self.result,'sourceSha256':value['sourceSha256'],
                'executionId':value['executionId'],'kind':'historical-tpm-owner-observation-v1'}
    def consume(self,operation):
        value=self._state();_need(value['consumedBy']is None and type(operation)is str and str(UUID(operation))==operation)
        self.validate(self.request);value['consumedBy']=operation
    def guard_dispatch(self,admission):
        value=self._state();_need(value['consumedBy']==admission.operation_identity)
        from . import ssh_dispatch_admission
        return ssh_dispatch_admission.add_dispatch_guard(admission,lambda:self.validate(self.request))
    def validate(self,request):
        value=self._state();_need(type(self)is OwnerWitness)
        if time.monotonic()>value['deadline']:raise WitnessExpired()
        for guard in value['guards']:guard()
        _need(validate_request(request)==self.request and value['sourceSha256']==hashlib.sha256(program(request,validity_ns=value['budgetNs'])).hexdigest())
        result=validate_result(self.result);_need(len(result['holders'])==1 and result['holders'][0]['uid']==request['qemu']['uid'])
        for guard in value['guards']:guard()
        if time.monotonic()>value['deadline']:raise WitnessExpired()
        return result['holders'][0]


def _mint(issuer,request,result,source_sha256,guards,deadline,budget_ns):
    _need(issuer is _ISSUER)
    value=object.__new__(OwnerWitness)
    _ATTESTATIONS[value]={'issuer':issuer,'request':json.dumps(request,sort_keys=True,separators=(',',':')),
        'result':json.dumps(result,sort_keys=True,separators=(',',':')),'sourceSha256':source_sha256,
        'guards':guards,'executionId':str(uuid4()),'budgetNs':budget_ns,'consumedBy':None,'deadline':min(time.monotonic()+MAX_WITNESS_AGE_SECONDS,deadline)}
    return value


@contextmanager

def observe(root,host,request,credential_file,*,guard,deadline=None):
    """Internal host-only protected-stdin controller; no public ownership input."""
    request=validate_request(request);private_input=None;witness=None;yielded=False
    deadline=time.monotonic()+180 if deadline is None else deadline
    _need(type(deadline)in (int,float)and math.isfinite(deadline)and deadline>time.monotonic())
    def remaining():
        result=60 if deadline is None else min(60,deadline-time.monotonic());_need(result>0);return result
    try:
        with transport.admitted_transport(root,host,request['machine'],deadline=deadline)as admitted:
            with deploy.direct.Guard(root,host=host)as authority:
                guard();budget_ns=min(30_000_000_000,max(1,int(remaining()*1_000_000_000)));source=program(request,validity_ns=budget_ns)
                command=('sudo','-S','-p','','--','python3','-I','-B','-c','exec('+repr(source.decode())+')')
                argv=transport.build_ssh_argv(authority.config,host,60,command=command)
                with SecretFile(str(credential_file))as credential:
                    credential.guard();admitted.revalidate();authority.guard();guard()
                    private_input=credential.text.encode()+b'\n'
                    reply=transport.run_ssh(argv,input=private_input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=remaining(),cwd=root)
                    credential.guard()
                    streams=(reply.stdout,reply.stderr)
                    _need(all(type(s)is bytes and len(s)<=65536 for s in streams))
                    _need(not any(credential.text.encode()in s for s in streams))
                _need(reply.returncode==0 and not reply.stderr)
                result=validate_result(json.loads(reply.stdout,object_pairs_hook=transport._reject_duplicate_keys))
                admitted.revalidate();authority.guard();guard()
                witness=_mint(_ISSUER,request,result,hashlib.sha256(source).hexdigest(),
                    (admitted.revalidate,authority.guard,guard),deadline,budget_ns)
                witness.validate(request)
                private_input=None;yielded=True
                yield witness
    except Exception:
        if yielded:raise
        raise ValueError('windows_tpm_owner_observation_unknown')from None
    finally:
        private_input=None
        if witness is not None:_ATTESTATIONS.pop(witness,None)
