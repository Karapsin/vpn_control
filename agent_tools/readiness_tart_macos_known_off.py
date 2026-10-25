"""Offgraph prototype: close an original OFF phase, then admit a NEW start.

No native custody factory, power dispatch or public route is provided. A future
factory must derive every input from qualified original Mac custody, including
complete host/guest inventories and a fresh aggregate capacity producer. The
fixed observer checks those originals; data/flags cannot mint either opaque type.
This never creates CleanStopped or resolves an unobserved shutdown cause.
"""
from __future__ import annotations
import hashlib,inspect,json,math,os,stat,sys,time,weakref
from pathlib import Path
from uuid import UUID,uuid5,NAMESPACE_URL
from . import durable_remote_job as jobs
from . import readiness
from . import readiness_tart_macos_power_fence as power_fences
from . import readiness_tart_macos_registry as custody

_EXECUTING_CODE=inspect.currentframe().f_code
QUALIFIED_RECOVERIES=frozenset()
__idle__=sorted(readiness.IDLE_VISIBILITY)
_PLANS=weakref.WeakKeyDictionary();_PHASES=weakref.WeakKeyDictionary();_ADMISSIONS=weakref.WeakKeyDictionary()

class KnownOffBlocked(ValueError):pass

def need(value):
    if not value:raise KnownOffBlocked('macos_known_off_unresolved')

def _json(value):return json.loads(json.dumps(value,allow_nan=False))
def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _uuid(value):
    need(type(value)is str and str(UUID(value))==value);return value

def _source_guard():
    need(_EXECUTING_CODE==compile(Path(__file__).read_bytes(),__file__,'exec',dont_inherit=True,optimize=sys.flags.optimize))

def _pin(path):
    i=Path(path).lstat();need(stat.S_ISREG(i.st_mode)and i.st_uid==os.geteuid()and stat.S_IMODE(i.st_mode)==0o600 and i.st_nlink==1)
    return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]

def _owner(value):
    need(type(value)is custody.OriginalOwner)
    return {'root':str(value.root),'generation':list(value.generation),'operationId':value.operation_id,
        'binding':jobs.asdict(value.binding),'purpose':value.program.purpose,'programSha256':value.program.digest,
        'streamLimit':value.program.stream_limit,'ownerSha256':_sha(value.historical_owner_source or jobs.owner_source())}

class ObservationPlan:
    __slots__=('__weakref__',)
    def __new__(cls,*a,**kw):raise TypeError('macos_known_off_source_required')

class OriginalOffPhase:
    """Physical original phase ended; stopCause stays unobserved."""
    __slots__=('__weakref__',)
    def __new__(cls,*a,**kw):raise TypeError('macos_known_off_original_observer_required')
    def as_dict(self):
        need(type(self)is OriginalOffPhase and self in _PHASES)
        plan,owner,reply=_PHASES[self];_close(plan,owner,reply);return _json(reply)

class KnownOffAdmission:
    """Only the newly journaled start identity, never a clean-stop receipt."""
    __slots__=('__weakref__',)
    def __new__(cls,*a,**kw):raise TypeError('macos_known_off_original_observer_required')
    def as_dict(self):
        need(type(self)is KnownOffAdmission and self in _ADMISSIONS)
        phase,path,pin,value=_ADMISSIONS[self];phase.as_dict();need(_pin(path)==pin and jobs._record(path)==value)
        return _json(value)


def observation_plan(*,target,machine,host_binding,operator,run_owner,power_owner,capacity_owner,
                     retained_owners,retained_roots,power_fence,run_report,provider_binary,provider_sha256,
                     fixture_root,config_sha256,artifacts,ledger_files):
    """Internal preparation; inputs must come from a future qualified factory.

    run_report is source-derived original child/manager metadata, not arbitrary
    process-name discovery. Capacity owner must cover ALL retained/pending claims.
    Controlled tests qualify protocol decisions only, never physical VM capacity.
    """
    _source_guard();need(type(operator)is custody.OperatorLock);operator.guard()
    need(type(host_binding)is jobs.MachineBinding and host_binding.account==str(os.geteuid()))
    run,power,capacity=map(_owner,(run_owner,power_owner,capacity_owner))
    need(run['binding']==power['binding']==capacity['binding']==jobs.asdict(host_binding))
    _uuid(machine);need(type(target)is str and target and run['operationId']!=power['operationId'])
    need(type(power_fence)is power_fences.PowerFence and (power_fence.target,power_fence.machine)==(target,machine)
        and getattr(power_fence._operator_guard,'__self__',None)is operator
        and getattr(power_fence._operator_guard,'__func__',None)is custody.OperatorLock.guard)
    original_power=power_fence.inspect();need(original_power is not None)
    power_record=power_fence.root/('macos-power-reservation-'+original_power['recoveryId']+'.json')
    root=Path(fixture_root);need(root.is_absolute()and root.resolve()==root)
    directory=root.lstat();need(stat.S_ISDIR(directory.st_mode)and directory.st_uid==os.geteuid()and stat.S_IMODE(directory.st_mode)==0o700)
    need(set(artifacts)=={'config.json','disk.img','nvram.bin'})
    pins={name:list(pin)for name,pin in artifacts.items()}
    need(all(type(pin)is list and len(pin)==9 and _pin(root/name)==pin for name,pin in pins.items()))
    need(_sha(jobs._read(root/'config.json',262144))==config_sha256)
    owners=[_owner(value)for value in retained_owners]
    need(all(row['binding']==jobs.asdict(host_binding)for row in owners))
    roots={str(Path(path)):list(generation)for path,generation in retained_roots.items()}
    need(run['root']in roots and power['root']in roots and capacity['root']in roots)
    need(len({(v['root'],v['operationId'])for v in owners})==len(owners)
         and all(v in owners for v in (run,power,capacity)))
    ledger={str(Path(path)):_pin(path)for path in ledger_files}
    need(len(ledger)>=2)
    binary=Path(provider_binary);i=binary.lstat()
    need(stat.S_ISREG(i.st_mode)and i.st_uid==os.geteuid()and i.st_mode&0o100 and not i.st_mode&0o022 and i.st_nlink==1)
    binary_pin=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
    need(_sha(binary.read_bytes())==provider_sha256)
    value={'target':target,'machine':machine,'hostBinding':jobs.asdict(host_binding),'run':run,'power':power,'capacity':capacity,
        'owners':owners,'roots':roots,'powerRecord':str(Path(power_record)),'powerPin':_pin(power_record),
        'powerValue':original_power,'runReport':str(Path(run_report)),'runReportPin':_pin(run_report),'provider':str(binary),'providerPin':binary_pin,'providerSha256':provider_sha256,
        'fixtureRoot':str(root),'rootIdentity':[directory.st_dev,directory.st_ino,directory.st_mode,directory.st_uid,directory.st_gid],
        'artifacts':pins,'configSha256':config_sha256,'ledgers':ledger}
    plan=object.__new__(ObservationPlan);_PLANS[plan]=(value,operator);return plan


def _observe(plan,owner_source):
    """Fixed ordinary observer: metadata, original receipts, provider lock only."""
    import contextlib,fcntl,hashlib,io,json,os,pathlib,stat,subprocess,sys,time,types
    def need(value):
        if not value:raise ValueError('macos_known_off_unresolved')
    def pin(path):
        i=pathlib.Path(path).lstat();need(stat.S_ISREG(i.st_mode)and i.st_uid==os.geteuid()and stat.S_IMODE(i.st_mode)==0o600 and i.st_nlink==1)
        return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
    module=types.ModuleType('fixed_original_owner');sys.modules[module.__name__]=module;exec(compile(owner_source,'fixed-original-owner','exec'),module.__dict__)
    binding=module.MachineBinding.from_dict(plan['hostBinding']);module._binding_live(binding)
    root=pathlib.Path(plan['fixtureRoot']);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    lock=-1
    def guard():
        i=os.fstat(fd);need([i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid]==plan['rootIdentity'])
        j=root.lstat();need([j.st_dev,j.st_ino,j.st_mode,j.st_uid,j.st_gid]==plan['rootIdentity'])
        for name,wanted in plan['artifacts'].items():need(pin(root/name)==wanted)
        if lock>=0:
            os.lseek(lock,0,os.SEEK_SET);raw=os.read(lock,262145)
            need(len(raw)<=262144)
        else:raw=module._read(root/'config.json',262144)
        need(hashlib.sha256(raw).hexdigest()==plan['configSha256'])
        need(not os.path.lexists(root/'state.vzvmsave'))
        for path,wanted in plan['ledgers'].items():need(pin(path)==wanted)
        need(pin(plan['powerRecord'])==plan['powerPin']and pin(plan['runReport'])==plan['runReportPin'])
        module._binding_live(binding)
    def absent(actor):
        observed=module._birth(actor['pid']);need(observed!=actor['birth'])
        if observed is None:
            try:os.kill(actor['pid'],0)
            except ProcessLookupError:pass
            else:need(False)
    def original(row):
        path=module._root(row['root'],tuple(row['generation']))/row['operationId']
        intent=module._intent(path,row['operationId'],binding)
        need((intent['purpose'],intent['programSha256'],intent['streamLimit'])==(row['purpose'],row['programSha256'],row['streamLimit']))
        need(hashlib.sha256(module._read(path/'program.py',module.MAX_PROGRAM_BYTES)).hexdigest()==row['programSha256']
            and hashlib.sha256(module._read(path/'owner.py',module.MAX_PROGRAM_BYTES)).hexdigest()==row['ownerSha256'])
        state,stdout,stderr=module.collect(row['root'],row['operationId'],binding,generation=tuple(row['generation']))
        need(state['state']=='terminal'and state['terminal']['streamsClosed']is True);absent(state['terminal']['owner'])
        return state,stdout,stderr
    try:
        guard()
        binary=pathlib.Path(plan['provider']);i=binary.lstat()
        actual=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
        need(actual==plan['providerPin']and hashlib.sha256(binary.read_bytes()).hexdigest()==plan['providerSha256'])
        response=subprocess.run([str(binary),'get',root.name,'--format','json'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        need(response.returncode==0 and not response.stderr and 0<len(response.stdout)<=65536)
        provider=json.loads(response.stdout);need(type(provider)is dict and provider.get('Name')==root.name and provider.get('State')=='stopped'and provider.get('Running')is False)
        lock=os.open('config.json',os.O_RDWR|os.O_NOFOLLOW,dir_fd=fd)
        need(pin(root/'config.json')==plan['artifacts']['config.json']);fcntl.lockf(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Supported Tart provider owns the same per-VM fcntl lock at actual run.
        # No blanket all-host FD or VM-region absence is claimed here.
        for location,generation in plan['roots'].items():
            directory=module._root(location,tuple(generation));entries=os.listdir(directory)
            actual=set(entries)
            expected={row['operationId']for row in plan['owners']if row['root']==location}
            need(actual==expected)
        for row in plan['owners']:original(row)
        run,run_raw,run_errors=original(plan['run']);power,power_raw,power_errors=original(plan['power']);capacity,raw,errors=original(plan['capacity'])
        need(capacity['terminal']['exitCode']==0 and not errors)
        capacity=json.loads(raw)
        need(type(capacity)is dict and set(capacity)=={'kind','target','machine','hostBoot','observedNs','deadlineNs','memoryMiB','requiredMemoryMiB','diskBytes','requiredDiskBytes','ledgerPins','complete'}
            and capacity['kind']=='macos-aggregate-capacity-v1'and capacity['target']==plan['target']and capacity['machine']==plan['machine']
            and capacity['hostBoot']==plan['hostBinding']['boot']and capacity['ledgerPins']==plan['ledgers']and capacity['complete']is True
            and type(capacity['observedNs'])is int and type(capacity['deadlineNs'])is int
            and capacity['observedNs']<=time.monotonic_ns()<=capacity['deadlineNs']<=capacity['observedNs']+60_000_000_000)
        for a,b in (('memoryMiB','requiredMemoryMiB'),('diskBytes','requiredDiskBytes')):
            need(type(capacity[a])is int and type(capacity[b])is int and capacity[a]>=capacity[b]>0)
        power_record=module._record(pathlib.Path(plan['powerRecord']));report=module._record(pathlib.Path(plan['runReport']))
        need(power_record==plan['powerValue']and power_record['action']=='shutdown'and power_record['state']=='pending'and power_record['target']==plan['target']and power_record['machine']==plan['machine']
            and power_record['originalRunOperationId']==plan['run']['operationId']and power_record['idleVisibility']==sorted(__idle__)and power_record['idleBlockers']==[])
        need(power['terminal']['exitCode']==0 and not run_errors and json.loads(run_raw)==report and not power_errors
            and json.loads(power_raw)=={'kind':'macos-original-power-phase-ended-v1','target':plan['target'],'machine':plan['machine'],
                'operationId':plan['power']['operationId'],'runOperationId':plan['run']['operationId'],'recoveryId':power_record['recoveryId'],'state':'ended'})
        need(type(report)is dict and set(report)=={'kind','target','machine','operationId','powerOperationId','powerRecoveryId','stopCause','actors'}
            and report['kind']=='macos-original-run-off-v1'and report['target']==plan['target']and report['machine']==plan['machine']
            and report['operationId']==plan['run']['operationId']and report['powerOperationId']==plan['power']['operationId']
            and report['powerRecoveryId']==power_record['recoveryId']and report['stopCause']=='off_unknown'
            and type(report['actors'])is list and len(report['actors'])>=2
            and len({(row['pid'],row['birth'])for row in report['actors']})==len(report['actors']))
        for actor in report['actors']:
            need(type(actor)is dict and set(actor)=={'pid','birth'}and type(actor['pid'])is int and actor['pid']>0 and type(actor['birth'])is str
                )
            absent(actor)
        guard();need(pin(root/'config.json')==plan['artifacts']['config.json'])
        return {'kind':'macos-original-off-phase-closed-v1','target':plan['target'],'machine':plan['machine'],'hostBoot':plan['hostBinding']['boot'],
            'runOperationId':plan['run']['operationId'],'powerOperationId':plan['power']['operationId'],'powerRecoveryId':report['powerRecoveryId'],
            'stopCause':'off_unknown','cleanStopped':False,'before':power_record['before'],'observedNs':time.monotonic_ns(),'capacityDeadlineNs':capacity['deadlineNs']}
    finally:
        if lock>=0:os.close(lock)
        os.close(fd)


def observation_program(plan):
    need(type(plan)is ObservationPlan and plan in _PLANS);_source_guard();value,operator=_PLANS[plan];operator.guard()
    source=inspect.getsource(_observe)+'\n__idle__='+repr(sorted(readiness.IDLE_VISIBILITY))+'\n'
    source+='import json\ntry:print(json.dumps(_observe('+repr(value)+','+repr(jobs.owner_source())+'),sort_keys=True))\nexcept Exception:print(json.dumps(dict(state="blocked",reason="macos_known_off_unresolved")));raise SystemExit(3)\n'
    return jobs.Program('macos-known-off-observer-v1',source.encode(),262144)


def _close(plan,owner,expected=None):
    need(type(plan)is ObservationPlan and plan in _PLANS and type(owner)is custody.OriginalOwner);_source_guard()
    value,operator=_PLANS[plan];operator.guard();program=observation_program(plan)
    need(owner.program==program and jobs.asdict(owner.binding)==value['hostBinding'])
    state=owner.observe();need(state['state']=='terminal'and state['terminal']['exitCode']==0)
    state,raw,errors=jobs.collect(owner.root,owner.operation_id,owner.binding,generation=owner.generation)
    need(not errors);reply=json.loads(raw)
    need(type(reply)is dict and set(reply)=={'kind','target','machine','hostBoot','runOperationId','powerOperationId','powerRecoveryId','stopCause','cleanStopped','before','observedNs','capacityDeadlineNs'}
        and reply['kind']=='macos-original-off-phase-closed-v1'and reply['target']==value['target']and reply['machine']==value['machine']
        and reply['hostBoot']==value['hostBinding']['boot']and reply['runOperationId']==value['run']['operationId']and reply['powerOperationId']==value['power']['operationId']
        and reply['stopCause']=='off_unknown'and reply['cleanStopped']is False and reply['before']==value['powerValue']['before'] and type(reply['observedNs'])is int and type(reply['capacityDeadlineNs'])is int
        and reply['observedNs']<=time.monotonic_ns()<=reply['capacityDeadlineNs']<=reply['observedNs']+60_000_000_000)
    need(expected is None or reply==expected)
    # Recheck current persisted metadata and no saved-memory adoption at every getter.
    root=Path(value['fixtureRoot']);need(not os.path.lexists(root/'state.vzvmsave'))
    for name,pin in value['artifacts'].items():need(_pin(root/name)==pin)
    for path,pin in value['ledgers'].items():need(_pin(path)==pin)
    need(_pin(value['powerRecord'])==value['powerPin']and _pin(value['runReport'])==value['runReportPin'])
    current=_observe(value,jobs.owner_source())
    need(all(current[key]==reply[key]for key in reply if key!='observedNs'))
    return reply


def close_original_phase(plan,observer_owner):
    reply=_close(plan,observer_owner);phase=object.__new__(OriginalOffPhase);_PHASES[phase]=(plan,observer_owner,reply);return phase


def admit_known_off(phase,recovery_id):
    """Journal only a NEW transition. No power call and no PowerFence bypass."""
    need(type(phase)is OriginalOffPhase);reply=phase.as_dict()
    need(type(recovery_id)is str and len(recovery_id)==64 and all(c in '0123456789abcdef'for c in recovery_id)and recovery_id!=reply['powerRecoveryId'])
    operation=str(uuid5(NAMESPACE_URL,'vpn-control-known-off-start:'+reply['target']+':'+reply['machine']+':'+recovery_id))
    plan=_PHASES[phase][0];value,_=_PLANS[plan]
    directory=Path(value['powerRecord']).parent
    path=jobs._root(directory)/('known-off-start-'+reply['runOperationId']+'.json')
    value={'schemaVersion':1,'kind':'macos-known-off-new-start-v1','target':reply['target'],'machine':reply['machine'],
        'operationId':operation,'recoveryId':recovery_id,'predecessor':reply['runOperationId'],'powerOperationId':reply['powerOperationId'],
        'powerRecoveryId':reply['powerRecoveryId'],'stopCause':'off_unknown','cleanStopped':False,'replayAllowed':False,'hostBoot':reply['hostBoot'],'before':reply['before'],
        'phaseObserverOperationId':_PHASES[phase][1].operation_id,'phaseObserverProgramSha256':_PHASES[phase][1].program.digest,
        'phaseSha256':_sha(json.dumps(reply,sort_keys=True,separators=(',',':')).encode())}
    if not os.path.lexists(path):jobs._publish(path,value)
    need(jobs._record(path)==value);admission=object.__new__(KnownOffAdmission);_ADMISSIONS[admission]=(phase,path,_pin(path),value)
    admission.as_dict();return admission
