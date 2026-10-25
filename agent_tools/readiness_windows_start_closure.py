"""Append-only closure of an exact durable start after its exact clean shutdown.

An age, missing PID, closed flag, or collected local DTO cannot authorize a new
start. Every verification re-collects both actual original HOST owners, checks
full streams and native actor/clean-stop receipts, and observes current stopped
artifact metadata. Existing owners and receipts are never replaced or removed.
"""
import inspect
import ast
import json
from uuid import UUID
import weakref

from . import readiness_windows_lifecycle as lifecycle
from . import readiness_windows_host_jobs as host

_EXECUTING_CODE=inspect.currentframe().f_code
_CLOSURES=weakref.WeakKeyDictionary()


def _need(value):
    if not value:raise ValueError('windows_start_original_closure_unresolved')


class OriginalStartClosure:
    __slots__=('__weakref__',)
    def __new__(cls,*args,**kwargs):raise TypeError('windows_start_closure_opaque')
    def __reduce__(self):raise TypeError('windows_start_closure_opaque')


def original(binding,lineage,clean,start_job,stop_job):
    _need(type(lineage)is lifecycle.ExistingLineage and type(clean)is lifecycle.CleanStopped
        and type(start_job)is host.OriginalHostJob and type(stop_job)is host.OriginalHostJob)
    actual=lifecycle.validate_lineage(binding,lineage.as_dict()).as_dict()
    stopped=lifecycle.validate_clean_stopped(binding,lineage,clean.as_dict()).as_dict()
    start,start_source,_=host._load(start_job);stop,_,_=host._load(stop_job)
    _need(start['purpose']in {'windows-persisted-raw-start','windows-persisted-managed-start'}and stop['purpose']=='windows-existing-graceful-powerdown'
        and start['operationId']!=stop['operationId']and start['namespace']==stop['namespace']
        and stop['operationId']==stopped['operationId']and stop['recoveryId']==stopped['recoveryId'])
    ns=start['namespace'];bound=ns['binding']
    _need(ns['vmRoot']==binding['spec']['root']and ns['vmRootIdentity']==actual['rootIdentity']
        and bound['machine']==actual['machine']and UUID(bound['boot'])==UUID(actual['hostBoot'])
        and bound['target']=='windows-host:'+binding['spec']['host']+':'+actual['machine'])
    values={}
    keys={'SPEC','OPERATION','LIFECYCLE_RID','LIFECYCLE_LINEAGE','LIFECYCLE_CLEAN'}
    for node in ast.parse(start_source).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in keys:
            key=node.targets[0].id;_need(key not in values);values[key]=ast.literal_eval(node.value)
    _need(set(values)==keys and values['SPEC']==binding['spec']and values['OPERATION']==start['operationId']and values['LIFECYCLE_RID']==start['recoveryId'])
    previous=lifecycle.validate_lineage(binding,values['LIFECYCLE_LINEAGE'])
    prior_clean=lifecycle.validate_clean_stopped(binding,previous,values['LIFECYCLE_CLEAN']).as_dict()
    start_intent={'schemaVersion':1,'kind':'windows-existing-start-v1','operationId':start['operationId'],'recoveryId':start['recoveryId'],
        'machine':actual['machine'],'hostBoot':actual['hostBoot'],'lineageSha256':lifecycle._lineage_sha(previous),
        'cleanPoweroffOperationId':prior_clean['operationId'],'replayAllowed':False}
    result=object.__new__(OriginalStartClosure)
    _CLOSURES[result]=(start_job,stop_job,json.loads(json.dumps({'binding':binding,'lineage':actual,'clean':stopped,'startIntent':start_intent},allow_nan=False)))
    return result


def _body(value):
    _need(type(value)is OriginalStartClosure and value in _CLOSURES)
    start,stop,body=_CLOSURES[value]
    # Reclose original files and all typed projections at every getter.
    reconstructed=original(body['binding'],lifecycle.validate_lineage(body['binding'],body['lineage']),
        lifecycle.validate_clean_stopped(body['binding'],lifecycle.validate_lineage(body['binding'],body['lineage']),body['clean']),start,stop)
    _need(_CLOSURES[reconstructed][2]==body)
    return start,stop,json.loads(json.dumps(body))


def _check(expected,start_source,stop_source,publish,already_locked=False):
    import contextlib,fcntl,hashlib,io,json,os,pathlib,stat,time,sys,subprocess
    def need(value):
        if not value:raise ValueError('instance_lifecycle_prior_start_unreconciled')
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value);value[key]=item
        return value
    def parse(raw):return json.loads(raw,object_pairs_hook=pairs)
    root=pathlib.Path(expected['binding']['spec']['root']);clean=expected['clean'];lineage=expected['lineage']
    def pin(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]
    rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    lockfd=None
    try:
        def guard():need(root.resolve()==root and pin(os.fstat(rootfd))==pin(os.lstat(root))==clean['artifacts']['rootIdentity'])
        guard()
        if not already_locked:
            lockfd=os.open(root/'intent.json',os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
            info=os.fstat(lockfd);need(stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1)
            end=time.monotonic()+5
            while True:
                try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:need(time.monotonic()<end);time.sleep(.01)
        def read(name):
            fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=rootfd)
            with os.fdopen(fd,'rb')as stream:
                info=os.fstat(stream.fileno());need(stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1 and info.st_size<=262144)
                raw=stream.read(262145);need(len(raw)<=262144);return parse(raw)
        def observe(source,record):
            stream=io.StringIO()
            with contextlib.redirect_stdout(stream):exec(compile(source,'original-host-observer','exec'),{'__name__':'original_host_observer'})
            value=parse(stream.getvalue());status=value['status'];terminal=status.get('terminal')
            need(status.get('state')=='terminal'and type(terminal)is dict and terminal.get('exitCode')==0
                and type(terminal.get('exitCode'))is int and terminal.get('streamsClosed')is True
                and terminal.get('binding')==record['namespace']['binding']and terminal.get('programSha256')==record['programSha256']
                and terminal.get('operationId')==record['operationId']and status.get('owner')==terminal.get('owner'))
            # Fixed observer already read+hashed both complete streams. Repeat
            # their correlation here before a native closure is published.
            import base64
            output={}
            for name in ('stdout','stderr'):
                raw=base64.b64decode(value[name+'Base64'],validate=True);projection=terminal[name]
                need(projection['overflow']is False and projection['retainedBytes']==projection['totalBytes']==len(raw)
                    and projection['sha256']==hashlib.sha256(raw).hexdigest());output[name]=raw
            return terminal,output
        start=expected['start'];stop=expected['stop']
        start_terminal,_=observe(start_source,start);stop_terminal,output=observe(stop_source,stop)
        need(parse(output['stdout'])==clean and output['stderr']==b'')
        need(read('readiness-recovery-'+clean['recoveryId']+'.result.json')==clean)
        native=read('existing-start-'+start['operationId']+'.intent.json')
        need(native==expected['startIntent'])
        prefix='existing-start-'+start['operationId']
        if start['purpose']=='windows-persisted-raw-start':
            qemu=read(prefix+'.qemu-intent.json');need(set(qemu)=={'operationId','actor','replayAllowed'}and qemu['operationId']==start['operationId']and qemu['replayAllowed']is False);qemu=qemu['actor']
        else:qemu=read(prefix+'.qemu-started.json')
        tpm=read(prefix+'.tpm-started.json');need(qemu==lineage['qemu']and tpm==lineage['tpm'])
        need(clean['actor']=={k:qemu[k]for k in ('pid','startTicks')}and clean['tpm']=={k:tpm[k]for k in ('pid','startTicks')})
        def absent(actor):
            path=pathlib.Path('/proc')/str(actor['pid'])
            if not os.path.isdir('/proc'):
                need(sys.platform=='darwin')
                reply=subprocess.run(['/bin/ps','-p',str(actor['pid']),'-o','pid='],capture_output=True,timeout=3)
                need(reply.returncode==1 and reply.stdout==b''and reply.stderr==b'');return True
            if not os.path.lexists(path):return True
            raw=(path/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
            need(len(fields)>19);return int(fields[19])!=actor['startTicks']
        need(os.name=='posix'and absent(qemu)and absent(tpm))
        name=prefix+'.closed.json';fresh=not os.path.lexists(root/name)
        if fresh:need(publish and _actual_stopped_artifacts(expected['binding']['spec'])==clean['artifacts'])
        receipt={'schemaVersion':1,'kind':'windows-existing-start-closure-v1','machine':clean['machine'],'hostBoot':clean['hostBoot'],
            'startOperationId':start['operationId'],'stopOperationId':stop['operationId'],'startProgramSha256':start['programSha256'],
            'stopProgramSha256':stop['programSha256'],'startTerminal':start_terminal,'stopTerminal':stop_terminal,'clean':clean,'replayAllowed':False}
        if publish:
            raw=json.dumps(receipt,sort_keys=True,separators=(',',':')).encode()
            try:
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=rootfd)
                with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                os.fsync(rootfd)
            except FileExistsError:pass
        need(read(name)==receipt);guard()
        need((not fresh or _actual_stopped_artifacts(expected['binding']['spec'])==clean['artifacts'])and absent(qemu)and absent(tpm))
        return receipt
    finally:
        if lockfd is not None:os.close(lockfd)
        os.close(rootfd)


def definitions(value):
    start,stop,body=_body(value)
    body['start']=start.as_dict();body['stop']=stop.as_dict()
    name='_closure_'+body['start']['operationId'].replace('-','_')
    source=inspect.getsource(lifecycle._stopped_artifacts).replace('def _stopped_artifacts(', 'def _actual_stopped_artifacts(',1)+'\n'+inspect.getsource(_check)+'\n'
    source+=name+'_expected='+repr(body)+'\n'+name+'_start='+repr(host.operation_program(start))+'\n'+name+'_stop='+repr(host.operation_program(stop))+'\n'
    source+='def '+name+'(publish=False,already_locked=False):\n return _check('+name+'_expected,'+name+'_start,'+name+'_stop,publish,already_locked)\n'
    return body['start']['operationId'],name,source


def program(value,*,publish=True):
    _need(type(publish)is bool);_,name,source=definitions(value)
    raw=(source+'\nimport json\nprint(json.dumps('+name+'(publish='+repr(publish)+')))\n').encode()
    _need(len(raw)<=host.jobs.MAX_PROGRAM_BYTES);compile(raw,'original start closure','exec');return raw
