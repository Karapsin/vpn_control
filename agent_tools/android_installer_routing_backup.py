"""Finite source-closed routing backup, before any installer authority.

Only two routing.show reads are available. This module grants no mutation,
installer lease, historical-owner adoption, or replay authority.
"""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
try:
    import resource
except ImportError:
    resource=None
import stat

from . import android_installer_component_bundle as bundle

READER='agent_tools/android_api35_large_routing_observation.py'
READER_TEST='agent_tools/tests/test_android_api35_large_routing_observation.py'
SOURCES={READER:'246db8b813b6be8a40a0ba3605e3854192adbc2f4b205a2d06ca62f397959ab7',
         READER_TEST:'c058f6b34132d2a4411552b201a3cf2cff72b5e3717e80ed602a3c198ed62264'}
LIMIT=33554432
CHUNK=524288
PUBLIC_SECONDS=300
OUTER_SECONDS=330


def _sources(receipt):
    files=bundle.load(receipt)
    if any(name not in files or hashlib.sha256(files[name]).hexdigest()!=digest for name,digest in SOURCES.items()):
        raise ValueError('routing_backup_reader_source_changed')
    own='agent_tools/android_installer_routing_backup.py'
    if files.get(own)!=bundle._read(__file__)[0]:raise ValueError('routing_backup_source_changed')
    tree=ast.parse(files[READER])
    values=[ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and
            any(isinstance(target,ast.Name) and target.id=='_OBSERVER' for target in node.targets)]
    if len(values)!=1:raise ValueError('routing_backup_reader_source_changed')
    return values[0]


def _collector(source,backend,argv,phase):
    """Compile the exact owned collector, replacing only its fixed argv gate.

    The caller of this private factory supplies the internally constructed JDK
    argv. The select loop, timeout, UID1000 drop, raw chunks and finally remain
    the source-authenticated large reader's actual statements.
    """
    tree=ast.parse(source);names={'getter_bounded','large_chunks','large_semantic'}
    nodes=[copy.deepcopy(n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    if {n.name for n in nodes}!=names:raise ValueError('routing_backup_reader_source_changed')
    bounded=next(n for n in nodes if n.name=='getter_bounded')
    expected=[n for n in bounded.body if isinstance(n,ast.Assign) and ast.unparse(n.targets[0])=='expected']
    if len(expected)!=1:raise ValueError('routing_backup_reader_source_changed')
    expected[0].value=ast.parse(repr(argv),mode='eval').body
    namespace={name:backend[name] for name in ('os','subprocess','select','time')}
    namespace.update(base64=base64,hashlib=hashlib,json=json,LARGE_OWNER=backend['BACKUP_OWNER'],
        LARGE_PHASE=phase,LARGE_PUBLIC_SECONDS=PUBLIC_SECONDS,LARGE_OUTER_SECONDS=OUTER_SECONDS,
        LARGE_OUTPUT_LIMIT=LIMIT,GETTER_RECORDS={})
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),
                 '<source-authenticated-routing-backup-reader>','exec'),namespace)
    return namespace


def _archive(directory,phase,record):
    """Persist complete streams before UTF8/JSON/envelope validation."""
    if phase not in ('routingBefore','routingAfter'):raise ValueError('routing_backup_phase_unknown')
    value=copy.deepcopy(record)
    for stream in ('stdout','stderr'):
        original=value[stream]
        if (type(original)is not dict or set(original)!={'bytes','sha256','encoding','chunkBytes','chunks'} or
            original['encoding']!='base64' or original['chunkBytes']!=65536 or
            type(original['bytes'])is not int or not 0<=original['bytes']<=LIMIT+1 or
            type(original['chunks'])is not list or len(original['chunks'])>513 or
            any(type(part)is not str or len(part)>87384 for part in original['chunks'])):
            raise ValueError('routing_backup_raw_unknown')
        raw=b''.join(base64.b64decode(part,validate=True) for part in original['chunks'])
        if len(raw)!=original['bytes'] or hashlib.sha256(raw).hexdigest()!=original['sha256']:
            raise ValueError('routing_backup_raw_changed')
        chunks=[]
        for index,offset in enumerate(range(0,len(raw),CHUNK)):
            name=phase+'-'+stream+'-'+str(index)+'.private';part=raw[offset:offset+CHUNK]
            bundle._write(directory/name,part)
            chunks.append({'name':name,'bytes':len(part),'sha256':hashlib.sha256(part).hexdigest(),
                           'pin':bundle._read(directory/name,True)[1]})
        value[stream]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'chunks':chunks}
    if value['stdout']['bytes']+value['stderr']['bytes']>LIMIT+1:raise ValueError('routing_backup_raw_unknown')
    bundle._write(directory/(phase+'-raw.json'),bundle._raw(value))
    value['manifestPin']=bundle._read(directory/(phase+'-raw.json'),True)[1]
    return value


def _retained(directory,phase,manifest):
    value={key:item for key,item in manifest.items() if key!='manifestPin'}
    raw,pin=bundle._read(directory/(phase+'-raw.json'),True)
    if pin!=manifest['manifestPin'] or raw!=bundle._raw(value):raise ValueError('routing_backup_raw_changed')
    streams={}
    for stream in ('stdout','stderr'):
        parts=[]
        for row in value[stream]['chunks']:
            part,current=bundle._read(directory/row['name'],True)
            if current!=row['pin'] or len(part)!=row['bytes'] or hashlib.sha256(part).hexdigest()!=row['sha256']:
                raise ValueError('routing_backup_raw_changed')
            parts.append(part)
        streams[stream]=b''.join(parts)
        if len(streams[stream])!=value[stream]['bytes'] or hashlib.sha256(streams[stream]).hexdigest()!=value[stream]['sha256']:
            raise ValueError('routing_backup_raw_changed')
    return streams


def _argv(backend,guard):
    jdk=backend['EXTERNAL']['selectedJdk'];java=Path(jdk['root'])/'bin/java'
    appdir=str(Path(backend['GETTER']['cli']).parent.parent/'lib/app')
    proven=guard.modules['transport'].readonly.proven
    guard.modules['adapter']._module(proven,guard.receipt['files']['agent_tools/android_api29_external_java_observation.py']['sha256'],('_configuration',))
    config=backend['read_fixed'](Path(appdir)/'vpn-control.cfg',1048576)
    if config.get('hashScope')!='full' or type(config.get('raw'))not in (bytes,str):
        raise ValueError('routing_backup_configuration_changed')
    text=config['raw'].decode('utf-8','strict') if type(config['raw'])is bytes else config['raw']
    raw=text.encode('utf-8','strict')
    if hashlib.sha256(raw).hexdigest()!=config.get('sha256'):
        raise ValueError('routing_backup_configuration_changed')
    classes,options=proven._configuration(raw,backend['GETTER']['manifest'])
    if classes!=backend['EXTERNAL']['classpath'] or options!=backend['EXTERNAL']['javaOptions']:
        raise ValueError('routing_backup_configuration_changed')
    args=[*[option.replace('$APPDIR',appdir) for option in backend['EXTERNAL']['javaOptions']],
          '-cp',':'.join(appdir+'/'+name for name in backend['EXTERNAL']['classpath']),
          'com.kardinal.vpncontrol.desktop.MainKt','--json','--android','--serial',backend['EXTERNAL']['serial'],
          '--timeout-seconds','300','--controller-id',guard.owner,'routing','show']
    return java,[str(java),*args]


def _read(source,backend,guard,directory,phase):
    guard();backend['command_host_guard']();backend['external_jdk_guard']()
    stage=copy.deepcopy(backend['getter_stage']());java,argv=_argv(backend,guard)
    if set(backend['LAUNCH']['environment'])!={'ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER'}:
        raise ValueError('routing_backup_environment_changed')
    guard.modules['adapter']._module(guard.modules['tls'],guard.receipt['files']['scripts/android_no_update_tls_preflight.py']['sha256'],('public_cli_environment',))
    environment=guard.modules['tls'].public_cli_environment(backend['LAUNCH']['adbPath'],Path(backend['GETTER']['cli']),backend['LAUNCH']['environment'])
    namespace=_collector(source,{**backend,'BACKUP_OWNER':guard.owner},argv,phase)
    chain,name=backend['parent_fds'](java);fd=None;result=None;manifest=None
    expected=backend['EXTERNAL']['selectedJdk']['files']['bin/java']['generation']
    try:
        fd=backend['os'].open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1]['fd'])
        if backend['fp'](backend['os'].fstat(fd))!=expected or backend['fp'](backend['os'].stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected:
            raise ValueError('routing_backup_jdk_changed')
        backend['guard_parents'](chain)
        result=namespace['getter_bounded'](argv,fd,environment,limit=LIMIT)
    finally:
        try:
            record=namespace['GETTER_RECORDS'].get(phase)
            if record is not None:manifest=_archive(directory,phase,record)
        finally:
            try:
                backend['guard_parents'](chain)
                if fd is not None and (backend['fp'](backend['os'].fstat(fd))!=expected or backend['fp'](backend['os'].stat(name,dir_fd=chain[-1]['fd'],follow_symlinks=False))!=expected):
                    raise ValueError('routing_backup_jdk_changed')
            finally:
                if fd is not None:backend['os'].close(fd)
                backend['close_parents'](chain)
                backend['external_jdk_guard']();guard()
                if backend['getter_stage']()!=stage:raise ValueError('routing_backup_stage_changed')
    record=namespace['GETTER_RECORDS'][phase]
    retained=_retained(directory,phase,manifest)
    if (record['returncode']!=0 or record['stdoutEof']is not True or record['stderrEof']is not True or
        record['stderr']['bytes']!=0 or result['returncode']!=0 or result['stderrRaw']!=''):
        raise ValueError('routing_backup_transport_unknown')
    raw=result['stdoutRaw'].encode()
    if raw!=retained['stdout'] or retained['stderr']!=b'':raise ValueError('routing_backup_raw_changed')
    value=_strict(raw)
    if (type(value)is not dict or value.get('ok')is not True or value.get('final')is not True or
        value.get('code')!='OK' or value.get('controllerId')!=guard.owner or
        type(value.get('configurationRevision'))is not int or value['configurationRevision']!=guard.revision):
        raise ValueError('routing_backup_public_unknown')
    semantic=namespace['large_semantic'](value)
    return value['data']['routing'],semantic,manifest


def _strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:
            if key in value:raise ValueError('routing_backup_duplicate_json')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda value:(_ for _ in ()).throw(ValueError('routing_backup_nonfinite_json')))


def _root_identity():
    if os.name!='posix' or resource is None:raise ValueError('routing_backup_posix_required')
    identity=[os.getuid(),os.geteuid(),os.getgid(),os.getegid(),sorted(os.getgroups())]
    if identity[:4]!=[0,0,0,0] or len(identity[4])>64:raise ValueError('routing_backup_root_required')
    return identity


def _assemble(directory,raw):
    """One create-only full backup; restore both original limits on every path."""
    if type(raw)is not bytes or not 0<len(raw)<=LIMIT:raise ValueError('routing_backup_size_unknown')
    identity=_root_identity();original=resource.getrlimit(resource.RLIMIT_FSIZE);admitted=(LIMIT,LIMIT)
    fd=None;chain=None;pin=None;restored=False
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE,admitted)
        if resource.getrlimit(resource.RLIMIT_FSIZE)!=admitted:raise ValueError('routing_backup_limit_unknown')
        before=bundle._directory(directory);chain,parents=bundle._parents(directory)
        if bundle._pin(os.fstat(chain[-1][1]))[:5]!=before['generation'][:5]:
            raise ValueError('routing_backup_parent_changed')
        fd=os.open('opening-routing.json',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=chain[-1][1])
        offset=0
        while offset<len(raw):
            written=os.write(fd,raw[offset:offset+CHUNK])
            if written<=0:raise ValueError('routing_backup_write_unknown')
            offset+=written
        os.fsync(fd);os.fsync(chain[-1][1]);os.lseek(fd,0,os.SEEK_SET);digest=hashlib.sha256();size=0
        while True:
            part=os.read(fd,CHUNK)
            if not part:break
            size+=len(part);digest.update(part)
        info=os.fstat(fd);pin=bundle._pin(info)
        after=bundle._directory(directory)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or
            info.st_uid!=identity[0] or info.st_gid!=identity[2] or size!=len(raw) or
            digest.hexdigest()!=hashlib.sha256(raw).hexdigest() or
            pin!=bundle._pin(os.stat('opening-routing.json',dir_fd=chain[-1][1],follow_symlinks=False)) or
            after['generation'][:5]!=before['generation'][:5] or after['parents']!=parents):
            raise ValueError('routing_backup_file_changed')
    finally:
        try:
            if fd is not None:os.close(fd)
            if chain is not None:bundle._close(chain)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE,original)
            restored=resource.getrlimit(resource.RLIMIT_FSIZE)==original and _root_identity()==identity
            if not restored:raise ValueError('routing_backup_limit_restore_unknown')
    return {'path':str(directory/'opening-routing.json'),'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'generation':pin,'parents':parents,'originalFileLimit':list(original),'admittedFileLimit':list(admitted),'limitsRestored':restored}


def _backup_guard(result):
    path=Path(result['path']);chain,parents=bundle._parents(path.parent);fd=None
    try:
        if parents!=result['parents']:raise ValueError('routing_backup_parent_changed')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=chain[-1][1])
        if bundle._pin(os.fstat(fd))!=result['generation']:raise ValueError('routing_backup_file_changed')
        size=0;digest=hashlib.sha256()
        while True:
            part=os.read(fd,min(CHUNK,LIMIT+1-size))
            if not part:break
            size+=len(part);digest.update(part)
            if size>LIMIT:raise ValueError('routing_backup_file_changed')
        current=bundle._directory(path.parent)
        if (size!=result['size'] or digest.hexdigest()!=result['sha256'] or current['parents']!=parents or
            bundle._pin(os.fstat(fd))!=result['generation'] or
            bundle._pin(os.stat(path.name,dir_fd=chain[-1][1],follow_symlinks=False))!=result['generation']):
            raise ValueError('routing_backup_file_changed')
    finally:
        if fd is not None:os.close(fd)
        bundle._close(chain)


def create(receipt,backend,request):
    """Fixed baseline request; derived private output, no caller argv or path."""
    source=_sources(receipt)
    selected=bundle.modules(receipt)
    guard=bundle.BaselineGuard(receipt,selected,backend,request)
    guard()
    directory=guard.args.output/'routing-backup';bundle._new_directory(directory)
    first,opening,before=_read(source,backend,guard,directory,'routingBefore')
    _,closing,after=_read(source,backend,guard,directory,'routingAfter')
    if opening!=closing:raise ValueError('routing_backup_semantic_changed')
    raw=bundle._raw(first);guard();_sources(receipt)
    result=_assemble(directory,raw)
    guard();_sources(receipt)
    _retained(directory,'routingBefore',before);_retained(directory,'routingAfter',after)
    _backup_guard(result)
    result.update(schema=1,kind='android-installer-routing-backup',request=copy.deepcopy(request),
                  semanticSha256=hashlib.sha256(opening).hexdigest(),formatVersion=7,
                  rawReads={'routingBefore':before,'routingAfter':after},
                  readCount=2,installerLeaseGranted=False,guestMutationPerformed=False,replayAllowed=False)
    bundle._write(directory/'backup-receipt.json',bundle._raw(result))
    _backup_guard(result)
    return result
