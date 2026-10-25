"""Explicit engineering qualification of an original clean native checkpoint.

The catalogue is repository-owned. No dirty-source waiver, caller dependency
subset, package relabel, final acceptance, or platform action is provided.
"""
from __future__ import annotations
import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
from . import linux_package_fixture_build as build
from . import native_artifact_reuse as reuse
from . import native_artifact_registry as registry
from . import native_review_source_closure as closure

_CORE = frozenset('agent_tools/'+name+'.py' for name in (
    'linux_package_fixture_build','ssh_tmux_session','ssh_tmux_session_ssh','ssh_transport',
    'native_artifact_registry','native_artifact_reuse','native_review_source_closure',
    'ssh_connection_session','ssh_channel_selection','ssh_connection_recovery','native_execution_context',
    'ssh_tmux_resource_admission'))
_REQUIRED_SCRIPTS = frozenset('scripts/'+name for name in (
    'version_metadata.py','prepare_desktop_update_fixture.py','fixture_environment.py',
    'native_fixture_run.sh','prepare_sing_box_desktop_runtime.sh','test_jpackage_launcher.py'))
# This known check-lifetime helper is unrelated to the fixed native build.
# Output retention is now used by the channel keeper and must be held as source.
# A new unknown tool file is never silently excluded.
_UNRELATED = frozenset({'agent_tools/managed_check_lease.py'})
_DYNAMIC = {'agent_tools/ssh_transport.py': frozenset({
    'ssh_connection_session','ssh_channel_selection','ssh_automatic_program',
    'readiness_nested_channel','readiness_ssh_master','readiness'})}
_STDLIB_DYNAMIC = {
    'agent_tools/ssh_direct_nested_channel.py': frozenset({'shlex'}),
    'agent_tools/readiness_transport.py': frozenset({'contextlib'}),
    'agent_tools/readiness_nested_channel.py': frozenset({'__future__'}),
}

class ExecutionContextError(ValueError):
    pass

def _need(value, reason):
    if not value:raise ExecutionContextError(reason)

def _dynamic_name(arg):
    if isinstance(arg,ast.Constant) and isinstance(arg.value,str):
        return arg.value.removeprefix('agent_tools.')
    if (isinstance(arg,ast.JoinedStr) and len(arg.values)==2
            and isinstance(arg.values[0],ast.FormattedValue)
            and isinstance(arg.values[0].value,ast.Name)
            and arg.values[0].value.id=='__package__'
            and arg.values[0].conversion==-1 and arg.values[0].format_spec is None
            and isinstance(arg.values[1],ast.Constant)
            and isinstance(arg.values[1].value,str) and arg.values[1].value.startswith('.')):
        return arg.values[1].value[1:]
    # The reviewed nested caller supports package and standalone execution.
    # Both branches must resolve to the same finite repository-owned module.
    if (isinstance(arg,ast.IfExp) and isinstance(arg.test,ast.Name)
            and arg.test.id=='__package__' and isinstance(arg.body,ast.JoinedStr)
            and isinstance(arg.orelse,ast.Constant) and isinstance(arg.orelse.value,str)
            and arg.orelse.value.startswith('agent_tools.')):
        name=_dynamic_name(arg.body)
        _need(arg.orelse.value=='agent_tools.'+name,'native_dependency_dynamic_unknown')
        return name
    raise ExecutionContextError('native_dependency_dynamic_unknown')

def _safe(path):
    return path in _UNRELATED or path == 'README.md' or path.startswith(('docs/','agent_docs/','agent_tools/tests/','tests/'))

def _source(root, sha):
    _need(reuse._head(root)==sha and not reuse._dirty_paths(root),'native_source_requires_clean_exact_checkpoint')

def _remote(root):
    raw=reuse._git(root,'ls-remote','origin','refs/heads/dev').decode().strip().split('\t')
    _need(len(raw)==2 and raw[1]=='refs/heads/dev','native_origin_ref_unknown')
    return reuse._sha(raw[0],'originDevSHA')

def _blob_inputs(root, rows):
    """Stream one fixed Git batch; retain digests and bounded Python source only."""
    import subprocess
    expected={};source={};by_oid={};cached_bytes=0
    for path,(mode,blob,size) in rows.items():by_oid.setdefault(blob,[]).append(path)
    process=subprocess.Popen(['git','-C',str(root),'cat-file','--batch'],stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    try:
        for blob,paths in by_oid.items():
            declared=rows[paths[0]][2]
            _need(all(rows[p][2]==declared for p in paths),'native_git_blob_size_unknown')
            _need(0<=declared<=128*1024**2,'native_git_blob_bound')
            process.stdin.write((blob+'\n').encode('ascii'));process.stdin.flush()
            header=process.stdout.readline(256).decode('ascii').strip().split()
            _need(header==[blob,'blob',str(declared)],'native_git_blob_changed')
            keep=any(p.endswith('.py') and p.startswith(('agent_tools/','scripts/')) for p in paths) or declared<=4096
            _need(not keep or declared<=8*1024**2,'native_tool_source_bound')
            chunks=[];hasher=hashlib.sha256();left=declared
            while left:
                block=process.stdout.read(min(left,1024**2));_need(bool(block),'native_git_blob_truncated')
                hasher.update(block)
                if keep:chunks.append(block)
                left-=len(block)
            _need(process.stdout.read(1)==b'\n','native_git_blob_frame_unknown')
            raw=b''.join(chunks) if keep else None
            digest=hasher.hexdigest();size=declared
            if raw is not None and raw.startswith(b'version https://git-lfs.github.com/spec/v1\n'):
                pointer=re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n',raw)
                _need(pointer is not None,'native_lfs_pointer_unknown');digest=pointer[1].decode();size=int(pointer[2])
                _need(size>0,'native_lfs_pointer_unknown')
            if raw is not None and any(p.endswith('.py') for p in paths):
                cached_bytes+=len(raw);_need(cached_bytes<=64*1024**2,'native_python_catalogue_bound')
            for path in paths:
                expected[path]={'mode':rows[path][0],'sha256':digest,'size':size,'gitBlobOID':blob}
                if raw is not None and path.endswith('.py'):source[path]=raw
        process.stdin.close();_need(process.wait(timeout=30)==0,'native_git_batch_unknown')
        return expected,source
    finally:
        if process.poll() is None:process.kill();process.wait(timeout=5)
        for stream in (process.stdin,process.stdout):
            if stream is not None:stream.close()


def _product_read(root_fd, relative, expected, directories, *, previous=None, stat_only=False):
    """A bounded FD walk with retained directory identity and file generation."""
    import os
    import stat
    parts=relative.split('/')
    _need(all(x not in ('','.','..') and '\\' not in x and '\x00' not in x for x in parts),'native_product_path_unknown')
    parent=os.dup(root_fd);file_fd=None
    try:
        current=[]
        for name in parts[:-1]:
            next_fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=next_fd;current.append(name)
            key='/'.join(current);pin=closure._structural(os.fstat(parent))
            _need(stat.S_ISDIR(pin[2]),'native_product_parent_type')
            _need(key not in directories or directories[key]==pin,'native_product_parent_changed')
            directories[key]=pin
        file_fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        before=os.fstat(file_fd);generation=closure.generation(before)
        _need(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid() and before.st_nlink==1
              and before.st_size==expected['size'] and bool(before.st_mode & 0o111)==(expected['mode']=='100755'),
              'native_product_type_or_size_changed')
        _need(previous is None or list(generation)==previous['generation'],'native_product_generation_changed')
        if not stat_only:
            digest=hashlib.sha256();left=expected['size']
            while left:
                block=os.read(file_fd,min(1024**2,left));_need(bool(block),'native_product_truncated')
                digest.update(block);left-=len(block)
            _need(os.read(file_fd,1)==b'' and digest.hexdigest()==expected['sha256'],'native_product_bytes_changed')
        _need(closure.generation(os.fstat(file_fd))==generation==closure.generation(
            os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)),'native_product_read_generation_changed')
        return {'sha256':expected['sha256'],'mode':expected['mode'],'generation':list(generation),
                'gitBlobOID':expected['gitBlobOID']}
    finally:
        if file_fd is not None:os.close(file_fd)
        os.close(parent)



def _gitlink(root, relative, commit):
    """The sole unused libsource link is bound, never initialized or upgraded."""
    import os
    import stat
    _need(relative == 'sing-box-libsrc','native_gitlink_unknown')
    path=root/relative
    if not os.path.lexists(path):
        return {'mode':'160000','gitCommitOID':commit,'state':'absent'}
    info=path.lstat()
    _need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid==os.getuid(),
          'native_gitlink_checkout_unsafe')
    generation=list(closure._structural(info))
    if not (path/'.git').exists():
        _need(not list(path.iterdir()),'native_gitlink_uninitialized_nonempty')
        _need(list(closure._structural(path.lstat()))==generation,'native_gitlink_checkout_changed')
        return {'mode':'160000','gitCommitOID':commit,'state':'uninitialized','directory':generation}
    _need(reuse._head(path)==commit,'native_gitlink_commit_changed')
    _need(not reuse._git(path,'--no-optional-locks','-c','core.fsmonitor=false','-c',
        'core.untrackedCache=false','-c','diff.ignoreSubmodules=none','status','--porcelain=v1',
        '--untracked-files=all','--ignore-submodules=none').strip(),'native_gitlink_checkout_dirty')
    rows={}
    for row in reuse._git(path,'ls-tree','-r','-l','-z',commit).split(b'\0'):
        if not row:continue
        metadata,name=row.split(b'\t',1);mode,kind,blob,size=metadata.decode().split()
        _need(mode in ('100644','100755') and kind=='blob','native_gitlink_nested_entry_unknown')
        rows[name.decode()]=(mode,blob,int(size))
    expected,_=_blob_inputs(path,rows);held=closure._Held();pins={};directories={}
    try:
        root_fd=held.directory(str(path))
        for name,item in expected.items():pins[name]=_product_read(root_fd,name,item,directories)
        for name,item in expected.items():_product_read(root_fd,name,item,directories,previous=pins[name])
        for name,item in expected.items():_product_read(root_fd,name,item,directories,previous=pins[name],stat_only=True)
        held.finish();held.final_identity_pass()
    finally:held.close()
    _need(reuse._head(path)==commit and list(closure._structural(path.lstat()))==generation,
          'native_gitlink_checkout_changed')
    return {'mode':'160000','gitCommitOID':commit,'state':'initialized','directory':generation,'files':pins}

def _catalogue(root, sha):
    rows={};gitlinks={}
    for row in reuse._git(root,'ls-tree','-r','-l','-z',sha).split(b'\0'):
        if not row:continue
        metadata,name=row.split(b'\t',1);path=name.decode('utf-8')
        if _safe(path):continue
        mode,kind,blob,size=metadata.decode().split()
        if mode=='160000' and kind=='commit':
            gitlinks[path]=_gitlink(root,path,blob);continue
        _need(mode in ('100644','100755') and kind=='blob','native_catalogue_nonregular')
        rows[path]=(mode,blob,int(size))
    _need('.gitmodules' not in rows,'native_gitmodules_unknown')
    _need(_CORE|_REQUIRED_SCRIPTS <= set(rows),'native_catalogue_missing_dependency')
    expected,sources=_blob_inputs(root,rows)
    # Static closure from fixed consumer roots; no caller subset or dynamic trust.
    pending=list(_CORE);seen=set();stdlib=set(sys.stdlib_module_names)|{'__future__'}
    while pending:
        path=pending.pop()
        if path in seen:continue
        _need(path in sources,'native_catalogue_missing_dependency');seen.add(path)
        tree=ast.parse(sources[path])
        for node in ast.walk(tree):
            dependencies=[]
            if isinstance(node,ast.Import):dependencies=[a.name for a in node.names]
            elif isinstance(node,ast.ImportFrom):
                if node.level:
                    _need(node.level==1,'native_dependency_relative_unknown')
                    dependencies=[path.split('/')[0]+'.'+(node.module or a.name) for a in node.names]
                elif node.module in ('agent_tools','scripts'):dependencies=[node.module+'.'+a.name for a in node.names]
                elif node.module:dependencies=[node.module]
            for name in dependencies:
                if name.split('.')[0] in stdlib:continue
                candidates=[name.replace('.','/')+'.py',name.replace('.','/')+'/__init__.py',path.rsplit('/',1)[0]+'/'+name.replace('.','/')+'.py']
                if path=='agent_tools/vm_workflow.py' and name=='fixture_environment':
                    candidates.append('scripts/fixture_environment.py')
                found=next((p for p in candidates if p in rows),None)
                _need(found is not None,'native_catalogue_missing_dependency');pending.append(found)
            if not isinstance(node,ast.Call):continue
            func=node.func
            dynamic=(isinstance(func,ast.Name) and func.id=='__import__' or isinstance(func,ast.Attribute) and func.attr in ('import_module','__import__'))
            if not dynamic:continue
            _need(len(node.args)==1 and not node.keywords,'native_dependency_dynamic_unknown');arg=node.args[0]
            name=_dynamic_name(arg)
            if name in _STDLIB_DYNAMIC.get(path,frozenset()):
                _need(isinstance(arg,ast.Constant) and arg.value==name
                      and name in stdlib,'native_dependency_dynamic_unknown')
                continue
            _need(name in _DYNAMIC.get(path,frozenset()) and 'agent_tools/'+name+'.py' in rows,'native_dependency_dynamic_unknown')
            pending.append('agent_tools/'+name+'.py')
    # Actual source consumed by the native tooling retains the existing held-FD
    # closure. Other product inputs retain exact bytes and generation with bounded
    # file and directory walks; they are never delegated to Git status/index flags.
    native=seen|{p for p in rows if p.startswith('scripts/')}
    held=closure._Held();pins={};directories={}
    try:
        root_fd=held.directory(str(root))
        for path,item in expected.items():
            if path in native:
                absolute=str(root/path);held.read(absolute,item['sha256'],max_bytes=max(1,item['size']))
                _need(len(held.files[absolute][3])==item['size'] and bool(held.files[absolute][1][2] & 0o111)==(item['mode']=='100755'),
                      'native_tool_source_size_or_mode_changed')
                pins[path]={'sha256':item['sha256'],'mode':item['mode'],'generation':list(held.files[absolute][1]),'gitBlobOID':item['gitBlobOID']}
            else:pins[path]=_product_read(root_fd,path,item,directories)
        # Rehash every product byte, then close native source hashes/FDs/parents.
        for path,item in expected.items():
            if path not in native:_product_read(root_fd,path,item,directories,previous=pins[path])
        held.finish()
        # Final pure named-file and parent generation bracket follows all hashing.
        for path,item in expected.items():
            if path not in native:_product_read(root_fd,path,item,directories,previous=pins[path],stat_only=True)
        held.final_identity_pass()
        for path,item in gitlinks.items():
            _need(_gitlink(root,path,item['gitCommitOID'])==item,'native_gitlink_checkout_changed')
        return {**pins,**gitlinks}
    finally:held.close()

def _diff(root, original, target):
    # Existing canonical diff parser rejects renames, symlinks and mode changes.
    entries=reuse._equivalence_diff(root,original,target)
    for entry in entries:
        path=entry['path']
        if path=='gradle.properties' and entry['status']=='M':
            bodies=[reuse._git(root,'show',sha+':gradle.properties') for sha in (original,target)]
            normalized=[re.sub(rb'^vpnControlVersion=[^\r\n]*',b'vpnControlVersion=<original>',x,flags=re.M) for x in bodies]
            _need(normalized[0]==normalized[1],'native_product_version_metadata_change')
        else:_need(_safe(path),'native_consumed_source_changed')
    return entries

def _artifacts(root, sha, ids):
    _need(isinstance(ids,tuple) and 0<len(ids)<=100 and len(set(ids))==len(ids),'native_artifacts_required')
    values={}
    for identity in ids:
        item=registry.verify_artifact_readonly(root,identity)
        _need(item.get('verification')=='verified' and item['artifact'].get('sourceSha')==sha,
              'native_artifact_source_or_bytes_changed')
        values[identity]={'artifact':item['artifact'],'location':item['location']}
    return values

@dataclass(frozen=True)
class EngineeringExecutionContext:
    coordinator_root: Path
    source_root: Path
    authority: bytes

    @classmethod
    def qualify(cls, coordinator_root, source_root, request, artifact_ids):
        coordinator=Path(coordinator_root).resolve(strict=True)
        source=build._source_root(coordinator,source_root);request=build._request(request)
        _source(source,request['sourceSha']);target=_remote(source)
        # merge-base uses immutable commit objects and never moves a ref.
        try:reuse._git(source,'merge-base','--is-ancestor',request['sourceSha'],target)
        except reuse.ArtifactReuseError as error:raise ExecutionContextError('native_target_not_descendant') from error
        diff=_diff(source,request['sourceSha'],target)
        record={'scope':'ENGINEERING_ORIGINAL_SOURCE_ONLY','sourceSha':request['sourceSha'],'targetSha':target,
                'baseVersion':request['baseVersion'],'targetVersion':request['targetVersion'],
                'catalogue':_catalogue(source,request['sourceSha']),
                'artifacts':_artifacts(coordinator,request['sourceSha'],tuple(artifact_ids)),
                'diff':diff,'nativeActionAllowed':False,'finalAcceptance':False}
        context=cls(coordinator,source,json.dumps(record,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
        context.revalidate(source,request)
        return context

    def revalidate(self, source_root, request, *, admission=True):
        expected=json.loads(self.authority);request=build._request(request)
        _need(Path(source_root).resolve()==self.source_root,'native_context_source_root_changed')
        _need(build._source_root(self.coordinator_root,self.source_root)==self.source_root,'native_context_repository_changed')
        _need(all(request[k]==expected[k] for k in ('sourceSha','baseVersion','targetVersion')),'native_context_source_or_version_changed')
        _source(self.source_root,expected['sourceSha'])
        if admission:_need(_remote(self.source_root)==expected['targetSha'],'native_target_ref_changed')
        try:reuse._git(self.source_root,'merge-base','--is-ancestor',expected['sourceSha'],expected['targetSha'])
        except reuse.ArtifactReuseError as error:raise ExecutionContextError('native_target_not_descendant') from error
        _need(_diff(self.source_root,expected['sourceSha'],expected['targetSha'])==expected['diff'],'native_diff_changed')
        _need(_catalogue(self.source_root,expected['sourceSha'])==expected['catalogue'],'native_tool_or_product_generation_changed')
        _need(_artifacts(self.coordinator_root,expected['sourceSha'],tuple(expected['artifacts']))==expected['artifacts'],
              'native_artifact_binding_changed')
        _source(self.source_root,expected['sourceSha'])
        if admission:_need(_remote(self.source_root)==expected['targetSha'],'native_target_ref_changed')
        return {'scope':expected['scope'],'sourceSha':expected['sourceSha'],'targetSha':expected['targetSha'],
                'originalPackageVersion':expected['targetVersion'],'contextSha256':hashlib.sha256(self.authority).hexdigest(),
                'nativeActionAllowed':False,'finalAcceptance':False}

    def require_native_consumers(self, paths):
        expected=json.loads(self.authority)
        for path in paths:
            path=Path(path).resolve(strict=True)
            try:relative=path.relative_to(self.source_root).as_posix()
            except ValueError as error:raise ExecutionContextError('native_consumer_outside_frozen_context') from error
            _need(relative in expected['catalogue'],'native_consumer_missing_from_catalogue')
            held=closure._Held()
            try:
                entry=expected['catalogue'][relative]
                held.read(str(path),entry['sha256'],tuple(entry['generation']))
                held.finish()
            finally:held.close()


def dispatch_linux_engineering(root, operation, inputs):
    """Fixed local frozen-producer invocation for the existing Linux MCP action.

    Child stdout/stderr are privately retained by the existing bounded capsule;
    only the frozen producer's finite public projection is returned. This never
    changes commands, inventory roots, admission mode, or original correlations.
    """
    import os
    import subprocess
    from . import ssh_tmux_mcp_adapter as adapter
    from . import ssh_tmux_session as session
    from . import ssh_transport
    _need(operation in ('preflight','start','status','collect') and type(operation) is str,
          'native_engineering_operation_invalid')
    _need(type(inputs) is dict and set(inputs)==build._REQUEST|{'engineeringContext'},
          'native_engineering_fields_invalid')
    selected=inputs['engineeringContext']
    _need(type(selected) is dict and set(selected)=={'sourceRoot','artifactIds'} and
          type(selected['sourceRoot']) is str and Path(selected['sourceRoot']).is_absolute() and
          '\x00' not in selected['sourceRoot'] and len(selected['sourceRoot'])<=4096,
          'native_engineering_selection_invalid')
    packet={'operation':operation,'request':{k:inputs[k] for k in build._REQUEST},
            'artifactIds':selected['artifactIds']}
    _,request,artifacts=build._engineering_packet(packet)
    root=Path(root).resolve(strict=True);source=build._source_root(root,selected['sourceRoot'])
    admitted=build._engineering_context(root,source,request,artifacts,operation)
    if operation=='start':
        burn=build._directory(root,False)/(request['correlationId']+'.engineering-local-launch.json')
        try:build._write_once(burn,{'request':request,'contextSha256':hashlib.sha256(admitted.authority).hexdigest()})
        except FileExistsError:
            proof=admitted.revalidate(source,request)
            return {'tool':'vm_workflow',**build._unknown(request['correlationId'],'already-journaled'),**proof,
                    'ok':False,'productAction':False,'evidenceClass':'engineering-original-source-package-fixture'}
    producer=source/'agent_tools/linux_package_fixture_build.py'
    expected=json.loads(admitted.authority)['catalogue'];held=closure._Held()
    try:
        # Retain the fixed child entrypoint and its repository Python consumers
        # across launch/EOF. Product bytes remain fully revalidated separately.
        for relative,entry in expected.items():
            if relative.startswith(('agent_tools/','scripts/')) and relative.endswith('.py'):
                held.read(str(source/relative),entry['sha256'],tuple(entry['generation']))
        def guard():
            admitted.revalidate(source,request,admission=operation in ('preflight','start'))
            held.finish();held.final_identity_pass()
        guard()
        argv=[sys.executable,'-I','-B',str(producer),'--engineering-local',str(root)]
        authority={'phase':{'preflight':'availability','start':'stage','status':'status','collect':'collect'}[operation],
                   'snapshot':{'contextSha256':hashlib.sha256(admitted.authority).hexdigest(),'request':request},
                   'sources':{str(producer):expected['agent_tools/linux_package_fixture_build.py']},
                   'transport':{},'local':{},'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest()}
        def launch():
            guard()
            return subprocess.Popen(argv,cwd=source,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,bufsize=0)
        outcome,capsule=adapter._capture(root,authority=authority,launch=launch,
                  payload=session.canonical(packet),guard=guard)
        _need(outcome['state']=='captured','native_engineering_response_unknown')
        receipt_raw,receipt_pin=adapter.pipe._read(capsule/'receipt.json')
        receipt=json.loads(receipt_raw)
        _need(receipt_pin==outcome['receiptPin'],'native_engineering_receipt_changed')
        raw,pin=adapter.pipe._read(capsule/'stdout',16384)
        _need(pin==receipt['stdoutPin'] and adapter.pipe._read(capsule/'stderr',adapter.MAX_STDERR)[1]==receipt['stderrPin'],
              'native_engineering_stream_changed')
        result=json.loads(raw,object_pairs_hook=ssh_transport._reject_duplicate_keys)
        proof=admitted.revalidate(source,request,admission=operation in ('preflight','start'))
        _need(type(result) is dict and all(result.get(k)==v for k,v in proof.items()) and
              result.get('correlationId')==request['correlationId'] and result.get('replayAllowed') is False,
              'native_engineering_public_identity_changed')
        public_keys={'state','reason','correlationId','replayAllowed','sourceSha'}
        if operation=='preflight':public_keys|={'baseVersion','targetVersion','host','packageFamilies','nativeActionAllowed'}
        if operation=='status':public_keys|={'terminalObservation'}
        if operation=='collect':public_keys|={'sourceFingerprint','artifacts','timingReceipts'}
        _need(not set(result)-public_keys-set(proof),'native_engineering_public_fields_changed')
        guard()
        return {'tool':'vm_workflow',**result,'ok':result.get('state') in ('ready','submitted','running'),
                'productAction':False,'evidenceClass':'engineering-original-source-package-fixture'}
    finally:held.close()
