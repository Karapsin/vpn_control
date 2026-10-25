"""One fixed Linux owner GUI recipe on an already reserved configured guest.

Registered source/package/preparation data never substitutes for fresh native
admission. Tooling and original package provenance stay separate. The existing
ScenarioExecutor owns the durable one-shot intent and UNKNOWN non-replay fence.
"""
from __future__ import annotations
import base64, hashlib, io, json, os, stat, subprocess, tarfile, zlib
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping
try:
    from . import native_scenario_bundle, native_scenario_execution, native_scenario_ssh, ssh_transport
    from . import native_artifact_registry as registry, native_artifact_reuse as reuse, native_environment
    from . import native_review_source_closure as closure
except ImportError:
    import native_scenario_bundle, native_scenario_execution, native_scenario_ssh, ssh_transport
    import native_artifact_registry as registry, native_artifact_reuse as reuse, native_environment
    import native_review_source_closure as closure

SCENARIO_ID='linux-owner-gui-lifecycle'
BUNDLE_SCENARIO_ID='linux-owner-gui-lifecycle-driver'
_FILES=('scripts/integration/linux_owner_lifecycle_scenario.py','scripts/integration/socks_http_fixture.py','scripts/native_fixture_run.sh')
_TRANSFER_ROOT_PROBE="import json,os,stat,sys\nv=json.loads(sys.stdin.buffer.read(8193));ready=False\ntry:\n if type(v) is not dict or set(v)!={'root','context','uid'} or type(v['uid']) is not int:raise ValueError('shape')\n r=v['root'];c=v['context'];u=v['uid']\n if type(r) is not str or type(c) is not str or not r.startswith('/') or os.path.dirname(r)!=c or '..' in r.split('/') or os.getuid()!=u:raise ValueError('binding')\n flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW;identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)\n cf=os.open(c,flags)\n try:\n  cs=os.fstat(cf)\n  if not stat.S_ISDIR(cs.st_mode) or cs.st_uid!=u or stat.S_IMODE(cs.st_mode)!=0o700:raise ValueError('context')\n  rf=os.open(os.path.basename(r),flags,dir_fd=cf)\n  try:\n   rs=os.fstat(rf)\n   ready=stat.S_ISDIR(rs.st_mode) and rs.st_uid==u and stat.S_IMODE(rs.st_mode)==0o700 and identity(rs)==identity(os.stat(os.path.basename(r),dir_fd=cf,follow_symlinks=False)) and identity(cs)==identity(os.fstat(cf))==identity(os.stat(c,follow_symlinks=False))\n  finally:os.close(rf)\n finally:os.close(cf)\nexcept (OSError,ValueError,KeyError,TypeError):ready=False\nprint(json.dumps({'ready':ready,'readOnly':True}))\n"
_INPUT_SCHEMA='vpn-control.linux-owner-gui-lifecycle.input'
_MAX_INPUT=65536

class NativeOwnerGuiLifecycleSshError(ValueError): pass

def require(value,reason):
    if not value:raise NativeOwnerGuiLifecycleSshError(reason)


def _source_namespace(source: bytes, socks: bytes):
    # Import only the pinned fixed driver functions. No main/native operation runs.
    namespace={'__name__':'fixed_gui_source','__file__':'fixed_gui_source','_FIXED_SOURCE':source,'_SOCKS_SOURCE':socks}
    exec(compile(source,'fixed_gui_source','exec'),namespace)
    namespace['_CUSTODY']=namespace['FixedGuiSourceCustody'].memory(source,socks)
    return namespace


def _probe_prefix(source,socks):
    # Bound source stays pinned while compressed transport avoids Linux's
    # per-argument limit after SSH quoting. Compression is source-only.
    def literal(raw):
        encoded=base64.b64encode(__import__('bz2').compress(raw)).decode('ascii')
        return '__import__("bz2").decompress(__import__("base64").b64decode('+repr(encoded)+'))'
    return ('import hashlib,json,sys;source='+literal(source)+';socks='+literal(socks)
        +';assert hashlib.sha256(source).hexdigest()=='+repr(hashlib.sha256(source).hexdigest())
        +';assert hashlib.sha256(socks).hexdigest()=='+repr(hashlib.sha256(socks).hexdigest())
        +';ns={"__name__":"fixed_gui_source","__file__":"fixed_gui_source","_FIXED_SOURCE":source,"_SOCKS_SOURCE":socks};exec(compile(source,"fixed_gui_source","exec"),ns);ns["_CUSTODY"]=ns["FixedGuiSourceCustody"].memory(source,socks);')


def _held_registered(root, artifact_id, maximum, held, expected_path=None):
    location_id=None
    if expected_path is not None:
        require(type(artifact_id) is str and len(artifact_id)==71 and artifact_id.startswith('sha256-') and all(c in '0123456789abcdef' for c in artifact_id[7:]),'registered_digest_binding')
        registry._readonly_private_directory(Path(root)/'.rag_index')
        registry._readonly_private_directory(Path(root)/registry.INDEX_RELATIVE)
        record=registry._read_record_readonly(Path(root)/registry.INDEX_RELATIVE/(artifact_id+'.json'))
        matches=[entry for entry in record['locations'] if entry['evidenceClass']=='local-verified' and entry.get('localPath')==str(expected_path)]
        require(len(matches)==1,'correlated_preparation_location')
        location_id=matches[0]['locationId']
    verified=(registry.verify_artifact_readonly(root,artifact_id) if location_id is None
              else registry.verify_artifact_readonly(root,artifact_id,location_id))
    require(verified.get('verification')=='verified','registered_local_bytes_required')
    location=verified.get('location',{});artifact=verified.get('artifact',{})
    require(location.get('evidenceClass')=='local-verified' and type(location.get('localPath')) is str,'local_artifact_location')
    path=location['localPath'];digest=artifact.get('sha256')
    require(artifact_id=='sha256-'+str(digest),'registered_digest_binding')
    raw=held.read(path,digest,max_bytes=maximum)
    require(len(raw)==artifact.get('size'),'registered_byte_population')
    return raw,artifact


def _package_inventory(path: str, package_digest: str, held):
    # Debian ar is simple and bounded; standard tarfile supports its gzip/xz data.
    # Unsupported compression fails admission instead of trusting an authored list.
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0));st=os.fstat(fd)
    try:
        require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and st.st_nlink==1 and st.st_size<=1024*1024*1024,'package_file')
        h=hashlib.sha256()
        with os.fdopen(os.dup(fd),'rb') as f:
            while chunk:=f.read(1048576):h.update(chunk)
        require(h.hexdigest()==package_digest,'package_bytes')
        os.lseek(fd,0,os.SEEK_SET)
        with os.fdopen(os.dup(fd),'rb') as stream:
            require(stream.read(8)==b'!<arch>\n','deb_archive')
            data=None
            while header:=stream.read(60):
                require(len(header)==60 and header[-2:]==b'`\n','deb_member_header')
                name=header[:16].decode('ascii').strip().rstrip('/');size=int(header[48:58]);require(0<size<=1024*1024*1024,'deb_member_size')
                if name.startswith('data.tar'):
                    require(data is None,'duplicate_deb_data');data=stream.read(size);require(len(data)==size,'deb_truncated')
                else:stream.seek(size,1)
                if size%2:stream.read(1)
            require(data is not None,'deb_data_missing')
        inventory=[]
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:*') as archive:
            for member in archive:
                name=member.name.removeprefix('./')
                require(not name.startswith('/') and '..' not in name.split('/'),'deb_path')
                if not name.startswith('opt/vpn-control/'):continue
                if member.isdir():continue
                if member.issym():
                    target=member.linkname
                    require(not target.startswith('/') and '\x00' not in target and os.path.normpath(os.path.join('/'+os.path.dirname(name),target)).startswith('/opt/vpn-control/'),'installed_image_symlink')
                    inventory.append({'path':'/'+name,'sha256':hashlib.sha256(target.encode()).hexdigest(),'symlinkTarget':target});continue
                require((member.isfile() and 0<member.size<=256*1024*1024) or member.islnk(),'installed_image_entry')
                body=archive.extractfile(member);require(body is not None,'installed_image_data')
                h=hashlib.sha256()
                while chunk:=body.read(1048576):h.update(chunk)
                inventory.append({'path':'/'+name,'sha256':h.hexdigest()})
        require(inventory and len({x['path'] for x in inventory})==len(inventory),'installed_image_inventory')
        require(closure.generation(st)==closure.generation(os.fstat(fd))==closure.generation(os.lstat(path)),'package_generation_drift')
        return sorted(inventory,key=lambda x:x['path'])
    finally:os.close(fd)


_HOST_ALLOCATION_PROBE=r'''import hashlib,json,os,stat,sys
v=json.loads(sys.stdin.buffer.read(16385));a=v['allocation']
def fail():print(json.dumps({'ready':False}));raise SystemExit(0)
try:
 if a['hostBootId']!=open('/proc/sys/kernel/random/boot_id').read().strip():fail()
 p='/proc/'+str(a['qemuPid']);info=os.stat(p,follow_symlinks=False)
 def ticks():return int(open(p+'/stat').read().rsplit(')',1)[1].split()[19])
 if info.st_uid!=a['qemuUid'] or ticks()!=a['qemuStartTicks']:fail()
 raw=open(p+'/cmdline','rb').read(16385)
 if len(raw)>16384 or hashlib.sha256(raw).hexdigest()!=a['qemuArgvSha256']:fail()
 args=raw.rstrip(b'\0').split(b'\0')
 if not os.path.basename(os.readlink(p+'/exe')).startswith('qemu-system-'):fail()
 memory=[];ports=[];disks=[]
 for i,arg in enumerate(args):
  if arg==b'-m' and i+1<len(args):memory.append(args[i+1].decode())
  if arg in (b'-netdev',b'-nic') and i+1<len(args):ports.append(args[i+1].decode())
  if arg==b'-drive' and i+1<len(args):disks.append(args[i+1].decode())
 expected_memory=str(a['configuredMemoryBytes']//1048576)
 if len(memory)!=1 or memory[0] not in (expected_memory,expected_memory+'M'):fail()
 if sum('hostfwd=tcp:127.0.0.1:'+str(a['sshPort'])+'-:22' in x for x in ports)!=1:fail()
 if sum('file='+a['diskPath'] in x.split(',') for x in disks)!=1:fail()
 d=os.stat(a['diskPath'],follow_symlinks=False)
 gen=[d.st_dev,d.st_ino,d.st_mode,d.st_uid,d.st_gid,d.st_nlink,d.st_size,d.st_mtime_ns,d.st_ctime_ns]
 # Live qcow2 data writes change size/time; structural identity is the reservation anchor.
 if gen[:6]!=a['diskGeneration'][:6] or not stat.S_ISREG(d.st_mode):fail()
 if ticks()!=a['qemuStartTicks']:fail()
 print(json.dumps({'ready':True}))
except Exception:fail()
'''

_LAUNCHER = "import hashlib,json,os,stat,subprocess,sys,time\njob,stage=sys.argv[1:]\nwhile not os.path.exists(os.path.join(job,'release')):time.sleep(.01)\nintent=json.load(open(os.path.join(job,'intent.json')))\nif any(intent.get(k)!=v for k,v in _ORIGINAL_PLAN.items()):raise ValueError('original_intent_changed')\nidentity=intent.get('identity',{})\nself_ticks=int(open('/proc/self/stat').read().rsplit(')',1)[1].split()[19])\nif identity.get('pid')!=os.getpid() or identity.get('startTicks')!=self_ticks:raise ValueError('original_launcher_identity')\nrows={x['path']:x for x in _ORIGINAL_CAPSULE['inputs']}\nimport base64\nsource=base64.b64decode(rows['scripts/integration/linux_owner_lifecycle_scenario.py']['body'])\nsocks=base64.b64decode(rows['scripts/integration/socks_http_fixture.py']['body'])\nnamespace={'__name__':'original_gui_launcher_types','__file__':'original_gui_launcher_types','_FIXED_SOURCE':source,'_SOCKS_SOURCE':socks}\nexec(compile(source,'original_gui_launcher_types','exec'),namespace)\nreceipt_path=os.path.join(job,'scenario-receipt.json')\ndef durable(name,value):\n path=os.path.join(job,name);fd=os.open(path+'.tmp',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())\n os.replace(path+'.tmp',path);d=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(d);os.close(d)\nrc=64;child_submitted=False;custody=None\ntry:\n custody=namespace['FixedGuiSourceCustody'](_ORIGINAL_CAPSULE)\n command=['/bin/sh','-c',custody.body('scripts/native_fixture_run.sh').decode(),'immutable-native-fixture-runner',\n  '--pid-file',os.path.join(job,'child.pid'),'--exit-file',os.path.join(job,'child.exit'),'--',\n  *custody.python_command(['--input',custody.path('scenario-input.json'),'--admissions',custody.path('admissions.json'),'--receipt',receipt_path])]\n fd=os.open(os.path.join(job,'failure.stderr'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,'wb') as err:\n  options={'stdin':subprocess.DEVNULL,'stdout':subprocess.DEVNULL,'stderr':err}\n  # This joined close follows every output/argv setup step and precedes\n  # the one original child dispatch. No named source is executed.\n  custody.finish();custody.finish()\n  child_submitted=True\n  rc=subprocess.call(command,**options)\n  err.flush();os.fsync(err.fileno())\nexcept Exception:\n rc=64\nfinally:\n if custody is not None:custody.close()\nevidence={'evidenceClass':'native-owner-gui-lifecycle','scenarioReceiptAvailable':False,'runnerExitCode':rc,\n 'cleanupState':'unknown','originalChildSubmitted':child_submitted,'replayAllowed':False}\ntry:\n fd=os.open(receipt_path,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  st=os.fstat(fd)\n  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4*1024*1024:raise ValueError()\n  raw=os.read(fd,4*1024*1024+1)\n  if len(raw)!=st.st_size:raise ValueError()\n  item=json.loads(raw)\n finally:os.close(fd)\n cleanup=item.get('cleanup')\n if item.get('schema')!='vpn-control.linux-owner-gui-lifecycle.receipt' or item.get('scenarioId')!=intent['scenarioId'] or item.get('correlationId')!=intent['correlationId'] or not isinstance(cleanup,dict):raise ValueError()\n evidence.update(scenarioReceiptAvailable=True,cleanupState=cleanup.get('state','unknown'),scenarioReceiptPath=receipt_path)\n raw_input=base64.b64decode(rows['scenario-input.json']['body']);typed=json.loads(raw_input);bound_source=json.loads(base64.b64decode(rows['admissions.json']['body']))['source']\n if hashlib.sha256(raw_input).hexdigest()!=intent['artifactIds']['scenarioInput'].removeprefix('sha256-') or item.get('sourceIdentity')!=typed['sourceIdentity'] or item.get('packageSourceSha')!=bound_source['packageSourceSha']:raise ValueError()\n expected_labels=('fresh-frontend-attach','hide','show-with-fresh-XID','graceful-close-to-tray','show-after-legitimate-XID-change','exact-frontend-crash','bounded-crash-lease-expiry-with-runtime-traffic','fresh-frontend-without-tray','graceful-close-detach-without-tray','reattach-same-original-owner')\n slices=item.get('slices')\n if rc==0 and (not isinstance(slices,list) or tuple(x.get('action') if isinstance(x,dict) else None for x in slices)!=expected_labels or not all(type(x.get('frames')) is int and x['frames']>=10 and x.get('sameController') is True and x.get('sameRuntime') is True for x in slices)):rc=1\n if rc==0 and (item.get('result')!='passed' or type(item.get('frames')) is not int or item['frames']<80 or cleanup.get('state')!='complete' or not all(cleanup.get(k) is True for k in ('ownerStopped','workspaceRemoved','protectedPreserved','referencesAbsent'))):rc=1\nexcept Exception:\n if rc==0:rc=1\ndurable('evidence.json',evidence)\nreceipt={k:intent[k] for k in ('scenarioId','host','environment','bundleHash','artifactIds','correlationId','jobId')}\nreceipt.update(pid=identity['pid'],startTicks=identity['startTicks'],exitCode=rc);durable('receipt.json',receipt)\n"

_RECEIVER = 'import base64,hashlib,json,os,stat,subprocess,sys,zlib\nroot,host,env,scenario,corr,bundle_hash,artifact_json=sys.argv[1:]\nos.umask(0o077)\nnames=(\'scripts/integration/linux_owner_lifecycle_scenario.py\',\'scripts/integration/socks_http_fixture.py\',\'scripts/native_fixture_run.sh\',\'native-scenario-manifest.json\',\'scenario-input.json\',\'admissions.json\')\ndef bad(reason):print(json.dumps({\'state\':\'unknown\',\'reason\':reason},separators=(\',\',\':\')));raise SystemExit(64)\ndef pairs(rows):\n result={}\n for k,v in rows:\n  if k in result:bad(\'duplicate_key\')\n  result[k]=v\n return result\nif scenario!=\'linux-owner-gui-lifecycle\':bad(\'scenario_not_allowed\')\ntry:\n artifacts=json.loads(artifact_json,object_pairs_hook=pairs)\n if type(artifacts) is not dict or set(artifacts)!={\'bundleManifest\',\'scenarioInput\'}:bad(\'invalid_artifacts\')\n header=json.loads(sys.stdin.buffer.readline(16385),object_pairs_hook=pairs)\n if type(header) is not dict or set(header)!={\'files\'} or type(header[\'files\']) is not list:bad(\'invalid_header\')\n files=header[\'files\']\n if tuple(x.get(\'path\') if type(x) is dict else None for x in files)!=names:bad(\'unexpected_inventory\')\nexcept Exception:bad(\'invalid_header\')\ndef private(path):\n info=os.stat(path,follow_symlinks=False)\n return stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700\nif not root.startswith(\'/\') or \'..\' in root.split(\'/\') or not private(root):bad(\'unsafe_root\')\nbase=os.path.join(root,\'native-scenario-jobs\',env,scenario);os.makedirs(base,mode=0o700,exist_ok=True)\nfor path in (os.path.join(root,\'native-scenario-jobs\'),os.path.join(root,\'native-scenario-jobs\',env),base):\n if not private(path):bad(\'unsafe_root\')\njob=os.path.join(base,corr)\ntry:os.mkdir(job,0o700)\nexcept FileExistsError:bad(\'job_already_exists\')\nstage=os.path.join(job,\'bundle\');os.mkdir(stage,0o700)\noriginal=[]\ndef generation(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]\nfor item in files:\n if set(item)!={\'path\',\'sizeBytes\',\'sha256\'}:bad(\'invalid_file_metadata\')\n path,size,digest=item[\'path\'],item[\'sizeBytes\'],item[\'sha256\']\n if type(size) is not int or not 0<size<=8*1024*1024 or type(digest) is not str or len(digest)!=64:bad(\'invalid_file_metadata\')\n target=os.path.join(stage,path);os.makedirs(os.path.dirname(target),mode=0o700,exist_ok=True)\n fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);parts=[];left=size;hasher=hashlib.sha256()\n with os.fdopen(fd,\'wb\') as out:\n  while left:\n   chunk=sys.stdin.buffer.read(min(left,65536))\n   if not chunk:bad(\'interrupted_transfer\')\n   out.write(chunk);parts.append(chunk);hasher.update(chunk);left-=len(chunk)\n  out.flush();os.fsync(out.fileno());gen=generation(os.fstat(out.fileno()))\n if hasher.hexdigest()!=digest:bad(\'input_hash_mismatch\')\n original.append({\'path\':path,\'body\':base64.b64encode(b\'\'.join(parts)).decode(),\'sha256\':digest,\'generation\':gen})\nrows={x[\'path\']:x for x in original};manifest=base64.b64decode(rows[\'native-scenario-manifest.json\'][\'body\'])\nif hashlib.sha256(manifest).hexdigest()!=bundle_hash or artifacts[\'bundleManifest\']!=\'sha256-\'+bundle_hash:bad(\'manifest_hash_mismatch\')\nif rows[\'scenario-input.json\'][\'sha256\']!=artifacts[\'scenarioInput\'].removeprefix(\'sha256-\'):bad(\'scenario_input_hash_mismatch\')\nparents={}\nfor name in names:\n path=os.path.dirname(os.path.join(stage,name))\n while True:\n  info=os.stat(path,follow_symlinks=False)\n  if not stat.S_ISDIR(info.st_mode):bad(\'unsafe_source_parent\')\n  parents[path]=[info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid]\n  if path==\'/\':break\n  path=os.path.dirname(path)\ncapsule={\'stage\':stage,\'inputs\':original,\'parents\':parents,\'manifestSha256\':bundle_hash}\nsource=base64.b64decode(rows[names[0]][\'body\']);socks=base64.b64decode(rows[names[1]][\'body\'])\nnamespace={\'__name__\':\'fixed_gui_receiver\',\'__file__\':\'fixed_gui_receiver\',\'_FIXED_SOURCE\':source,\'_SOCKS_SOURCE\':socks}\nexec(compile(source,\'fixed_gui_receiver\',\'exec\'),namespace)\ncustody=namespace[\'FixedGuiSourceCustody\'](capsule)\ntry:\n typed=json.loads(custody.body(\'scenario-input.json\'),object_pairs_hook=pairs);namespace[\'validate_input\'](typed,corr)\n intent={\'scenarioId\':scenario,\'host\':host,\'environment\':env,\'bundleHash\':bundle_hash,\'artifactIds\':artifacts,\'correlationId\':corr,\'jobId\':\'gui-lifecycle-\'+corr}\n def durable(path,value):\n  fd=os.open(path+\'.tmp\',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n  with os.fdopen(fd,\'w\') as out:json.dump(value,out,sort_keys=True);out.flush();os.fsync(out.fileno())\n  os.replace(path+\'.tmp\',path);d=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(d);os.close(d)\n durable(os.path.join(job,\'intent.json\'),intent)\n # Retain the emitted source for evidence. Execution uses the original literal.\n launcher=os.path.join(job,\'launch.py\');fd=os.open(launcher,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)\n with os.fdopen(fd,\'w\') as out:out.write(_LAUNCHER_SOURCE);out.flush();os.fsync(out.fileno())\n raw=(json.dumps(capsule,sort_keys=True,separators=(\',\',\':\'))+\'\\n\').encode(\'utf-8\');seal=hashlib.sha256(raw).hexdigest()\n wire=json.loads(raw)\n for row in wire[\'inputs\']:row[\'body\']=base64.b64decode(row[\'body\'],validate=True).decode(\'utf-8\')\n encoded=base64.b64encode(zlib.compress(json.dumps(wire,sort_keys=True,separators=(\',\',\':\')).encode(\'utf-8\'))).decode(\'ascii\')\n command=\'import base64,hashlib,json,zlib;wire=json.loads(zlib.decompress(base64.b64decode(\'+repr(encoded)+\')));\\nfor row in wire["inputs"]:row["body"]=base64.b64encode(row["body"].encode("utf-8")).decode("ascii")\\nraw=(json.dumps(wire,sort_keys=True,separators=(",",":"))+chr(10)).encode("utf-8");assert hashlib.sha256(raw).hexdigest()==\'+repr(seal)+\';_ORIGINAL_CAPSULE=wire;_ORIGINAL_PLAN=\'+repr(intent)+\';exec(compile(\'+repr(_LAUNCHER_SOURCE)+\',"original_fixed_gui_launcher","exec"))\'\n if len(command.encode())>=65536:bad(\'launcher_command_bound\')\n argv=[sys.executable,\'-I\',\'-B\',\'-c\',command,job,stage]\n options={\'stdin\':subprocess.DEVNULL,\'stdout\':subprocess.DEVNULL,\'stderr\':subprocess.DEVNULL,\'start_new_session\':True}\n custody.finish();custody.finish()\n proc=subprocess.Popen(argv,**options)\n try:ticks=int(open(\'/proc/%d/stat\'%proc.pid).read().rsplit(\')\',1)[1].split()[19])\n except Exception:bad(\'proc_generation_unavailable\')\n identity={\'jobId\':intent[\'jobId\'],\'pid\':proc.pid,\'startTicks\':ticks,\'receiptPath\':os.path.join(job,\'receipt.json\')}\n intent[\'identity\']=identity;durable(os.path.join(job,\'intent.json\'),intent)\n fd=os.open(os.path.join(job,\'release\'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)\n print(json.dumps({\'state\':\'submitted\',\'identity\':identity},separators=(\',\',\':\')))\nfinally:custody.close()\n'

def _receiver():
    return '_LAUNCHER_SOURCE='+repr(_LAUNCHER)+'\n'+_RECEIVER

_COLLECT=r'''import hashlib,json,os,stat,sys
root,host,env,scenario,corr,bundle_hash,artifact_json,pid,ticks=sys.argv[1:]
job=os.path.join(root,'native-scenario-jobs',env,scenario,corr)
def unknown():print(json.dumps({'state':'unknown','correlationId':corr}));raise SystemExit(0)
def read(name):
 fd=os.open(os.path.join(job,name),os.O_RDONLY|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd)
  if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600 or st.st_size>4*1024*1024:unknown()
  raw=os.read(fd,4*1024*1024+1)
  if len(raw)!=st.st_size:unknown()
  if name=="scenario-receipt.json":
   global receipt_raw
   receipt_raw=raw
  return json.loads(raw)
 finally:os.close(fd)
try:
 st=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:unknown()
 intent=read('intent.json');wrapper=read('receipt.json');receipt=read('scenario-receipt.json')
 expected={'scenarioId':scenario,'host':host,'environment':env,'correlationId':corr,'bundleHash':bundle_hash,'artifactIds':json.loads(artifact_json)}
 if any(intent.get(k)!=v or wrapper.get(k)!=v for k,v in expected.items()):unknown()
 identity=intent.get('identity',{})
 if any(type(identity.get(k)) is not int for k in ('pid','startTicks')) or any(type(wrapper.get(k)) is not int for k in ('pid','startTicks','exitCode')) or identity.get('pid')!=int(pid) or identity.get('startTicks')!=int(ticks) or wrapper.get('pid')!=int(pid) or wrapper.get('startTicks')!=int(ticks):unknown()
 if receipt.get('schema')!='vpn-control.linux-owner-gui-lifecycle.receipt' or receipt.get('scenarioId')!=scenario or receipt.get('correlationId')!=corr:unknown()
 cleanup=receipt.get('cleanup',{})
 if not isinstance(cleanup,dict):unknown()
 summary={'state':'collected','scenarioId':scenario,'correlationId':corr,'result':receipt.get('result') if receipt.get('result') in ('passed','failed','unknown') else 'unknown',
  'exitCode':wrapper.get('exitCode'),'frames':receipt.get('frames') if type(receipt.get('frames')) is int else None,
  'cleanup':{'state':cleanup.get('state'),**{k:cleanup.get(k) if type(cleanup.get(k)) is bool else None for k in ('ownerStopped','workspaceRemoved','protectedPreserved','referencesAbsent')}},
  'ownedActors':receipt.get('ownedActors') if isinstance(receipt.get('ownedActors'),list) and len(receipt['ownedActors'])<=16 else None,'originalEvidenceDirectory':receipt.get('originalEvidenceDirectory'),'sourceIdentity':receipt.get('sourceIdentity'),'packageSourceSha':receipt.get('packageSourceSha'),'displayRestoration':receipt.get('displayRestoration'),'replayAllowed':False}
 # Retain the actual complete guest receipt in the private caller payload.
 # Existing transport budget stays 8192. A larger receipt remains immutable
 # on the guest and its observation is explicitly partial/UNKNOWN.
 summary['actualReceiptRaw']=receipt_raw.decode('utf-8')
 summary['actualReceiptSha256']=hashlib.sha256(receipt_raw).hexdigest()
 complete=json.dumps(summary,separators=(',',':'),ensure_ascii=False,allow_nan=False)
 if len(complete.encode('utf-8'))>8192:
  print(json.dumps({'state':'unknown','correlationId':corr,'partial':True,'reason':'collector_output_limit','originalRetained':True,'originalReceiptSha256':hashlib.sha256(receipt_raw).hexdigest()},separators=(',',':')))
 else:print(complete)
except Exception:unknown()
'''

class NativeOwnerGuiLifecycleSshDriver(native_scenario_ssh.NativeScenarioSshDriver):
    def __init__(self,repository_root,bundle_resolver,input_resolver,timeout_seconds=30,ssh_binary='ssh',configuration_root=None):
        super().__init__(repository_root,bundle_resolver,timeout_seconds,ssh_binary,configuration_root)
        self.input_resolver=input_resolver

    def _prepare(self,plan):
        require(plan.scenario_id==SCENARIO_ID and set(plan.artifact_ids)=={'bundleManifest','scenarioInput'},'fixed_gui_artifacts')
        bundle=Path(self.bundle_resolver(plan))
        verified=native_scenario_bundle.verify_bundle(self.root,bundle,plan.bundle_hash)
        require(verified['scenarioId']==BUNDLE_SCENARIO_ID,'fixed_gui_bundle')
        require(plan.artifact_ids['bundleManifest']=='sha256-'+plan.bundle_hash,'bundle_artifact_binding')
        held=closure._Held()
        try:
            manifest_bytes=held.read(str(bundle/native_scenario_bundle.MANIFEST_NAME),plan.bundle_hash,max_bytes=65536)
            sources={row['path']:held.read(str(bundle/row['path']),row['sha256'],max_bytes=row['sizeBytes']) for row in verified['files']}
            ns=_source_namespace(sources[_FILES[0]],sources[_FILES[1]])
            raw,input_identity=_held_registered(self.root,plan.artifact_ids['scenarioInput'],_MAX_INPUT,held)
            value=ns['validate_input'](json.loads(raw,object_pairs_hook=closure._pairs),plan.correlation_id)
            original=input_identity.get('sourceSha')
            require(original==value['sourceIdentity']['sourceSha'],'input_tooling_source_binding')
            admissions={}
            for name in ('guest','display','fixture','protected'):
                key={'guest':'guestAdmissionArtifactId','display':'displayAdmissionArtifactId','fixture':'fixtureAdmissionArtifactId','protected':'protectedOwnerArtifactId'}[name]
                data,identity=_held_registered(self.root,value[key],262144,held,Path(self.root)/'.rag_index'/'native-owner-gui-preparations'/plan.correlation_id/(name+'.json'))
                admissions[name]=json.loads(data,object_pairs_hook=closure._pairs)
                require(type(admissions[name]) is dict,'preparation_receipt_object')
            admissions['source']=self._source_admission(value,held)
            guest=admissions['guest'];require(guest.get('host')==plan.host and guest.get('environment')==plan.environment,'guest_route_binding')
            self._allocation(guest)
            held.finish();held.finish()
        except BaseException:
            held.close();raise
        try:
            config=ssh_transport.load_config(self.configuration_root);target=config.hosts.get(plan.host)
            remote_root=getattr(target,'fixture_transfer_root',None) if target else None
            require(isinstance(remote_root,PurePosixPath) and remote_root.is_absolute(),'configured_fixture_transfer_root')
            require(target.port==guest['allocation']['sshPort'],'configured_guest_port')
            return bundle,raw,value,admissions,sources,config,remote_root,held,manifest_bytes
        except BaseException:
            held.close();raise

    def _source_admission(self,value,held):
        package=value['installedPackage'];checked=registry.verify_artifact_readonly(self.root,package['artifactId'])
        require(checked.get('verification')=='verified' and checked['artifact']['platform']=='linux'
                and checked['artifact']['sha256']==package['sha256'],'registered_deb')
        package_source=checked['artifact']['sourceSha'];source=value['sourceIdentity']
        proof=reuse.acceptance_equivalence_check_readonly(self.root,source['artifactSetId'],package_source,source['sourceSha'])
        require(package['artifactId'] in proof['immutableArtifactIDs'],'frozen_package_population')
        require(proof['productTreeSha256']==source['sourceFingerprint'],'derived_frozen_product_fingerprint')
        inventory=_package_inventory(checked['location']['localPath'],package['sha256'],held)
        require(any(x['path'].startswith('/opt/vpn-control/lib/app/desktopApp-') and x['sha256']==package['desktopMainJarSha256'] for x in inventory),'package_jar_binding')
        source_admission={'targetSourceSha':source['sourceSha'],'packageSourceSha':package_source,
            'packageSha256':package['sha256'],'artifactSetId':source['artifactSetId'],'equivalence':proof,'installedFiles':inventory}
        return source_admission

    def _allocation(self,guest):
        allocation=guest.get('allocation')
        require(type(allocation) is dict and set(allocation)=={'hostAlias','hostBootId','qemuPid','qemuStartTicks','qemuUid','qemuArgvSha256','configuredMemoryBytes','sshPort','diskPath','diskGeneration','reservationId','operator'},'allocation_fields')
        require(all(type(allocation[k]) is int and allocation[k]>0 for k in ('qemuPid','qemuStartTicks','configuredMemoryBytes','sshPort'))
                and type(allocation['qemuUid']) is int and allocation['qemuUid']>=0 and 1024<=allocation['sshPort']<=65535,'allocation_identity')
        require(type(allocation['diskGeneration']) is list and len(allocation['diskGeneration'])==9
                and all(type(x) is int and x>=0 for x in allocation['diskGeneration']),'allocation_disk_generation')
        # The reservation state is an existing original record, never an authored
        # caller success flag. Loading does no allocation or token publication.
        directory,path=native_environment._root_paths(self.root);native_environment._require_private(directory,directory=True)
        state=native_environment._load(path)
        matches=[x for x in state['reservations'] if x.get('id')==allocation['reservationId']]
        require(len(matches)==1,'reservation_missing_or_ambiguous');record=matches[0]
        require(record.get('hostAlias')==allocation['hostAlias'] and record.get('environment')==guest['environment']
                and record.get('operator')==allocation['operator'] and record.get('allocationState')=='running'
                and record.get('requestedMemoryBytes')==allocation['configuredMemoryBytes'],'reservation_binding')
        config=ssh_transport.load_config(self.configuration_root)
        require(allocation['hostAlias'] in config.hosts,'allocation_configured_host')
        result=self._run(config,allocation['hostAlias'],native_scenario_ssh._py(_HOST_ALLOCATION_PROBE),json.dumps({'allocation':allocation}).encode())
        require(result and result.get('ready') is True,'fresh_qemu_allocation_unavailable')

    def _run_closed(self,config,host,command,payload,held):
        argv=ssh_transport.build_ssh_argv(config,host,self.timeout_seconds,command=command,ssh_binary=self.ssh_binary)
        connection=ssh_transport.connection_host(config,host)
        def run(environment=None):
            options={'input':payload,'stdout':subprocess.PIPE,'stderr':subprocess.DEVNULL,
                'timeout':self.timeout_seconds+2,'env':environment,'check':False}
            def submit(submitted, **submitted_options):
                # Configuration/askpass/output/argv setup is complete before this
                # joined closing immediately at the actual original dispatch.
                held.finish();held.finish()
                return ssh_transport._run_inline(submitted,**submitted_options)
            return ssh_transport.run_ssh(argv,runner=submit,**options)
        try:
            if connection.password is not None:
                import tempfile
                with tempfile.TemporaryDirectory(prefix='vpn-control-gui-askpass-') as temporary:
                    _,environment=ssh_transport._askpass_environment(connection.password,Path(temporary))
                    done=run(environment)
            else:done=run()
        except (OSError,subprocess.TimeoutExpired):return None
        if done.returncode!=0 or len(done.stdout)>8192:return None
        try:value=json.loads(done.stdout,object_pairs_hook=closure._pairs)
        except (ValueError,UnicodeError):return None
        return value if type(value) is dict else None

    def _preflight_prepared(self,prepared):
        _,raw,_,admissions,sources,config,remote_root,held,_=prepared
        root_check=self._run_closed(config,admissions['guest']['host'],native_scenario_ssh._py(_TRANSFER_ROOT_PROBE),json.dumps({'root':str(remote_root),'context':str(Path(admissions['guest']['ownedRoot']).parent),'uid':admissions['guest']['uid']}).encode(),held)
        if not root_check or root_check.get('ready') is not True or root_check.get('readOnly') is not True:
            return {'ready':False,'requirements':{'guiAdmission':{'state':'unknown','reason':'configured_transfer_root_unavailable','evidenceScope':'read-only-guest-probe'}},'scenarioId':SCENARIO_ID}
        program=_probe_prefix(sources[_FILES[0]],sources[_FILES[1]])+'v=json.loads(sys.stdin.buffer.read(262145),object_pairs_hook=ns["pairs"]);ns["validate_input"](v["input"]);print(json.dumps(ns["admission_probe"](v["input"],v["admissions"])))'
        payload=json.dumps({'input':json.loads(raw),'admissions':admissions}).encode()
        value=self._run_closed(config,admissions['guest']['host'],native_scenario_ssh._py(program),payload,held)
        return {'ready':bool(value and value.get('ready') is True),'requirements':{'guiAdmission':{'state':'ready' if value and value.get('ready') is True else 'unknown','reason':'fresh_fixed_gui_probe','evidenceScope':'read-only-guest-probe'}},'scenarioId':SCENARIO_ID}

    def preflight(self,plan):
        prepared=self._prepare(plan)
        try:return self._preflight_prepared(prepared)
        finally:prepared[-2].close()

    def submit(self,plan):
        prepared=self._prepare(plan)
        bundle,raw,_,admissions,sources,config,remote_root,held,manifest=prepared
        try:
            ready=self._preflight_prepared(prepared);require(ready['ready'],'fresh_gui_admission_required')
            entries=[];contents=[]
            for relative,body in [(p,sources[p]) for p in _FILES]+[(native_scenario_bundle.MANIFEST_NAME,manifest),('scenario-input.json',raw),('admissions.json',json.dumps(admissions,sort_keys=True,separators=(',',':')).encode()+b'\n')]:
                entries.append({'path':relative,'sizeBytes':len(body),'sha256':hashlib.sha256(body).hexdigest()});contents.append(body)
            payload=json.dumps({'files':entries},sort_keys=True,separators=(',',':')).encode()+b'\n'+b''.join(contents)
            command=native_scenario_ssh._py(_receiver(),str(remote_root),plan.host,plan.environment,plan.scenario_id,plan.correlation_id,plan.bundle_hash,json.dumps(dict(plan.artifact_ids),sort_keys=True,separators=(',',':')))
            result=self._run_closed(config,plan.host,command,payload,held)
            require(result and result.get('state')=='submitted','gui_submit_unknown_observe_original')
            return self._identity(result.get('identity'),pending=True)
        finally:held.close()

    def collect(self,plan,identity):
        # Observation requires neither the local bundle nor retired input bytes.
        if plan.scenario_id!=SCENARIO_ID or identity.pid is None or identity.start_ticks is None:return None
        try:
            config=ssh_transport.load_config(self.configuration_root);target=config.hosts.get(plan.host);remote_root=getattr(target,'fixture_transfer_root',None)
            if not isinstance(remote_root,PurePosixPath) or not remote_root.is_absolute():return None
            value=self._run(config,plan.host,native_scenario_ssh._py(_COLLECT,str(remote_root),plan.host,plan.environment,plan.scenario_id,plan.correlation_id,plan.bundle_hash,json.dumps(dict(plan.artifact_ids),sort_keys=True,separators=(',',':')),str(identity.pid),str(identity.start_ticks)),None)
            return value if value and value.get('state') in ('collected','unknown') and value.get('correlationId')==plan.correlation_id else None
        except (OSError,ValueError):return None


def fixture_preflight(root,request):
    def bundle(plan):
        item=registry.verify_artifact_readonly(root,plan.artifact_ids['bundleManifest']);require(item.get('verification')=='verified','registered_bundle')
        path=Path(item['location']['localPath']);require(path.name==native_scenario_bundle.MANIFEST_NAME,'bundle_manifest_name');return path.parent
    def input_path(plan):
        item=registry.verify_artifact_readonly(root,plan.artifact_ids['scenarioInput']);require(item.get('verification')=='verified','registered_input');return Path(item['location']['localPath'])
    plan=native_scenario_execution.ScenarioPlan.from_mapping({'scenarioId':SCENARIO_ID,'host':request['host'],'environment':request['environment'],
        'bundleHash':request['bundleManifestArtifactId'].removeprefix('sha256-'),'artifactIds':{'bundleManifest':request['bundleManifestArtifactId'],'scenarioInput':request['scenarioInputArtifactId']},'correlationId':request['scenarioCorrelationId']})
    try:return NativeOwnerGuiLifecycleSshDriver(root,bundle,input_path).preflight(plan)
    except (ValueError,OSError):return {'ready':False,'scenarioId':SCENARIO_ID,'requirements':{'guiAdmission':{'state':'unknown','reason':'fixed_gui_admission_unavailable','evidenceScope':'registered-and-live-guest'}}}

PREPARATION_SCENARIO='linux-owner-gui-lifecycle-preparation'

def preparation_preflight(root,request):
    """Produce registered observations through the existing fixture-preflight action.

    The preparation artifact contains exact selectors for already owned actors.
    Fixed native observation captures actual facts; no guest mutation is dispatched.
    Local exclusive receipts record the original observation and its source bytes.
    """
    held=closure._Held();output=None
    try:
        artifact_id=request['bundleManifestArtifactId']
        raw,identity=_held_registered(root,artifact_id,65536,held)
        manifest=json.loads(raw,object_pairs_hook=closure._pairs)
        selected=registry.verify_artifact_readonly(root,artifact_id)
        path=Path(selected['location']['localPath']);require(path.name==native_scenario_bundle.MANIFEST_NAME,'preparation_bundle_manifest')
        verified=native_scenario_bundle.verify_bundle(root,path.parent,artifact_id.removeprefix('sha256-'))
        require(verified['scenarioId']==BUNDLE_SCENARIO_ID,'preparation_fixed_bundle')
        sources={row['path']:held.read(str(path.parent/row['path']),row['sha256'],max_bytes=row['sizeBytes']) for row in verified['files']}
        ns=_source_namespace(sources[_FILES[0]],sources[_FILES[1]])
        raw,identity=_held_registered(root,request['preparationInputArtifactId'],65536,held)
        selectors=ns['validate_preparation'](json.loads(raw,object_pairs_hook=closure._pairs))
        require(selectors['host']==request['host'] and selectors['environment']==request['environment'],'preparation_route_binding')
        require(identity.get('sourceSha')==selectors['sourceIdentity']['sourceSha'],'preparation_tooling_source')
        config=ssh_transport.load_config(root);target=config.hosts.get(request['host'])
        require(target is not None and target.port==selectors['guest']['allocation']['sshPort'],'prepared_configured_guest_route')
        driver=NativeOwnerGuiLifecycleSshDriver(root,lambda p:path.parent,lambda p:None)
        source=driver._source_admission(selectors,held)
        guest={**selectors['guest'],'host':request['host'],'environment':request['environment']}
        driver._allocation(guest)
        held.finish();held.finish()
        output=Path(root)/'.rag_index'/'native-owner-gui-preparations'/selectors['correlationId']
        output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        require(output.parent.lstat().st_uid==os.getuid() and stat.S_IMODE(output.parent.lstat().st_mode)==0o700,'preparation_output_owner')
        output.mkdir(mode=0o700)
        intent={'scenarioId':PREPARATION_SCENARIO,'correlationId':selectors['correlationId'],'host':request['host'],'environment':request['environment'],
            'bundleManifestArtifactId':artifact_id,'preparationInputArtifactId':request['preparationInputArtifactId'],'nativeActionAllowed':False}
        ns['durable'](output/'observation-intent.json',intent)
        program=_probe_prefix(sources[_FILES[0]],sources[_FILES[1]])+'v=json.loads(sys.stdin.buffer.read(262145),object_pairs_hook=ns["pairs"]);\ntry:\n result=ns["observe_preparation"](v["selectors"],v["source"])\nexcept Exception as error:\n gate=str(error) if isinstance(error,ns["ScenarioError"]) else type(error).__name__;result={"state":"unknown","gate":gate if __import__("re").fullmatch("[A-Za-z0-9_-]{1,64}",gate) else "native_preparation_unavailable","nativeActionAllowed":False}\nprint(json.dumps(result,separators=(",",":")))'
        observed=driver._run_closed(config,request['host'],native_scenario_ssh._py(program),json.dumps({'selectors':selectors,'source':source}).encode(),held)
        require(observed and observed.get('state')=='observed' and observed.get('nativeActionAllowed') is False
                and observed.get('productAcceptance') is False,'preparation_unknown_'+str((observed or {}).get('gate','transport')))
        held.finish();held.finish()
        ns['private_directory'](output)
        admissions=observed['admissions'];require(type(admissions) is dict and set(admissions)=={'guest','display','fixture','protected'},'preparation_observation_population')
        expected={'guest':'vpn-control.linux-owner-gui.guest','display':'vpn-control.linux-owner-gui.display',
            'fixture':'vpn-control.linux-owner-gui.fixture','protected':'vpn-control.linux-owner-gui.protected'}
        receipts={}
        for name in ('guest','display','fixture','protected'):
            item=admissions[name]
            require(type(item) is dict and item.get('schema')==expected[name] and type(item.get('schemaVersion')) is int
                    and item['schemaVersion']==1,'preparation_receipt_shape')
            ns['durable'](output/(name+'.json'),item)
            body=(output/(name+'.json')).read_bytes()
            registered=registry.register_artifact(root,{'platform':'linux','artifactKind':'owner-gui-'+name,'evidenceClass':'local-verified',
                'localPath':str(output/(name+'.json')),'sha256':hashlib.sha256(body).hexdigest(),'size':len(body),
                'sourceSha':selectors['sourceIdentity']['sourceSha'],'sourceFingerprint':selectors['sourceIdentity']['sourceFingerprint']})
            receipts[name]=registered['artifactId']
        spec=observed['scenarioInput'];ns['validate_input'](spec,selectors['correlationId'])
        for name,key in (('guest','guestAdmissionArtifactId'),('display','displayAdmissionArtifactId'),('fixture','fixtureAdmissionArtifactId'),('protected','protectedOwnerArtifactId')):
            spec[key]=receipts[name]
        ns['durable'](output/'scenario-input.json',spec);body=(output/'scenario-input.json').read_bytes()
        registered=registry.register_artifact(root,{'platform':'linux','artifactKind':'owner-gui-input','evidenceClass':'local-verified',
            'localPath':str(output/'scenario-input.json'),'sha256':hashlib.sha256(body).hexdigest(),'size':len(body),
            'sourceSha':selectors['sourceIdentity']['sourceSha'],'sourceFingerprint':selectors['sourceIdentity']['sourceFingerprint']})
        result={'state':'observed','ready':True,'scenarioId':PREPARATION_SCENARIO,'scenarioInputArtifactId':registered['artifactId'],
            'scenarioCorrelationId':selectors['correlationId'],'bundleManifestArtifactId':artifact_id,'admissionArtifactIds':receipts,
            'requirements':{'preparation':{'state':'ready','reason':'actual_fixed_native_observation','evidenceScope':'original-registered-observation'}},
            'nativeActionAllowed':False,'productAcceptance':False}
        ns['durable'](output/'observation-result.json',result)
        return result
    except (ValueError,OSError,KeyError,TypeError) as error:
        reason=str(error) if isinstance(error,NativeOwnerGuiLifecycleSshError) else 'preparation_unavailable'
        return {'state':'unknown','ready':False,'scenarioId':PREPARATION_SCENARIO,'requirements':{'preparation':{'state':'unknown','reason':reason[:128],
            'evidenceScope':'registered-selectors-and-native-observation'}},'nativeActionAllowed':False,'productAcceptance':False,
            'replayAllowed':False,'originalObservationPath':str(output) if output else None}
    finally:held.close()
