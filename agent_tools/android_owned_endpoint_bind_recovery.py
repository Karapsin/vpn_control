"""Separately fenced recovery of the measured, still-linked API29 d959 bind.

This adapter never cleans stages, changes daemon privilege, or retires old receipts.
Native execution belongs to the sole operator. Admission and status are read-only.
"""
from __future__ import annotations
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from . import android_endpoint_admission as endpoint

ORIGINAL='d959d5e7-54e4-4801-b0bd-4b2cdcdfa310'
REMAINING='b059ee7a-9e5f-488e-9f3b-5923b7d648da'
A18='a18fa96c-fde5-432a-bc48-77e9d2e3c21d'
NAMESPACE='76434e4c-6588-4c7e-b939-e3c464de601f'
A18_SHA='965cc6728eb7e50eb71f17c91ade696173e1e53f1d94f9fa0c14964217c64a0a'
NAMESPACE_SHA='9d55fad0a9274abd6627b1f7016a19a07ea7c0af53d9a9d43fb1bf4f83dfa711'
ENDPOINT_SHA='8274fffd51310221658a60686c8ffe4858ee4f5baa87197132b118df096cfca7'
TARGET='/system/etc/security/cacerts'
PID='6654'
CA_NAME='f6366156.0'
CA_SHA='10ed775feff892318b35858be61dfc8ca3989b256b849d92d0ef78a4feeb61f3'
UUID=re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')

def _file_fp(i):
    return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink]

def _directory_fp(path: Path):
    i=path.lstat()
    if not stat.S_ISDIR(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o700:
        raise ValueError('recovery_directory_unsafe')
    return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid]

def _private(path: Path,limit=1048576):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        i=os.fstat(f.fileno())
        if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.getuid() or stat.S_IMODE(i.st_mode)!=0o600 or i.st_nlink!=1 or not 0<i.st_size<=limit:
            raise ValueError('recovery_private_unsafe')
        raw=f.read(limit+1)
        if len(raw)!=i.st_size or _file_fp(i)!=_file_fp(os.fstat(f.fileno())) or _file_fp(i)!=_file_fp(path.lstat()):
            raise ValueError('recovery_private_changed')
    return json.loads(raw),hashlib.sha256(raw).hexdigest(),_file_fp(i)

def _source_snapshot(path: Path,limit=1048576):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        before=os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or not 0<before.st_size<=limit:
            raise ValueError('recovery_source_unsafe')
        raw=f.read(limit+1)
        if len(raw)!=before.st_size or _file_fp(before)!=_file_fp(os.fstat(f.fileno())) or _file_fp(before)!=_file_fp(path.lstat()):
            raise ValueError('recovery_source_changed')
    return {'generation':_file_fp(before),'sha256':hashlib.sha256(raw).hexdigest()},raw

def _source(path: Path):
    return _source_snapshot(path)[0]

def _write(path: Path,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

_TREE_BODY=r'''
set -f
exec 3</system/etc/security/cacerts || exit 71
printf '%s\n' __NS__
/system/bin/readlink /proc/$$/ns/mnt || exit 72
printf '%s\n' __TARGET__
/system/bin/stat -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' /system/etc/security/cacerts || exit 73
printf '%s\n' __FD__
/system/bin/stat -L -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' /proc/$$/fd/3 || exit 74
printf '%s\n' __LINK__
/system/bin/readlink /proc/$$/fd/3 || exit 75
printf '%s\n' __FDINFO__
/system/bin/cat /proc/$$/fdinfo/3 || exit 76
printf '%s\n' __MOUNTS__
/system/bin/cat /proc/$$/mountinfo || exit 77
printf '%s\n' __FILES__
set +f
n=0
for p in /proc/$$/fd/3/* /proc/$$/fd/3/.[!.]* /proc/$$/fd/3/..?*; do
 [ -e "$p" ] || { [ ! -L "$p" ] || exit 78; continue; }
 [ ! -L "$p" ] && [ -f "$p" ] || exit 79
 n=$((n+1)); [ "$n" -le 139 ] || exit 80
 printf 'NAME|%s\n' "${p##*/}"
 /system/bin/stat -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' "$p" || exit 81
 /system/bin/sha256sum "$p" || exit 82
 /system/bin/stat -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' "$p" || exit 83
done
set -f
printf '%s\n' __AFTER__
/system/bin/stat -L -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' /proc/$$/fd/3 || exit 84
/system/bin/stat -c '%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F' /system/etc/security/cacerts || exit 85
printf '%s\n' __MOUNTS_AFTER__
/system/bin/cat /proc/$$/mountinfo || exit 86
printf '%s\n' __END__
'''

def _parse_tree(text,plan,stock,mounted,inside):
    lines=text.splitlines();marks=['__NS__','__TARGET__','__FD__','__LINK__','__FDINFO__','__MOUNTS__','__FILES__','__AFTER__','__MOUNTS_AFTER__','__END__']
    positions=[lines.index(m) for m in marks]
    if positions!=sorted(positions) or any(lines.count(m)!=1 for m in marks) or positions[0]!=0 or positions[-1]!=len(lines)-1:raise ValueError('bind_tree_framing')
    sections={m:lines[positions[n]+1:positions[n+1]] for n,m in enumerate(marks[:-1])}
    def one(key):
        if len(sections[key])!=1:raise ValueError('bind_tree_fields')
        return sections[key][0]
    ns=one('__NS__')
    if not re.fullmatch(r'mnt:\[[0-9]+\]',ns) or inside and ns!=plan['zygote']['namespace']:raise ValueError('bind_namespace_changed')
    target=one('__TARGET__');parts=target.split(':')
    if len(parts)!=10 or parts[-1]!='directory' or not all(re.fullmatch(r'[0-9]+',x) for x in parts[:-1]) or int(parts[5])<1 or target!=one('__FD__') or sections['__AFTER__']!=[target,target] or one('__LINK__')!=plan['target']:raise ValueError('bind_target_changed')
    mountlines=sections['__MOUNTS__']
    if mountlines!=sections['__MOUNTS_AFTER__']:raise ValueError('bind_mount_changed')
    fdids=re.findall(r'^mnt_id:\s*([0-9]+)$','\n'.join(sections['__FDINFO__']),re.M)
    entries=[];ids=set()
    for line in mountlines:
        halves=line.split(' - ')
        if len(halves)!=2:raise ValueError('bind_mount_grammar')
        fields=halves[0].split();right=halves[1].split()
        if len(fields)<6 or len(right)<3 or fields[0] in ids:raise ValueError('bind_mount_grammar')
        ids.add(fields[0]);entries.append({'fields':fields,'filesystem':right[0],'source':right[1],'options':right[2]})
    members=[x for x in entries if len(fdids)==1 and x['fields'][0]==fdids[0]]
    if len(members)!=1:raise ValueError('bind_descriptor_changed')
    ownroot='/local/tmp/vpn-control-endpoint-d959d5e7-54e4-4801-b0bd-4b2cdcdfa310'
    refs=[x for x in entries if x['fields'][2]=='253:32' and (x['fields'][3]==ownroot or x['fields'][3].startswith(ownroot+'/')) or x['fields'][4]==plan['staging'] or x['fields'][4].startswith(plan['staging']+'/')]
    member=members[0];files=sections['__FILES__'];manifest={};generations={}
    if len(files)%4:raise ValueError('bind_manifest_framing')
    for n in range(0,len(files),4):
        filename,generation,digest,after=files[n:n+4]
        if not filename.startswith('NAME|'):raise ValueError('bind_certificate_name')
        name=filename[5:];g=generation.split(':')
        if not re.fullmatch(r'[0-9a-f]{8}\.[0-9]+',name) or name in manifest or len(g)!=10 or g[:3]!=['0','0','644'] or g[-1]!='regular file' or not all(re.fullmatch(r'[0-9]+',x) for x in g[:-1]) or int(g[5])<1 or generation!=after:raise ValueError('bind_certificate_generation')
        match=re.fullmatch(r'([0-9a-f]{64})  /proc/[1-9][0-9]*/fd/3/'+re.escape(name),digest)
        if not match or not 0<int(g[6])<=65536:raise ValueError('bind_certificate_hash')
        manifest[name]={'size':int(g[6]),'sha256':match[1]};generations[name]=generation
    expected=dict(stock['manifest'])
    if mounted and inside:
        expected[CA_NAME]={'size':1188,'sha256':CA_SHA}
        if len(refs)!=1 or member!=refs[0] or member['fields'][0]!='664' or member['fields'][2]!='253:32' or member['fields'][3]!=ownroot or member['fields'][4]!=plan['target'] or member['filesystem']!='ext4' or target!=stock['stageGeneration']:raise ValueError('bind_owned_mount_changed')
    else:
        if refs or target!=stock['targetGeneration'] or member!=stock['membership']:raise ValueError('bind_stock_target_changed')
    if manifest!=expected or len(manifest)!=(139 if mounted and inside else 138):raise ValueError('bind_stock_manifest_changed')
    if not inside and generations!=stock['generations']:raise ValueError('bind_stock_generation_changed')
    if inside and not mounted and generations!=stock['generations']:raise ValueError('bind_stock_generation_changed')
    return {'namespace':ns,'targetGeneration':target,'membership':member,'manifest':manifest,'generations':generations,'mountinfo':'\n'.join(mountlines)}

_REMOTE=r'''
BUNDLE=__BUNDLE__;TREE_BODY=__TREE_BODY__;NEW_ID=__NEW_ID__
base_binding=BUNDLE['binding'];directory=job;reserve=job/'owned-bind-recovery-reservation.json'
admitpath=job/('owned-bind-'+NEW_ID+'.json');attempt=job/('owned-bind-'+NEW_ID+'.attempt.json');terminal=job/('owned-bind-'+NEW_ID+'.recovered.json')
def fail(reason):unknown(reason)
def native_read(words,limit=131072):
 result=subprocess.run([adb,'-s',serial,'shell','-T',*words],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120 if '/system/bin/sh' in words else 10,check=False)
 if result.returncode or result.stderr or len(result.stdout)>limit:fail('bind_read_failed')
 try:return result.stdout.decode('utf-8','strict').strip()
 except UnicodeError:fail('bind_read_failed')
def principal_pin():
 info=native_read(['/system/bin/stat','-c','%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F','/system/xbin/su'],4096)
 if info!=BUNDLE['principal']['generation']:fail('bind_principal_changed')
 digest=native_read(['/system/bin/sha256sum','/system/xbin/su'],4096)
 if digest!=BUNDLE['principal']['sha256']+'  /system/xbin/su':fail('bind_principal_changed')
 return {'generation':info,'sha256':BUNDLE['principal']['sha256']}
def privileged(words):
 principal_pin();result=native_read(['/system/xbin/su','0,0',*words]);principal_pin();return result
def native_directories():
 result={}
 for name,path in (('root',root),('job',job)):
  i=path.lstat()
  if not stat.S_ISDIR(i.st_mode) or stat.S_IMODE(i.st_mode)!=0o700 or i.st_uid!=os.getuid():fail('bind_directory_changed')
  result[name]=[i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid]
 return result
current_attempt_pin=None
def private_guard():
 if isinstance(BUNDLE.get('receipt'),dict):
  if remaining_pin(admitpath,131072)!=BUNDLE.get('receiptPin') or remaining_pin(reserve,8192)!=BUNDLE.get('reservationPin'):fail('bind_receipt_changed')
  for proof in BUNDLE['receipt']['proofs']:
   if remaining_pin(job/proof['name'],1048576)!=proof['pin']:fail('bind_proof_changed')
 if current_attempt_pin is not None and remaining_pin(attempt,8192)!=current_attempt_pin:fail('bind_attempt_changed')
 plan=remaining_records_guard(native=True)
 dirs=native_directories()
 if isinstance(BUNDLE.get('receipt'),dict) and dirs!=BUNDLE['receipt']['snapshot']['directories']:fail('bind_directory_changed')
 if plan!=BUNDLE['baseline']['plan']:fail('bind_plan_changed')
 for label,wanted in BUNDLE['baseline']['records'].items():
  path=root if label=='root' else job if label=='job' else lease if label=='lease' else pathlib.Path(expected['backupPath']) if label=='backup' else job/label
  if label in {'root','job'}:
   i=path.lstat();got=[i.st_dev,i.st_ino,i.st_mode,i.st_uid]
  else:got=remaining_pin(path,67108864 if label=='backup' else 65536 if label=='ca.pem' else 8192)
  if got!=wanted:fail('bind_original_record_changed')
 for proof in BUNDLE['proofs']:
  path=job/proof['name'];pin=remaining_pin(path,1048576)
  if pin['sha256']!=proof['sha256'] or proof.get('pin') is not None and pin!=proof['pin']:fail('bind_proof_changed')
 for group in BUNDLE['history']:
  hjob=root/('android-endpoint-'+group['correlationId'])
  i=hjob.lstat()
  if group.get('directory') and [i.st_dev,i.st_ino,i.st_mode,i.st_uid]!=group['directory']:fail('bind_history_changed')
  for name,wanted in group['pins'].items():
   got=remaining_pin(hjob/name,32768)
   if group.get('permissionFingerprint'):
    gen=list(got['generation']);gen[5]=stat.S_IMODE(gen[5]);got={'fingerprint':gen,'sha256':got['sha256']}
   if got!=wanted:fail('bind_history_changed')
 if os.path.lexists(reserve) and json.loads(private(reserve,8192))!=base_binding:fail('bind_other_recovery_recorded')
 return plan

def fresh_tree(inside,mounted):
 ns=['/system/xbin/su','0,0','/system/bin/nsenter','-t','6654','-m','--'] if inside else []
 outer=' '.join(shlex.quote(x) for x in [*ns,'/system/bin/sh','-c',TREE_BODY]);principal_pin()
 text=native_read(['/system/bin/sh','-c',shlex.quote(outer)]);principal_pin()
 try:return _parse_tree(text,plan,BUNDLE['stock'],mounted,inside)
 except (ValueError,IndexError) as exc:fail(str(exc))
def compact_tree(value):
 return {key:value[key] for key in ('namespace','targetGeneration','membership')}|{key+'Sha256':hashlib.sha256(json.dumps(value[key],sort_keys=True,separators=(',',':')).encode()).hexdigest() for key in ('manifest','generations','mountinfo')}
def snapshot(mounted):
 private_guard();principal_pin()
 if privileged(['/system/bin/id','-u'])!='0':fail('bind_principal_changed')
 help_result=subprocess.run([adb,'-s',serial,'shell','-T','/system/xbin/su','--help'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10,check=False)
 if help_result.returncode or len(help_result.stdout)>8192 or len(help_result.stderr)>8192:fail('bind_principal_changed')
 help_out=help_result.stdout.decode('utf-8','strict').strip();help_err=help_result.stderr.decode('utf-8','strict').strip()
 if help_out and help_err or (help_out or help_err)!=AOSP_HELP:fail('bind_principal_changed')
 principal_pin()
 raw=privileged(['/system/bin/cat','/proc/6654/stat'])
 try:pid=raw.split(' ',1)[0];ticks=int(raw.rsplit(')',1)[1].split()[19])
 except (IndexError,ValueError):fail('bind_zygote_changed')
 if pid!='6654' or ticks!=46432071 or privileged(['/system/bin/readlink','/proc/6654/ns/mnt'])!=plan['zygote']['namespace']:fail('bind_zygote_changed')
 zraw=privileged(['/system/bin/cat','/proc/6654/mountinfo']);layout=mount_layout(plan,zraw)
 if mounted and (len(layout['owned'])!=1 or len(layout['references'])!=1 or layout['owned'][0][0]!='664'):fail('bind_owned_mount_changed')
 if not mounted and (layout['owned'] or layout['references']):fail('bind_mount_still_referenced')
 stage=native_read(['/system/bin/stat','-c','%u:%g:%a:%d:%i:%h:%s:%Y:%Z:%F',plan['staging']])
 if stage!=BUNDLE['baseline']['stageGeneration'] or native_read(['/system/bin/sha256sum',plan['staging']+'/f6366156.0'])!=BUNDLE['baseline']['stageCa']:fail('bind_stage_changed')
 outside=fresh_tree(False,mounted);inside=fresh_tree(True,mounted)
 if inside['mountinfo']!=zraw:fail('bind_namespace_inventory_changed')
 public=remaining_public('0');private_guard();principal_pin()
 if privileged(['/system/bin/readlink','/proc/6654/ns/mnt'])!=plan['zygote']['namespace'] or privileged(['/system/bin/cat','/proc/6654/mountinfo'])!=zraw:fail('bind_namespace_inventory_changed')
 return {'directories':native_directories(),'public':public,'outside':compact_tree(outside),'inside':compact_tree(inside),'stageGeneration':stage,'principal':principal_pin()}
def pair(mounted):
 a=snapshot(mounted);b=snapshot(mounted)
 if a!=b:fail('bind_observation_changed')
 return b

def operate():
 global plan,remote_intent_raw,current_attempt_pin
 descriptor=lease_lock()
 try:
  remote_intent_raw=private(job/'intent.json',8192);plan=private_guard()
  if action=='owned-bind-admit':
   if os.path.lexists(reserve) or any(os.path.lexists(p) for p in (admitpath,attempt,terminal)):fail('bind_recovery_already_recorded')
   first=pair(True)
   proofs=[]
   for proof in BUNDLE['proofs']:proofs.append({**proof,'pin':remaining_pin(job/proof['name'],1048576)})
   record(reserve,base_binding)
   if pair(True)!=first:fail('bind_observation_changed')
   receipt={'schema':1,'kind':'android-owned-linked-bind-recovery','binding':base_binding,'snapshot':first,'proofs':proofs,'source':BUNDLE['source']}
   record(admitpath,receipt);emit('ready','bind_recovery_admitted',bindRecoveryCorrelationId=NEW_ID,receipt=receipt,receiptPin=remaining_pin(admitpath,131072),reservationPin=remaining_pin(reserve,8192),originalOutcome='unknown')
  receipt=json.loads(private(admitpath,131072))
  if receipt.get('binding')!=base_binding or receipt.get('source')!=BUNDLE['source'] or receipt.get('schema')!=1 or receipt.get('kind')!='android-owned-linked-bind-recovery':fail('bind_receipt_changed')
  if BUNDLE.get('receipt') is None:
   if action!='owned-bind-status':fail('bind_admission_required')
  elif receipt!=BUNDLE['receipt'] or remaining_pin(admitpath,131072)!=BUNDLE.get('receiptPin') or remaining_pin(reserve,8192)!=BUNDLE.get('reservationPin'):fail('bind_receipt_changed')
  for proof in receipt['proofs']:
   if remaining_pin(job/proof['name'],1048576)!=proof['pin']:fail('bind_proof_changed')
  if os.path.lexists(terminal):
   recovered=json.loads(private(terminal,131072));now=pair(False)
   if recovered!={'schema':1,'binding':base_binding,'receiptSha256':remaining_pin(admitpath,131072)['sha256'],'snapshot':now}:fail('bind_recovered_proof_changed')
   emit('recovered','bind_stock_restored',bindRecoveryCorrelationId=NEW_ID,originalOutcome='unknown',stageRetired=False,leaseReleased=False)
  if action=='owned-bind-once':
   if os.path.lexists(attempt):fail('bind_attempt_recorded')
   if pair(True)!=receipt['snapshot']:fail('bind_receipt_stale')
   # Create-only durable fence before the only native effect.
   record(attempt,{'schema':1,'binding':base_binding,'receiptSha256':remaining_pin(admitpath,131072)['sha256']})
   current_attempt_pin=remaining_pin(attempt,8192)
   if pair(True)!=receipt['snapshot']:fail('bind_receipt_stale')
   if remaining_pin(attempt,8192)!=current_attempt_pin or remaining_pin(admitpath,131072)!=BUNDLE['receiptPin'] or remaining_pin(reserve,8192)!=BUNDLE['reservationPin']:fail('bind_effect_journal_changed')
   argv=[adb,'-s',serial,'shell','-T','/system/xbin/su','0,0','/system/bin/nsenter','-t','6654','-m','--','/system/bin/umount','/system/etc/security/cacerts']
   try:r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
   except (OSError,subprocess.TimeoutExpired):fail('bind_unmount_uncertain')
   record(job/('owned-bind-'+NEW_ID+'.command.json'),{'schema':1,'argv':argv,'returncode':r.returncode,'stdoutSha256':hashlib.sha256(r.stdout).hexdigest(),'stderrSha256':hashlib.sha256(r.stderr).hexdigest(),'stdout':base64.b64encode(r.stdout[:4096]).decode(),'stderr':base64.b64encode(r.stderr[:4096]).decode(),'truncated':len(r.stdout)>4096 or len(r.stderr)>4096})
   if r.returncode or r.stdout or r.stderr:fail('bind_unmount_uncertain')
   if remaining_pin(attempt,8192)!=current_attempt_pin:fail('bind_attempt_changed')
  elif action!='owned-bind-status':fail('bind_action_invalid')
  if not os.path.lexists(attempt):
   if pair(True)!=receipt['snapshot']:fail('bind_receipt_stale')
   emit('ready','bind_recovery_admitted',bindRecoveryCorrelationId=NEW_ID,receipt=receipt,receiptPin=remaining_pin(admitpath,131072),reservationPin=remaining_pin(reserve,8192),originalOutcome='unknown')
  if current_attempt_pin is None:current_attempt_pin=remaining_pin(attempt,8192)
  if json.loads(private(attempt,8192))!={'schema':1,'binding':base_binding,'receiptSha256':remaining_pin(admitpath,131072)['sha256']}:fail('bind_attempt_changed')
  now=pair(False)
  if now['public']!=receipt['snapshot']['public']:fail('bind_owner_changed')
  if remaining_pin(attempt,8192)!=current_attempt_pin:fail('bind_attempt_changed')
  record(terminal,{'schema':1,'binding':base_binding,'receiptSha256':remaining_pin(admitpath,131072)['sha256'],'snapshot':now})
  emit('recovered','bind_stock_restored',bindRecoveryCorrelationId=NEW_ID,originalOutcome='unknown',stageRetired=False,leaseReleased=False)
 finally:release_lock(descriptor)
operate()
'''

def _proof_bundle(root: Path):
    folder=root/'.runtime/parity-evidence/android-current'
    paths=[folder/('api29-stock-diagnostic-'+A18+'.json'),folder/('api29-namespace-diagnostic-'+NAMESPACE+'.json')]
    pins=[_private(p) for p in paths]
    if pins[0][1]!=A18_SHA or pins[1][1]!=NAMESPACE_SHA:raise ValueError('bind_capsule_changed')
    a,n=[p[0] for p in pins]
    if a.get('endpointCorrelationId')!=ORIGINAL or n.get('endpointCorrelationId')!=ORIGINAL or n.get('sourceProofCorrelationId')!=A18 or n.get('baseline')!=a['baseline'] or n.get('summary')!={'observerNamespaceEqualsZygote':True,'observerMount664Present':True,'zygoteMount664Present':True,'inventoriesEqual':True}:raise ValueError('bind_capsule_invalid')
    stocks=[x['facts'] for x in a['parsed'] if x['view']=='outside']
    if len(stocks)!=2 or stocks[0]!=stocks[1] or len(stocks[0]['manifest'])!=138:raise ValueError('bind_stock_invalid')
    admission=a['history']['data']['mount-recovery-a057e620-2d50-4e91-800e-983f1df8ad86.json']
    history=[{'correlationId':'e2721259-f63c-44f8-ba27-5d17cd5e254e','directory':a['history']['directory'],'pins':a['history']['pins']},{'correlationId':admission['binding']['historicalCorrelationId'],'permissionFingerprint':True,'pins':admission['snapshot']['native']['historicalRecords']}]
    stock={k:stocks[0][k] for k in ('manifest','generations','targetGeneration','membership')};stock['membership']={'fields':stock['membership']['fields'],'filesystem':stock['membership']['filesystem'],'source':stock['membership']['source'],'options':stock['membership']['superOptions']}
    stock['stageGeneration']=a['baseline']['stageGeneration']
    bundle={'baseline':a['baseline'],'stock':stock,'principal':n['principalPin'],'history':history,'proofs':[{'name':'stock-diagnostic-'+A18+'.json','sha256':A18_SHA},{'name':'namespace-diagnostic-'+NAMESPACE+'.json','sha256':NAMESPACE_SHA}]}
    return bundle,list(zip(paths,pins))

def _program(bundle,new_id,snapshots=None):
    paths=(Path(__file__).absolute(),Path(endpoint.__file__).absolute())
    if snapshots is None:snapshots={str(path):_source_snapshot(path) for path in paths}
    own_pin,own_raw=snapshots[str(paths[0])];endpoint_pin,endpoint_raw=snapshots[str(paths[1])]
    if endpoint_pin['sha256']!=ENDPOINT_SHA:raise ValueError('bind_endpoint_source_changed')
    if bundle.get('source') and bundle['source']!={'helperSha256':own_pin['sha256'],'endpointSha256':endpoint_pin['sha256']}:raise ValueError('bind_local_source_changed')
    own_text=own_raw.decode('utf-8','strict');endpoint_text=endpoint_raw.decode('utf-8','strict')
    own_ast=ast.parse(own_text);endpoint_ast=ast.parse(endpoint_text)
    def literal(tree,name):
        matches=[n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
        if len(matches)!=1:raise ValueError('bind_source_definition_changed')
        def evaluate(node):
            if isinstance(node,ast.Constant) and isinstance(node.value,(str,int,float)):return node.value
            if isinstance(node,ast.Name):return literal(tree,node.id)
            if isinstance(node,ast.BinOp) and isinstance(node.op,ast.Add):return evaluate(node.left)+evaluate(node.right)
            if isinstance(node,ast.Call) and not node.keywords:
                if isinstance(node.func,ast.Name) and node.func.id=='repr' and len(node.args)==1:return repr(evaluate(node.args[0]))
                if isinstance(node.func,ast.Attribute) and node.func.attr=='strip' and not node.args:
                    value=evaluate(node.func.value)
                    if isinstance(value,str):return value.strip()
            raise ValueError('bind_source_expression_changed')
        return evaluate(matches[0])
    remote=literal(endpoint_ast,'_REMOTE')
    if remote.count("\nif action=='start':")!=1:raise ValueError('bind_endpoint_source_changed')
    definitions=[n for n in own_ast.body if isinstance(n,ast.FunctionDef) and n.name=='_parse_tree']
    if len(definitions)!=1:raise ValueError('bind_source_definition_changed')
    parse_source=ast.get_source_segment(own_text,definitions[0])
    constants='CA_NAME='+repr(literal(own_ast,'CA_NAME'))+'\nCA_SHA='+repr(literal(own_ast,'CA_SHA'))+'\n'
    # Every embedded definition comes from the same descriptor-validated source snapshots.
    program=remote.split("\nif action=='start':",1)[0]+'\n'+constants+parse_source+'\n'+literal(own_ast,'_REMOTE').replace('__BUNDLE__',repr(bundle)).replace('__TREE_BODY__',repr(literal(own_ast,'_TREE_BODY'))).replace('__NEW_ID__',repr(new_id))
    ast.parse(program);return program

def _call(root: Path|str,new_id: str,action: str):
    root=Path(root).resolve()
    if not isinstance(new_id,str) or not UUID.fullmatch(new_id) or new_id in {ORIGINAL,REMAINING,A18,NAMESPACE}:raise ValueError('bind_distinct_correlation_required')
    bundle,proofpins=_proof_bundle(root)
    original=endpoint._intent_path(root,ORIGINAL);op=endpoint._recovery_local_snapshot(original);intent=op[0]
    req=endpoint._remaining_path(root,REMAINING,'.request.json');rp=endpoint._recovery_local_snapshot(req)
    remaining_binding={'correlationId':REMAINING,'originalIntentSha256':op[1]}
    if intent.get('correlationId')!=ORIGINAL or rp[0]!={'schema':1,'endpointCorrelationId':ORIGINAL,'binding':remaining_binding}:raise ValueError('bind_original_binding_changed')
    local=root/'.rag_index/android-owned-endpoint-bind';local.mkdir(mode=0o700,parents=True,exist_ok=True);dirpin=_directory_fp(local);parentpin=_directory_fp(local.parent)
    snapshots={str(path):_source_snapshot(path) for path in (Path(__file__).absolute(),Path(endpoint.__file__).absolute())}
    sources={path:value[0] for path,value in snapshots.items()}
    source_binding={'helperSha256':sources[str(Path(__file__).absolute())]['sha256'],'endpointSha256':ENDPOINT_SHA}
    binding={'correlationId':new_id,'endpointCorrelationId':ORIGINAL,'originalIntentSha256':op[1]}
    request=local/(new_id+'.request.json');receipt=local/(new_id+'.json');attempt=local/(new_id+'.attempt.json');reservation=local/'reservation.json'
    with endpoint._shared_device_lease(root,intent['host'],intent['device']) as lease:
        lp=endpoint._recovery_local_snapshot(lease)
        if action=='owned-bind-admit':
            if any(os.path.lexists(x) for x in (request,receipt,attempt,reservation)):raise ValueError('bind_local_already_recorded')
            value={'schema':1,'binding':binding,'source':source_binding}
            _write(reservation,value);_write(request,value)
        requestpin=_private(request,8192);respin=_private(reservation,8192)
        if requestpin[0]!={'schema':1,'binding':binding,'source':source_binding} or respin[0]!=requestpin[0]:raise ValueError('bind_local_request_changed')
        receiptpin=_private(receipt,262144) if os.path.lexists(receipt) else None
        attemptpin=_private(attempt,8192) if os.path.lexists(attempt) else None
        bundle.update(binding=binding,source=source_binding)
        if receiptpin:
            envelope=receiptpin[0]
            if envelope.get('receipt',{}).get('binding')!=binding or envelope['receipt'].get('source')!=source_binding:raise ValueError('bind_local_receipt_changed')
            bundle.update(envelope)
        if action=='owned-bind-once':
            if receiptpin is None:raise ValueError('bind_admission_required')
            if attemptpin is not None:return {'state':'unknown','reason':'bind_local_attempt_recorded','originalOutcome':'unknown','replayAllowed':False}
            _write(attempt,{'schema':1,'receiptSha256':receiptpin[1]});attemptpin=_private(attempt,8192)
        def guard():
            endpoint._readmission_local_guard(root,intent,lease)
            if _directory_fp(local)!=dirpin or _directory_fp(local.parent)!=parentpin or endpoint._recovery_local_snapshot(original)!=op or endpoint._recovery_local_snapshot(req)!=rp or endpoint._recovery_local_snapshot(lease)!=lp:raise ValueError('bind_local_owner_changed')
            for path,pin in proofpins:
                if _private(path)!=pin:raise ValueError('bind_local_capsule_changed')
            for path,pin in sources.items():
                if _source(Path(path))!=pin:raise ValueError('bind_local_source_changed')
            for path,pin in ((request,requestpin),(reservation,respin),(receipt,receiptpin),(attempt,attemptpin)):
                if pin is not None and _private(path,262144)!=pin:raise ValueError('bind_local_journal_changed')
        guard();config=endpoint.ssh_transport.load_config(root);host=intent['host']
        if str(config.hosts[host].fixture_transfer_root)!=intent['remoteRoot'] or endpoint.ssh_transport.connection_host(config,host).password is not None:raise ValueError('bind_route_changed')
        expected={**intent['remote'],'cleanupRemaining':remaining_binding};program=_program(bundle,new_id,snapshots)
        command=endpoint._endpoint_python_command(endpoint.android_observation._canonical_cli_environment_source()+program,action,intent['remoteRoot'],intent['device'],ORIGINAL,json.dumps(expected,separators=(',',':')))
        argv=endpoint.ssh_transport.build_ssh_argv(config,host,60,command=command)
        guard()  # Reject source exchange after generation and before remote submission.
        try:
            code,output=endpoint.android_observation._run_probe(argv,24000);guard()
            if code:raise ValueError('bind_transport_failed')
            result=json.loads(output)
        except (OSError,TimeoutError,RuntimeError,ValueError):
            guard();return {'state':'unknown','reason':'bind_transport_unknown','originalOutcome':'unknown','replayAllowed':False}
        if result.get('correlationId')!=ORIGINAL or result.get('bindRecoveryCorrelationId') not in (None,new_id):raise ValueError('bind_response_changed')
        if result.get('state')=='ready' and (action=='owned-bind-admit' or receiptpin is None):
            envelope={key:result[key] for key in ('receipt','receiptPin','reservationPin')}
            if envelope['receipt'].get('binding')!=binding or envelope['receipt'].get('source')!=source_binding:raise ValueError('bind_response_receipt_changed')
            _write(receipt,envelope)
        return {**result,'originalOutcome':'unknown','replayAllowed':False,'stageRetired':False,'leaseReleased':False}

def admit(root,new_correlation_id):return _call(root,new_correlation_id,'owned-bind-admit')
def unmount_once(root,new_correlation_id):return _call(root,new_correlation_id,'owned-bind-once')
def status(root,new_correlation_id):return _call(root,new_correlation_id,'owned-bind-status')
