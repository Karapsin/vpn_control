"""Separately correlated shell-only OS proxy observation; never restores proxy state.

Root compiles/stages after review. The old failed-check helper stays immutable.
AOSP URLs refer to android15-release; runtime signature/access still needs proof.
Staging scope: the authorized single operator controls the disposable guest's
shell UID 2000 namespace. Authority starts at acquisition of the currently
private, shell-owned correlation directory and exclusive DEX descriptor. The
pre-cd mkdir inode is not attested; concurrent adversarial shell-UID writers
before acquisition are outside this ownership model. No existing file may be
clobbered, and acquired parent/file identity is guarded afterward.
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
from agent_tools import android_installer_failed_check_retirement as old

ADMISSION = '45a379b3-417e-4e00-a8e4-e2e8657c1705'
OS_OBSERVATION = '80b0c504-4780-4c95-a421-29b76808eec7'
OLD_HELPER_SHA = '3eed5a2ecf544ab306e79847152145e1d78112bd5f40ec00f66a8638e0c40f7c'
OLD_OS_SOURCE_SHA = 'b339d8a49d23b99c2aea3c38947e205000e925abc2a84e569ed9eb2db18944b9'
OS_RECEIPT_PIN = {'bytes':112482,'generation':[66307,103947470,112482,1790997593530047735,1790997593530047735,384,1000,1],'sha256':'b4b771c0e6ea4b1888276c4d338059146ff1f6a9c3a35f3b913b516e3fcf5a65'}
OS_CAPTURE_PIN = {'bytes':70435,'generation':[66307,103947469,70435,1790997593528716116,1790997593528716116,384,1000,1],'sha256':'c4276ab0d415eae3729bd3a3b0a2671d2b42484e807fdc19158055589b8261b2'}
STAGE_AUTHORITY = {'model':'authorized-single-operator-shell-namespace','uid':2000,'parentAuthority':'current-private-parent-at-cd-acquisition','preCdMkdirInodeContinuity':'not-proven','concurrentAdversarialSameUidWriters':'outside-authorized-model','existingFileOverwriteAllowed':False}
JAVA_REL = 'agent_tools/fixtures/android_proxy_os_probe/ProxyProbe.java'
JAVA_SHA = '7bdf36cfed66df1e022be0e2a6a0d886153e51e078b7422346bd44cc2e838585'
PRIMARY = {
 'baseUrl':'https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android15-release/',
 'files':{
  'framework/src/android/net/IConnectivityManager.aidl':'fd587c60a6181c53adce2016677b1fc12be18594a6bbedd79cbbd78e54a36247',
  'framework/src/android/net/ConnectivityManager.java':'0e4f0a2b5ab2a972942dcb6d557ea8a3b73fa07224a1772963eb79df40f06e90',
  'service/src/com/android/server/ConnectivityService.java':'91b5d7a9922cd2386cae8284cc64b30dccbba180c55b098bea62756177937818',
  'service/src/com/android/server/connectivity/ProxyTracker.java':'80e1fca0d07e4adb44042b4dcac2b0cb9f318d24ea651e6369613dd3ad626cb0'},
 'actualDeviceApplicability':'requires-runtime-measurement'}
_UUID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}')


def regular_pin(path: Path | str, limit: int = 67108864) -> dict:
    """Pin a root-selected compiler/source without changing filesystem permissions."""
    path=Path(path)
    parents=old._ancestry(path.parent)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>limit:raise ValueError('regular_input_unsafe')
        raw=b''
        while len(raw)<=limit:
            chunk=os.read(fd,min(65536,limit+1-len(raw)))
            if not chunk:break
            raw+=chunk
        gen=old._generation(before)
        if len(raw)>limit or old._generation(os.fstat(fd))!=gen or old._generation(path.lstat())!=gen or old._ancestry(path.parent)!=parents:raise ValueError('regular_input_changed')
        return {'path':str(path.absolute()),'generation':gen,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'parents':parents}
    finally:os.close(fd)


def _private_pin(path: Path, limit: int = 1048576) -> dict:
    parents=old._ancestry(path.parent)
    raw,gen,digest=old.private_snapshot(path,limit)
    if old._ancestry(path.parent)!=parents:raise ValueError('private_parent_changed')
    return {'path':str(path),'generation':gen,'sha256':digest,'bytes':len(raw),'parents':parents}


def _guard(pins: list[dict]) -> None:
    for pin in pins:
        if regular_pin(pin['path'],max(pin['bytes'],1))!=pin:raise ValueError('input_generation_changed')


def _directory(root: Path, correlation: str) -> Path:
    if not _UUID.fullmatch(correlation) or correlation in (ADMISSION,OS_OBSERVATION,'0dd55704-1e80-4d62-8d9d-2f0a123e0c3b'):raise ValueError('fresh_correlation_required')
    base=root/'.rag_index'/'android-proxy-os-observation'
    if not base.exists():base.mkdir(mode=0o700)
    fd=old._directory(base);os.close(fd);old._ancestry(base)
    return base/correlation


def prepare(root: Path | str, correlation: str, *, expected_java_sha256: str,
            javac: Path | str, java: Path | str, d8_jar: Path | str) -> dict:
    """Admit local proof and return fixed build argv. Does not run a compiler/native tool."""
    from agent_tools import ssh_transport,android_observation,android_installer_tool_bundle
    root=Path(root).resolve();directory=_directory(root,correlation)
    if expected_java_sha256!=JAVA_SHA:raise ValueError('reviewed_java_sha_required')
    source=root/JAVA_REL;source_pin=regular_pin(source,65536)
    if source_pin['sha256']!=JAVA_SHA or regular_pin(Path(old.__file__))['sha256']!=OLD_HELPER_SHA or hashlib.sha256(old.remote_metadata_bound_proxy_service_source().encode()).hexdigest()!=OLD_OS_SOURCE_SHA:raise ValueError('reviewed_source_changed')
    admission=root/'.rag_index'/'android-installer-failed-check-retirement'/ADMISSION
    raw,_,_=old.private_snapshot(admission/'intent.json',65536);local=json.loads(raw)
    intent=local['dispatch'];binding=local['binding'];old.validate_original(intent,binding['originalIntent'],intent['correlationId'])
    config=ssh_transport.load_config(root)
    if intent['host'] not in config.hosts or ssh_transport.connection_host(config,intent['host']).password is not None or str(config.hosts[intent['host']].fixture_transfer_root)!=intent['fixtureRoot']:raise ValueError('configured_route_changed')
    profile=android_observation._profile(config.hosts[intent['host']].android_devices[intent['device']])
    if any(profile[a]!=intent['remote'][b] for a,b in (('serial','serial'),('expectedAvd','avd'),('api','api'),('adb','adb'))):raise ValueError('device_profile_changed')
    bundle=android_installer_tool_bundle.load(root,intent['toolBundleId'])
    if intent['remote']['toolBundle']!={k:bundle[k] for k in ('toolBundleId','reviewedTreeSha256','manifest')}:raise ValueError('original_bundle_changed')
    files=[admission/'intent.json',admission/'metadata-identity-1247d3dc-557e-4c99-a1b3-1ac737128cf3-capsule.json',
        admission/('diagnostic-'+OS_OBSERVATION+'.json'),admission/('diagnostic-'+OS_OBSERVATION+'-result.json'),
        root/'.runtime'/'parity-evidence'/'android-current'/'api35-retirement-d0fb-native-receipt.json',
        root/'.runtime'/'parity-evidence'/'android-current'/('api35-os-proxy-'+OS_OBSERVATION+'-connectivity.txt')]
    files += [root/'.rag_index'/'android-installer-dispatch'/intent['correlationId']/name for name in ('dispatch.json','intent.json')]
    pins=[_private_pin(p) for p in files]
    if pins[1]['sha256']!=old._OS_METADATA_CAPSULE_SHA or pins[4]['sha256']!=old._OS_METADATA_IDENTITY['priorDiagnosticReceiptSha256'] or pins[5]['sha256']!=OS_CAPTURE_PIN['sha256']:raise ValueError('historical_proof_changed')
    prior=json.loads(old.private_snapshot(files[3],65536)[0]);request=json.loads(old.private_snapshot(files[2],65536)[0])
    if prior.get('receiptSha256')!=OS_RECEIPT_PIN['sha256'] or prior.get('errorType') is not None or prior.get('currentFailurePhase')!='metadata-os-closing-guard' or request.get('diagnosticSourceSha256')!=OLD_OS_SOURCE_SHA:raise ValueError('prior_os_observation_changed')
    compilers=[regular_pin(Path(p)) for p in (javac,java,d8_jar)]
    with old._local_lock(root,intent['host'],intent['device']) as (lease,guard):
        lease_pin=_private_pin(lease,1024)
        if {k:lease_pin[k] for k in ('generation','sha256')}!=binding['localLeasePin']:raise ValueError('original_local_lease_changed')
        _guard(pins+[source_pin]+compilers+[lease_pin]);guard()
        directory.mkdir(mode=0o700)
        copied=directory/'ProxyProbe.java';fd=os.open(copied,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(source.read_bytes());stream.flush();os.fsync(stream.fileno())
        (directory/'classes').mkdir(mode=0o700);(directory/'dex').mkdir(mode=0o700)
        commands=[[compilers[0]['path'],'-encoding','UTF-8','--release','8','-d',str(directory/'classes'),str(copied)],
            [compilers[1]['path'],'-cp',compilers[2]['path'],'com.android.tools.r8.D8','--min-api','35','--output',str(directory/'dex'),str(directory/'classes'/'ProxyProbe.class')]]
        value={'schema':1,'kind':'android-proxy-os-build-intent','correlationId':correlation,'originalOutcome':'unknown','historicalRowPresence':'unavailable',
            'dispatch':intent,'binding':binding,'localPins':pins+[source_pin]+compilers+[lease_pin,_private_pin(copied),regular_pin(root/ssh_transport.CONFIG_FILENAME,1048576)],'commands':commands,
            'artifactPath':str(directory/'dex'/'classes.dex'),'primarySource':PRIMARY,'javaSha256':JAVA_SHA,
            'remoteSourceSha256':hashlib.sha256(remote_source().encode()).hexdigest(),'productMutationAllowed':False,'stageAuthority':STAGE_AUTHORITY}
        _guard(value['localPins']);guard();old._save(directory/'intent.json',value)
    return {'state':'prepared','correlationId':correlation,'intentPath':str(directory/'intent.json'),'commands':commands,'artifactPath':value['artifactPath'],'intentPin':{k:_private_pin(directory/'intent.json',65536)[k] for k in ('generation','sha256')},'compilerReceiptRequired':True,'nativeExecuted':False}


def bind_artifact(root: Path | str, correlation: str, compiler_receipt: Path | str) -> dict:
    """Bind root's measured compilation. Caller booleans cannot substitute for bytes/pins."""
    root=Path(root).resolve();directory=_directory(root,correlation)
    raw,gen,digest=old.private_snapshot(directory/'intent.json',65536);intent=json.loads(raw)
    if intent.get('kind')!='android-proxy-os-build-intent' or intent.get('correlationId')!=correlation or intent.get('javaSha256')!=JAVA_SHA or intent.get('remoteSourceSha256')!=hashlib.sha256(remote_source().encode()).hexdigest():raise ValueError('build_intent_binding_changed')
    _guard(intent['localPins'])
    receipt_path=Path(compiler_receipt).absolute();receipt_raw,receipt_gen,receipt_sha=old.private_snapshot(receipt_path,65536);receipt=json.loads(receipt_raw)
    if receipt.get('intentPin')!={'generation':gen,'sha256':digest} or receipt.get('javaSha256')!=JAVA_SHA or receipt.get('correlationId')!=correlation:raise ValueError('compiler_receipt_binding_changed')
    commands=receipt.get('commands')
    if not isinstance(commands,list) or len(commands)!=2 or any(c.get('argv')!=argv or type(c.get('exit')) is not int or c['exit']!=0 or not isinstance(c.get('stdoutSha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['stdoutSha256']) or not isinstance(c.get('stderrSha256'),str) or not re.fullmatch('[0-9a-f]{64}',c['stderrSha256']) for c,argv in zip(commands,intent['commands'])):raise ValueError('compiler_commands_unproved')
    artifact=Path(intent['artifactPath']);data,artifact_gen,artifact_sha=old.private_snapshot(artifact,16384)
    if len(data)<112 or data[:8] not in tuple(('dex\n%03d\x00'%n).encode() for n in (35,37,38,39,40,41)) or receipt.get('artifactSha256')!=artifact_sha:raise ValueError('dex_artifact_unproved')
    value={'schema':1,'correlationId':correlation,'intentPin':{'generation':gen,'sha256':digest},'compilerReceiptPin':{'path':str(receipt_path),'generation':receipt_gen,'sha256':receipt_sha},
        'artifactPin':{'path':str(artifact),'generation':artifact_gen,'sha256':artifact_sha,'bytes':len(data)},'javaSha256':JAVA_SHA,'primarySource':PRIMARY}
    _guard(intent['localPins']);old._save(directory/'artifact.json',value)
    return {'state':'bound','correlationId':correlation,'artifactSha256':artifact_sha,'artifactBytes':len(data),'nativeExecuted':False}


def parse_probe(raw: bytes | str, correlation: str) -> dict:
    if isinstance(raw,bytes):raw=raw.decode('utf-8','strict')
    if len(raw.encode())>16384:raise ValueError('probe_bounds')
    value=json.loads(raw)
    if value.get('state')!='observed' or value.get('schema')!=1 or type(value.get('uid')) is not int or value['uid']!=2000 or value.get('correlationId')!=correlation:raise ValueError('getter_observation_unknown')
    reads=value.get('reads')
    if not isinstance(reads,list) or len(reads)!=2 or reads[0]!=reads[1]:raise ValueError('getter_observation_unstable')
    for read in reads:
        if not isinstance(read,dict) or set(read)!={'global','defaultForShell'}:raise ValueError('getter_observation_shape')
        for proxy in read.values():
            if proxy is None:continue
            if not isinstance(proxy,dict) or set(proxy)!={'host','port','exclusionList','pacUrl'} or type(proxy['port']) is not int or not -1<=proxy['port']<=65535 or proxy['host'] is not None and not isinstance(proxy['host'],str) or not isinstance(proxy['pacUrl'],str) or not isinstance(proxy['exclusionList'],list) or len(proxy['exclusionList'])>32 or any(not isinstance(x,str) for x in proxy['exclusionList']):raise ValueError('getter_proxy_shape')
    return value


def remote_source() -> str:
    """Derive a new observer, never rewriting the immutable historical source."""
    import inspect
    source=old.remote_metadata_bound_proxy_service_source()
    constants={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body[:3]}
    checks=constants['CHECKS'];start=checks.index("phase='metadata-os-service-capture'");end=checks.index("phase='metadata-os-closing-guard'",start)
    replacement='\n'+inspect.getsource(parse_probe)+r"""
phase='proxy-os-artifact-admission'
artifact=diagnostic['probeArtifact']
if artifact.get('javaSha256')!=PROBE_JAVA_SHA or artifact.get('primarySource')!=PROBE_PRIMARY or artifact.get('correlationId')!=diagnostic_id:raise ValueError('probe_artifact_binding_changed')
dex=base64.b64decode(artifact['dexBase64'],validate=True)
if not 112<=len(dex)<=16384 or dex[:8] not in tuple(('dex\n%03d\x00'%n).encode() for n in (35,37,38,39,40,41)) or artifact.get('artifactSha256')!=hashlib.sha256(dex).hexdigest():raise ValueError('probe_artifact_bytes_changed')
os_prior=root/'android-failed-check-retirement-diagnostic-80b0c504-4780-4c95-a421-29b76808eec7'
os_raw,os_pin=snapshot_file(os_prior/'receipt.json',1048576)
if {**os_pin,'bytes':len(os_raw)}!=PROBE_OS_RECEIPT_PIN:raise ValueError('probe_os_prior_changed')
os_value=json.loads(os_raw)
if os_value.get('diagnosticSourceSha256')!=PROBE_OLD_OS_SHA or os_value.get('exception') is not None or os_value.get('currentFailurePhase')!='metadata-os-closing-guard' or os_value.get('originalOutcome')!='unknown' or os_value.get('installerMetadataCensus')!=identity['census']:raise ValueError('probe_os_prior_binding_changed')
cap_raw,cap_pin=snapshot_file(os_prior/'connectivity.txt',1048576)
if {**cap_pin,'bytes':len(cap_raw)}!=PROBE_OS_CAPTURE_PIN:raise ValueError('probe_os_prior_capture_changed')
def shell2000(command):
 result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T',command],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
 if result.returncode!=0 or len(result.stdout)>16384 or len(result.stderr)>65536:raise ValueError('probe_shell_command_unknown')
 return result.stdout.decode('utf-8','strict').rstrip('\r\n')
if shell2000('/system/bin/id -u')!='2000':raise ValueError('probe_shell_uid_required')
# All original guards precede a durable, create-only tooling-stage fence.
if parse_installer_metadata_census(authenticated_privileged_read(shell,METADATA_SCRIPT))!=identity['census']:raise ValueError('probe_metadata_changed_before_stage')
guard_files(pins,paths,parents);verify_manifest();fixture_stopped(output)
stage_name='android-proxy-os-stage-'+diagnostic_id
root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
os.mkdir(stage_name,0o700,dir_fd=root_fd)
stage_fd=os.open(stage_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root_fd)
_create(stage_fd,'binding.json',{'diagnosticCorrelationId':diagnostic_id,'originalOutcome':'unknown','artifactSha256':artifact['artifactSha256'],'javaSha256':PROBE_JAVA_SHA,'productMutationAllowed':False})
_create(stage_fd,'stage-fence.json',{'correlationId':diagnostic_id,'effect':'fixed-readonly-dex-stage','devicePath':'/data/local/tmp/vpn-control-os-proxy-'+diagnostic_id,'leaseReleaseAllowed':False})
dex_fd=os.open('classes.dex',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=stage_fd)
with os.fdopen(dex_fd,'wb') as stream:stream.write(dex);stream.flush();os.fsync(stream.fileno())
os.fsync(stage_fd);os.close(stage_fd);os.fsync(root_fd);os.close(root_fd)
local_dex=root/stage_name/'classes.dex';local_dex_raw,local_dex_pin=snapshot_file(local_dex,16384)
if local_dex_raw!=dex:raise ValueError('probe_host_stage_changed')
device_dir='/data/local/tmp/vpn-control-os-proxy-'+diagnostic_id;device_dex=device_dir+'/classes.dex'
phase='proxy-os-fixed-stage'
quote=__import__('shlex').quote
fmt='%d|%i|%s|%y|%z|%a|%u|%g|%h|%F'
directory_fmt='%d|%i|%a|%u|%F'
# Authority starts at cd acquisition of the CURRENT private shell-owned parent.
# We do not attest continuity of the pre-cd mkdir inode. After acquisition, cwd
# retains that parent through named exchange; concurrent hostile shell writers
# before acquisition are outside the explicitly authorized single-operator model.
# noclobber opens one exclusive file descriptor. No chmod/named adb push follows.
staging=('set -eu; test "$(/system/bin/id -u)" = 2000; umask 077; '
 'test ! -e '+device_dir+'; test ! -L '+device_dir+'; /system/bin/mkdir -m 700 '+device_dir+'; '
 'CDPATH=; cd -P '+device_dir+'; test "$(/system/bin/stat -c '+quote('%a|%u|%F')+' .)" = '+quote('700|2000|directory')+'; before=$(/system/bin/stat -c '+quote(directory_fmt)+' .); '
 'test "$before" = "$(/system/bin/stat -c '+quote(directory_fmt)+' '+device_dir+')"; '
 'test ! -e ./classes.dex; test ! -L ./classes.dex; set -C; exec 4>./classes.dex; set +C; '
 'test "$(/system/bin/stat -Lc '+quote('%a|%u|%h|%s|%F')+' /proc/self/fd/4)" = '+quote('600|2000|1|0|regular file')+'; '
 'held=$(/system/bin/stat -Lc '+quote(fmt)+' /proc/self/fd/4); '
 'test "$held" = "$(/system/bin/stat -c '+quote(fmt)+' ./classes.dex)"; '
 'test "$before" = "$(/system/bin/stat -c '+quote(directory_fmt)+' '+device_dir+')"; '
 'printf %s '+quote(base64.b64encode(dex).decode())+' | /system/bin/base64 -d >&4; '
 'held=$(/system/bin/stat -Lc '+quote(fmt)+' /proc/self/fd/4); '
 'test "$held" = "$(/system/bin/stat -c '+quote(fmt)+' ./classes.dex)"; '
 'test "$before" = "$(/system/bin/stat -c '+quote(directory_fmt)+' '+device_dir+')"; '
 'printf "%s\\n" "$before"; /system/bin/stat -c '+quote(fmt)+' '+device_dir+' ./classes.dex; '
 'printf "%s\\n" "$held"; /system/bin/sha256sum ./classes.dex')
stage_report=shell2000(staging)
stage_lines=stage_report.splitlines()
if len(stage_lines)!=5 or stage_lines[2]!=stage_lines[3]:raise ValueError('probe_exclusive_stage_changed')
dir_fields=stage_lines[1].split('|')
if len(dir_fields)!=10 or stage_lines[0]!='|'.join([dir_fields[i] for i in (0,1,5,6,9)]):raise ValueError('probe_stage_parent_changed')
if stage_lines[4].split()!=[artifact['artifactSha256'],'./classes.dex']:raise ValueError('probe_staged_bytes_changed')
expected_stage_generation=stage_lines[1:3]
if snapshot_file(local_dex,16384)[1]!=local_dex_pin:raise ValueError('probe_host_stage_generation_changed')
def device_generation():
 value=shell2000('set -eu; test "$(/system/bin/id -u)" = 2000; test ! -L '+device_dir+'; test ! -L '+device_dex+'; /system/bin/stat -c "%d|%i|%s|%y|%z|%a|%u|%g|%h|%F" '+device_dir+' '+device_dex+'; /system/bin/sha256sum '+device_dex)
 lines=value.splitlines()
 if len(lines)!=3:raise ValueError('probe_device_generation_shape')
 directory_fields=lines[0].split('|');file_fields=lines[1].split('|')
 if len(directory_fields)!=10 or len(file_fields)!=10 or directory_fields[5:7]!=['700','2000'] or directory_fields[-1]!='directory' or file_fields[2]!=str(len(dex)) or file_fields[5:7]!=['600','2000'] or file_fields[8:]!=['1','regular file'] or lines[2].split()!=[artifact['artifactSha256'],device_dex]:raise ValueError('probe_device_stage_unsafe')
 return value
stage_generation=device_generation()
if stage_generation.splitlines()[:2]!=expected_stage_generation:raise ValueError('probe_stage_generation_changed')
phase='proxy-os-getters'
file_stat=stage_generation.splitlines()[1]
quote=__import__('shlex').quote
command=('set -eu; test "$(/system/bin/id -u)" = 2000; exec 3<'+device_dex+'; '
 'test "$(/system/bin/stat -Lc '+quote('%d|%i|%s|%y|%z|%a|%u|%g|%h|%F')+' /proc/self/fd/3)" = '+quote(file_stat)+'; '
 'got=$(/system/bin/sha256sum /proc/self/fd/3); test "${got%% *}" = '+artifact['artifactSha256']+'; '
 'CLASSPATH=/proc/self/fd/3 /system/bin/app_process /system/bin ProxyProbe '+diagnostic_id)
probe_result=subprocess.run([expected['adb'],'-s',expected['serial'],'shell','-T',command],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
# Retain exact private reply before checking exit/schema. A failed getter is never null.
if len(probe_result.stdout)>16384 or len(probe_result.stderr)>65536:raise ValueError('probe_reply_bounds')
service_bytes=probe_result.stdout
service_capture={'name':'connectivity.txt','bytes':len(service_bytes),'sha256':hashlib.sha256(service_bytes).hexdigest(),'exit':probe_result.returncode,'stderr':{'bytes':len(probe_result.stderr),'sha256':hashlib.sha256(probe_result.stderr).hexdigest()},'interpretation':'named-binder-getters','historicalRowPresence':'unavailable','proxyRestorationPerformed':False,'deviceStageGeneration':stage_generation,'javaSha256':PROBE_JAVA_SHA,'artifactSha256':artifact['artifactSha256'],'stageAuthority':PROBE_STAGE_AUTHORITY}
if probe_result.returncode!=0:raise ValueError('probe_getter_execution_unknown')
observed=parse_probe(service_bytes,diagnostic_id)
if device_generation()!=stage_generation:raise ValueError('probe_device_stage_generation_changed')
if snapshot_file(local_dex,16384)[1]!=local_dex_pin or snapshot_file(os_prior/'receipt.json',1048576)[1]!=os_pin or snapshot_file(os_prior/'connectivity.txt',1048576)[1]!=cap_pin:raise ValueError('probe_input_changed_after_getters')
"""
    checks=checks[:start]+replacement+checks[end:]
    checks+=r"""
phase='proxy-os-final-guard'
if device_generation()!=stage_generation:raise ValueError('probe_device_stage_generation_changed')
"""
    bootstrap=source[source.index('import base64,fcntl,hashlib,json,os,pathlib,stat,subprocess,sys'):]
    extras={'PROBE_JAVA_SHA':JAVA_SHA,'PROBE_PRIMARY':PRIMARY,'PROBE_STAGE_AUTHORITY':STAGE_AUTHORITY,'PROBE_OS_RECEIPT_PIN':OS_RECEIPT_PIN,'PROBE_OS_CAPTURE_PIN':OS_CAPTURE_PIN,'PROBE_OLD_OS_SHA':OLD_OS_SOURCE_SHA,
        'METADATA_SCRIPT':old._INSTALLER_METADATA_READ,'OS_METADATA_IDENTITY':old._OS_METADATA_IDENTITY,'OS_METADATA_CAPSULE_SHA':old._OS_METADATA_CAPSULE_SHA}
    return ('ORIGINAL_SHA='+repr(constants['ORIGINAL_SHA'])+'\nPREFIX='+repr(constants['PREFIX'])+'\nCHECKS='+repr(checks)+'\n'
        +'\n'.join(k+'='+repr(v) for k,v in extras.items())+'\n'+bootstrap)


def observe(root: Path | str, correlation: str) -> dict:
    """Root-only call after review/build: stage one immutable probe and read getters."""
    from agent_tools import ssh_transport
    root=Path(root).resolve();directory=_directory(root,correlation)
    intent_raw,intent_gen,intent_sha=old.private_snapshot(directory/'intent.json',65536);intent=json.loads(intent_raw)
    art_raw,art_gen,art_sha=old.private_snapshot(directory/'artifact.json',65536);artifact=json.loads(art_raw)
    if intent.get('correlationId')!=correlation or artifact.get('correlationId')!=correlation or artifact.get('intentPin')!={'generation':intent_gen,'sha256':intent_sha} or intent.get('javaSha256')!=JAVA_SHA or artifact.get('javaSha256')!=JAVA_SHA or intent.get('remoteSourceSha256')!=hashlib.sha256(remote_source().encode()).hexdigest():raise ValueError('probe_local_binding_changed')
    inputs=intent['localPins']+[_private_pin(directory/'intent.json',65536),_private_pin(directory/'artifact.json',65536)]
    compiler_pin=artifact['compilerReceiptPin'];artifact_pin=artifact['artifactPin']
    compiler_raw,gen,sha=old.private_snapshot(Path(compiler_pin['path']),65536)
    if (gen,sha)!=(compiler_pin['generation'],compiler_pin['sha256']):raise ValueError('compiler_receipt_generation_changed')
    dex,dex_gen,dex_sha=old.private_snapshot(Path(artifact_pin['path']),16384)
    if (dex_gen,dex_sha)!=(artifact_pin['generation'],artifact_pin['sha256']):raise ValueError('dex_generation_changed')
    inputs += [_private_pin(Path(compiler_pin['path']),65536),_private_pin(Path(artifact_pin['path']),16384)]
    dispatch=intent['dispatch'];binding=intent['binding'];config=ssh_transport.load_config(root)
    if str(config.hosts[dispatch['host']].fixture_transfer_root)!=dispatch['fixtureRoot'] or ssh_transport.connection_host(config,dispatch['host']).password is not None:raise ValueError('probe_route_changed')
    diagnostic={'diagnosticCorrelationId':correlation,'originalAdapterSha256':binding['adapterSha256'],'diagnosticSourceSha256':intent['remoteSourceSha256'],
        'metadataIdentity':old._OS_METADATA_IDENTITY,'metadataIdentityCapsulePin':{'sha256':old._OS_METADATA_CAPSULE_SHA},
        'priorDiagnosticReceiptSha256':old._OS_METADATA_IDENTITY['priorDiagnosticReceiptSha256'],
        'probeArtifact':{'correlationId':correlation,'javaSha256':JAVA_SHA,'artifactSha256':dex_sha,'dexBase64':base64.b64encode(dex).decode(),'primarySource':PRIMARY,'compilerReceiptSha256':sha}}
    packet={**dispatch['remote'],'retirementBinding':binding,'diagnosticBinding':diagnostic}
    with old._local_lock(root,dispatch['host'],dispatch['device']) as (lease,guard):
        _guard(inputs);guard()
        if {k:_private_pin(lease,1024)[k] for k in ('generation','sha256')}!=binding['localLeasePin']:raise ValueError('probe_original_lease_changed')
        old._save(directory/'observe-request.json',{'correlationId':correlation,'intentPin':{'generation':intent_gen,'sha256':intent_sha},'artifactPin':{'generation':art_gen,'sha256':art_sha},'remoteSourceSha256':intent['remoteSourceSha256'],'originalOutcome':'unknown'})
        _guard(inputs);guard()
        argv=ssh_transport.build_ssh_argv(config,dispatch['host'],60,command=('python3','-I','-B','-c',source_carrier(remote_source()),'diagnose',dispatch['fixtureRoot'],dispatch['host'],dispatch['device'],dispatch['correlationId'],json.dumps(packet,sort_keys=True,separators=(',',':'))))
        if any(len(x.encode())>=131072 for x in argv):raise ValueError('probe_transport_argument_bounds')
        code,out=old.diagnostic_transport(argv,directory/'observe-transport.json',{'correlationId':correlation,'remoteSourceSha256':intent['remoteSourceSha256']})
        _guard(inputs);guard()
        try:value=json.loads(out) if code==0 and len(out)<=16384 else None
        except (ValueError,UnicodeError):value=None
        old._save(directory/'observe-result.json',value if isinstance(value,dict) else {'state':'unknown','reason':'probe_transport_unknown'})
        return {'ok':isinstance(value,dict) and value.get('state')=='diagnosed' and value.get('errorType') is None,**(value if isinstance(value,dict) else {'state':'unknown'}),'originalOutcome':'unknown','proxyRestorationPerformed':False}


def remote_collector_source() -> str:
    source=old.remote_metadata_bound_proxy_collector_source()
    return source.replace("'metadata-os-closing-guard')", "'metadata-os-closing-guard','proxy-os-artifact-admission','proxy-os-fixed-stage','proxy-os-getters','proxy-os-final-guard')",1)


def collect(root: Path | str, correlation: str, collection: str, *, kind: str = 'status',
            offset: int = 0, expected_pin: dict | None = None) -> dict:
    """Collect existing bounded receipts/captures; never re-stage or run the getter."""
    from agent_tools import ssh_transport
    root=Path(root).resolve();directory=_directory(root,correlation)
    if not _UUID.fullmatch(collection) or collection==correlation or kind not in ('status','receipt','connectivity') or type(offset) is not int or offset<0 or kind!='status' and not isinstance(expected_pin,dict):raise ValueError('probe_collection_request_invalid')
    raw,gen,digest=old.private_snapshot(directory/'intent.json',65536);intent=json.loads(raw)
    request_raw,request_gen,request_sha=old.private_snapshot(directory/'observe-request.json',65536);request=json.loads(request_raw)
    source_hash=hashlib.sha256(remote_source().encode()).hexdigest()
    if request.get('intentPin')!={'generation':gen,'sha256':digest} or request.get('remoteSourceSha256')!=source_hash:raise ValueError('probe_collection_binding_changed')
    inputs=[_private_pin(directory/'intent.json',65536),_private_pin(directory/'observe-request.json',65536)]
    _guard(inputs)
    dispatch=intent['dispatch'];config=ssh_transport.load_config(root)
    old._save(directory/('collection-'+collection+'.json'),{'correlationId':correlation,'kind':kind,'offset':offset,'expectedPin':expected_pin,'requestPin':{'generation':request_gen,'sha256':request_sha}})
    argv=ssh_transport.build_ssh_argv(config,dispatch['host'],60,command=('python3','-I','-B','-c','exec('+repr(remote_collector_source())+')',dispatch['fixtureRoot'],correlation,kind,str(offset),json.dumps(expected_pin),source_hash))
    code,out=old.diagnostic_transport(argv,directory/('collection-'+collection+'-transport.json'),{'correlationId':correlation,'collectionCorrelationId':collection})
    _guard(inputs)
    try:value=json.loads(out) if code==0 and len(out)<=4096 else None
    except (ValueError,UnicodeError):value=None
    result_path=directory/('collection-'+collection+'-result.json')
    old._save(result_path,value if isinstance(value,dict) else {'state':'unknown','reason':'probe_collection_transport_unknown'})
    if not isinstance(value,dict) or value.get('diagnosticCorrelationId')!=correlation:return {'ok':False,'state':'unknown','resultPath':str(result_path)}
    return {'ok':value.get('state')!='unknown',**{k:v for k,v in value.items() if k!='chunk'},'resultPath':str(result_path)}


def source_carrier(source: str) -> str:
    """Scoped hash-checked carrier; avoids nested SSH quoting's argument inflation."""
    import zlib
    raw=source.encode()
    if len(raw)>262144:raise ValueError('probe_source_bounds')
    compressed=base64.b64encode(zlib.compress(raw,9)).decode()
    return ("import base64,hashlib,zlib;_probe_source=zlib.decompress(base64.b64decode("+repr(compressed)+",validate=True));"
        +"assert len(_probe_source)=="+str(len(raw))+" and hashlib.sha256(_probe_source).hexdigest()=="+repr(hashlib.sha256(raw).hexdigest())+";exec(_probe_source)")
