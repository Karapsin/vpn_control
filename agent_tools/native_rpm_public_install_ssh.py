"""One-shot, fixed SSH transport for the Fedora RPM public recovery harness.

No password is read here. The guest harness owns temporary authentication and
restoration. An owner-only authorization record admits one exact correlation,
artifact set and source pair for the named fixture account and P baseline.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile
from typing import Any, Mapping

try:
    from . import native_artifact_registry, native_rpm_public_install_adapter as adapter, native_scenario_bundle, native_scenario_ssh, ssh_transport, ssh_transfer
except ImportError:
    import native_artifact_registry, native_rpm_public_install_adapter as adapter, native_scenario_bundle, native_scenario_ssh, ssh_transport, ssh_transfer

_BUNDLE_ID = 'linux-public-update-driver'
_AUTH_PURPOSE = 'linux-rpm-public-install-recovery'
_ACCOUNT = 'vpnfixture'
_AUTH_HANDLE = re.compile(r'^rpm-auth-[0-9a-f]{32}$')
_MAX_ARCHIVE = 2 * 1024 * 1024 * 1024
_MAX_TARGET = 1024 * 1024 * 1024
_MAX_MEMBER = 1024 * 1024 * 1024


class RpmPublicInstallSshError(ValueError):
    pass


def _observe_proc_tree(proc: Path, uid: int) -> dict[str, Any]:
    """Report bounded same-UID proc visibility without claiming workspace absence."""
    uninspectable: list[dict[str, Any]] = []
    same_uid = 0
    truncated = False

    def uncertain(pid: int, phase: str, *, start_ticks: int | None = None, state: str | None = None,
                  ppid: int | None = None, process_group: int | None = None,
                  session: int | None = None, comm: str | None = None,
                  error_errno: int | None = None) -> None:
        nonlocal truncated
        if len(uninspectable) < 32:
            uninspectable.append({'pid': pid, 'startTicks': start_ticks, 'state': state,
                                  'ppid': ppid, 'processGroup': process_group, 'session': session,
                                  'comm': comm, 'errorErrno': error_errno,
                                  'phase': phase, 'reason': 'unreadable'})
        else:
            truncated = True

    try:
        entries = sorted((entry for entry in proc.iterdir() if entry.name.isdecimal()),
                         key=lambda entry: int(entry.name))
    except OSError as error:
        return {'procState': 'unknown', 'sameUidCount': 0, 'uninspectable': [
            {'pid': 0, 'startTicks': None, 'state': None, 'ppid': None,
             'processGroup': None, 'session': None, 'comm': None, 'errorErrno': error.errno,
             'phase': 'proc', 'reason': 'unreadable'}],
            'truncated': False}
    if len(entries) > 4096:
        truncated = True
        entries = entries[:4096]
    for entry in entries:
        pid = int(entry.name)
        try:
            owner = os.stat(entry, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            uncertain(pid, 'identity', error_errno=error.errno)
            continue
        if owner.st_uid != uid:
            continue
        same_uid += 1
        try:
            raw_stat = (entry / 'stat').read_text(encoding='ascii')
            comm = raw_stat.split('(', 1)[1].rsplit(')', 1)[0]
            if not 0 < len(comm) <= 64 or not all(char.isascii() and (char.isalnum() or char in '_.:-()') for char in comm):
                comm = None
            fields = raw_stat.rsplit(')', 1)[1].split()
            state, ppid, process_group, session, start_ticks = (
                fields[0], int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))
            if len(state) != 1 or ppid < 0 or process_group <= 0 or session <= 0 or start_ticks <= 0:
                raise ValueError()
        except (OSError, ValueError, IndexError):
            uncertain(pid, 'generation')
            continue
        if state in ('Z', 'X'):
            continue
        try:
            os.readlink(entry / 'cwd')
        except OSError as error:
            uncertain(pid, 'cwd', start_ticks=start_ticks, state=state,
                      ppid=ppid, process_group=process_group, session=session,
                      comm=comm, error_errno=error.errno)
            continue
        try:
            descriptors = list((entry / 'fd').iterdir())
        except OSError as error:
            uncertain(pid, 'fd', start_ticks=start_ticks, state=state,
                      ppid=ppid, process_group=process_group, session=session,
                      comm=comm, error_errno=error.errno)
            continue
        if len(descriptors) > 8192:
            truncated = True
            descriptors = descriptors[:8192]
        for descriptor in descriptors:
            if not descriptor.name.isdecimal():
                continue
            try:
                os.readlink(descriptor)
            except FileNotFoundError:
                # Individual descriptors may close after the directory listing.
                continue
            except OSError as error:
                uncertain(pid, 'descriptor', start_ticks=start_ticks, state=state,
                          ppid=ppid, process_group=process_group, session=session,
                          comm=comm, error_errno=error.errno)
                break
    return {'procState': 'unknown' if uninspectable or truncated else 'clear',
            'sameUidCount': same_uid, 'uninspectable': uninspectable, 'truncated': truncated}


_PROC_OBSERVE = ('import json,os\nfrom pathlib import Path\nfrom typing import Any\n'
                 + inspect.getsource(_observe_proc_tree)
                 + "\nprint(json.dumps(_observe_proc_tree(Path('/proc'),os.geteuid()),separators=(',',':')))\n")


def observe_proc(root: Path | str, request: Mapping[str, Any]) -> dict[str, Any]:
    """Read-only Fedora fixture process diagnostic; no caller command or path."""
    if (not isinstance(request, Mapping) or set(request) != {'host', 'environment'}
            or request.get('host') != 'fedora2328' or request.get('environment') != 'fedora2328'):
        raise RpmPublicInstallSshError('RPM proc diagnostic requires the exact owned Fedora guest.')
    config = ssh_transport.load_config(root)
    host = config.hosts.get('fedora2328')
    if host is None or host.user != _ACCOUNT:
        raise RpmPublicInstallSshError('RPM proc diagnostic guest identity is unavailable.')
    driver = RpmPublicInstallSshDriver(root, timeout_seconds=20)
    result = driver._remote(config, 'fedora2328', _PROC_OBSERVE, ())
    entries = result.get('uninspectable') if isinstance(result, Mapping) else None
    valid_entries = isinstance(entries, list) and len(entries) <= 32 and all(
        isinstance(entry, Mapping) and set(entry) == {'pid', 'startTicks', 'state', 'ppid', 'processGroup', 'session', 'comm', 'errorErrno', 'phase', 'reason'}
        and type(entry['pid']) is int and 0 <= entry['pid'] <= 2**31 - 1
        and (entry['startTicks'] is None or type(entry['startTicks']) is int and entry['startTicks'] > 0)
        and (entry['state'] is None or isinstance(entry['state'], str) and len(entry['state']) == 1)
        and all(entry[key] is None or type(entry[key]) is int and entry[key] >= 0
                for key in ('ppid', 'processGroup', 'session'))
        and (entry['comm'] is None or isinstance(entry['comm'], str) and 0 < len(entry['comm']) <= 64
             and all(char.isascii() and (char.isalnum() or char in '_.:-()') for char in entry['comm']))
        and (entry['errorErrno'] is None or type(entry['errorErrno']) is int and 0 < entry['errorErrno'] <= 255)
        and entry['phase'] in {'proc', 'identity', 'generation', 'cwd', 'fd', 'descriptor'}
        and entry['reason'] == 'unreadable' for entry in entries) if entries is not None else False
    if (not isinstance(result, Mapping) or result.get('procState') not in {'clear', 'unknown'}
            or type(result.get('sameUidCount')) is not int or not 0 <= result['sameUidCount'] <= 4096
            or not valid_entries or type(result.get('truncated')) is not bool
            or result['procState'] == 'clear' and (entries or result['truncated'])
            or result['procState'] == 'unknown' and not (entries or result['truncated'])):
        return {'ok': False, 'host': 'fedora2328', 'environment': 'fedora2328',
                'procState': 'unknown', 'sameUidCount': None, 'uninspectable': [],
                'truncated': True, 'evidenceScope': 'same-uid-proc-visibility-only'}
    return {'ok': True, 'host': 'fedora2328', 'environment': 'fedora2328',
            'procState': result['procState'], 'sameUidCount': result['sameUidCount'],
            'uninspectable': result['uninspectable'], 'truncated': result['truncated'],
            'evidenceScope': 'same-uid-proc-visibility-only'}


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode()


def _private_file(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or not 0 < before.st_size <= limit:
            raise RpmPublicInstallSshError('Frozen input is unsafe.')
        raw = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(raw))):
            raw.extend(chunk)
            if len(raw) > limit:
                raise RpmPublicInstallSshError('Frozen input exceeds its bound.')
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(raw) != before.st_size:
            raise RpmPublicInstallSshError('Frozen input changed during admission.')
        return bytes(raw)
    finally:
        os.close(fd)


def _registered(root: Path, artifact_id: str) -> Path:
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    location = verified.get('location')
    if verified.get('verification') != 'verified' or not isinstance(location, Mapping) or not isinstance(location.get('localPath'), str):
        raise RpmPublicInstallSshError('Registered RPM artifact bytes are unavailable or changed.')
    return Path(location['localPath'])


def _sha(path: Path, maximum: int) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or not 0 < before.st_size <= maximum:
            raise RpmPublicInstallSshError('RPM artifact is unsafe or exceeds its bound.')
        digest = hashlib.sha256()
        while chunk := os.read(fd, 65536):
            digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise RpmPublicInstallSshError('RPM artifact changed during admission.')
        return digest.hexdigest()
    finally:
        os.close(fd)


def _fixture(archive: Path, typed: Mapping[str, Any]) -> dict[str, Any]:
    """Inspect the built tree archive, rejecting links, extra files and raw Git."""
    names: set[str] = set()
    receipt_raw: bytes | None = None
    hashes: dict[str, tuple[int, str]] = {}
    total = 0
    try:
        with tarfile.open(archive, 'r:*') as source:
            for member in source:
                name = member.name.removeprefix('./')
                if (name.startswith('/') or '\\' in name or any(part in ('', '.', '..') for part in name.split('/'))
                        or name in names or member.issym() or member.islnk() or member.isdev()):
                    raise RpmPublicInstallSshError('RPM fixture archive has an unsafe member.')
                if member.isdir():
                    continue
                if not member.isfile() or member.size < 0 or member.size > _MAX_MEMBER:
                    raise RpmPublicInstallSshError('RPM fixture archive has an unsupported member.')
                total += member.size
                if len(names) >= 128 or total > 4 * 1024 * 1024 * 1024:
                    raise RpmPublicInstallSshError('RPM fixture archive expands beyond its bound.')
                names.add(name)
                if name == 'fixture-receipt.json':
                    if member.size > 1024 * 1024:
                        raise RpmPublicInstallSshError('RPM fixture receipt is oversized.')
                    receipt_raw = source.extractfile(member).read()
                elif name.startswith('packages/base/') or name.startswith('packages/target/'):
                    digest = hashlib.sha256(); count = 0
                    stream = source.extractfile(member)
                    while chunk := stream.read(65536):
                        count += len(chunk); digest.update(chunk)
                    hashes[name] = (count, digest.hexdigest())
                else:
                    raise RpmPublicInstallSshError('RPM fixture archive contains files outside the built fixture tree.')
    except (tarfile.TarError, OSError) as error:
        raise RpmPublicInstallSshError('RPM fixture archive is unreadable.') from error
    if receipt_raw is None:
        raise RpmPublicInstallSshError('RPM fixture receipt is missing.')
    try:
        receipt = json.loads(receipt_raw)
    except (UnicodeError, ValueError) as error:
        raise RpmPublicInstallSshError('RPM fixture receipt is invalid.') from error
    builds = receipt.get('builds') if isinstance(receipt, dict) else None
    if (not isinstance(builds, list) or len(builds) != 2 or receipt.get('schemaVersion') != 1
            or receipt.get('testOnly') is not True or receipt.get('productionTrustChanged') is not False
            or receipt.get('sourceFingerprint') != typed['sourceFingerprint']):
        raise RpmPublicInstallSshError('RPM fixture receipt does not bind the admitted source.')
    base, target = builds
    if (not isinstance(base, dict) or not isinstance(target, dict) or base.get('label') != 'base'
            or target.get('label') != 'target' or not (base.get('sourceFingerprint') == target.get('sourceFingerprint') == typed['sourceFingerprint'])
            or base.get('codeFingerprint') != target.get('codeFingerprint')
            or base.get('version') != typed['expectedBaseVersion'] or target.get('version') != typed['expectedTargetVersion']
            or base.get('mainJarSha256') != typed['expectedDesktopJarSha256']):
        raise RpmPublicInstallSshError('RPM fixture base, target, or installed image identity differs.')
    expected: set[str] = set()
    for build in builds:
        assets = build.get('assets')
        if not isinstance(assets, list):
            raise RpmPublicInstallSshError('RPM fixture assets are invalid.')
        rpm = [a for a in assets if isinstance(a, dict) and a.get('packageType') == 'rpm']
        if len(rpm) != 1:
            raise RpmPublicInstallSshError('RPM fixture requires one RPM per build.')
        for asset in assets:
            if not isinstance(asset, dict):
                raise RpmPublicInstallSshError('RPM fixture asset is invalid.')
            name = asset.get('fileName')
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}', name):
                raise RpmPublicInstallSshError('RPM fixture asset name is invalid.')
            relative = f"packages/{build['label']}/{name}"
            expected.add(relative)
            if hashes.get(relative) != (asset.get('sizeBytes'), asset.get('sha256')):
                raise RpmPublicInstallSshError('RPM fixture asset differs from its frozen receipt.')
            url = asset.get('downloadUrl')
            if build['label'] == 'target' and (not isinstance(url, str) or not url.startswith(typed['fixtureHttpsOrigin'] + '/')):
                raise RpmPublicInstallSshError('RPM target asset is outside the admitted HTTPS fixture.')
    if set(hashes) != expected:
        raise RpmPublicInstallSshError('RPM fixture archive inventory differs from its receipt.')
    rpm_target = next(a for a in target['assets'] if a.get('packageType') == 'rpm')
    if rpm_target['sha256'] != typed['targetPackageSha256']:
        raise RpmPublicInstallSshError('RPM target artifact differs from source receipt.')
    manifest = receipt.get('manifest')
    if (not isinstance(manifest, dict) or manifest.get('schemaVersion') != 1
            or manifest.get('assets') != target['assets']
            or not isinstance(manifest.get('releaseNotesUrl'), str)
            or not manifest['releaseNotesUrl'].startswith(typed['fixtureHttpsOrigin'] + '/')):
        raise RpmPublicInstallSshError('RPM target manifest differs from built assets.')
    return receipt


def _authorization(root: Path, intent: adapter.RpmPublicInstallIntent, source_fingerprint: str) -> None:
    if not _AUTH_HANDLE.fullmatch(intent.credential_handle):
        raise RpmPublicInstallSshError('RPM authorization handle is invalid.')
    directory = root / '.runtime' / 'linux-rpm-public-install-authorizations'
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RpmPublicInstallSshError('RPM authorization store is not owner-only.')
    auth_file = directory / (intent.credential_handle + '.json')
    auth_info = auth_file.lstat()
    if not stat.S_ISREG(auth_info.st_mode) or auth_info.st_uid != os.getuid() or stat.S_IMODE(auth_info.st_mode) != 0o600:
        raise RpmPublicInstallSshError('RPM authorization record is not owner-only.')
    value = json.loads(_private_file(auth_file, 4096))
    expected = {'schemaVersion': 2, 'handle': intent.credential_handle, 'host': intent.host,
                'environment': intent.environment, 'account': _ACCOUNT, 'purpose': _AUTH_PURPOSE,
                'passwordStatus': 'P', 'preservePasswordBaseline': True,
                'correlationId': intent.correlation_id, 'bundleHash': intent.bundle_hash,
                'artifactIds': dict(intent.artifact_ids), 'sourceFingerprint': source_fingerprint}
    if value != expected:
        raise RpmPublicInstallSshError('RPM authorization binding does not match this fixture.')


def admission(root: Path | str, intent: adapter.RpmPublicInstallIntent) -> dict[str, Any]:
    repository = Path(root).resolve()
    paths = {name: _registered(repository, artifact_id) for name, artifact_id in intent.artifact_ids.items()}
    for name, limit in (('scenarioInput', 65536), ('sourceFixture', _MAX_ARCHIVE), ('targetPackage', _MAX_TARGET)):
        if _sha(paths[name], limit) != intent.artifact_ids[name].removeprefix('sha256-'):
            raise RpmPublicInstallSshError('RPM registered artifact hash changed.')
    raw = _private_file(paths['scenarioInput'], 65536)
    typed = adapter.parse_scenario_input(raw, intent)
    _authorization(repository, intent, typed['sourceFingerprint'])
    for name in ('sourceFixture', 'targetPackage'):
        artifact = native_artifact_registry.verify_artifact(repository, intent.artifact_ids[name]).get('artifact')
        if not isinstance(artifact, Mapping) or artifact.get('sourceFingerprint') != typed['sourceFingerprint']:
            raise RpmPublicInstallSshError('Registered RPM source fingerprint differs from the frozen fixture.')
    bundle = paths['bundleManifest']
    if bundle.name != native_scenario_bundle.MANIFEST_NAME:
        raise RpmPublicInstallSshError('RPM bundle manifest path is invalid.')
    verified = native_scenario_bundle.verify_bundle(repository, bundle.parent, intent.bundle_hash)
    if verified.get('scenarioId') != _BUNDLE_ID:
        raise RpmPublicInstallSshError('RPM harness bundle is not allowlisted.')
    _fixture(paths['sourceFixture'], typed)
    config = ssh_transport.load_config(repository)
    host = config.hosts.get(intent.host)
    if (host is None or host.user != _ACCOUNT or not isinstance(host.fixture_transfer_root, PurePosixPath)
            or not host.fixture_transfer_root.is_absolute()):
        raise RpmPublicInstallSshError('RPM host must use the configured fixture account and private transfer root.')
    return {'paths': paths, 'typed': typed, 'bundle': verified, 'config': config,
            'remoteRoot': str(host.fixture_transfer_root)}

_ASSESS_HARNESS = r'''def assess_harness(out_path,intent,rc,run=subprocess.run):
 """Read only the owned harness receipt; retain workspace for exact recovery."""
 try:
  with open(out_path,'rb') as source: first=source.readline(4097)
  pointer=json.loads(first)
  evidence=pointer.get('evidence'); workspace=pointer.get('workspace')
  if not isinstance(evidence,str) or not evidence.startswith('/tmp/vpn-public-install-evidence-') or '/' in evidence[len('/tmp/vpn-public-install-evidence-'):] or workspace!=os.path.join(evidence,'workspace'): raise ValueError()
  info=os.stat(evidence,follow_symlinks=False)
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077: raise ValueError()
  result_path=os.path.join(evidence,'install-result.json')
  fd=os.open(result_path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_size>1024*1024: raise ValueError()
   raw=os.read(fd,1024*1024+1)
   if len(raw)!=info.st_size: raise ValueError()
   result=json.loads(raw)
  finally: os.close(fd)
  accepted=result.get('accepted'); protected=result.get('protectedReceipt'); recovery=result.get('replacementRecoveryObservation')
  if not all(isinstance(value,dict) for value in (accepted,protected,recovery)): raise ValueError()
  operation=accepted.get('operationId'); job=accepted.get('data',{}).get('jobId')
  if not isinstance(operation,str) or not isinstance(job,str) or protected.get('jobId')!=job or recovery.get('operationId')!=operation: raise ValueError()
  if accepted.get('code')!='ACCEPTED' or accepted.get('final') is not False or accepted['data'].get('handoffReady') is not True: raise ValueError()
  if protected.get('phase')!='SUCCEEDED' or protected.get('code')!='OK' or recovery.get('ok') is not True or recovery.get('code')!='OK' or recovery.get('final') is not True: raise ValueError()
  origin=accepted.get('controllerId'); next_owner=recovery.get('controllerId'); data=recovery.get('data')
  if not isinstance(origin,str) or not isinstance(next_owner,str) or not next_owner or origin==next_owner or not isinstance(data,dict) or data.get('jobId')!=job or data.get('originControllerId')!=origin or data.get('originRequestId')!=accepted.get('requestId'): raise ValueError()
  if result.get('sourceFingerprint')!=intent['sourceFingerprint'] or result.get('targetVersion')!=intent['expectedTargetVersion'] or result.get('productionTrustedInstallSucceeded') is not True or result.get('sameSourceRecoveryProven') is not True: raise ValueError()
  # The frozen harness writes install-result only after owner.wait and after
  # restore verifies the original shadow record. Check its cleanup side effect
  # and current P state as independent evidence of that completed path.
  auth_dir=os.path.join(evidence,'private-fixture-auth')
  auth_absent=not os.path.lexists(auth_dir)
  account=run(['passwd','--status','vpnfixture'],capture_output=True,text=True,timeout=30)
  fields=account.stdout.strip().split() if account.returncode==0 else []
  account_p=len(fields)>=2 and fields[0]=='vpnfixture' and fields[1]=='P'
  credential_restored=(result.get('retainedFixtureAuth') is True and result.get('preservesExistingFixturePassword') is True and auth_absent and account_p)
  # A live or retained synthetic workspace is evidence for later cleanup; this
  # collector neither removes it nor turns absence of a path into success.
  workspace_removed=not os.path.lexists(workspace)
  verify=run(['rpm','-V','vpn-control'],capture_output=True,timeout=30)
  clean=verify.returncode==0 and not verify.stdout and not verify.stderr
  flags={'ownerStopped':True,'protectedPreserved':True,'workspaceRemoved':workspace_removed}
  complete=rc==0 and credential_restored and clean and all(flags.values())
  summary={'correlationId':intent['correlationId'],'result':'passed' if complete else 'failed',
   'operationId':operation,'protectedJobId':job,'rpmVerifyClean':clean,
   'credentialRestored':credential_restored,
   'cleanup':{'state':'complete' if complete else 'preserved-for-recovery',**flags}}
  return summary,rc if rc!=0 else 0 if complete else 1
 except Exception:
  return None,rc if rc!=0 else 1
'''

_LAUNCHER = r'''import json,os,subprocess,sys,time,stat
job,stage=sys.argv[1:]
while not os.path.exists(os.path.join(job,'release')): time.sleep(.02)
intent=json.load(open(os.path.join(job,'intent.json'),encoding='utf-8'))
def durable(name,value):
 path=os.path.join(job,name); tmp=path+'.tmp'; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as out: out.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()); out.flush(); os.fsync(out.fileno())
 os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
entry=os.path.join(stage,'scripts','test_linux_public_install.py')
fixture=os.path.join(stage,'fixture')
runner="import pathlib,runpy,sys;p=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(p.parent));sys.argv=[str(p),*sys.argv[2:]];runpy.run_path(str(p),run_name='__main__')"
args=[sys.executable,'-I','-B','-c',runner,entry,'--launcher','/opt/vpn-control/bin/vpn-control','--expected-target-version',intent['expectedTargetVersion'],'--confirm-owned-disposable-vm','--require-same-source-recovery','--rpm-source-fixture',fixture,'--retained-fixture-auth','--preserve-existing-fixture-password','--cleanup-synthetic-workspace']
out_path=os.path.join(job,'harness.stdout'); err_path=os.path.join(job,'harness.stderr')
with open(out_path,'xb',buffering=0) as out,open(err_path,'xb',buffering=0) as err:
 rc=subprocess.call(['/bin/sh',os.path.join(stage,'scripts','native_fixture_run.sh'),'--pid-file',os.path.join(job,'child.pid'),'--exit-file',os.path.join(job,'child.exit'),'--',*args],stdout=out,stderr=err)
''' + _ASSESS_HARNESS + r'''
summary,rc=assess_harness(out_path,intent,rc)
identity=intent['identity']
receipt={'scenarioId':intent['scenarioId'],'host':intent['host'],'environment':intent['environment'],'bundleHash':intent['bundleHash'],'artifactIds':intent['artifactIds'],'correlationId':intent['correlationId'],'pid':identity['pid'],'startTicks':identity['startTicks'],'exitCode':rc,'scenarioEvidence':summary,'failurePhase':'harness-unverified' if summary is None else None}
durable('receipt.json',receipt)
'''

_SUBMIT = r'''import hashlib,json,os,stat,subprocess,sys,tarfile
root,metadata,size,digest=sys.argv[1:]
intent=json.loads(metadata); size=int(size)
os.umask(0o077)
def bad(reason): print(json.dumps({'state':'unknown','reason':reason},separators=(',',':'))); raise SystemExit(64)
names=('scripts/test_linux_public_install.py','scripts/linux_fixture_auth.py','scripts/arch_public_update.py','scripts/rpm_public_update.py','scripts/prepare_desktop_update_fixture.py','scripts/fixture_environment.py','scripts/macos_packaging_jdk_preflight.py','scripts/native_fixture_run.sh','native-scenario-manifest.json','scenario-input.json','source-fixture.tar','target.rpm')
if not 0<size<=4*1024*1024*1024 or set(intent.get('fileHashes',{}))!=set(names): bad('transfer_inventory_invalid')
if intent.get('scenarioId')!='linux-rpm-public-install-recovery' or intent.get('artifactIds',{}).get('bundleManifest')!='sha256-'+intent.get('bundleHash',''): bad('intent_invalid')
def private(path):
 st=os.stat(path,follow_symlinks=False)
 return stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700
if not os.path.isabs(root) or '..' in root.split('/') or not private(root): bad('unsafe_root')
if subprocess.run(['id','-un'],capture_output=True,text=True).stdout.strip()!='vpnfixture': bad('wrong_account')
status=subprocess.run(['passwd','-S','vpnfixture'],capture_output=True,text=True)
if status.returncode or len(status.stdout.split())<2 or status.stdout.split()[1]!='P': bad('password_baseline_changed')
base=os.path.join(root,'native-scenario-jobs',intent['environment'],intent['scenarioId'])
os.makedirs(base,mode=0o700,exist_ok=True)
for p in (os.path.join(root,'native-scenario-jobs'),os.path.join(root,'native-scenario-jobs',intent['environment']),base):
 if not private(p): bad('unsafe_job_root')
job=os.path.join(base,intent['correlationId'])
try: os.mkdir(job,0o700)
except FileExistsError: bad('job_already_exists')
transfer=os.path.join(job,'transfer.tar'); fd=os.open(transfer,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); remaining=size; h=hashlib.sha256()
with os.fdopen(fd,'wb') as out:
 while remaining:
  chunk=sys.stdin.buffer.read(min(remaining,65536))
  if not chunk: bad('interrupted_transfer')
  out.write(chunk); h.update(chunk); remaining-=len(chunk)
 out.flush(); os.fsync(out.fileno())
if h.hexdigest()!=digest: bad('transfer_hash_mismatch')
stage=os.path.join(job,'stage'); os.mkdir(stage,0o700)
expected=set(intent['fileHashes'])
with tarfile.open(transfer,'r:') as archive:
 members=archive.getmembers()
 if {m.name for m in members}!=expected or len(members)!=len(expected): bad('transfer_inventory_mismatch')
 for member in members:
  if not member.isfile() or member.size!=intent['fileHashes'][member.name]['size'] or member.size>2*1024*1024*1024: bad('transfer_member_invalid')
  dest=os.path.join(stage,member.name)
  os.makedirs(os.path.dirname(dest),mode=0o700,exist_ok=True)
  stream=archive.extractfile(member); fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); h=hashlib.sha256()
  with os.fdopen(fd,'wb') as out:
   while chunk:=stream.read(65536): out.write(chunk); h.update(chunk)
   out.flush(); os.fsync(out.fileno())
  if h.hexdigest()!=intent['fileHashes'][member.name]['sha256']: bad('member_hash_mismatch')
manifest=open(os.path.join(stage,'native-scenario-manifest.json'),'rb').read()
if hashlib.sha256(manifest).hexdigest()!=intent['bundleHash']: bad('bundle_hash_mismatch')
m=json.loads(manifest)
if m.get('scenarioId')!='linux-public-update-driver' or m.get('schemaVersion')!=1 or [x.get('path') for x in m.get('files',[])]!=list(names[:8]): bad('wrong_bundle')
if any(m['files'][i].get('sha256')!=intent['fileHashes'][name]['sha256'] or m['files'][i].get('sizeBytes')!=intent['fileHashes'][name]['size'] for i,name in enumerate(names[:8])): bad('bundle_file_mismatch')
if intent['artifactIds'].get('scenarioInput')!='sha256-'+intent['fileHashes']['scenario-input.json']['sha256'] or intent['artifactIds'].get('sourceFixture')!='sha256-'+intent['fileHashes']['source-fixture.tar']['sha256'] or intent['artifactIds'].get('targetPackage')!='sha256-'+intent['fileHashes']['target.rpm']['sha256']: bad('artifact_binding_mismatch')
typed=json.load(open(os.path.join(stage,'scenario-input.json'),encoding='utf-8'))
for key in ('scenarioId','host','environment','correlationId','sourceFingerprint','expectedBaseVersion','expectedTargetVersion','expectedBaseNevra','expectedTargetNevra','expectedDesktopJarSha256'):
 if typed.get(key)!=intent.get(key): bad('typed_input_mismatch')
if typed.get('preservePasswordBaseline') is not True or typed.get('productionTrustChanged') is not False: bad('typed_input_mismatch')
fixture=os.path.join(stage,'fixture'); os.mkdir(fixture,0o700)
expanded=0; entries=0
with tarfile.open(os.path.join(stage,'source-fixture.tar'),'r:*') as archive:
 for member in archive:
  name=member.name.removeprefix('./')
  if member.isdir():
   if name.startswith('/') or '..' in name.split('/'): bad('fixture_directory_invalid')
   continue
  if not member.isfile() or name.startswith('/') or '..' in name.split('/') or not (name=='fixture-receipt.json' or name.startswith('packages/base/') or name.startswith('packages/target/')): bad('fixture_member_invalid')
  expanded+=member.size; entries+=1
  if entries>128 or member.size>1024*1024*1024 or expanded>4*1024*1024*1024: bad('fixture_expansion_bound')
  dest=os.path.join(fixture,name); os.makedirs(os.path.dirname(dest),mode=0o700,exist_ok=True)
  fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400)
  with os.fdopen(fd,'wb') as out:
   source=archive.extractfile(member)
   while chunk:=source.read(65536): out.write(chunk)
   out.flush(); os.fsync(out.fileno())
receipt=json.load(open(os.path.join(fixture,'fixture-receipt.json'),encoding='utf-8'))
if receipt.get('sourceFingerprint')!=intent['sourceFingerprint']: bad('fixture_source_mismatch')
sys.path.insert(0,os.path.join(stage,'scripts'))
from rpm_public_update import verify_rpm_bundle_base
try: verified=verify_rpm_bundle_base('/opt/vpn-control/bin/vpn-control',fixture)
except Exception: bad('installed_base_not_verified')
if verified.get('version')!=intent['expectedBaseVersion'] or verified.get('mainJarSha256')!=intent['expectedDesktopJarSha256']: bad('installed_base_mismatch')
def nevra(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=30)
 return p.stdout.strip() if p.returncode==0 and not p.stderr else None
fmt='%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}'
if nevra(['rpm','-q','--qf',fmt,'vpn-control'])!=intent['expectedBaseNevra']: bad('installed_base_nevra_mismatch')
if nevra(['rpm','-qp','--qf',fmt,os.path.join(stage,'target.rpm')])!=intent['expectedTargetNevra']: bad('target_package_nevra_mismatch')
def durable(name,value):
 path=os.path.join(job,name); tmp=path+'.tmp'; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as out: out.write((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()); out.flush(); os.fsync(out.fileno())
 os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
intent={k:v for k,v in intent.items() if k!='fileHashes'}
durable('intent.json',intent)
launcher=os.path.join(job,'launch.py'); fd=os.open(launcher,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'w') as out: out.write(LAUNCH_CODE); out.flush(); os.fsync(out.fileno())
proc=subprocess.Popen([sys.executable,'-I','-B',launcher,job,stage],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
try: ticks=int(open('/proc/%d/stat'%proc.pid,encoding='ascii').read().rsplit(')',1)[1].split()[19])
except Exception: proc.kill(); bad('process_generation_unavailable')
identity={'pid':proc.pid,'startTicks':ticks}
intent['identity']=identity; durable('intent.json',intent)
fd=os.open(os.path.join(job,'release'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.close(fd)
print(json.dumps({'state':'submitted','correlationId':intent['correlationId']},separators=(',',':')))
'''.replace('LAUNCH_CODE', repr(_LAUNCHER))

_STATUS = r'''import json,os,stat,sys
root,host,env,corr,bundle,artifacts=sys.argv[1:]
job=os.path.join(root,'native-scenario-jobs',env,'linux-rpm-public-install-recovery',corr)
def unknown(): print(json.dumps({'state':'unknown','correlationId':corr},separators=(',',':'))); raise SystemExit(0)
def read(name):
 fd=os.open(os.path.join(job,name),os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>1024*1024: unknown()
  return json.loads(os.read(fd,1024*1024+1))
 finally: os.close(fd)
try:
 info=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: unknown()
 intent=read('intent.json')
 expected={'scenarioId':'linux-rpm-public-install-recovery','host':host,'environment':env,'correlationId':corr,'bundleHash':bundle,'artifactIds':json.loads(artifacts)}
 if any(intent.get(k)!=v for k,v in expected.items()): unknown()
 identity=intent.get('identity')
 if not isinstance(identity,dict) or type(identity.get('pid')) is not int or type(identity.get('startTicks')) is not int: unknown()
 try: receipt=read('receipt.json')
 except FileNotFoundError: receipt=None
 if receipt is not None:
  if any(receipt.get(k)!=v for k,v in expected.items()) or receipt.get('pid')!=identity['pid'] or receipt.get('startTicks')!=identity['startTicks'] or type(receipt.get('exitCode')) is not int: unknown()
  summary=receipt.get('scenarioEvidence')
  if not isinstance(summary,dict) or summary.get('correlationId')!=corr: summary=None
  print(json.dumps({'state':'terminal','correlationId':corr,'exitCode':receipt['exitCode'],'scenarioEvidence':summary,'failurePhase':receipt.get('failurePhase') if receipt.get('failurePhase') in ('harness-unverified','guest-admission') else None},separators=(',',':'))); raise SystemExit(0)
 try:
  parts=open('/proc/%d/stat'%identity['pid'],encoding='ascii').read().rsplit(')',1)[1].split()
  if parts[0]=='Z' or int(parts[19])!=identity['startTicks']: unknown()
 except Exception: unknown()
 print(json.dumps({'state':'running','correlationId':corr},separators=(',',':')))
except Exception: unknown()
'''

class RpmPublicInstallSshDriver:
    def __init__(self, repository_root: Path | str, timeout_seconds: int = 60, ssh_binary: str = 'ssh'):
        self.root = Path(repository_root).resolve()
        self.timeout_seconds = timeout_seconds
        self.ssh_binary = ssh_binary
        self.journal = self.root / '.rag_index' / 'native-rpm-public-install'

    def _journal_path(self, correlation: str) -> Path:
        adapter.RpmPublicInstallAdapter._correlation(correlation)
        return self.journal / (correlation + '.json')

    def _read_journal(self, correlation: str) -> dict[str, Any] | None:
        path = self._journal_path(correlation)
        try:
            value = json.loads(_private_file(path, 8192))
            if not isinstance(value, dict) or value.get('correlationId') != correlation:
                return None
            return value
        except (OSError, ValueError):
            return None

    def _save_journal(self, intent: adapter.RpmPublicInstallIntent) -> None:
        self.journal.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.journal.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RpmPublicInstallSshError('RPM local journal is not private.')
        fd = os.open(self._journal_path(intent.correlation_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(_canonical(intent.public_mapping()))
            out.flush(); os.fsync(out.fileno())
        directory = os.open(self.journal, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)

    @staticmethod
    def _transfer(path: Path, captured: Mapping[str, Any], intent: adapter.RpmPublicInstallIntent) -> dict[str, Any]:
        paths = captured['paths']
        bundle = paths['bundleManifest'].parent
        names = [entry['path'] for entry in captured['bundle']['files']]
        files: dict[str, Path] = {name: bundle / name for name in names}
        files.update({'native-scenario-manifest.json': paths['bundleManifest'],
                      'scenario-input.json': paths['scenarioInput'],
                      'source-fixture.tar': paths['sourceFixture'],
                      'target.rpm': paths['targetPackage']})
        hashes = {}
        with tarfile.open(path, 'w') as archive:
            for name, source in files.items():
                maximum = _MAX_ARCHIVE if name == 'source-fixture.tar' else _MAX_TARGET if name == 'target.rpm' else 8 * 1024 * 1024
                digest = _sha(source, maximum)
                info = source.stat()
                if not stat.S_ISREG(info.st_mode):
                    raise RpmPublicInstallSshError('RPM transfer member is unsafe.')
                archive.add(source, arcname=name, recursive=False)
                hashes[name] = {'size': info.st_size, 'sha256': digest}
        return hashes

    def _remote(self, config: Any, host: str, program: str, args: tuple[str, ...], payload: Path | None = None) -> Mapping[str, Any] | None:
        import subprocess
        import threading
        from contextlib import nullcontext
        command = native_scenario_ssh._py(program, *args)
        argv = ssh_transport.build_ssh_argv(config, host, self.timeout_seconds, command=command, ssh_binary=self.ssh_binary)
        connection = ssh_transport.connection_host(config, host)
        context = tempfile.TemporaryDirectory(prefix='vpn-rpm-askpass-') if connection.password is not None else nullcontext(None)
        with context as temporary:
            environment = ssh_transport._askpass_environment(connection.password, Path(temporary))[1] if temporary is not None else None
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=environment)
            except OSError:
                return None
            errors: list[Exception] = []
            def write() -> None:
                try:
                    if payload is not None:
                        with payload.open('rb') as source:
                            while chunk := source.read(65536):
                                process.stdin.write(chunk)
                    process.stdin.close()
                except (OSError, BrokenPipeError) as error:
                    errors.append(error)
                    try: process.stdin.close()
                    except OSError: pass
            writer = threading.Thread(target=write, daemon=True)
            writer.start()
            expired = threading.Event()
            def timeout() -> None:
                expired.set()
                try: process.kill()
                except OSError: pass
            timer = threading.Timer(self.timeout_seconds + 2, timeout)
            timer.start()
            try:
                output = process.stdout.read(8193)
                process.wait()
            finally:
                timer.cancel()
            writer.join(timeout=1)
            if expired.is_set() or errors or process.returncode != 0 or len(output) > 8192:
                return None
            try:
                value = json.loads(output)
                return value if isinstance(value, dict) else None
            except (UnicodeError, ValueError):
                return None

    def submit(self, intent: adapter.RpmPublicInstallIntent) -> Mapping[str, Any]:
        captured = admission(self.root, intent)
        # The local no-replay intent is durable before a guest receives bytes.
        try:
            self._save_journal(intent)
        except FileExistsError as error:
            raise RpmPublicInstallSshError('RPM correlation already has an intent; observe it instead.') from error
        with tempfile.TemporaryDirectory(prefix='vpn-rpm-transfer-') as temporary:
            transfer = Path(temporary) / 'transfer.tar'
            hashes = self._transfer(transfer, captured, intent)
            metadata = {**intent.public_mapping(), 'expectedBaseVersion': captured['typed']['expectedBaseVersion'],
                        'expectedTargetVersion': captured['typed']['expectedTargetVersion'],
                        'expectedBaseNevra': captured['typed']['expectedBaseNevra'],
                        'expectedTargetNevra': captured['typed']['expectedTargetNevra'],
                        'expectedDesktopJarSha256': captured['typed']['expectedDesktopJarSha256'],
                        'sourceFingerprint': captured['typed']['sourceFingerprint'], 'fileHashes': hashes}
            result = self._remote(captured['config'], intent.host, _SUBMIT,
                (captured['remoteRoot'], json.dumps(metadata, sort_keys=True, separators=(',', ':')),
                 str(transfer.stat().st_size), _sha(transfer, 4 * 1024 * 1024 * 1024)), transfer)
        return result if result and result.get('state') == 'submitted' and result.get('correlationId') == intent.correlation_id else {'state': 'unknown', 'correlationId': intent.correlation_id}

    def status(self, correlation_id: str) -> Mapping[str, Any]:
        stored = self._read_journal(correlation_id)
        if stored is None:
            return {'state': 'unknown', 'correlationId': correlation_id}
        try:
            config = ssh_transport.load_config(self.root)
            host = config.hosts.get(stored['host'])
            if host is None or host.user != _ACCOUNT or not isinstance(host.fixture_transfer_root, PurePosixPath):
                raise RpmPublicInstallSshError('RPM configured host is unavailable.')
            result = self._remote(config, stored['host'], _STATUS,
                (str(host.fixture_transfer_root), stored['host'], stored['environment'], correlation_id,
                 stored['bundleHash'], json.dumps(stored['artifactIds'], sort_keys=True, separators=(',', ':'))))
            return result if result and result.get('correlationId') == correlation_id else {'state': 'unknown', 'correlationId': correlation_id}
        except (OSError, ValueError, KeyError):
            return {'state': 'unknown', 'correlationId': correlation_id}

    def collect(self, correlation_id: str) -> Mapping[str, Any]:
        return self.status(correlation_id)


def preflight(root: Path | str, request: Mapping[str, Any]) -> dict[str, Any]:
    required = {'scenarioId', 'host', 'environment', 'bundleManifestArtifactId', 'scenarioInputArtifactId',
                'sourceFixtureArtifactId', 'targetPackageArtifactId', 'credentialHandle', 'scenarioCorrelationId'}
    if (not isinstance(request, Mapping) or set(request) != required
            or not isinstance(request.get('bundleManifestArtifactId'), str)):
        raise RpmPublicInstallSshError('RPM preflight inputs are invalid.')
    intent = adapter.RpmPublicInstallIntent.from_mapping({'scenarioId': request['scenarioId'],
        'host': request['host'], 'environment': request['environment'],
        'bundleHash': request['bundleManifestArtifactId'].removeprefix('sha256-'),
        'artifactIds': {'bundleManifest': request['bundleManifestArtifactId'],
                        'scenarioInput': request['scenarioInputArtifactId'],
                        'sourceFixture': request['sourceFixtureArtifactId'],
                        'targetPackage': request['targetPackageArtifactId']},
        'credentialHandle': request['credentialHandle'], 'correlationId': request['scenarioCorrelationId']})
    try:
        admission(root, intent)
        return {'ready': True, 'scenarioId': adapter.SCENARIO_ID}
    except (OSError, ValueError, tarfile.TarError) as error:
        return {'ready': False, 'scenarioId': adapter.SCENARIO_ID, 'requirements': {'rpmAdmission': {'state': 'failed', 'reason': type(error).__name__, 'evidenceScope': 'registered-local-and-owner-only'}}}
