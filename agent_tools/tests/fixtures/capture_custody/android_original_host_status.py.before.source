"""Exact original0dd host-only observation for the existing status adapter.

No application, installer, lease, runtime or trust operation is available here.
The existing status envelope remains UNKNOWN; the complete private capsule supplies
actual source-bound original records and actor disposition for reconciliation.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid
import zlib
from . import android_original_host_wire as wire

ORIGINAL = '0dd55704-1e80-4d62-8d9d-2f0a123e0c3b'
ORIGINAL_DISPATCH_SHA = '23e6c8babcf76401f099d4636d569c922064e8334da647d05e795a612b704412'
ORIGINAL_INTENT_SHA = '1b1eba7b0744ae47adc98b6b7fd7cc1480bc62a5b2ed7d4902fb36de580d7656'
ORIGINAL_LEASE_SHA = '44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a'
ORIGINAL_BUNDLE = 'sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac'
_HOST_TEMPLATE = 'import os,stat,json,hashlib,base64,time\nfrom pathlib import Path\ndef _generation(info: os.stat_result) -> list[int]:\n    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,\n            stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink]\n\ndef _directory(path: Path) -> int:\n    # Walk every parent through descriptor-relative O_NOFOLLOW, including root.\n    absolute = path.absolute(); fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)\n    try:\n        for part in absolute.parts[1:]:\n            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n            os.close(fd); fd = child\n        info = os.fstat(fd)\n        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700: raise ValueError("private_parent_invalid")\n        return fd\n    except BaseException:\n        os.close(fd); raise\n\ndef _ancestry(path: Path) -> list[list[int]]:\n    absolute = path.absolute(); fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)\n    result = []\n    try:\n        for part in absolute.parts[1:]:\n            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)\n            os.close(fd); fd = child; info = os.fstat(fd)\n            result.append([info.st_dev, info.st_ino, info.st_mode, info.st_uid])\n        return result\n    finally: os.close(fd)\n\ndef private_snapshot(path: Path, limit: int = 1_048_576) -> tuple[bytes, list[int], str]:\n    ancestry = _ancestry(path.parent); parent = _directory(path.parent)\n    try:\n        info = os.fstat(parent)\n        if ancestry[-1] != [info.st_dev, info.st_ino, info.st_mode, info.st_uid]: raise ValueError("private_parent_changed")\n        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)\n        with os.fdopen(fd, "rb") as stream:\n            before = os.fstat(stream.fileno()); payload = stream.read(limit + 1); after = os.fstat(stream.fileno())\n        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)\n        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600 or\n            before.st_nlink != 1 or len(payload) > limit or len(payload) != before.st_size or\n            _generation(before) != _generation(after) or _generation(before) != _generation(named) or _ancestry(path.parent) != ancestry):\n            raise ValueError("private_file_changed")\n        return payload, _generation(before), hashlib.sha256(payload).hexdigest()\n    finally: os.close(parent)\nCORRELATION=\'0dd55704-1e80-4d62-8d9d-2f0a123e0c3b\'\nJOB=Path(_FIXTURE_ROOT)/("android-installer-"+CORRELATION)\nEXPECTED_REMOTE=_EXPECTED_REMOTE\nROLES={\'dispatch.json\':16384,\'identity.json\':4096,\'output/fixture-identity.json\':4096,\'output/fixture-receipt.json\':1048576,\'output/handoff.json\':1048576,\'output/intent.json\':8192,\'output/lifecycle-receipt.json\':1048576,\'output/phase-check.json\':1048576,\'output/probe.json\':1048576,\'output/run-started.json\':1024,\'output/worker-finished.json\':4096}\nACTORS={\'worker\':(1169929,72285068),\'fixture\':(1172004,72288190)}\ndef unique(pairs):\n value={}\n for key,item in pairs:\n  if key in value:raise ValueError(\'duplicate_json_key\')\n  value[key]=item\n return value\ndef record(role,limit):\n path=JOB/role\n try:\n  raw,generation,digest=private_snapshot(path,limit)\n  return {\'state\':\'present\',\'bytes\':len(raw),\'sha256\':digest,\'generation\':generation,\'base64\':base64.b64encode(raw).decode()}\n except FileNotFoundError:\n  ancestry=_ancestry(path.parent);fd=_directory(path.parent)\n  try:\n   try:os.stat(path.name,dir_fd=fd,follow_symlinks=False)\n   except FileNotFoundError:pass\n   else:raise ValueError(\'absent_changed\')\n   if _ancestry(path.parent)!=ancestry:raise ValueError(\'absent_parent_changed\')\n  finally:os.close(fd)\n  return {\'state\':\'absent\',\'parentAncestry\':ancestry}\ndef procraw(pid,name,limit):\n fd=os.open(\'/proc/\'+str(pid)+\'/\'+name,os.O_RDONLY|os.O_NOFOLLOW)\n try:\n  raw=os.read(fd,limit+1)\n  if len(raw)>limit:raise ValueError(\'actor_capture_bounds\')\n  return raw\n finally:os.close(fd)\ndef actor(name,pin):\n pid,ticks=pin\n try:\n  raw=procraw(pid,\'stat\',4096);fields=raw.rsplit(b\')\',1)[1].split()\n  start=int(fields[19]);ppid=int(fields[1]);session=int(fields[3]);cmd=procraw(pid,\'cmdline\',16384);status=procraw(pid,\'status\',16384)\n  if procraw(pid,\'stat\',4096).rsplit(b\')\',1)[1].split()[19]!=str(start).encode():raise ValueError(\'actor_identity_changed\')\n  rows=dict(line.split(b\':\',1)for line in status.splitlines()if b\':\'in line)\n  uid=[int(x)for x in rows[b\'Uid\'].split()];gid=[int(x)for x in rows[b\'Gid\'].split()]\n  return {\'state\':\'matching\'if start==ticks else \'reused\',\'pid\':pid,\'startTicks\':start,\'expectedStartTicks\':ticks,\'ppid\':ppid,\'session\':session,\'uid\':uid,\'gid\':gid,\'commandBytes\':len(cmd),\'commandSha256\':hashlib.sha256(cmd).hexdigest(),\'commandBase64\':base64.b64encode(cmd).decode()}\n except FileNotFoundError:\n  if os.path.lexists(\'/proc/\'+str(pid)):raise ValueError(\'actor_partial\')\n  return {\'state\':\'absent\',\'pid\':pid,\'expectedStartTicks\':ticks}\nresult={\'state\':\'unknown\',\'correlationId\':CORRELATION,\'replayAllowed\':False,\'leaseReleased\':False,\'scope\':\'original0dd_host_only_records_and_actor_identity\',\'adbCommands\':0}\ntry:\n if os.getuid()!=1000:raise ValueError(\'host_principal_changed\')\n boot=Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()\n first={role:record(role,limit)for role,limit in ROLES.items()};actors1={name:actor(name,pin)for name,pin in ACTORS.items()}\n if first[\'dispatch.json\'][\'state\']!=\'present\' or json.dumps(json.loads(base64.b64decode(first[\'dispatch.json\'][\'base64\']),object_pairs_hook=unique),sort_keys=True)!=json.dumps(EXPECTED_REMOTE,sort_keys=True):raise ValueError(\'original_remote_dispatch_changed\')\n if first[\'identity.json\'][\'state\']!=\'present\' or json.dumps(json.loads(base64.b64decode(first[\'identity.json\'][\'base64\']),object_pairs_hook=unique),sort_keys=True)!=json.dumps({\'pid\':1169929,\'startTicks\':72285068},sort_keys=True):raise ValueError(\'original_worker_record_changed\')\n fixture=json.loads(base64.b64decode(first[\'output/fixture-identity.json\'][\'base64\']),object_pairs_hook=unique)\n if type(fixture.get(\'pid\'))is not int or type(fixture.get(\'startTicks\'))is not int or fixture.get(\'pid\')!=1172004 or fixture.get(\'startTicks\')!=72288190 or fixture.get(\'correlationId\')!=CORRELATION:raise ValueError(\'original_fixture_record_changed\')\n second={role:record(role,limit)for role,limit in ROLES.items()};actors2={name:actor(name,pin)for name,pin in ACTORS.items()}\n if first!=second:raise ValueError(\'original_record_changed\')\n if actors1!=actors2:raise ValueError(\'original_actor_disposition_changed\')\n if Path(\'/proc/sys/kernel/random/boot_id\').read_text().strip()!=boot:raise ValueError(\'host_boot_changed\')\n result.update(state=\'observed\',hostBoot=boot,hostUid=os.getuid(),records=first,actorPasses=[actors1,actors2])\nexcept BaseException as error:\n result.update(reason=str(error)if type(error)is ValueError and len(str(error))<64 else \'record_or_actor_unreadable\',errorClass=type(error).__name__,errno=getattr(error,\'errno\',None))\nprint(encode_payload(result).decode(\'ascii\'),flush=True)\n'


def remote_source(intent):
    # Only this adapter calls the builder, after authentic original intent/config
    # admission. Neither the public status action nor codec accepts a path/command.
    codec_source = Path(wire.__file__).read_text(encoding='utf-8')
    return (codec_source + '\n_FIXTURE_ROOT=' + repr(intent['fixtureRoot']) +
            '\n_EXPECTED_REMOTE=' + repr(intent['remote']) + '\n' + _HOST_TEMPLATE)


def _write(directory, name, value):
    payload = value if type(value) is bytes else (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
    directory.guard()
    descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory.fd)
    try:
        remaining = memoryview(payload)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise OSError('short_private_capture_write')
            remaining = remaining[count:]
        os.fsync(descriptor)
        actual = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        def generation(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.getuid() or
                stat.S_IMODE(actual.st_mode) != 0o600 or actual.st_nlink != 1 or
                actual.st_size != len(payload) or generation(actual) != generation(named) or
                os.pread(descriptor, len(payload) + 1, 0) != payload):
            raise ValueError('retained_capture_changed')
        directory.guard()
    finally:
        os.close(descriptor)
    directory.guard()


def observe_original(root, intent):
    from . import ssh_direct_nested_channel as direct, ssh_transport as transport
    from . import private_inventory_lock as private, android_observation
    from . import android_qualified_cli_observation as qualified
    from . import android_installer_tool_bundle as bundles
    if (type(intent) is not dict or intent.get('correlationId') != ORIGINAL or
            intent.get('host') != 'archlinux' or intent.get('device') != 'api35' or
            intent.get('toolBundleId') != ORIGINAL_BUNDLE):
        raise ValueError('only_reviewed_original_host_status')
    if not direct.coordinator_capable():
        return {'state': 'unknown', 'reason': 'transport_or_receipt_unknown'}
    root = Path(root).resolve(strict=True)
    parent = root / '.rag_index/android-installer-dispatch' / ORIGINAL
    parent_info = os.lstat(parent)
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or
            stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise ValueError('original_observation_parent_invalid')
    capsule = parent / ('host-observation-' + uuid.uuid4().hex)
    capsule.mkdir(mode=0o700)
    guard = None
    custody = None
    output_directory = private.Directory(capsule)
    phase = 'admission'
    complete = False
    failure = None
    result = None
    started = time.monotonic()
    try:
        guard = direct.Guard(root)
        consumed = [Path(__file__), Path(wire.__file__),
                    Path(qualified.__file__), Path(bundles.__file__), Path(android_observation.__file__),
                    Path(__file__).with_name('android_installer_dispatch.py')]
        for source in consumed:
            guard.held.read(str(source), hashlib.sha256(source.read_bytes()).hexdigest())
        original_raw = guard.held.read(str(parent / 'dispatch.json'), ORIGINAL_DISPATCH_SHA)
        if json.dumps(json.loads(original_raw), sort_keys=True) != json.dumps(intent, sort_keys=True):
            raise ValueError('original_dispatch_binding_changed')
        guard.held.read(str(parent / 'intent.json'), ORIGINAL_INTENT_SHA)
        lease = root / '.rag_index/android-native-device-leases/lease-archlinux-api35.json'
        guard.held.read(str(lease), ORIGINAL_LEASE_SHA)
        config = guard.config
        host = config.hosts['archlinux']
        profile = android_observation._profile(host.android_devices['api35'])
        # Preserve full original bundle admission in the existing _remote gate,
        # and independently recheck that immutable bundle before/after retention.
        bundle = bundles.load(root, ORIGINAL_BUNDLE)
        expected_bundle = {key: bundle[key] for key in ('toolBundleId', 'reviewedTreeSha256', 'manifest')}
        if (intent['remote']['toolBundle'] != expected_bundle or
                str(host.fixture_transfer_root) != intent['fixtureRoot'] or
                any(profile[field] != intent['remote'][remote] for field, remote in
                    (('serial', 'serial'), ('expectedAvd', 'avd'), ('api', 'api'), ('adb', 'adb'))) ):
            raise ValueError('original_host_profile_changed')
        # Exact dispatch SHA holds the original staged CLI path/source/bundle.
        # This host-only programme never executes that CLI; configured fresh
        # CLI admission remains an independent operation.
        source = remote_source(intent)
        digest = hashlib.sha256(source.encode()).hexdigest()
        _write(output_directory, 'source.private.py', source.encode())
        _write(output_directory, 'admission.private.json', {'correlationId': ORIGINAL, 'programSha256': digest,
               'directSourcePins': guard.source_pins, 'authoritySha256': guard.authority_sha,
               'bundleId': ORIGINAL_BUNDLE, 'adbCommands': 0, 'replayAllowed': False})
        guard.guard()
        packed = base64.b64encode(zlib.compress(source.encode())).decode('ascii')
        wrapper = ('import base64,zlib,hashlib;raw=zlib.decompress(base64.b64decode(' + repr(packed) +
                   ',validate=True));assert hashlib.sha256(raw).hexdigest()==' + repr(digest) +
                   ';exec(compile(raw,"fixed_original0dd_host_only","exec"))')
        argv = transport.build_ssh_argv(config, 'archlinux', 60, command=('python3', '-I', '-B', '-c', wrapper))
        guard.guard()
        phase = 'capture'
        custody = qualified.OuterCustody(argv)
        _write(output_directory, 'accepted.private.json', {'pid': custody.child.pid, 'correlationId': ORIGINAL,
               'programSha256': digest, 'adbCommands': 0, 'replayAllowed': False})
        custody.send(b'{}')
        initial = custody.observe(60)
        _write(output_directory, 'initial.private.json', initial)
        for name, data in custody.raw.items():
            _write(output_directory, 'initial-' + name + '.private', bytes(data))
        custody.finish_naturally()
        final = custody.snapshot()
        _write(output_directory, 'final.private.json', final)
        for name, data in custody.raw.items():
            _write(output_directory, 'final-' + name + '.private', bytes(data))
        _write(output_directory, 'stream-digests.private.json', {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()} for name, data in custody.raw.items()})
        if (not initial['complete'] or initial['overflow'] or initial['sendError'] or
                initial['returnCode'] != 0 or custody.raw['stderr']):
            raise ValueError('original_host_capture_unknown')
        phase = 'decode'
        decoded = wire.decode_payload_bytes(bytes(custody.raw['stdout']))
        _write(output_directory, 'decoded.private.json', decoded)
        result = wire._strict_json(decoded)
        _write(output_directory, 'decoded-digest.private.json', {'bytes': len(decoded), 'sha256': hashlib.sha256(decoded).hexdigest()})
        if (result.get('state') != 'observed' or result.get('correlationId') != ORIGINAL or
                type(result.get('hostUid')) is not int or result.get('hostUid') != 1000 or result.get('hostBoot') != '25515f23-b966-4c3a-ae63-d38452375578'):
            raise ValueError('original_host_payload_unknown')
        phase = 'closing'
        if bundles.load(root, ORIGINAL_BUNDLE) != bundle:
            raise ValueError('original_bundle_closing_changed')
        guard.guard()
        complete = True
    except (OSError, ValueError, KeyError, TypeError, zlib.error) as error:
        failure = {'phase': phase, 'type': type(error).__name__, 'reason': 'original_host_observation_unknown'}
    finally:
        if custody is not None and not custody.closed:
            custody.finish_naturally()
        closing = False
        if guard is not None:
            try:
                guard.guard()
                closing = True
            except (OSError, ValueError, KeyError, TypeError):
                complete = False
            finally:
                guard.close()
        try:
            _write(output_directory, 'receipt.private.json', {'correlationId': ORIGINAL,
                   'observationComplete': complete and closing, 'closingAuthenticated': closing,
                   'originalOutcome': 'UNKNOWN', 'failure': failure, 'elapsedSeconds': time.monotonic() - started,
                   'leaseReleased': False, 'adbCommands': 0, 'replayAllowed': False})
        finally:
            output_directory.close()
    # The original worker/status outcome is never promoted by a diagnostic read.
    return {'state': 'unknown', 'reason': 'worker_or_receipt_unknown' if complete and closing else 'transport_or_receipt_unknown'}
