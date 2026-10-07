"""Causal NTAccount coverage uses the exact emitted native PowerShell cases."""
import base64
import json
import os
import re
import shutil
import subprocess
import unittest

from agent_tools import windows_secondary_ordinary_read as subject

POWERSHELL = shutil.which('powershell.exe') if os.name == 'nt' else None


class NativeAccountGuardTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, 'native Windows PowerShell required; guest census runs the same cases')
    def test_actual_null_constructor_red_and_guard_green(self):
        source = subject.nt_account_regression_powershell()
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(source.encode('utf-16le')).decode()], capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        subject.validate_nt_account_regression(json.loads(result.stdout.decode('utf-8-sig')))

    @unittest.skipUnless(POWERSHELL, 'native Windows PowerShell parser required')
    def test_actual_census_factory_outer_and_fixed_body_parse(self):
        sources = []
        for factory in (subject.ordinary_actor_census_powershell, subject.boot_diagnosis_powershell):
            outer = factory('c22f9067-2f64-4568-b035-3ec69ed39b9c')
            payload = re.search(r"\$bytes=\[Convert\]::FromBase64String\('([^']+)'\)", outer).group(1)
            sources.extend((outer, base64.b64decode(payload, validate=True).decode('utf-8')))
        for source in sources:
            encoded = base64.b64encode(source.encode('utf-8')).decode()
            command = "$ErrorActionPreference='Stop';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + encoded + "'));$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($s,[ref]$tokens,[ref]$errors);[Console]::Out.WriteLine($errors.Count);if($errors.Count -ne 0){exit 1}"
            argv = [POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(command.encode('utf-16le')).decode()]
            self.assertLess(len(subprocess.list2cmdline(argv)) + 1, 32767)
            result = subprocess.run(argv, capture_output=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout.decode('utf-8-sig').strip(), '0')

    def test_actual_projection_basename_regex_refuses_arguments(self):
        value = r'C:\PRIVATE_PATH_SENTINEL\svchost.exe (PRIVATE_MACHINE_SENTINEL)'
        match = re.search(r"if\(\$candidate -match '([^']+)'\)\{\$process=", subject.BOOT_EVENT_PROJECTION)
        actual = match.group(1)
        result = re.search(actual, value)
        self.assertIsNotNone(result)
        self.assertEqual(result.group(1), 'svchost.exe')
        self.assertIsNone(re.search(actual, value + ' PRIVATE_ARGUMENT_SENTINEL'))

    @unittest.skipUnless(POWERSHELL, 'native Windows PowerShell projection required')
    def test_actual_boot_projection_private_and_foreign_fields_refused(self):
        source = subject.boot_projection_regression_powershell()
        argv = [POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(source.encode('utf-16le')).decode()]
        self.assertLess(len(subprocess.list2cmdline(argv)) + 1, 32767)
        result = subprocess.run(argv, capture_output=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout.decode('utf-8-sig').strip(), 'projection-green')

    def test_false_success_and_missing_actual_cases_refused(self):
        for value in [None, {}, {'oldNull': {'failed': False}}, {'oldNull': {'failed': True, 'errorId': 'foreign'}, 'guarded': []}]:
            with self.assertRaises(ValueError):
                subject.validate_nt_account_regression(value)

    def test_foreign_correlation_refused(self):
        for value in [None, 1, '', 'NOT-A-UUID']:
            with self.assertRaises((ValueError, AttributeError, TypeError)):
                subject.ordinary_actor_census_powershell(value)

class NativeMuxWrapperTests(unittest.TestCase):
    @staticmethod
    def emitted_decoder(wrapper):
        import ast
        nodes=[]
        for node in ast.parse(wrapper).body:
            if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROGRAM' for t in node.targets):break
            nodes.append(node)
        ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'actual secondary emitted decoder','exec'),ns)
        return ns['decode_native_source']

    def test_actual_previous_route_exceeds_cap_successor_preserves_complete_source(self):
        import ast,inspect,hashlib,sys,tempfile
        from pathlib import Path,PurePosixPath
        from agent_tools import ssh_transport as ssh,windows_credential_probe_ssh as probe,windows_parallel_vm_prepare_transport as old
        source='# PUBLIC SOURCE\n'*6500+"print('PUBLIC')\n"
        node=next(n for n in ast.walk(ast.parse(inspect.getsource(old._dispatch))) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='wrapper' for t in n.targets))
        previous=eval(compile(ast.Expression(node.value),'actual previous wrapper','eval'),{'program':source,'base64':base64})
        wrapper=subject.compressed_native_wrapper(source)
        with tempfile.TemporaryDirectory() as tmp:
            config=ssh.SshConfig(Path(tmp),{'gateway':ssh.SshHost('gateway','gateway.example',22,'public',Path('/public/key'),Path('/public/known')),'arch':ssh.SshHost('arch','arch',22,'public',Path('/public/key'),PurePosixPath('/public/known'),transport='nested',gateway='gateway',remote_host_alias='arch',remote_control_path=PurePosixPath('/public/socket'))})
            before=ssh.build_ssh_argv(config,'arch',command=probe._remote_command(previous))
            after=ssh.build_ssh_argv(config,'arch',command=probe._remote_command(wrapper))
        self.assertGreater(max(len(x.encode())+1 for x in before),65536)
        self.assertLess(max(len(x.encode())+1 for x in after),65536)
        nodes=[]
        for n in ast.parse(wrapper).body:
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='secret' for t in n.targets):break
            nodes.append(n)
        body=ast.unparse(ast.Module(body=nodes,type_ignores=[]))+"\nprint(__import__('json').dumps({'length':len(PROGRAM.encode()),'sha256':__import__('hashlib').sha256(PROGRAM.encode()).hexdigest()}))"
        actual=subprocess.run([sys.executable,'-c',body],capture_output=True,timeout=3,check=True)
        self.assertEqual(json.loads(actual.stdout),{'length':len(source.encode()),'sha256':hashlib.sha256(source.encode()).hexdigest()})
        self.assertIn('secret=sys.stdin.buffer.read(513)',wrapper)
        self.assertIn('stderr=sys.stderr.buffer',wrapper)
        self.assertNotIn('stderr=subprocess.DEVNULL',wrapper)

    def test_actual_emitted_decoder_refuses_malformed_and_wrong_source(self):
        import gzip,hashlib
        source=b"print('PUBLIC')\n";packed=gzip.compress(source,mtime=0);digest=hashlib.sha256(source).hexdigest();decode=self.emitted_decoder(subject.compressed_native_wrapper(source.decode()))
        self.assertEqual(decode(base64.b64encode(packed).decode(),len(source),digest),source.decode())
        cases=[(b'not gzip',len(source),digest),(packed[:-1],len(source),digest),(packed+b'trailing',len(source),digest),(packed+packed,len(source),digest),(packed,len(source)-1,digest),(packed,len(source)+1,digest),(packed,len(source),'0'*64),(gzip.compress(b'A'*131001,mtime=0),131001,digest),(gzip.compress(b'\xff',mtime=0),1,hashlib.sha256(b'\xff').hexdigest())]
        for data,size,sha in cases:
            with self.subTest(size=size,sha=sha),self.assertRaises(ValueError):decode(base64.b64encode(data).decode(),size,sha)
        with self.assertRaises(ValueError):decode('not base64!',len(source),digest)
        corrupt=packed[:-8]+bytes([packed[-8]^1])+packed[-7:]
        with self.assertRaises(ValueError):decode(base64.b64encode(corrupt).decode(),len(source),digest)

    def test_complete_factory_source_and_wrapper_caps_refuse(self):
        import random
        with self.assertRaises(ValueError):subject.compressed_native_wrapper('#'+'A'*131001)
        text=random.Random(20261006).randbytes(50000).hex()
        with self.assertRaises(ValueError):subject.compressed_native_wrapper('PUBLIC='+repr(text))


if __name__ == '__main__':
    unittest.main()


# Exact historical callback methods from original441fa597, with only host peer guard excluded.
import os,json
from scripts import native_fixture_qga as qga
class ActualCapture(qga.QgaReadOnlyClient):

    def bind(self, run, guest, identity):
        self.run, self.guest, self.identity = (run, guest, identity)
        self.frames = 0
        return self

    def _read_response(self, connection, deadline):
        received = bytearray()

        class CapturingSocket:

            def __getattr__(self, name):
                return getattr(connection, name)

            def recv(self, size):
                chunk = connection.recv(size)
                received.extend(chunk[:max(0, self_limit + 1 - len(received))])
                return chunk
        self_limit = self.max_response_bytes
        complete = False
        reason = 'unknown'
        raw = None
        try:
            raw = super()._read_response(CapturingSocket(), deadline)
            complete = True
            reason = 'complete'
        except EOFError:
            reason = 'eof'
            raise
        except TimeoutError:
            reason = 'deadline'
            raise
        except qga.QgaProtocolError:
            reason = 'overflow'
            raise
        finally:
            self._retain_response(bytes(received), complete, reason)
        return raw

    def _retain_response(self, raw, complete, reason):
        self.frames += 1
        name = 'qga-' + self.guest.slot + '-' + str(self.frames) + '.private'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.run['rootFd'])
        try:
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        metadata = json.dumps({'complete': complete, 'reason': reason, 'retainedBytes': len(raw), 'responseLimit': self.max_response_bytes, 'replayAllowed': False}, sort_keys=True).encode()
        fd = os.open(name[:-8] + '.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=self.run['rootFd'])
        try:
            offset = 0
            while offset < len(metadata):
                offset += os.write(fd, metadata[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)



# Actual archived reader helper/body, fixed prefix excluded; only inert payload literal substituted.
# Source attribution retained in source-provenance.json; corrected native8047 remains separate.
LEGACY = "FIELDS=('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')\nCUSTODIAN_SCRIPT='PUBLIC inert source body, no guest dispatch'\nREAD_CORRELATION='3eb54e37-da75-495c-8496-6baab85d41b6'\ndef need(ok, reason):\n    if not ok:\n        raise ValueError(reason)\n\ndef generation(info):\n    return [getattr(info, name) for name in FIELDS]\n\ndef file_hash(fd, maximum):\n    before = inventory.generation(os.fstat(fd))\n    need(stat.S_ISREG(before[2]) and before[5] == 1 and (0 < before[6] <= maximum), 'boot-file-shape')\n    os.lseek(fd, 0, os.SEEK_SET)\n    digest = hashlib.sha256()\n    count = 0\n    while count <= maximum:\n        raw = os.read(fd, min(1048576, maximum + 1 - count))\n        if not raw:\n            break\n        count += len(raw)\n        digest.update(raw)\n    need(count == before[6] and inventory.generation(os.fstat(fd)) == before, 'boot-file-generation')\n    return {'generation': before, 'sha256': digest.hexdigest()}\n\ndef read_record(path, limit):\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    try:\n        st = os.fstat(fd)\n        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (st.st_size <= limit), 'context-read-bound')\n        raw = os.read(fd, limit + 1)\n        need(len(raw) == st.st_size and generation(os.fstat(fd)) == generation(st) == generation(path.lstat()), 'context-read-closing')\n        return {'generation': generation(st), 'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode()}\n    finally:\n        os.close(fd)\nvalue = {'state': 'UNKNOWN', 'correlationId': READ_CORRELATION, 'originalCorrelationId': CORRELATION, 'installerAction': False, 'productAcceptance': False, 'replayAllowed': False}\nfd = None\noriginalFd = None\nterminalFd = None\ntry:\n    before = readonly_custody()\n    originalRoot = Path(PREPARED['template']).parent / ('secondary-base-stage-' + CORRELATION)\n    originalFd = os.open(originalRoot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    rootPin = generation(os.fstat(originalFd))\n    need(rootPin == generation(originalRoot.lstat()) and rootPin[3] == 0 and (stat.S_IMODE(rootPin[2]) == 448), 'base-original-journal')\n    records = {name: read_record(originalRoot / name, 16384) for name in ('custodian-intent.json', 'custodian-started.json', 'unknown.json')}\n    bodies = {name: json.loads(base64.b64decode(record['base64'])) for name, record in records.items()}\n    need(bodies['custodian-intent.json'] == {'scriptSha256': hashlib.sha256(CUSTODIAN_SCRIPT.encode()).hexdigest(), 'submitted': True, 'replayAllowed': False}, 'base-original-source-intent')\n    need(bodies['custodian-started.json'] == {'pid': 6060} and bodies['unknown.json'].get('originalCustodianPid') == 6060 and (bodies['unknown.json'].get('originalGuestFileHandle') is None) and (bodies['unknown.json'].get('transferred') == 0) and (bodies['unknown.json'].get('phase') == 'custodian-ready'), 'base-original-start-binding')\n    journal = Path(PREPARED['template']).parent / ('secondary-base-original-status-' + READ_CORRELATION)\n    journal.mkdir(mode=448)\n    fd = os.open(journal, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    guest = fixed_guest('secondary')\n    client = AccessClient(str(guest.root / 'vm-r-a85c4b4f/qga.sock'), timeout_seconds=15, max_response_bytes=1048576).bind({'rootFd': fd}, guest, ROW)\n    prepare.record_at(fd, 'original-status-intent.json', {'originalGuestPid': 6060, 'originalCorrelationId': CORRELATION, 'custodianSourceSha256': hashlib.sha256(CUSTODIAN_SCRIPT.encode()).hexdigest(), 'readOnly': True, 'replayAllowed': False})\n    need(readonly_custody()['descriptorRoles'] == before['descriptorRoles'], 'base-original-predispatch')\n    status = client.guest_exec_status(6060)\n    prepare.record_at(fd, 'original-status.json', status)\n    path = journal / 'original-status.json'\n    terminalFd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n    terminalPin = file_hash(terminalFd, 1048576)\n    need(terminalPin['generation'] == generation(path.lstat()), 'base-original-terminal-name')\n    need(type(status) is dict and type(status.get('exited')) is bool, 'base-original-status-schema')\n    value.update({'state': 'ORIGINAL_BASE_CUSTODIAN_OBSERVED', 'originalGuestPid': 6060, 'originalStatusReceipt': {'path': str(path), 'pin': terminalPin}, 'status': status, 'originalRecords': records})\n    need(generation(os.fstat(originalFd)) == rootPin == generation(originalRoot.lstat()), 'base-original-journal-closing')\n    for name, record in records.items():\n        need(read_record(originalRoot / name, 16384) == record, 'base-original-record-closing')\n    need(file_hash(terminalFd, 1048576) == terminalPin and generation(path.lstat()) == terminalPin['generation'], 'base-original-terminal-closing')\n    need(readonly_custody()['descriptorRoles'] == before['descriptorRoles'], 'base-original-custody-closing')\nexcept BaseException as error:\n    value.update({'errorType': type(error).__name__, 'errorDetail': str(error)[:256]})\n    cause = error.__cause__\n    if isinstance(cause, OSError):\n        value.update({'causeType': type(cause).__name__, 'causeErrno': cause.errno})\nfinally:\n    if terminalFd is not None:\n        try:\n            need(file_hash(terminalFd, 1048576) == terminalPin and generation(path.lstat()) == terminalPin['generation'], 'base-original-terminal-final')\n            value['originalTerminalCustodyClosed'] = True\n        except BaseException:\n            value = {'state': 'UNKNOWN', 'correlationId': READ_CORRELATION, 'originalCorrelationId': CORRELATION, 'reason': 'base-original-terminal-closing', 'installerAction': False, 'productAcceptance': False, 'replayAllowed': False}\n        finally:\n            os.close(terminalFd)\n    if originalFd is not None:\n        os.close(originalFd)\n    if fd is not None:\n        prepare.record_at(fd, 'result.json', value)\n        os.close(fd)\nraw = json.dumps(value, sort_keys=True).encode()\nneed(len(raw) <= 48000, 'base-original-result-bound')\nprint(raw.decode(), flush=True)\n"
CORRECTED = "FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')\nCUSTODIAN_SCRIPT = 'PUBLIC inert source body, no guest dispatch'\nREAD_CORRELATION = 'd7b0ee9a-77e0-4852-8cf6-2d167a17f602'\n\ndef need(ok, reason):\n    if not ok:\n        raise ValueError(reason)\n\ndef generation(info):\n    return [getattr(info, name) for name in FIELDS]\n\ndef file_hash(fd, maximum):\n    before = inventory.generation(os.fstat(fd))\n    need(stat.S_ISREG(before[2]) and before[5] == 1 and (0 < before[6] <= maximum), 'boot-file-shape')\n    os.lseek(fd, 0, os.SEEK_SET)\n    digest = hashlib.sha256()\n    count = 0\n    while count <= maximum:\n        raw = os.read(fd, min(1048576, maximum + 1 - count))\n        if not raw:\n            break\n        count += len(raw)\n        digest.update(raw)\n    need(count == before[6] and inventory.generation(os.fstat(fd)) == before, 'boot-file-generation')\n    return {'generation': before, 'sha256': digest.hexdigest()}\n\ndef read_record(path, limit):\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)\n    try:\n        st = os.fstat(fd)\n        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (st.st_size <= limit), 'context-read-bound')\n        raw = os.read(fd, limit + 1)\n        need(len(raw) == st.st_size and generation(os.fstat(fd)) == generation(st) == generation(path.lstat()), 'context-read-closing')\n        return {'generation': generation(st), 'sha256': hashlib.sha256(raw).hexdigest(), 'base64': base64.b64encode(raw).decode()}\n    finally:\n        os.close(fd)\nvalue = {'state': 'UNKNOWN', 'correlationId': READ_CORRELATION, 'originalCorrelationId': CORRELATION, 'installerAction': False, 'productAcceptance': False, 'replayAllowed': False}\nfd = None\noriginalFd = None\nterminalFd = None\ntry:\n    before = readonly_custody()\n    originalRoot = Path(PREPARED['template']).parent / ('secondary-base-stage-' + CORRELATION)\n    originalFd = os.open(originalRoot, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    rootPin = generation(os.fstat(originalFd))\n    need(rootPin == generation(originalRoot.lstat()) and rootPin[3] == 0 and (stat.S_IMODE(rootPin[2]) == 448), 'base-original-journal')\n    records = {name: read_record(originalRoot / name, 16384) for name in ('custodian-intent.json', 'custodian-started.json', 'unknown.json')}\n    bodies = {name: json.loads(base64.b64decode(record['base64'])) for name, record in records.items()}\n    need(bodies['custodian-intent.json'] == {'scriptSha256': hashlib.sha256(CUSTODIAN_SCRIPT.encode()).hexdigest(), 'submitted': True, 'replayAllowed': False}, 'base-original-source-intent')\n    need(bodies['custodian-started.json'] == {'pid': 6060} and bodies['unknown.json'].get('originalCustodianPid') == 6060 and (bodies['unknown.json'].get('originalGuestFileHandle') is None) and (bodies['unknown.json'].get('transferred') == 0) and (bodies['unknown.json'].get('phase') == 'custodian-ready'), 'base-original-start-binding')\n    journal = Path(PREPARED['template']).parent / ('secondary-base-original-status-' + READ_CORRELATION)\n    journal.mkdir(mode=448)\n    fd = os.open(journal, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    guest = fixed_guest('secondary')\n    client = AccessClient(str(guest.root / 'vm-r-a85c4b4f/qga.sock'), timeout_seconds=15, max_response_bytes=1048576).bind({'rootFd': fd}, guest, ROW)\n    prepare.record_at(fd, 'original-status-intent.json', {'originalGuestPid': 6060, 'originalCorrelationId': CORRELATION, 'custodianSourceSha256': hashlib.sha256(CUSTODIAN_SCRIPT.encode()).hexdigest(), 'readOnly': True, 'replayAllowed': False})\n    need(readonly_custody()['descriptorRoles'] == before['descriptorRoles'], 'base-original-predispatch')\n    status = client.guest_exec_status(6060)\n    prepare.record_at(fd, 'original-status.json', status)\n    path = journal / 'original-status.json'\n    terminalFd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n    terminalPin = file_hash(terminalFd, 1048576)\n    need(terminalPin['generation'] == generation(path.lstat()), 'base-original-terminal-name')\n    need(type(status) is dict and type(status.get('exited')) is bool, 'base-original-status-schema')\n    value.update({'state': 'ORIGINAL_BASE_CUSTODIAN_OBSERVED', 'originalGuestPid': 6060, 'originalStatusReceipt': {'path': str(path), 'pin': terminalPin}, 'status': status, 'originalRecords': records})\n    need(generation(os.fstat(originalFd)) == rootPin == generation(originalRoot.lstat()), 'base-original-journal-closing')\n    for name, record in records.items():\n        need(read_record(originalRoot / name, 16384) == record, 'base-original-record-closing')\n    need(file_hash(terminalFd, 1048576) == terminalPin and generation(path.lstat()) == terminalPin['generation'], 'base-original-terminal-closing')\n    need(readonly_custody()['descriptorRoles'] == before['descriptorRoles'], 'base-original-custody-closing')\nexcept BaseException as error:\n    demote_closed_observation(value, error)\nfinally:\n    if terminalFd is not None:\n        try:\n            need(file_hash(terminalFd, 1048576) == terminalPin and generation(path.lstat()) == terminalPin['generation'], 'base-original-terminal-final')\n            value['originalTerminalCustodyClosed'] = True\n        except BaseException:\n            value = {'state': 'UNKNOWN', 'correlationId': READ_CORRELATION, 'originalCorrelationId': CORRELATION, 'reason': 'base-original-terminal-closing', 'installerAction': False, 'productAcceptance': False, 'replayAllowed': False}\n        finally:\n            os.close(terminalFd)\n    if originalFd is not None:\n        os.close(originalFd)\n    if fd is not None:\n        prepare.record_at(fd, 'result.json', value)\n        os.close(fd)\nraw = json.dumps(value, sort_keys=True).encode()\nneed(len(raw) <= 48000, 'base-original-result-bound')\nprint(raw.decode(), flush=True)\n"



import json,os,socket,tempfile,threading,unittest
from pathlib import Path
from types import SimpleNamespace
from scripts import native_fixture_qga as qga
class LocalQga:
 def __init__(self,p):
  self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.bind(str(p));self.socket.listen();self.socket.settimeout(2);self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
 def run(self):
  try:
   for _ in range(2):
    conn,_=self.socket.accept()
    with conn:
     file=conn.makefile('rb');line=file.readline();sync=json.loads(line.lstrip(b'\xff'));conn.sendall(b'\xff'+json.dumps({'return':sync['arguments']['id']}).encode()+b'\n');line=file.readline()
     if line:conn.sendall(b'{"return":{"exited":false}}\n')
  except (OSError,ValueError):pass
 def close(self):self.thread.join(3);self.socket.close()
class CollisionTests(unittest.TestCase):
 def test_actual_two_clients_callback_collision_is_wrapped_as_connection_failed(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);server=LocalQga(root/'s');guest=SimpleNamespace(slot='secondary')
   try:
    writer=ActualCapture(str(root/'s')).bind({'rootFd':fd},guest,{});observer=ActualCapture(str(root/'s'),timeout_seconds=15).bind({'rootFd':fd},guest,{})
    self.assertEqual(writer.guest_exec_status(1),{'exited':False})
    with self.assertRaises(qga.QgaObservationUnknown)as caught:observer.guest_exec_status(2)
    self.assertEqual(caught.exception.reason,'connection failed');self.assertIsInstance(caught.exception.__cause__,FileExistsError);self.assertEqual(caught.exception.__cause__.errno,17)
    self.assertTrue((root/'qga-secondary-1.private').is_file());self.assertEqual(writer.frames,2);self.assertEqual(observer.frames,1)
   finally:server.close();os.close(fd)
 def test_same_actual_callbacks_shared_sequence_keeps_all_four_original_frames(self):
  Fixed=subject.shared_frame_client(ActualCapture)
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);server=LocalQga(root/'s');guest=SimpleNamespace(slot='secondary');run={'rootFd':fd}
   try:
    writer=Fixed(str(root/'s')).bind(run,guest,{});observer=Fixed(str(root/'s'),timeout_seconds=15).bind(run,guest,{})
    self.assertEqual(writer.guest_exec_status(1),{'exited':False});self.assertEqual(observer.guest_exec_status(2),{'exited':False});self.assertEqual(run['responseFrameSequence'],4)
    self.assertEqual(sorted(x.name for x in root.iterdir()if x.suffix=='.private'),['qga-secondary-'+str(i)+'.private'for i in range(1,5)])
    for i in range(1,5):self.assertTrue(json.loads((root/('qga-secondary-'+str(i)+'.json')).read_bytes())['complete'])
   finally:server.close();os.close(fd)
 def test_shared_sequence_invalid_or_exhausted_refuses_before_any_journal_write(self):
  Fixed=subject.shared_frame_client(ActualCapture)
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
   try:
    for bad in [True,-1,40001]:
     with self.assertRaises(ValueError):Fixed(str(root/'s')).bind({'rootFd':fd,'responseFrameSequence':bad},SimpleNamespace(slot='secondary'),{})
    run={'rootFd':fd,'responseFrameSequence':40000};client=Fixed(str(root/'s')).bind(run,SimpleNamespace(slot='secondary'),{})
    with self.assertRaises(ValueError):client._retain_response(b'PUBLIC',True,'complete')
    self.assertEqual(list(root.iterdir()),[])
   finally:os.close(fd)




import ast,base64,hashlib,io,json,os,stat,tempfile,unittest,contextlib
from pathlib import Path
from types import SimpleNamespace
from agent_tools import windows_parallel_vm_source_inventory as inventory,windows_parallel_vm_prepare as prepare
CORR='4ac1cdea-5a25-4ad6-8a66-41f1c8a92e8b'
class WholeEntryTests(unittest.TestCase):
 def run_body(self,source,drift):
  tree=ast.parse(source);boundary=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='value'for t in n.targets));functions=[n for n in tree.body[:boundary]if isinstance(n,ast.FunctionDef)and n.name in ('need','generation','file_hash','read_record')];constants={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body[:boundary]if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in ('CUSTODIAN_SCRIPT','READ_CORRELATION','FIELDS')}
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);original=root/('secondary-base-stage-'+CORR);original.mkdir(mode=0o700)
   for name,value in [('custodian-intent.json',{'scriptSha256':hashlib.sha256(constants['CUSTODIAN_SCRIPT'].encode()).hexdigest(),'submitted':True,'replayAllowed':False}),('custodian-started.json',{'pid':6060}),('unknown.json',{'originalCustodianPid':6060,'originalGuestFileHandle':None,'transferred':0,'phase':'custodian-ready'})]:
    (original/name).write_text(json.dumps(value));(original/name).chmod(0o600)
   calls=[];custody={'descriptorRoles':{'exact':'PUBLIC'}}
   class Client:
    def __init__(self,*args,**kwargs):pass
    def bind(self,*args):return self
    def guest_exec_status(self,pid):
     calls.append(pid)
     if drift=='record':(original/'unknown.json').write_text('{}')
     if drift=='root':original.rename(root/'exchanged-original');original.mkdir(mode=0o700)
     if drift=='custody':custody['descriptorRoles']={'foreign':'PUBLIC'}
     return {'exited':True,'exitcode':1,'err-data':base64.b64encode(b'PUBLIC original timeout').decode()}
   ns={'os':os,'Path':Path,'stat':stat,'base64':base64,'hashlib':hashlib,'json':json,'inventory':inventory,'prepare':prepare,'CORRELATION':CORR,'PREPARED':{'template':str(root/'template')},'AccessClient':Client,'fixed_guest':lambda x:SimpleNamespace(root=root),'ROW':{},'demote_closed_observation':subject.demote_closed_observation,'readonly_custody':lambda:json.loads(json.dumps(custody)),**constants}
   exec(compile(ast.Module(body=functions,type_ignores=[]),'actual helpers','exec'),ns)
   # Native owner UID is the sole filesystem admission seam; all other generation fields/readbacks are real.
   originalGeneration=ns['generation'];identity=(original.stat().st_dev,original.stat().st_ino)
   def generation(info):
    result=originalGeneration(info)
    if(info.st_dev,info.st_ino)==identity:result[3]=0
    return result
   ns['generation']=generation
   out=io.StringIO()
   with contextlib.redirect_stdout(out):exec(compile(ast.Module(body=tree.body[boundary:],type_ignores=[]),'actual emitted whole reader','exec'),ns)
   value=json.loads(out.getvalue());assert (root/('secondary-base-original-status-'+constants['READ_CORRELATION'])).exists(),value;published=json.loads((root/('secondary-base-original-status-'+constants['READ_CORRELATION'])/'result.json').read_bytes());self.assertEqual(value,published);self.assertEqual(calls,[6060]);return value
 def test_actual_original_same_inode_record_drift_red_keeps_stale_observed(self):
  value=self.run_body(LEGACY,'record');self.assertEqual(value['state'],'ORIGINAL_BASE_CUSTODIAN_OBSERVED');self.assertIn('originalRecords',value);self.assertEqual(value['errorDetail'],'base-original-record-closing')
 def test_corrected_whole_entry_closing_refusals_demote_without_status_replay(self):
  source=CORRECTED
  for drift in ['record','root','custody']:
   with self.subTest(drift=drift):
    value=self.run_body(source,drift);self.assertEqual(value['state'],'UNKNOWN');self.assertNotIn('originalRecords',value);self.assertIn('status',value);self.assertIs(value['originalTerminalCustodyClosed'],True);self.assertIs(value['replayAllowed'],False)
 def test_unchanged_records_and_closing_accept_actual_one_status_diagnostic(self):
  value=self.run_body(LEGACY,None);self.assertEqual(value['state'],'ORIGINAL_BASE_CUSTODIAN_OBSERVED');self.assertIs(value['originalTerminalCustodyClosed'],True)




import base64,json,os,shutil,subprocess,unittest
POWERSHELL=shutil.which('powershell.exe') if os.name=='nt' else None
class NativeWin32ClassificationTests(unittest.TestCase):
 @unittest.skipUnless(POWERSHELL,'actual Windows Win32Exception and PowerShell wrapper required')
 def test_actual_hresult_red_typed_native_code_green(self):
  source="$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);"+subject.NATIVE_ERROR_FAMILY_CONTROL+"\n[Console]::Out.WriteLine(($nativeErrorControl|ConvertTo-Json -Compress))"
  r=subprocess.run([POWERSHELL,'-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(source.encode('utf-16le')).decode()],capture_output=True,timeout=15)
  self.assertEqual(r.returncode,0,r.stderr)
  v=json.loads(r.stdout.decode('utf-8-sig'));self.assertEqual(v['ioNativeErrorCode'],32);self.assertIs(v['boundedDepthRefused'],True);self.assertIs(v['oldWrappedIOPolicyRejected'],True);self.assertNotEqual(v['oldHresultMasked'],5);self.assertEqual(v['nativeErrorCode'],5)
  for name in ('oldPolicyRejected','wrongCodeRejected','foreignTypeRefused'):self.assertIs(v[name],True)



class NativeRecordCreationTests(unittest.TestCase):
    @unittest.skipUnless(POWERSHELL, 'Windows creation-time FileSecurity API required; exact SYSTEM owner role separately proven in disposable guest')
    def test_actual_default_inheritance_red_protected_constructor_green(self):
        # Exercise the actual seven-argument producer constructor. CI uses its own
        # SID as owner; this proves creation-time ACL behavior, not SYSTEM authority.
        constructor = re.search(r"\$stream=(\[IO.FileStream\]::new\([^\n]+\))", subject.SYSTEM_RECORD_PUBLISHER).group(1)
        source = r"""
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Join-Path ([IO.Path]::GetTempPath()) ('vpn-record-causal-'+[Guid]::NewGuid().ToString())
[void][IO.Directory]::CreateDirectory($root)
try{
 $parent=[Security.AccessControl.DirectorySecurity]::new()
 $parent.SetSecurityDescriptorSddlForm(('O:'+ $sid +'D:P(A;OICI;FA;;;'+$sid+')'))
 [IO.Directory]::SetAccessControl($root,$parent)
 $oldPath=Join-Path $root 'old-public.json'
 $old=[IO.FileStream]::new($oldPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
 try{$old.WriteByte(80);$old.Flush($true)}finally{$old.Dispose()}
 $oldAcl=[IO.File]::GetAccessControl($oldPath)
 if($oldAcl.AreAccessRulesProtected){throw 'OLD_DEFAULT_EXPECTED_INHERITANCE'}
 $path=Join-Path $root 'fixed-public.json'
 $security=[Security.AccessControl.FileSecurity]::new()
 $security.SetSecurityDescriptorSddlForm(('O:'+ $sid +'D:P(A;;FA;;;'+$sid+')'))
 $stream=CONSTRUCTOR
 try{$stream.WriteByte(80);$stream.Flush($true)}finally{$stream.Dispose()}
 $acl=[IO.File]::GetAccessControl($path)
 if(-not $acl.AreAccessRulesProtected -or $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne $sid -or @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object {$_.IsInherited}).Count -ne 0){throw 'FIXED_CREATION_ACL'}
 $duplicateRefused=$false;try{$stream=CONSTRUCTOR;$stream.Dispose()}catch{if(($_.Exception.InnerException -isnot [IO.IOException])){throw};$duplicateRefused=$true}
 if(-not $duplicateRefused){throw 'FIXED_CREATE_NEW'}
 [Console]::Out.WriteLine('creation-acl-green')
}finally{[IO.Directory]::Delete($root,$true)}
""".replace('CONSTRUCTOR', constructor)
        result = subprocess.run([POWERSHELL, '-NoProfile', '-NonInteractive', '-EncodedCommand', base64.b64encode(source.encode('utf-16le')).decode()], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        self.assertEqual(result.stdout.decode('utf-8-sig').strip(), 'creation-acl-green')


# Exact historical consumer source; public identities only, no guest execution.
import ast,contextlib,hashlib,io,socket,sys,tempfile,threading,types
from pathlib import Path
CLEANUP_FIXTURES = Path(__file__).parent / 'fixtures/windows_secondary_cleanup'
CLEANUP_PROVENANCE_SHA256 = '3eb5efdca7385e8980d6aa9d20d315d468237ca32357e0d4fdb45c713f47eaff'
def cleanup_fixture(name):
 raw_manifest=(CLEANUP_FIXTURES/'provenance.json').read_bytes()
 if hashlib.sha256(raw_manifest).hexdigest()!=CLEANUP_PROVENANCE_SHA256:raise ValueError('cleanup-fixture-provenance')
 expected=json.loads(raw_manifest)['files'][name];raw=(CLEANUP_FIXTURES/name).read_bytes()
 if len(raw)!=expected['bytes']or hashlib.sha256(raw).hexdigest()!=expected['sha256']:raise ValueError('cleanup-fixture-source')
 return raw.decode('utf-8')
def cleanup_namespace():
 module=types.ModuleType('secondary_cleanup_harmless_fixture');sys.modules[module.__name__]=module;ns=module.__dict__
 exec(compile(cleanup_fixture('sdk_consumer.source'),'actual-sdk-source','exec'),ns)
 exec(compile(cleanup_fixture('decision_consumer.source'),'actual-decision-source','exec'),ns)
 ns.update(shared_frame_client=subject.shared_frame_client,demote_closed_observation=subject.demote_closed_observation,cleanup_custody_identity=subject.cleanup_custody_identity,publish_cleanup_observation=subject.publish_cleanup_observation,CLEANUP_SCRIPT='# PUBLIC inert native effect interception',ORIGINAL_SCRIPT_SHA='a'*64,CORRELATION='4ac1cdea-5a25-4ad6-8a66-41f1c8a92e8b',ROW={})
 ns['ORIGINAL_TERMINAL_PROOF']={'originalTerminalExited':True,'originalTerminalExitCode':1,'originalCustodianPid':6060,'originalCustodianBirthTicks':639268668935834031,'originalGuestFileHandle':None,'transferred':0}
 ns['CLEANUP_BINDING']={'rootNativeId':'PUBLIC-root','members':[{'name':name,'nativeId':'PUBLIC-'+str(i)}for i,name in enumerate(ns['MEMBERS'])]}
 return ns
@unittest.skipIf(os.name == 'nt', 'QGA transport requires Unix sockets; Windows runs native reader lifetime instead')
class CleanupWholeEntryTests(unittest.TestCase):
 def exercise(self,old=False,drift=None,repair=0,resource_change=False,previous=False,custody_drift=False,publication_drift=False,publication_legacy=False,publication_parent_drift=False,publication_record_drift=False):
  selected='legacy_interfaces.source' if old else 'legacy_publication.source' if publication_legacy else 'legacy_resources.source' if previous else 'current_publication.source'
  ns=cleanup_namespace()
  with tempfile.TemporaryDirectory(prefix='cs-',dir='/tmp')as d:
   root=Path(d).resolve();guest=root/'g';(guest/'vm-r-a85c4b4f').mkdir(parents=True)
   ns['inventory'].DESTINATIONS=(str(guest),str(root/'foreign'))
   ns['PREPARED']={'template':str(root/'template.qcow2')};ns['READ_CORRELATION']='public-test'
   observations=[]
   def custody():
    observations.append(1)
    return {'qemuPid':124 if custody_drift and len(observations)>1 else 123,'qemuStartTicks':45,'parentPid':12,'parentStartTicks':34,'descriptorRoles':[],'protectedPeerPids':[456],'memoryAvailableKiB':500000+len(observations) if resource_change else 500000,'diskAvailableBytes':999999999+len(observations) if resource_change else 999999999}
   ns['readonly_custody']=custody
   gen=ns['generation'];ns['generation']=lambda st:[*gen(st)[:3],0,gen(st)[4],2 if __import__('stat').S_ISDIR(st.st_mode) else gen(st)[5],*gen(st)[6:]];ns['inventory'].generation=ns['generation']
   # macOS has no Linux SO_PEERCRED; ONLY native peer check is bypassed.
   ns['AccessClient']._synchronize=ns['QgaReadOnlyClient']._synchronize
   original=root/('secondary-base-stage-'+ns['CORRELATION']);original.mkdir(mode=0o700)
   bodies={'custodian-intent.json':{'scriptSha256':ns['ORIGINAL_SCRIPT_SHA'],'submitted':True,'replayAllowed':False},'custodian-started.json':{'pid':6060},'unknown.json':{'originalCustodianPid':6060,'originalGuestFileHandle':None,'transferred':0}}
   for name,body in bodies.items(): (original/name).write_text(json.dumps(body));(original/name).chmod(0o600)
   server=socket.socket(socket.AF_UNIX);server.bind(str(guest/'vm-r-a85c4b4f/qga.sock'));server.listen();server.settimeout(.5)
   events=[];errors=[];stop=threading.Event();held_effect=[];terminal_names=[]
   def serve():
    try:
     while not stop.is_set():
      try:c,_=server.accept()
      except socket.timeout:continue
      with c:
       f=c.makefile('rb');sync=json.loads(f.readline().lstrip(b'\xff'));c.sendall(b'\xff'+json.dumps({'return':sync['arguments']['id']}).encode()+b'\n')
       req=json.loads(f.readline());cmd=req['execute'];events.append(cmd)
       if cmd=='guest-exec':
        pid=100+events.count('guest-exec');effect='$performDelete=$true' in req['arguments']['arg'][-1]
        if effect:
         journal=root/'secondary-base-cleanup-public-test';p=journal/'preflight-terminal.json';terminal_names.append(str(p))
         live=[]
         for fd in range(3,256):
          try:
           if os.fstat(fd).st_ino==p.stat().st_ino:live.append(fd)
          except OSError:pass
         held_effect.extend(live)
         if drift=='swap':p.rename(p.with_suffix('.original'));p.write_bytes(b'foreign terminal')
         elif drift:p.write_bytes(b'foreign terminal')
        result={'pid':pid}
       else:
        pid=req['arguments']['pid'];effect=pid==102;b=ns['CLEANUP_BINDING']
        payload={'pid':pid,'birthTicks':123,'originalCorrelationId':ns['CORRELATION'],'installerAction':False,'productAcceptance':False,'replayAllowed':False}
        if effect:payload.update(state='ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED',rootAbsent=True,effects=[{'name':m['name'],'nativeId':m['nativeId'],'markedOriginalHandle':True}for m in b['members']]+[{'name':'original-root','nativeId':b['rootNativeId'],'markedOriginalHandle':True}])
        else:payload.update(state='ORIGINAL_BASE_PARTIAL_CLEANUP_ADMITTED',rootNativeId=b['rootNativeId'],memberNames=ns['MEMBERS'],originalCustodianAbsent=True,allMemberIdentityHashAclClosing=True,cleanupPerformed=False,deleteEffects=[])
        result={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(payload).encode()).decode(),'err-data':''}
       c.sendall(json.dumps({'return':result}).encode()+b'\n')
    except BaseException as e:errors.append(e)
   thread=threading.Thread(target=serve);thread.start()
   original_record_at=ns['prepare'].record_at;publication_fds=[];durable=[]
   def record_at(directory_fd,name,value):
    if name=='result.json':
     path=root/'secondary-base-cleanup-public-test/preflight-terminal.json'
     if path.exists():
      for n in range(3,256):
       try:
        if os.fstat(n).st_ino==path.stat().st_ino:publication_fds.append(n)
       except OSError:pass
      if publication_drift:path.write_bytes(b'foreign same inode at result publication')
      if publication_parent_drift:root.chmod(0o750)
      if publication_record_drift:(original/'unknown.json').write_bytes(b'foreign original record at result publication')
    original_record_at(directory_fd,name,value)
    if name.startswith('result'):
     current=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
     try:durable.append(json.loads(os.read(current,1048576)))
     finally:os.close(current)
   ns['prepare'].record_at=record_at
   s=cleanup_fixture(selected)
   # Legacy staged REDs isolate every measured interface without effects.
   if repair>=1:s=s.replace('fixed_guest(ROW)',"fixed_guest('secondary')").replace("original=guest.root/('secondary-base-stage-'+CORRELATION)","original=Path(PREPARED['template']).parent/('secondary-base-stage-'+CORRELATION)")
   if repair>=2:s=s.replace('for name in FIELDS',"for name in ('custodian-intent.json','custodian-started.json','unknown.json')")
   if repair>=3:s=s.replace("root=guest.root/('secondary-base-cleanup-'+READ_CORRELATION)","root=Path(PREPARED['template']).parent/('secondary-base-cleanup-'+READ_CORRELATION)").replace("SharedAccess(ROW['qga'],","SharedAccess(str(guest.root/'vm-r-a85c4b4f/qga.sock'),")
   try:
    with contextlib.redirect_stdout(io.StringIO()):exec(compile(s,'actual-complete-entry','exec'),ns)
   finally:stop.set();thread.join(2);server.close()
   self.assertFalse(errors,errors);self.assertFalse(thread.is_alive())
   for fd in held_effect:
    with self.assertRaises(OSError):os.fstat(fd)
   self.publication_fds=publication_fds;self.durable=durable
   for n in publication_fds:
    with self.assertRaises(OSError):os.fstat(n)
   return ns['value'],events,held_effect
 def test_actual_publication_parent_identity_drift_refuses(self):
  value,events,_=self.exercise(publication_parent_drift=True);self.assertEqual(value['state'],'UNKNOWN');self.assertIn('parent-closing',value['errorDetail']);self.assertFalse(value['originalTerminalCustodyClosed']);self.assertEqual(self.durable[-1]['state'],'UNKNOWN');self.assertEqual(len(value['effects']),4)
 def test_actual_original_record_publication_drift_refuses(self):
  value,events,_=self.exercise(publication_record_drift=True);self.assertEqual(value['state'],'UNKNOWN');self.assertIn('original-record-closing',value['errorDetail']);self.assertFalse(value['originalTerminalCustodyClosed']);self.assertEqual(self.durable[-1]['state'],'UNKNOWN');self.assertEqual(len(value['effects']),4)
 def test_actual_publication_boundary_red_before_fix_green_unknown_after(self):
  value,events,_=self.exercise(publication_legacy=True,publication_drift=True);self.assertEqual(value['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED');self.assertTrue(value['originalTerminalCustodyClosed']);self.assertFalse(self.publication_fds);self.assertEqual(self.durable[0]['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED')
  value,events,_=self.exercise(publication_drift=True);self.assertEqual(value['state'],'UNKNOWN');self.assertFalse(value['originalTerminalCustodyClosed']);self.assertTrue(self.publication_fds);self.assertEqual([x['state']for x in self.durable],['UNKNOWN','UNKNOWN']);self.assertEqual(len(value['effects']),4);self.assertEqual(events.count('guest-exec'),2)
 def test_success_publication_snapshot_pending_final_capture_closed(self):
  value,events,_=self.exercise();self.assertEqual(value['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED');self.assertTrue(value['originalTerminalCustodyClosed']);self.assertFalse(value['publicationPending']);self.assertTrue(self.publication_fds);self.assertEqual(self.durable[0]['state'],'UNKNOWN');self.assertTrue(self.durable[0]['publicationPending']);self.assertFalse(self.durable[0]['originalTerminalCustodyClosed'])
 def test_actual_changed_custody_identity_refuses_before_guest(self):
  value,events,_=self.exercise(custody_drift=True);self.assertEqual(value['state'],'UNKNOWN');self.assertIn('current-custody',value['errorDetail']);self.assertEqual(events,[])
 def test_actual_dynamic_resource_dto_red_then_stable_projection_green(self):
  value,events,_=self.exercise(previous=True,resource_change=True);self.assertEqual(value['state'],'UNKNOWN');self.assertIn('current-custody',value['errorDetail']);self.assertEqual(events,[])
  value,events,_=self.exercise(resource_change=True);self.assertEqual(value['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED');self.assertEqual(events.count('guest-exec'),2)
 def test_legacy_interfaces_red(self):
  rows=[]
  for repair,reason in [(0,'guest-slot'),(1,'st_dev'),(2,'qga')]:
   value,events,_=self.exercise(old=True,repair=repair);self.assertEqual(value['state'],'UNKNOWN');self.assertIn(reason,value['errorDetail']);self.assertEqual(events,[]);rows.append({'repair':repair,'reason':reason,'requests':events})
  self.assertEqual([row['reason']for row in rows],['guest-slot','st_dev','qga'])
 def test_legacy_descriptor_boundary_red(self):
  value,events,held=self.exercise(old=True,repair=3);self.assertEqual(value['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED');self.assertFalse(held);self.assertEqual(events.count('guest-exec'),2)
 def test_complete_named_terminal_swap_refuses(self):
  value,events,_=self.exercise(drift='swap');self.assertEqual(value['state'],'UNKNOWN');self.assertIn('terminal-closing',value['errorDetail']);self.assertEqual(events.count('guest-exec'),2)
 def test_complete_socket_entry_and_lifetime_green(self):
  value,events,held=self.exercise();self.assertEqual(value['state'],'ORIGINAL_BASE_PARTIAL_CLEANUP_OBSERVED');self.assertEqual(events,['guest-exec','guest-exec-status']*2);self.assertTrue(held)
 def test_complete_closing_terminal_drift_refuses(self):
  value,events,_=self.exercise(drift=True);self.assertEqual(value['state'],'UNKNOWN');self.assertIn('terminal-closing',value['errorDetail']);self.assertEqual(events.count('guest-exec'),2)

def cleanup_reader_lifetime_powershell():
 old=cleanup_fixture('legacy_file_binding.ps1');new=cleanup_fixture('current_file_binding.ps1')
 cs=cleanup_fixture('delete_native.cs');helpers=cleanup_fixture('reader_handles.ps1')
 a=old.replace('function Close-FileBinding','function Legacy-CloseFileBinding');b=new
 return "$ErrorActionPreference='Stop'\nAdd-Type -TypeDefinition @'\n"+cs+"\n'@\n"+r'''
Add-Type -TypeDefinition 'public static class TertiaryPrivateStage {public static string Pin(Microsoft.Win32.SafeHandles.SafeFileHandle h,bool d){if(h.IsClosed||h.IsInvalid)throw new System.Exception("PUBLIC_HANDLE_CLOSED");return "PUBLIC";}}'
function Assert-RecordedAcl([string]$path,$expected) {}
'''+helpers+a+b+r'''
$root=Join-Path ([IO.Path]::GetTempPath()) ('SecondaryPublicLifetime-'+[guid]::NewGuid().ToString())
[void][IO.Directory]::CreateDirectory($root);$path=Join-Path $root 'PUBLIC';[IO.File]::WriteAllText($path,'PUBLIC')
$info=Get-Item -LiteralPath $path;$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
$expected=[ordered]@{nativeId='PUBLIC';length=$info.Length;sha256=$hash;creationTicks=$info.CreationTimeUtc.Ticks;writeTicks=$info.LastWriteTimeUtc.Ticks;acl=$null}
$h=$null;$stream=$null;$named=$null
try{
 $h=Open-OriginalDelete $path $false 'PUBLIC'
 $legacy=[ordered]@{path=$path;handle=$h;expected=$expected}
 # Capture actual named reader's real SafeFileHandle from old function.
 $originalReader=(Get-Command Open-NamedReader).ScriptBlock
 function Open-NamedReader([string]$path,[bool]$directory,[string]$nativeId){$script:lastNamed=. $originalReader $path $directory $nativeId;return $script:lastNamed}
 Legacy-CloseFileBinding $legacy
 if(-not $script:lastNamed.IsClosed){throw 'PUBLIC_OLD_READER_NOT_CLOSED'}
 $named=Open-NamedReader $path $false 'PUBLIC';$stream=[IO.FileStream]::new($named,[IO.FileAccess]::Read)
 $entry=[ordered]@{path=$path;handle=$h;expected=$expected;named=$named;stream=$stream}
 Close-FileBinding $entry
 if($named.IsClosed -or -not $stream.CanRead){throw 'PUBLIC_READER_LOST_BEFORE_EFFECT'}
 $writeDenied=$false;try{[IO.File]::WriteAllText($path,'foreign')}catch{$e=$_.Exception;for($i=0;$i -lt 4 -and $e;$i++){if($e -is [IO.IOException] -and ($e.HResult -band 65535) -eq 32){$writeDenied=$true;break};$e=$e.InnerException};if(-not $writeDenied){throw}}
 if(-not $writeDenied){throw 'PUBLIC_FOREIGN_WRITE_ALLOWED'}
 [StaleLockNative]::MarkDelete($h)
 if($named.IsClosed -or -not $stream.CanRead){throw 'PUBLIC_READER_LOST_AT_MARKDELETE'}
 $stream.Dispose();$stream=$null;$h.Dispose();$h=$null
 if([IO.File]::Exists($path)){throw 'PUBLIC_DELETE_POSTCONDITION'}
 [Console]::Out.WriteLine('PUBLIC_LIFETIME_RED_GREEN')
}finally{if($stream){$stream.Dispose()}elseif($named){$named.Dispose()};if($h){$h.Dispose()};if([IO.File]::Exists($path)){[IO.File]::Delete($path)};[IO.Directory]::Delete($root)}
'''

class NativeCleanupReaderLifetimeTests(unittest.TestCase):
 @unittest.skipUnless(POWERSHELL, 'native Windows PowerShell 5.1/Win32 sharing required')
 def test_actual_old_reader_closed_fixed_reader_survives_markdelete(self):
  result=subprocess.run([POWERSHELL,'-NoLogo','-NoProfile','-NonInteractive','-Command',cleanup_reader_lifetime_powershell()],capture_output=True,text=True,timeout=30)
  self.assertEqual(result.returncode,0,result.stderr)
  self.assertIn('PUBLIC_LIFETIME_RED_GREEN',result.stdout)


# Actual complete tracked admission consumer with retained historical guard AST.
import copy
def run_typed_admission_actual(legacy=False,pid=42,exitcode=0,flags=None):
 source=subject.readonly_admission_consumer('f2eed851-9388-4a67-823a-9ccb57d4d9aa','a'*64,'31d63e766b886b945023fee42bf05f2a3e726a643edd6d40170cca8993f2ea2c',['-NoProfile','PUBLIC inert body'])
 tree=ast.parse(source)
 if legacy:
  guards={node.value.args[1].value:node for node in ast.parse(cleanup_fixture('legacy_admission_guards.source')).body}
  class HistoricalGuard(ast.NodeTransformer):
   def visit_Expr(self,node):
    if isinstance(node.value,ast.Call)and isinstance(node.value.func,ast.Name)and node.value.func.id=='need'and len(node.value.args)>1 and isinstance(node.value.args[1],ast.Constant)and node.value.args[1].value in guards:
     return guards[node.value.args[1].value]
    return self.generic_visit(node)
  tree=ast.fix_missing_locations(HistoricalGuard().visit(tree))
 module=types.ModuleType('actual_typed_routine_'+os.urandom(4).hex());module.__file__='tracked-readonly-admission';sys.modules[module.__name__]=module
 try:
  exec(compile(cleanup_fixture('sdk_consumer.source'),'actual-existing-sdk','exec'),module.__dict__)
  module.__dict__.update(re=re,shared_frame_client=subject.shared_frame_client,cleanup_custody_identity=subject.cleanup_custody_identity,demote_closed_observation=subject.demote_closed_observation,publish_cleanup_observation=subject.publish_cleanup_observation,validate_nt_account_regression=subject.validate_nt_account_regression,ROW={})
  body_sha=('d30b8d6365511ce6350e01d22b8ea290949eae746ca601ae1f3626c9abddadb5' if legacy else '31d63e766b886b945023fee42bf05f2a3e726a643edd6d40170cca8993f2ea2c');corr='f2eed851-9388-4a67-823a-9ccb57d4d9aa'
  identity={'state':'ORIGINAL_ACTOR_CENSUS_STARTED','pid':pid,'birthTicks':1,'correlationId':corr,'bodySha256':body_sha,'sourceValidated':False,'sid':'S-1-5-18'}
  actor={'correlationId':corr,'win32UserName':None,'bootUtc':'2026-10-05T23:28:49.1890040Z','explorers':[],'runtimeOffProven':False,'installerStarted':False,'productAcceptance':False,'replayAllowed':False}
  guarded=[{'label':label,'result':{'accepted':False,'constructorCalled':False,'reason':'INTERACTIVE_NAME_UNAVAILABLE'}}for label in ('null','empty','number')]+[{'label':'name','result':{'accepted':True,'constructorCalled':True,'value':'vpn-control-causal-probe'}}]
  cases={'correlationId':corr,'regression':{'oldNull':{'failed':True,'errorId':'CannotFindAppropriateCtor,PUBLIC'},'guarded':guarded}}
  processes={'correlationId':corr,'processCensusComplete':True,'processCount':1,'effectOwners':[],'runtimeOffProven':False,'installerStarted':False,'productAcceptance':False,'replayAllowed':False}
  raw='\n'.join(json.dumps(v)for v in (identity,actor,cases,processes)).encode();terminal={'exited':True,'exitcode':exitcode,'out-data':base64.b64encode(raw).decode(),'err-data':''};terminal.update(flags or {})
  supplied={'dispatch':0,'status':0}
  class SuppliedClient(module.AccessClient):
   def _exchange(self,command,spec):
    if command!='guest-exec':raise AssertionError('foreign command')
    supplied['dispatch']+=1
    if supplied['dispatch']!=1:raise AssertionError('replay')
    self._retain_response(b'PUBLIC_START',True,'complete');return {'pid':42}
   def guest_exec_status(self,original_pid):
    if type(original_pid)is not int or original_pid!=42:raise AssertionError('foreign PID')
    supplied['status']+=1
    if supplied['status']!=1:raise AssertionError('status replay')
    self._retain_response(b'PUBLIC_TERMINAL',True,'complete');return copy.deepcopy(terminal)
  module.AccessClient=SuppliedClient
  custody={'qemuPid':1,'qemuStartTicks':2,'parentPid':3,'parentStartTicks':4,'descriptorRoles':[],'protectedPeerPids':[]}
  module.readonly_custody=lambda:copy.deepcopy(custody)
  actual_parent=module.parent_identity
  # Local fixture is unprivileged; only native SYSTEM identity is supplied.
  module.parent_identity=lambda s:actual_parent(s)[:3]+[0,0]
  with tempfile.TemporaryDirectory()as temp:
   module.PREPARED={'template':str(Path(temp)/'PUBLIC_TEMPLATE')};module.inventory.DESTINATIONS=(temp,temp);out=io.StringIO()
   with contextlib.redirect_stdout(out):exec(compile(tree,'actual-tracked-consumer','exec'),module.__dict__)
   value=json.loads(out.getvalue());assert 'journalPath' in value, value; journal=Path(value['journalPath']);pending=json.loads((journal/'result.json').read_bytes());actual_terminal=json.loads((journal/'admission-terminal.json').read_bytes());assert actual_terminal==terminal and pending['state']=='UNKNOWN'and pending['originalTerminalCustodyClosed']is False;assert supplied=={'dispatch':1,'status':1};assert module.fd is not None
   try:os.fstat(module.fd)
   except OSError:pass
   else:raise AssertionError('journal leaked')
   return value
 finally:sys.modules.pop(module.__name__,None)
@unittest.skipIf(os.name == 'nt', 'actual retained QGA SDK uses Unix sockets; these supplied API cases run on Unix')
class TypedAdmissionWholeEntryTests(unittest.TestCase):
 def test_actual_tracked_consumer_matches_reviewed_parameterized_source(self):
  self.assertEqual(ast.dump(ast.parse(subject.READONLY_ADMISSION_CONSUMER)),ast.dump(ast.parse(cleanup_fixture('reviewed_admission_consumer.source'))))
  for args in (('', 'a'*64, 'b'*64, ['PUBLIC']), ('f2eed851-9388-4a67-823a-9ccb57d4d9aa', 'bad', 'b'*64, ['PUBLIC']), ('f2eed851-9388-4a67-823a-9ccb57d4d9aa','a'*64,'b'*64,[False])):
   with self.subTest(args=args),self.assertRaises(ValueError):subject.readonly_admission_consumer(*args)
 def test_actual_whole_legacy_malformed_green_fixed_unknown(self):
  malformed=[{'pid':42.0},{'exitcode':False},{'exitcode':0.0},{'flags':{'out-truncated':'false'}},{'flags':{'out-truncated':0}},{'flags':{'err-truncated':0.0}},{'flags':{'err-truncated':None}}]
  for payload in malformed:
   with self.subTest(payload=payload):
    self.assertEqual(run_typed_admission_actual(legacy=True,**payload)['state'],'CURRENT_READONLY_ADMISSION_OBSERVED');fixed=run_typed_admission_actual(**payload);self.assertEqual(fixed['state'],'UNKNOWN');self.assertNotIn('inspection',fixed)
 def test_actual_optional_absence_and_present_exact_false_green(self):
  for flags in (None,{'out-truncated':False,'err-truncated':False}):
   with self.subTest(flags=flags):self.assertEqual(run_typed_admission_actual(flags=flags)['state'],'CURRENT_READONLY_ADMISSION_OBSERVED')
 def test_actual_true_truncation_stays_unknown(self):
  for flag in ('out-truncated','err-truncated'):
   with self.subTest(flag=flag):self.assertEqual(run_typed_admission_actual(flags={flag:True})['state'],'UNKNOWN')
