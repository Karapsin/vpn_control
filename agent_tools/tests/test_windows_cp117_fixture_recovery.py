"""Deterministic recovery guards and the generated one-shot launch call graph."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import windows_cp117_fixture_recovery as r

class RecoveryTests(unittest.TestCase):
    def test_recipe_preserves_disk_chain_firmware_and_tpm(self):
        recipe=r.recipe();argv=recipe['qemuArgv']
        self.assertIn('file='+r.DISK+',if=none,id=disk,format=qcow2',argv)
        self.assertIn('if=pflash,format=raw,file='+r.VARS,argv)
        self.assertIn('dir='+r.TPM_STATE,recipe['tpmArgv'])
        self.assertIn('4096',argv);self.assertIn('4',argv)
        self.assertFalse(any('cdrom'in v or '.iso'in v or 'cp135-launch'in v for v in argv))
        self.assertNotIn(2316,(r.SSH_PORT,r.VNC_PORT));self.assertNotIn(5909,(r.SSH_PORT,r.VNC_PORT))
        self.assertEqual(r.BASELINE[r.DISK]['fingerprint']['st_ino'],103551218)
        self.assertEqual(r.BASELINE[r.BACKING]['fingerprint']['st_ino'],32677688)
        self.assertEqual(r.BASELINE[r.CODE]['fingerprint']['st_size']+r.BASELINE[r.VARS]['fingerprint']['st_size'],4*1024**2)

    def test_generated_all_modes_parse(self):
        request={'claim':{'reservedMemoryBytes':r.MEMORY_BYTES}}
        compile(r._observer(request['claim']),'<observer>','exec')
        compile(r._program(request),'<start>','exec')

    def test_missing_authority_has_no_side_effect(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();(root/'.runtime/parity-evidence').mkdir(parents=True)
            with mock.patch.object(r,'_claim',side_effect=r.RecoveryUnknown('claim-missing')),mock.patch.object(r,'_stream')as launch:
                result=r.start(root)
                self.assertEqual(result['state'],'unknown');launch.assert_not_called()
                self.assertFalse((root/'.runtime/parity-evidence'/result['evidenceLeaf']/'attempt.json').exists())
                with self.assertRaisesRegex(r.RecoveryUnknown,'attempt-consumed'):r.start(root)

    def _registry(self,root,**updates):
        directory=root/'.rag_index/native-environments';directory.mkdir(parents=True,mode=0o700)
        os.chmod(root/'.rag_index',0o700);(directory/'lock').write_bytes(b'');os.chmod(directory/'lock',0o600)
        record={'id':r.RESERVATION_ID,'token':'private-inert-token','hostAlias':r.HOST,'environment':r.ENVIRONMENT,'operator':r.OPERATOR,
                'requestedMemoryBytes':r.MEMORY_BYTES,'allocationState':'pending','activeJob':'absent',**updates}
        (directory/'reservations.json').write_text(json.dumps({'version':1,'reservations':[record]}));os.chmod(directory/'reservations.json',0o600)
        return directory

    def test_actual_registry_claim_and_accounting(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();self._registry(root)
            with r._claim(root)as(claim,verify):
                self.assertEqual(claim['reservedMemoryBytes'],r.MEMORY_BYTES);verify()
                self.assertNotIn('private-inert-token',json.dumps(claim))

    def test_claim_wrong_owner_active_unknown_and_memory_fail(self):
        for updates in ({'operator':'other'},{'activeJob':'unknown'},{'allocationState':'running'},{'requestedMemoryBytes':r.MEMORY_BYTES+1}):
            with self.subTest(updates=updates),tempfile.TemporaryDirectory()as temp:
                root=Path(temp).resolve();self._registry(root,**updates)
                with self.assertRaisesRegex(r.RecoveryUnknown,'claim-authority'):
                    with r._claim(root):pass

    def test_named_claim_lock_exchange_rejected(self):
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();directory=self._registry(root)
            with self.assertRaisesRegex(r.RecoveryUnknown,'claim-lock-drift'):
                with r._claim(root)as(_,verify):
                    (directory/'lock').rename(directory/'old-lock');(directory/'lock').write_bytes(b'');os.chmod(directory/'lock',0o600);verify()

    def test_claim_writer_excluded_and_busy_is_bounded(self):
        import fcntl
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();directory=self._registry(root)
            with r._claim(root):
                fd=os.open(directory/'lock',os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
            fd=os.open(directory/'lock',os.O_RDONLY)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    with r._claim(root):pass
            finally:os.close(fd)

    def test_stale_wrong_child_frame_is_rejected(self):
        request={'claim':{'reservedMemoryBytes':r.MEMORY_BYTES}}
        child={'pid':456,'startTicks':9,'argvSha256':r._digest(r.recipe()['tpmArgv']),'bootId':r.BOOT_ID}
        fingerprint={k:0 for k in r._FP_FIELDS};fingerprint.update(st_mode=stat.S_IFREG|0o600,st_uid=1000,st_nlink=1)
        pin={'fingerprint':fingerprint,'sha256':r._digest(child)};intentpin={'fingerprint':fingerprint,'sha256':r._digest(request)}
        frame={'kind':'child','requestSha256':r._digest(request),'correlationId':r.CORRELATION,
               'value':{'role':'tpm','child':child,'pin':pin,'intentPin':intentpin,'attemptPin':pin,'leafIdentity':{'st_dev':1,'st_ino':2,'st_mode':stat.S_IFDIR|0o700,'st_uid':1000,'st_gid':1000}}}
        r._validate_frame(frame,request,[])
        frame['value']['child']['bootId']='stale-boot'
        with self.assertRaisesRegex(r.RecoveryUnknown,'stream-child'):r._validate_frame(frame,request,[])
        frame['value']['child']=child;frame['requestSha256']='wrong-request'
        with self.assertRaisesRegex(r.RecoveryUnknown,'stream-request'):r._validate_frame(frame,request,[])

    def test_actual_start_callgraph_records_before_spawn(self):
        self._actual_start_callgraph()

    def test_directory_fsync_fences_before_daemon_spawn(self):
        self._actual_start_callgraph(require_directory_fsync=True)

    def _actual_start_callgraph(self,require_directory_fsync=False):
        """Execute real generated startup with only host/process transports inert.

        Before repair, ordinary intent creation changes leaf ctime/size and the
        full-directory guard blocks TPM. A same-identity private leaf must admit
        its own journal writes while rejecting foreign entries/replaced parents.
        """
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();guest=root/'guest';guest.mkdir(mode=0o700);leaf=guest/'recovery';events=[];frames=[]
            recipe=r.recipe();recipe['leaf']=str(leaf);recipe['files']={};request={'claim':{'reservedMemoryBytes':r.MEMORY_BYTES}}
            common=r._REMOTE_COMMON.replace('__RECIPE__',repr(recipe)).replace('__REQUEST__',repr(request))
            ns={};exec(common,ns)
            real_lstat=os.lstat;real_open=os.open;real_fsync=os.fsync;directory_syncs=[];fixed_guest='/home/kardinal/vpn-control-windows-msi-acceptance-cp117'
            def fsync(fd):
                info=os.fstat(fd)
                if stat.S_ISDIR(info.st_mode):directory_syncs.append(info.st_ino)
                return real_fsync(fd)
            def lstat(path,*args,**kwargs):return real_lstat(guest if str(path)==fixed_guest else path,*args,**kwargs)
            def osopen(path,*args,**kwargs):return real_open(guest if str(path)==fixed_guest else path,*args,**kwargs)
            def opened(path,*args,**kwargs):
                if path=='/proc/sys/kernel/random/boot_id':return io.StringIO(r.BOOT_ID)
                return open(path,*args,**kwargs)
            parent=r._fp(real_lstat(guest));proof={'state':'ready','recipeSha256':r._digest(recipe),'reservedMemoryBytes':r.MEMORY_BYTES,'parent':parent,'observedAtNs':__import__('time').time_ns()}
            fake_run=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout=json.dumps(proof).encode())
            def popen(argv,**kwargs):
                role='tpm'if argv==recipe['tpmArgv']else'qemu';events.append(role)
                self.assertTrue((leaf/'attempt.json').is_file());self.assertTrue((leaf/(role+'-attempt.json')).is_file())
                if require_directory_fsync:
                    self.assertIn(real_lstat(guest).st_ino,directory_syncs)
                    self.assertGreaterEqual(directory_syncs.count(real_lstat(leaf).st_ino),3 if role=='tpm' else 5)
                for name in(('swtpm.sock',)if role=='tpm'else('qmp.sock','qga.sock')):(leaf/name).touch()
                return types.SimpleNamespace(pid=456 if role=='tpm' else 789)
            ns.update({'identity':lambda pid,argv:{'pid':pid,'startTicks':1,'argvSha256':r._digest(argv),'bootId':r.BOOT_ID},
                       'child_guard':lambda *a:None,'socket_guard':lambda *a:{'fingerprint':{},'kernelInode':'1'},'file_guard':lambda *a:None,
                       'emit':lambda kind,value:frames.append((kind,value)),'result':lambda value:frames.append(('result',value)),'open':opened})
            start=r._REMOTE_START.replace('__OBSERVER__',repr('inert-readonly-observer'))
            # Stop immediately after exact QEMU spawn: no live process/file access.
            class StopAfterQemu(Exception):pass
            def stopping_popen(argv,**kwargs):
                result=popen(argv,**kwargs)
                if argv==recipe['qemuArgv']:raise StopAfterQemu()
                return result
            with mock.patch.object(ns['os'],'lstat',side_effect=lstat),mock.patch.object(ns['os'],'open',side_effect=osopen),mock.patch.object(ns['os'],'fsync',side_effect=fsync),mock.patch.object(ns['os'],'access',return_value=True),mock.patch.object(ns['subprocess'],'run',side_effect=fake_run),mock.patch.object(ns['subprocess'],'Popen',side_effect=stopping_popen),mock.patch.object(ns['sys'],'stdin',types.SimpleNamespace(buffer=io.BytesIO(b'inert\n'))):
                exec(start,ns)
            for name in('ROOT_FD','LEAF_FD','lock'):
                if ns.get(name)is not None:os.close(ns[name])
            self.assertEqual(events,['tpm','qemu'],frames)
            self.assertEqual(frames[0][0],'child');self.assertEqual(frames[0][1]['role'],'tpm')

    def test_fifo_and_coordinated_local_authority_rewrite_never_adopted(self):
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();path=root/'.runtime/parity-evidence/inert';path.mkdir(parents=True,mode=0o700)
            capture=AuthorityCapture(root,'inert')
            try:
                original=capture.create('authority.json',b'{"pid":456}')
                self.assertEqual(r._local_read(capture,'authority.json',original),b'{"pid":456}')
                (path/'authority.json').unlink();os.mkfifo(path/'authority.json',0o600)
                with self.assertRaises(ValueError):r._local_read(capture,'authority.json',original)
                (path/'authority.json').unlink();replacement=capture.create('authority.json',b'{"pid":999}')
                self.assertNotEqual(original,replacement)
                with self.assertRaisesRegex(r.RecoveryUnknown,'local-pin'):r._local_read(capture,'authority.json',original)
            finally:capture.close()

    def test_status_without_external_original_pin_cannot_submit(self):
        with tempfile.TemporaryDirectory()as temp,mock.patch.object(r.subprocess,'run')as submit:
            with self.assertRaisesRegex(r.RecoveryUnknown,'original-receipt-required'):r.status(temp,{})
            submit.assert_not_called()

    def test_stream_retains_original_frame_before_malformed_terminal(self):
        """A real inert local transport dies after an original authority frame.

        Captured frames remain on the thrown observation and in protected files;
        no second Popen/remote submit is attempted because terminal JSON is lost.
        """
        import sys
        from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
        request={'inert':True}
        child={'pid':456,'startTicks':1,'argvSha256':r._digest(r.recipe()['tpmArgv']),'bootId':r.BOOT_ID}
        fingerprint={k:0 for k in r._FP_FIELDS};fingerprint.update(st_mode=stat.S_IFREG|0o600,st_uid=1000,st_nlink=1)
        pin={'fingerprint':fingerprint,'sha256':r._digest(child)};intent={'fingerprint':fingerprint,'sha256':r._digest(request)}
        frame={'kind':'child','requestSha256':r._digest(request),'correlationId':r.CORRELATION,
               'value':{'role':'tpm','child':child,'pin':pin,'intentPin':intent,'attemptPin':pin,
                        'leafIdentity':{'st_dev':1,'st_ino':2,'st_mode':stat.S_IFDIR|0o700,'st_uid':1000,'st_gid':1000}}}
        source='import sys;sys.stdin.buffer.read();sys.stderr.write('+repr('RECOVERY '+json.dumps(frame)+'\n')+');sys.stderr.flush();sys.stdout.write("not-json")'
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();path=root/'.runtime/parity-evidence/inert';path.mkdir(parents=True,mode=0o700);capture=AuthorityCapture(root,'inert')
            real=r.subprocess.Popen
            try:
                with mock.patch.object(r.subprocess,'Popen',wraps=real)as submitted,mock.patch.object(r.os,'fsync',wraps=os.fsync)as flushed:
                    with self.assertRaises(json.JSONDecodeError)as caught:r._stream([sys.executable,'-c',source],b'inert\n',capture,request)
                    submitted.assert_called_once();self.assertEqual(caught.exception.frames[0]['frame'],frame)
                    self.assertIn(mock.call(capture.fd),flushed.call_args_list)
                self.assertTrue((path/'authority-0.json').is_file());self.assertTrue((path/'partial.stdout.private').is_file())
            finally:capture.close()

if __name__=='__main__':unittest.main()
