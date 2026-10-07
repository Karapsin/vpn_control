"""Inert generated privileged holder census; never SSH/sudo/install/build."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import ssh_tmux_privileged_staging_recovery as privileged
from agent_tools import ssh_tmux_source_staging_recovery as recovery
from agent_tools import ssh_tmux_session_ssh as old
from agent_tools import ssh_tmux_session as session


class RootCensusTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.job=self.root/recovery.OLD_CORRELATION;self.job.mkdir(mode=0o700)
        session.write_once(self.job/'stage-intent.json',session.canonical(old.purpose(recovery.OLD_REQUEST)))
        self.proc=self.root/'proc';self.proc.mkdir();self.entry=self.proc/'992';self.entry.mkdir()
        fields=['S']+['1']*18+['888']+['1']*3
        (self.entry/'stat').write_text('992 (inert) '+' '.join(fields))
        (self.entry/'status').write_bytes(b'Kthread:\t0\n')
        (self.entry/'cmdline').write_bytes(b'inert\0');(self.entry/'cwd').symlink_to(self.root)
        self.euid=1000
        self.native=os.readlink

    def program(self,source):
        value=source.replace(old.REMOTE_ROOT,str(self.root)).replace("pathlib.Path('/proc').iterdir()",f"pathlib.Path({str(self.proc)!r}).iterdir()")
        if source==privileged.ROOT_PROGRAM:
            # Inert test's own UID stands in for Arch's fixed UID1000; keep the
            # euid0 proof and all generated root scan operations unchanged.
            value=value.replace('i.st_uid!=1000','i.st_uid!='+str(os.getuid()))
        return value

    def readlink(self,path,*args,**kwargs):
        if Path(path)==self.entry/'cwd' and self.euid!=0:raise PermissionError(13,'nondumpable private process')
        return self.native(path,*args,**kwargs)

    def run_program(self,source):
        out=io.StringIO()
        with mock.patch('os.geteuid',side_effect=lambda:self.euid),mock.patch('os.readlink',side_effect=self.readlink),mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(session.canonical({'request':old.purpose(recovery.OLD_REQUEST)})))),contextlib.redirect_stdout(out):
            exec(compile(self.program(source),'<inert-fixed-root-read>','exec'),{})
        return json.loads(out.getvalue())

    def test_measured_nondumpable_permission_red_then_complete_root_read(self):
        with self.assertRaises(SystemExit) as err:self.run_program(recovery.PROOF)
        self.assertEqual(err.exception.code,36)
        self.euid=0;value=self.run_program(privileged.ROOT_PROGRAM)
        self.assertEqual(value['readAuthority'],{'effectiveUid':0,'filesystemUid':1000,'censusScope':'all-uids'})
        self.assertIs(value['proof']['noJobProcesses'],True);self.assertEqual(sorted(p.name for p in self.job.iterdir()),['stage-intent.json'])

    def test_root_requirement_missing_cwd_and_permission_still_refuse(self):
        with self.assertRaises(SystemExit):self.run_program(privileged.ROOT_PROGRAM)
        self.euid=0;(self.entry/'cwd').unlink()
        with self.assertRaises(FileNotFoundError):self.run_program(privileged.ROOT_PROGRAM)
        with mock.patch('os.readlink',side_effect=PermissionError(13,'denied')):
            # run_program installs its own readlink mock; explicit fixed exec
            # verifies root cannot make a permission gap disappear.
            with self.assertRaises(PermissionError),mock.patch('os.geteuid',return_value=0):exec(self.program(privileged.ROOT_PROGRAM),{})

    def test_pid_identity_and_cmdline_race_refuse(self):
        self.euid=0
        for mutation in ("(p/'stat').write_bytes(before.replace(b'888',b'999'))", "(p/'cmdline').write_bytes(b'changed')"):
            source=self.program(privileged.ROOT_PROGRAM).replace("   after_status=",'   '+mutation+'\n   after_status=')
            with self.assertRaises(SystemExit),mock.patch('os.geteuid',return_value=0):exec(source,{})
            (self.entry/'stat').write_text('992 (inert) '+' '.join(['S']+['1']*18+['888']+['1']*3));(self.entry/'cmdline').write_bytes(b'inert\0')

    def test_kernel_thread_authenticated_without_cwd_not_generic_skip(self):
        self.euid=0;(self.entry/'status').write_bytes(b'Kthread:\t1\n');(self.entry/'cmdline').write_bytes(b'');(self.entry/'cwd').unlink()
        self.run_program(privileged.ROOT_PROGRAM)
        (self.entry/'status').write_bytes(b'Kthread:\t0\n')
        with self.assertRaises(FileNotFoundError):self.run_program(privileged.ROOT_PROGRAM)
        (self.entry/'status').write_bytes(b'unknown\n')
        with self.assertRaises(SystemExit):self.run_program(privileged.ROOT_PROGRAM)

    def test_other_uid_holder_not_skipped(self):
        self.euid=0;(self.entry/'cmdline').write_bytes(b'git\0'+os.fsencode(self.job/'source')+b'\0')
        # The generated privileged scanner has no UID comparison or skip.
        self.assertNotIn('st_uid',privileged.ROOT_PROGRAM[privileged.ROOT_PROGRAM.index('def scan():'):privileged.ROOT_PROGRAM.index('def census():')])
        with self.assertRaises(SystemExit) as err:self.run_program(privileged.ROOT_PROGRAM)
        self.assertEqual(err.exception.code,37)

    def test_foreign_stage_writer_refused(self):
        self.euid=0;(self.job/'tmux-worker.py').write_bytes(b'foreign')
        with self.assertRaises(SystemExit):self.run_program(privileged.ROOT_PROGRAM)
        self.assertEqual((self.job/'tmux-worker.py').read_bytes(),b'foreign')

    def test_wrapper_fixed_source_stdin_only_and_no_secret_output(self):
        calls=[];fake=types.ModuleType('subprocess');fake.PIPE=-1;fake.DEVNULL=-3
        fake.TimeoutExpired=subprocess.TimeoutExpired
        def run(argv,**kwargs):
            calls.append((argv,kwargs));return types.SimpleNamespace(returncode=0,stdout=b'{"state":"inert"}')
        fake.run=run;out=io.StringIO()
        with mock.patch.dict('sys.modules',{'subprocess':fake}),mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(b'PRIVATE\n'))),contextlib.redirect_stdout(out):exec(privileged.WRAPPER,{})
        argv,kwargs=calls[0]
        self.assertEqual(argv[:7],['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I'])
        self.assertNotIn('PRIVATE',str(argv));self.assertEqual(kwargs['input'],b'PRIVATE\n');self.assertEqual(kwargs['stderr'],fake.DEVNULL)
        self.assertNotIn('PRIVATE',out.getvalue())
        with self.assertRaises(old.AdapterError):privileged.command('arbitrary')
        self.assertLess(len(privileged.command(privileged.WRAPPER)[-1]),30000)


if __name__=='__main__':unittest.main()

class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        index=self.root/'.rag_index';index.mkdir(mode=0o700)
        directory=self.root/recovery.build._JOURNAL;directory.mkdir(mode=0o700)
        self.job=directory/recovery.OLD_CORRELATION;self.job.mkdir(mode=0o700)
        self.claim=directory/'archlinux.claim'
        session.write_once(self.claim,session.canonical({'correlationId':recovery.OLD_CORRELATION,'host':'archlinux'}))
        self.claim_pin=session.read(self.claim)[1]
        self.before={'original':{'original':{'coordinator':{'records':{'claim':self.claim_pin}}}}}
        self.id='b851a47c-7a62-49c4-8ca4-d827ad181eef'
        self.proof_job=index/('tmux-privileged-staging-'+self.id);self.proof_job.mkdir(mode=0o700)
        self.remote={'readonly-root':'fixture'};self.cred={'file':'fixture'}
        intent={'correlationId':self.id,'local':self.before,'credentialPin':self.cred,'programSha256':hashlib.sha256(privileged.ROOT_PROGRAM.encode()).hexdigest(),'replayAllowed':False}
        intent_pin=session.write_once(self.proof_job/'intent.json',session.canonical(intent))
        saved={'correlationId':self.id,'local':self.before,'intentPin':intent_pin,'remote':self.remote,'rootProgramSha256':hashlib.sha256(privileged.ROOT_PROGRAM.encode()).hexdigest(),'oldOutcome':'unknown','replayAllowed':False}
        self.proof_pin=session.write_once(self.proof_job/'proof.json',session.canonical(saved))
        def local(root):
            old.need(session.read(self.claim)[1]==self.claim_pin,'claim_changed')
            return self.job,self.before
        patches=[mock.patch.object(privileged,'local_authority',side_effect=local),
                 mock.patch.object(privileged,'credential',return_value=(b'private\n',self.cred)),
                 mock.patch.object(privileged,'validate',side_effect=lambda x:x),
                 mock.patch.object(privileged.PrivilegedDriver,'_query',return_value=self.remote)]
        for p in patches:p.start();self.addCleanup(p.stop)

    def test_explicit_archive_after_fresh_complete_read_preserves_history(self):
        result=privileged.archive(self.root,self.id,self.proof_pin)
        self.assertEqual(result['state'],'archived');self.assertEqual(result['oldOutcome'],'unknown')
        self.assertEqual(list(self.job.iterdir()),[])
        self.assertTrue((self.proof_job/'archive-fence.json').exists());self.assertTrue((self.proof_job/'terminal.json').exists())
        with self.assertRaises(FileNotFoundError):privileged.archive(self.root,self.id,self.proof_pin)

    def test_fence_then_transport_loss_no_archive_replay(self):
        with mock.patch.object(old,'rename_complete',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):privileged.archive(self.root,self.id,self.proof_pin)
        self.assertTrue(self.claim.exists())
        with self.assertRaises(FileExistsError):privileged.archive(self.root,self.id,self.proof_pin)

    def test_permission_gap_or_changed_remote_proof_never_archives(self):
        with mock.patch.object(privileged.PrivilegedDriver,'_query',side_effect=old.AdapterError('permission_gap')):
            with self.assertRaises(old.AdapterError):privileged.archive(self.root,self.id,self.proof_pin)
        self.assertTrue(self.claim.exists());self.assertFalse((self.proof_job/'archive-fence.json').exists())
        with mock.patch.object(privileged.PrivilegedDriver,'_query',return_value={'changed':True}):
            with self.assertRaises(old.AdapterError):privileged.archive(self.root,self.id,self.proof_pin)

    def test_same_byte_claim_and_proof_exchange_refuse(self):
        p=self.proof_job/'proof.json';raw=p.read_bytes();p.unlink();session.write_once(p,raw)
        with self.assertRaises(old.AdapterError):privileged.archive(self.root,self.id,self.proof_pin)
        self.assertTrue(self.claim.exists())
        raw=self.claim.read_bytes();self.claim.unlink();session.write_once(self.claim,raw)
        with self.assertRaises(old.AdapterError):privileged.archive(self.root,self.id,self.proof_pin)

    def test_fence_exchange_before_rename_detected(self):
        original=session.read;calls=[0]
        def read(path,*args,**kwargs):
            if Path(path).name=='archive-fence.json':
                calls[0]+=1
                if calls[0]==2:
                    p=Path(path);raw=p.read_bytes();p.unlink();p.write_bytes(raw);p.chmod(0o600)
            return original(path,*args,**kwargs)
        with mock.patch.object(session,'read',side_effect=read):
            with self.assertRaises(old.AdapterError):privileged.archive(self.root,self.id,self.proof_pin)
        self.assertTrue(self.claim.exists())
