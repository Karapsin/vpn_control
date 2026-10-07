"""Inert source-staging failure and no-replay tests; no native transport."""
import base64
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
from agent_tools import ssh_tmux_source_staging_recovery as recovery
from agent_tools import ssh_tmux_session_ssh as old
from agent_tools import ssh_tmux_session as session
from agent_tools import linux_package_fixture_build as build


def remote_program(program, payload, handler):
    fake=types.ModuleType('subprocess');fake.run=handler
    fake.PIPE=subprocess.PIPE;fake.DEVNULL=subprocess.DEVNULL;fake.TimeoutExpired=subprocess.TimeoutExpired
    result=io.StringIO()
    with mock.patch.dict('sys.modules',{'subprocess':fake}),mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(session.canonical(payload)))),contextlib.redirect_stdout(result):
        exec(compile(program,'<fixed-stage>','exec'),{'__name__':'diagnostic'})
    return json.loads(result.getvalue())


class StageTests(unittest.TestCase):
    def test_actual_clone_timeout_vs_exact_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            req=old.purpose(recovery.OLD_REQUEST)
            tools=old.TmuxArchDriver(Path(__file__).resolve().parents[2])._tools()
            payload={'request':req,'build':base64.b64encode(tools['linux_package_fixture_build.py']['raw']).decode(),
                     'tool':base64.b64encode(tools['ssh_tmux_session.py']['raw']).decode()}
            calls=[]
            def handler(argv,**kw):
                calls.append((argv,kw))
                if argv[1]=='clone':raise subprocess.TimeoutExpired(argv,60)
                if argv[1]=='init':Path(argv[2]).mkdir()
                if 'fetch' in argv:
                    self.assertEqual(argv[-1],req['sourceSha']);self.assertIn('--depth=1',argv);self.assertIn('--no-tags',argv)
                    self.assertEqual(kw['env']['GIT_LFS_SKIP_SMUDGE'],'1');self.assertEqual(kw['timeout'],60)
                if 'checkout' in argv:
                    (root/req['correlationId']/'source'/'agent_tools').mkdir()
                    self.assertEqual(kw['env']['GIT_LFS_SKIP_SMUDGE'],'1')
                return types.SimpleNamespace(stdout=req['sourceSha'].encode(),returncode=0)
            old_program=old._STAGE.replace(old.REMOTE_ROOT,str(root))
            with self.assertRaises(subprocess.TimeoutExpired):remote_program(old_program,payload,handler)
            self.assertFalse((root/req['correlationId']/'stage-ready.json').exists())
            # Different fresh correlation only, never retry old consumed job.
            req={**req,'correlationId':'f947e7c3-fdbd-44dd-9b65-03bcb2ed4820'};payload['request']=req
            program=recovery.STAGE_V2.replace(old.REMOTE_ROOT,str(root))
            with mock.patch.object(session,'preflight',return_value={}):
                # Generated stage imports its own reviewed tool, so replace only
                # final preflight function invocation in inert fixture.
                program=program.replace("proof=namespace['preflight'](job,source,request)","proof={'source':{},'parent':{},'job':{}}")
                result=remote_program(program,payload,handler)
            self.assertEqual(result['state'],'staged')
            self.assertTrue((root/req['correlationId']/'stage-ready.json').exists())
            self.assertEqual(sum('fetch' in a for a,_ in calls),1)
            self.assertFalse(any('--remote-run' in a for a,_ in calls))
            with self.assertRaises(FileExistsError):remote_program(program,payload,handler)
            self.assertEqual(sum('fetch' in a for a,_ in calls),1)

    def test_fixed_flat_command_and_no_arbitrary_source(self):
        with self.assertRaises(old.AdapterError):recovery.command('print("arbitrary")')
        for program in (recovery.PROOF,recovery.STAGE_V2):
            self.assertNotIn('\n',recovery.command(program)[-1]);self.assertLess(len(recovery.command(program)[-1]),30000)

    def test_current_fresh_snapshot_and_historical_refusal(self):
        from agent_tools.tests.test_ssh_tmux_session_ssh import DriverTests
        fixture=DriverTests('test_missing_claim_cannot_direct_submit')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.start()['state'], 'submitted')
        # Actual current tools, transport and provider source; no snapshot seam.
        current=recovery.CurrentExactFetchDriver(fixture.root)
        value=current._snapshot(fixture.req)
        self.assertEqual(value['adapterSource']['sha256'], recovery.CURRENT_ADAPTER_SHA)
        with self.assertRaisesRegex(old.AdapterError, 'frozen_adapter_changed'):
            recovery.ExactFetchDriver(fixture.root)._snapshot(fixture.req)
        with mock.patch.object(recovery, 'CURRENT_ADAPTER_SHA', '0'*64):
            with self.assertRaisesRegex(old.AdapterError, 'current_adapter_changed'):
                current._snapshot(fixture.req)

    def test_v2_generation_binds_new_source(self):
        driver=recovery.ExactFetchDriver(Path(__file__).resolve().parents[2])
        with mock.patch.object(old.TmuxArchDriver,'_snapshot',return_value={'adapterSource':{'sha256':recovery.FROZEN_ADAPTER_SHA}}):
            value=driver._snapshot(recovery.OLD_REQUEST)
            self.assertIn('stagingCompanionSource',value)
            self.assertEqual(value['stageProgramSha256'],hashlib.sha256(recovery.STAGE_V2.encode()).hexdigest())


class ProofTests(unittest.TestCase):
    def make(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name);self.root.chmod(0o700)
        self.job=self.root/recovery.OLD_CORRELATION;self.job.mkdir(mode=0o700)
        session.write_once(self.job/'stage-intent.json',session.canonical(old.purpose(recovery.OLD_REQUEST)))
        self.program=recovery.PROOF.replace(old.REMOTE_ROOT,str(self.root))
        # Inert actual census with deterministic no-process namespace, not a
        # schema-only returned proof.
        self.program=self.program.replace("entries=list(pathlib.Path('/proc').iterdir())","entries=[]")

    def run_program(self,program=None):
        out=io.StringIO()
        with mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(session.canonical({'request':old.purpose(recovery.OLD_REQUEST)})))),contextlib.redirect_stdout(out):
            exec(compile(program or self.program,'<fixed-proof>','exec'),{})
        return json.loads(out.getvalue())

    def test_actual_partial_source_no_effect(self):
        self.make();source=self.job/'source';source.mkdir();(source/'.git').mkdir()
        value=self.run_program();recovery._valid_remote(value)
        self.assertIs(value['proof']['noBuildEffects'],True)
        self.assertEqual(sorted(p.name for p in self.job.iterdir()),['source','stage-intent.json'])

    def test_actual_effect_record_and_checkout_reject(self):
        self.make()
        for name in ('stage-ready.json','tmux-tool.py','tmux.sock','tmux-worker.py','release.json','terminal.json'):
            p=self.job/name;p.write_bytes(b'foreign')
            with self.assertRaises(SystemExit):self.run_program()
            self.assertEqual(p.read_bytes(),b'foreign');p.unlink()
        source=self.job/'source';source.mkdir();(source/'gradle.properties').write_text('checkout')
        with self.assertRaises(SystemExit):self.run_program()

    def test_actual_same_byte_intent_exchange_reject(self):
        self.make()
        injected=self.program.replace('scan()\n  if sorted',"scan()\n  temp=job/'swap';temp.write_bytes(raw);temp.chmod(0o600);os.replace(temp,job/'stage-intent.json')\n  if sorted")
        with self.assertRaises(SystemExit):self.run_program(injected)

    def test_actual_job_process_blocks(self):
        self.make()
        proc=self.root/'proc';proc.mkdir();entry=proc/'321';entry.mkdir()
        fields=['S']+['1']*18+['777']+['1']*3
        (entry/'stat').write_text('321 (git) '+' '.join(fields))
        (entry/'cmdline').write_bytes(b'git\0clone\0'+os.fsencode(self.job/'source')+b'\0')
        (entry/'cwd').symlink_to(self.root)
        program=self.program.replace('entries=[]',f'entries=list(pathlib.Path({str(proc)!r}).iterdir())')
        with self.assertRaises(SystemExit) as got:self.run_program(program)
        self.assertEqual(got.exception.code,37)

    def test_false_numeric_bool_and_unrecognized_fields_refuse(self):
        self.make();value=self.run_program()
        value['proof']['noBuildEffects']=1
        with self.assertRaises(old.AdapterError):recovery._valid_remote(value)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.root.chmod(0o700)
        (self.root/'.rag_index').mkdir(mode=0o700)
        self.directory=self.root/build._JOURNAL;self.directory.mkdir(mode=0o700)
        self.job=self.directory/recovery.OLD_CORRELATION;self.job.mkdir(mode=0o700)
        self.claim=self.directory/'archlinux.claim'
        session.write_once(self.claim,session.canonical({'correlationId':recovery.OLD_CORRELATION,'host':'archlinux'}))
        self.original_claim=session.read(self.claim)[1]
        self.before={'original':{'coordinator':{'records':{'claim':self.original_claim}}}}
        self.remote={'state':'staging-only','request':old.purpose(recovery.OLD_REQUEST),'proof':{},'replayAllowed':False}
        self.value={'local':self.before,'remote':self.remote,'proofProgramSha256':hashlib.sha256(recovery.PROOF.encode()).hexdigest()}
        self.pin=session.write_once(self.job/'stage-recovery-proof.json',session.canonical(self.value))
        self.patches=[mock.patch.object(recovery,'_local',side_effect=self.local),
                      mock.patch.object(recovery,'_valid_remote',side_effect=lambda x:x),
                      mock.patch.object(recovery.ExactFetchDriver,'_query',return_value=self.remote)]
        for p in self.patches:p.start();self.addCleanup(p.stop)

    def local(self,driver):
        old.need(session.read(self.claim)[1]==self.original_claim,'claim_changed')
        return self.job,self.before

    def test_one_archive_preserves_unknown_no_replay(self):
        result=recovery.archive_failed_claim(self.root,self.pin)
        self.assertEqual(result['state'],'archived');self.assertEqual(result['oldOutcome'],'unknown')
        self.assertFalse(self.claim.exists());self.assertTrue((self.job/'stage-recovery-proof.json').exists())
        self.assertEqual(recovery.recovery_status(self.root)['state'],'archived')
        with self.assertRaises(FileNotFoundError):recovery.archive_failed_claim(self.root,self.pin)

    def test_crash_after_fence_no_second_archive(self):
        with mock.patch.object(old,'rename_complete',side_effect=OSError('interrupted')):
            with self.assertRaises(OSError):recovery.archive_failed_claim(self.root,self.pin)
        self.assertTrue(self.claim.exists())
        with self.assertRaises(FileExistsError):recovery.archive_failed_claim(self.root,self.pin)

    def test_same_byte_claim_drift_before_archive_rejects(self):
        raw=self.claim.read_bytes();self.claim.unlink();session.write_once(self.claim,raw)
        with self.assertRaises(old.AdapterError):recovery.archive_failed_claim(self.root,self.pin)
        self.assertFalse((self.job/'stage-recovery-fence.json').exists())

    def test_remote_drift_and_lost_observation_preserve_claim(self):
        for value in ({'state':'unknown'},None):
            with mock.patch.object(recovery.ExactFetchDriver,'_query',return_value=value):
                with self.assertRaises(old.AdapterError):recovery.archive_failed_claim(self.root,self.pin)
            self.assertTrue(self.claim.exists())

    def test_archive_collision_never_overwrites(self):
        target=self.directory/(recovery.OLD_CORRELATION+'.staging-only.claim');target.write_bytes(b'foreign');target.chmod(0o600)
        with self.assertRaises(old.AdapterError):recovery.archive_failed_claim(self.root,self.pin)
        self.assertEqual(target.read_bytes(),b'foreign');self.assertTrue(self.claim.exists())


if __name__=='__main__':unittest.main()

class LocalCaptureTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.tmux_historical_source.family import load_family
        modules,factory,temporary=load_family();self.addCleanup(temporary.cleanup)
        # Historical source family is test-local; current production never
        # imports these fixtures or promotes their synthetic receipt to native.
        for name,value in (('recovery',modules['ssh_tmux_source_staging_recovery']),
                           ('old',modules['ssh_tmux_session_ssh']),
                           ('session',modules['ssh_tmux_session'])):
            patch=mock.patch.dict(globals(),{name:value});patch.start();self.addCleanup(patch.stop)
        self.fixture=factory.DriverTests('test_missing_claim_cannot_direct_submit')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.req=dict(recovery.OLD_REQUEST);self.fixture.remote.stage_loss=True
        self.assertEqual(self.fixture.start()['state'],'unknown')
        self.root=self.fixture.root;self.driver=self.fixture.driver;self.job=self.fixture.job()
        capture=self.job/'tmux-query-596b46a1-344f-48d0-a8eb-6eb112d6a6b9';capture.mkdir(mode=0o700)
        session.write_once(capture/'stdout',b'');session.write_once(capture/'stderr',b'x'*4096)
        tools=self.driver._tools()
        payload={'request':old.purpose(recovery.OLD_REQUEST),'build':base64.b64encode(tools['linux_package_fixture_build.py']['raw']).decode(),
                 'tool':base64.b64encode(tools['ssh_tmux_session.py']['raw']).decode()}
        config,_=self.driver._transport()
        argv=recovery.ssh_transport.build_ssh_argv(config,'archlinux',10,command=old.command(old._STAGE))
        record={'schemaVersion':1,'requestSha256':hashlib.sha256(session.canonical(payload)).hexdigest(),
                'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest(),'exitCode':1,'timedOut':False,
                'stdoutPin':session.read(capture/'stdout')[1],'stderrPin':session.read(capture/'stderr')[1],'replayAllowed':False}
        session.write_once(capture/'receipt.json',session.canonical(record))
        self.capture=capture
        for name,value in (('ORIGINAL_CAPTURE_PINS',{n:session.read(capture/n)[1] for n in ('stdout','stderr','receipt.json')}),
                           ('ORIGINAL_ADAPTER_INTENT_PIN',session.read(self.job/'tmux-adapter-intent.json')[1]),
                           ('STDERR_SHA',hashlib.sha256(b'x'*4096).hexdigest())):
            patch=mock.patch.object(recovery,name,value);patch.start();self.addCleanup(patch.stop)

    def test_exact_historical_provider_refuses_source_mutation(self):
        recovery._local(self.driver)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'provider.py';path.write_bytes(Path(old.__file__).read_bytes()+b'\n')
            with mock.patch.object(old,'__file__',str(path)):
                with self.assertRaisesRegex(old.AdapterError,'frozen_adapter_changed'):
                    recovery._frozen()

    def test_actual_local_full_capture_and_intent_generation(self):
        recovery._local(self.driver)
        path=self.job/'tmux-adapter-intent.json';raw=path.read_bytes();path.unlink();session.write_once(path,raw)
        with self.assertRaisesRegex(old.AdapterError,'original_adapter_intent_changed'):recovery._local(self.driver)

    def test_actual_local_same_byte_capture_replacement_and_hardlink(self):
        recovery._local(self.driver)
        path=self.capture/'stderr';raw=path.read_bytes();path.unlink();session.write_once(path,raw)
        with self.assertRaises(old.AdapterError):recovery._local(self.driver)
        os.link(path,self.capture/'foreign')
        with self.assertRaises(old.AdapterError):recovery._local(self.driver)

    def test_no_old_submit_from_v2_status_or_claim_closure(self):
        with mock.patch.object(recovery.ExactFetchDriver,'submit') as submit:
            with self.assertRaises(old.AdapterError):recovery.operate_v2(self.root,'release',{'correlationId':recovery.OLD_CORRELATION})
            submit.assert_not_called()
