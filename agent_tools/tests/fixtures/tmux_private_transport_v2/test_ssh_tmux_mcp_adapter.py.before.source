"""Fixed-purpose adapter: inert local stand-ins, never SSH/native builds."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
try:import resource
except ImportError:resource=None
from agent_tools import ssh_tmux_mcp_adapter as adapter
from agent_tools import ssh_tmux_session as session
from agent_tools.tests import test_ssh_tmux_session_ssh as original

ROOT=Path(__file__).resolve().parents[2]
PIN=original.pin() if os.name=='posix' else None

@unittest.skipUnless(os.name=='posix','POSIX coordinator; no native operations')
class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.fixture=original.DriverTests('test_coordinator_injected_driver_retains_authority_before_release');self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root.resolve();self.fixture.root=self.root
        for name in ('ssh_tmux_source_staging_recovery.py','ssh_tmux_session_ssh.py'):
            shutil.copyfile(ROOT/'agent_tools'/name,self.root/'agent_tools'/name)
        self.driver=adapter.McpTmuxDriver(self.root)
        self.archive=self.root/'inert-remote.tar';self.fixture.archive();self.archive.write_bytes(self.fixture.remote.archive)
        self.calls=[];self.client=subprocess.Popen
        self.patch=mock.patch.object(subprocess,'Popen',side_effect=self.launch);self.patch.start();self.addCleanup(self.patch.stop)

    def launch(self,argv,**kwargs):
        self.calls.append(argv)
        code="""import sys,json,base64,pathlib,hashlib
v=json.loads(sys.stdin.buffer.read());corr=v.get('request',{}).get('correlationId');action=v.get('action');pins=json.loads(sys.argv[2])
if not v:r={'available':True,'reason':'available','nativeActionAllowed':False}
elif 'build' in v:r={'state':'staged','correlationId':corr,'stagePin':pins[0]}
elif action=='prepare':r={'state':'prepared','correlationId':corr,'anchorPin':pins[1],'replayAllowed':False,'artifactVerification':'required'}
elif action=='release':r={'state':'released','correlationId':corr,'replayAllowed':False,'artifactVerification':'required'}
elif action=='status':r={'state':'terminal','correlationId':corr,'exitCode':0,'terminalPin':pins[2],'replayAllowed':False,'artifactVerification':'required'}
else:
 b=pathlib.Path(sys.argv[1]).read_bytes();p=pins[3];p['generation'][5]=len(b);p['sha256']=hashlib.sha256(b).hexdigest();r={'offset':v['offset'],'totalBytes':len(b),'chunkBase64':base64.b64encode(b[v['offset']:v['offset']+v['limit']]).decode(),'resultSha256':p['sha256'],'resultPin':p,'artifactVerification':'required','replayAllowed':False}
print(json.dumps(r))
"""
        return self.client([sys.executable,'-I','-c',code,str(self.archive),json.dumps([original.pin(n) for n in range(1,5)])],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)

    def start(self):return adapter.build.start(self.root,self.fixture.req,driver=self.driver,admission=lambda *args:{'state':'ready'})

    def test_full_fixed_staging_build_status_and_multichunk_verified_collection(self):
        self.assertEqual('submitted',self.start()['state'])
        self.assertEqual('unknown',self.driver.status(self.fixture.req)['state'])
        with mock.patch.object(adapter.build.FixedArchDriver,'collect',return_value={'state':'ready'}) as registered:
            self.assertEqual({'state':'ready'},self.driver.collect_existing(self.fixture.req));registered.assert_called_once()
        job=self.fixture.job();self.assertEqual(self.fixture.remote.archive,(job/'result.tar').read_bytes());self.assertTrue((job/'tmux-output-ready.json').is_file())
        self.assertEqual(12,len(list((job/'output/.rag_index/build-timings').iterdir())))
        births=list((self.root/'.rag_index/linux-package-fixture-build-pipe-collection').iterdir())
        phases=[json.loads((b/'intent.json').read_bytes())['authority']['phase'] for b in births]
        self.assertEqual(1,phases.count('stage'));self.assertEqual(1,phases.count('release'));self.assertGreater(phases.count('collect'),1)
        for b in births:
            receipt=json.loads((b/'receipt.json').read_bytes());self.assertFalse(receipt['replayAllowed'])
            intent=json.loads((b/'intent.json').read_bytes());a=intent['authority'];self.assertNotIn('terminalPin',a['local']) if a['phase'] in ('stage','prepare','release') else None
        before=len(self.calls);self.assertEqual('unknown',self.start()['state']);self.assertEqual(before,len(self.calls))

    def test_availability_read_only_no_claim_and_preflight_source_gate(self):
        self.assertEqual({'available':True,'reason':'available','nativeActionAllowed':False},self.driver.availability())
        self.assertFalse((self.root/adapter.build._JOURNAL/'archlinux.claim').exists())
        with mock.patch.object(adapter.build,'preflight',return_value={'state':'ready'}) as preflight:
            self.assertEqual('ready',self.driver.preflight(self.fixture.req)['state']);preflight.assert_called_once_with(self.root,self.fixture.req,source_root=self.root)

    def test_internal_release_requires_birth_and_public_release_never_launches(self):
        self.start();job=self.fixture.job();(job/'tmux-mcp-adapter-birth.json').unlink();(job/'tmux-mcp-adapter-birth-seal.json').unlink()
        count=len(self.calls)
        with self.assertRaises(ValueError):self.driver._action(self.fixture.req,'release')
        self.assertEqual(count,len(self.calls))
        for action,raw in [('release',{'correlationId':self.fixture.req['correlationId']}),('shell',{}),('availability',{'command':'id'}),('status',{'correlationId':self.fixture.req['correlationId'],'path':'secret'})]:
            with self.subTest(action=action),self.assertRaises(ValueError):adapter.operate(self.root,action,raw)
        self.assertEqual(count,len(self.calls))

    def test_crossed_request_source_birth_and_samebyte_local_intent_exchange_reject_before_query(self):
        self.start();job=self.fixture.job();count=len(self.calls)
        birth=job/'tmux-mcp-adapter-birth.json';raw=birth.read_bytes();value=json.loads(raw);value['sources'][str(Path(adapter.__file__).absolute())]['sha256']='0'*64;birth.write_text(json.dumps(value))
        self.assertEqual('unknown',self.driver.status(self.fixture.req)['state']);self.assertEqual(count,len(self.calls))

    def test_samebyte_local_intent_exchange_in_final_guard_rejects_before_query(self):
        self.start();job=self.fixture.job();count=len(self.calls)
        path=job/'tmux-adapter-intent.json';saved=adapter.pipe._read(path)[1]
        real=self.driver._phase;changed=[]
        def drift(*args):
            result=real(*args)
            if not changed:
                replacement=job/'inert-replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path);changed.append(True)
            return result
        with mock.patch.object(self.driver,'_phase',side_effect=drift):
            self.assertEqual('unknown',self.driver.status(self.fixture.req)['state'])
        self.assertNotEqual(saved,adapter.pipe._read(path)[1]);self.assertEqual(count,len(self.calls))

    def test_same_byte_birth_exchange_rejects_before_launch_and_never_reseals(self):
        self.start();job=self.fixture.job();birth=job/'tmux-mcp-adapter-birth.json';count=len(self.calls)
        replacement=job/'inert-samebytes';replacement.write_bytes(birth.read_bytes());replacement.chmod(0o600);replacement.replace(birth)
        seal=(job/'tmux-mcp-adapter-birth-seal.json').read_bytes()
        self.assertEqual('unknown',self.driver.status(self.fixture.req)['state']);self.assertEqual(count,len(self.calls));self.assertEqual(seal,(job/'tmux-mcp-adapter-birth-seal.json').read_bytes())

    def test_closed_program_and_schema_reject_without_any_process(self):
        for program,payload in [('print(1)',{}),(adapter.old._AVAILABILITY,{'command':'id'}),(adapter.old._ACTION,{'request':{}})]:
            with self.subTest(program=program),self.assertRaises(ValueError):self.driver._query(program,payload)
        self.assertEqual([],self.calls)

    def test_source_clean_gate_failure_prevents_stage_or_claim_replay(self):
        with mock.patch.object(adapter.build,'_source_preflight',side_effect=ValueError('inert dirty source')):
            self.assertEqual('unknown',self.start()['state'])
        self.assertEqual([],self.calls)

    @unittest.skipUnless(resource is not None,'POSIX RLIMIT causal')
    def test_actual_4096_regular_fd_red_pipe_green_and_large_early_payload(self):
        code="import sys,os;sys.stdin.buffer.read();os.write(1,b'x'*8192)"
        def limit():resource.setrlimit(resource.RLIMIT_FSIZE,(4096,4096))
        path=self.root/'red-regular'
        with path.open('wb') as out:self.client([sys.executable,'-I','-c',code],stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.DEVNULL,preexec_fn=limit).wait()
        self.assertEqual(4096,path.stat().st_size)
        authority={'phase':'stage','snapshot':{},'sources':{},'transport':{},'local':{},'argvSha256':'a'*64}
        result,capsule=adapter._capture(self.root,authority=authority,launch=lambda:self.client([sys.executable,'-I','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,preexec_fn=limit),payload=b'x'*100000,guard=lambda:None)
        self.assertEqual('captured',result['state']);self.assertEqual(8192,(capsule/'stdout').stat().st_size)
        self.assertEqual(100000,json.loads((capsule/'receipt.json').read_bytes())['stdinBytesWritten'])

    def test_unknown_exit_timeout_output_cap_and_postguard_keep_private_finite_receipts(self):
        authority={'phase':'availability','snapshot':None,'sources':{},'transport':{},'local':{},'argvSha256':'a'*64}
        cases=[('exit',"import sys;sys.stderr.write('private raw marker');sys.exit(255)",1),('timeout',"import sys,time;sys.stdout.write('partial');sys.stdout.flush();time.sleep(10)",.05),('cap',"import os;os.write(1,b'x'*"+str(adapter.MAX_STDOUT+4096)+")",1)]
        for kind,code,timeout in cases:
            with self.subTest(kind=kind):
                result,capsule=adapter._capture(self.root,authority=authority,launch=lambda:self.client([sys.executable,'-I','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0),payload=b'{}',guard=lambda:None,timeout_seconds=timeout)
                self.assertEqual('unknown',result['state']);record=json.loads((capsule/'receipt.json').read_bytes());self.assertFalse(record['replayAllowed']);self.assertNotIn('private raw marker',json.dumps(record))
                self.assertEqual(kind=='timeout',record['timedOut']);self.assertEqual(kind=='cap',record['capped']);self.assertEqual(adapter.pipe._read(capsule/'stdout',adapter.MAX_STDOUT+1)[1],record['stdoutPin'])
        count=0
        def guard():
            nonlocal count
            count+=1
            if count==3:raise ValueError('private authority detail')
        result,capsule=adapter._capture(self.root,authority=authority,launch=lambda:self.client([sys.executable,'-I','-c',"import sys;sys.stdin.buffer.read();print('{}')"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0),payload=b'{}',guard=guard)
        self.assertEqual('unknown',result['state']);self.assertEqual('authority_changed',json.loads((capsule/'receipt.json').read_bytes())['failure'])

    def test_existing_frozen_v2_job_phase_readonly_binding_has_no_hardcoded_history(self):
        # Legacy completed jobs with reviewed841 snapshot remain observable/collectable,
        # while a legacy preparation/release cannot be adopted by this adapter.
        self.start();job=self.fixture.job();(job/'tmux-mcp-adapter-birth.json').unlink();(job/'tmux-mcp-adapter-birth-seal.json').unlink()
        self.assertEqual('unknown',self.driver.status(self.fixture.req)['state'])
        with mock.patch.object(adapter.build.FixedArchDriver,'collect',return_value={'state':'ready'}):self.assertEqual({'state':'ready'},self.driver.collect_existing(self.fixture.req))

    def test_unsupported_coordinator_rejected_before_driver_or_phase(self):
        with mock.patch.object(adapter.os,'name','nt'),mock.patch.object(adapter.subprocess,'Popen') as launch,self.assertRaises(ValueError):adapter.operate(self.root,'availability',{})
        launch.assert_not_called()
