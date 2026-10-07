import ast
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest import mock
from agent_tools import android_retired_endpoint_fresh_owner as helper
from agent_tools import android_endpoint_admission as endpoint

class RetiredEndpointTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.job=pathlib.Path(self.temp.name);self.lease=self.job/'lease';self.lease.write_text('lease')
        self.snapshot={'native':{'stageGeneration':None,'caGeneration':None},'public':{'owner':'fresh','revision':0},'stock':{'inside':'pinned','outside':'pinned'},'binding':{'correlationId':'new'}}
        self.ret={'binding':self.snapshot['binding'],'snapshot':self.snapshot,'leasePin':self.pin(self.lease)}
        self.scope={'RET':self.ret,'RET_ID':'new','job':self.job,'retbase':self.job/'retired-new','pathlib':pathlib,'os':__import__('os'),'json':json,'remaining_pin':self.pin,'private':lambda path,*_:path.read_bytes(),'retcontrols':lambda:None,'retsnapshot':lambda:self.snapshot,'lease':self.lease,'lease_lock':lambda:None,'release_lock':lambda _:None,'record':self.record,'emit':self.emit,'action':'retired-admit'}
        nodes=[n for n in ast.parse(helper._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name in {'retpath','retfail','retadmission','retired_release_guard','retired_dispatch'}]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-retired-dispatch>','exec'),self.scope)
    def pin(self,path,*_):
        raw=path.read_bytes();return {'sha256':hashlib.sha256(raw).hexdigest(),'generation':[path.stat().st_ino,len(raw),path.stat().st_mtime_ns]}
    def record(self,path,value):
        with path.open('x') as f:json.dump(value,f)
    def emit(self,state,reason=None,**extra):raise Result(state,reason,extra)
    def run_action(self,action):
        self.scope['action']=action
        with self.assertRaises(Result) as result:self.scope['retired_dispatch']()
        return result.exception
    def test_admit_complete_collect_preserves_old_unknown(self):
        self.assertEqual('ready',self.run_action('retired-admit').state)
        self.assertEqual('reconciled',self.run_action('retired-complete').state)
        result=self.run_action('retired-collect');self.assertTrue(result.extra['leaseReleased'])
        self.assertEqual('unknown',result.extra['originalOutcome']);self.assertFalse(result.extra['oldCleanupReplayed'])
        self.assertFalse(self.lease.exists());self.assertFalse(any(self.job.glob('remaining-stage-*')))
    def test_admission_not_replayed(self):
        self.run_action('retired-admit');self.assertEqual('retired_already_recorded',self.run_action('retired-admit').reason)
    def test_attempt_lost_response_never_replayed(self):
        self.run_action('retired-admit');normal=self.scope['record']
        def fail(path,value):
            normal(path,value)
            if str(path).endswith('.attempt.json'):raise RuntimeError('lost-response')
        self.scope['record']=fail;self.scope['action']='retired-complete'
        with self.assertRaises(RuntimeError):self.scope['retired_dispatch']()
        self.scope['record']=normal
        self.assertEqual('retired_attempt_recorded',self.run_action('retired-complete').reason)
        self.assertEqual('retired_completion_unknown',self.run_action('retired-status').reason)
    def test_epoch_drift_before_terminal_rejected(self):
        self.run_action('retired-admit');self.scope['retsnapshot']=lambda:{**self.snapshot,'public':{'owner':'other'}}
        self.assertEqual('retired_admission_stale',self.run_action('retired-complete').reason)
        self.assertFalse((self.job/'retired-new.attempt.json').exists())
    def test_lease_replacement_rejected(self):
        self.run_action('retired-admit');self.run_action('retired-complete');self.lease.write_text('foreign')
        self.assertEqual('retired_lease_changed',self.run_action('retired-collect').reason)
    def test_collect_crash_never_replayed(self):
        self.run_action('retired-admit');self.run_action('retired-complete');normal=self.scope['record']
        def fail(path,value):
            normal(path,value)
            if str(path).endswith('.collect.json'):raise RuntimeError('crash')
        self.scope['record']=fail;self.scope['action']='retired-collect'
        with self.assertRaises(RuntimeError):self.scope['retired_dispatch']()
        self.scope['record']=normal;self.assertEqual('retired_collect_recorded',self.run_action('retired-collect').reason);self.assertTrue(self.lease.exists())
    def test_release_guard_rejects_terminal_drift(self):
        self.run_action('retired-admit');self.run_action('retired-complete');self.run_action('retired-collect')
        (self.job/'retired-new.terminal.json').write_text('{}')
        with self.assertRaises(Result) as result:self.scope['retired_release_guard']()
        self.assertEqual('retired_release_changed',result.exception.reason)
    def test_same_bytes_proof_generation_replacement_rejected(self):
        source=self.job/'source-proof';source.write_text('same');capsule=self.job/'capsule';capsule.write_text('capture')
        ready=self.job/'remaining-stage-old.json';ready.write_text('ready')
        self.ret.update({'proofName':'capsule','proofPin':self.pin(capsule),'readyPin':self.pin(ready),'journalPins':{}})
        self.scope.update({'retired_records_guard':lambda:{},'BUNDLE':{'baseline':{'plan':{}},'proofs':[{'name':'source-proof','sha256':self.pin(source)['sha256']}],'history':[]},'ret_source_proof_pins':None,'remaining':{'correlationId':'old'},'root':self.job,'stat':__import__('stat')})
        node=next(n for n in ast.parse(helper._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='retcontrols');exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-retired-controls>','exec'),self.scope)
        self.scope['retcontrols']();info=source.stat();__import__('os').utime(source,ns=(info.st_atime_ns,info.st_mtime_ns+1))
        with self.assertRaises(Result) as result:self.scope['retcontrols']()
        self.assertEqual('retired_source_proof_changed',result.exception.reason)
    def test_collect_concurrent_terminal_drift_preserves_lease(self):
        self.run_action('retired-admit');self.run_action('retired-complete');normal=self.scope['record']
        def replace(path,value):
            normal(path,value)
            if str(path).endswith('.release.json'):(self.job/'retired-new.terminal.json').write_text('{}')
        self.scope['record']=replace;self.assertEqual('retired_post_changed',self.run_action('retired-collect').reason);self.assertTrue(self.lease.exists())
    def test_actual_composition_excludes_runtime_mutators(self):
        paths=[pathlib.Path(helper.__file__).absolute(),pathlib.Path(endpoint.__file__).absolute().with_name('android_diagnostic_composition.py')]
        snapshots={str(p):({'sha256':hashlib.sha256(p.read_bytes()).hexdigest()},p.read_bytes()) for p in paths}
        prefix=endpoint._REMOTE.split("\nif action=='start':",1)[0]+'\nBUNDLE={}\noperate()\n'
        with mock.patch.object(helper.recovery,'_program',return_value=prefix):program=helper._program({},self.ret,'new',snapshots)
        compile(program,'<actual-whole-composition>','exec');names={n.name for n in ast.parse(program).body if isinstance(n,ast.FunctionDef)}
        self.assertFalse(names&helper._MUTATORS);self.assertIn('retired_records_guard',names)
    def test_source_snapshot_exchange_rejected(self):
        p=self.job/'source';p.write_text('code');p.unlink();p.symlink_to('/dev/null')
        with self.assertRaises((OSError,ValueError)):helper.recovery._source_snapshot(p)

class Result(Exception):
    def __init__(self,state,reason,extra):self.state=state;self.reason=reason;self.extra=extra

class EpochRegression(unittest.TestCase):
    def test_frozen_old_epoch_conflict_then_explicit_current_admission(self):
        current='fresh';off={'runtimeRunning':False,'runtimeObservation':'stopped','selectedLocationId':None,'activeLocationId':None};backup=b'{}'
        def command(argv,**_):
            owner=argv[argv.index('--controller-id')+1] if '--controller-id' in argv else None
            if owner is not None and owner!=current:raise ValueError('CONFLICT')
            words=argv[argv.index('30')+1:]
            if words[:1]==['--controller-id']:words=words[2:]
            data=off if words==['status'] else {'operations':[]} if words==['operations','list'] else {'routing':{}}
            return json.dumps({'ok':True,'code':'OK','final':True,'controllerId':current,'configurationRevision':0,'data':data})
        scope={'identity':lambda _:None,'installed':lambda:None,'routes':lambda:{},'unknown':lambda reason:(_ for _ in ()).throw(ValueError(reason)),'private':lambda _:backup,'pathlib':pathlib,'expected':{'backupPath':'/backup','backupSha256':hashlib.sha256(backup).hexdigest()},'hashlib':hashlib,'json':json,'canonical_rules':lambda _:'same-rules','observed_readmission_owner':'historical','remaining':{},'readmission':None,'action':'remaining-cleanup-status','cli':'/cli','serial':'serial','ROUTING_CLI_SECONDS':30,'ROUTING_PROCESS_SECONDS':30,'environment':{},'command':command}
        nodes=[n for n in ast.parse(endpoint._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name in {'remaining_public','public_argv'}];exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-frozen-public-reader>','exec'),scope)
        with self.assertRaisesRegex(ValueError,'CONFLICT'):scope['remaining_public']('2000')
        scope['observed_readmission_owner']=None;self.assertEqual(current,scope['remaining_public']('2000')['owner'])
        current='drift'
        with self.assertRaisesRegex(ValueError,'CONFLICT'):scope['remaining_public']('2000')

class LocalClaimRelease(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name).resolve();self.identifier='new'
        self.directory=self.root/'.rag_index/android-retired-endpoint';self.directory.mkdir(parents=True,mode=0o700)
        self.intent={'host':'archlinux','device':'api29'};self.snapshot={'binding':{'correlationId':'new'},'public':{'owner':'fresh','revision':0},'native':{'stageGeneration':None,'caGeneration':None},'stock':{'inside':'stock','outside':'stock'}}
        self.ret={'binding':self.snapshot['binding'],'snapshot':self.snapshot,'leasePin':{'generation':[1],'sha256':'a'*64}}
        terminal={'schema':1,'kind':'retired-endpoint-reconciled','binding':self.ret['binding'],'admissionPin':{'generation':[1,2,3,4,5,0o100600,1000,1],'sha256':'b'*64},'attemptPin':{'generation':[1,3,3,4,5,0o100600,1000,1],'sha256':'c'*64},'snapshot':{**self.snapshot,'proofPins':{'old-source':{'generation':[4],'sha256':'d'*64}}},'originalOutcome':'unknown'}
        tp=self.remote_pin(terminal);release={'schema':1,'binding':self.ret['binding'],'terminalPin':tp,'lease':self.ret['leasePin']}
        self.result={'state':'reconciled','reason':'retired_metadata_complete','retiredCorrelationId':'new','correlationId':helper.recovery.ORIGINAL,'leaseReleased':True,'originalOutcome':'unknown','oldCleanupReplayed':False,'terminal':terminal,'terminalPin':tp,'release':release,'releasePin':self.remote_pin(release)}
        helper.recovery._write(self.directory/'new.remote-closed.json',helper._validate_remote_closed(self.result,self.ret));pin=helper.recovery._private(self.directory/'new.remote-closed.json');helper.recovery._write(self.directory/'new.remote-closed.pin.json',{'schema':1,'sha256':pin[1],'generation':list(pin[2])})
        self.lease=self.root/'lease';helper.recovery._write(self.lease,{'owner':'android-endpoint','correlationId':helper.recovery.ORIGINAL,**self.intent})
    def remote_pin(self,value):return {'generation':[1,2,len((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()),4,5,0o100600,1000,1],'sha256':hashlib.sha256((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()}
    def release(self,guard=lambda released=False:None):return helper._release_local_locked(self.root,'new',self.ret,self.intent,None,None,self.lease,guard)
    def test_actual_local_release_closed_marker_and_no_replay(self):
        result=self.release();self.assertTrue(result['localLeaseReleased']);self.assertFalse(result['remoteEffects']);self.assertFalse(self.lease.exists())
        helper._closed_local(self.root,'new',self.ret,self.intent)
        self.assertEqual('retired_local_release_attempt_recorded',self.release()['reason'])
    def test_same_bytes_claim_replacement_is_rejected(self):
        calls=[]
        def guard(released=False):
            calls.append(released)
            if len(calls)==2:
                raw=self.lease.read_bytes();old=self.lease.with_name('old-lease');self.lease.rename(old);self.lease.write_bytes(raw);self.lease.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'retired_local_claim_changed'):self.release(guard)
        self.assertTrue(self.lease.exists());self.assertEqual('retired_local_release_attempt_recorded',self.release()['reason'])
    def test_missing_closed_marker_is_not_default_permission(self):
        self.lease.unlink()
        with self.assertRaises(OSError):helper._closed_local(self.root,'new',self.ret,self.intent)
    def test_remote_terminal_hash_drift_rejected_before_local_effect(self):
        self.result['terminal']['originalOutcome']='success'
        with self.assertRaisesRegex(ValueError,'retired_remote_closed_unverified'):helper._validate_remote_closed(self.result,self.ret)
        self.assertTrue(self.lease.exists())
    def test_remote_receipt_replacement_breaks_authenticated_closed_marker(self):
        self.release();path=self.directory/'new.remote-closed.json';raw=path.read_bytes();path.rename(path.with_name('old-remote'));path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'retired_remote_closed_generation_changed'):helper._closed_local(self.root,'new',self.ret,self.intent)
    def test_crash_after_fence_never_releases_claim_on_replay(self):
        calls=[]
        def guard(released=False):
            calls.append(released)
            if len(calls)==2:raise RuntimeError('response-lost')
        with self.assertRaises(RuntimeError):self.release(guard)
        self.assertTrue(self.lease.exists());self.assertEqual('retired_local_release_attempt_recorded',self.release()['reason'])
    def test_old_local_claim_cannot_be_adopted(self):
        self.lease.write_text('{}');self.lease.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'retired_local_claim_changed'):self.release()
    def test_post_release_guard_runs_in_terminal_mode(self):
        calls=[];self.release(lambda released=False:calls.append(released));self.assertTrue(calls[-1]);self.assertFalse(any(calls[:-1]))
