"""Reserved-but-unreceipted admission completion, isolated from native cleanup."""
import ast
import tempfile
from pathlib import Path
import json
import os
import unittest
from agent_tools import android_remaining_stage_admission_completion as completion
from agent_tools import android_owned_endpoint_bind_recovery as recovery

CID='478d0530-607d-4c10-a18c-a0368a58b27c'
class CompletionHarness:
    def __init__(self,root):
        self.job=root;self.writes=[];self.effects=[];self.snapshot={'public':{'owner':'owner','revision':0,'rulesSha256':'a'*64},'native':{},'records':{}}
        self.original={'remaining-stage-admission.json':{'correlationId':recovery.REMAINING,'originalIntentSha256':'f'*64},'intent.json':{'outcome':'unknown'},'checkpoint-cleanup-unmount.json':{'phase':'cleanup-unmount'}}
        for name,value in self.original.items():recovery._write(root/name,value)
        self.meta={'binding':{'correlationId':CID},'source':{'frozen':'source'}};self.remaining=self.original['remaining-stage-admission.json'];self.drift=False;self.crash=None
    def pin(self,path,*_):
        _,sha,fp=recovery._private(path);return {'sha256':sha,'generation':fp}
    def execute(self,action='remaining-admission-complete'):
        class Result(Exception):pass
        def emit(state,reason,**extra):raise Result({'state':state,'reason':reason,**extra})
        def fail(reason):emit('unknown',reason)
        paths={'completion_intent':self.job/('completion-'+CID+'.json'),'completion_attempt':self.job/('completion-'+CID+'.attempt.json'),'completion_terminal':self.job/('completion-'+CID+'.terminal.json'),'completion_reserve':self.job/'completion-reserve.json','ready_path':self.job/('remaining-stage-'+recovery.REMAINING+'.json')}
        proofpin={'sha256':'e'*64,'generation':[1]*8}
        def controls(allow_ready=False):
            if not allow_ready and paths['ready_path'].exists():fail('completion_ready_already_recorded')
            return proofpin
        def snapshot(allow_ready=False):
            controls(allow_ready)
            if self.drift and paths['completion_attempt'].exists():fail('completion_owner_changed')
            return {'remainingSnapshot':self.snapshot,'proofPin':proofpin,'outsideFingerprint':'a','insideFingerprint':'b','directories':{}}
        def record(path,value):
            recovery._write(path,value);self.writes.append(path.name)
            if self.crash=='after-fence' and path==paths['completion_attempt']:fail('completion_lost_response')
            if self.crash=='after-ready' and path==paths['ready_path']:fail('completion_lost_response')
        scope={**paths,'emit':emit,'fail':fail,'lease_lock':lambda:1,'release_lock':lambda _:None,'private':lambda path,*_:path.read_bytes(),'private_guard':lambda:{},'META':self.meta,'completion_controls':controls,'completion_snapshot':snapshot,'record':record,'remaining_pin':self.pin,'os':os,'json':json,'job':self.job,'remaining':self.remaining,'COMPLETION_ID':CID,'action':action,'completion_intent_pin':None,'completion_attempt_pin':None,'completion_proof_pin':None,'completion_reserve_pin':None,'completion_ready_pin':None}
        function=next(n for n in ast.parse(completion._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='complete_metadata')
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-generated-completion>','exec'),scope)
        try:scope['complete_metadata']()
        except Result as exc:return exc.args[0]
        raise AssertionError('missing finite result')

class InterruptedAdmissionCompletionTest(unittest.TestCase):
    def test_measured_interrupted_admission_can_complete_metadata_without_native_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));before={name:(h.job/name).read_bytes() for name in h.original};result=h.execute()
            self.assertEqual('ready',result['state'],result);self.assertEqual([],h.effects);self.assertEqual(before,{name:(h.job/name).read_bytes() for name in h.original});self.assertEqual(h.remaining,result['remaining']['binding']);self.assertFalse(result['stageRetired']);self.assertFalse(result['leaseReleased'])
            self.assertEqual('ready',h.execute('remaining-admission-status')['state']);self.assertEqual('completion_already_recorded',h.execute()['reason'])
    def test_fenced_crash_before_metadata_write_never_retries(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));h.crash='after-fence';self.assertEqual('completion_lost_response',h.execute()['reason']);h.crash=None
            self.assertEqual('completion_already_recorded',h.execute()['reason']);self.assertEqual('completion_metadata_unknown',h.execute('remaining-admission-status')['reason']);self.assertFalse((h.job/('remaining-stage-'+recovery.REMAINING+'.json')).exists())
    def test_lost_response_after_receipt_can_collect_without_rewrite(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));h.crash='after-ready';self.assertEqual('completion_lost_response',h.execute()['reason']);h.crash=None;name='remaining-stage-'+recovery.REMAINING+'.json';before=(h.job/name).stat()
            self.assertEqual('ready',h.execute('remaining-admission-status')['state']);self.assertEqual(before,(h.job/name).stat());self.assertEqual(1,h.writes.count(name))
    def test_owner_drift_after_fence_prevents_metadata_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));h.drift=True;self.assertEqual('completion_owner_changed',h.execute()['reason']);self.assertFalse((h.job/('remaining-stage-'+recovery.REMAINING+'.json')).exists());self.assertEqual('completion_already_recorded',h.execute()['reason'])
    def test_existing_receipt_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));path=h.job/('remaining-stage-'+recovery.REMAINING+'.json');recovery._write(path,{'existing':'foreign'});before=path.read_bytes();self.assertEqual('completion_ready_already_recorded',h.execute()['reason']);self.assertEqual(before,path.read_bytes())
    def test_old_cleanup_attempt_unroot_or_terminal_refuses_completion(self):
        # Actual generated controls with all earlier private facts inertly admitted.
        function=next(n for n in ast.parse(completion._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='completion_controls')
        for suffix in ('attempt.json','unroot.json','terminal.json','release.json'):
            with self.subTest(suffix=suffix),tempfile.TemporaryDirectory() as raw:
                job=Path(raw);recovery._write(job/('remaining-stage-'+recovery.REMAINING+'.'+suffix),{})
                scope={'private_guard':lambda:None,'native_directories':lambda:{},'BUNDLE':{'receipt':{'snapshot':{'directories':{}}}},'remaining':{'correlationId':recovery.REMAINING},'job':job,'os':os,'fail':lambda reason:(_ for _ in ()).throw(ValueError(reason))}
                exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-completion-controls>','exec'),scope)
                with self.assertRaisesRegex(ValueError,'completion_cleanup_already_recorded'):scope['completion_controls']()
    def test_actual_controls_reject_same_bytes_completion_fence_replacement(self):
        function=next(n for n in ast.parse(completion._REMOTE).body if isinstance(n,ast.FunctionDef) and n.name=='completion_controls')
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));intent=h.job/'new-intent.json';attempt=h.job/'new-attempt.json';reserve=h.job/'new-reserve.json';ready=h.job/'new-ready.json'
            recovery._write(intent,{'intent':1});recovery._write(attempt,{'attempt':1});wanted=h.pin(attempt)
            data=attempt.read_bytes();attempt.unlink();attempt.write_bytes(data);attempt.chmod(0o600)
            scope={'private_guard':lambda:None,'native_directories':lambda:{},'BUNDLE':{'receipt':{'snapshot':{'directories':{}}}},'remaining':h.remaining,'job':h.job,'os':os,'json':json,'private':lambda path,*_:path.read_bytes(),'ready_path':ready,'completion_intent':intent,'completion_intent_pin':h.pin(intent),'completion_attempt':attempt,'completion_attempt_pin':wanted,'completion_reserve':reserve,'completion_ready_pin':None,'completion_reserve_pin':None,'remaining_pin':h.pin,'fail':lambda reason:(_ for _ in ()).throw(ValueError(reason))}
            exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-completion-controls>','exec'),scope)
            with self.assertRaisesRegex(ValueError,'completion_journal_changed'):scope['completion_controls']()
    def test_frozen_parser_stock_namespace_membership_is_explicitly_authenticated(self):
        from agent_tools.tests.test_android_owned_endpoint_bind_recovery import trees,PLAN
        text,stock=trees(False);changed=text.replace('25 1 251:2','250 1 251:2').replace('mnt_id: 25','mnt_id: 250')
        with self.assertRaisesRegex(ValueError,'bind_stock_target_changed'):recovery._parse_tree(changed,PLAN,stock,False,True)
        admitted={**stock,'membership':{**stock['membership'],'fields':['250',*stock['membership']['fields'][1:]]}}
        self.assertEqual(138,len(recovery._parse_tree(changed,PLAN,admitted,False,True)['manifest']))
        with self.assertRaises(ValueError):recovery._parse_tree(changed.replace('64258:1142','64258:9999'),PLAN,admitted,False,True)
    def test_generated_metadata_dispatch_has_no_native_effect_call(self):
        tree=ast.parse(completion._REMOTE);calls=[ast.unparse(n.func) for n in ast.walk(tree) if isinstance(n,ast.Call)]
        self.assertNotIn('subprocess.run',calls);self.assertNotIn('shell',calls);self.assertNotIn('adb_call',calls)
