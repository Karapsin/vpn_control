"""Explicit fresh owner readmission versus concurrent transaction owner drift."""
import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from agent_tools import android_remaining_stage_fresh_owner_admission as fresh
from agent_tools import android_remaining_stage_admission_completion as historical
from agent_tools import android_owned_endpoint_bind_recovery as recovery
from agent_tools.tests.test_android_remaining_stage_admission_completion import CompletionHarness,CID

OLD={'owner':'old-epoch','revision':0,'rulesSha256':'a'*64}
CURRENT={**OLD,'owner':'current-epoch'}

def execute_snapshot(source,expected,current):
    function=next(node for node in ast.parse(source).body if isinstance(node,ast.FunctionDef) and node.name=='completion_snapshot')
    scope={'completion_controls':lambda *_:None,'remaining_snapshot':lambda:{'public':dict(current),'native':{'stageGeneration':'stage'},'records':{}},'META':{'post':{'public':expected,'name':'proof'}},'BUNDLE':{'baseline':{'stageGeneration':'stage'}},'completion_tree':lambda inside:'inside' if inside else 'outside','remaining_pin':lambda *_:{'sha256':'proof'},'job':Path('/inert'),'native_directories':lambda:{},'fresh_owner_proof_pin':{'sha256':'owner-proof'},'fail':lambda reason:(_ for _ in ()).throw(ValueError(reason))}
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-completion-snapshot>','exec'),scope)
    return scope['completion_snapshot']()

class FreshOwnerAdmissionTest(unittest.TestCase):
    def program(self):
        root=Path(fresh.__file__).resolve().parent.parent
        paths=(Path(recovery.__file__).absolute(),Path(fresh.endpoint.__file__).absolute(),Path(historical.__file__).absolute(),Path(fresh.__file__).absolute(),root/'agent_tools/android_diagnostic_composition.py')
        snapshots={str(path):recovery._source_snapshot(path) for path in paths}
        meta={'freshOwnerAdmission':{'kind':'explicit-fresh-owner-admission'},'source':{},'post':{'public':CURRENT}}
        program=fresh._program({'binding':{'correlationId':CID},'source':{},'proofs':[]},meta,CID,snapshots)
        return program
    def test_measured_epoch_change_before_new_transaction_requires_explicit_fresh_proof(self):
        # Frozen old behavior is preserved; its historical owner pin rejects a new epoch.
        with self.assertRaisesRegex(ValueError,'completion_owner_changed'):execute_snapshot(historical._REMOTE,OLD,CURRENT)
        result=execute_snapshot(self.program(),CURRENT,CURRENT)
        self.assertEqual(CURRENT,result['remainingSnapshot']['public']);self.assertEqual({'sha256':'owner-proof'},result['freshOwnerProofPin'])
    def test_owner_drift_during_new_transaction_still_rejects(self):
        with self.assertRaisesRegex(ValueError,'completion_owner_changed'):execute_snapshot(self.program(),CURRENT,{**CURRENT,'owner':'changed-again'})
    def test_without_explicit_fresh_mode_generation_refuses(self):
        with self.assertRaisesRegex(ValueError,'fresh_owner_admission_required'):fresh._program({}, {}, CID,{})
    def test_actual_added_controls_reject_prior_remote_effect_or_proof_replacement(self):
        function=next(node for node in ast.parse(fresh._FRESH).body if isinstance(node,ast.FunctionDef) and node.name=='fresh_owner_controls')
        with tempfile.TemporaryDirectory() as raw:
            job=Path(raw);proofpath=job/'proof.json';freshmeta={'failedCorrelationId':fresh.FAILED,'proofName':'proof.json','proofSha256':'a'*64}
            scope={'FRESH':freshmeta,'job':job,'os':os,'fresh_owner_proof_pin':None,'remaining_pin':lambda *_:{'sha256':'b'*64},'fail':lambda reason:(_ for _ in ()).throw(ValueError(reason))}
            exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-fresh-controls>','exec'),scope)
            with self.assertRaisesRegex(ValueError,'fresh_owner_proof_changed'):scope['fresh_owner_controls']()
            path=job/('remaining-admission-completion-'+fresh.FAILED+'.attempt.json');path.write_text('effect')
            with self.assertRaisesRegex(ValueError,'fresh_owner_prior_effect_present'):scope['fresh_owner_controls']()
    def test_actual_fresh_proof_accepts_new_epoch_then_rejects_same_bytes_replacement(self):
        function=next(node for node in ast.parse(fresh._FRESH).body if isinstance(node,ast.FunctionDef) and node.name=='fresh_owner_controls')
        with tempfile.TemporaryDirectory() as raw:
            job=Path(raw);path=job/'proof.json';historical_source={'historical':'b45'}
            proof={'kind':'readonly-remaining-completion-owner-diagnostic','diagnosticCorrelationId':fresh.OWNER_PROOF,'failedCompletionCorrelationId':fresh.FAILED,'endpointCorrelationId':recovery.ORIGINAL,'promoted':False,'summary':{'currentOwnerStable':True,'currentRuntimeOffAndFinalHistoryVerified':True,'currentRulesMatchBackup':True,'completionRemoteEffectsAbsent':True,'historicalOwnerMatchesCurrent':False},'currentPublic':CURRENT,'metadataSource':historical_source,'sourceProofSha256':historical.POST_SHA,'observations':[{'snapshot':{'public':CURRENT}},{'snapshot':{'public':CURRENT}}]}
            recovery._write(path,proof)
            def pin(path,*_):
                _,sha,generation=recovery._private(path);return {'sha256':sha,'generation':generation}
            admitted=pin(path)
            owner={'failedCorrelationId':fresh.FAILED,'proofName':path.name,'proofSha256':admitted['sha256'],'proofCorrelationId':fresh.OWNER_PROOF,'historicalSource':historical_source}
            scope={'job':job,'os':os,'json':json,'FRESH':owner,'META':{'post':{'public':CURRENT,'sha256':historical.POST_SHA}},'correlation':recovery.ORIGINAL,'fresh_owner_proof_pin':None,'remaining_pin':pin,'private':lambda path,*_:path.read_bytes(),'fail':lambda reason:(_ for _ in ()).throw(ValueError(reason))}
            exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-fresh-proof>','exec'),scope)
            scope['fresh_owner_controls']();self.assertEqual(admitted,scope['fresh_owner_proof_pin'])
            rawbytes=path.read_bytes();path.unlink();path.write_bytes(rawbytes);path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'fresh_owner_proof_changed'):scope['fresh_owner_controls']()
    def test_new_transaction_uses_separate_namespace_and_compatible_fenced_metadata(self):
        with tempfile.TemporaryDirectory() as raw:
            h=CompletionHarness(Path(raw));h.snapshot['public']=CURRENT;result=h.execute()
            self.assertEqual('ready',result['state']);self.assertEqual(h.remaining,result['remaining']['binding']);self.assertFalse(result['replayAllowed']);self.assertEqual([],h.effects)
            self.assertEqual('completion_already_recorded',h.execute()['reason'])
    def test_generated_program_does_not_dispatch_consumed_bind_operator(self):
        program=self.program();tree=ast.parse(program)
        self.assertFalse(any(isinstance(n,ast.FunctionDef) and n.name=='operate' for n in tree.body))
        calls=[n.func.id for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        self.assertNotIn('operate',calls)
        self.assertIn('fresh_owner_controls',calls)
