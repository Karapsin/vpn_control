"""Explicit fresh-owner metadata admission, preserving the consumed completion."""
from __future__ import annotations
import ast
import hashlib
import json
import os
from pathlib import Path
from . import android_endpoint_admission as endpoint
from . import android_owned_endpoint_bind_recovery as recovery
from . import android_remaining_stage_admission_completion as historical

HISTORICAL_SHA='b45fbeaa0938e2f2bbb19c7995ec7940b0ccea99bc0ce3cb684a3d58940628e6'
FAILED='a29b1f9e-6bba-48e5-8b5f-915a2d0196f4'
OWNER_PROOF='2bbfd7b3-e264-4816-bfc8-91e2d561e048'
OWNER_PROOF_SHA='dc1575c8714b63483ed89c2f8b32070de69f0a4d5f0dfc52f314d461ef614bb6'
_FRESH=r'''
FRESH=__FRESH__;fresh_owner_proof_pin=None

def fresh_owner_controls():
 global fresh_owner_proof_pin
 for suffix in ('.json','.attempt.json','.terminal.json'):
  if os.path.lexists(job/('remaining-admission-completion-'+FRESH['failedCorrelationId']+suffix)):fail('fresh_owner_prior_effect_present')
 path=job/FRESH['proofName'];pin=remaining_pin(path,131072)
 if pin['sha256']!=FRESH['proofSha256'] or fresh_owner_proof_pin is not None and pin!=fresh_owner_proof_pin:fail('fresh_owner_proof_changed')
 value=json.loads(private(path,131072))
 if value.get('kind')!='readonly-remaining-completion-owner-diagnostic' or value.get('diagnosticCorrelationId')!=FRESH['proofCorrelationId'] or value.get('failedCompletionCorrelationId')!=FRESH['failedCorrelationId'] or value.get('endpointCorrelationId')!=correlation or value.get('promoted') is not False or value.get('summary')!={'currentOwnerStable':True,'currentRuntimeOffAndFinalHistoryVerified':True,'currentRulesMatchBackup':True,'completionRemoteEffectsAbsent':True,'historicalOwnerMatchesCurrent':False} or value.get('currentPublic')!=META['post']['public'] or value.get('metadataSource')!=FRESH['historicalSource']:fail('fresh_owner_proof_changed')
 if len(value.get('observations',[]))!=2 or value['observations'][0]!=value['observations'][1] or value['observations'][0]['snapshot']['public']!=META['post']['public']:fail('fresh_owner_proof_changed')
 if value['sourceProofSha256']!=META['post']['sha256']:fail('fresh_owner_proof_changed')
 fresh_owner_proof_pin=pin
'''

def _prepare(root,completion_id):
    if completion_id in {FAILED,OWNER_PROOF}:raise ValueError('fresh_owner_distinct_correlation_required')
    bundle,meta,pins,snapshots=historical._prepare(root,completion_id)
    hp=snapshots[str(Path(historical.__file__).absolute())]
    if hp[0]['sha256']!=HISTORICAL_SHA:raise ValueError('fresh_owner_consumed_source_changed')
    proofpath=root/'.runtime/parity-evidence/android-current'/('api29-remaining-completion-owner-diagnostic-'+OWNER_PROOF+'.json');proofpin=recovery._private(proofpath,131072);proof=proofpin[0]
    if proofpin[1]!=OWNER_PROOF_SHA or proof.get('failedCompletionCorrelationId')!=FAILED or proof.get('endpointCorrelationId')!=recovery.ORIGINAL or proof.get('diagnosticCorrelationId')!=OWNER_PROOF or proof.get('promoted') is not False or proof.get('metadataSource')!=meta['source'] or proof['sourceProofSha256']!=historical.POST_SHA:raise ValueError('fresh_owner_proof_invalid')
    wanted={'completionRemoteEffectsAbsent':True,'currentOwnerStable':True,'currentRulesMatchBackup':True,'currentRuntimeOffAndFinalHistoryVerified':True,'historicalOwnerMatchesCurrent':False}
    if proof.get('summary')!=wanted or len(proof.get('observations',[]))!=2 or proof['observations'][0]!=proof['observations'][1] or proof['historicalPublic']!=meta['post']['public'] or proof['currentPublic']['revision']!=proof['historicalPublic']['revision'] or proof['currentPublic']['rulesSha256']!=proof['historicalPublic']['rulesSha256']:raise ValueError('fresh_owner_proof_invalid')
    olddir=root/'.rag_index/android-remaining-stage-completion'
    for suffix in ('.request.json','.attempt.json'):
        path=olddir/(FAILED+suffix);pin=recovery._private(path,8192)
        if pin[0].get('binding',{}).get('correlationId')!=FAILED or pin[0].get('source')!=meta['source']:raise ValueError('fresh_owner_failed_fence_changed')
        pins.append((path,pin))
    reserve=olddir/'reservation.json';reservepin=recovery._private(reserve,8192)
    if reservepin[0]!=pins[-1][1][0]:raise ValueError('fresh_owner_failed_fence_changed')
    pins.extend([(reserve,reservepin),(proofpath,proofpin)])
    ownpath=Path(__file__).absolute();snapshots[str(ownpath)]=recovery._source_snapshot(ownpath)
    historical_source=dict(meta['source']);meta['source'][str(ownpath.relative_to(root))]=snapshots[str(ownpath)][0]['sha256']
    meta['post']['public']=proof['currentPublic']
    meta['freshOwnerAdmission']={'kind':'explicit-fresh-owner-admission','failedCorrelationId':FAILED,'proofCorrelationId':OWNER_PROOF,'proofName':'remaining-completion-owner-diagnostic-'+OWNER_PROOF+'.json','proofSha256':OWNER_PROOF_SHA,'historicalSource':historical_source}
    return bundle,meta,pins,snapshots

def _program(bundle,meta,completion_id,snapshots):
    if meta.get('freshOwnerAdmission',{}).get('kind')!='explicit-fresh-owner-admission':raise ValueError('fresh_owner_admission_required')
    program=historical._program(bundle,meta,completion_id,snapshots)
    initial_tree=ast.parse(program)
    retired_operators=[node for node in initial_tree.body if isinstance(node,ast.FunctionDef) and node.name=='operate']
    if len(retired_operators)!=1:raise ValueError('fresh_owner_dependency_changed')
    # The consumed bind operator is unrelated to this metadata-only dispatch.
    program=program.replace(ast.get_source_segment(program,retired_operators[0]),'',1)
    inherited_program=program;tree=ast.parse(program)
    controls=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='completion_controls']
    snapshots_defs=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='completion_snapshot']
    if len(controls)!=1 or len(snapshots_defs)!=1:raise ValueError('fresh_owner_dependency_changed')
    node=controls[0];old=ast.get_source_segment(program,node);node.body.insert(0,ast.Expr(value=ast.Call(func=ast.Name(id='fresh_owner_controls',ctx=ast.Load()),args=[],keywords=[])))
    program=program.replace(old,ast.unparse(ast.fix_missing_locations(node)),1)
    node=snapshots_defs[0];old=ast.get_source_segment(inherited_program,node)
    returns=[item for item in ast.walk(node) if isinstance(item,ast.Return)]
    if len(returns)!=1 or not isinstance(returns[0].value,ast.Dict):raise ValueError('fresh_owner_dependency_changed')
    returns[0].value.keys.append(ast.Constant('freshOwnerProofPin'));returns[0].value.values.append(ast.Name(id='fresh_owner_proof_pin',ctx=ast.Load()))
    program=program.replace(old,ast.unparse(ast.fix_missing_locations(node)),1)
    if not program.endswith('complete_metadata()\n'):raise ValueError('fresh_owner_dispatch_changed')
    owntext=snapshots[str(Path(__file__).absolute())][1].decode('utf-8');ownast=ast.parse(owntext)
    template=ast.literal_eval(next(node.value for node in ownast.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_FRESH' for target in node.targets)))
    additions=template.replace('__FRESH__',repr(meta['freshOwnerAdmission']))
    scope={};path=Path(endpoint.__file__).absolute().with_name('android_diagnostic_composition.py');exec(compile(snapshots[str(path)][1],str(path),'exec'),scope)
    # Declare the new guard before the sole original metadata dispatch is called.
    return scope['compose_readonly_diagnostic'](program[:-len('complete_metadata()\n')],additions)+'\ncomplete_metadata()\n'

def _call(root,completion_id,action):
    # Reuse the exact reviewed local fence/transport implementation in a separate namespace.
    path=Path(historical.__file__).absolute();pin,raw=recovery._source_snapshot(path)
    if pin['sha256']!=HISTORICAL_SHA:raise ValueError('fresh_owner_consumed_source_changed')
    tree=ast.parse(raw.decode('utf-8'));nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='_call']
    if len(nodes)!=1:raise ValueError('fresh_owner_dependency_changed')
    node=nodes[0]
    matches=[item for item in ast.walk(node) if isinstance(item,ast.Constant) and item.value=='.rag_index/android-remaining-stage-completion']
    if len(matches)!=1:raise ValueError('fresh_owner_dependency_changed')
    matches[0].value='.rag_index/android-remaining-stage-fresh-owner'
    bindings=[item.value for item in ast.walk(node) if isinstance(item,ast.Assign) and len(item.targets)==1 and isinstance(item.targets[0],ast.Subscript) and isinstance(item.targets[0].value,ast.Name) and item.targets[0].value.id=='meta' and isinstance(item.targets[0].slice,ast.Constant) and item.targets[0].slice.value=='binding']
    if len(bindings)!=1 or not isinstance(bindings[0],ast.Dict):raise ValueError('fresh_owner_dependency_changed')
    bindings[0].keys.extend([ast.Constant('ownerProofSha256'),ast.Constant('failedCompletionCorrelationId'),ast.Constant('admissionKind')]);bindings[0].values.extend([ast.Constant(OWNER_PROOF_SHA),ast.Constant(FAILED),ast.Constant('explicit-fresh-owner-admission')])
    scope={'Path':Path,'os':os,'json':json,'endpoint':endpoint,'recovery':recovery,'_prepare':_prepare,'_program':_program,'POST_SHA':historical.POST_SHA}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'<reviewed-fresh-owner-local-fence>','exec'),scope)
    return scope['_call'](root,completion_id,action)

def complete(root,completion_id):return _call(root,completion_id,'remaining-admission-complete')
def status(root,completion_id):return _call(root,completion_id,'remaining-admission-status')
