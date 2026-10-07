"""Exact public shapes, private-field causal regression, no native calls."""
import copy
import json
import io
import tarfile
import unittest
from agent_tools import tmux_public_projection as projection
from agent_tools.tests import test_ssh_tmux_session_ssh as adapter_tests

CORR='da8fd22e-6d2d-4cc5-8fb8-6aae90946f47'
REQUEST={'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','baseVersion':'2.1.19','targetVersion':'2.2.2','correlationId':CORR}
SHORT={'correlationId':CORR}


def collected():
    items=[]
    for family,count in (('default',3),('arch',1)):
        paths=[family+'/fixture-receipt.json']+[family+'/packages/'+stage+'/asset-'+str(n)+'.pkg' for stage in ('base','target') for n in range(count)]
        for path in paths:items.append({'family':family,'relativePath':path,'artifactId':'sha256-'+'a'*64,'sha256':'a'*64,'size':1})
    timings=[];refs=[]
    for family in ('default','arch'):
        for stage in ('base','target'):
            for phase in ('runtime-prep','gradle','packaging'):
                name=f'linux-package-{family}-{CORR}-{phase}-{stage}.json'
                timings.append({'phase':phase,'pipelineId':'linux-package-'+family,'sha256':'b'*64,'path':'/private/host/.rag_index/linux-package-fixture-build/'+CORR+'/output/.rag_index/build-timings/'+name})
                refs.append({'path':'.rag_index/build-timings/'+name,'sha256':'b'*64})
    return {'state':'ready',**SHORT,'sourceSha':REQUEST['sourceSha'],'sourceFingerprint':'c'*64,'artifacts':items,'timingReceipts':timings,'timingReferences':refs,'replayAllowed':False}


def nested():
    return {'state':'terminal',**SHORT,'exitCode':0,'terminalPin':{'generation':[1,2,33152,1000,1000,500,1,1,1],'sha256':'a'*64},'artifactVerification':'required','replayAllowed':False}


class PublicProjectionTests(unittest.TestCase):
    def test_original_spread_private_success_is_causal_and_projection_rejects(self):
        forged={'available':True,'private':'private-secret-marker','command':'unexpected'}
        old={'tool':'vm_workflow',**forged,'ok':True}
        self.assertIn('private-secret-marker',json.dumps(old))
        with self.assertRaisesRegex(ValueError,'^tmux_public_result_invalid$'):projection.project('availability',forged,{})

    def test_availability_and_preflight_exact_current_shapes(self):
        for available in (True,False):
            value={'available':available,'reason':'available' if available else 'tmux_unavailable','nativeActionAllowed':False}
            self.assertEqual(value,projection.project('availability',value,{}))
            value={'state':'ready' if available else 'blocked','sourceSha':REQUEST['sourceSha'],'baseVersion':'2.1.19','targetVersion':'2.2.2','host':'archlinux','packageFamilies':['default','arch'],'nativeActionAllowed':False,'reason':'available' if available else 'tmux_unavailable'}
            self.assertEqual(value,projection.project('preflight',value,REQUEST))

    def test_start_consumed_and_blocked_never_project_replay(self):
        values=[{'state':'submitted',**SHORT,'replayAllowed':False}]+[{'state':'unknown',**SHORT,'replayAllowed':False,'reason':reason} for reason in ('already-journaled','submission-response-lost','submission-response-uncertain')]+[{'state':'blocked',**SHORT,'replayAllowed':False,'reason':'build-host-already-claimed'}]
        for value in values:self.assertEqual(value,projection.project('start',value,REQUEST))
        for value in values:
            for changed in ({**value,'replayAllowed':0},{**value,'private':'secret'},{**value,'correlationId':'11111111-1111-1111-1111-111111111111'}):
                with self.assertRaises(ValueError):projection.project('start',changed,REQUEST)

    def test_status_variants_and_terminal_metadata_are_bounded(self):
        values=[{'state':'ready',**SHORT,'sourceSha':REQUEST['sourceSha'],'replayAllowed':False},{'state':'running',**SHORT,'sourceSha':REQUEST['sourceSha'],'reason':'running','replayAllowed':False}]
        for reason in projection._DRIVER_REASONS:values.append({'state':'unknown',**SHORT,'reason':reason,'sourceSha':REQUEST['sourceSha'],'replayAllowed':False})
        for reason in projection._STATUS_REASONS:values.append({'state':'unknown',**SHORT,'reason':reason,'replayAllowed':False})
        for value in values:self.assertEqual(value,projection.project('status',value,SHORT))
        value={'state':'unknown',**SHORT,'sourceSha':REQUEST['sourceSha'],'reason':'explicit-collection-required','remoteTerminal':nested(),'replayAllowed':False}
        result=projection.project('status',value,SHORT)
        self.assertNotIn('remoteTerminal',result);self.assertEqual('a'*64,result['terminalObservation']['receiptSha256']);self.assertNotIn('generation',json.dumps(result))
        for attack in ({**nested(),'private':'secret'},{**nested(),'exitCode':True},{**nested(),'exitCode':2**40},{**nested(),'replayAllowed':0}):
            with self.assertRaises(ValueError):projection.project('status',{**value,'remoteTerminal':attack},SHORT)

    def test_collected_exact_ten_artifacts_and_twelve_timings_omit_private_paths(self):
        value=collected();result=projection.project('collect',value,SHORT)
        self.assertEqual(10,len(result['artifacts']));self.assertEqual(12,len(result['timingReceipts']))
        self.assertNotIn('/private/',json.dumps(result));self.assertNotIn('relativePath',json.dumps(result));self.assertNotIn('timingReferences',result)
        self.assertEqual({'default','arch'},{row['family'] for row in result['artifacts']})
        self.assertEqual({'base','target'},{row['stage'] for row in result['timingReceipts']})

    def test_nested_collection_private_extras_duplicates_and_crossed_digest_reject(self):
        attacks=[]
        for area in ('artifacts','timingReceipts','timingReferences'):
            value=collected();value[area][0]['private']='secret';attacks.append(value)
            value=collected();value[area][1]=copy.deepcopy(value[area][0]);attacks.append(value)
            value=collected();value[area].pop();attacks.append(value)
        value=collected();value['artifacts'][0]['size']=True;attacks.append(value)
        value=collected();value['artifacts'][0]['artifactId']='sha256-'+'d'*64;attacks.append(value)
        value=collected();value['timingReferences'][0]['sha256']='d'*64;attacks.append(value)
        value=collected();value['artifacts'][0]['relativePath']='../private';attacks.append(value)
        value=collected();value['timingReceipts'][0]['path']='/private/arbitrary';attacks.append(value)
        value=collected();value['sourceFingerprint']='private';attacks.append(value)
        for value in attacks:
            with self.subTest(value=value),self.assertRaises(ValueError):projection.project('collect',value,SHORT)

    def test_all_public_operations_reject_forged_private_success_and_invalid_requests(self):
        cases=[('availability',{'available':True,'reason':'available','nativeActionAllowed':False},{}),('start',{'state':'submitted',**SHORT,'replayAllowed':False},REQUEST),('status',{'state':'ready',**SHORT,'sourceSha':REQUEST['sourceSha'],'replayAllowed':False},SHORT),('collect',collected(),SHORT)]
        for operation,value,request in cases:
            for forged in ({**value,'private':'secret'},None,[],{'state':'ready'}):
                with self.subTest(operation=operation,forged=forged),self.assertRaises(ValueError):projection.project(operation,forged,request)
            with self.assertRaises(ValueError):projection.project(operation,value,{**request,'command':'anything'})
        with self.assertRaises(ValueError):projection.project('release',{},SHORT)

    def test_actual_frozen_adapter_collected_schema_passes_projection(self):
        # Existing fixture runs the fixed coordinator and complete verifier with
        # mocked remote packets. No SSH, tmux or packaging command is executed.
        fixture=adapter_tests.DriverTests('test_coordinator_injected_driver_retains_authority_before_release')
        fixture.setUp()
        try:
            fixture.start();fixture.archive()
            # The older fixture uses spaced timing JSON. Actual PhaseRecorder
            # emits sorted compact JSON plus newline; preserve that producer's
            # exact bytes for the canonical timing-publication path.
            out=io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(fixture.remote.archive),mode='r:') as old,tarfile.open(fileobj=out,mode='w') as new:
                for item in old:
                    raw=old.extractfile(item).read()
                    if item.name.startswith('.rag_index/build-timings/'):
                        raw=(json.dumps(json.loads(raw),sort_keys=True,separators=(',',':'))+'\n').encode()
                    item.size=len(raw);new.addfile(item,io.BytesIO(raw))
            fixture.remote.archive=out.getvalue();value=fixture.driver.collect_existing(fixture.req)
            result=projection.project('collect',value,{'correlationId':fixture.req['correlationId']})
            self.assertEqual(10,len(result['artifacts']));self.assertEqual(12,len(result['timingReceipts']));self.assertEqual(1,fixture.remote.builds)
        finally:fixture.doCleanups()

    def test_boolean_zero_and_reason_schema_substitution_reject(self):
        availability={'available':True,'reason':'available','nativeActionAllowed':False}
        for changed in ({**availability,'available':1},{**availability,'nativeActionAllowed':0},{**availability,'reason':'private'},{**availability,'reason':'tmux_unavailable'}):
            with self.assertRaises(ValueError):projection.project('availability',changed,{})
        for changed in ({'state':'unknown',**SHORT,'sourceSha':REQUEST['sourceSha'],'reason':'missing-journal','replayAllowed':False},{'state':'unknown',**SHORT,'reason':'prepared-not-released','replayAllowed':False}):
            with self.assertRaises(ValueError):projection.project('status',changed,SHORT)
        with self.assertRaises(ValueError):projection.project('preflight',{}, {**REQUEST,'targetVersion':True})
