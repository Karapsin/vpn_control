"""Actual normal reservation callers over owned fixture CAS; no native effects.

Native observations below are inert typed fixtures. Their current timestamps
exercise policy freshness only and never relabel the preserved native receipt.
"""
import ast,copy,hashlib,json,os,sys,tempfile,time,types,unittest,uuid
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
FIXTURES=Path(__file__).parent/'fixtures/windows_conservative_policy'
from agent_tools import native_environment as environments
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests.test_native_vm_spec import request as spec_request
GIB=1024**3
BOOT='25515f23-b966-4c3a-ae63-d38452375578'
BEFORE=os.environ.get('VPN_CONTROL_WINDOWS_POLICY_BEFORE')
SOURCE_OVERRIDES={}
BEFORE_PINS={'windows_vm_resources': '2659a18cd8683c8d3b1b5ff749803c052fcf7e17dc1e669d2d57fb67c67396a0', 'windows_vm_deploy': '435a988592590b3b0110db550ab4d2e22212999bee5501e9b0cecb273c381d77', 'readiness_resources': '45cc6144e9f330c288576214d9f92d96641ee615421ab3b0e43c620d420cc05a'}

def load(name,after,*,portable_value=False):
    path=ROOT/'agent_tools'/(name+'.py')if after else FIXTURES/(name+'.py.before.source')
    raw=SOURCE_OVERRIDES.get(name,path.read_bytes())if after else path.read_bytes()
    if not after and hashlib.sha256(raw).hexdigest()!=BEFORE_PINS[name]:raise ValueError('whole-policy-beforeimage-changed')
    module=types.ModuleType('agent_tools._policy_'+name+('_after'if after else'_before'))
    module.__package__='agent_tools';module.__file__=str(ROOT/'agent_tools'/(name+'.py'))
    sys.modules[module.__name__]=module
    code_path=FIXTURES/(name+'.py.after.source')if after and name in SOURCE_OVERRIDES else path
    if portable_value:
        # The complete Linux producer has POSIX imports. These unchanged pure
        # definitions are the actual component bodies under portable test.
        wanted={'measurement','_conservative_policy_value','conservative_policy_measurement','validate_conservative_policy_measurement'}
        nodes=[node for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef)and node.name in wanted]
        if {node.name for node in nodes}!=wanted:raise AssertionError('policy value definition missing')
        module.copy=copy;module.json=json
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(code_path),'exec'),vars(module))
    else:exec(compile(raw,str(code_path),'exec',dont_inherit=True),vars(module))
    return module

def observation(deployment=None,*,include_own=False,physical=64*GIB,available=48*GIB):
    now=time.time_ns()//1000000
    vms=[{'pid':pid,'startTicks':pid+1,'sessionId':pid,'uid':1000,'commandSha256':str(index)*64,'executableGeneration':[1]*9,'configuredMemoryBytes':6*GIB}for index,pid in enumerate((101,102),1)]
    if include_own:vms.append({'pid':201,'startTicks':202,'sessionId':201,'uid':1000,'commandSha256':'3'*64,'executableGeneration':[1]*9,'configuredMemoryBytes':4*GIB})
    sample=lambda stamp:{'observedAtUnixMs':stamp,'availableMemoryBytes':available,'psi':'normal','psiSomeAvg10':0.,'psiFullAvg10':0.,'vmstat':{'pswpin':0,'pswpout':0,'oomKill':0}}
    return {'schemaVersion':1,'deploymentId':deployment or str(uuid.uuid4()),'mode':'host-resources','state':'resources-observed','reason':None,'hostBootId':BOOT,'vms':vms,'physicalMemoryBytes':physical,'swapUsedBytes':0,'samples':[sample(now-100),sample(now)],'freeDiskBytes':300*GIB,'inventoryComplete':True,'nativeActionAllowed':False,'replayAllowed':False}

def unload_fixtures():
    for name in list(sys.modules):
        if name.startswith('agent_tools._policy_'):sys.modules.pop(name,None)

def old_claims():
    rows=[]
    for index,(memory,state)in enumerate(((6,'running'),(6,'running'),(6,'running'),(2,'running'),(4,'pending')),1):
        rows.append({'id':'env-inert-'+str(index),'token':'NONSECRET-owned-fixture-'+str(index),'hostAlias':'archlinux','environment':'old-inert-'+str(index),'operator':'owned-fixture','requestedMemoryBytes':memory*GIB,'allocationState':state,'createdAtUnixMs':1,'activeJob':'unknown','activeJobEvidence':None,'observationMaximumAgeMs':60000,'originalOutcome':'UNKNOWN'})
    return rows

class PolicyValueTests(unittest.TestCase):
    def setUp(self):self.addCleanup(unload_fixtures);self.facts=load('windows_vm_resources',True,portable_value=True)
    def test_native_observation_and_every_held_claim_are_retained_truthfully(self):
        native=observation();before=copy.deepcopy(native);mapping=[{'reservationId':r['id'],'memoryBytes':r['requestedMemoryBytes']}for r in old_claims()if r['allocationState']=='running'];policy=self.facts.conservative_policy_measurement(native,mapping)
        self.assertEqual(native,before);self.assertEqual(policy['runningConfiguredMemoryBytes'],32*GIB)
        self.assertEqual(policy['policyDerivation']['nativeObservation'],native)
        self.assertEqual(policy['policyDerivation']['nativeMeasurement'],self.facts.measurement(native))
        self.assertEqual(policy['policyDerivation']['addedRunningClaimBytes'],20*GIB)
        self.assertEqual(policy['policyDerivation']['deduplicatedBytes'],0)
        self.assertFalse(policy['policyDerivation']['claimStatesChanged']);self.assertFalse(policy['policyDerivation']['historicalOutcomesChanged'])
        self.facts.validate_conservative_policy_measurement(policy,native,mapping)
        policy['policyDerivation']['nativeObservation']['vms'].clear();self.assertEqual(native,before)
    def test_unrepresented_native_actor_is_fully_added_to_all_claims(self):
        native=observation();extra=copy.deepcopy(native['vms'][0]);extra.update(pid=999,startTicks=1000,sessionId=999,configuredMemoryBytes=2*GIB);native['vms'].append(extra)
        mapping=[{'reservationId':r['id'],'memoryBytes':r['requestedMemoryBytes']}for r in old_claims()if r['allocationState']=='running']
        policy=self.facts.conservative_policy_measurement(native,mapping)
        self.assertEqual(policy['runningConfiguredMemoryBytes'],34*GIB)
        self.assertEqual(policy['policyDerivation']['nativeMeasurement']['runningConfiguredMemoryBytes'],14*GIB)
        from agent_tools import vm_workflow
        plan=vm_workflow.admit_plan(policy,requested_memory_bytes=4*GIB,headroom_bytes=8*GIB,reservations=[{'id':'owned-pending','memoryBytes':4*GIB}])
        self.assertEqual(plan['requiredMemoryBytes'],50*GIB)
    def test_unknown_malformed_and_ambiguous_inputs_refuse(self):
        native=observation();claim={'reservationId':'owned','memoryBytes':GIB}
        for changed in (None,{},dict(native,state='unknown'),dict(native,inventoryComplete=False)):
            with self.subTest(kind=type(changed).__name__),self.assertRaises(ValueError):self.facts.conservative_policy_measurement(changed,[claim])
        for mapping in (None,[claim,claim],[dict(claim,memoryBytes=True)],[dict(claim,memoryBytes=0)],[dict(claim,memoryBytes=-1)],[dict(claim,reservationId='')],[dict(claim,extra=True)]):
            with self.subTest(mapping=mapping),self.assertRaises(ValueError):self.facts.conservative_policy_measurement(native,mapping)
    def test_changed_cross_fields_and_unknown_policy_cannot_reach_writer(self):
        native=observation();mapping=[{'reservationId':'owned','memoryBytes':GIB}];policy=self.facts.conservative_policy_measurement(native,mapping)
        for mode in ('native','configured','held','mapping','zero','kind','schema','source','extra'):
            changed=copy.deepcopy(policy)
            if mode=='native':changed['policyDerivation']['nativeObservation']['vms'][0]['startTicks']+=1
            if mode=='configured':changed['runningConfiguredMemoryBytes']-=1
            if mode=='held':changed['policyDerivation']['addedRunningClaimBytes']-=1
            if mode=='mapping':changed['policyDerivation']['runningAllocationMapping'][0]['reservationId']='foreign'
            if mode=='zero':changed['policyDerivation']['deduplicatedBytes']=1
            if mode=='kind':changed['policyDerivation']['kind']='native-observed'
            if mode=='schema':changed['policyDerivation']['schemaVersion']=True
            if mode=='source':changed['policyDerivation']['nativeMeasurement']['samples'][0]['observedAtUnixMs']+=1
            if mode=='extra':changed['acceptedWithoutProof']=True
            with self.subTest(mode=mode),self.assertRaisesRegex(ValueError,'derivation_changed'):self.facts.validate_conservative_policy_measurement(changed,native,mapping)

@unittest.skipUnless(os.name=='posix','Actual private reservation/journal CAS uses POSIX ownership and flock')
class PolicyCallerTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(unload_fixtures)
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup);self.root=Path(self.temporary.name).resolve();self.root.chmod(0o700)
        self.facts=load('windows_vm_resources',True);self.deploy=load('windows_vm_deploy',BEFORE!='deploy');self.resource=load('readiness_resources',BEFORE!='resources')
        self.resource.facts=self.facts;self.context=ExitStack();self.addCleanup(self.context.close)
        import agent_tools
        self.context.enter_context(mock.patch.object(agent_tools,'windows_vm_resources',self.facts))
        self.context.enter_context(mock.patch.dict(sys.modules,{'agent_tools.windows_vm_resources':self.facts}))
        self.old=old_claims()
        with environments._LockedState(self.root)as locked:locked.state['reservations']=copy.deepcopy(self.old);locked.save()
        self.spec=spec_request();self.spec.update(deploymentId=str(uuid.uuid4()),host='archlinux',root='/home/owner/owned-new-policy-vm',memoryMiB=4096,cpus=4,headroomMiB=8192);self.spec=FreshWindowsVmSpec.parse(self.spec)
        self.own_running=False;self.physical=64*GIB
        authority=SimpleNamespace(config=SimpleNamespace(hosts={'archlinux':object()}),guard=lambda:None)
        guard=mock.MagicMock();guard.__enter__.return_value=authority
        self.context.enter_context(mock.patch.object(self.deploy.direct,'Guard',return_value=guard))
        self.context.enter_context(mock.patch.object(self.deploy,'resources',side_effect=lambda root,spec,cred:observation(spec['deploymentId'],include_own=self.own_running,physical=self.physical)))
        self.context.enter_context(mock.patch.object(self.deploy,'_execute',side_effect=AssertionError('VM dispatch forbidden by owned test')))
        def remote(root,target,mode,credential_file=None,**kwargs):
            if mode=='peer':return {'state':'peer-observed','platform':'linux','hostBootId':BOOT}
            self.assertEqual(mode,'host-resources');return observation(target.deployment_id,include_own=self.own_running,physical=self.physical)
        self.context.enter_context(mock.patch.object(self.resource,'_remote_observation',side_effect=remote))
    def rows(self):
        with environments._LockedState(self.root)as locked:return copy.deepcopy(locked.state['reservations'])
    def assert_old_preserved(self):self.assertEqual(self.rows()[:len(self.old)],self.old)
    def raw_prepare(self,caller=None):return (caller or self.deploy)._prepare_reservation(self.root,self.spec,'/INERT_HOST_CREDENTIAL')
    def resource_prepare(self,caller=None):return (caller or self.resource).prepare_start(self.root,host='archlinux',machine_uuid=self.spec.deployment_id,fixture_root=self.spec.root,credential_file='/INERT_HOST_CREDENTIAL',requested_memory_bytes=4*GIB,headroom_bytes=8*GIB,operation_id=str(uuid.uuid4()))
    def test_whole_deploy_prepare_admits_conservative_policy_and_preserves_unknowns(self):
        before=observation(self.spec.deployment_id);prepared=self.raw_prepare();policy=prepared['request']['measurement']
        self.assertEqual(policy['runningConfiguredMemoryBytes'],32*GIB);self.assertEqual(policy['policyDerivation']['nativeObservation']['vms'],before['vms'])
        self.assertEqual(prepared['pending'],[{'id':self.old[-1]['id'],'memoryBytes':4*GIB}]);self.assert_old_preserved()
    def test_whole_deploy_mark_running_keeps_prepare_policy_semantics(self):
        fixed=load('windows_vm_deploy',True)
        with mock.patch.object(fixed,'resources',side_effect=lambda root,spec,cred:observation(spec['deploymentId'],include_own=self.own_running)),mock.patch.object(fixed.direct,'Guard',self.deploy.direct.Guard):prepared=self.raw_prepare(fixed)
        self.own_running=True;result=self.deploy._mark_running(self.root,self.spec,prepared,'/INERT_HOST_CREDENTIAL')
        self.assertEqual(result['reservation']['allocationState'],'running');self.assert_old_preserved()
    def test_whole_prepare_start_keeps_real_plan_and_normal_gate_consistent(self):
        admission=self.resource_prepare()
        with admission._journal().locked(deadline=admission.deadline)as journal:prepared=admission._prepared(journal)
        self.assertEqual(prepared['plan']['requiredMemoryBytes'],48*GIB)
        self.assertEqual(prepared['request']['measurement']['runningConfiguredMemoryBytes'],32*GIB)
        self.assertEqual(prepared['census']['vms'],observation()['vms']);self.assert_old_preserved()
    def test_whole_submitting_update_keeps_policy_separate_from_native_snapshot(self):
        fixed=load('readiness_resources',True);fixed.facts=self.facts
        with mock.patch.object(fixed,'_remote_observation',side_effect=self.resource._remote_observation):admission=self.resource_prepare(fixed)
        selected=self.resource.ResourceAdmission(admission.root,admission.target,admission.machine_uuid,admission.operation_id,admission.directory,admission.credential_file,admission.deadline)
        original=environments.reserve_environment;captured=[]
        def record(root,request):captured.append(copy.deepcopy(request));return original(root,request)
        with mock.patch.object(environments,'reserve_environment',side_effect=record):self.assertTrue(selected.mark_submitting())
        policy=captured[0]['measurement'];self.assertEqual(policy['runningConfiguredMemoryBytes'],32*GIB)
        self.assertEqual(policy['policyDerivation']['nativeMeasurement']['runningConfiguredMemoryBytes'],12*GIB)
        self.assertEqual(selected.submission_snapshot()['census']['vms'],observation()['vms']);self.assert_old_preserved()
    def test_whole_resource_mark_running_cannot_fail_after_admitted_submission(self):
        fixed=load('readiness_resources',True);fixed.facts=self.facts
        with mock.patch.object(fixed,'_remote_observation',side_effect=self.resource._remote_observation):admission=self.resource_prepare(fixed);self.assertTrue(admission.mark_submitting())
        selected=self.resource.ResourceAdmission(admission.root,admission.target,admission.machine_uuid,admission.operation_id,admission.directory,admission.credential_file,admission.deadline)
        self.own_running=True;result=selected.mark_running({'pid':201,'startTicks':202})
        self.assertEqual(result['reservation']['allocationState'],'running');self.assert_old_preserved()
    def test_real_canonical_capacity_refuses_conservative_overcommit(self):
        self.physical=47*GIB
        with self.assertRaises(environments.NativeEnvironmentError):self.raw_prepare()
        self.assertEqual(self.rows(),self.old)
    def test_tampered_derived_field_is_refused_before_real_reservation_writer(self):
        def mutate(policy,deadline):policy['runningConfiguredMemoryBytes']-=1
        with mock.patch.object(self.deploy,'_wait_for_resource_clock',side_effect=mutate),self.assertRaisesRegex(ValueError,'derivation_changed'):self.raw_prepare()
        self.assertEqual(self.rows(),self.old)
    def test_inventory_cas_still_refuses_a_changed_original_claim(self):
        original=environments.reserve_environment
        def changed(root,request):
            with environments._LockedState(root)as locked:locked.state['reservations'][0]['requestedMemoryBytes']+=GIB;locked.save()
            return original(root,request)
        with mock.patch.object(environments,'reserve_environment',side_effect=changed),self.assertRaisesRegex(environments.NativeEnvironmentError,'inventory changed'):self.raw_prepare()
        self.assertEqual(len(self.rows()),len(self.old))

if __name__=='__main__':unittest.main()
