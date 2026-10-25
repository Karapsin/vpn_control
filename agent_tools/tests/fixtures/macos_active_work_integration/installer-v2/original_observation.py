"""OFFGRAPH provider-owned original observation association. No new dispatch.

Load compiled held bytes in the SAME SourceSession package as the Mac modules.
The sole factory accepts an actual live MacCustody, not a DTO/token/skip flag.
It must run before append. Source-only tests use controlled actual class seams;
this module has no native/public enrollment qualification.
"""
from . import readiness_tart_macos_registry as mac
from . import readiness_qemu_jobs as protocol
from . import readiness_tart_macos_lease_bridge as bridge
from . import readiness_guest_jobs as guest_workflow
from . import readiness_lease_workflow as lease_workflow
from . import readiness_tart_macos_lease_executor as lease_executor
from . import readiness_tart_macos_lease_qualification as qualification
from contextlib import ExitStack
import ast,base64,hashlib,json,os,stat,sys,time,types
from pathlib import Path

_CODE=sys._getframe().f_code
ROLE='fixed_active_work_diagnostic_install'
INSTALL_OPERATION='ca6919f5-137e-4a1e-a68b-bef546c230da'
PUBLICATION_PURPOSE='macos-active-work-publication-v1'

def need(value,reason):
    if not value:raise mac.MacBlocked(reason)
def deny(*args,**kwargs):raise mac.MacBlocked('macos_original_observation_only')
class _Association:
    """No backend/custody/executor/argv/payload authority exposed publicly."""
    __slots__=('_c','_held','_self','_admission','_plan','_plan_ref','_publisher','_rows','_files','_descriptor','_proofs','_closed','_owns')
    def __init__(self):raise mac.MacBlocked('macos_original_factory_required')
    def _source_guard(self):
        need(not self._closed,'macos_original_observer_closed')
        self._self.guard()
        need(_CODE==compile(self._self.body,__file__,'exec',dont_inherit=True),'macos_original_observer_executed_source_changed')
        for proof in self._proofs:proof.guard()
    def _retain(self,path,pin):
        for held in self._proofs:
            if held.path==Path(path):
                need(list(held.generation)==pin['generation']and hashlib.sha256(held.body).hexdigest()==pin['sha256'],'macos_original_retained_reference_changed')
                held.guard();return held
        held=self._held.enter_context(mac.PublicProof(path,pin));self._proofs.append(held);return held
    def _guard(self,deadline):
        """Whole actual MacCustody.guard boundary, changing ONLY the source
        view to its source-owned bounded pending-publication observer view.
        Caller never receives a public guard bypass or a mutable MacCustody.
        """
        mac._limit(deadline);self._source_guard();c=self._c
        c._operator.guard()  # Actual same target/operator flock is mandatory.
        c._check_source_custody(c.descriptor)
        current,pin=c._registry._json(c._descriptor_path)
        need(current==c.descriptor==self._descriptor and pin==c.descriptor_pin,'macos_registration_changed')
        for held in c._records:held.guard()
        for held in c._artifact_holders:held.guard()
        for held in c._credentials.values():held.guard()
        # _record() was held once during factory construction. Its actual
        # holder is in c._records above; repeated status must not leak more FDs.
        plan=self._plan
        need(plan['originalRun']==c.run_intent['operationId']and plan['predecessor']=={'path':str(c._descriptor_path),'pin':c.descriptor_pin},'macos_publication_association_changed')
        publisher=self._publication_status()
        # UNKNOWN publication remains idle-blocking and cannot grant any new
        # dispatch, but it must not strand ORIGINAL read-only status/collect.
        # Its immutable original intent/program/root remain mandatory here.
        need(publisher['state']in{'running','terminal','unknown'},'macos_publication_original_missing')
        # Both censuses occur while the real provider publication/operator lock
        # is held. It is checked again after the second census, before any call.
        self._admission.observe_pending_subset(c.run_intent['plan']['bootstrapShare'],self._rows,self._files)
        c._operator.guard()
        created=c.create_owner.observe();need(created['state']=='terminal'and created['terminal']['exitCode']==0,'macos_original_create_unknown')
        original=c.run_owner.observe();need(original['state']=='running','macos_original_run_unknown')
        mac.jobs._binding_live(c.host_binding)
        need(mac.jobs._birth(c.wrapper_actor['pid'])==c.wrapper_actor['birth']and mac._parent(c.wrapper_actor['pid'],deadline)==original['owner']['pid']and mac._parent(c.actor['pid'],deadline)==c.wrapper_actor['pid'],'macos_original_actor_lineage_changed')
        c._public_actor.guard(deadline=deadline)
        need(mac._listener(c.actor['pid'],c.actor['birth'],c.endpoint['port'],deadline)==c.descriptor['listener'],'macos_endpoint_listener_changed')
        c._resource_claims();self._source_guard()
        return (c.binding.target,c.binding.machine,c.actor['pid'],c.actor['birth'],c.run_intent['operationId'])
    def _publication_status(self):
        owner=self._publisher;J=mac.jobs
        J._root(owner.root,owner.generation);job=owner.root/owner.operation_id
        intent=J._intent(job,owner.operation_id,owner.binding)
        need((intent['purpose'],intent['programSha256'],intent['streamLimit'])==(PUBLICATION_PURPOSE,owner.program.digest,owner.program.stream_limit)and J._read(job/'program.py',J.MAX_PROGRAM_BYTES)==owner.program.source and J._read(job/'owner.py',J.MAX_PROGRAM_BYTES)==(owner.historical_owner_source if owner.historical_owner_source is not None else J.owner_source()),'macos_publication_program_changed')
        result=J.observe(owner.root,owner.operation_id,owner.binding,generation=owner.generation)
        if result['state']=='terminal':J.collect(owner.root,owner.operation_id,owner.binding,generation=owner.generation)
        return result
    def _call(self,source,deadline):
        # Source is produced ONLY by the fixed internal methods below. There is
        # no public execute/source/argv argument on this object.
        c=self._c;argv,payload=protocol.stdin_command(source)
        with c.operator(deadline=deadline):
            before=self._guard(deadline)
            command=[c.binding.tart_binary,'exec','-i',c.binding.vm_name,c.binding.guest_python,*argv[1:]]
            reply=c._native_call(command,payload,deadline)
            need(self._guard(deadline)==before,'macos_original_connection_changed')
            return reply
    def host_status(self,operation,*,deadline):
        c=self._c;operation=mac.jobs._uuid(operation)
        with c.operator(deadline=deadline):
            self._guard(deadline)
            intent=mac.jobs._intent(c.run_owner.root/operation,operation,c.host_binding)
            owner=mac.OriginalOwner(c.run_owner.root,c.run_owner.generation,operation,c.host_binding,mac.jobs.Program(intent['purpose'],mac.jobs._read(c.run_owner.root/operation/'program.py',mac.jobs.MAX_PROGRAM_BYTES),intent['streamLimit']))
            need(mac.jobs._read(owner.root/operation/'owner.py',mac.jobs.MAX_PROGRAM_BYTES)==mac.jobs.owner_source(),'macos_original_owner_source_changed')
            result=mac.jobs.observe(owner.root,operation,c.host_binding,generation=owner.generation)
            if result['state']=='terminal':owner.observe()
            self._guard(deadline);return result
    def host_collect(self,operation,*,deadline):
        c=self._c;operation=mac.jobs._uuid(operation)
        with c.operator(deadline=deadline):
            self._guard(deadline);status=self.host_status(operation,deadline=deadline)
            need(status['state']=='terminal','macos_original_not_terminal')
            result=mac.jobs.collect(c.run_owner.root,operation,c.host_binding,generation=c.run_owner.generation)
            self._guard(deadline);return result
    def guest_status(self,fixture_id,operation,*,deadline):
        c=self._c;operation=mac.jobs._uuid(operation);c._registry._id(fixture_id)
        # The original discriminant reads the actual existing host intent. A
        # caller cannot supply binding/namespace/spec/source or create a job.
        original=guest_workflow._posix_original(c.root,fixture_id,operation)
        need(original is not None,'macos_original_guest_admission_missing')
        namespace=c.load_guest_namespace();need(original['namespace']==namespace,'macos_original_guest_namespace_changed')
        bound=mac.jobs.MachineBinding.from_dict(original['binding'])
        need((bound.target,bound.machine,bound.account)==(c.binding.target,c.binding.machine,str(c.binding.ordinary_uid)),'macos_original_guest_target_changed')
        path=c.root/'.runtime/readiness-guest-jobs'/fixture_id/operation/'intent.json'
        self._retain(path,c._registry._json(path)[1])
        source=protocol.operation_program(namespace,operation,original['binding'],submit=False)
        return self._call(source,deadline)
    def guest_collect(self,fixture_id,operation,*,deadline):
        reply=self.guest_status(fixture_id,operation,deadline=deadline)
        need(type(reply.returncode)is int and reply.returncode==0,'macos_original_reply_unknown')
        value=json.loads(reply.stdout)
        need(value.get('status',{}).get('state')=='terminal'and set(value)>={'stdout','stderr'},'macos_original_not_terminal')
        return reply
    def _lease(self,fixture_id,operation,deadline):
        c=self._c;operation=mac.jobs._uuid(operation);c._registry._id(fixture_id)
        path=c.root/'.rag_index/readiness-leases/admissions'/fixture_id/(operation+'.json')
        value,pin=c._registry._json(path)
        value=lease_workflow._external_admission(value,fixture_id,operation)
        need(value['provider']=='tart-macos','macos_original_lease_provider_changed')
        snapshot=value['executor']
        registration=snapshot['registration'];original_fixture=c._registry._id(snapshot['fixtureId'])
        original_path=c.root/'.rag_index/readiness-fixtures'/(original_fixture+'.json')
        need(registration['path']==str(original_path),'macos_original_lease_epoch_changed')
        old,old_pin=c._registry._json(original_path);need(old_pin==registration['pin'],'macos_original_lease_epoch_changed')
        def physical(d):
            result={key:value for key,value in d.items()if key not in{'fixtureId','sources','sourceAdmission'}}
            result['sourceAdmission']={key:value for key,value in d['sourceAdmission'].items()if key!='activeWorkInstall'}
            return result
        need(physical(old)==physical(c.descriptor),'macos_original_lease_physical_changed')
        self._retain(original_path,old_pin)
        need((snapshot['binding']['target'],snapshot['binding']['machine'],snapshot['binding']['account'])==(c.binding.target,c.binding.machine,str(c.binding.ordinary_uid)),'macos_original_lease_target_changed')
        roots={'/private/var/tmp/vc-recovery-macos-leases':'v1','/private/var/tmp/vc-recovery-macos-leases-v2':'v2'}
        need(snapshot['namespace'].get('root')in roots and c.load_lease_namespace(roots[snapshot['namespace']['root']])==snapshot['namespace'],'macos_original_lease_namespace_changed')
        self._retain(path,pin)
        capsule_path,capsule_pin=mac._reference(snapshot['capsule'],c.root)
        need(capsule_path.is_relative_to(c.lifecycle_root/'lease-executors'),'macos_original_lease_capsule_route')
        held=self._retain(capsule_path,capsule_pin)
        capsule=held.value();need(capsule['binding']==snapshot['binding']and capsule['namespace']==snapshot['namespace'],'macos_original_lease_capsule_changed')
        # Reuse the exact native-evidence parser. Its public load() wrapper
        # accepts ordinary admission custody; this ORIGINAL-only factory uses
        # the same pure parser under our private actual physical/operator guard.
        # It yields no acquisition authority and never accepts a caller proof.
        self._guard(deadline)
        proof=qualification._load(c,snapshot['qualification'])
        original=json.loads(proof.raw)
        need(set(capsule)==set(original)and capsule['namespace']==proof.namespace and all(capsule[key]==original[key]for key in('schemaVersion','provider','bridge','files'))and all(capsule['binding'][key]==original['binding'][key]for key in('target','machine','account','principal','home')),'macos_original_native_producer_changed')
        self._guard(deadline)
        # This is the original artifact, not live module regeneration. The
        # archive renderer verifies complete schema/code/root/source custody.
        source=bridge.observer_source(held.body,'status',expected_sha256=capsule_pin['sha256'],operation=operation)
        return source,held.body,capsule_pin['sha256']
    def lease_status(self,fixture_id,operation,*,deadline):
        with self._c.operator(deadline=deadline):
            self._guard(deadline);source,_,_=self._lease(fixture_id,operation,deadline)
            return self._call(source.decode('utf-8'),deadline)
    def lease_collect(self,fixture_id,operation,*,deadline):
        with self._c.operator(deadline=deadline):
            self._guard(deadline);source,_,_=self._lease(fixture_id,operation,deadline)
            return self._lease_collect_source(source,deadline)
    def _lease_collect_source(self,source,deadline):
        # Retain the complete authenticated original archive preamble. Replace
        # ONLY its exact final main() call with this fixed READ-ONLY collector.
        suffix=b'\nraise SystemExit(main())\n';need(source.endswith(suffix),'macos_original_lease_renderer_changed')
        collector='''
import base64
b=binding();root,packet=namespace(b);op=J._uuid(CONFIG['operation']);original(root,op,b)
status,out,err=J.collect(root/'jobs',op,b.job_binding(),generation=tuple(packet['jobGeneration']))
need(status['state']=='terminal','macos_original_not_terminal')
print(json.dumps({'operationId':op,'status':status,'stdout':base64.b64encode(out).decode('ascii'),'stderr':base64.b64encode(err).decode('ascii')},sort_keys=True))
'''
        fixed=source[:-len(suffix)]+collector.encode();need(len(fixed)<=262144,'macos_original_collect_source_bound')
        return self._call(fixed.decode('utf-8'),deadline)
    def close(self):
        if not self._closed:
            self._closed=True;self._held.close()
            if self._owns:self._c.close()
    # Normal private, public and direct provider paths cannot interpret this as
    # admission custody or a generic executor. No action/flag changes the lane.
    guard=qualifications=operator=ordinary_guest_call=guest_probe=guest_job_executor=lease_executor=execute=submit=acquire=cancel=reconcile=dispatch_recovery=reconcile_ready=gui_endpoint=vnc_action=prepare_lease_namespace=admit_lease_namespace=admit_guest_namespace=prepare_unlock_observer_namespace=reserve_unlock_observer=admit_unlock_observer=collect_unlock_observer=deny

def prepare_current(custody,*,deadline):
    """Internal provider factory. MUST be called before first share append.
    No caller record/path/blob/token/boolean is accepted as authority.
    The fixed provider publication intent must already be durably captured and
    refer to an actual OriginalOwner waiting before its first append.
    """
    need(type(custody)is mac.MacCustody,'macos_actual_current_custody_required')
    c=custody
    with c.operator(deadline=deadline):
        c.guard(deadline=deadline)
        obj=object.__new__(_Association);obj._c=c;obj._held=ExitStack();obj._proofs=[];obj._closed=False;obj._owns=False
        try:
            own=Path(__file__);raw,own_pin=c._registry._body(own)
            obj._self=obj._held.enter_context(mac.PublicProof(own,own_pin));obj._source_guard()
            sibling=own.with_name('admission_candidate.py');raw,pin=c._registry._body(sibling)
            held=obj._held.enter_context(mac.PublicProof(sibling,pin));obj._proofs.append(held)
            obj._admission=types.ModuleType('_held_original_observer_source_view');exec(compile(held.body,str(sibling),'exec'),obj._admission.__dict__)
            staging=own.with_name('bundle-staging-pins.json');raw,pin=c._registry._body(staging)
            held=obj._held.enter_context(mac.PublicProof(staging,pin));obj._proofs.append(held)
            staged=held.value();need(staged['operationId']==INSTALL_OPERATION and set(staged['files'])==obj._admission.FILES,'macos_fixed_bundle_source_changed')
            obj._files={name:{key:row[key]for key in('sha256','bytes')}for name,row in staged['files'].items()}
            path=c.lifecycle_root/('active-work-publication-'+INSTALL_OPERATION+'.intent.json')
            plan,pin=c._registry._json(path);obj._plan_ref={'path':str(path),'pin':pin};obj._plan=c._record(obj._plan_ref)
            fields={'schemaVersion','role','state','originalRun','predecessor','originalReferences','publisherOperationId','publisherProgram','fixedFiles','operatorPath'}
            need(type(plan)is dict and set(plan)==fields and type(plan['schemaVersion'])is int and plan['schemaVersion']==1 and plan['role']==ROLE and plan['state']=='captured_before_first_append','macos_publication_plan_invalid')
            need(plan['originalRun']==c.run_intent['operationId'] and plan['predecessor']=={'path':str(c._descriptor_path),'pin':c.descriptor_pin} and plan['originalReferences']==c.descriptor['sourceAdmission'] and plan['fixedFiles']==obj._files and plan['operatorPath']==str(c._operator.path),'macos_publication_original_changed')
            operation=mac.jobs._uuid(plan['publisherOperationId']);root=c.run_owner.root
            intent=mac.jobs._intent(root/operation,operation,c.host_binding)
            need(intent['purpose']==PUBLICATION_PURPOSE and plan['publisherProgram']=={'path':str(root/operation/'program.py'),'sha256':intent['programSha256']},'macos_publication_program_changed')
            program=mac.jobs.Program(intent['purpose'],mac.jobs._read(root/operation/'program.py',mac.jobs.MAX_PROGRAM_BYTES),intent['streamLimit'])
            obj._publisher=mac.OriginalOwner(root,c.run_owner.generation,operation,c.host_binding,program)
            need(obj._publisher.observe()['state']=='running','macos_publication_owner_not_waiting')
            # Before append the actual old full tree guard MUST still pass.
            c._public_share.guard();obj._rows=list(c._public_share.rows.values());obj._descriptor=json.loads(json.dumps(c.descriptor))
            obj._guard(deadline)
            # Durable association is source-owned data created BEFORE append.
            # It is not a bearer token: reopening still proves original records,
            # current source, physical custody, publisher and actual flock.
            association={'schemaVersion':1,'role':ROLE,'state':'original_observation_enrolled_before_append','originalRun':c.run_intent['operationId'],'descriptor':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'sourceAdmission':c.descriptor['sourceAdmission'],'publicationPlan':obj._plan_ref,'originalRowsSha256':hashlib.sha256(json.dumps(obj._rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'fixedFiles':obj._files,'observerSource':{'path':str(own),'pin':own_pin},'admissionSource':{'path':str(sibling),'pin':pin},'target':c.binding.target,'machine':c.binding.machine,'operatorPath':str(c._operator.path)}
            # The admission source pin variable above was subsequently reused
            # for the plan; obtain it from the actual retained source holder.
            association['admissionSource']={'path':str(sibling),'pin':{'generation':list(obj._proofs[0].generation),'sha256':hashlib.sha256(obj._proofs[0].body).hexdigest()}}
            path=c.lifecycle_root/('active-work-original-observer-'+INSTALL_OPERATION+'.json')
            raw=(json.dumps(association,sort_keys=True,separators=(',',':'))+'\n').encode()
            try:mac.jobs._create(path,raw)
            except FileExistsError:need(mac.jobs._read(path,1048576)==raw,'macos_original_association_conflict')
            obj._guard(deadline);return obj
        except BaseException:obj.close();raise

def _reopen_original(root,fixture_id,*,deadline):
    """Fresh-client original-only route after a partial/complete append.

    No caller admission/source/token/boolean accepted. The exact predecessor
    descriptor and its provider-created before-append association select all
    references. This does NOT register/refresh an alias or load bundle code.
    """
    from . import readiness_fixture_registry as registry
    root=Path(root).resolve(strict=True);fixture_id=registry._id(fixture_id)
    descriptor_path=root/'.rag_index/readiness-fixtures'/(fixture_id+'.json')
    selected_path=descriptor_path;selected,selected_pin=registry._json(selected_path)
    need(selected.get('provider')=='tart-macos','macos_original_provider_changed')
    run_path,run_pin=mac._reference(selected['originalRun'],root)
    need(run_path.name=='intent.json','macos_original_run_route')
    association_path=run_path.parent/('active-work-original-observer-'+INSTALL_OPERATION+'.json')
    association,association_pin=registry._json(association_path)
    fields={'schemaVersion','role','state','originalRun','descriptor','sourceAdmission','publicationPlan','originalRowsSha256','fixedFiles','observerSource','admissionSource','target','machine','operatorPath'}
    need(type(association)is dict and set(association)==fields and type(association['schemaVersion'])is int and association['schemaVersion']==1 and association['role']==ROLE and association['state']=='original_observation_enrolled_before_append','macos_original_association_invalid')
    # Original jobs/leases keep their ORIGINAL fixture IDs. The provider-held
    # before-append association selects the current observation epoch, never a
    # caller-supplied alias/token. All non-source physical custody must match.
    ref=association['descriptor'];descriptor_path=Path(ref['path'])
    need(descriptor_path.parent==root/'.rag_index/readiness-fixtures'and descriptor_path.suffix=='.json','macos_original_association_route')
    fixture_id=registry._id(descriptor_path.stem);descriptor,descriptor_pin=registry._json(descriptor_path)
    need(ref=={'path':str(descriptor_path),'pin':descriptor_pin}and association['sourceAdmission']==descriptor['sourceAdmission'],'macos_original_association_epoch_changed')
    def physical(d):
        result={key:value for key,value in d.items()if key not in{'fixtureId','sources','sourceAdmission'}}
        result['sourceAdmission']={key:value for key,value in d['sourceAdmission'].items()if key!='activeWorkInstall'}
        return result
    need(physical(selected)==physical(descriptor),'macos_original_association_physical_changed')
    own=Path(__file__);need(association['observerSource']['path']==str(own)and association['admissionSource']['path']==str(own.with_name('admission_candidate.py')),'macos_original_observer_source_route')
    lock=mac.OperatorLock(run_path.parent/'macos-operator.lock')
    need(association['operatorPath']==str(lock.path),'macos_original_operator_route')
    retained=ExitStack();c=None;obj=None
    try:
        retained.enter_context(mac.PublicProof(association_path,association_pin))
        retained.enter_context(mac.PublicProof(selected_path,selected_pin))
        self_held=retained.enter_context(mac.PublicProof(own,association['observerSource']['pin']))
        need(_CODE==compile(self_held.body,__file__,'exec',dont_inherit=True),'macos_original_observer_executed_source_changed')
        held=retained.enter_context(mac.PublicProof(own.with_name('admission_candidate.py'),association['admissionSource']['pin']))
        view=types.ModuleType('_reopened_held_original_source_view');exec(compile(held.body,str(held.path),'exec'),view.__dict__)
        with lock.acquire(deadline=deadline):
            lock.guard()
            # The only source-admission specialization is this fixed tree view.
            # All ordinary/historical proof parsing stays the exact CURRENT
            # source-owned production method. No canonical globals are patched.
            class ObserverTree(mac.PublicSourceTree):
                def guard(self):
                    lock.guard();self.presented.guard()
                    rows=list(self.rows.values())
                    need(hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()==association['originalRowsSha256'],'macos_original_rows_changed')
                    view.observe_pending_subset(str(self.root),rows,association['fixedFiles']);lock.guard()
            class Custody(lease_executor._OriginalMacCustody):
                def __init__(self,root,fixture_id,descriptor,descriptor_pin):
                    # Historical source maps are provenance, never executable
                    # selectors/new work. The actual before-append association
                    # authenticates this exact old map; current host code stays
                    # guarded by inherited _check_source_custody().
                    self._admitted_sources=dict(descriptor['sources'])
                    mac.MacCustody.__init__(self,root,fixture_id,descriptor,descriptor_pin)
                def _admit_public_sources(self,references):
                    original=mac.MacCustody._admit_public_sources
                    local_globals=dict(original.__globals__);local_globals['PublicSourceTree']=ObserverTree
                    fixed=types.FunctionType(original.__code__,local_globals,original.__name__,original.__defaults__,original.__closure__)
                    fixed(self,references)
                guard=qualifications=ordinary_guest_call=guest_probe=guest_job_executor=lease_executor=execute=submit=acquire=cancel=reconcile=dispatch_recovery=reconcile_ready=gui_endpoint=vnc_action=prepare_lease_namespace=admit_lease_namespace=admit_guest_namespace=prepare_unlock_observer_namespace=reserve_unlock_observer=admit_unlock_observer=collect_unlock_observer=deny
            c=Custody(root,fixture_id,descriptor,descriptor_pin)
            c._operator=lock
            need((c.binding.target,c.binding.machine,c.run_intent['operationId'])==(association['target'],association['machine'],association['originalRun']),'macos_original_binding_changed')
            plan=c._record(association['publicationPlan'])
            need(plan['originalRun']==c.run_intent['operationId']and plan['predecessor']==association['descriptor']and plan['fixedFiles']==association['fixedFiles']and plan['originalReferences']==association['sourceAdmission']and plan['operatorPath']==str(lock.path),'macos_publication_association_changed')
            operation=mac.jobs._uuid(plan['publisherOperationId']);intent=mac.jobs._intent(c.run_owner.root/operation,operation,c.host_binding)
            need(intent['purpose']==PUBLICATION_PURPOSE and plan['publisherProgram']=={'path':str(c.run_owner.root/operation/'program.py'),'sha256':intent['programSha256']},'macos_publication_program_changed')
            program=mac.jobs.Program(intent['purpose'],mac.jobs._read(c.run_owner.root/operation/'program.py',mac.jobs.MAX_PROGRAM_BYTES),intent['streamLimit'])
            publisher=mac.OriginalOwner(c.run_owner.root,c.run_owner.generation,operation,c.host_binding,program)
            obj=object.__new__(_Association);obj._c=c;obj._held=retained;obj._proofs=[held];obj._closed=False;obj._owns=True;obj._self=self_held;obj._admission=view;obj._plan=plan;obj._plan_ref=association['publicationPlan'];obj._publisher=publisher;obj._rows=list(c._public_share.rows.values());obj._files=association['fixedFiles'];obj._descriptor=descriptor
            obj._guard(deadline);return obj
    except BaseException:
        if obj is not None:obj.close()
        else:
            if c is not None:c.close()
            retained.close()
        raise


def reopen_original(root,fixture_id,*,deadline):
    try:return _reopen_original(root,fixture_id,deadline=deadline)
    except mac.MacBlocked:raise
    except (OSError,ValueError,TypeError,KeyError,AttributeError):
        raise mac.MacBlocked('macos_original_observation_unavailable')from None

def observe_original(root,fixture_id,kind,operation,*,deadline):
    """Finite registry/workflow hook: identifiers select EXISTING records only.
    It does not return admission custody, a backend or an executable callback.
    """
    need(type(kind)is str and kind in{'host','guest','lease'},'macos_original_kind_invalid')
    operation=mac.jobs._uuid(operation);view=reopen_original(root,fixture_id,deadline=deadline)
    try:
        if kind=='host':return view.host_status(operation,deadline=deadline)
        if kind=='guest':return view.guest_status(fixture_id,operation,deadline=deadline)
        return view.lease_status(fixture_id,operation,deadline=deadline)
    finally:view.close()

def collect_original(root,fixture_id,kind,operation,*,deadline):
    need(type(kind)is str and kind in{'host','guest','lease'},'macos_original_kind_invalid')
    operation=mac.jobs._uuid(operation);view=reopen_original(root,fixture_id,deadline=deadline)
    try:
        if kind=='host':return view.host_collect(operation,deadline=deadline)
        if kind=='guest':return view.guest_collect(fixture_id,operation,deadline=deadline)
        return view.lease_collect(fixture_id,operation,deadline=deadline)
    finally:view.close()
