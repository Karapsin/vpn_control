"""Local SOURCE-ONLY integration controls; never guest/native/admin/network.
Uses actual isolated SourceSession, PublicSourceTree, OperatorLock and retained
host child owner paths. Kernel target/registration construction seams remain
controlled exactly as the independently reviewed v2 controls.
"""
import contextlib,copy,hashlib,importlib.util,json,os,shutil,stat,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent/'fixtures/macos_active_work_integration';ROOT=Path(__file__).resolve().parents[2];V2=HERE/'installer-v2'
def module(path,name):
    m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(path.read_bytes(),str(path),'exec'),m.__dict__);return m
BASE=module(V2/'test_successor.py','_reviewed_v2_controls_'+uuid.uuid4().hex);BASE.ROOT=ROOT
_CLOSURE=None

def closure():
    global _CLOSURE
    if _CLOSURE is not None:return _CLOSURE
    loader=module(ROOT/'agent_tools/source_module_loader.py','_integration_closure_'+uuid.uuid4().hex)
    s=loader.SourceSession(ROOT/'agent_tools','readiness_tart_macos_registry')
    try:
        for name in('readiness_qemu_jobs','readiness_guest_jobs','readiness_lease_workflow','readiness_tart_macos_lease_executor'):s.load(name)
        s.guard();_CLOSURE={Path(path).relative_to(ROOT):raw for path,raw in s.cache.values()};s.guard()
        _CLOSURE[Path('agent_tools/source_module_loader.py')]=(ROOT/'agent_tools/source_module_loader.py').read_bytes()
        _CLOSURE[Path('agent_tools/tool_action_policy.json')]=(ROOT/'agent_tools/tool_action_policy.json').read_bytes()
    finally:s.close()
    # Only these eight source candidates overlay the held current dependency set.
    for name in ('readiness_tart_macos_lease_executor.py', 'readiness_tart_macos_active_work_original.py', 'readiness_tart_macos_active_work_sources.py', 'readiness_fixture_registry.py', 'readiness_tart_macos_lease_qualification.py', 'readiness_lease_workflow.py', 'readiness_tart_macos_active_work_publication.py', 'readiness_tart_macos_registry.py', 'readiness_guest_jobs.py'):_CLOSURE[Path('agent_tools')/name]=(ROOT/'agent_tools'/name).read_bytes()
    return _CLOSURE

def qualification_module(root):
    # Only fixed test data paths+manifest digest change for portability; the
    # complete authenticated callback/custody/decoder functions remain intact.
    directory=root/'fixed-qualification-sources';directory.mkdir(mode=0o700)
    old=json.loads((HERE/'qualification-pins.json').read_bytes());current={}
    for role,ref in old.items():
        raw=(HERE/'qualification-dependencies'/(role+'.source')).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=ref['sha256']:raise AssertionError('fixture_source_changed')
        path=directory/(role+'.py');path.write_bytes(raw);path.chmod(0o600)
        current[role]={'path':str(path),'sha256':ref['sha256'],'bytes':len(raw)}
    raw=(json.dumps(current,sort_keys=True)+'\n').encode();path=directory/'qualification-pins.json';path.write_bytes(raw);path.chmod(0o600)
    before=(HERE/'qualification-pins.json').read_bytes();body=(HERE/'qualification_candidate.py').read_bytes()
    old_sha=hashlib.sha256(before).hexdigest().encode();new_sha=hashlib.sha256(raw).hexdigest().encode()
    if body.count(old_sha)!=1:raise AssertionError('fixture_manifest_literal_changed')
    path=directory/'qualification_candidate.py';path.write_bytes(body.replace(old_sha,new_sha));path.chmod(0o600)
    return module(path,'_portable_complete_qualification_'+uuid.uuid4().hex)

class OriginalRouteControls(BASE.OpaqueAssociationControls):
    def setUp(self):
        self.overlay_tmp=tempfile.TemporaryDirectory();self.overlay=Path(self.overlay_tmp.name).resolve()
        for rel,raw in closure().items():
            path=self.overlay/rel;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
        before_module=BASE.module
        def local_loader(path,name):
            m=before_module(path,name)
            if path.name=='source_module_loader.py':
                actual=m.SourceSession;m.SourceSession=lambda directory,entry:actual(self.overlay/'agent_tools',entry)
            return m
        BASE.module=local_loader
        try:super().setUp()
        finally:BASE.module=before_module
        self.M=self.session.load('readiness_tart_macos_active_work_original')
    def tearDown(self):
        try:super().tearDown()
        finally:self.overlay_tmp.cleanup()
    def test_public_factory_no_association_preserves_old_default(self):
        self.assertIsNone(self.M.executor_for_original(self.root,{'provider':'tart-macos','fixtureId':'owned-control'}))
        self.assertIsNone(self.M.guest_original_response(self.root,'owned-control',str(uuid.uuid4()),deadline=time.monotonic()+2))
    def test_public_guest_hook_shortcircuits_existing_resubmit_lane(self):
        import ast
        before=ast.parse((HERE/'before/readiness_guest_jobs.py').read_bytes())
        current=ast.parse((ROOT/'agent_tools/readiness_guest_jobs.py').read_bytes())
        old=next(n for n in ast.walk(before)if isinstance(n,ast.FunctionDef)and n.name=='reconcile')
        new=next(n for n in ast.walk(current)if isinstance(n,ast.FunctionDef)and n.name=='reconcile')
        selected=[n for n in new.body if isinstance(n,ast.If)and ast.unparse(n.test)=='response is not None']
        self.assertEqual(len(selected),1);self.assertIsInstance(selected[0].body[0],ast.Return)
        # Actual function, with only existing local metadata/canonical carrier
        # seams controlled. The default old lane would open _executor (RED).
        workflow=self.session.load('readiness_guest_jobs');events=[]
        old_hook=self.M.guest_original_response;old_directory=workflow._directory;old_status=workflow.status;old_effective=workflow._effective_intent;old_record=workflow.jobs._record;old_recorded=workflow._record_observation;old_executor=workflow._executor
        try:
            workflow._directory=lambda *a,**k:self.lib;workflow.status=lambda *a,**k:{'state':'unknown'}
            workflow._effective_intent=lambda *a:{'binding':{'target':'controlled'}};workflow.jobs._record=lambda *a:{}
            workflow._record_observation=lambda *a:events.append('recorded_original')or{'state':'unknown'}
            workflow._executor=lambda *a,**k:(_ for _ in()).throw(AssertionError('new dispatch lane'))
            self.M.guest_original_response=lambda *a,**k:{'status':{'state':'unknown'}}
            op=str(uuid.uuid4());(self.lib/op).mkdir(mode=0o700)
            self.assertEqual(workflow.reconcile(self.root,'owned-control',op,deadline=time.monotonic()+2),{'state':'unknown'})
            self.assertEqual(events,['recorded_original'])
            old_scope=dict(workflow.__dict__);exec(compile(ast.fix_missing_locations(ast.Module(body=[old],type_ignores=[])),'<exact-before-reconcile>','exec'),old_scope)
            with self.assertRaisesRegex(AssertionError,'new dispatch lane'):old_scope['reconcile'](self.root,'owned-control',op,deadline=time.monotonic()+2)
        finally:
            self.M.guest_original_response=old_hook;workflow._directory=old_directory;workflow.status=old_status;workflow._effective_intent=old_effective;workflow.jobs._record=old_record;workflow._record_observation=old_recorded;workflow._executor=old_executor
    def test_adapter_status_absence_cannot_become_acquire_authority(self):
        adapter=object.__new__(self.M._ReadOnlyOriginalLeaseExecutor);adapter.root=self.root;adapter.fixture_id='owned-control'
        old_observe=self.M.observe_original;old_normalize=self.M.lease_executor.normalize
        try:
            import subprocess
            self.M.observe_original=lambda *a,**k:subprocess.CompletedProcess([],0,b'{}',b'')
            self.M.lease_executor.normalize=lambda *a:{'state':'unsubmitted','jobState':'unsubmitted','ok':True}
            value=adapter.observe(str(uuid.uuid4()),deadline=time.monotonic()+1)
            self.assertEqual(value['state'],'unknown');self.assertIs(value['ok'],False)
            for name in('submit','cancel','reconcile','execute'):
                with self.subTest(name=name),self.assertRaises(self.mac.MacBlocked):getattr(adapter,name)()
        finally:self.M.observe_original=old_observe;self.M.lease_executor.normalize=old_normalize

    def test_actual_fixed_publisher_waits_for_association_then_full_union_admits_only_terminal(self):
        self._exercise_actual_fixed_publisher()
    def test_actual_partial_copy_failure_keeps_original_status_and_no_admission(self):
        self._exercise_actual_fixed_publisher(failed_copy=True)
    def test_whole_old_publisher_transitive_drift_appends_red_inner_session_guard_zeroappend_green(self):
        self._exercise_actual_fixed_publisher(transitive_drift=True,old_guard=True)
        # Fresh actual custody/session for the paired current candidate.
        self.tearDown();self.setUp()
        self._exercise_actual_fixed_publisher(transitive_drift=True)
    def _exercise_actual_fixed_publisher(self,failed_copy=False,transitive_drift=False,old_guard=False):
        import dataclasses,threading
        pub=self.session.load('readiness_tart_macos_active_work_publication');sources=self.session.load('readiness_tart_macos_active_work_sources');c=self.c
        if old_guard:
            old_path=(HERE/'before-integration-v1')/'candidate/agent_tools/readiness_tart_macos_active_work_publication.py'
            pub=types.ModuleType(self.session.prefix+'._whole_old_publication');pub.__package__=self.session.prefix;pub.__file__=str(old_path);sys.modules[pub.__name__]=pub
            exec(compile(old_path.read_bytes(),str(old_path),'exec'),pub.__dict__)
        # Owned source metadata is created under the fixed internal route. No
        # arbitrary publisher argument selects any file, code or destination.
        source_dir=self.lib/('active-work-install-source-'+sources.INSTALL_OPERATION)/'bundle';source_dir.mkdir(mode=0o700,parents=True)
        refs={}
        for name in sources.FILES:
            p=source_dir/name;p.write_bytes((V2/'bundle-staging'/name).read_bytes());p.chmod(0o600)
            _,pin=self.registry._body(p);refs[name]={'path':str(p),'pin':pin}
        source_record=self.lib/('active-work-install-source-'+sources.INSTALL_OPERATION+'.json')
        self.J._publish(source_record,{'schemaVersion':1,'role':sources.ROLE,'originalRun':c.run_intent['operationId'],'target':c.binding.target,'machine':c.binding.machine,'files':refs})
        _,source_pin=self.registry._json(source_record)
        config={'root':str(self.root),'fixtureId':c.fixture_id,'operationId':self.operation,'descriptor':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'sources':{},'jobRoot':str(self.jobroot),'jobRootGeneration':list(self.gen),'hostBinding':self.J.asdict(self.binding),'sourceInput':{'path':str(source_record),'pin':source_pin}}
        c.guest_proof={'initialPacket':{'agent':{'rawBoot':'87AC272F-619B-4CC0-B9FC-3E32DAEE5B18'}}}
        ctor=self.mac.MacCustody.__init__;program=pub.program;source_pins=self.mac._source_pins;pubos=pub.os;write=pub._write
        def controlled_init(new,*args):
            new.__dict__.update(c.__dict__);new._held=contextlib.ExitStack();new._records=list(c._records);new._cleanup=new._held.close
        original_owner=self.J._owner_identity(self.J._record(self.jobroot/self.operation/'owner.json'))
        proxy=types.SimpleNamespace(**vars(os));proxy.getppid=lambda:original_owner['pid']
        self.mac.MacCustody.__init__=controlled_init;pub.program=lambda *a:self.program;self.mac._source_pins=lambda:{};pub.os=proxy
        if failed_copy:
            def broken_write(fd,raw):write(fd,raw);raise OSError('owned_partial_copy_control')
            pub._write=broken_write
        errors=[]
        def child():
            try:
                if old_guard:pub._owned_publish(config)
                else:pub._owned_publish(config,self.session.guard)
            except BaseException as e:errors.append(e)
        worker=threading.Thread(target=child);worker.start()
        try:
            time.sleep(.08);self.assertTrue(worker.is_alive());self.assertFalse((self.share/sources.BUNDLE).exists())
            # Actual same flock can be acquired while the publisher waits; it
            # must not hold it and deadlock the BEFORE-append association.
            if transitive_drift:
                transitive=self.overlay/'agent_tools/readiness_lease_workflow.py'
                transitive.write_bytes(transitive.read_bytes()+b'\n# owned transitive-drift causal control\n')
                if old_guard:self.scope=self.M.prepare_current(c,deadline=time.monotonic()+3)
                worker.join(timeout=4);self.assertFalse(worker.is_alive())
                if old_guard:
                    self.assertEqual(errors,[]);self.assertTrue((self.share/sources.BUNDLE).exists())
                    with self.assertRaises(ValueError):self.session.guard()  # detected only AFTER append (RED)
                else:
                    self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],ValueError)
                    self.assertFalse((self.share/sources.BUNDLE).exists())  # source guard BEFORE append (GREEN)
                return
            self.scope=self.M.prepare_current(c,deadline=time.monotonic()+3)
            worker.join(timeout=4);self.assertFalse(worker.is_alive())
            if failed_copy:
                self.assertEqual(len(errors),1);self.assertIsInstance(errors[0],OSError)
                self.assertFalse((self.lib/('active-work-install-'+sources.INSTALL_OPERATION+'.json')).exists())
                self.assertEqual(len(list((self.share/sources.BUNDLE).iterdir())),1)
                self.assertEqual(self.scope.host_status(self.operation,deadline=time.monotonic()+2)['operationId'],self.operation)
                with self.assertRaises(self.mac.MacBlocked):self.scope.submit()
                return
            self.assertEqual(errors,[])
            record=self.lib/('active-work-install-'+sources.INSTALL_OPERATION+'.json');value,pin=self.registry._json(record)
            self.assertEqual(stat.S_IMODE((self.share/sources.BUNDLE).stat().st_mode),0o555)
            self.assertEqual(set(value['files']),sources.FILES)
            for row in value['files'].values():self.assertEqual(stat.S_IMODE(row['generation'][2]),0o444)
            # Full optional role is not admitted while its original publisher
            # owner is still running, even though all five bytes are present.
            c.descriptor=copy.deepcopy(c.descriptor);c.descriptor['sourceAdmission']['activeWorkInstall']={'path':str(record),'pin':pin}
            rows=list(c._public_share.rows.values())
            with self.assertRaises(sources.Invalid):sources.admit_optional(c,{'path':str(record),'pin':pin},rows)
            self.release.write_bytes(b'owned-close');until=time.monotonic()+3
            while time.monotonic()<until:
                terminal=self.J.observe(self.jobroot,self.operation,self.binding,generation=self.gen)
                if terminal['state']=='terminal':break
                time.sleep(.02)
            additional=sources.admit_optional(c,{'path':str(record),'pin':pin},rows)
            self.assertEqual(len(additional),6)
            joined=self.mac.PublicSourceTree(self.share,rows+additional);joined.guard()
            # A DTO, extra field, or numeric-false qualification is never enough.
            with self.assertRaises(sources.Invalid):sources.admit_optional(types.SimpleNamespace(**vars(c)),{'path':str(record),'pin':pin},rows)
            actual_record=c._record
            old_source=types.ModuleType(self.session.prefix+'._whole_initial_admission');old_source.__package__=self.session.prefix;old_source.__file__=str(HERE/'before-strict-admission/readiness_tart_macos_active_work_sources.py')
            exec(compile(Path(old_source.__file__).read_bytes(),old_source.__file__,'exec'),old_source.__dict__)
            try:
                for mutation in('extra','bool'):
                    altered=copy.deepcopy(value)
                    if mutation=='extra':altered['foreignAuthority']=False
                    else:altered['qualification']['idleAuthority']=0
                    c._record=lambda ref:altered if ref.get('path')==str(record)else actual_record(ref)
                    self.assertEqual(len(old_source.admit_optional(c,{'path':str(record),'pin':pin},rows)),6)  # old whole predicate RED
                    with self.assertRaises(sources.Invalid):sources.admit_optional(c,{'path':str(record),'pin':pin},rows)
            finally:c._record=actual_record
        finally:
            worker.join(timeout=3);self.mac.MacCustody.__init__=ctor;pub.program=program;self.mac._source_pins=source_pins;pub.os=pubos;pub._write=write

    def test_actual_lease_facade_denies_mutation_before_local_cancel_marker(self):
        workflow=self.session.load('readiness_lease_workflow');adapter=object.__new__(self.M._ReadOnlyOriginalLeaseExecutor)
        factory=workflow.fixtures.lease_executor_from_snapshot;provider=getattr(adapter,'provider');seen=[]
        try:
            workflow.fixtures.lease_executor_from_snapshot=lambda *a:adapter
            old_publish=workflow.jobs._publish;workflow.jobs._publish=lambda *a:seen.append(a)or None
            value={'provider':'tart-macos','executor':{},'operationId':str(uuid.uuid4())}
            for action in('cancel','acquire','reconcile'):
                with self.subTest(action=action),self.assertRaises(self.mac.MacBlocked):workflow._external_original(self.root,self.lib,action,value,{},deadline=time.monotonic()+1)
            self.assertEqual(seen,[])
            # Actual ordinary executor leaves the original action gate alone.
            self.M.require_original_action(types.SimpleNamespace(provider=provider),'cancel')
        finally:workflow.fixtures.lease_executor_from_snapshot=factory;workflow.jobs._publish=old_publish

    def test_fixed_helper_wrong_run_and_machine_refuse_before_any_staging_or_append(self):
        import dataclasses
        pub=self.session.load('readiness_tart_macos_active_work_publication');source=self.session.load('readiness_tart_macos_active_work_sources');c=self.c
        reviewed=self.root/'.runtime/tool-recovery/macos-active-work-install-packet-v2/bundle-staging';reviewed.mkdir(mode=0o700,parents=True)
        for name in source.FILES:
            path=reviewed/name;path.write_bytes((V2/'bundle-staging'/name).read_bytes());path.chmod(0o600)
        old_path=(HERE/'before-integration-v2')/'candidate/agent_tools/readiness_tart_macos_active_work_publication.py'
        old=types.ModuleType(self.session.prefix+'._early_binding_whole_before');old.__package__=self.session.prefix;old.__file__=str(old_path);sys.modules[old.__name__]=old;exec(compile(old_path.read_bytes(),str(old_path),'exec'),old.__dict__)
        run=c.run_intent['operationId'];binding=c.binding;guard=c.guard;c.guard=lambda **_:('controlled valid other fixture',)
        try:
            for kind,reason in(('run','macos_fixed_helper_run_changed'),('machine','macos_fixed_helper_machine_changed')):
                if kind=='run':c.run_intent['operationId']=str(uuid.uuid4())
                else:c.binding=dataclasses.replace(binding,machine=str(uuid.uuid4()))
                before=list(self.lib.iterdir())
                with self.assertRaisesRegex(self.mac.MacBlocked,reason):pub.prepare_source_enrollment(c,deadline=time.monotonic()+1)
                with self.assertRaisesRegex(self.mac.MacBlocked,reason):pub.program(c,str(uuid.uuid4()))
                self.assertEqual(list(self.lib.iterdir()),before);self.assertFalse((self.share/source.BUNDLE).exists())
                # Whole old function was willing to stage the fixed guest
                # helper for a different authenticated source-owned selection.
                # Local owned temp filesystem only, no guest/VM/source share.
                old.prepare_source_enrollment(c,deadline=time.monotonic()+2)
                self.assertTrue((self.lib/('active-work-install-source-'+source.INSTALL_OPERATION)).exists())
                import shutil
                shutil.rmtree(self.lib/('active-work-install-source-'+source.INSTALL_OPERATION));(self.lib/('active-work-install-source-'+source.INSTALL_OPERATION+'.json')).unlink()
                c.run_intent['operationId']=run;c.binding=binding
        finally:c.run_intent['operationId']=run;c.binding=binding;c.guard=guard

    def test_host_source_enrollment_is_fixed_create_only_and_does_not_touch_share(self):
        pub=self.session.load('readiness_tart_macos_active_work_publication');source=self.session.load('readiness_tart_macos_active_work_sources')
        reviewed=self.root/'.runtime/tool-recovery/macos-active-work-install-packet-v2/bundle-staging';reviewed.mkdir(mode=0o700,parents=True)
        for name in source.FILES:
            path=reviewed/name;path.write_bytes((V2/'bundle-staging'/name).read_bytes());path.chmod(0o600)
        before=list(self.share.iterdir());ref=pub.prepare_source_enrollment(self.c,deadline=time.monotonic()+3)
        self.assertEqual(list(self.share.iterdir()),before);self.c._public_share.guard()
        record=self.registry._json(Path(ref['path']))[0];self.assertEqual(set(record['files']),source.FILES)
        for name,item in record['files'].items():
            self.assertEqual(item['pin']['sha256'],source.EXPECTED_FILES[name]['sha256'])
            self.assertEqual(stat.S_IMODE(Path(item['path']).stat().st_mode),0o600)
        with self.assertRaises(FileExistsError):pub.prepare_source_enrollment(self.c,deadline=time.monotonic()+3)

    def test_actual_submit_marker_precedes_lost_ack_and_blocks_second_dispatch(self):
        pub=self.session.load('readiness_tart_macos_active_work_publication');c=self.c
        original_program=pub.program;original_submit=self.J.submit;original_guard=c.guard
        calls=[]
        try:
            pub.program=lambda *a:self.program;c.guard=lambda **kw:('controlled',)
            def lost(*a,**k):calls.append(1);raise OSError('owned_lost_ack_control')
            self.J.submit=lost
            with self.assertRaises(OSError):pub.submit_prepared(c,self.operation,deadline=time.monotonic()+2)
            marker=self.lib/('active-work-publication-submit-'+self.operation+'.json')
            before=marker.read_bytes();self.assertEqual(stat.S_IMODE(marker.stat().st_mode),0o600)
            with self.assertRaises(FileExistsError):pub.submit_prepared(c,self.operation,deadline=time.monotonic()+2)
            self.assertEqual(calls,[1]);self.assertEqual(marker.read_bytes(),before)
        finally:pub.program=original_program;self.J.submit=original_submit;c.guard=original_guard

    def test_real_carrier_callback_retained_before_actual_ordinary_postguard(self):
        import dataclasses
        q=qualification_module(self.lib)
        c=self.c;prefix='/usr/local/libexec/vpn-tool-recovery-cont-63517582'
        wrapper=self.lib/'owned-public-carrier.py'
        wrapper.write_text('#!'+sys.executable+'\nimport sys\nsys.stdin.buffer.read()\nprint("PUBLIC_RETAINED_BEFORE_POSTGUARD",flush=True)\n')
        wrapper.chmod(0o700)
        c.binding=dataclasses.replace(c.binding,tart_binary=str(wrapper),guest_python=prefix+'/python/bin/python3.12')
        c.descriptor['binding']=dataclasses.asdict(c.binding)
        c.guest_proof={'prefix':prefix,'publicFiles':{name:'a'*64 for name in('python/bin/python3.12','tart-guest-agent','guest-probe.py','guest-probe-main.py','readonly-probe','launchDaemon')}}
        c._descriptor_path.write_text(json.dumps(c.descriptor));_,c.descriptor_pin=self.registry._json(c._descriptor_path)
        # Only current custody's guard is controlled: actual original
        # ordinary_guest_call and inside-_native_call capture both execute.
        output=self.lib/'callback';output.mkdir(mode=0o700)
        calls=[]
        def phase_guard(**kw):
            calls.append(1)
            if len(calls)==2:raise self.mac.MacBlocked('controlled_postguard_drift')
            return ('original','actual')
        c.guard=phase_guard
        payload=self.mac.guest_probe_source(c.binding,prefix=c.guest_proof['prefix'],public_files=c.guest_proof['publicFiles']);argv,payload=self.M.protocol.stdin_command(payload)
        with self.assertRaises(self.mac.MacBlocked):c.ordinary_guest_call(c.binding,argv,payload,time.monotonic()+2)
        self.assertEqual(list(output.iterdir()),[])  # actual old carrier loses response at postguard
        calls.clear()
        with self.mac.private.Directory(output)as held:
            with q.capture_before_factory(self.session,c.descriptor,held,deadline=time.monotonic()+5)as captured:
                payload=self.mac.guest_probe_source(c.binding,prefix=c.guest_proof['prefix'],public_files=c.guest_proof['publicFiles'])
                argv,payload=self.M.protocol.stdin_command(payload)
                with self.assertRaises(self.mac.MacBlocked):c.ordinary_guest_call(c.binding,argv,payload,time.monotonic()+4)
                self.assertEqual((output/'call-1-factory.stdout.json').read_bytes(),b'PUBLIC_RETAINED_BEFORE_POSTGUARD\n')
                callback=[json.loads(line)for line in(output/'call-1-factory.capture.jsonl').read_bytes().splitlines()][-1]
                self.assertIs(callback['actorAbsent'],True);self.assertIs(callback['stdoutEof'],True);self.assertIs(callback['stderrEof'],True)
                self.assertEqual(stat.S_IMODE((output/'call-1-factory.stdout.json').stat().st_mode),0o600)
                self.assertIsNone(self.J._birth(callback['actor']['pid']))
                # Exact source and global deadline reject before child creation.
                before=len(list(output.iterdir()))
                with self.assertRaises(q.Blocked):c._native_call([str(wrapper)],b'foreign source',time.monotonic()+1)
                self.assertEqual(len(list(output.iterdir())),before)
                captured.state['calls']=16
                with self.assertRaises(q.Blocked):c._native_call([str(wrapper),'exec','-i',c.binding.vm_name,c.binding.guest_python,*argv[1:]],payload,time.monotonic()+1)
                self.assertEqual(len(list(output.iterdir())),before)
            with self.assertRaises(q.Blocked):
                with q.capture_before_factory(self.session,c.descriptor,held,deadline=time.monotonic()-1):self.fail('expired group must not enter')

    def test_whole_old_constructor_waits_past_caller_budget_red_lazy_constructor_zero_external_green(self):
        import ast,selectors,subprocess
        c=self.c;mac=self.mac;M=self.M
        c.descriptor['sources']=mac._source_pins()
        c._descriptor_path.write_text(json.dumps(c.descriptor));_,c.descriptor_pin=self.registry._json(c._descriptor_path)
        plan_path=self.lib/('active-work-publication-'+M.INSTALL_OPERATION+'.intent.json')
        plan=self.registry._json(plan_path)[0];plan['predecessor']={'path':str(c._descriptor_path),'pin':c.descriptor_pin};plan_path.write_text(json.dumps(plan))
        self.scope=M.prepare_current(c,deadline=time.monotonic()+3)
        rows=list(c._public_share.rows.values())
        snapshot={'kind':M.lease_executor.KIND,'provider':'tart-macos','fixtureId':c.fixture_id,'sources':c.descriptor['sources'],'binding':{'machine':c.binding.machine},'registration':{'path':str(c._descriptor_path),'pin':c.descriptor_pin}}
        def controlled_init(new,*args):
            new.__dict__.update(c.__dict__);new._held=contextlib.ExitStack();new._records=list(c._records);new._cleanup=new._held.close
            new._admit_public_sources(c.descriptor['sourceAdmission'])
        def controlled_assembly(self,references):self._public_share=PublicSourceTree(self.run_intent['plan']['bootstrapShare'],CONTROL_ROWS)
        controlled_assembly.__globals__['PublicSourceTree']=mac.PublicSourceTree;controlled_assembly.__globals__['CONTROL_ROWS']=rows
        before_ctor=mac.MacCustody.__init__;before_admit=mac.MacCustody._admit_public_sources;before_reopen=M.reopen_original;before_observe=M.observe_original
        mac.MacCustody.__init__=controlled_init;mac.MacCustody._admit_public_sources=controlled_assembly
        seen=[]
        def counted(*a,**kw):seen.append(kw['deadline']);return before_reopen(*a,**kw)
        M.reopen_original=counted
        old_path=(HERE/'before-integration-v1')/'candidate/agent_tools/readiness_tart_macos_active_work_original.py'
        before_tree=ast.parse(old_path.read_bytes());node=next(n for n in before_tree.body if isinstance(n,ast.ClassDef)and n.name=='_ReadOnlyOriginalLeaseExecutor')
        scope=dict(M.__dict__);scope['reopen_original']=counted
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(old_path),'exec'),scope)
        old=scope['_ReadOnlyOriginalLeaseExecutor']
        def holder(seconds):
            raw='import fcntl,os,time\nf=os.open('+repr(str(c._operator.path))+',os.O_RDWR|os.O_NOFOLLOW)\nfcntl.flock(f,fcntl.LOCK_EX)\nprint("OWNED_LOCK",flush=True)\ntime.sleep('+repr(seconds)+')\nos.close(f)\n'
            process=subprocess.Popen([sys.executable,'-I','-B','-c',raw],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            sel=selectors.DefaultSelector();sel.register(process.stdout,selectors.EVENT_READ)
            try:self.assertTrue(sel.select(2));self.assertEqual(process.stdout.readline(),b'OWNED_LOCK\n')
            finally:sel.close()
            return process
        processes=[]
        try:
            process=holder(.25);processes.append(process);start=time.monotonic();admitted_deadline=start+.03
            old(self.root,snapshot)
            self.assertGreater(time.monotonic(),admitted_deadline);self.assertEqual(len(seen),1)
            # The old class actually entered the real target flock/reopen route
            # with its independent30s deadline; no guest carrier is stubbed in.
            self.assertGreater(seen[0],admitted_deadline+20)
            process.communicate(timeout=2);self.assertEqual(process.returncode,0)
            process=holder(.25);processes.append(process);seen.clear();start=time.monotonic()
            current=M._ReadOnlyOriginalLeaseExecutor(self.root,snapshot)
            self.assertEqual(seen,[]);self.assertLess(time.monotonic()-start,.10)
            with self.assertRaises(mac.MacBlocked):current.observe(str(uuid.uuid4()),deadline=time.monotonic()-1)
            self.assertEqual(seen,[])  # expired path must not even try reopen
            with self.assertRaises(mac.MacBlocked):current.observe(str(uuid.uuid4()),deadline=time.monotonic()+.03)
            self.assertEqual(len(seen),1);self.assertLess(seen[0]-time.monotonic(),.02)
            process.communicate(timeout=2);self.assertEqual(process.returncode,0)
            workflow=self.session.load('readiness_lease_workflow');factory=workflow.fixtures.lease_executor_from_snapshot;publish=workflow.jobs._publish;native=[]
            try:
                workflow.fixtures.lease_executor_from_snapshot=lambda *a:M._ReadOnlyOriginalLeaseExecutor(self.root,snapshot)
                workflow.jobs._publish=lambda *a:native.append(a)
                seen.clear()
                for action in('cancel','acquire','reconcile'):
                    with self.subTest(action=action),self.assertRaises(mac.MacBlocked):workflow._external_original(self.root,self.lib,action,{'provider':'tart-macos','executor':snapshot,'operationId':str(uuid.uuid4())},{},deadline=time.monotonic()-1)
                self.assertEqual(seen,[]);self.assertEqual(native,[])
            finally:workflow.fixtures.lease_executor_from_snapshot=factory;workflow.jobs._publish=publish
        finally:
            M.reopen_original=before_reopen;M.observe_original=before_observe;mac.MacCustody.__init__=before_ctor;mac.MacCustody._admit_public_sources=before_admit
            for process in processes:
                if process.poll()is None:process.wait(timeout=2)
                for stream in(process.stdout,process.stderr):
                    if stream is not None and not stream.closed:stream.close()

    def test_completed_four_reference_admission_uses_normal_full_union_factory_not_historical_view(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+3)
        current=json.loads(json.dumps(self.c.descriptor));current['fixtureId']='complete-union-control';current['sourceAdmission']['activeWorkInstall']={'path':str(self.lib/'fixed-not-yet-valid.json'),'pin':{}}
        path=self.c._descriptor_path.with_name(current['fixtureId']+'.json');self.J._publish(path,current)
        old_path=HERE/'before-future-union/readiness_tart_macos_active_work_original.py'
        import ast
        tree=ast.parse(old_path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_enrollment_path')
        scope=dict(self.M.__dict__);exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(old_path),'exec'),scope)
        self.assertIsNotNone(scope['_enrollment_path'](self.root,current['fixtureId']))  # whole old selector always chose historical lane RED
        self.assertIsNone(self.M._enrollment_path(self.root,current['fixtureId']))
        self.assertIsNotNone(self.M._enrollment_path(self.root,self.c.fixture_id))
        snapshot={'provider':'tart-macos','fixtureId':current['fixtureId'],'kind':self.M.lease_executor.KIND}
        self.assertIsNone(self.M.executor_for_original(self.root,snapshot))
        # Returning to normal constructor is NOT new source authority. Invalid
        # four-reference data must still fail its actual provider checks.
        with self.assertRaises((self.mac.MacBlocked,KeyError,ValueError)):
            self.M.lease_executor.OriginalMacLeaseExecutor(self.root,snapshot)

class FixedSourceControls(unittest.TestCase):
    def test_actual_five_files_reject_foreign_hash_and_extra_leaf(self):
        loader=module(ROOT/'agent_tools/source_module_loader.py','_strict_loader_'+uuid.uuid4().hex)
        # Isolated candidate's plain validator has no source/native execution.
        source=module(ROOT/'agent_tools/readiness_tart_macos_active_work_sources.py','_strict_sources_'+uuid.uuid4().hex)
        expected=copy.deepcopy(source.EXPECTED_FILES)
        with tempfile.TemporaryDirectory()as tmp:
            bundle=Path(tmp)/source.BUNDLE;bundle.mkdir(mode=0o700)
            for name in source.FILES:
                (bundle/name).write_bytes((V2/'bundle-staging'/name).read_bytes());(bundle/name).chmod(0o444)
            bundle.chmod(0o555);actual=source.observe_five_files(bundle,expected)
            self.assertEqual(set(actual['files']),source.FILES)
            with self.assertRaises(source.Invalid):source.observe_five_files(bundle,{name:{**row,'sha256':'0'*64}for name,row in expected.items()})
            bundle.chmod(0o700);(bundle/'foreign').write_bytes(b'not executed')
            with self.assertRaises(source.Invalid):source.observe_five_files(bundle,expected)
    def test_exact_public_beforeimages_unchanged(self):
        for name,digest in {'readiness_tart_macos_lease_executor.py': 'fb898918e68a5a9153e6ad96486cee8dc83cbeb5cd0c953819fcb6c2b812cb3c', 'readiness_fixture_registry.py': '01483be6045cf695f2187da11a0db87efb5c6b95e2945c92f0b6c731dd1571c0', 'readiness_tart_macos_lease_qualification.py': '40e2960cb0f879214e214526a7bb8f4d11f73dcf0a270d34af611d4493248e40', 'readiness_lease_workflow.py': '059a0ff511e1b41a2ad9dc0f57214b105e6e960621936fec72a6c95b06f57d7a', 'readiness_tart_macos_registry.py': 'de5a459dc5f7c1b4e714f85ce16b27fa1aef45bdfcfd5db10655561506ff6e55', 'readiness_guest_jobs.py': '4106011f1525f0d6c527ef1eaafd6529ce4d5a6dd5b273692817bad85f2271d0'}.items():self.assertEqual(hashlib.sha256((HERE/'before'/name).read_bytes()).hexdigest(),digest)

if __name__=='__main__':unittest.main()
