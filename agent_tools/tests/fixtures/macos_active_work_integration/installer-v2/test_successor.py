"""SOURCE ONLY controls. Real owned temp files/children; no guest/framework/
sudo/admin/network. Root/account/target seams are explicitly controlled.
"""
import ast,contextlib,copy,hashlib,importlib.util,json,os,stat,subprocess,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];OLD=HERE.with_name('macos-active-work-install-packet-v1')
def module(path,name):
    scope=types.ModuleType(name);scope.__file__=str(path);sys.modules[name]=scope
    exec(compile(path.read_bytes(),str(path),'exec'),scope.__dict__);return scope
def info_namespace(value,uid=None,gid=None):
    fields={key:getattr(value,key)for key in dir(value)if key.startswith('st_')}
    if uid is not None:fields['st_uid']=uid
    if gid is not None:fields['st_gid']=gid
    return types.SimpleNamespace(**fields)
class SuccessorControls(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();os.chmod(self.root,0o700)
    def tearDown(self):self.tmp.cleanup()
    def run_whole_installer(self,which,*,mutate=False):
        path=which/'bundle-staging/install.py';m=module(path,'_controlled_install_'+uuid.uuid4().hex)
        raw=path.read_bytes();cfg=copy.deepcopy(m.CONFIG);base=self.root/uuid.uuid4().hex;base.mkdir(mode=0o700)
        lib=base/'libexec';rules=base/'rules';bundle=base/'bundle'
        for p in(lib,rules,bundle):p.mkdir(mode=0o700)
        watched=base/'held-source';watched.write_bytes(b'before')
        source_pin=watched.stat();owners={}
        for name in('main.py','caller.py','bundle.json','authorization.applescript'):(bundle/name).write_bytes((which/'bundle-staging'/name).read_bytes())
        cfg['bundle']=str(bundle);cfg['pythonCanonical']=os.path.realpath(sys.executable);cfg['oldPublicFiles']={};cfg['oldRule']=str(base/'old-rule');Path(cfg['oldRule']).write_bytes(cfg['oldRuleBytes'].encode());cfg['candidateRule']=str(lib/cfg['leafName']/'sudoers.candidate')
        probe=b'class Native: pass\n';cfg['probeSha256']=hashlib.sha256(probe).hexdigest()
        m.CONFIG=cfg;m.PROBE=probe;m.__source_digest__=hashlib.sha256(raw).hexdigest();m.identity=lambda _: {'owned':'controlled'}
        m.sys=types.SimpleNamespace(argv=['fixed'],platform='darwin',executable=sys.executable,_getframe=sys._getframe)
        m.signal=types.SimpleNamespace(SIGALRM=14,SIG_DFL=0,signal=lambda *_:None,alarm=lambda *_:None)
        proxy=types.SimpleNamespace(**{key:getattr(os,key)for key in dir(os)})
        proxy.getuid=proxy.geteuid=lambda:0
        proxy.fchown=lambda fd,uid,gid:owners.update({os.fstat(fd).st_ino:(uid,gid)})
        proxy.fstat=lambda fd:info_namespace(os.fstat(fd),*owners[os.fstat(fd).st_ino])if os.fstat(fd).st_ino in owners else os.fstat(fd)
        m.os=proxy
        class Held:
            def open(self,p,**kwargs):
                if p==str(bundle)+'/install.py':return raw
                if p=='/usr/local/libexec':return os.open(lib,os.O_RDONLY|os.O_DIRECTORY)
                if p=='/private/etc/sudoers.d':return os.open(rules,os.O_RDONLY|os.O_DIRECTORY)
                if p.startswith('/usr/local/libexec/'):p=str(lib/p.removeprefix('/usr/local/libexec/'))
                elif p.startswith('/private/etc/sudoers.d/'):p=str(rules/p.removeprefix('/private/etc/sudoers.d/'))
                if Path(p).is_file():return Path(p).read_bytes()
                return b'controlled-protected-source'
            def guard(self):
                if watched.stat().st_mtime_ns!=source_pin.st_mtime_ns or watched.read_bytes()!=b'before':raise m.Refused('held_source_changed')
            def close(self):pass
        m.Held=Held
        def waited(*_):
            if mutate:watched.write_bytes(b'changed-by-owned-control-during-visudo')
        m.validate_rule=waited
        old_umask=os.umask(0o077)
        try:
            try:m.run();error=None
            except m.Refused as e:error=str(e)
        finally:os.umask(old_umask)
        leaf=lib/cfg['leafName'];rule=rules/cfg['ruleName']
        return {'mode':stat.S_IMODE(leaf.stat().st_mode),'rule':rule.exists(),'error':error,'leaf':leaf}
    def test_whole_before_umask077_red_exact_newleaf0755_green(self):
        before=self.run_whole_installer(OLD);after=self.run_whole_installer(HERE)
        self.assertEqual(before['mode'],0o700);self.assertEqual(after['mode'],0o755)
        self.assertTrue(before['rule']);self.assertTrue(after['rule'])
    def test_whole_before_visudo_source_change_publishes_rule_red_new_refuses_before_rule_green(self):
        before=self.run_whole_installer(OLD,mutate=True);after=self.run_whole_installer(HERE,mutate=True)
        self.assertTrue(before['rule']);self.assertFalse(after['rule']);self.assertEqual(after['error'],'held_source_changed')
    def test_whole_before_late_entry_singlewalk_red_exact_secondcensus_green(self):
        for which,accepts in((OLD,True),(HERE,False)):
            m=module(which/'admission_candidate.py','_pending_'+uuid.uuid4().hex)
            root=self.root/uuid.uuid4().hex;root.mkdir(mode=0o700)
            proxy=types.SimpleNamespace(**{key:getattr(os,key)for key in dir(os)})
            walk=os.walk;injected=[]
            def raced(*args,**kwargs):
                yield from walk(*args,**kwargs)
                if not injected:(root/'late-unlisted').write_bytes(b'never-read');injected.append(True)
            proxy.walk=raced;m.os=proxy
            expected={name:{'bytes':10,'sha256':'a'*64}for name in m.FILES}
            if accepts:self.assertEqual(m.observe_pending_subset(str(root),[],expected)['state'],'original_observation_metadata_view_only')
            else:
                with self.assertRaises(m.Invalid):m.observe_pending_subset(str(root),[],expected)

class OpaqueAssociationControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();os.chmod(self.root,0o700)
        loader=module(ROOT/'agent_tools/source_module_loader.py','_source_only_loader_'+uuid.uuid4().hex)
        self.session=loader.SourceSession(ROOT/'agent_tools','readiness_tart_macos_registry')
        self.mac=self.session.module;self.J=self.mac.jobs
        for name in('readiness_qemu_jobs','readiness_guest_jobs','readiness_lease_workflow','readiness_tart_macos_lease_executor'):self.session.load(name)
        self.M=types.ModuleType(self.session.prefix+'._ignored_original_observation');self.M.__package__=self.session.prefix;self.M.__file__=str(HERE/'original_observation.py');sys.modules[self.M.__name__]=self.M
        exec(compile((HERE/'original_observation.py').read_bytes(),self.M.__file__,'exec'),self.M.__dict__)
        self.registry=self.session.load('readiness_fixture_registry');self.backend=self.session.load('readiness_tart_macos')
        self.lib=self.root/'.runtime/case';self.lib.mkdir(mode=0o700,parents=True)
        self.jobroot=self.lib/'jobs';self.jobroot.mkdir(mode=0o700)
        self.gen=self.J.root_generation(self.jobroot);self.binding=self.J.current_binding('owned-control','owned-control-machine')
        self.release=self.lib/'release';self.operation=str(uuid.uuid4())
        program=self.J.Program(self.M.PUBLICATION_PURPOSE,('import pathlib,time\np=pathlib.Path('+repr(str(self.release))+')\nprint("owned-public-status",flush=True)\nfor n in range(150):\n if p.exists():break\n time.sleep(.02)\n').encode(),4096)
        self.program=program;self.J.submit(self.jobroot,self.operation,self.binding,program,generation=self.gen)
        until=time.monotonic()+3
        while time.monotonic()<until:
            status=self.J.observe(self.jobroot,self.operation,self.binding,generation=self.gen)
            if status['state']=='running':break
            time.sleep(.01)
        self.assertEqual(status['state'],'running',status)
        self.c=object.__new__(self.mac.MacCustody);c=self.c
        c.root=self.root;c.lifecycle_root=self.lib;c.run_intent={'operationId':'2d933a39-0fb6-46a4-9fd9-02221d81c4b9','plan':{'bootstrapShare':str(self.lib/'share')}}
        c.run_owner=types.SimpleNamespace(root=self.jobroot,generation=self.gen,observe=lambda:{'state':'running','owner':{'pid':os.getpid()}})
        c.create_owner=types.SimpleNamespace(observe=lambda:{'state':'terminal','terminal':{'exitCode':0}})
        share=self.lib/'share';share.mkdir(mode=0o700);(share/'original.py').write_bytes(b'old-public');os.chmod(share/'original.py',0o600)
        original={'path':'original.py','kind':'file','generation':list(self.mac.private._generation((share/'original.py').lstat())),'sha256':hashlib.sha256(b'old-public').hexdigest()}
        c._public_share=self.mac.PublicSourceTree(share,[original]);self.share=share
        c.fixture_id='owned-control';c.host_binding=self.binding;c.binding=self.backend.MacBinding(target='local-tart-macos-'+'a'*24,machine='ecdc399a-8f2b-5410-b85d-e4db56ddc6c1',vm_name='vpn-tool-recovery-tart-macos-owned-control',tart_binary='/fixed/tart',fixture_root='/fixed/vpn-tool-recovery-tart-macos-owned-control',guest_python='/fixed/python',ordinary_uid=502,ordinary_account='toolrecovery',ordinary_home='/Users/toolrecovery',memory_mib=4096,storage_fixture_id='owned-storage')
        c._operator=self.mac.OperatorLock(self.lib/'macos-operator.lock');c._records=[];c._artifact_holders=[];c._credentials={};c._held=contextlib.ExitStack();c._registry=self.registry
        c._check_source_custody=lambda _:None;c._resource_claims=lambda:None;c.wrapper_actor={'pid':os.getpid(),'birth':self.J._birth(os.getpid())};c.actor=dict(c.wrapper_actor);c.endpoint={'port':12345};c._public_actor=types.SimpleNamespace(guard=lambda **_:None)
        self.mac._parent=lambda *args:os.getpid();self.mac._listener=lambda *args:['controlled-listener']
        self.J._publish(self.lib/'intent.json',c.run_intent);_,run_pin=self.registry._json(self.lib/'intent.json')
        c.descriptor={'fixtureId':'owned-control','sources':{},'provider':'tart-macos','originalRun':{'path':str(self.lib/'intent.json'),'pin':run_pin},'listener':['controlled-listener'],'sourceAdmission':{'originalManifest':{},'continuation':{},'logPreparation':{}}};c._descriptor_path=self.root/'.rag_index/readiness-fixtures/owned-control.json';c._descriptor_path.parent.mkdir(mode=0o700,parents=True);self.J._publish(c._descriptor_path,c.descriptor);_,c.descriptor_pin=self.registry._json(c._descriptor_path)
        c._cleanup=lambda:c._held.close()
        staged=json.loads((HERE/'bundle-staging-pins.json').read_bytes());files={name:{key:pin[key]for key in('sha256','bytes')}for name,pin in staged['files'].items()}
        plan={'schemaVersion':1,'role':self.M.ROLE,'state':'captured_before_first_append','originalRun':c.run_intent['operationId'],'predecessor':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'originalReferences':c.descriptor['sourceAdmission'],'publisherOperationId':self.operation,'publisherProgram':{'path':str(self.jobroot/self.operation/'program.py'),'sha256':program.digest},'fixedFiles':files,'operatorPath':str(c._operator.path)}
        self.J._publish(self.lib/('active-work-publication-'+self.M.INSTALL_OPERATION+'.intent.json'),plan)
        self.scope=None;self.extra=[]
    def tearDown(self):
        self.release.write_bytes(b'owned-close');until=time.monotonic()+4
        while time.monotonic()<until:
            s=self.J.observe(self.jobroot,self.operation,self.binding,generation=self.gen)
            if s['state']=='terminal':self.J.collect(self.jobroot,self.operation,self.binding,generation=self.gen);break
            time.sleep(.02)
        for scope in self.extra:scope.close()
        if self.scope:self.scope.close()
        self.c._held.close();self.session.close();self.tmp.cleanup()
    def test_actual_original_owner_status_collect_survives_partial_append_new_dispatch_rejected(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        association=self.lib/('active-work-original-observer-'+self.M.INSTALL_OPERATION+'.json')
        self.assertTrue(association.exists());self.assertEqual(stat.S_IMODE(association.stat().st_mode),0o600)
        (self.share/'active-work-4a9f62cc').mkdir(mode=0o700);(self.share/'active-work-4a9f62cc/main.py').write_bytes(b'')
        os.chmod(self.share/'active-work-4a9f62cc/main.py',0o600)
        with self.assertRaises(self.mac.MacBlocked):self.c.guard(deadline=time.monotonic()+5)
        current=self.scope.host_status(self.operation,deadline=time.monotonic()+5)
        self.assertEqual(current['state'],'running');self.assertEqual(current['operationId'],self.operation)
        for method in('guard','ordinary_guest_call','execute','submit','acquire','cancel','reconcile','dispatch_recovery','gui_endpoint','guest_job_executor','lease_executor','prepare_lease_namespace','admit_guest_namespace'):
            with self.subTest(method=method),self.assertRaises(self.mac.MacBlocked):getattr(self.scope,method)()
        with self.assertRaises(self.backend.MacBlocked):self.backend.MacTartBackend(self.c.binding,self.scope)
        with self.assertRaises(self.mac.MacBlocked):self.M.lease_executor.QualifiedMacLeaseExecutor(self.scope,deadline=time.monotonic()+2)
        self.release.write_bytes(b'owned-close');until=time.monotonic()+3
        while time.monotonic()<until:
            current=self.scope.host_status(self.operation,deadline=time.monotonic()+3)
            if current['state']=='terminal':break
            time.sleep(.02)
        result,out,err=self.scope.host_collect(self.operation,deadline=time.monotonic()+3)
        self.assertEqual(result['state'],'terminal');self.assertEqual(out,b'owned-public-status\n');self.assertEqual(err,b'')
    def test_dto_scope_construction_and_original_other_operation_denied(self):
        with self.assertRaises(self.mac.MacBlocked):self.M.prepare_current(types.SimpleNamespace(custody=True),deadline=time.monotonic()+1)
        with self.assertRaises(self.mac.MacBlocked):self.M._Association()
        for kind in('acquire','start','resume','reboot','login','wake_display','cancel','reconcile','input'):
            with self.subTest(kind=kind),self.assertRaises(self.mac.MacBlocked):self.M.observe_original(self.root,'owned-control',kind,str(uuid.uuid4()),deadline=time.monotonic()+1)
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        with self.assertRaises(self.J.DurableJobError):self.scope.host_status(str(uuid.uuid4()),deadline=time.monotonic()+3)
        with self.assertRaises(self.mac.MacBlocked):self.scope.guest_status('absent-fixture',str(uuid.uuid4()),deadline=time.monotonic()+3)
    def test_original_changed_or_unlisted_extra_blocks_even_status(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        (self.share/'foreign').write_bytes(b'never-read')
        with self.assertRaises(Exception):self.scope.host_status(self.operation,deadline=time.monotonic()+3)
        (self.share/'foreign').unlink();(self.share/'original.py').write_bytes(b'changed')
        with self.assertRaises(Exception):self.scope.host_status(self.operation,deadline=time.monotonic()+3)
    def test_real_crossprocess_publication_flock_required_before_original_status(self):
        import selectors
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        with self.assertRaises(self.mac.MacBlocked):self.scope._guard(time.monotonic()+1)
        raw=('import fcntl,os,time\nf=os.open('+repr(str(self.c._operator.path))+',os.O_RDWR|os.O_NOFOLLOW)\nfcntl.flock(f,fcntl.LOCK_EX)\nprint("OWNED_LOCK",flush=True)\ntime.sleep(.3)\nos.close(f)\n')
        process=subprocess.Popen([sys.executable,'-I','-B','-c',raw],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        birth=self.J._birth(process.pid)
        try:
            selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
            self.assertTrue(selector.select(2));self.assertEqual(process.stdout.readline(),b'OWNED_LOCK\n');selector.close()
            with self.assertRaises(self.mac.MacBlocked):self.scope.host_status(self.operation,deadline=time.monotonic()+.05)
            out,err=process.communicate(timeout=2);self.assertEqual(process.returncode,0);self.assertEqual(err,b'')
            self.assertIsNone(self.J._birth(process.pid));self.assertIsNotNone(birth)
            self.assertIn(self.scope.host_status(self.operation,deadline=time.monotonic()+3)['state'],{'running','terminal'})
        finally:
            process.wait(timeout=2)
            for stream in(process.stdout,process.stderr):
                if stream is not None and not stream.closed:stream.close()
    def test_reconnect_reopens_durable_provider_association_after_partial_not_a_bearer_token(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        rows=list(self.c._public_share.rows.values());c=self.c;mac=self.mac
        (self.share/'active-work-4a9f62cc').mkdir(mode=0o700)
        # Only kernel/target constructor seams are controlled; the actual
        # reconnect factory, source holds, census, operator and durable owner
        # status all execute. No guest/registry mutation or native enrollment.
        def controlled_init(new,root,fixture,descriptor,pin):
            new.__dict__.update(c.__dict__);new._held=contextlib.ExitStack();new._records=list(c._records);new._cleanup=lambda:new._held.close()
            new._admit_public_sources(descriptor['sourceAdmission'])
        def controlled_source_assembly(self,references):
            self._public_share=PublicSourceTree(self.run_intent['plan']['bootstrapShare'],CONTROL_ROWS)
        # Preserve all original methods in the private SourceSession only.
        before_ctor=mac.MacCustody.__init__;before_admit=mac.MacCustody._admit_public_sources
        controlled_source_assembly.__globals__['PublicSourceTree']=mac.PublicSourceTree;controlled_source_assembly.__globals__['CONTROL_ROWS']=rows
        mac.MacCustody.__init__=controlled_init;mac.MacCustody._admit_public_sources=controlled_source_assembly
        try:
            reopened=self.M.reopen_original(self.root,'owned-control',deadline=time.monotonic()+5);self.extra.append(reopened)
            self.assertEqual(reopened.host_status(self.operation,deadline=time.monotonic()+3)['operationId'],self.operation)
            hooked=self.M.observe_original(self.root,'owned-control','host',self.operation,deadline=time.monotonic()+3)
            self.assertEqual(hooked['operationId'],self.operation)
            old_alias=copy.deepcopy(c.descriptor);old_alias['fixtureId']='old-source-control';old_alias['sources']={'historical.py':'a'*64}
            self.J._publish(c._descriptor_path.with_name('old-source-control.json'),old_alias)
            old_selected=self.M.observe_original(self.root,'old-source-control','host',self.operation,deadline=time.monotonic()+3)
            self.assertEqual(old_selected['operationId'],self.operation)
            self.release.write_bytes(b'owned-close');until=time.monotonic()+3
            while time.monotonic()<until:
                hooked=self.M.observe_original(self.root,'owned-control','host',self.operation,deadline=time.monotonic()+3)
                if hooked['state']=='terminal':break
                time.sleep(.02)
            collected,out,err=self.M.collect_original(self.root,'owned-control','host',self.operation,deadline=time.monotonic()+3)
            self.assertEqual(collected['state'],'terminal');self.assertEqual(out,b'owned-public-status\n');self.assertEqual(err,b'')
            with self.assertRaises(mac.MacBlocked):reopened.execute(('anything',),payload=b'never')
            with self.assertRaises(mac.MacBlocked):self.M.reopen_original(self.root,'foreign',deadline=time.monotonic()+1)
        except FileNotFoundError:
            self.fail('valid enrolled reconnect must not lose original status')
        finally:
            mac.MacCustody.__init__=before_ctor;mac.MacCustody._admit_public_sources=before_admit
    def test_actual_admitted_guest_status_carrier_only_no_generic_execute(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5);c=self.c
        op=str(uuid.uuid4());namespace={'schemaVersion':1,'root':'/private/var/tmp/vc-recovery-jobs','generation':[1,2],'admissionGeneration':[1,3],'target':c.binding.target,'machine':c.binding.machine,'actualMachineId':c.binding.machine,'account':'502','ownerSourceSha256':hashlib.sha256(self.J.owner_source()).hexdigest()}
        self.J._publish(self.lib/'guest-jobs.json',namespace)
        path=self.root/'.runtime/readiness-guest-jobs/owned-control'/op;path.mkdir(mode=0o700,parents=True);os.chmod(path.parent,0o700)
        intent={'schemaVersion':1,'fixtureId':'owned-control','operationId':op,'binding':{'target':c.binding.target,'machine':c.binding.machine,'boot':'original-control-boot','account':'502'},'namespace':namespace,'spec':{'count':3,'intervalSeconds':.1}}
        self.J._publish(path/'intent.json',intent);seen=[]
        def owned_carrier(argv,payload,deadline):
            canonical,_=self.M.protocol.stdin_command(payload.decode());self.assertEqual(tuple(argv[5:]),canonical[1:])
            tree=ast.parse(payload);parameters=next(n.value for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PARAMETERS'for t in n.targets))
            value=ast.literal_eval(parameters);self.assertEqual(value['mode'],'observe');self.assertEqual(value['operationId'],op)
            seen.append(value)
            reply={'status':{'state':'terminal','operationId':op},'admissionConsumed':True,'stdout':'cHVibGlj','stderr':''}
            # Real newly owned harmless child, not the Tart manager/guest. Its
            # canonical public payload is retained only in memory by this test.
            return subprocess.run([sys.executable,'-I','-B','-c','print('+repr(json.dumps(reply))+')'],input=payload,capture_output=True,timeout=2)
        c._native_call=owned_carrier
        (self.share/'active-work-4a9f62cc').mkdir(mode=0o700)
        result=self.scope.guest_collect('owned-control',op,deadline=time.monotonic()+3)
        self.assertEqual(result.returncode,0);self.assertEqual(len(seen),1)
        with self.assertRaises(self.mac.MacBlocked):self.scope.execute((),payload=b'new')
    def test_unknown_publisher_keeps_other_original_observation_visible_without_new_dispatch(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5)
        owner=self.jobroot/self.operation/'owner.json';before=owner.read_bytes();backup=owner.with_name('owner.before.json');owner.rename(backup)
        try:
            with self.c.operator(deadline=time.monotonic()+3):
                status=self.scope._publication_status();self.assertEqual(status['state'],'unknown')
                self.scope._guard(time.monotonic()+3)
            observed=self.scope.host_status(self.operation,deadline=time.monotonic()+3);self.assertEqual(observed['state'],'unknown')
            with self.assertRaises(self.mac.MacBlocked):self.scope.acquire()
        finally:backup.rename(owner);self.assertEqual(owner.read_bytes(),before)
    def test_original_lease_status_collect_use_authenticated_archive_and_parser_only(self):
        self.scope=self.M.prepare_current(self.c,deadline=time.monotonic()+5);c=self.c;op=str(uuid.uuid4())
        L=self.session.load('readiness_tart_macos_leases');B=self.M.bridge
        bound=L.MacLeaseBinding(c.binding.target,c.binding.machine,'87AC272F-619B-4CC0-B9FC-3E32DAEE5B18','502','toolrecovery','/Users/toolrecovery','100237')
        raw=B.capsule(bound);initial=json.loads(raw)
        ns={'schemaVersion':1,'root':'/private/var/tmp/vc-recovery-macos-leases-v2','target':bound.target,'machine':bound.machine,'account':'502','sources':{key:hashlib.sha256(__import__('base64').b64decode(value)).hexdigest()for key,value in initial['files'].items()},'rootGeneration':[2,3],'jobGeneration':[2,4],'admissionGeneration':[2,5]}
        raw=B.bind_namespace(raw,ns,expected_sha256=hashlib.sha256(raw).hexdigest());archive=json.loads(raw)
        directory=self.lib/'lease-executors/archive';directory.mkdir(mode=0o700,parents=True);cap=directory/'capsule.json';self.J._create(cap,raw);_,pin=self.registry._json(cap)
        reference={'path':str(cap),'pin':pin};qualification_ref={'path':str(self.lib/'lease-native-qualification.json'),'pin':{'sha256':'a'*64,'generation':[1]*9}}
        snapshot={'provider':'tart-macos','fixtureId':'owned-control','registration':{'path':str(c._descriptor_path),'pin':c.descriptor_pin},'binding':initial['binding'],'namespace':ns,'capsule':reference,'qualification':qualification_ref}
        admission={'schemaVersion':2,'fixtureId':'owned-control','operationId':op,'provider':'tart-macos','ttlSeconds':3,'executor':snapshot,'readyIdentities':['controlled']*6,'sources':dict(self.M.lease_workflow._LOADED)}
        path=self.root/'.rag_index/readiness-leases/admissions/owned-control';path.mkdir(mode=0o700,parents=True);self.J._publish(path/(op+'.json'),admission)
        c.load_lease_namespace=lambda version:ns
        qualified=[];original_parser=self.M.qualification._load
        def parser(actual,ref):
            self.assertIs(actual,c);self.assertEqual(ref,qualification_ref);qualified.append(ref)
            return types.SimpleNamespace(raw=raw,namespace=ns)
        self.M.qualification._load=parser;calls=[]
        def carrier(argv,payload,deadline):
            tree=ast.parse(payload);config=ast.literal_eval(next(node.value for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='CONFIG'for t in node.targets)))
            self.assertEqual(config['action'],'status');self.assertEqual(config['operation'],op)
            calls.append(payload);return subprocess.run([sys.executable,'-I','-B','-c','print("PUBLIC_ORIGINAL_REPLY")'],capture_output=True,timeout=2)
        c._native_call=carrier
        try:
            self.scope.lease_status('owned-control',op,deadline=time.monotonic()+4)
            self.scope.lease_collect('owned-control',op,deadline=time.monotonic()+4)
            self.assertEqual(len(qualified),2);self.assertEqual(len(calls),2)
            self.assertTrue(calls[0].endswith(b'\nraise SystemExit(main())\n'));self.assertFalse(calls[1].endswith(b'\nraise SystemExit(main())\n'))
            self.assertIn(b"J.collect(root/'jobs',op,b.job_binding()",calls[1])
            # No route exposes the cancel/acquire/reconcile archive renderer.
            for name in('acquire','cancel','reconcile','submit'):
                with self.assertRaises(self.mac.MacBlocked):getattr(self.scope,name)()
        finally:self.M.qualification._load=original_parser
if __name__=='__main__':unittest.main()
