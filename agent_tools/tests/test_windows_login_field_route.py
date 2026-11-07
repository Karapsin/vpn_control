"""Sign-in route: reference capture, fixture steps, closed history and sign-in transitions.

Every case runs the actual module-level sign-in definitions of the whole preserved
source (the refusal or trap found on clone 246a3304) and of the current source over
real files and controlled guest/monitor seams. No secret or guest exists here.
"""
import ast,copy,hashlib,json,os,re,stat,sys,tempfile,time,types,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness_windows as windows,readiness_windows_leases as leases,readiness_windows_login as login

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
SID='S-1-5-21-1-2-3-1004';OPERATION='117fd197-772d-48d5-9255-ce3006d7fdbd'
DEFINITIONS=('PrivateInputUnknown','_ProtectedOwner','private_keys','enter_private','ppm','screen_gate','wait_known_field','prepare_screen','_login_flow')


def digest(filename):
    raw=(FIXTURE/filename).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][filename]:raise AssertionError(filename+' beforeimage changed')
    return raw


def before_module(filename='login.before.source'):
    module=types.ModuleType('agent_tools._login_route_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
    sys.modules[module.__name__]=module;exec(compile(digest(filename),module.__file__,'exec'),module.__dict__);return module


def flow_namespace(raw,*,mode,expected,profile=None):
    tree=ast.parse(raw);ns={'hashlib':hashlib,'json':json,'re':re,'os':os,'time':types.SimpleNamespace(monotonic=time.monotonic,sleep=lambda _:None,monotonic_ns=time.monotonic_ns)}
    ns['_rename_create_only']=login._rename_create_only
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef))and node.name in DEFINITIONS:
            exec(compile(ast.Module(body=[node],type_ignores=[]),'<login-definition>','exec'),ns)
    ns.update(LOGIN_MODE=mode,LOGIN_EXPECTED=copy.deepcopy(expected),LOGIN_SID=SID,SPEC={'deploymentId':'machine'},SETUP={'user':'fixtureuser'},OPERATION=OPERATION,
              LOGIN_ACCOUNT_SCRIPT='account',SESSION_SCRIPT='session',LOGIN_SCREEN_PIN_SCRIPT='pin',LOGIN_PROFILE=profile,LOGIN_OWNER_SECRET=b'A',LOGIN_ORIGINAL=None,LOGIN_FRAME=0)
    return ns


def frame(value):return b'P6\n320 200\n255\n'+bytes((value,value,value))*(320*200)


def facts(*,user='fixtureuser',flags=0,state=0,logon=5,token=SID):
    return {'machine':'MACHINE','boot':'boot','expectedSid':SID,'ordinary':True,'tokenSid':token,'console':1,'explorers':[{'Id':9,'SessionId':1}] if user else [],'session':{'SessionId':1,'State':state,'Flags':flags,'User':user,'Logon':logon}}


def crop_profile(value):
    pixels=bytes((value,value,value))*(320*200)
    return {'width':320,'height':200,'crops':[{'rect':[0,0,320,200],'sha256':hashlib.sha256(pixels).hexdigest()}]}


class FlowHarness(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.expected={'actor':{'pid':1},'hostBoot':'h','controlConnection':'c','boot':'boot','console':1,'logon':5,'user':'fixtureuser'}
        self.before={'actor':{'pid':1},'hostBoot':'h','controlConnection':'c'};self.frames=[];self.inputs=[];self.scripts=[];self.after=[]
    def run_flow(self,raw,mode,fresh,*,profile=None,phase=False):
        ns=flow_namespace(raw,mode=mode,expected=self.expected,profile=profile)
        if phase:ns.update(LOGIN_OWNER_PHASE=lambda *_:None,LOGIN_OWNER_REMAINING=lambda:getattr(self,'remaining',170))
        root=self.root
        def read(name):return json.loads((root/name).read_text())
        def save(name,value):
            fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w')as stream:json.dump(value,stream)
        def monitor(command,arguments=None):
            if command=='screendump':
                path=Path(arguments['filename']);path.write_bytes(self.frames.pop(0) if len(self.frames)>1 else self.frames[0]);path.chmod(0o600);return {}
            if command=='query-mice':return [{'current':True,'absolute':True}]
            self.inputs.append(command);return {}
        def script(label,source):
            self.scripts.append(label)
            if label.startswith('login-account-'):return {'name':'fixtureuser','sid':SID,'enabled':True,'loginKeyboard':'00000409'}
            if label.startswith('login-screen-pin-'):
                outcome=getattr(self,'pin_result',None)
                if isinstance(outcome,Exception):raise outcome
                return outcome if outcome is not None else {'pinned':True,'accountSettingsChanged':False}
            if label.startswith('login-after-'):
                value=self.after.pop(0)
                if isinstance(value,Exception):raise value
                return value
            return copy.deepcopy(fresh)
        return ns['_login_flow'](root,read,save,monitor,lambda:None,script,copy.deepcopy(fresh),self.before)
    def names(self):return sorted(path.name for path in self.root.iterdir() if not path.name.endswith('.ppm'))


class FieldCaptureTests(FlowHarness):
    current=Path(login.__file__).read_bytes()
    def test_before_has_no_capture_mode_current_keeps_one_public_journal(self):
        self.frames=[frame(200)]
        with self.assertRaisesRegex(ValueError,'instance_login_action'):self.run_flow(digest('login.before.source'),'login-field-capture',facts())
    def test_capture_presses_return_once_retains_frames_and_never_repeats(self):
        self.frames=[frame(0),frame(200),frame(200),frame(90),frame(90)]
        value=self.run_flow(self.current,'login-field-capture',facts())
        self.assertEqual('field-capture-observed',value['login']['state']);self.assertEqual(['input-send-event','send-key'],self.inputs)
        self.assertGreaterEqual(value['login']['frames'],6)
        self.assertEqual(['login-field-capture-'+OPERATION+'.intent.json','login-field-capture-'+OPERATION+'.terminal.json'],self.names())
        self.inputs.clear();again=self.run_flow(self.current,'login-field-capture',facts())
        self.assertEqual([],self.inputs);self.assertEqual(value['login']['frames'],again['login']['frames'])
        self.assertIs(False,json.loads((self.root/('login-field-capture-'+OPERATION+'.intent.json')).read_text())['privateInput'])
    def test_visible_screen_needs_no_pointer_wake(self):
        self.frames=[frame(200)];self.run_flow(self.current,'login-field-capture',facts());self.assertEqual(['send-key'],self.inputs)
    def test_ready_changed_or_foreign_session_never_receives_input(self):
        self.frames=[frame(200)]
        for fresh,expected in ((facts(flags=1),{}),(facts(logon=6),{}),(facts(user='other',token='S-1-5-21-9'),{}),(facts(token='S-1-5-21-9'),{}),(facts(),{'boot':'other'}),(facts(),{'actor':{'pid':2}})):
            with self.subTest(fresh=fresh,expected=expected):
                saved=self.expected;self.expected={**saved,**expected}
                with self.assertRaises(ValueError):self.run_flow(self.current,'login-field-capture',fresh)
                self.expected=saved;self.assertEqual([],self.inputs);self.assertEqual([],self.names())
    def test_signed_out_console_is_captured_under_its_empty_identity(self):
        self.expected={**self.expected,'logon':0,'user':''};self.frames=[frame(200)]
        self.assertEqual('field-capture-observed',self.run_flow(self.current,'login-field-capture',facts(user='',logon=0,token=None,state=1))['login']['state'])
    def test_interrupted_capture_closes_with_no_more_input(self):
        self.frames=[frame(200)];name='login-field-capture-'+OPERATION
        intent={'operationId':OPERATION,'expected':self.expected,'account':SID,'privateInput':False,'replayAllowed':False}
        path=self.root/(name+'.intent.json');path.write_text(json.dumps(intent));path.chmod(0o600);leaf=self.root/('login-'+OPERATION+'-00.ppm');leaf.write_bytes(frame(200))
        self.assertEqual('field-capture-observed',self.run_flow(self.current,'login-field-capture',facts())['login']['state']);self.assertEqual([],self.inputs)
        self.assertEqual('field-capture-interrupted',json.loads((self.root/(name+'.terminal.json')).read_text())['state'])
    def test_changed_retained_journal_refuses(self):
        self.frames=[frame(200)];self.run_flow(self.current,'login-field-capture',facts())
        self.expected={**self.expected,'hostBoot':'h'};path=self.root/('login-field-capture-'+OPERATION+'.intent.json');body=json.loads(path.read_text());body['privateInput']=True;path.chmod(0o600);path.write_text(json.dumps(body))
        with self.assertRaisesRegex(ValueError,'instance_login_capture_changed'):self.run_flow(self.current,'login-field-capture',facts())


class FixtureStepTests(FlowHarness):
    current=Path(login.__file__).read_bytes()
    def test_lock_before_leaves_no_terminal_current_closes_its_key_once(self):
        self.frames=[frame(200)]
        self.run_flow(digest('login.before.source'),'login-lock-fixture',facts(flags=1))
        self.assertEqual(['login-test-lock-'+OPERATION+'.intent.json'],self.names())
        (self.root/('login-test-lock-'+OPERATION+'.intent.json')).unlink();self.inputs.clear()
        self.run_flow(self.current,'login-lock-fixture',facts(flags=1))
        self.assertEqual(['login-test-lock-'+OPERATION+'.intent.json','login-test-lock-'+OPERATION+'.terminal.json'],self.names());self.assertEqual(['send-key'],self.inputs)
        self.run_flow(self.current,'login-lock-fixture',facts(flags=1));self.assertEqual(['send-key'],self.inputs)
    def test_screen_pin_runs_its_fixed_query_once_and_closes(self):
        self.frames=[frame(200)]
        with self.assertRaisesRegex(ValueError,'instance_login_action'):self.run_flow(digest('login.before.source'),'login-screen-pin',facts(flags=1))
        value=self.run_flow(self.current,'login-screen-pin',facts(flags=1));self.assertEqual('screen-pinned',value['login']['state']);self.assertEqual([],self.inputs)
        again=self.run_flow(self.current,'login-screen-pin',facts(flags=1));self.assertEqual('screen-pinned',again['login']['state'])
        labels={label for label in self.scripts if label.startswith('login-screen-pin-')}
        self.assertEqual({'login-screen-pin-'+OPERATION.replace('-','')[:12]},labels,'a repeat re-reads the one guest program')
        self.assertEqual('screen-pinned',json.loads((self.root/('login-screen-pin-'+OPERATION+'.terminal.json')).read_text())['state'])
    def test_screen_pin_that_ended_unverified_closes_and_still_refuses(self):
        self.frames=[frame(200)];real=self.run_flow
        ns_script=self.pin_outcome
        for outcome,reason in ((ValueError('instance_guest_program_failed'),'instance_guest_program_failed'),({'pinned':False,'accountSettingsChanged':False},'instance_login_screen_pin_unverified')):
            with self.subTest(outcome=outcome):
                for path in list(self.root.iterdir()):path.unlink()
                self.pin_result=outcome
                with self.assertRaisesRegex(ValueError,reason):self.run_flow(self.current,'login-screen-pin',facts(flags=1))
                self.assertEqual('screen-pin-unverified',json.loads((self.root/('login-screen-pin-'+OPERATION+'.terminal.json')).read_text())['state'])
    def pin_outcome(self):return getattr(self,'pin_result',None)
    def test_lock_with_a_lost_reply_closes_only_from_the_observed_lock_and_never_presses_again(self):
        self.frames=[frame(200)];name='login-test-lock-'+OPERATION
        intent={'operationId':OPERATION,'intentionalTestState':'locked','expected':self.expected,'account':SID,'replayAllowed':False}
        path=self.root/(name+'.intent.json');path.write_text(json.dumps(intent));path.chmod(0o600)
        self.run_flow(self.current,'login-lock-fixture',facts(flags=1));self.assertEqual([],self.inputs);self.assertFalse((self.root/(name+'.terminal.json')).exists())
        self.run_flow(self.current,'login-lock-fixture',facts(flags=0));self.assertEqual([],self.inputs)
        self.assertEqual('lock-observed',json.loads((self.root/(name+'.terminal.json')).read_text())['state'])
    def test_pin_changes_only_the_lock_image_policy(self):
        self.assertEqual(4,login.LOGIN_SCREEN_PIN.count('New-ItemProperty'))
        for forbidden in ('AutoAdminLogon','DefaultPassword','Set-LocalUser','Winlogon','Add-LocalGroupMember','net user'):self.assertNotIn(forbidden,login.LOGIN_SCREEN_PIN)


class TransitionTests(FlowHarness):
    current=Path(login.__file__).read_bytes()
    def ready(self):return facts(flags=1,logon=5)
    def bundle(self):return {'password':crop_profile(90),'lockscreen':crop_profile(200)}
    def test_slow_render_after_wake_before_refused_current_waits_for_the_reviewed_screen(self):
        self.frames=[frame(0),frame(0),frame(200),frame(90)];self.after=[self.ready()]
        with self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):
            self.run_flow(digest('login.before.source'),'login-submit',facts(),profile=self.bundle())
        for path in list(self.root.iterdir()):path.unlink()
        self.inputs.clear();self.frames=[frame(0),frame(0),frame(200),frame(90)];self.after=[self.ready()]
        value=self.run_flow(self.current,'login-submit',facts(),profile=self.bundle())
        self.assertEqual('ready',value['login']['state']);self.assertEqual('input-send-event',self.inputs[0]);self.assertEqual(1+1+2,len(self.inputs))
    def test_unknown_screen_after_wake_still_refuses_before_any_secret(self):
        real=time.monotonic;clock=[real()]
        def advance():clock[0]+=3;return clock[0]
        self.frames=[frame(0),frame(33)]
        raw=self.current
        ns_time=mock.patch.object(time,'monotonic',side_effect=lambda:advance())
        with ns_time,self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):self.run_flow(raw,'login-submit',facts(),profile=self.bundle())
        self.assertFalse((self.root/('login-credential-'+OPERATION+'.intent.json')).exists());self.assertEqual(['input-send-event'],self.inputs)
    def test_field_lost_during_admission_before_types_blind_current_refuses_before_the_credential(self):
        self.frames=[frame(90),frame(200)];self.after=[self.ready()]
        self.run_flow(digest('login.before.source'),'login-submit',facts(),profile=self.bundle())
        self.assertEqual(2,len(self.inputs),'the original typed into a screen it no longer saw')
        for path in list(self.root.iterdir()):path.unlink()
        self.inputs.clear();self.frames=[frame(90),frame(200)];self.after=[self.ready()]
        with mock.patch.object(time,'monotonic',side_effect=iter(range(0,10000,3))),self.assertRaisesRegex(ValueError,'instance_login_screen_unrecognized'):
            self.run_flow(self.current,'login-submit',facts(),profile=self.bundle())
        self.assertEqual([],self.inputs);self.assertFalse((self.root/('login-credential-'+OPERATION+'.intent.json')).exists())
    def test_no_budget_to_finish_refuses_before_the_credential(self):
        self.frames=[frame(90)];self.after=[self.ready()];self.remaining=5
        self.run_flow(digest('login.before.source'),'login-submit',facts(),profile=self.bundle(),phase=True);self.assertTrue(self.inputs)
        for path in list(self.root.iterdir()):path.unlink()
        self.inputs.clear();self.frames=[frame(90)];self.after=[self.ready()];self.remaining=5
        with self.assertRaisesRegex(ValueError,'instance_login_budget_insufficient'):
            self.run_flow(self.current,'login-submit',facts(),profile=self.bundle(),phase=True)
        self.assertEqual([],self.inputs);self.assertFalse((self.root/('login-credential-'+OPERATION+'.intent.json')).exists())
    def test_lost_agent_replies_after_the_key_keep_observing_refusals_do_not(self):
        for failure in (TimeoutError('collection-deadline'),OSError('reset'),ValueError(),json.JSONDecodeError('x','y',0),ValueError('instance_guest_output')):
            with self.subTest(failure=failure):
                for path in list(self.root.iterdir()):path.unlink()
                self.frames=[frame(90)];self.after=[failure,self.ready()];self.inputs.clear()
                self.assertEqual('ready',self.run_flow(self.current,'login-submit',facts(),profile=self.bundle(),phase=True)['login']['state'])
                self.assertEqual(2,len(self.inputs))
    def test_console_transition_after_the_key_before_blocked_current_keeps_observing(self):
        failure=ValueError('instance_guest_program_failed')
        self.frames=[frame(90)];self.after=[failure,self.ready()]
        with self.assertRaisesRegex(ValueError,'instance_guest_program_failed'):
            self.run_flow(digest('login.before.source'),'login-submit',facts(),profile=self.bundle())
        for path in list(self.root.iterdir()):path.unlink()
        self.after=[failure,self.ready()];self.inputs.clear()
        value=self.run_flow(self.current,'login-submit',facts(),profile=self.bundle(),phase=True)
        self.assertEqual('ready',value['login']['state']);self.assertEqual(1+1,len(self.inputs),'one password key and one Return, never retyped')
        self.assertTrue((self.root/('login-credential-'+OPERATION+'.terminal.json')).exists())
    def test_no_answer_ever_stays_open_and_never_retypes(self):
        self.frames=[frame(90)];self.after=[ValueError('instance_guest_program_failed')]*2
        with self.assertRaisesRegex(ValueError,'instance_login_after_unresolved'):
            self.run_flow(self.current,'login-submit',facts(),profile=self.bundle())
        self.assertEqual(2,len(self.inputs));self.assertTrue((self.root/('login-credential-'+OPERATION+'.intent.json')).exists())
        self.assertFalse((self.root/('login-credential-'+OPERATION+'.terminal.json')).exists())
    def test_other_failures_after_the_key_are_not_swallowed(self):
        self.frames=[frame(90)];self.after=[ValueError('instance_host_epoch')]
        with self.assertRaisesRegex(ValueError,'instance_host_epoch'):self.run_flow(self.current,'login-submit',facts(),profile=self.bundle())


class ClosedHistoryTests(unittest.TestCase):
    identity={'hostBoot':'h','expected':{'boot':'boot'},'account':SID,'user':'fixtureuser','profile':{}}
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700);(self.root/'intent.json').write_text('{}');(self.root/'intent.json').chmod(0o600)
    def prior(self,module,packet,*,credential=False):
        operation=str(uuid.uuid4());sha='a'*64
        owner=module._ProtectedOwner(self.root,operation,self.identity,sha,sha)
        intent={'schemaVersion':2,'operationId':operation,'identity':self.identity,'sourceSha256':sha,'root':owner._root_pin(),'lock':owner._pin(os.lstat(self.root/'intent.json')),'hostBoot':'h','creator':{'pid':os.getpid(),'birth':1},'deadlineNs':0,'replayAllowed':False}
        record={'operationId':operation,'sourceSha256':sha,'pid':2**22-1,'birth':1}
        for suffix,value in (('.intent.json',intent),('.owner.json',record),('.terminal.json',{'admission':intent,'owner':record,'packet':{**packet,'operationId':operation,'replayAllowed':False}})):
            path=self.root/('login-owner-'+operation+suffix);path.write_text(json.dumps(value));path.chmod(0o600)
        if credential:
            path=self.root/('login-credential-'+operation+'.intent.json');path.write_text('{}');path.chmod(0o600)
        digest_=hashlib.sha256(json.dumps(self.identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        return {operation:{'sourceSha256':sha,'identitySha256':digest_}}
    def attempt(self,module,approved):
        # The owner's host-boot guard reads a Linux /proc file; history logic runs for real.
        with mock.patch.object(module._ProtectedOwner,'guard'),mock.patch.dict(module.__dict__,{'LOGIN_PUBLIC_REASONS':{'instance_login_screen_unrecognized'}}):
            owner=module._ProtectedOwner(self.root,str(uuid.uuid4()),self.identity,'b'*64,'b'*64,approved);owner.block_prior()
    refused={'state':'blocked','reason':'instance_login_screen_unrecognized'}
    def test_refusal_before_any_credential_before_strands_the_machine_current_allows_a_new_attempt(self):
        old=before_module()
        approved=self.prior(old,self.refused)
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(old,approved)
        self.attempt(login,approved)
    def test_refusal_with_public_preparation_also_closes(self):
        approved=self.prior(login,self.refused);operation=next(iter(approved))
        path=self.root/('login-preparation-'+operation+'-dismiss.intent.json');path.write_text('{}');path.chmod(0o600)
        self.attempt(login,approved)
    def test_any_credential_trace_keeps_the_machine_closed(self):
        approved=self.prior(login,self.refused,credential=True)
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)
    def test_credential_phase_receipt_keeps_the_machine_closed(self):
        approved=self.prior(login,self.refused);operation=next(iter(approved))
        path=self.root/('login-owner-'+operation+'.phase-credential.terminal.json');path.write_text('{}');path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)
    def test_packet_that_never_became_an_owner_before_strands_current_closes(self):
        operation=str(uuid.uuid4());digest_=hashlib.sha256(json.dumps(self.identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        approved={operation:{'sourceSha256':'a'*64,'identitySha256':digest_}}
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(before_module(),approved)
        self.attempt(login,approved)
        path=self.root/('login-preparation-'+operation+'-wake.intent.json');path.write_text('{}');path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)
    def close_credential(self,operation,*,state='ready',change=None):
        body={'operationId':operation,'state':state,'boot':'boot','account':SID,'console':2,'logon':77,'settingsChanged':False,'replayAllowed':False};body.update(change or {})
        admitted={'operationId':operation,'expected':self.identity['expected'],'profile':self.identity['profile'],'account':SID,'replayAllowed':False}
        for name,value in (('login-credential-'+operation+'.intent.json',admitted),('login-credential-'+operation+'.terminal.json',body)):
            path=self.root/name;path.write_text(json.dumps(value));path.chmod(0o600)
        return body
    def test_credential_closed_later_by_status_opens_the_next_attempt_only_with_its_ready_terminal(self):
        submitted={'state':'owner-terminal','loginState':'credential-submitted','boot':'boot','account':SID,'console':1,'logon':0}
        approved=self.prior(login,submitted);operation=next(iter(approved))
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)
        body=self.close_credential(operation);self.attempt(login,approved)
        prepared=self.root/('login-preparation-'+operation+'-dismiss.intent.json');prepared.write_text('{}');prepared.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)
        closed=self.root/('login-preparation-'+operation+'-dismiss.terminal.json');closed.write_text(json.dumps({**body,'phase':'dismiss','state':'ready-observed'}));closed.chmod(0o600);self.attempt(login,approved)
    def test_a_foreign_or_unready_credential_terminal_never_opens_it(self):
        submitted={'state':'blocked','reason':'instance_login_screen_unrecognized'}
        for change in ({'state':'unresolved'},{'boot':'other'},{'account':'S-1-5-21-9'},{'console':'1'},{'operationId':'other'}):
            with self.subTest(change=change):
                approved=self.prior(login,submitted);operation=next(iter(approved));self.close_credential(operation,change=change)
                with self.assertRaises(ValueError):self.attempt(login,approved)
                for path in list(self.root.iterdir()):
                    if path.name!='intent.json':path.unlink()
    def test_deadline_stops_before_the_credential_and_never_inside_a_password(self):
        owner=login._ProtectedOwner(self.root,str(uuid.uuid4()),self.identity,'a'*64,'a'*64)
        owner.intent={'hostBoot':'h','deadlineNs':0,'root':owner._root_pin(),'lock':owner._pin(os.lstat(self.root/'intent.json'))}
        import pathlib
        with mock.patch.object(pathlib.Path,'read_text',return_value='h\n'):
            with self.assertRaisesRegex(ValueError,'instance_login_owner_deadline'):owner.guard(True)
            owner.typing=True;owner.guard(True)
            old=before_module()._ProtectedOwner(self.root,str(uuid.uuid4()),self.identity,'a'*64,'a'*64);old.intent=dict(owner.intent);old.typing=True
            with self.assertRaisesRegex(ValueError,'instance_login_owner_deadline'):old.guard(True)
    def test_running_or_unresolved_owner_keeps_the_machine_closed(self):
        approved=self.prior(login,{'state':'owner-terminal','loginState':'credential-submitted','boot':'boot','account':SID,'console':1,'logon':5})
        with self.assertRaisesRegex(ValueError,'instance_login_prior_owner_unresolved'):self.attempt(login,approved)


class ApprovedHistoryTests(unittest.TestCase):
    def journal(self,root,operation,binding,*,packets=()):
        directory=root/'.runtime/readiness-windows-login'/operation;directory.mkdir(mode=0o700,parents=True)
        identity={'operationId':operation,'binding':binding,'expectedSid':SID,'profile':{},'expected':{}}
        path=directory/'credential.intent.json';path.write_text(json.dumps({'identity':identity,'callerSha256':'a'*64,'replayAllowed':False}));path.chmod(0o600)
        for name in packets:
            packet=directory/name;packet.write_text('x=1\n');packet.chmod(0o600)
    def run_history(self,module,packets):
        from agent_tools.tests.test_native_vm_spec import request
        from agent_tools.native_review_source_closure import _Held
        spec=request();binding={'provider':'raw-qemu-windows','spec':spec,'setup':{'imageName':'Windows 11 Pro','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'},'context':{'hostBootId':str(uuid.uuid4()),'pending':[]},'uri':None,'domain':None,'xmlSha256':None}
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();root.chmod(0o700);self.journal(root,str(uuid.uuid4()),binding,packets=packets)
            backend=types.SimpleNamespace(root=root,machine=spec['deploymentId'],binding=binding);held=_Held()
            try:return module._approved_predecessors(backend,str(uuid.uuid4()),held)
            finally:held.close()
    def test_journal_without_any_packet_was_never_sent_before_strands_current_skips(self):
        with self.assertRaisesRegex(ValueError,'windows_login_prior_source_untrusted'):self.run_history(before_module(),())
        self.assertEqual({},self.run_history(login,()))
    def test_retained_status_packet_or_foreign_submit_still_refuses(self):
        for packets in (('login-status-1.py',),('login-submit-1.py',)):
            with self.subTest(packets=packets):
                with self.assertRaises(ValueError):self.run_history(login,packets)


class PureHelperTests(unittest.TestCase):
    def test_expected_binds_one_fresh_full_observation(self):
        session=facts()
        value=login.expected_from_facts({'actor':{'pid':1},'hostBoot':'h','controlConnection':'c','sessionFacts':session})
        self.assertEqual({'actor':{'pid':1},'hostBoot':'h','controlConnection':'c','boot':'boot','console':1,'logon':5,'user':'fixtureuser'},value)
        for bad in (None,{},{'sessionFacts':None},{'sessionFacts':{}}):
            with self.assertRaisesRegex(ValueError,'windows_login_expected'):login.expected_from_facts(bad)
    def test_profile_shape_refuses_before_any_owner(self):
        good={'password':crop_profile(1),'lockscreen':crop_profile(2)};self.assertIs(good,login.validate_profile(good))
        for bad in (None,{},{'password':crop_profile(1)},{'password':{},'lockscreen':crop_profile(2)},
                    {'password':{**crop_profile(1),'crops':[]},'lockscreen':crop_profile(2)},
                    {'password':{**crop_profile(1),'crops':[{'rect':[0,0,9999,1],'sha256':'a'*64}]},'lockscreen':crop_profile(2)},
                    {'password':{**crop_profile(1),'crops':[{'rect':[5,5,5,5],'sha256':'a'*64}]},'lockscreen':crop_profile(2)},
                    {'password':{**crop_profile(1),'crops':[{'rect':[0,0,1,1],'sha256':'zz'}]},'lockscreen':crop_profile(2)},
                    {'password':{**crop_profile(1),'width':100},'lockscreen':crop_profile(2)}):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError,'windows_login_profile'):login.validate_profile(bad)


class RecoverLoginTests(unittest.TestCase):
    def backend(self,result,*,state='locked',profiles=None):
        machine='246a3304-86f3-4e96-bf47-d53c28f83a27';backend=types.SimpleNamespace(machine=machine,expected_sid=SID,binding={'setup':{'user':'fixtureuser'}},_guard=lambda:None,login_credential='/private/user.secret',
            login_profiles=profiles if profiles is not None else {'locked':{'name':'locked-profile'},'signed_out':{'name':'signed-out-profile'}},
            last_facts={'guest':'running','actor':{'pid':1},'hostBoot':'h','controlConnection':'c','sessionFacts':facts()})
        observed=types.SimpleNamespace(ordinary_session=state);return backend,observed
    def recover(self,backend,observed,result,state='locked'):
        with mock.patch.object(windows.guest,'validate_session',return_value={'ordinary_session':state}),mock.patch.object(windows.login_module,'execute',return_value=result)as execute:
            windows.WindowsBackend._recover_login(backend,'f'*64,observed,float('inf'));return execute
    def ready(self,backend):
        from uuid import uuid5,UUID
        return {'state':'terminal','operationId':str(uuid5(UUID(backend.machine),'f'*64)),'login':{'state':'ready'},'replayAllowed':False}
    def test_one_owner_per_recovery_bound_to_the_state_profile(self):
        backend,observed=self.backend(None);execute=self.recover(backend,observed,self.ready(backend));args=execute.call_args.args
        self.assertEqual({'name':'locked-profile'},args[2]);self.assertEqual('/private/user.secret',args[4]);self.assertEqual('boot',args[3]['boot']);self.assertEqual(self.ready(backend)['operationId'],args[1])
        backend,observed=self.backend(None,state='signed_out');execute=self.recover(backend,observed,self.ready(backend),state='signed_out');self.assertEqual({'name':'signed-out-profile'},execute.call_args.args[2])
    def follow(self,backend,observed,first,statuses,*,attempt=1,digest=None):
        """Run the real follow loop over a short real deadline with no real waits."""
        with mock.patch.object(windows.guest,'validate_session',return_value={'ordinary_session':'locked'}),mock.patch.object(windows.login_module,'execute',return_value=first)as execute,\
                mock.patch.object(windows.login_module,'observe_original',side_effect=statuses)as status,mock.patch.object(windows.time,'sleep'):
            error=None
            try:windows.WindowsBackend._recover_login(backend,'f'*64,observed,time.monotonic()+5.3,attempt,digest)
            except Exception as failure:error=failure
            return error,execute,status
    def test_anything_but_a_ready_terminal_is_followed_read_only_and_stays_an_unknown_outcome(self):
        backend,observed=self.backend(None);ok=self.ready(backend)
        for result in ({**ok,'login':{'state':'credential-submitted'}},{**ok,'replayAllowed':True},{**ok,'operationId':str(uuid.uuid4())},{**ok,'state':'unknown','reason':'credential_submission_unresolved'},{**ok,'state':'blocked','reason':'instance_login_session_changed'},{**ok,'state':'blocked','reason':'instance_login_entry_unknown'}):
            with self.subTest(result=result):
                error,execute,status=self.follow(backend,observed,result,lambda *_:{'state':'unknown'},digest='a'*64)
                self.assertIsInstance(error,windows.providers.ProviderError);self.assertEqual('windows_original_outcome_unknown',str(error));execute.assert_called_once();self.assertGreaterEqual(status.call_count,1)
    def test_a_slow_owner_is_followed_to_ready_through_lost_status_replies(self):
        backend,observed=self.backend(None);ok=self.ready(backend)
        replies=iter([ValueError('windows_login_terminal_reply'),OSError('reset'),{**ok,'state':'observed','login':{'state':'credential-submission-unresolved'}},{**ok,'state':'observed','login':{'state':'ready'}}])
        def status(*_):
            value=next(replies)
            if isinstance(value,Exception):raise value
            return value
        with mock.patch.object(windows.guest,'validate_session',return_value={'ordinary_session':'locked'}),mock.patch.object(windows.login_module,'execute',return_value={**ok,'state':'unknown','reason':'original_owner_running'}),mock.patch.object(windows.login_module,'observe_original',side_effect=status)as observer,mock.patch.object(windows.time,'sleep'):
            windows.WindowsBackend._recover_login(backend,'f'*64,observed,time.monotonic()+60,1,'a'*64)
        self.assertEqual(4,observer.call_count)
    def test_a_refusal_before_any_credential_frees_the_next_dispatch_under_a_new_operation(self):
        from uuid import uuid5,UUID
        from agent_tools import readiness
        backend,observed=self.backend(None)
        for attempt,suffix in ((1,''),(2,':2')):
            operation=str(uuid5(UUID(backend.machine),'f'*64+suffix))
            error,execute,status=self.follow(backend,observed,{'state':'blocked','reason':'instance_login_screen_unrecognized','operationId':operation,'replayAllowed':False},lambda *_:{},attempt=attempt,digest='a'*64)
            self.assertIs(type(error),readiness.RecoveryUnsubmitted);self.assertEqual(attempt,error.attempt);self.assertEqual(operation,execute.call_args.args[1]);status.assert_not_called()
        error2,*_=self.follow(backend,observed,{'state':'blocked','reason':'instance_login_screen_unrecognized'},lambda *_:{},attempt=1,digest='b'*64)
        self.assertNotEqual(error.proof_sha256,error2.proof_sha256)
    def test_a_refusal_without_a_dispatch_identity_stays_unknown(self):
        backend,observed=self.backend(None)
        with self.assertRaisesRegex(windows.providers.ProviderError,'windows_original_outcome_unknown'):
            self.recover(backend,observed,{'state':'blocked','reason':'instance_login_screen_unrecognized'})
    def test_a_refusal_that_can_follow_the_credential_never_frees_a_dispatch(self):
        self.assertNotIn('instance_login_session_changed',windows._LOGIN_NOTHING_TYPED);self.assertNotIn('instance_login_entry_unknown',windows._LOGIN_NOTHING_TYPED)
        self.assertNotIn('instance_login_owner_deadline',windows._LOGIN_NOTHING_TYPED);self.assertNotIn('instance_login_after_unresolved',windows._LOGIN_NOTHING_TYPED)
    def test_before_owner_status_echoes_the_old_packet_current_reaches_an_open_credential(self):
        import textwrap
        def run(source,*,mode,packet,credential=True,terminal=False):
            program=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='program')
            owner_init=next(ast.literal_eval(n.value.func.value) for n in ast.walk(program) if isinstance(n,ast.Assign) and getattr(n.targets[0],'id','')=='owner_init')
            body=textwrap.indent(textwrap.dedent(owner_init),'    ')
            with tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary)
                if credential:(root/('login-credential-'+OPERATION+'.intent.json')).write_text('{}')
                if terminal:(root/('login-credential-'+OPERATION+'.terminal.json')).write_text('{}')
                printed=[]
                class Owner:
                    def __init__(self,*_):pass
                    def existing(self):return {'state':'terminal','packet':packet}
                namespace={'epoch':lambda:None,'chain':lambda:None,'MODE':mode,'LOGIN_EXPECTED':{},'LOGIN_PROFILE':{},'LOGIN_SID':SID,'SPEC':{'deploymentId':'m'},'CONTEXT':{'hostBootId':'h'},'SETUP':{'user':'u'},'OPERATION':OPERATION,
                           'root':root,'json':json,'os':os,'_ProtectedOwner':Owner,'print':printed.append,'require':lambda *_:None}
                exec('def harness():\n'+body+'\n    return "fell-through"\n',namespace)
                with mock.patch.object(sys,'argv',['x','a','b','1','{}']):outcome=namespace['harness']()
                return outcome,len(printed)
        unready={'state':'owner-terminal','loginState':'credential-submitted'}
        self.assertEqual((None,1),run(digest('login.before.source'),mode='login-status',packet=unready))
        current=Path(login.__file__).read_bytes()
        self.assertEqual(('fell-through',0),run(current,mode='login-status',packet=unready))
        self.assertEqual(('fell-through',0),run(current,mode='login-status',packet={'state':'blocked','reason':'instance_login_entry_unknown'}))
        self.assertEqual((None,1),run(current,mode='login-status',packet={'state':'owner-terminal','loginState':'ready'}))
        self.assertEqual((None,1),run(current,mode='login-status',packet=unready,terminal=True))
        self.assertEqual((None,1),run(current,mode='login-status',packet={'state':'blocked','reason':'instance_login_screen_unrecognized'},credential=False))
        self.assertEqual((None,1),run(current,mode='login-submit',packet=unready),'a repeated submit never reaches the flow')
    def test_state_without_a_reviewed_profile_or_a_changed_session_refuses_before_execute(self):
        backend,observed=self.backend(None,profiles={'locked':{}},state='signed_out')
        with mock.patch.object(windows.login_module,'execute')as execute,self.assertRaisesRegex(windows.providers.ProviderError,'windows_recovery_state_changed'):
            windows.WindowsBackend._recover_login(backend,'f'*64,observed,float('inf'))
        execute.assert_not_called()
        backend,observed=self.backend(None)
        with mock.patch.object(windows.guest,'validate_session',return_value={'ordinary_session':'ready'}),mock.patch.object(windows.login_module,'execute')as execute,self.assertRaisesRegex(windows.providers.ProviderError,'windows_recovery_state_changed'):
            windows.WindowsBackend._recover_login(backend,'f'*64,observed,float('inf'))
        execute.assert_not_called()
    def test_before_backend_has_no_login_capability(self):
        tree=ast.parse(digest('windows.before.source'))
        self.assertFalse(any(isinstance(n,ast.FunctionDef) and n.name=='_recover_login' for n in ast.walk(tree)))
        self.assertIn("self.capabilities<={'reconnect','resume','wake_display','reboot'}",digest('windows.before.source').decode())


class ReadyBookkeepingTests(unittest.TestCase):
    '''A sign-in refused before anything was typed is finished; only a lost reply is worth a status read.'''
    def module(self,before):
        if not before:return windows
        filename='windows-reconcile.before.source';raw=(FIXTURE/filename).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((FIXTURE/'provenance.json').read_bytes())['sha256'][filename])
        module=types.ModuleType('agent_tools._reconcile_before_'+uuid.uuid4().hex);module.__package__='agent_tools';module.__file__=str(FIXTURE/filename)
        sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module
    def observed(self,before,outcomes):
        module=self.module(before);binding={'spec':{'deploymentId':'machine'}}
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);operation=root/'.runtime/readiness-windows-login/11111111-1111-4111-8111-111111111111';operation.mkdir(parents=True)
            (operation/'credential.intent.json').write_text(json.dumps({'identity':{'binding':binding}}));(operation/'login-submit-0.py').write_text('source')
            for index,outcome in enumerate(outcomes):(operation/('login-submit-%d.result.json'%index)).write_text(json.dumps(outcome))
            backend=types.SimpleNamespace(capabilities=frozenset({'login'}),root=root,binding=binding)
            with mock.patch.object(module.login_module,'observe_original') as status:
                module.WindowsBackend.reconcile_ready(backend,None,time.monotonic()+170)
            return status.call_count
    REFUSED={'state':'blocked','reason':'instance_login_screen_unrecognized','replayAllowed':False}
    def test_before_reads_a_refused_sign_in_on_every_readiness_call(self):
        self.assertEqual(1,self.observed(True,[self.REFUSED]))
    def test_current_skips_it_and_still_follows_a_lost_reply(self):
        self.assertEqual(0,self.observed(False,[self.REFUSED]))
        self.assertEqual(1,self.observed(False,[]))
        self.assertEqual(1,self.observed(False,[{'state':'credential-submitted','replayAllowed':False}]))
        self.assertEqual(1,self.observed(False,[{'state':'blocked','reason':'instance_login_session_changed','replayAllowed':False}]))
        self.assertEqual(0,self.observed(False,[{'state':'terminal','login':{'state':'ready'}}]))


class LeaseEvidenceTests(unittest.TestCase):
    binding=leases.WindowsLeaseBinding('246a3304-86f3-4e96-bf47-d53c28f83a27','2026-11-06T00:30:36.5000000Z',SID,'1:5','00000000:0000000000000000:0000000000000000')
    original={'admissionNonce':str(uuid.uuid4()),'programSha256':'a'*64}
    def unknown(self):
        return {'schemaVersion':1,'operationId':OPERATION,'machine':self.binding.machine,'boot':self.binding.boot,'rootGeneration':self.binding.root_generation,'state':'unknown','reason':'original_lease_evidence_unavailable','replayAllowed':False}
    def test_unavailable_read_before_reports_a_changed_owner_current_observes_again(self):
        old=before_module('leases.before.source')
        binding=old.WindowsLeaseBinding(*vars(self.binding).values())
        with self.assertRaisesRegex(ValueError,'windows_lease_original_owner_changed'):old.validate_observation(self.unknown(),binding,OPERATION,original_identity=self.original)
        result=leases.validate_observation(self.unknown(),self.binding,OPERATION,original_identity=self.original)
        self.assertEqual(('unknown',True,'observe_original'),(result['state'],result['ok'],result['nextAction']))
    def test_a_real_identity_mismatch_still_refuses(self):
        value={**self.unknown(),'reason':'original_owner_unresolved','admissionNonce':str(uuid.uuid4()),'programSha256':'a'*64}
        with self.assertRaisesRegex(ValueError,'windows_lease_original_owner_changed'):leases.validate_observation(value,self.binding,OPERATION,original_identity=self.original)
    def test_other_unknown_reasons_without_identity_still_refuse(self):
        value={**self.unknown(),'reason':'guest_identity_changed'}
        with self.assertRaisesRegex(ValueError,'windows_lease_original_owner_changed'):leases.validate_observation(value,self.binding,OPERATION,original_identity=self.original)
    def test_lease_receipts_are_published_whole(self):
        # The C# seam stays Windows-only; the native cancel race is covered natively.
        old=digest('leases.before.source').decode();new=Path(leases.__file__).read_text()
        self.assertNotIn('.pending-',old);self.assertIn('string temp=path+".pending-"+Guid.NewGuid().ToString("N")',new);self.assertIn('File.Move(temp,path);',new)


if __name__=='__main__':unittest.main()
