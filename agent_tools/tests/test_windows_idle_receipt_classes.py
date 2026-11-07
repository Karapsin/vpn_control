"""Host receipts of finished work close; anything open or foreign still blocks idle.

Each case runs the actual nested host_work of the whole preserved packet source
(the original refusal on clone 246a3304) and of the current one, over real files.
"""
import ast,hashlib,json,os,re,stat,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import readiness_windows_remote as current_remote

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
PNG=b'\x89PNG\r\n\x1a\n'+b'frame'*40
ACTOR={'pid':4242,'startTicks':99}


def before_source():
    raw=(FIXTURE/'remote.before.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256']['remote.before.source']:
        raise AssertionError('remote beforeimage changed')
    return raw


def current_source():return Path(current_remote.__file__).read_bytes()


def host_work_module(raw):
    nodes=[n for n in ast.walk(ast.parse(raw)) if isinstance(n,ast.FunctionDef) and n.name=='host_work']
    if len(nodes)!=1:raise AssertionError('host_work is not unique')
    return ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))


class Receipts:
    def __init__(self,root):
        self.root=root;self.rpc=mock.Mock(side_effect=AssertionError('no guest call expected'))
        self.processes=[{'pid':1,'name':'System'}]
    def write(self,name,value):
        path=self.root/name;path.write_bytes(value if type(value)is bytes else json.dumps(value).encode());path.chmod(0o600)
    def run(self,raw):
        root=self.root
        def require(value,reason):
            if not value:raise ValueError(reason)
        def read(name):return json.loads((root/name).read_text())
        def save(name,value):
            path=root/name
            with path.open('x')as stream:json.dump(value,stream)
        def private(path):
            info=os.lstat(path);require(stat.S_ISREG(info.st_mode),'instance_private');return info
        def generation(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        namespace={'root':root,'os':os,'re':re,'hashlib':hashlib,'read':read,'read_guest_terminal':read,'save':save,'require':require,'private':private,'generation':generation,
                   'rpc':self.rpc,'result':{'idleFacts':{'processes':self.processes}},'current_actor':ACTOR,'SPEC':{'deploymentId':str(uuid.uuid4())},'ORIGINAL_HOST_PHASES':[],'CREATOR_ENROLLED':False}
        exec(compile(host_work_module(raw),'<host-work>','exec'),namespace)
        return namespace['host_work']()
    def inspection(self,**change):
        operation=str(uuid.uuid4());prefix='inspection-'+operation;leaf='setup-frame-'+operation.replace('-','')+'.png'
        intent={'schemaVersion':1,'operationId':operation,'probe':False,'before':{'qemu':{'pid':ACTOR['pid'],'startTicks':ACTOR['startTicks']}}}
        intent.update(change.get('intent',{}))
        self.write(prefix+'.intent.json',intent)
        self.write(leaf,change.get('png',PNG))
        result={'frame':leaf,'bytes':len(PNG),'sha256':hashlib.sha256(PNG).hexdigest()};result.update(change.get('result',{}))
        if change.get('complete',True):self.write(prefix+'.result.json',result)
        for marker in change.get('markers',()):self.write(prefix+marker,{'enterSent':True})
        return prefix
    def guest_program(self,label,*,terminal='.terminal.json',exitcode=0):
        operation=str(uuid.uuid4());prefix='readiness-'+operation+'-'+label
        self.write(prefix+'.intent.json',{'operationId':operation});self.write(prefix+'.ack.json',{'operationId':operation,'ack':{'pid':7777},'replayAllowed':False})
        if terminal:self.write(prefix+terminal,{'exited':True,'exitcode':exitcode})
        return prefix
    def owner(self,packet,operation=None):
        operation=operation or str(uuid.uuid4());prefix='login-owner-'+operation;packet={'operationId':operation,**packet}
        self.write(prefix+'.intent.json',{'operationId':operation});self.write(prefix+'.terminal.json',{'packet':packet});return operation


class IdleReceiptClassTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve()/'vm';self.root.mkdir(mode=0o700);self.receipts=Receipts(self.root)
    def outcome(self,raw=None):
        result=self.receipts.run(current_source() if raw is None else raw);return result['terminalCount'],sorted(row['reason'] for row in result['unresolved'])

    def test_completed_frame_inspection_before_blocks_current_closes(self):
        self.receipts.inspection()
        self.assertEqual((0,['unclassified_original_intent']),self.outcome(before_source()))
        self.assertEqual((1,[]),self.outcome())

    def test_inspection_with_any_gap_stays_open(self):
        for change in ({'intent':{'probe':True}},{'markers':('.input-started.json',)},{'markers':('.input-complete.json',)},{'complete':False},
                       {'png':PNG+b'changed'},{'result':{'sha256':'0'*64}},{'result':{'frame':'setup-frame-other.png'}},
                       {'intent':{'before':{'qemu':{'pid':1,'startTicks':1}}}},{'intent':{'operationId':str(uuid.uuid4())}},{'intent':{'extra':True}}):
            with self.subTest(change=change):
                for path in self.root.iterdir():path.unlink()
                self.receipts.inspection(**change)
                self.assertEqual((0,['original_inspection_unresolved']),self.outcome())

    def test_read_only_program_left_pending_is_collected_through_its_original_pid(self):
        prefix=self.receipts.guest_program('idle',terminal=None)
        self.receipts.rpc=mock.Mock(return_value={'exited':True,'exitcode':0})
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome(before_source()))
        self.assertEqual((1,[]),self.outcome());self.receipts.rpc.assert_called_once_with('guest-exec-status',{'pid':7777})
        self.assertTrue((self.root/(prefix+'.observed-terminal.json')).exists())
        self.assertEqual((1,[]),self.outcome());self.receipts.rpc.assert_called_once()

    def test_read_only_program_still_running_stays_open(self):
        self.receipts.guest_program('interactive',terminal=None);self.receipts.rpc=mock.Mock(return_value={'exited':False})
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())

    def test_program_the_agent_forgot_closes_only_with_its_pid_absent_from_the_census(self):
        prefix=self.receipts.guest_program('login-after-0123456789ab',terminal=None);self.receipts.rpc=mock.Mock(side_effect=ValueError())
        self.receipts.processes=[{'pid':7777,'name':'powershell.exe'}]
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
        self.receipts.processes=[{'pid':1,'name':'System'}]
        self.assertEqual((1,[]),self.outcome())
        self.assertTrue((self.root/(prefix+'.orphan-closed.json')).exists())
        self.receipts.rpc.reset_mock();self.assertEqual((1,[]),self.outcome());self.receipts.rpc.assert_not_called()

    def test_lost_transport_is_not_treated_as_a_forgotten_program_when_the_census_is_absent(self):
        self.receipts.guest_program('session',terminal=None);self.receipts.rpc=mock.Mock(side_effect=OSError());self.receipts.processes=None
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())

    def test_lost_exec_reply_read_only_closes_only_when_no_other_shell_runs(self):
        prefix=self.receipts.guest_program('idle',terminal=None);(self.root/(prefix+'.ack.json')).unlink()
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome(before_source()))
        self.receipts.processes=[{'pid':5,'name':'powershell.exe','self':False}]
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
        self.receipts.processes=[{'pid':6,'name':'powershell.exe','self':True},{'pid':1,'name':'System','self':False}]
        self.assertEqual((1,[]),self.outcome());self.assertTrue((self.root/(prefix+'.orphan-closed.json')).exists())
        self.receipts.processes=None;self.assertEqual((1,[]),self.outcome())
    def test_lost_exec_reply_of_an_effectful_program_stays_open(self):
        prefix=self.receipts.guest_program('lease-cancel',terminal=None);(self.root/(prefix+'.ack.json')).unlink()
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
    def test_signal_terminal_closes_on_every_census(self):
        prefix=self.receipts.guest_program('idle',terminal=None);self.receipts.rpc=mock.Mock(return_value={'exited':True,'signal':-1073741510})
        self.assertEqual((1,[]),self.outcome());self.assertEqual((1,[]),self.outcome())
        self.receipts.write(prefix+'.terminal.json',{'exited':True,'signal':5});self.assertEqual((1,[]),self.outcome())
    def test_ended_without_any_code_stays_open(self):
        self.receipts.guest_program('idle',terminal=None);self.receipts.rpc=mock.Mock(return_value={'exited':True})
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
    def test_refused_guard_or_lost_transport_write_no_false_receipt(self):
        prefix=self.receipts.guest_program('idle',terminal=None)
        for failure in (ValueError('instance_process_changed'),TimeoutError('collection-deadline'),OSError('reset')):
            with self.subTest(failure=failure):
                self.receipts.rpc=mock.Mock(side_effect=failure)
                self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
                self.assertFalse((self.root/(prefix+'.orphan-closed.json')).exists())
    def test_a_reused_pid_of_another_program_does_not_keep_a_forgotten_one_open(self):
        self.receipts.guest_program('session',terminal=None);self.receipts.rpc=mock.Mock(side_effect=ValueError())
        self.receipts.processes=[{'pid':7777,'name':'explorer.exe'}]
        self.assertEqual((1,[]),self.outcome())
    def test_unreadable_intent_is_named_and_never_aborts_the_census(self):
        prefix='readiness-'+str(uuid.uuid4())+'-idle';(self.root/(prefix+'.intent.json')).write_bytes(b'')
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())
    def test_an_unfinished_stop_blocks_idle(self):
        self.receipts.write('stop-intent.json',{'schemaVersion':1})
        self.assertEqual((0,[]),self.outcome(before_source()))
        self.assertEqual((0,['original_lifecycle_unresolved']),self.outcome())
        self.receipts.write('stop-result.json',{});self.assertEqual((0,[]),self.outcome())
    def test_status_closes_a_login_program_that_ended_with_no_retained_output(self):
        prefix=self.receipts.guest_program('login-after-0123456789ab',terminal='.observed-terminal.json',exitcode=1)
        self.assertEqual((1,[]),self.outcome())
    def test_effectful_program_without_terminal_never_closes_and_the_agent_is_not_asked(self):
        for label in ('lease-acquire','lease-cancel','lease-enroll','job-start-0123456789abcdef','job-enroll-0123456789abcdef','login-screen-pin-0123456789ab'):
            with self.subTest(label=label):
                for path in self.root.iterdir():path.unlink()
                self.receipts.guest_program(label,terminal=None)
                self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())

    def test_failed_read_only_program_retained_terminal_closes(self):
        self.receipts.guest_program('idle',terminal='.observed-terminal.json',exitcode=1)
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome(before_source()))
        self.assertEqual((1,[]),self.outcome())

    def test_sleep_capability_receipt_before_blocks_current_closes(self):
        self.receipts.guest_program('sleep-capability')
        self.assertEqual((0,['unclassified_original_intent']),self.outcome(before_source()))
        self.assertEqual((1,[]),self.outcome())

    def test_finished_sign_in_owner_closes(self):
        operation=self.receipts.owner({'state':'owner-terminal','loginState':'ready'})
        self.receipts.write('login-credential-'+operation+'.intent.json',{});self.receipts.write('login-credential-'+operation+'.terminal.json',{'state':'ready'})
        self.receipts.write('login-preparation-'+operation+'-wake.intent.json',{});self.receipts.write('login-preparation-'+operation+'-wake.terminal.json',{'state':'ready-observed'})
        self.assertEqual((0,['unclassified_original_intent']*3),self.outcome(before_source()))
        self.assertEqual((3,[]),self.outcome())

    def test_refused_owner_before_any_credential_closes_with_its_public_preparation(self):
        operation=self.receipts.owner({'state':'blocked','reason':'instance_login_screen_unrecognized'})
        self.receipts.write('login-preparation-'+operation+'-dismiss.intent.json',{})
        self.assertEqual((2,[]),self.outcome())

    def test_any_open_credential_stays_blocking(self):
        operation=self.receipts.owner({'state':'owner-terminal','loginState':'credential-submitted'})
        self.receipts.write('login-credential-'+operation+'.intent.json',{})
        self.assertEqual((0,['original_login_work_unresolved','original_login_work_unresolved']),self.outcome())
        for path in self.root.iterdir():path.unlink()
        operation=self.receipts.owner({'state':'blocked','reason':'instance_login_entry_unknown'})
        self.receipts.write('login-credential-'+operation+'.intent.json',{})
        self.assertEqual((0,['original_login_work_unresolved','original_login_work_unresolved']),self.outcome())

    def test_owner_without_a_terminal_stays_blocking(self):
        self.receipts.write('login-owner-'+str(uuid.uuid4())+'.intent.json',{})
        self.assertEqual((0,['original_login_work_unresolved']),self.outcome())

    def test_update_policy_that_ended_unverified_closes_its_receipt(self):
        prefix='fixture-update-policy-'+str(uuid.uuid4())
        self.receipts.write(prefix+'.intent.json',{'replayAllowed':False});self.receipts.write(prefix+'.terminal.json',{'state':'update-policy-unverified','replayAllowed':False})
        self.assertEqual((1,[]),self.outcome())
    def test_update_policy_receipt_closes_only_with_its_verified_terminal(self):
        prefix='fixture-update-policy-'+str(uuid.uuid4())
        self.receipts.write(prefix+'.intent.json',{'replayAllowed':False})
        self.assertEqual((0,['unclassified_original_intent']),self.outcome(before_source()))
        self.assertEqual((0,['original_fixture_policy_unresolved']),self.outcome())
        self.receipts.write(prefix+'.terminal.json',{'state':'update-policy-applied','replayAllowed':False})
        self.assertEqual((1,[]),self.outcome())

    def test_update_policy_program_without_terminal_stays_open(self):
        self.receipts.guest_program('update-policy',terminal=None)
        self.assertEqual((0,['original_guest_work_unresolved']),self.outcome())

    def test_public_fixture_steps_need_their_terminal(self):
        for kind in ('test-lock','field-capture','screen-pin'):
            with self.subTest(kind=kind):
                for path in self.root.iterdir():path.unlink()
                prefix='login-'+kind+'-'+str(uuid.uuid4())
                self.receipts.write(prefix+'.intent.json',{'replayAllowed':False})
                self.assertEqual((0,['original_login_work_unresolved']),self.outcome())
                self.receipts.write(prefix+'.terminal.json',{'replayAllowed':False})
                self.assertEqual((1,[]),self.outcome())

    def test_legacy_and_unknown_receipts_are_never_adopted(self):
        for name,reason in (('login-wake-'+str(uuid.uuid4())+'.intent.json','original_login_work_unresolved'),
                            ('login-dismiss-'+str(uuid.uuid4())+'.intent.json','original_login_work_unresolved'),
                            ('fixture-profile-'+str(uuid.uuid4())+'.intent.json','unclassified_original_intent'),
                            ('inspection-not-a-uuid.intent.json','unclassified_original_intent')):
            with self.subTest(name=name):
                for path in self.root.iterdir():path.unlink()
                self.receipts.write(name,{})
                self.assertEqual((0,[reason]),self.outcome())


class SignedOutWakeTests(unittest.TestCase):
    """The admission statements of the actual wake branch, before and current."""
    def admitted(self,raw,fresh,before):
        tree=ast.parse(raw)
        branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and isinstance(n.test,ast.Compare)
                    and getattr(n.test.left,'id','')=='MODE' and getattr(n.test.comparators[0],'value','')=='wake_display')
        body=[];seen=False
        for statement in branch.body:
            if isinstance(statement,ast.Assign) and getattr(statement.targets[0],'id','')=='fresh':seen=True;continue
            if seen and isinstance(statement,ast.Assign) and getattr(statement.targets[0],'id','')=='mice':break
            if seen:body.append(statement)
        def require(value,reason):
            if not value:raise ValueError(reason)
        namespace={'require':require,'fresh':fresh,'before':before,'SPEC':{'deploymentId':'machine'}}
        exec(compile(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])),'<wake-admission>','exec'),namespace)
    def facts(self,**change):
        value={'machine':'MACHINE','boot':'b','console':1,'expectedSid':'SID','tokenSid':'SID','ordinary':True,'session':{'State':0,'Flags':0,'User':'fixtureuser','Logon':5}}
        session=change.pop('session',{});value.update(change);value['session']={**value['session'],**session};return value
    def test_signed_out_sign_in_screen_before_refused_current_admitted(self):
        signed_out=self.facts(tokenSid=None,session={'State':1,'User':'','Logon':0})
        with self.assertRaisesRegex(ValueError,'instance_recovery_session_changed'):self.admitted(before_source(),signed_out,signed_out)
        self.admitted(current_source(),signed_out,signed_out)
    def test_locked_session_stays_admitted_in_both(self):
        locked=self.facts()
        self.admitted(before_source(),locked,locked);self.admitted(current_source(),locked,locked)
    def test_changed_identity_still_refuses(self):
        before=self.facts()
        for fresh in (self.facts(boot='other'),self.facts(console=2),self.facts(ordinary=False),self.facts(tokenSid='OTHER'),self.facts(session={'Logon':6}),self.facts(session={'State':1}),
                      self.facts(tokenSid=None,session={'User':''})):
            with self.subTest(fresh=fresh):
                with self.assertRaisesRegex(ValueError,'instance_recovery_session_changed'):self.admitted(current_source(),fresh,before)


if __name__=='__main__':unittest.main()
