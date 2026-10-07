"""Actual unchanged TLS/action + authenticated phase protocol; inert OS only.

Historical causal RED source/log are retained separately. Native acceptance is
never inferred from these TempFS JVM/ADB child programs.
"""
import json
import io,os,sys
from contextlib import redirect_stdout,redirect_stderr
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import ExitStack

from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests import test_android_installer_component_bundle as fixtures
from scripts.test_android_no_update_tls_preflight import FakeAdb

NEW_OWNER='34a12ada-9a54-4a10-8b72-c8e87e9a9069'
TARGET_OWNER='58d54342-1278-4b4b-a98f-b5128a3335ce'
OPERATION='e2054e17-a98d-4bd1-b955-e08f85f7de75'
FOREIGN='8cc56586-146b-45ce-afb6-33ed64a3092d'


class InProcessProduct:
    """Execute the exact inert child source; preserve real pipe EOF/capture ABI."""
    def __init__(self,argv,**kwargs):
        self.returncode=None;self.stdin=None;self.pid=424242
        output,error=io.StringIO(),io.StringIO();original=sys.argv
        try:
            sys.argv=list(argv)
            with redirect_stdout(output),redirect_stderr(error):
                try:exec(compile(Path(argv[0]).read_bytes(),argv[0],'exec'),{'__name__':'__main__'})
                except SystemExit as exit:self.returncode=exit.code if type(exit.code)is int else 0
            if self.returncode is None:self.returncode=0
        finally:sys.argv=original
        self.stdout=self.pipe(output.getvalue().encode());self.stderr=self.pipe(error.getvalue().encode())
    @staticmethod
    def pipe(raw):
        read,write=os.pipe()
        try:os.write(write,raw)
        finally:os.close(write)
        return os.fdopen(read,'rb',buffering=0)
    def poll(self):return self.returncode
    def wait(self,timeout=None):return self.returncode
    def kill(self):self.returncode=-9
    def terminate(self):self.returncode=-15


class InstallerPhaseGuardTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.BundleTests();self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        self.selected,self.backend,self.args,self.state_path,self.log,_,_=self.fixture.fixture()
        self.backend['subprocess'].Popen=InProcessProduct
        self.args.cli_environment=self.backend['LAUNCH']['environment']
        self.installed=self.fixture.root/'installed.apk';self.installed.write_bytes(self.args.base_apk.read_bytes())
        self.original_intent=self.args.intent_file.read_bytes()

    def state(self,**changes):
        state=json.loads(self.state_path.read_bytes());state.update(changes)
        self.state_path.write_text(json.dumps(state));return state

    def rows(self):return [json.loads(line) for line in self.log.read_text().splitlines()]

    def product_children(self,foreign_pending=False):
        # Real private executable children provide only the OS/product response
        # seam. Actual generated component transport and guard code are retained.
        java=Path(self.backend['EXTERNAL']['selectedJdk']['root'])/'bin/java'
        adb=Path(self.backend['LAUNCH']['adbPath'])
        raw=java.read_text().replace('BASE='+repr(str(self.args.base_apk)), 'BASE='+repr(str(self.installed)))
        raw=raw.replace("owner=args[args.index('--controller-id')+1]", "owner=args[args.index('--controller-id')+1] if '--controller-id' in args else None")
        needle=" owner=args[args.index('--controller-id')+1] if '--controller-id' in args else None\n"
        branch=''' if state.get('discoverConflict') and owner is None:
  print(json.dumps({'ok':False,'code':'CONFLICT','final':True,'controllerId':state['owner'],'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'}}));sys.exit(0)
 if state.get('ownerDrift') and args[-2:]==['operations','list']:
  state['owner']='8cc56586-146b-45ce-afb6-33ed64a3092d';pathlib.Path(STATE).write_text(json.dumps(state))
 if args[-2:]==['updates','install']:
  interactive='--interactive' in args
  if interactive:
   state['operations']=[{'id':OP,'final':False,'code':'ACCEPTED'}]+EXTRA
   pathlib.Path(STATE).write_text(json.dumps(state))
   print(json.dumps({'ok':True,'code':'ACCEPTED','final':False,'controllerId':state['owner'],'configurationRevision':0,'operationId':OP,'data':{}}));sys.exit(0)
  print(json.dumps({'ok':False,'code':'INTERACTION_REQUIRED','final':True,'controllerId':state['owner'],'configurationRevision':0,'data':{}}));sys.exit(1)
 if args[-3:-1] in (['operations','status'],['operations','wait']):
  state['operations']=[{'id':OP,'final':True,'code':'OK'}]
  pathlib.Path(STATE).write_text(json.dumps(state))
  print(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':state['owner'],'configurationRevision':0,'operationId':OP,'data':{'installerStarted':True,'installed':None,'installPhase':'handed_off','availableVersion':'2.2.3','installReceiptId':'owned-receipt','installSessionId':42}}));sys.exit(0)
 if args[-2:]==['updates','status'] and state.get('terminal'):
  installed=state['terminal']=='installed'
  print(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':state['owner'],'configurationRevision':0,'data':{'installReceipt':{'installReceiptId':'owned-receipt','installSessionId':state.get('terminalSession',42),'installPhase':state['terminal'],'installed':installed}}}));sys.exit(0)
'''.replace('OP',repr(OPERATION)).replace('EXTRA',repr([{'id':FOREIGN,'final':False}] if foreign_pending else []))
        self.assertEqual(1,raw.count(needle));raw=raw.replace(needle,needle+branch)
        # Actual public envelope requestId changes per request; operations-list
        # DTO identity is id, while command envelopes carry operationId.
        raw=raw.replace("json.dumps({'ok':","json.dumps({'requestId':__import__('uuid').uuid4().hex,'ok':")
        raw=raw.replace("print('versionName=2.2.2 versionCode=16840')", "print('versionName=2.2.3 versionCode=16860' if state.get('terminal')=='installed' else 'versionName=2.2.2 versionCode=16840')")
        java.write_text(raw)
        # ADB shares the same actual device state and independent installed file.
        adbraw=adb.read_text().replace('BASE='+repr(str(self.args.base_apk)), 'BASE='+repr(str(self.installed)))
        adbraw=adbraw.replace("print('versionName=2.2.2 versionCode=16840')", "print('versionName=2.2.3 versionCode=16860' if state.get('terminal')=='installed' else 'versionName=2.2.2 versionCode=16840')")
        adb.write_text(adbraw)
        self.backend['LAUNCH']['adbFacts']['generation']=self.backend['fp'](adb.stat())
        self.backend['EXTERNAL']['selectedJdk']=self.backend['external_jdk']('jdk17')

    def campaign(self,expected='installed',foreign_pending=False,drift=False,setup_fault=None,session_fault=False):
        self.product_children(foreign_pending)
        intent=json.loads(self.args.intent_file.read_bytes());intent['expectedTerminal']=expected
        self.args.intent_file.write_text(json.dumps(intent));self.original_intent=self.args.intent_file.read_bytes()
        self.args.expected_terminal=expected
        self.guard=bundle.CurrentGuard(self.fixture.receipt,self.selected,self.backend,self.args)
        restore=self.selected['adapter'].install(self.selected['lifecycle'],self.selected['tls'],self.backend,self.args,self.guard)
        self.addCleanup(restore)
        self.args.intent=self.selected['lifecycle'].validate_intent(self.args)
        tls=self.selected['tls'];lifecycle=self.selected['lifecycle'];fixture=self
        class EpochAdb(FakeAdb):
            def unroot(self):
                super().unroot()
                census=''.join(name+'\t'+str(pid)+'\t'+str(pid)+' ('+name+') '+' '.join(['S']+['0']*18+[str(tick)])+'\n' for pid,name,tick in [(11,'adbd',101),(22,'zygote64',100)])
                fixture.state(processCensus=census)
            def exec_out_bytes(self,*words):return fixture.installed.read_bytes()
            def shell(self,*words):
                if words==('pidof','zygote64'):return '22'
                if words in (('getprop','ro.kernel.qemu.avd_name'),('getprop','ro.boot.qemu.avd_name')):return 'owned-fixture'
                if words==('dumpsys','package','com.kardinal.vpncontrol'):
                    return 'versionName=2.2.3 versionCode=16860 flags=[HAS_CODE]' if json.loads(fixture.state_path.read_bytes()).get('terminal')=='installed' else 'versionName=2.2.2 versionCode=16840 flags=[HAS_CODE]'
                if words==('am','force-stop','com.kardinal.vpncontrol'):
                    fixture.state(owner=NEW_OWNER,discoverConflict=setup_fault=='conflict',ownerDrift=setup_fault=='drift')
                return super().shell(*words)
        self.adb=EpochAdb()
        args=SimpleNamespace(**vars(self.args));args.intent=self.args.intent
        args.certificate=self.fixture.root/'fixture-ca.pem';args.certificate.write_text('inert-certificate')
        args.leaf_certificate=self.fixture.root/'fixture-leaf.pem';args.leaf_certificate.write_text('inert-leaf')
        args.fixture_parent=self.args.output;args.device_port=45629;args.host_port=61000
        args.staging='/data/local/tmp/vpn-control-installer-api29';args.receipt=self.args.output/'lifecycle-receipt.json'
        args.expected_avd=self.args.avd;args.expected_api=self.args.api
        args.expected_version=self.args.base_version;args.expected_code=self.args.base_code
        args.probe_output=self.args.output/'probe.json';args.governed_callbacks=True
        args.reconciliation_timeout_seconds=5;args.reconciliation_poll_seconds=0.01
        args.continue_file=self.args.output/'continue';args.handoff_ready_file=self.args.output/'handoff-ready'
        self.args.probe_output=args.probe_output;self.args.governed_callbacks=True
        self.args.continue_file=args.continue_file;self.args.fixture_parent=args.fixture_parent
        def handoff_ready(current_args,operation):return True
        def continue_ui(path,parent):
            # This is the sole OS UI observation seam; immutable identity comes
            # from the ACTUAL action's handoff file and retained command reply.
            handoff=json.loads((self.args.output/'handoff.json').read_bytes())['identity']
            self.assertEqual(OPERATION,handoff['operationId'])
            if expected=='installed':self.installed.write_bytes(self.args.target_apk.read_bytes())
            self.state(owner=TARGET_OWNER if expected=='installed' else NEW_OWNER,terminal=expected,operations=[],terminalSession=43 if session_fault else 42)
            xml=b'<hierarchy owned="true"/>'
            lifecycle.write_cli_evidence(SimpleNamespace(intent=current_args_intent(),output=self.args.output),
                'callback-continue-evidence.json',{'correlationId':intent['correlationId'],'sourceSha':intent['pair']['sourceSha'],
                'targetArtifactId':intent['pair']['targetArtifactId'],'phase':'continue','uiSha256':__import__('hashlib').sha256(xml).hexdigest(),
                **{key:handoff[key] for key in ('operationId','receiptId','sessionId')},'focusedInstaller':None})
            for name,raw in [('callback-continue-ui.xml',xml),('continue',b'continue\n')]:
                bundle._write(self.args.output/name,raw)
            if drift:self.state(owner=FOREIGN)
        def current_args_intent():return self.guard._command_binding()
        seams={'Adb':mock.Mock(return_value=self.adb),'require_device_time_within_certificates':mock.Mock(),
            'secure_private_fixture_files':mock.Mock(),'device_mode':mock.Mock(return_value=0o755),
            'device_label':mock.Mock(return_value='u:object_r:system_security_cacerts_file:s0'),
            'require_android_certificate_store_layout':mock.Mock(),'android_ca_store_filename':mock.Mock(return_value='fixture.0'),
            'require_android_ca_store_entry':mock.Mock(),'relabel_staged_ca_store':mock.Mock(return_value=[args.staging+'/fixture.0'])}
        with ExitStack() as stack:
            for name,value in seams.items():stack.enter_context(mock.patch.object(tls,name,value))
            stack.enter_context(mock.patch.object(lifecycle,'await_handoff_ready',side_effect=handoff_ready))
            stack.enter_context(mock.patch.object(lifecycle,'wait_for_continue_file',side_effect=continue_ui))
            # Only fixed OS dialog observations are simulated. Both original
            # governed-callback parsers and identity comparisons still execute.
            def ready(current_args,operation):
                xml=b'<hierarchy package="com.android.packageinstaller"/>'
                value={'correlationId':intent['correlationId'],'sourceSha':intent['pair']['sourceSha'],
                    'targetArtifactId':intent['pair']['targetArtifactId'],'phase':'handoff-ready',
                    'uiSha256':__import__('hashlib').sha256(xml).hexdigest(),'operationId':operation,
                    'receiptId':'owned-receipt','sessionId':42,'owner':NEW_OWNER,'revision':0,
                    'focusedInstaller':'com.android.packageinstaller'}
                lifecycle.write_cli_evidence(current_args,'callback-handoff-ready-evidence.json',value)
                bundle._write(self.args.output/'callback-handoff-ready-ui.xml',xml)
                return True
            stack.enter_context(mock.patch.object(lifecycle,'await_handoff_ready',side_effect=ready))
            result=tls.run_fixture_lifecycle(args,lifecycle.action,target_install=True,
                ca_store_target='/system/etc/security/cacerts',expected_proxy='null')
        self.assertEqual({},self.adb.reverse_map);self.assertEqual('null',self.adb.proxy);self.assertFalse(self.adb.rooted)
        self.assertEqual(self.original_intent,self.args.intent_file.read_bytes())
        self.assertEqual(1,len([row for row in self.rows() if row[-2:]==['updates','install'] and '--interactive'in row]))
        return result

    def test_selected_tls_environment_clone_rejected_before_current_guard(self):
        import types
        module=self.selected['tls'];function=module.public_cli_environment
        clone=types.FunctionType(function.__code__,dict(function.__globals__),argdefs=function.__defaults__)
        with mock.patch.object(module,'public_cli_environment',clone):
            with self.assertRaisesRegex(ValueError,'hook_changed'):
                bundle._selected_modules(self.fixture.receipt,self.selected)
        self.assertFalse(self.log.exists())

    def test_selected_tls_environment_changed_defaults_rejected_before_guard(self):
        import types
        module=self.selected['tls'];function=module.public_cli_environment
        clone=types.FunctionType(function.__code__,function.__globals__,argdefs=('foreign',))
        with mock.patch.object(module,'public_cli_environment',clone):
            with self.assertRaisesRegex(ValueError,'hook_changed'):
                bundle._selected_modules(self.fixture.receipt,self.selected)
        self.assertFalse(self.log.exists())

    def test_tls_setup_action_fresh_epoch_full_actual_lifecycle(self):
        result=self.campaign()
        self.assertEqual('terminal-confirmed',result['probe']['acceptance'])
        self.assertEqual(TARGET_OWNER,self.guard.owner)
        action=json.loads((self.args.output/'component-guard-action-admission.json').read_bytes())['record']
        self.assertEqual(NEW_OWNER,action['owner']);self.assertNotEqual(action['setupFacts']['processes'],action['actionFacts']['processes'])
        self.assertEqual('installer-reconciliation',self.guard.phase)

    def test_owned_pending_operation_then_cancellation_full_actual_lifecycle(self):
        result=self.campaign('cancelled')
        self.assertEqual('terminal-confirmed',result['probe']['acceptance'])
        self.assertEqual(OPERATION,self.guard.accepted_operation)
        self.assertEqual(42,self.guard.handoff['sessionId'])
        with self.assertRaisesRegex(ValueError,'action_admission_required'):
            self.selected['lifecycle'].invoke(self.args.cli,self.args.serial,'updates','download')
        self.assertEqual(1,len([row for row in self.rows() if row[-2:]==['updates','download']]))

    def test_target_read_scope_never_authorizes_new_install(self):
        self.campaign()
        self.assertEqual('installer-reconciliation',self.guard.phase)
        self.assertEqual(TARGET_OWNER,self.guard._command_binding()['expectedOwner'])
        with self.assertRaisesRegex(ValueError,'action_admission_required'):
            self.selected['lifecycle'].invoke(self.args.cli,self.args.serial,'updates','install',interactive=True,asynchronous=True)
        self.assertEqual(1,len([row for row in self.rows() if row[-2:]==['updates','install'] and '--interactive'in row]))

    def test_foreign_pending_rejected_after_single_effect_cleanup_preserved(self):
        with self.assertRaises(self.selected['lifecycle'].InvocationFailure):self.campaign(foreign_pending=True)
        self.assertEqual(1,len([row for row in self.rows() if row[-2:]==['updates','install'] and '--interactive'in row]))
        self.assertEqual({},self.adb.reverse_map);self.assertEqual('null',self.adb.proxy);self.assertFalse(self.adb.rooted)
        self.assertTrue((self.args.output/'component-effect-unknown.json').is_file())

    def test_conflict_discovery_never_adopts_owner_or_starts_check(self):
        with self.assertRaisesRegex(ValueError,'fresh_owner_unknown'):self.campaign(setup_fault='conflict')
        self.assertFalse((self.args.output/'component-guard-action-admission.json').exists())
        self.assertEqual(0,len([row for row in self.rows() if row[-2:]==['updates','check']]))
        self.assertEqual(fixtures.OWNER,self.guard.owner)
        self.assertEqual({},self.adb.reverse_map)

    def test_owner_drift_between_two_setup_reads_is_not_admitted(self):
        with self.assertRaisesRegex(ValueError,'fresh_owner_unknown'):self.campaign(setup_fault='drift')
        self.assertFalse((self.args.output/'component-guard-action-admission.json').exists())
        self.assertEqual(0,len([row for row in self.rows() if row[-2:]==['updates','check']]))
        self.assertEqual({},self.adb.reverse_map)

    def test_foreign_terminal_session_never_admits_target_owner(self):
        with self.assertRaisesRegex(RuntimeError,'reconciliation outcome unknown'):self.campaign(session_fault=True)
        self.assertFalse((self.args.output/'component-guard-reconciliation-admission.json').exists())
        self.assertEqual(NEW_OWNER,self.guard.owner)
        self.assertEqual({},self.adb.reverse_map);self.assertEqual('null',self.adb.proxy)
        self.assertEqual(1,len([row for row in self.rows() if row[-2:]==['updates','install'] and '--interactive'in row]))

    def test_unadmitted_mutation_and_memory_phase_claim_have_zero_effects(self):
        self.guard=bundle.CurrentGuard(self.fixture.receipt,self.selected,self.backend,self.args)
        restore=self.selected['adapter'].install(self.selected['lifecycle'],self.selected['tls'],self.backend,self.args,self.guard)
        self.addCleanup(restore)
        with self.assertRaisesRegex(ValueError,'action_admission_required'):
            self.selected['lifecycle'].invoke(self.args.cli,self.args.serial,'updates','check')
        self.guard.phase='installer-action'
        with self.assertRaisesRegex(ValueError,'unadmitted_phase'):
            self.selected['lifecycle'].invoke(self.args.cli,self.args.serial,'updates','check')
        self.assertEqual(0,len([row for row in self.rows() if row[-2:]==['updates','check']]))
        self.assertFalse((self.args.output/'component-effect-check.json').exists())


if __name__=='__main__':unittest.main()


class PublicEnvelopeSchemaTests(unittest.TestCase):
    def test_actual_operation_list_id_admits_only_retained_operation(self):
        row={'id':OPERATION,'final':False,'code':'ACCEPTED'}
        guard=SimpleNamespace(owner=NEW_OWNER,revision=0,phase='installer-action',accepted_operation=OPERATION,
            _physical=lambda:None,_capture=lambda record:None)
        def command(words,*args):
            data={'operations':[row]} if words==['operations','list'] else {'runtimeRunning':False,'runtimeObservation':'stopped'}
            return {'returncode':0,'stdout':{'requestId':__import__('uuid').uuid4().hex,'ok':True,'code':'OK',
                'final':True,'controllerId':NEW_OWNER,'configurationRevision':0,'data':data}}
        guard.backend={'component_command':command}
        bundle.CurrentGuard._public_reads(guard)
        row['id']=FOREIGN
        with self.assertRaisesRegex(ValueError,'operations_unknown'):bundle.CurrentGuard._public_reads(guard)

    def test_unique_request_ids_do_not_change_stable_status_authority(self):
        values=[{'requestId':'first','ok':True,'code':'OK','final':True,'controllerId':NEW_OWNER,
                    'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'}},
                {'requestId':'ops','ok':True,'code':'OK','final':True,'controllerId':NEW_OWNER,
                    'configurationRevision':0,'data':{'operations':[]}},
                {'requestId':'last','ok':True,'code':'OK','final':True,'controllerId':NEW_OWNER,
                    'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'}}]
        guard=SimpleNamespace(_fresh_reply=lambda *args:values.pop(0))
        self.assertEqual((NEW_OWNER,0),bundle.CurrentGuard._fresh_owner(guard,{},'0'*64))
