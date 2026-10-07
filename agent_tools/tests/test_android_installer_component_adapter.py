"""Actual lifecycle/TLS hooks and durable private command capture."""
import base64,hashlib,json,pathlib,tempfile,types,unittest
from unittest import mock
from scripts import android_installer_lifecycle as lifecycle
from scripts import android_no_update_tls_preflight as tls
from agent_tools import android_installer_component_adapter as adapter
from agent_tools.tests.fixtures.android_component_hermetic import scope,OWNER
from agent_tools import android_installer_component_bundle as bundle

class AdapterTests(unittest.TestCase):
    def test_fresh_import_does_not_probe_checkout_private_history(self):
        """Real fresh import; forbidden paths are blocked before any OS access."""
        import subprocess,sys,textwrap
        root=pathlib.Path(__file__).resolve().parents[2]
        script=textwrap.dedent("""
            import os,sys,builtins,json,io
            root=sys.argv[1]
            forbidden=[os.path.join(root,name) for name in ('.runtime','.rag_index')]
            attempted=[]
            def wrap(function):
                def guarded(path,*args,**kwargs):
                    if isinstance(path,(str,bytes,os.PathLike)):
                        name=os.path.abspath(os.fsdecode(path))
                        if any(name==prefix or name.startswith(prefix+os.sep) for prefix in forbidden):
                            attempted.append('checkout-private-access')
                            raise PermissionError('blocked before OS access')
                    return function(path,*args,**kwargs)
                return guarded
            os.stat=wrap(os.stat);os.lstat=wrap(os.lstat);os.open=wrap(os.open)
            builtins.open=wrap(builtins.open);io.open=wrap(io.open)
            sys.path.insert(0,root)
            import agent_tools.tests.test_android_installer_component_adapter
            print(json.dumps({'attempts':len(attempted)}))
        """)
        result=subprocess.run([sys.executable,'-I','-B','-c',script,str(root)],capture_output=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual({'attempts':0},json.loads(result.stdout))

    def test_tls_hook_globals_and_defaults_rejected_before_install(self):
        function=tls.public_cli_environment
        for kind in ('globals','defaults','kwdefaults'):
            clone=types.FunctionType(function.__code__,dict(function.__globals__) if kind=='globals' else function.__globals__,
                                     argdefs=('foreign',) if kind=='defaults' else function.__defaults__)
            if kind=='kwdefaults':clone.__kwdefaults__={'unexpected':None}
            with self.subTest(kind=kind),mock.patch.object(tls,'public_cli_environment',clone):
                with self.assertRaisesRegex(ValueError,'hook_changed'):
                    adapter._module(tls,adapter.TLS_SHA,('public_cli_environment',))

    def test_tls_keyword_default_types_remain_exact(self):
        function=tls.run_fixture_lifecycle
        with mock.patch.object(function,'__kwdefaults__',{**function.__kwdefaults__,'target_install':0}):
            with self.assertRaisesRegex(ValueError,'hook_changed'):
                adapter._module(tls,adapter.TLS_SHA,('run_fixture_lifecycle',))

    def test_tls_default_drift_after_install_rejected_before_public_command(self):
        self.install()
        function=tls.public_cli_environment
        with mock.patch.object(function,'__defaults__',('foreign',)):
            with self.assertRaisesRegex(ValueError,'hook_changed'):
                lifecycle.invoke(self.args.cli,self.args.serial,'updates','check')
        self.assertEqual([],self.calls)

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=pathlib.Path(self.tmp.name).resolve();self.path.chmod(0o700)
        self.env,self.calls,self.saved,self.guards,_,_=scope()
        self.env['COMMAND_SOURCE_SHA']=hashlib.sha256(pathlib.Path(adapter.transport.__file__).read_bytes()).hexdigest()
        self.intent={'correlationId':'d475b822-e8b5-4a8d-a27e-ecf3a07a2d88','expectedOwner':OWNER,'expectedRevision':0,'pair':{'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','targetArtifactId':'sha256-'+'a'*64}}
        self.intent['expectedApi']=29;self.env['LAUNCH']['device']='api29'
        self.args=types.SimpleNamespace(cli=pathlib.Path(self.env['GETTER']['cli']),serial=self.env['EXTERNAL']['serial'],api='29',output=self.path,intent_file=self.path/'intent.json',cli_environment=None)
        self.load=mock.patch.object(lifecycle.target_admission,'load_intent',return_value=self.intent);self.load.start()
        self.restore=None
    def tearDown(self):
        if self.restore:self.restore()
        self.load.stop();self.tmp.cleanup()
    def install(self,guard=lambda:None):
        self.backend_functions()
        self.restore=adapter.install(lifecycle,tls,self.env,self.args,guard)
    def backend_functions(self):
        # Compile the fixed functions in production module import context; child
        # fixtures replace only the OS invocation after closure is checked.
        import ast
        raw=adapter.transport.REMOTE+'\n'+adapter.transport._bounded_source()
        imports='import hashlib,json,os,pathlib,re,stat,errno,ctypes,fcntl,signal,subprocess,time,select,shutil\nfrom pathlib import Path\n'
        code=compile(imports+ast.unparse(ast.parse(raw)),'<production-module-test>','exec',dont_inherit=True)
        code=getattr(self,'actual_factory_code',code)
        names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded'}
        for value in code.co_consts:
            if isinstance(value,types.CodeType) and value.co_name in names:
                previous=self.env[value.co_name]
                defaults=previous.__defaults__ if value.co_name!='command_binary' else None
                self.env[value.co_name]=types.FunctionType(value,self.env,argdefs=defaults)

    def complete_template_code(self, device, mutate=False):
        """Whole compiler context; TempFS public sources, no native admission reads.

        Census/launch/getter DTOs are empty because top-level code is compiled,
        never executed. Actual generated functions execute in the bounded-child
        protocol backend below, as they did after the old private prerequisite.
        """
        import ast
        from agent_tools import android_avd_launch_recovery as census
        from agent_tools import android_api35_coldboot_product_observation as api35
        reader=adapter.transport.readonly
        getter=api35 if device=='api35' else reader.getter_source
        modules=(census,getter,getter.coldboot,reader.proven,adapter.transport)
        stage=self.path/'template-sources';stage.mkdir(mode=0o700)
        pins={}
        for module in modules:
            path=stage/pathlib.Path(module.__file__).name
            if path in pins:continue
            bundle._write(path,bundle._read(module.__file__)[0])
            pins[path]=bundle._read(path,True)
        if mutate:next(iter(pins)).write_bytes(b'foreign-source')
        templates=(census._CENSUS.replace('__CFG__',repr({})),
                   getter.coldboot._BOOT.replace('__LAUNCH__',repr({})),
                   getter._GETTER.replace('__GETTER__',repr({})),
                   reader.proven._REMOTE.replace('__EXTERNAL__',repr({})),
                   adapter.transport.REMOTE,adapter.transport._bounded_source())
        source=adapter.production_imports(device)+'\n'.join(templates)
        for path,pin in pins.items():
            if bundle._read(path,True)!=pin:raise ValueError('template_source_changed')
        return compile(ast.unparse(ast.parse(source)),'<whole-public-template-context>','exec',dont_inherit=True)

    def test_actual_complete_template_production_namespace_adapter_and_lifecycle(self):
        self.actual_factory_code=self.complete_template_code('api29')
        self.full_action('installed')
        self.assertTrue((self.path/'component-transport-admission.json').is_file())

    def test_actual_api35_complete_template_context_and_lifecycle(self):
        self.actual_factory_code=self.complete_template_code('api35')
        self.env['EXTERNAL']['serial']='emulator-5682';self.env['LAUNCH']['device']='api35';self.args.serial='emulator-5682'
        self.args.api='35';self.intent['expectedApi']=35
        self.full_action('installed')

    def test_actual_staged_template_mutation_refuses_before_lifecycle_child(self):
        with self.assertRaisesRegex(ValueError,'template_source_changed'):
            self.complete_template_code('api35',mutate=True)
        self.assertEqual([],self.calls)

    def test_finite_context_selector_rejects_crossed_device_before_code_auth(self):
        self.backend_functions();self.env['LAUNCH']['device']='api35'
        self.env['component_command']=lambda *a:None
        with self.assertRaisesRegex(ValueError,'installer_adapter_crossed_context'):
            adapter.install(lifecycle,tls,self.env,self.args,lambda:None)
        self.assertEqual([],self.calls);self.assertFalse((self.path/'component-transport-admission.json').exists())
        for value in (None,True,'android-api35','api34','api35\nimport private'):
            with self.assertRaises(ValueError):adapter.production_imports(value)
        self.assertEqual(adapter.production_imports('api29')+'import base64\n',adapter.production_imports('api35'))

    def test_api35_claim_cannot_adopt_api29_compiler_functions(self):
        self.backend_functions()
        self.env['LAUNCH']['device']='api35';self.env['EXTERNAL']['serial']='emulator-5682'
        self.args.api='35';self.args.serial='emulator-5682';self.intent['expectedApi']=35
        with self.assertRaisesRegex(ValueError,'installer_adapter_backend_changed'):
            adapter.install(lifecycle,tls,self.env,self.args,lambda:None)
        self.assertFalse((self.path/'component-transport-admission.json').exists())

    def test_canonical_proof_rejects_changed_function_and_foreign_globals(self):
        self.backend_functions();original=self.env['command_request']
        self.env['command_request']=lambda *a:(30,False,False,False)
        with self.assertRaisesRegex(ValueError,'installer_adapter_backend_changed'):
            adapter.install(lifecycle,tls,self.env,self.args,lambda:None)
        self.env['command_request']=types.FunctionType(original.__code__,dict(self.env),argdefs=original.__defaults__)
        with self.assertRaisesRegex(ValueError,'installer_adapter_backend_changed'):
            adapter.install(lifecycle,tls,self.env,self.args,lambda:None)
        self.assertEqual([],self.calls);self.assertFalse((self.path/'component-transport-admission.json').exists())
    def child(self,code=0,body=None,raw=None):
        def invoke(*args,**kwargs):
            self.calls.append(args[2])
            output=json.dumps(body or {'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':0,'data':{}}) if raw is None else raw
            exit_code=code
            if args[2][-1:] == ['status'] and args[2][-2:]!=['updates','status']:
                output=json.dumps({'ok':True,'final':True,'code':'OK','controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False}});exit_code=0
            self.env['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':exit_code,'failure':None,'stdoutBase64':base64.b64encode(output.encode()).decode(),'stderrBase64':'','stdoutBytes':len(output.encode()),'stderrBytes':0})
            return dict(returncode=exit_code,stdoutRaw=output,stderrRaw='')
        self.env['command_binary']=invoke
    def test_same_code_tls_foreign_globals_refused_before_admission(self):
        function=tls.public_cli_environment
        clone=types.FunctionType(function.__code__,dict(function.__globals__),argdefs=function.__defaults__)
        with mock.patch.object(tls,'public_cli_environment',clone):
            with self.assertRaisesRegex(ValueError,'hook_changed'):self.install()
        self.assertEqual([],self.calls)
        self.assertFalse((self.path/'component-transport-admission.json').exists())

    def test_same_code_tls_altered_defaults_refused_before_admission(self):
        function=tls.public_cli_environment
        clone=types.FunctionType(function.__code__,function.__globals__,argdefs=({'PATH':'foreign'},))
        with mock.patch.object(tls,'public_cli_environment',clone):
            with self.assertRaisesRegex(ValueError,'hook_changed'):self.install()
        self.assertEqual([],self.calls)

    def test_same_code_tls_altered_keyword_defaults_refused_before_admission(self):
        function=tls.run_fixture_lifecycle
        clone=types.FunctionType(function.__code__,function.__globals__,argdefs=function.__defaults__)
        clone.__kwdefaults__={**function.__kwdefaults__,'target_install':True}
        with mock.patch.object(tls,'run_fixture_lifecycle',clone):
            with self.assertRaisesRegex(ValueError,'hook_changed'):self.install()
        self.assertEqual([],self.calls)

    def test_counterfeit_phase_protocol_cannot_select_command_owner(self):
        self.backend_functions()
        counterfeit=type('CurrentGuard',(),{'__call__':lambda self:None,
            '_command_binding':lambda self:{'expectedOwner':OWNER,'expectedRevision':0}})()
        with self.assertRaisesRegex(ValueError,'phase_source_changed'):
            adapter.install(lifecycle,tls,self.env,self.args,counterfeit)
        self.assertEqual([],self.calls)
        self.assertFalse((self.path/'component-transport-admission.json').exists())

    def test_actual_semantic_action_substitution_refused_before_child(self):
        self.install()
        with mock.patch.object(lifecycle,'action',lambda *args:None):
            with self.assertRaises(lifecycle.InvocationFailure) as caught:
                lifecycle.invoke(self.args.cli,self.args.serial,'updates','status')
        self.assertEqual('installer_adapter_semantic_guard_changed',str(caught.exception.__cause__))
        self.assertEqual([],self.calls)

    def test_complete_installer_check_download_noninteractive_async_actual_hook(self):
        self.install();self.child()
        for words in (('status',),('operations','list'),('updates','status'),('updates','check'),('updates','download')):
            record=lifecycle.invoke(self.args.cli,self.args.serial,*words);self.assertEqual('OK',record['response']['code'])
        self.child(1,{'ok':False,'code':'INTERACTION_REQUIRED','final':True,'controllerId':OWNER,'configurationRevision':0})
        record=lifecycle.invoke(self.args.cli,self.args.serial,'updates','install');lifecycle.final(record,'INTERACTION_REQUIRED')
        self.child(0,{'ok':True,'code':'ACCEPTED','final':False,'operationId':OWNER,'controllerId':OWNER,'configurationRevision':0})
        record=lifecycle.invoke(self.args.cli,self.args.serial,'updates','install',interactive=True,asynchronous=True)
        self.assertFalse(record['response']['final']);self.assertIn('--async',self.calls[-1]);self.assertFalse(record['installedLauncherAccepted'])
        captures=sorted(self.path.glob('component-cli-*.json'));self.assertEqual(11,len(captures))
        for path in captures:self.assertEqual(0o600,path.stat().st_mode&0o777);self.assertIn('record',json.loads(path.read_bytes()))
    def test_actual_tls_no_update_probe_hook_retains_original_server_count_validation(self):
        self.install();self.child(body={'ok':True,'code':'OK','final':True,'controllerId':OWNER,'configurationRevision':0,'data':{'checked':True,'available':False}})
        log=self.path/'server.log';log.write_text('{"served": "manifest"}\n')
        result=tls.public_no_update_probe(self.args.cli,self.args.serial,log,self.path/'probe.out')
        self.assertEqual(1,result['manifestCount']);self.assertEqual(0o600,(self.path/'probe.out').stat().st_mode&0o777)
        log.write_text('{"served": "manifest"}\n'*2)
        with self.assertRaises(FileExistsError):tls.public_no_update_probe(self.args.cli,self.args.serial,log,self.path/'probe2.out')
    def test_invalid_json_exact_private_capture_precedes_finite_invocation_error(self):
        self.install();self.child(raw='raw-private-secret')
        with self.assertRaises(lifecycle.InvocationFailure)as caught:lifecycle.invoke(self.args.cli,self.args.serial,'updates','status')
        self.assertNotIn('raw-private-secret',str(caught.exception));self.assertEqual('raw-private-secret',caught.exception.record['stdout'])
        value=json.loads((self.path/'component-cli-00001.json').read_bytes());self.assertEqual('raw-private-secret',value['record']['stdoutRaw'])
    def test_repeated_installation_refused_before_any_command(self):
        self.install();self.restore();self.restore=None
        with self.assertRaises(FileExistsError):self.install()
        self.assertEqual([],self.calls)
    def test_actual_foreign_owner_guard_and_no_stale_raw_adoption(self):
        count=[0]
        def guard():
            count[0]+=1
            if count[0]>=3:raise ValueError('actual_current_owner_changed')
        self.install(guard);self.child()
        self.env['GETTER_RECORDS']['captures']=[{'stdoutBase64':base64.b64encode(b'old-unrelated-reply').decode()}]
        with self.assertRaisesRegex(ValueError,'actual_current_owner_changed'):lifecycle.invoke(self.args.cli,self.args.serial,'updates','check')
        self.assertEqual([],self.calls)
    def test_actual_source_hook_mutation_refused_before_admission_file(self):
        with mock.patch.object(lifecycle,'invoke',lambda *a:None):
            with self.assertRaisesRegex(ValueError,'installer_adapter_hook_changed'):adapter.install(lifecycle,tls,self.env,self.args,lambda:None)
        self.assertEqual([],list(self.path.glob('component-*')))

    def test_consumed_fence_same_byte_replacement_rejects_before_child(self):
        self.install();self.child()
        path=self.path/'component-transport-admission.json';raw=path.read_bytes();path.rename(self.path/'historical-admission.json');path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'installer_adapter_fence_changed'):lifecycle.invoke(self.args.cli,self.args.serial,'updates','check')
        self.assertEqual([],self.calls)

    def test_same_session_unknown_interactive_install_never_resubmits(self):
        self.install();self.child(raw='actual-malformed-install-response')
        for attempt in range(2):
            with self.assertRaises((lifecycle.InvocationFailure,ValueError)):
                lifecycle.invoke(self.args.cli,self.args.serial,'updates','install',interactive=True,asynchronous=True)
        self.assertEqual(1,sum('--interactive'in argv for argv in self.calls))
        self.assertTrue((self.path/'component-effect-install-interactive.json').is_file())
        unknown=json.loads((self.path/'component-effect-unknown.json').read_bytes())
        self.assertFalse(unknown['effectContinuationAllowed']);self.assertFalse(unknown['replayAllowed'])
        self.child()
        observed=lifecycle.invoke(self.args.cli,self.args.serial,'status')
        self.assertEqual('OK',observed['response']['code'])
        with self.assertRaisesRegex(ValueError,'uncertain_effect_consumed'):
            lifecycle.invoke(self.args.cli,self.args.serial,'updates','download')
        self.assertEqual(0,sum(argv[-2:]==['updates','download'] for argv in self.calls))

    def test_positive_check_consumed_once_even_if_return_was_valid(self):
        self.install();self.child()
        lifecycle.invoke(self.args.cli,self.args.serial,'updates','check')
        with self.assertRaises(FileExistsError):lifecycle.invoke(self.args.cli,self.args.serial,'updates','check')
        self.assertEqual(1,sum(argv[-2:]==['updates','check'] for argv in self.calls))
        self.assertFalse((self.path/'component-effect-unknown.json').exists())
        # A distinct admitted phase may continue after the positive result.
        lifecycle.invoke(self.args.cli,self.args.serial,'updates','download')
        self.assertEqual(1,sum(argv[-2:]==['updates','download'] for argv in self.calls))

    def test_effect_admission_fsync_failure_prevents_every_child(self):
        self.install();self.child();original=lifecycle.write_cli_evidence
        def fail(args,name,value):
            if name=='component-effect-install-interactive.json':raise OSError('fsync_failed')
            return original(args,name,value)
        with mock.patch.object(lifecycle,'write_cli_evidence',side_effect=fail):
            with self.assertRaises(OSError):lifecycle.invoke(self.args.cli,self.args.serial,'updates','install',interactive=True,asynchronous=True)
        self.assertEqual([],self.calls)

    def contradictory_install(self,interactive,flag):
        self.install()
        body={'ok':not interactive,'code':'ACCEPTED' if interactive else 'INTERACTION_REQUIRED',
              'final':not interactive,'controllerId':OWNER,'configurationRevision':0,'operationId':OWNER}
        if flag=='missing':body.pop('ok')
        elif flag=='integer':body['ok']=1 if interactive else 0
        self.child(0 if interactive else 1,body)
        lifecycle.invoke(self.args.cli,self.args.serial,'updates','install',interactive=interactive,asynchronous=interactive)
        with self.assertRaisesRegex(ValueError,'uncertain_effect_consumed'):
            lifecycle.invoke(self.args.cli,self.args.serial,'updates','download')
        self.assertEqual(1,sum(argv[-2:]==['updates','install'] for argv in self.calls))
        self.assertEqual(0,sum(argv[-2:]==['updates','download'] for argv in self.calls))
        self.assertTrue((self.path/'component-effect-unknown.json').is_file())
    def test_contradictory_interactive_ok_false_cannot_continue(self):self.contradictory_install(True,'wrong')
    def test_missing_interactive_ok_cannot_continue(self):self.contradictory_install(True,'missing')
    def test_integer_interactive_ok_cannot_continue(self):self.contradictory_install(True,'integer')
    def test_contradictory_noninteractive_ok_true_cannot_continue(self):self.contradictory_install(False,'wrong')
    def test_missing_noninteractive_ok_cannot_continue(self):self.contradictory_install(False,'missing')
    def test_integer_noninteractive_ok_cannot_continue(self):self.contradictory_install(False,'integer')

    def test_tls_unknown_check_and_later_mutations_never_resubmit(self):
        self.install();self.child(raw='actual-malformed-check-response')
        log=self.path/'server.log';log.write_text('{"served": "manifest"}\n')
        for attempt in range(2):
            with self.assertRaises((lifecycle.InvocationFailure,ValueError)):
                tls.public_no_update_probe(self.args.cli,self.args.serial,log,self.path/('output%d'%attempt))
        with self.assertRaises((lifecycle.InvocationFailure,ValueError)):
            lifecycle.invoke(self.args.cli,self.args.serial,'updates','download')
        self.assertEqual(1,sum(argv[-2:]==['updates','check'] for argv in self.calls))
        self.assertEqual(0,sum(argv[-2:]==['updates','download'] for argv in self.calls))

    def full_action(self,terminal,loss=False):
        self.intent['backupSha256']='b'*64
        self.args.intent=self.intent
        self.args.target_sha256='a'*64;self.args.target_version='2.2.2';self.args.target_code='16840'
        self.args.expected_terminal=terminal;self.args.probe_output=self.path/'checkpoint.json'
        self.args.continue_file=self.path/'continue';self.args.fixture_parent=self.path
        self.install();submitted=[]
        def child(path,pin,argv,environment,limit,timeout):
            words=argv[argv.index('updates'):] if 'updates'in argv else argv[argv.index('operations'):] if 'operations'in argv else ['status']
            submitted.append(words)
            if loss and words==['updates','install'] and '--interactive'in argv:
                raw='actual-lost-install-response'
                self.env['GETTER_RECORDS']['captures'].append({'returncode':None,'failure':'permission_command_timeout','stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw),'stderrBytes':0})
                raise ValueError('permission_command_timeout')
            code=0;response={'ok':True,'code':'OK','final':True,'controllerId':OWNER,'configurationRevision':0,'data':{'runtimeRunning':False}}
            if words==['updates','install']:
                if '--interactive'in argv:response.update(code='ACCEPTED',final=False,operationId=OWNER)
                else:code=1;response.update(ok=False,code='INTERACTION_REQUIRED')
            elif words[:2] in (['operations','status'],['operations','wait']):
                installed=terminal=='installed';code=0 if installed else 130
                response.update(ok=installed,code='OK' if installed else 'CANCELLED',operationId=OWNER,
                    data={'availableVersion':'2.2.2','installReceiptId':'receipt','installSessionId':17,'installPhase':terminal,'installed':installed})
            raw=json.dumps(response)
            self.env['GETTER_RECORDS'].setdefault('captures',[]).append({'returncode':code,'failure':None,'stdoutBase64':base64.b64encode(raw.encode()).decode(),'stderrBase64':'','stdoutBytes':len(raw),'stderrBytes':0})
            return dict(returncode=code,stdoutRaw=raw,stderrRaw='')
        self.env['command_binary']=child
        class Adb:
            def shell_id(self):return 'uid=2000'
            def shell(self,*words):return 'versionName=2.2.2 versionCode=16840' if words[:2]==('dumpsys','package') else ''
        receipt={}
        with mock.patch.object(lifecycle,'wait_for_continue_file'),mock.patch.object(tls,'require_installed_base_hash',return_value='a'*64):
            if loss:
                with self.assertRaises(lifecycle.InvocationFailure):lifecycle.action(self.args,Adb(),receipt)
                self.assertEqual(2,submitted.count(['updates','install']))
                self.assertEqual('invocation',json.loads((self.path/'cli-failure.json').read_bytes())['guard'])
                full=[json.loads(p.read_bytes()) for p in self.path.glob('component-cli-*.json')]
                self.assertTrue(any(item['record']['captures'] and item['record']['captures'][-1]['failure']=='permission_command_timeout' for item in full))
            else:
                result=lifecycle.action(self.args,Adb(),receipt)
                self.assertEqual('terminal-confirmed',result['acceptance']);self.assertEqual(2,submitted.count(['updates','install']))
                self.assertEqual(1,submitted.count(['operations','status',OWNER]));self.assertEqual(1,submitted.count(['operations','wait',OWNER]))
                self.assertEqual(terminal,result['originalOperation']['stage'])
    def test_full_actual_action_installed_without_replacing_invoke(self):self.full_action('installed')
    def test_full_actual_action_cancelled_without_replacing_invoke(self):self.full_action('cancelled')
    def test_full_actual_action_response_loss_no_repeat_install(self):self.full_action('installed',loss=True)

if __name__=='__main__':unittest.main()
