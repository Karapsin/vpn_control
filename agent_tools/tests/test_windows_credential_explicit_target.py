"""Whole-source causals for explicit VM selection before private credential work."""
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
from types import ModuleType, SimpleNamespace
import tempfile
import unittest
from unittest import mock

from agent_tools import windows_credential_probe_ssh as probe
from agent_tools import windows_credential_recovery_ssh as recovery

FIXTURES = Path(__file__).parent / 'fixtures/windows_credential_explicit_target'
CORRELATION = '321e4567-e89b-42d3-a456-426614174000'


def before(name):
    provenance = json.loads((FIXTURES/'provenance.json').read_bytes())
    leaf = name+'.before.source'; raw = (FIXTURES/leaf).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == provenance['files'][leaf]['sha256']
    module = ModuleType('agent_tools._credential_target_before_'+name)
    module.__package__ = 'agent_tools'; module.__file__ = str(Path(probe.__file__).with_name(name+'.py'))
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


def mcp_functions(path, root, modules):
    tree = ast.parse(path.read_bytes())
    names = {'_vm_invalid_before_recovery','_vm_workflow_dispatch','_vm_workflow_impl','vm_workflow',
             '_credential_workflow_refusal','_credential_probe_refusal'}
    nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    for node in nodes: node.decorator_list=[]
    ns = {'Any':object, 'REPO_ROOT':root,'_agent_module':lambda name:modules[name],
          '_error':lambda tool,reason:{'state':'blocked','reason':reason},
          '_native_response':lambda tool,action,value,inputs:value,
          'native_workflow_policy':SimpleNamespace(refusal=lambda action:None),
          'windows_vm_setup_policy':SimpleNamespace(refusal=lambda action,inputs:None)}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
    return ns


def config():
    admission=SimpleNamespace(task_name='Fixture_BaseInstall',task_path='\\',expected_task_state='Disabled',
        expected_last_result=1601,expected_task_execute=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        expected_task_principal='fixtureuser',expected_task_arguments_sha256='a'*64)
    descriptor=SimpleNamespace(environment='selected-vm',qga_socket_path=PurePosixPath('/owned/selected/qga.sock'),
        qemu_pid=123,qemu_start_ticks=456,account_name='fixtureuser',expected_sid='S-1-5-21-11-22-33-1002',
        credential_path=Path('/controlled/private-input'),recovery_admission=admission)
    target=SimpleNamespace(windows_credential_probe=descriptor,fixture_transfer_root=PurePosixPath('/owned/private'))
    return SimpleNamespace(hosts={'arch':target})


class ExplicitCredentialTargetTests(unittest.TestCase):
    def exercise(self,module,root,environment_marker,*,selector=False):
        options={'environment':'selected-vm'} if selector else {}
        module.start(root,'arch',CORRELATION,**options)

    def test_whole_before_direct_missing_selector_reaches_default_vm_current_refuses(self):
        for name,current in [('windows_credential_probe_ssh',probe),('windows_credential_recovery_ssh',recovery)]:
            old=before(name)
            for module,is_before in [(old,True),(current,False)]:
                with self.subTest(name=name,before=is_before), tempfile.TemporaryDirectory() as raw:
                    root=Path(raw);(root/'.runtime').mkdir(mode=0o700);cfg=config();markers=[]
                    transport=module if name.endswith('probe_ssh') else module.transport
                    with mock.patch.object(transport,'_config',return_value=cfg), \
                         mock.patch.object(transport,'_private_secret',return_value=b'controlled-A!9') as secret, \
                         mock.patch.object(transport,'_run_ssh',side_effect=lambda *a:markers.append('selected-vm') or b'{"state":"submitted","pid":7}'):
                        if is_before:self.exercise(module,root,markers)
                        else:
                            with self.assertRaisesRegex(ValueError,'Explicit Windows environment'):
                                self.exercise(module,root,markers)
                    self.assertEqual(['selected-vm'] if is_before else [],markers)
                    if not is_before:
                        secret.assert_not_called();self.assertFalse((root/'.runtime/native-credentials').exists())

    def test_missing_and_wrong_environment_precede_all_private_boundaries(self):
        for module in (probe,recovery):
            for environment in (None,'wrong-vm'):
                with self.subTest(module=module.__name__,environment=environment), tempfile.TemporaryDirectory() as raw:
                    cfg=config()
                    with mock.patch.object(probe,'_config',return_value=cfg), \
                         mock.patch.object(probe,'_private_secret') as private, \
                         mock.patch.object(probe,'_run_ssh') as remote, \
                         mock.patch.object(recovery,'_reserve') as reserve, \
                         mock.patch.object(recovery.native_credentials.NativeCredentialStore,'create') as create, \
                         mock.patch.object(recovery.native_credentials.NativeCredentialStore,'read') as read:
                        with self.assertRaises(ValueError):module.start(raw,'arch',CORRELATION,environment=environment)
                        for boundary in (private,remote,reserve,create,read):boundary.assert_not_called()
        with mock.patch.object(probe,'_config') as load:
            with self.assertRaises(ValueError):probe.start_with_private_secret('.', 'arch', CORRELATION,b'controlled-A!9')
            load.assert_not_called()

    def test_matching_environment_preserves_selected_vm_only(self):
        for module in (probe,recovery):
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as raw:
                root=Path(raw);(root/'.runtime').mkdir(mode=0o700)
                with mock.patch.object(probe,'_config',return_value=config()), \
                     mock.patch.object(probe,'_private_secret',return_value=b'controlled-A!9'), \
                     mock.patch.object(probe,'_run_ssh',return_value=b'{"state":"submitted","pid":7}') as remote:
                    self.assertEqual('submitted',module.start(root,'arch',CORRELATION,environment='selected-vm')['state'])
                payload=json.loads(remote.call_args.args[3][4:]);self.assertEqual('/owned/selected/qga.sock',payload['socketPath'])

    def test_configuration_swap_during_private_read_never_reselects_or_dispatches(self):
        cfg=config()
        def swapped(_):
            cfg.hosts['arch'].windows_credential_probe.qga_socket_path=PurePosixPath('/foreign/qga.sock')
            return b'controlled-A!9'
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(probe,'_config',return_value=cfg), \
             mock.patch.object(probe,'_private_secret',side_effect=swapped),mock.patch.object(probe,'_run_ssh') as remote:
            with self.assertRaisesRegex(ValueError,'binding changed'):
                probe.start(raw,'arch',CORRELATION,environment='selected-vm')
            remote.assert_not_called()
        cfg=config()
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(probe,'_config',return_value=cfg), \
             mock.patch.object(recovery,'_reserve',side_effect=lambda *a:setattr(cfg.hosts['arch'].windows_credential_probe,'qemu_pid',999)), \
             mock.patch.object(recovery.native_credentials.NativeCredentialStore,'create') as create,mock.patch.object(probe,'_run_ssh') as remote:
            with self.assertRaisesRegex(ValueError,'binding changed'):
                recovery.start(raw,'arch',CORRELATION,environment='selected-vm')
            create.assert_not_called();remote.assert_not_called()

    def test_original_recovery_verification_passes_retained_environment_and_full_binding(self):
        record={'correlationId':CORRELATION,'handle':'nc-'+'a'*32,'environment':'original-vm','socketPath':'/original/qga.sock',
                'pid':1,'startTicks':2,'accountName':'fixtureuser','expectedSid':'S-1-5-21-11-22-33-1002','previousCredentialPath':'/original/secret'}
        with tempfile.TemporaryDirectory() as raw,mock.patch.object(recovery.native_credentials.NativeCredentialStore,'read',return_value=b'controlled-A!9'), \
             mock.patch.object(probe,'start_with_private_secret',return_value={'state':'submitted'}) as start:
            recovery._verify_and_publish(raw,'arch',record,15)
        self.assertEqual('original-vm',start.call_args.kwargs['environment'])
        self.assertEqual(('original-vm','/original/qga.sock',1,2,'fixtureuser','S-1-5-21-11-22-33-1002',Path('/original/secret')),start.call_args.kwargs['expected_binding'])

    def test_whole_mcp_before_default_target_effect_current_refuses_before_admission(self):
        for action,name,current in [('windows-credential-probe-start','windows_credential_probe_ssh',probe),
                                    ('windows-credential-recover-start','windows_credential_recovery_ssh',recovery)]:
            for is_before in (True,False):
                with self.subTest(action=action,before=is_before),tempfile.TemporaryDirectory() as raw:
                    root=Path(raw);(root/'.runtime').mkdir(mode=0o700);module=before(name) if is_before else current;markers=[]
                    transport=module if name.endswith('probe_ssh') else module.transport
                    dispatch=mock.Mock(side_effect=AssertionError('no readiness transport for invalid selector'))
                    path=FIXTURES/'mcp_server.before.source' if is_before else Path(__file__).parents[1]/'mcp_server.py'
                    ns=mcp_functions(path,root,{name:module,'windows_credential_probe_ssh':module if name.endswith('probe_ssh') else probe,
                                               'readiness_vm_dispatch':SimpleNamespace(admitted_dispatch=dispatch)})
                    with mock.patch.object(transport,'_config',return_value=config()), \
                         mock.patch.object(transport,'_private_secret',return_value=b'controlled-A!9'), \
                         mock.patch.object(transport,'_run_ssh',side_effect=lambda *a:markers.append('selected-vm') or b'{"state":"submitted","pid":7}'):
                        inputs={'host':'arch','correlationId':CORRELATION}
                        if is_before:ns['_vm_workflow_dispatch'](action,inputs)
                        else:
                            self.assertEqual('blocked',ns['vm_workflow'](action,inputs)['state'])
                            self.assertEqual('blocked',ns['vm_workflow'](action,{**inputs,'environment':'wrong-vm'})['state'])
                    self.assertEqual(['selected-vm'] if is_before else [],markers);dispatch.assert_not_called()

    def test_authenticated_old_transport_test_seam_fails_current_intercepts_real_carrier(self):
        from agent_tools.tests import test_windows_credential_probe_ssh as current
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        for leaf in ('probe_transport_test.before.source','probe-test-failure.json'):
            self.assertEqual(provenance['files'][leaf]['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest())
        old=ModuleType('_old_probe_transport_test');old.__file__=str(FIXTURES/'probe_transport_test.before.source')
        exec(compile((FIXTURES/'probe_transport_test.before.source').read_bytes(),old.__file__,'exec'),old.__dict__)
        name='test_raw_multiline_helpers_are_rejected_but_both_real_paths_build_encoded_argv'
        for module,is_before in ((old,True),(current,False)):
            case=module.WindowsCredentialProbeSshTest(name);result=unittest.TestResult()
            with mock.patch.object(probe.ssh_transport,'run_ssh',side_effect=OSError('controlled carrier not intercepted')) as carrier:
                case.run(result)
            self.assertEqual(not is_before,result.wasSuccessful())
            self.assertEqual(1 if is_before else 0,carrier.call_count)

    def test_public_matching_selector_forwarded_status_schema_stays_original_only(self):
        source=Path(__file__).parents[1]/'mcp_server.py'
        for family,module in (('probe',probe),('recover',recovery)):
            with self.subTest(family=family),tempfile.TemporaryDirectory() as raw:
                action='windows-credential-'+family+'-start'
                ns=mcp_functions(source,Path(raw),{'windows_credential_'+('probe' if family=='probe' else 'recovery')+'_ssh':module})
                inputs={'host':'arch','correlationId':CORRELATION,'environment':'selected-vm'}
                with mock.patch.object(module,'start',return_value={'state':'submitted'}) as start:
                    self.assertTrue(ns['_vm_workflow_dispatch'](action,inputs)['ok'])
                self.assertEqual({'environment':'selected-vm','timeout_seconds':15},start.call_args.kwargs)
                with mock.patch.object(module,'status',return_value={'state':'submitted'}) as status:
                    self.assertTrue(ns['_vm_workflow_dispatch'](action.replace('-start','-status'),{'host':'arch','correlationId':CORRELATION})['ok'])
                    self.assertEqual({'timeout_seconds':15},status.call_args.kwargs)
                    self.assertEqual('blocked',ns['_vm_workflow_dispatch'](action.replace('-start','-status'),inputs)['state'])

    def test_original_expected_binding_refuses_same_environment_foreign_vm(self):
        cfg=config();expected=probe._descriptor(cfg.hosts['arch'])
        cfg.hosts['arch'].windows_credential_probe.qga_socket_path=PurePosixPath('/foreign/qga.sock')
        with mock.patch.object(probe,'_config',return_value=cfg),mock.patch.object(probe,'_run_ssh') as remote:
            with self.assertRaisesRegex(ValueError,'binding does not match'):
                probe.start_with_private_secret('.', 'arch', CORRELATION,b'controlled-A!9',environment='selected-vm',expected_binding=expected)
            remote.assert_not_called()

    def test_all_retained_before_artifacts_are_authenticated(self):
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        for leaf,pin in provenance['files'].items():
            self.assertEqual(pin['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest(),leaf)
