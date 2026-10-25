"""Authentic full-helper RED/GREEN for explicitly selected historical VM mutations."""
import hashlib
import json
import re
from contextlib import ExitStack,contextmanager
from pathlib import Path
from types import ModuleType,SimpleNamespace
import tempfile
import unittest
from unittest import mock
from agent_tools import windows_msi_stale_lock_recovery as stale
from agent_tools import windows_msi_stale_lock_reconcile as reconcile
from agent_tools import windows_msi_owner_relaunch as relaunch
from agent_tools import windows_update_fixture_stage_recovery as stage
from agent_tools.tests.test_windows_credential_explicit_target import mcp_functions

FIXTURES=Path(__file__).parent/'fixtures/windows_original_vm_selector'
D=('windows-cp117','/owned/original/qga.sock',589342,520739,'S-1-5-21-1-2-3-1002')
SELECTOR={'host':'archlinux','vmIdentity':'589342:520739'}
CASES=(('windows-msi-stale-lock-recover',stale,'recover'),
       ('windows-msi-stale-lock-reconcile',reconcile,'reconcile'),
       ('windows-msi-owner-relaunch-launch',relaunch,'launch'),
       ('windows-fixture-stage-recover-7f27',stage,'recover'))


def before(module):
    leaf=module.__name__.rsplit('.',1)[1]+'.before.source';raw=(FIXTURES/leaf).read_bytes()
    provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
    assert hashlib.sha256(raw).hexdigest()==provenance['files'][leaf]['sha256']
    value=ModuleType('agent_tools._selector_before_'+leaf);value.__package__='agent_tools';value.__file__=module.__file__
    exec(compile(raw,module.__file__,'exec'),value.__dict__);return value


def original(module):
    base={'environment':D[0],'socketPath':D[1],'pid':D[2],'startTicks':D[3],'expectedSid':D[4]}
    if module is stage or 'stage_recovery' in module.__name__:
        request={'host':'archlinux','correlationId':stage._CORRELATION,'sourceSha':'a'*40,
                 'fixtureReceiptArtifactId':'sha256-'+'1'*64,'baseMsiArtifactId':'sha256-'+'2'*64,'targetMsiArtifactId':'sha256-'+'3'*64}
        return {**base,'request':request,'leaseId':'123e4567-e89b-42d3-a456-426614174000'}
    return {**base,'request':{'host':'archlinux','correlationId':stale._CORRELATION,'sourceSha':stale._SOURCE,
                             **stale._ARTIFACTS,'expectedCurrentVersion':'2.1.17'}}


@contextmanager
def controlled(module,root):
    """Real helper/journal code; only original metadata and actual native effects controlled."""
    markers=[];record=original(module);descriptor=[D]
    with ExitStack() as stack:
        def patch(obj,name,**kw):return stack.enter_context(mock.patch.object(obj,name,**kw))
        patch(stale.base,'_private_intent',return_value=record)
        patch(stale.base,'_descriptor',side_effect=lambda *_:(object(),object(),descriptor[0]))
        # Before-module imports resolve the current dependency; both retain the same fixed native-boundary ABI.
        if 'stale_lock_recovery' in module.__name__:
            patch(module,'_admit',side_effect=lambda *_:(object(),descriptor[0],'a'*64))
            def effect(*args):
                if args[-1]=='remove':markers.append(('guest-lock-remove',args[1]));return 'removed'
                return 'stale-proven'
            patch(module,'_run',side_effect=effect)
        elif 'stale_lock_reconcile' in module.__name__:
            patch(module,'_admit',side_effect=lambda *_:(object(),descriptor[0],'a'*64))
            patch(module,'_safe_proof',return_value=True)
            patch(module,'close',return_value={'state':'recovered','replayAllowed':False,'nativeActionAllowed':False})
            patch(module.stale,'_run',side_effect=lambda *a:markers.append(('guest-lock-reconcile-remove',a[1])) or 'removed')
        elif 'owner_relaunch' in module.__name__:
            patch(module,'_admit',side_effect=lambda *_:(object(),descriptor[0],'a'*64,'b'*64))
            patch(module.stale_reconcile,'status',return_value={'state':'terminal-proven','replayAllowed':False,'nativeActionAllowed':False})
            patch(module.liveness,'observe',return_value={'state':'absent'})
            patch(module,'_run',side_effect=lambda *a:(markers.append(('guest-task-launch',a[1])) if a[-1]=='launch' else None) or {'version':1,'state':'launched','cliSha256':'a'*64,'ownerPid':7,'sessionId':1,'runtimeRunning':False})
        else:
            patch(module.stage,'_read_intent',return_value=record)
            patch(module,'_bound',side_effect=lambda *_:(record,{},object(),object(),descriptor[0]))
            patch(module,'_evidence',return_value=('a'*64,'b'*64))
            exact={'state':'unknown','correlationId':module._CORRELATION,'binding':'exact','phase':'guest-stage-absent','replayAllowed':False,'nativeActionAllowed':False}
            patch(module.stage,'diagnose',return_value=exact)
            patch(module,'_remote_cleanup',side_effect=lambda *a:markers.append(('host-original-stage-cleanup',a[-1])) or True)
            patch(module,'_idle',return_value=True);patch(module,'_campaign_closed',return_value=True);patch(module,'_remove_bundle',return_value=True)
        yield markers,record,descriptor


class OriginalVmSelectorTests(unittest.TestCase):
    def test_whole_before_each_default_effect_red_current_missing_selector_zero_effects(self):
        for action,current,method in CASES:
            for module,is_before in ((before(current),True),(current,False)):
                with self.subTest(action=action,before=is_before),tempfile.TemporaryDirectory() as raw:
                    with controlled(module,Path(raw)) as (markers,_,__):
                        if is_before:getattr(module,method)(raw,{'host':'archlinux'})
                        else:
                            with self.assertRaisesRegex(ValueError,'Explicit original VM'):getattr(module,method)(raw,{'host':'archlinux'})
                        self.assertEqual(1 if is_before else 0,len(markers))
                        if markers:self.assertEqual(D,markers[0][1])

    def test_all_matching_selectors_continue_only_exact_native_binding(self):
        for action,module,method in CASES:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as raw:
                with controlled(module,Path(raw)) as (markers,_,__):
                    result=getattr(module,method)(raw,SELECTOR)
                    self.assertEqual(1,len(markers));self.assertEqual(D,markers[0][1]);self.assertNotEqual('unknown',result['state'])
                    getattr(module,method)(raw,SELECTOR)
                    self.assertEqual(1,len(markers))

    def test_wrong_or_noncanonical_selector_precedes_recovery_and_all_effects(self):
        bad=('589343:520739','589342:520740','0589342:520739','589342:0520739','0:1','1:0','2147483648:1','1:9223372036854775808','1:2:3',True)
        for action,module,method in CASES:
            for identity in bad:
                with self.subTest(action=action,identity=identity),tempfile.TemporaryDirectory() as raw:
                    with controlled(module,Path(raw)) as (markers,_,__):
                        boundary='_bound' if module is stage else '_admit'
                        with mock.patch.object(module,boundary,side_effect=AssertionError('recovery entered')):
                            with self.assertRaises(ValueError):getattr(module,method)(raw,{'host':'archlinux','vmIdentity':identity})
                        self.assertEqual([],markers)

    def test_same_actor_selector_requires_original_full_socket_environment_sid_binding(self):
        for action,module,method in CASES:
            for key,value in [('socketPath','/foreign/qga.sock'),('environment','foreign-vm'),('expectedSid','S-1-5-21-1-2-3-9999')]:
                with self.subTest(action=action,field=key),tempfile.TemporaryDirectory() as raw:
                    with controlled(module,Path(raw)) as (markers,record,_):
                        record[key]=value
                        with self.assertRaises(ValueError):getattr(module,method)(raw,SELECTOR)
                        self.assertEqual([],markers)

    def test_configuration_swap_after_intent_preserves_unknown_and_never_mutates_new_target(self):
        for action,module,method in CASES:
            if module is stage:continue
            with self.subTest(action=action),tempfile.TemporaryDirectory() as raw:
                with controlled(module,Path(raw)) as (markers,_,descriptor):
                    leaf='_write' if module is reconcile else '_write_intent';write=getattr(module,leaf)
                    def swapped(*args):
                        write(*args);descriptor[0]=(D[0],'/foreign/qga.sock',D[2],D[3],D[4])
                    with mock.patch.object(module,leaf,side_effect=swapped):
                        self.assertEqual('unknown',getattr(module,method)(raw,SELECTOR)['state'])
                    self.assertEqual([],markers)

    def test_public_complete_before_defaults_current_zero_transport_or_effect(self):
        for action,current,method in CASES:
            for is_before in (True,False):
                with self.subTest(action=action,before=is_before),tempfile.TemporaryDirectory() as raw:
                    module=before(current) if is_before else current;root=Path(raw)
                    dispatch=mock.Mock(side_effect=AssertionError('invalid target reached transport'))
                    path=FIXTURES/'mcp_server.before.source' if is_before else Path(__file__).parents[1]/'mcp_server.py'
                    ns=mcp_functions(path,root,{current.__name__.split('.')[-1]:module,
                        'readiness_vm_dispatch':SimpleNamespace(admitted_dispatch=dispatch)})
                    ns['re']=re
                    with controlled(module,root) as (markers,_,__):
                        inputs={'host':'archlinux'}
                        if is_before:ns['_vm_workflow_dispatch'](action,inputs)
                        else:
                            self.assertEqual('blocked',ns['vm_workflow'](action,inputs)['state'])
                            self.assertEqual('blocked',ns['vm_workflow'](action,{**inputs,'vmIdentity':'999:999'})['state'])
                        self.assertEqual(1 if is_before else 0,len(markers));dispatch.assert_not_called()

    def test_public_matching_target_continues_only_its_effect_boundary(self):
        source=Path(__file__).parents[1]/'mcp_server.py'
        for action,module,_ in CASES:
            with self.subTest(action=action),tempfile.TemporaryDirectory() as raw:
                ns=mcp_functions(source,Path(raw),{module.__name__.split('.')[-1]:module});ns['re']=__import__('re')
                with controlled(module,Path(raw)) as (markers,_,__):
                    result=ns['_vm_workflow_dispatch'](action,SELECTOR)
                    self.assertTrue(result['ok']);self.assertEqual(1,len(markers));self.assertEqual(D,markers[0][1])

    def test_all_retained_whole_before_artifacts_have_exact_custody(self):
        provenance=json.loads((FIXTURES/'provenance.json').read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        for leaf,pin in provenance['files'].items():
            self.assertEqual(pin['sha256'],hashlib.sha256((FIXTURES/leaf).read_bytes()).hexdigest(),leaf)
        policy=json.loads((FIXTURES/'policy.before.source').read_bytes())
        old=[group['classification']for group in policy['groups']if group['surface']=='vm_workflow'and'windows-msi-stale-lock-reconcile'in group['actions']]
        self.assertEqual(['remote_observation'],old)
