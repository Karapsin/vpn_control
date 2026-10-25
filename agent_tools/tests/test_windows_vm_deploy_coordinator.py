"""Physical coordinator state, source custody and original-attempt isolation."""
import hashlib
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from agent_tools import windows_vm_deploy as deploy
from agent_tools import native_environment as environments
from agent_tools.native_review_source_closure import _Held
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests import test_native_vm_spec as specs


@unittest.skipUnless(os.name=='posix','POSIX coordinator state')
class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.root.chmod(0o700)
        self.spec=FreshWindowsVmSpec.parse(specs.request())
        self.setup={'imageName':'Windows 11 Pro','locale':'en-US','user':'ordinary','administrator':'fixtureAdmin'}
        self.context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]}
        self.media_patch=mock.patch.object(deploy,'installer_media',return_value={'state':'media-observed','images':[
            {'name':'Windows 11 Pro','languages':['en-US']}]})
        self.media_patch.start();self.addCleanup(self.media_patch.stop)
    def claim(self):
        correlation='a'*32;directory=deploy._runtime_group(self.root,'windows-vm-deploy')/correlation;directory.mkdir(mode=0o700)
        # Reading original source must never execute it, including on UNKNOWN.
        source=('SPEC='+repr(self.spec.as_dict())+'\nSETUP='+repr(self.setup)+'\nCONTEXT='+repr(self.context)+"\nMODE='start'\nraise RuntimeError('SOURCE_MUST_NOT_EXECUTE')\n").encode()
        deploy.stage._retain(directory,'caller.py',source)
        parent=self.root/'.rag_index/windows-vm-deploy-intents';parent.mkdir(mode=0o700,parents=True)
        value={'spec':self.spec.as_dict(),'setup':self.setup,'context':self.context,'mode':'start',
               'correlationId':correlation,'callerSha256':hashlib.sha256(source).hexdigest()}
        path=parent/(self.spec.deployment_id+'.intent.json');deploy.stage._retain(parent,path.name,value)
        return path,directory/'caller.py'
    def clock_ahead_reservation(self,module=deploy,*,ahead=65):
        from agent_tools import vm_workflow
        class Clock:
            now=2_000_000_000_000_000_000
            elapsed=0.0
            sleeps=[]
            @classmethod
            def time_ns(cls):return cls.now
            @classmethod
            def monotonic(cls):return cls.elapsed
            @classmethod
            def sleep(cls,seconds):cls.sleeps.append(seconds);cls.elapsed+=seconds;cls.now+=round(seconds*1_000_000_000)
        now=Clock.now//1_000_000
        samples=[{'observedAtUnixMs':now+ahead-100,'availableMemoryBytes':32*1024**3,'psi':'normal','psiSomeAvg10':0.0,'psiFullAvg10':0.0,'vmstat':{'pswpin':0,'pswpout':0,'oomKill':0}},
                 {'observedAtUnixMs':now+ahead,'availableMemoryBytes':32*1024**3,'psi':'normal','psiSomeAvg10':0.0,'psiFullAvg10':0.0,'vmstat':{'pswpin':0,'pswpout':0,'oomKill':0}}]
        observation={'schemaVersion':1,'deploymentId':self.spec.deployment_id,'mode':'host-resources','state':'resources-observed','reason':None,
                     'hostBootId':self.context['hostBootId'],'vms':[],'physicalMemoryBytes':64*1024**3,'swapUsedBytes':0,'samples':samples,
                     'freeDiskBytes':512*1024**3,'inventoryComplete':True,'nativeActionAllowed':False,'replayAllowed':False}
        authority=mock.MagicMock();authority.config.hosts={self.spec.host:object()}
        guard=mock.MagicMock();guard.__enter__.return_value=authority
        with mock.patch.object(module,'time',Clock),mock.patch.object(vm_workflow,'time',Clock),mock.patch.object(module.direct,'Guard',return_value=guard),mock.patch.object(module,'resources',return_value=observation):
            result=module._prepare_reservation(self.root,self.spec,'/INERT_PRIVATE_CREDENTIAL')
        return result,Clock
    def test_fresh_remote_clock_ahead_waits_then_uses_unchanged_freshness_guard(self):
        result,clock=self.clock_ahead_reservation()
        self.assertEqual('pending',result['request']['allocationState'])
        self.assertTrue(clock.sleeps)
        self.assertGreaterEqual(clock.now//1_000_000,2_000_000_000_065)
        self.assertEqual(2_000_000_000_065,result['request']['measurement']['samples'][-1]['observedAtUnixMs'])
    def test_clock_ahead_exceeding_readiness_budget_cannot_reserve(self):
        with self.assertRaises(environments.NativeEnvironmentError):self.clock_ahead_reservation(ahead=181_000)
        self.assertFalse((self.root/'.rag_index/native-environments/reservations.json').exists())
    def test_preserved_clock_failure_uses_the_same_real_reservation_guard(self):
        folder=Path(__file__).parent/'fixtures/resource_clock_ahead';raw=(folder/'windows_vm_deploy.py.before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes());self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._resource_clock_before');before.__package__='agent_tools';before.__file__=str(folder/'windows_vm_deploy.py.before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with self.assertRaisesRegex(environments.NativeEnvironmentError,'samples are not recent'):self.clock_ahead_reservation(before)
        self.assertFalse((self.root/'.rag_index/native-environments/reservations.json').exists())
        self.assertEqual('pending',self.clock_ahead_reservation()[0]['request']['allocationState'])
    def retry_unsubmitted_preparation(self,module=deploy,*,change=None):
        credential=self.root/'sudo.secret';credential.write_text('INERT_LOCAL_FIXTURE\n');credential.chmod(0o600)
        def prepare(*_):
            request={'hostAlias':self.spec.host,'environment':'owned-unit-vm','operator':'windows-vm-deploy',
                     'requestedMemoryBytes':self.spec.memory_mib*1024**2,'headroomBytes':8*1024**3,
                     'measurement':{'physicalMemoryBytes':32*1024**3,'runningConfiguredMemoryBytes':0,'pressure':'normal','swapUsedBytes':0},'allocationState':'pending'}
            return {'reservation':environments.reserve_environment(self.root,request),'request':request,'hostBootId':self.context['hostBootId'],'pending':[]}
        def native(_root,_spec,mode,**kwargs):
            self.assertEqual('start',mode);kwargs['before_submit']()
            return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}
        with mock.patch.object(module,'_prepare_reservation',side_effect=environments.NativeEnvironmentError('receipt clock is ahead')):
            first=module.start(self.root,self.spec.as_dict(),self.setup,str(credential))
        self.assertFalse(first['vmSubmitted'])
        setup=dict(self.setup)
        if change=='setup':setup['user']='anotherUser'
        if change=='credential':credential.write_text('ANOTHER_INERT_LOCAL_FIXTURE\n')
        with mock.patch.object(module,'_prepare_reservation',side_effect=prepare),mock.patch.object(module,'_execute',side_effect=native) as dispatch:
            result=module.start(self.root,self.spec.as_dict(),setup,str(credential))
        self.assertEqual(1,dispatch.call_count)
        return result
    def test_unsubmitted_resource_refusal_can_prepare_again_without_replacing_credentials(self):
        self.assertEqual('unknown',self.retry_unsubmitted_preparation()['state'])
    def test_unsubmitted_preparation_cannot_change_payload_or_credential_generation(self):
        for change in ['setup','credential']:
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
                original=self.root;self.root=Path(temporary);self.root.chmod(0o700)
                try:
                    with self.assertRaisesRegex(ValueError,'deployment_preparation_changed'):self.retry_unsubmitted_preparation(change=change)
                finally:self.root=original
    def test_legacy_unbound_credential_preparation_is_preserved_and_blocks(self):
        parent=deploy._runtime_group(self.root,'windows-vm-credentials')/self.spec.deployment_id;parent.mkdir(mode=0o700)
        marker=parent/'original';marker.write_bytes(b'UNCHANGED_ORIGINAL_PREPARATION');marker.chmod(0o600)
        with mock.patch.object(deploy,'_prepare_reservation',side_effect=AssertionError('no new preparation')):
            with self.assertRaisesRegex(ValueError,'deployment_preparation_exists'):deploy.start(self.root,self.spec.as_dict(),self.setup,'/MISSING')
        self.assertEqual(b'UNCHANGED_ORIGINAL_PREPARATION',marker.read_bytes())
    def test_preserved_preparation_failure_created_unbound_credentials_that_prevented_retry(self):
        folder=Path(__file__).parent/'fixtures/resource_clock_ahead';raw=(folder/'windows_vm_deploy.py.before.source').read_bytes()
        before=types.ModuleType('agent_tools._preparation_order_before');before.__package__='agent_tools';before.__file__=str(folder/'windows_vm_deploy.py.before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with mock.patch.object(before,'installer_media',return_value={'state':'media-observed','images':[{'name':'Windows 11 Pro','languages':['en-US']}]}),self.assertRaises(FileExistsError):self.retry_unsubmitted_preparation(before)
    def test_empty_runtime_is_created_without_prior_attempt_directories(self):
        self.assertFalse((self.root/'.runtime').exists())
        path=deploy._runtime_group(self.root,'windows-vm-deploy')
        self.assertTrue(path.is_dir());self.assertEqual(0o700,path.stat().st_mode&0o777)

    def test_preserved_admission_exception_fixed_finite_refusal_precedes_vm_submission(self):
        folder=Path(__file__).parent/'fixtures/reservation_preparation_refusal'
        raw=(folder/'before.source').read_bytes();metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._prepare_refusal_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        for module,fixed in ((before,False),(deploy,True)):
            with self.subTest(fixed=fixed),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
                root=Path(temporary);root.chmod(0o700);credential=root/'sudo.secret'
                credential.write_text('INERT_LOCAL_FIXTURE\n');credential.chmod(0o600)
                state=root/'.rag_index/native-environments';state.mkdir(mode=0o700,parents=True)
                payload=b'{"version":1,"reservations":[]}\n';(state/'reservations.json').write_bytes(payload)
                with mock.patch.object(module,'_prepare_reservation',side_effect=environments.NativeEnvironmentError('configured memory exceeds physical capacity')), \
                     mock.patch.object(module,'_execute',side_effect=AssertionError('VM must never submit')) as native:
                    if fixed:
                        result=module.start(root,self.spec.as_dict(),self.setup,str(credential))
                        self.assertEqual('blocked',result['state']);self.assertFalse(result['vmSubmitted']);self.assertFalse(result['replayAllowed'])
                    else:
                        with self.assertRaises(environments.NativeEnvironmentError):module.start(root,self.spec.as_dict(),self.setup,str(credential))
                    native.assert_not_called()
                self.assertEqual(payload,(state/'reservations.json').read_bytes())
                self.assertFalse((root/'.rag_index/windows-vm-deploy-intents').exists())
    def test_runtime_alias_is_refused_without_writing_foreign_directory(self):
        with tempfile.TemporaryDirectory() as other:
            (self.root/'.runtime').symlink_to(other,target_is_directory=True)
            with self.assertRaises(ValueError):deploy._runtime_group(self.root,'windows-vm-deploy')
            self.assertEqual([],list(Path(other).iterdir()))
    def test_original_start_blocks_before_credentials_or_new_preparation(self):
        path,_=self.claim();original=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'original_exists'):
            deploy.start(self.root,self.spec.as_dict(),self.setup,'/MISSING_PRIVATE_CREDENTIAL')
        self.assertEqual(original,path.read_bytes())
        self.assertFalse((self.root/'.runtime/windows-vm-credentials').exists())

    def test_consumed_stop_claim_refuses_before_credentials_or_transport(self):
        self.claim();group=self.root/'.rag_index/windows-vm-deploy-stops';group.mkdir(mode=0o700)
        path=group/(self.spec.deployment_id+'.intent.json');path.write_bytes(b'ORIGINAL_UNKNOWN_STOP');path.chmod(0o600)
        with mock.patch.object(deploy.direct,'Guard',side_effect=AssertionError('no transport')),self.assertRaisesRegex(ValueError,'original_exists'):
            deploy.stop(self.root,self.spec.deployment_id,'/MISSING_PRIVATE_CREDENTIAL')
        self.assertEqual(b'ORIGINAL_UNKNOWN_STOP',path.read_bytes())
    def test_status_parses_original_source_as_data_and_holds_physical_identity(self):
        _,source=self.claim()
        def observation(*args,**kwargs):return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}
        with mock.patch.object(deploy,'_execute',side_effect=observation) as native:
            result=deploy.status(self.root,self.spec.deployment_id,'/PRIVATE_ARGUMENT')
        self.assertEqual('unknown',result['state']);self.assertEqual('status',native.call_args.args[2])
        def exchange(*args,**kwargs):
            replacement=source.with_name('replacement');replacement.write_bytes(source.read_bytes());replacement.chmod(0o600);replacement.replace(source)
            return observation()
        with mock.patch.object(deploy,'_execute',side_effect=exchange),self.assertRaises(ValueError):
            deploy.status(self.root,self.spec.deployment_id,'/PRIVATE_ARGUMENT')
    def test_source_capsule_is_retained_before_closing_and_drift_never_seals_it(self):
        source=self.root/'owned.py';source.write_bytes(b'VALUE=1\n');source.chmod(0o600)
        held=_Held();self.addCleanup(held.close);held.read(str(source),hashlib.sha256(source.read_bytes()).hexdigest())
        def guard():held.finish();held.final_identity_pass()
        first=self.root/'first';first.mkdir(mode=0o700)
        deploy._retain_sources(first,[source],SimpleNamespace(guard=guard))
        self.assertEqual(source.read_bytes(),(first/'sources/owned.py').read_bytes())
        second=self.root/'second';second.mkdir(mode=0o700);retain=deploy.stage._retain
        def changed(directory,name,value):
            result=retain(directory,name,value)
            if name=='owned.py':source.write_bytes(b'VALUE=2\n')
            return result
        with mock.patch.object(deploy.stage,'_retain',side_effect=changed),self.assertRaises(ValueError):
            deploy._retain_sources(second,[source],SimpleNamespace(guard=guard))
        self.assertEqual(b'VALUE=1\n',(second/'sources/owned.py').read_bytes())
        self.assertFalse((second/'sources/manifest.json').exists())

    def test_native_credential_preparation_beforeimage_and_real_private_files(self):
        folder=Path(__file__).parent/'fixtures/deploy_credential_path'
        raw=(folder/'before.source').read_bytes();provenance=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(provenance['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._deploy_path_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        for module,fixed in ((before,False),(deploy,True)):
            with self.subTest(fixed=fixed),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
                root=Path(temporary);root.chmod(0o700)
                credential=root/'sudo.secret';credential.write_text('INERT_LOCAL_FIXTURE\n');credential.chmod(0o600)
                calls=[]
                def prepare(*_):
                    request={'hostAlias':self.spec.host,'environment':'owned-unit-vm','operator':'windows-vm-deploy',
                             'requestedMemoryBytes':self.spec.memory_mib*1024**2,'headroomBytes':8*1024**3,
                             'measurement':{'physicalMemoryBytes':32*1024**3,'runningConfiguredMemoryBytes':0,
                                            'pressure':'normal','swapUsedBytes':0},'allocationState':'pending'}
                    return {'reservation':environments.reserve_environment(root,request),'request':request,
                            'hostBootId':self.context['hostBootId'],'pending':[]}
                def native(_root,_spec,mode,**kwargs):
                    self.assertEqual('start',mode)
                    self.assertTrue(all(type(value)is str for value in kwargs['payload'].values()))
                    kwargs['before_submit']();calls.append(mode)
                    return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}
                with (mock.patch.object(module,'_prepare_reservation',side_effect=prepare),
                      mock.patch.object(module,'_execute',side_effect=native)):
                    if fixed:self.assertEqual('unknown',module.start(root,self.spec.as_dict(),self.setup,str(credential))['state'])
                    else:
                        with self.assertRaisesRegex(ValueError,'credential_path'):
                            module.start(root,self.spec.as_dict(),self.setup,str(credential))
                self.assertEqual(['start'] if fixed else [],calls)
                rows=json.loads((root/'.rag_index/native-environments/reservations.json').read_bytes())['reservations']
                self.assertEqual('unknown' if fixed else 'absent',rows[0]['activeJob'])
                private=root/'.runtime/windows-vm-credentials'/self.spec.deployment_id
                self.assertEqual(0o600,(private/'user.secret').stat().st_mode&0o777)


if __name__=='__main__':unittest.main()
