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
