import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import android_endpoint_admission as endpoint
from agent_tools.tests import test_android_endpoint_admission as fixtures
CORRELATION = fixtures.CORRELATION
try:
    from agent_tools import android_recovered_endpoint_stage_cleanup as stage
except ImportError:
    stage = None

STAGE = '0c825b31-bceb-42d7-a472-613e3792f3cc'


class RecoveredStageCleanupTest(unittest.TestCase):
    def fixture(self, root):
        helper = fixtures.AndroidCleanupReadmissionTest()
        intent, state, config, old, recovery, observe = helper.recovery_fixture(root)
        with mock.patch.object(endpoint.ssh_transport, 'load_config', return_value=config), mock.patch.object(endpoint, '_remote', side_effect=observe):
            self.assertEqual('ready', endpoint.recovery_readmission(root, CORRELATION, old, recovery)['state'])
            self.assertEqual('partial', endpoint.recovery_unmount_once(root, CORRELATION, old, recovery)['state'])
        state['effects'].clear()
        return helper, intent, state, config, old, recovery, observe

    def remote(self,root,helper,state,observe):
        source=stage._remote_source()
        # The recovery fixture's closure retains its actual fake subprocess
        # implementation; run the same generated program with that boundary.
        import inspect
        command=inspect.getclosurevars(observe).nonlocals['command']
        def adapted(argv,**kwargs):
            if state.get('failingPublicStatus') and argv[0]=='/bin/cli' and fixtures._public_words(argv)==['status']:
                return fixtures.SimpleNamespace(returncode=state.get('publicExit',126),stdout=state.get('publicStdout',b''),stderr=state.get('publicStderr',b'private actual generated status failure'))
            words=argv[5:] if argv[3:5]==['shell','-T'] else []
            if words[:2]==['/system/xbin/su','0,0']:
                argv=[*argv[:5],*words[2:]];words=words[2:]
            if words[:1]==['/system/bin/sh'] and '[ -e ' in words[-1] and CORRELATION in words[-1]:
                return fixtures.SimpleNamespace(returncode=0,stdout=b'absent' if state.get('retired') else b'present',stderr=b'')
            if words[:1]==['/system/bin/nsenter'] and words[5:8]==['/system/bin/stat','-c','%F'] and state.get('targetCa')==b'present':
                return fixtures.SimpleNamespace(returncode=0,stdout=b'regular file',stderr=b'')
            return command(argv,**kwargs)
        def dispatch(_root,intent,action):
            with mock.patch.object(endpoint,'_REMOTE',source):
                return helper.execute(root,intent['remote'],'recovery-status',adapted)
        return dispatch

    def test_required_dependency_drift_rejects_before_new_stage_request(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            source=endpoint._REMOTE.replace('def installed():',"def installed():\n raise ValueError('changed')",1)
            with mock.patch.object(endpoint,'_REMOTE',source),mock.patch.object(stage,'_remote') as remote:
                self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                remote.assert_not_called()
            self.assertFalse((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.request.json')).exists())
            self.assertEqual([],state['effects'])

    def test_generated_failed_status_command_preserves_finite_phase_and_private_future_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            state['failingPublicStatus']=True
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                result=stage.admit(root,CORRELATION,old,recovery,STAGE)
            self.assertEqual('unknown',result['state']);self.assertEqual('command_failed',result['reason'])
            self.assertEqual({'phase':'public-status','outcome':'nonzero','stderrClass':'other'},result.get('commandDiagnostic'))
            self.assertNotIn('private actual',json.dumps(result));self.assertEqual([],state['effects'])
            path=root/('android-endpoint-'+CORRELATION)/('recovered-stage-'+STAGE+'.command-failure.json')
            self.assertTrue(path.exists(),'future command stderr was discarded instead of captured privately')

    def test_completed_recovery_zero_target_ordinary_guard_rejects_but_bound_stage_admission_succeeds(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            helper, intent, state, config, old, recovery, observe = self.fixture(root)
            self.assertNotIn(b'/system/etc/security/cacerts', state['mountinfo'])
            with mock.patch.object(endpoint.ssh_transport, 'load_config', return_value=config), mock.patch.object(endpoint, '_remote', side_effect=observe):
                ordinary = endpoint.cleanup_readmission(root, CORRELATION, STAGE)
            self.assertEqual('unknown', ordinary['state'])
            self.assertEqual('readmission_mountinfo_invalid', ordinary['reason'])
            self.assertEqual([], state['effects'])
            self.assertIsNotNone(stage, 'completed-recovery stage cleanup adapter is missing')
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                admitted=stage.admit(root,CORRELATION,old,recovery,STAGE)
            self.assertEqual('ready',admitted['state'],admitted)

    def test_full_generated_stage_cleanup_retires_only_owned_stage_and_leases_then_status_is_read_only(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            originals={str(p):p.read_bytes() for p in root.rglob('*.json')}
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                cleaned=stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)
                self.assertEqual('cleaned',cleaned['state'],cleaned)
                self.assertEqual([['rm','-r','/data/local/tmp/vpn-control-endpoint-'+CORRELATION],'unroot'],state['effects'])
                self.assertFalse((root/'android-native-device-api29.lease').exists())
                self.assertFalse((root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())
                before={str(p):p.read_bytes() for p in root.rglob('*.json')}
                for _ in range(2):self.assertEqual('cleaned',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*.json')})
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
            for name,content in originals.items():
                if 'lease-' in name or name.endswith('.lease'):continue
                self.assertEqual(content,Path(name).read_bytes(),name)

    def test_admission_rejects_current_native_public_and_ownership_drift(self):
        variants=[{'owner':'foreign-owner'},{'revision':-1},{'rules':{}},{'runtime':True},{'operations':[{'final':False}]},
                  {'package':'f'*64},{'namespace':'mnt:[99]'},{'inode':'0:755:64800:99'},{'ca':'f'*64},
                  {'targetCa':b'present'},{'historicalStagePresent':True},
                  {'mountinfo':b'94 1 253:0 / / ro - ext4 /dev/system ro\n131 94 253:32 / /data rw - ext4 /dev/data rw\n200 94 253:32 /foreign /system/etc/security/cacerts rw - ext4 /dev/data rw\n'}]
        for variant in variants:
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root);state.update(variant)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects']);self.assertFalse((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json')).exists())

    def test_cleanup_rejects_drift_after_admission_before_effect(self):
        variants=[{'owner':'foreign-owner'},{'revision':1},{'rules':{}},{'runtime':True},{'operations':[{'final':False}]},
                  {'package':'f'*64},{'namespace':'mnt:[99]'},{'inode':'0:755:64800:99'},{'ca':'f'*64}]
        for variant in variants:
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state']);state.update(variant)
                    self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                    for _ in range(2):self.assertEqual('unknown',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects']);self.assertTrue((root/'android-native-device-api29.lease').exists())

    def test_inter_effect_drift_blocks_unroot_and_retains_unknown_fence_and_leases(self):
        for changed in ({'owner':'late-owner'},{'rules':{}},{'runtime':True},{'namespace':'mnt:[99]'}):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                base=self.remote(root,helper,state,observe)
                import inspect
                command=inspect.getclosurevars(observe).nonlocals['command']
                def drift(argv,**kwargs):
                    result=command(argv,**kwargs)
                    if state.get('retired'):state.update(changed)
                    return result
                # Substitute only the fake native boundary in the fixture.
                def remote(_root,intent,action):
                    source=stage._remote_source()
                    with mock.patch.object(endpoint,'_REMOTE',source):return helper.execute(root,intent['remote'],'recovery-status',drift)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=remote):
                    self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                    self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                    self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                    for _ in range(2):self.assertEqual('unknown',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([['rm','-r','/data/local/tmp/vpn-control-endpoint-'+CORRELATION]],state['effects'])
                self.assertTrue((root/'android-native-device-api29.lease').exists());self.assertTrue((root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())

    def test_private_generation_mode_hardlink_and_same_byte_rewrite_reject_before_cleanup(self):
        import os
        for attack in ('rewrite','mode','hardlink','foreign-lease','remote-complete'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)) as remote:
                    self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                    path=root/('android-endpoint-'+CORRELATION)/'mount-intent.json'
                    if attack=='rewrite':path.write_bytes(path.read_bytes())
                    elif attack=='mode':path.chmod(0o644)
                    elif attack=='hardlink':os.link(path,path.parent/'hardlink.json')
                    elif attack=='foreign-lease':(root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').write_text('{}')
                    else:
                        path=root/('android-endpoint-'+CORRELATION)/('mount-recovery-'+recovery+'.complete.json');path.write_bytes(path.read_bytes())
                    self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects'])

    def test_lost_terminal_response_collects_once_without_replaying_effects(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root);base=self.remote(root,helper,state,observe)
            def lost(root_,intent_,action):
                value=base(root_,intent_,action)
                if action=='cleanup':raise ValueError('lost-response')
                return value
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=lost):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertTrue((root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())
                effects=list(state['effects'])
                for _ in range(2):self.assertEqual('unknown',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('cleaned',stage.collect(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('cleaned',stage.collect(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual(effects,state['effects'])
                self.assertEqual('cleaned',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])

    def test_source_same_byte_rewrite_and_hardlink_reject_before_dispatch(self):
        import os
        for attack in ('rewrite','hardlink','changed-bytes'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                source=root/'stage-source.py';source.write_bytes(Path(stage.__file__).read_bytes())
                with mock.patch.object(stage,'__file__',str(source)),mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)) as remote:
                    self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                    if attack=='rewrite':source.write_bytes(source.read_bytes())
                    elif attack=='changed-bytes':source.write_bytes(source.read_bytes()+b'\n# newly reviewed source must not replace this consumed request\n')
                    else:os.link(source,root/'source-alias.py')
                    remote.reset_mock();self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state']);remote.assert_not_called()
                self.assertEqual([],state['effects'])

    def test_local_lease_rewrite_after_remote_complete_blocks_local_unlink_and_collect_preserves_claim(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root);base=self.remote(root,helper,state,observe)
            lease=root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json'
            def rewrite(root_,intent_,action):
                value=base(root_,intent_,action)
                if action=='cleanup':lease.write_bytes(lease.read_bytes())
                return value
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=rewrite):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state']);self.assertTrue(lease.exists())
            # Rewritten claims cannot be retroactively accepted by collection.
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=base):
                self.assertEqual('unknown',stage.collect(root,CORRELATION,old,recovery,STAGE)['state']);self.assertTrue(lease.exists())

    def test_missing_completion_or_unsafe_completion_never_admits_effects(self):
        import os
        for attack in ('missing','hardlink','mode','forged'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                path=root/('android-endpoint-'+CORRELATION)/('mount-recovery-'+recovery+'.complete.json')
                if attack=='missing':path.unlink()
                elif attack=='hardlink':os.link(path,path.parent/'complete-alias.json')
                elif attack=='mode':path.chmod(0o644)
                else:path.write_text('{}')
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects'])

    def test_distinct_correlation_validation_is_read_only_and_no_dispatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve()
            with mock.patch.object(stage,'_remote') as remote:
                for function in (stage.admit,stage.cleanup_once,stage.status,stage.collect):
                    with self.assertRaises(ValueError):function(root,CORRELATION,CORRELATION,CORRELATION,STAGE)
                remote.assert_not_called()
            self.assertEqual([],list(root.iterdir()))

    def test_local_and_remote_locks_cover_proof_effects_and_unlinks(self):
        import fcntl,os
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            state['assertRemoteLock']=True;base=self.remote(root,helper,state,observe)
            local=root/'.rag_index/android-native-device-leases/lock-archlinux-api29.json';remote_path=root/'android-native-device-api29.lock'
            def dispatch(*args):
                fd=os.open(local,os.O_RDWR)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
                return base(*args)
            original_unlink=Path.unlink
            def unlink(path,*args,**kwargs):
                if path.name in ('android-native-device-api29.lease','lease-archlinux-api29.json'):
                    lock=remote_path if path.name.endswith('.lease') else local
                    fd=os.open(lock,os.O_RDWR)
                    try:
                        with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    finally:os.close(fd)
                return original_unlink(path,*args,**kwargs)
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=dispatch),mock.patch.object(Path,'unlink',unlink):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('cleaned',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('cleaned',stage.status(root,CORRELATION,old,recovery,STAGE)['state'])
            for lock in (local,remote_path):
                fd=os.open(lock,os.O_RDWR)
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)

    def test_generated_receipt_caps_and_budget_cover_actual_serial_paths(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            base=self.remote(root,helper,state,observe);sizes=[]
            def dispatch(*args):
                value=base(*args);sizes.append(len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())+1);return value
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=dispatch):
                for function,action in ((stage.admit,'admit'),(stage.cleanup_once,'cleanup'),(stage.status,'status'),(stage.collect,'collect')):
                    state['timeouts']=Counter();value=function(root,CORRELATION,old,recovery,STAGE)
                    self.assertIn(value['state'],('ready','cleaned'),value)
                    self.assertGreaterEqual(stage._transport_budget(action),sum(t*n for t,n in state['timeouts'].items())+60)
            self.assertLessEqual(max(sizes),endpoint.android_observation.MAX_OUTPUT_BYTES)
            for path in root.rglob('recovered-stage-*.json'):self.assertLessEqual(path.stat().st_size,8192)
            self.assertEqual(16384,endpoint.android_observation.MAX_OUTPUT_BYTES);self.assertEqual(4096,endpoint.ssh_transfer.MAX_OUTPUT_BYTES)

    def test_terminal_same_byte_rewrite_and_hardlink_are_not_collected_as_the_original_generation(self):
        import os
        for attack in ('remote-rewrite','remote-hardlink','local-rewrite'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                    self.assertEqual('cleaned',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                    path=(root/'.rag_index/android-endpoint-admission' if attack=='local-rewrite' else root/('android-endpoint-'+CORRELATION))/('recovered-stage-'+STAGE+'.complete.json')
                    if attack=='remote-hardlink':os.link(path,path.parent/'terminal-alias.json')
                    else:path.write_bytes(path.read_bytes())
                    for function in (stage.status,stage.collect):self.assertEqual('unknown',function(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([['rm','-r','/data/local/tmp/vpn-control-endpoint-'+CORRELATION],'unroot'],state['effects'])

    def test_uncertain_unroot_is_fenced_and_never_replayed_or_lease_retired(self):
        import inspect
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            base=self.remote(root,helper,state,observe)
            def dispatch(root_,intent_,action):
                if action!='cleanup':return base(root_,intent_,action)
                source=stage._remote_source();command=inspect.getclosurevars(observe).nonlocals['command']
                def failed(argv,**kwargs):
                    result=command(argv,**kwargs)
                    if argv[3]=='unroot':return fixtures.SimpleNamespace(returncode=1,stdout=b'',stderr=b'private-uncertain')
                    return result
                with mock.patch.object(endpoint,'_REMOTE',source):return helper.execute(root,intent_['remote'],'recovery-status',failed)
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=dispatch):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                effects=list(state['effects'])
                for function in (stage.cleanup_once,stage.status,stage.collect,stage.status):self.assertEqual('unknown',function(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual(effects,state['effects'])
            self.assertTrue((root/'android-native-device-api29.lease').exists());self.assertTrue((root/'.rag_index/android-native-device-leases/lease-archlinux-api29.json').exists())

    def test_near_ceiling_actual_inventory_serial_budget_remains_bounded(self):
        from collections import Counter
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper=fixtures.AndroidCleanupReadmissionTest()
            intent,state,config,old,recovery,observe=helper.recovery_fixture(root)
            extra=''.join(str(300+i)+' 131 253:32 /unrelated'+str(i)+' /extra'+str(i)+' rw - ext4 /dev/data rw\n' for i in range(126))
            state['extraMountinfo']=extra;state['postExtraMountinfo']='500 131 253:32 /last /last rw - ext4 /dev/data rw\n';state['mountinfo']+=extra.encode()
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(endpoint,'_remote',side_effect=observe):
                self.assertEqual('ready',endpoint.recovery_readmission(root,CORRELATION,old,recovery)['state'])
                self.assertEqual('partial',endpoint.recovery_unmount_once(root,CORRELATION,old,recovery)['state'])
            state['effects'].clear()
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                for function,action in ((stage.admit,'admit'),(stage.cleanup_once,'cleanup'),(stage.status,'status'),(stage.collect,'collect')):
                    state['timeouts']=Counter();value=function(root,CORRELATION,old,recovery,STAGE)
                    self.assertIn(value['state'],('ready','cleaned'),value)
                    actual=sum(t*n for t,n in state['timeouts'].items())
                    self.assertGreaterEqual(stage._transport_budget(action),actual+60)

    def test_real_competing_device_lock_blocks_admission_before_any_native_proof(self):
        import fcntl,os,threading
        for domain in ('local','remote'):
            with self.subTest(domain=domain),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                path=root/'.rag_index/android-native-device-leases/lock-archlinux-api29.json' if domain=='local' else root/'android-native-device-api29.lock'
                fd=os.open(path,os.O_RDWR);fcntl.flock(fd,fcntl.LOCK_EX);results=[];started=threading.Event();state['reads']=0
                def work():
                    started.set();results.append(stage.admit(root,CORRELATION,old,recovery,STAGE))
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    thread=threading.Thread(target=work);thread.start();started.wait(1)
                    try:
                        thread.join(.1);self.assertTrue(thread.is_alive());self.assertEqual(0,state['reads']);self.assertEqual([],state['effects'])
                    finally:fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)
                    thread.join(3);self.assertFalse(thread.is_alive());self.assertEqual('ready',results[0]['state'],results)

    def test_real_nested_transport_preserves_bounds_and_uses_existing_observation_cap(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            captured=[];base=self.remote(root,helper,state,observe)
            def dispatch(*args):captured.append(args[1]);return base(*args)
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=dispatch):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
            config=helper.endpoint_nested_transport_fixture(root)
            def probe(argv,budget):
                self.assertLess(max(len(x.encode()) for x in argv),65536)
                inner=__import__('shlex').split(argv[-1]);destination=__import__('shlex').split(inner[-1])
                self.assertEqual('python3',destination[0]);self.assertEqual('recovery-status',destination[3])
                self.assertEqual(captured[0]['remote'],json.loads(destination[-1]))
                self.assertEqual(stage._transport_budget('admit'),budget)
                return 0,json.dumps({'state':'unknown','reason':'stage_unverified','correlationId':CORRELATION}).encode()
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(endpoint.android_observation,'_run_probe',side_effect=probe) as runner:
                self.assertEqual('unknown',stage._remote(root,captured[0],'admit')['state']);runner.assert_called_once()
            self.assertEqual([],state['effects'])

    def test_existing_failed_admission_diagnostic_is_read_only_preserves_old_source_request_and_no_replay(self):
        DIAGNOSTIC='dda5f802-15c7-41be-82a0-5f84ab7289d9'
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            source=root/'source-copy.py';source.write_bytes(Path(stage.__file__).read_bytes())
            state['failingPublicStatus']=True
            with mock.patch.object(stage,'__file__',str(source)),mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                request=root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.request.json');retained=request.read_bytes()
                # Legacy failed admission had no private stderr capture.
                capture=root/('android-endpoint-'+CORRELATION)/('recovered-stage-'+STAGE+'.command-failure.json');capture.unlink()
                source.write_bytes(source.read_bytes())
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,DIAGNOSTIC)
                self.assertEqual('unknown',result['state']);self.assertEqual('command_failed',result['reason'])
                self.assertEqual({'phase':'public-status','outcome':'nonzero','stderrClass':'other'},result['commandDiagnostic'])
                self.assertEqual('unavailable',result['originalCommandEvidence'])
                self.assertEqual(retained,request.read_bytes());self.assertEqual([],state['effects'])
                self.assertFalse(capture.exists(),'original stderr must not be retroactively manufactured')
                new=root/('android-endpoint-'+CORRELATION)/('recovered-stage-'+DIAGNOSTIC+'.command-failure.json')
                import base64,hashlib,stat
                evidence=json.loads(new.read_bytes());self.assertEqual(126,evidence['returncode'])
                self.assertEqual(b'private actual generated status failure',base64.b64decode(evidence['stderr']))
                before=new.read_bytes();pin=new.stat();self.assertEqual(0o600,stat.S_IMODE(pin.st_mode));self.assertLessEqual(pin.st_size,8192)
                self.assertNotIn('private actual',json.dumps(result))
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,DIAGNOSTIC)
                self.assertEqual('unknown',result['state']);self.assertEqual(before,new.read_bytes());self.assertEqual(pin.st_ino,new.stat().st_ino)
                state['failingPublicStatus']=False
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,'fea99040-bd30-4323-a89c-d0b278b55bd6')
                self.assertEqual('partial',result['state'],result);self.assertEqual('unavailable',result['originalCommandEvidence']);self.assertFalse(result['receiptPresent'])
                self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state']);self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual(retained,request.read_bytes());self.assertEqual([],state['effects'])

    def test_stage_diagnostic_rejects_effect_fence_and_forged_public_fields(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                state['owner']='changed';self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,'dda5f802-15c7-41be-82a0-5f84ab7289d9')
                self.assertEqual('unknown',result['state']);self.assertEqual([],state['effects'])
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',return_value={'state':'unknown','reason':'command_failed','correlationId':CORRELATION,'commandDiagnostic':{'phase':'private-secret','outcome':'nonzero','stderrClass':'other'},'publicFailure':{'code':'private-secret','exitDisposition':'matched','final':True}}):
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,'fea99040-bd30-4323-a89c-d0b278b55bd6')
                self.assertNotIn('private-secret',json.dumps(result));self.assertNotIn('commandDiagnostic',result)

    def test_generated_public_failure_code_and_bounded_raw_capture_are_private_and_create_only(self):
        import base64,hashlib,stat
        for large in (False,True):
            with self.subTest(large=large),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                state['failingPublicStatus']=True;state['publicExit']=1
                output=json.dumps({'schemaVersion':1,'ok':False,'code':'PERMISSION_DENIED','final':True}).encode()
                state['publicStdout']=output if not large else b'private-output-'*10000
                state['publicStderr']=b'Permission denied private-diagnostic' if not large else b'private-stderr-'*10000
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                    result=stage.admit(root,CORRELATION,old,recovery,STAGE)
                self.assertEqual('unknown',result['state']);self.assertNotIn('private-diagnostic',json.dumps(result));self.assertNotIn('private-output',json.dumps(result))
                if not large:self.assertEqual({'code':'PERMISSION_DENIED','exitDisposition':'matched','final':True},result['publicFailure'])
                path=root/('android-endpoint-'+CORRELATION)/('recovered-stage-'+STAGE+'.command-failure.json')
                value=json.loads(path.read_bytes());self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode));self.assertLessEqual(path.stat().st_size,8192)
                self.assertEqual(hashlib.sha256(state['publicStdout']).hexdigest(),value['stdoutSha256'])
                self.assertEqual(hashlib.sha256(state['publicStderr']).hexdigest(),value['stderrSha256'])
                self.assertLessEqual(len(base64.b64decode(value['stdout'])),1024);self.assertLessEqual(len(base64.b64decode(value['stderr'])),1024)
                self.assertEqual(large,value['truncated']);self.assertEqual([],state['effects'])

    def test_diagnostic_canonical_binding_and_consumed_local_request_are_required(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve()
            with mock.patch.object(stage,'_remote') as remote:
                with self.assertRaises(ValueError):stage.diagnostic(root,CORRELATION,'d861ec64-e487-4035-afd1-e8dd8400f5c7','aae27b01-a810-4088-93f2-ff06a036d112',STAGE,STAGE)
                remote.assert_not_called();self.assertEqual([],list(root.iterdir()))
            helper,intent,state,config,old,recovery,observe=self.fixture(root)
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote') as remote:
                self.assertEqual('unknown',stage.diagnostic(root,CORRELATION,old,recovery,STAGE,'dda5f802-15c7-41be-82a0-5f84ab7289d9')['state']);remote.assert_not_called()
            self.assertEqual([],state['effects'])

    def test_actual_status_argv_and_adapter_pin_recovery_owner_and_reject_later_provider_epoch(self):
        import ast,inspect,os
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            protected=json.loads((root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+recovery+'.json')).read_bytes())['snapshot']['public']
            current='82b3af51-d264-4920-9854-3496f6ae28c2';state['owner']=current;seen=[]
            command=inspect.getclosurevars(observe).nonlocals['command']
            def checked(argv,**kwargs):
                if argv[0]=='/bin/cli' and fixtures._public_words(argv)==['status']:
                    adapter=Path(kwargs['env']['PATH'].split(os.pathsep)[0])/'adb'
                    line=next(line for line in adapter.read_text().splitlines() if line.startswith('CONFIG='))
                    configuration=json.loads(ast.literal_eval(line.removeprefix('CONFIG=')))
                    self.assertEqual(protected['owner'],argv[argv.index('--controller-id')+1])
                    self.assertEqual(protected['owner'],configuration['owner']);self.assertEqual(protected['revision'],configuration['revision'])
                    self.assertEqual('status',configuration['operation']);self.assertNotIn('--if-revision',argv)
                    seen.append(configuration)
                    value={'schemaVersion':1,'ok':False,'code':'CONFLICT','final':True,'controllerId':current,'configurationRevision':0}
                    return fixtures.SimpleNamespace(returncode=1,stdout=json.dumps(value).encode(),stderr=b'')
                return command(argv,**kwargs)
            def remote(_root,dispatch,action):
                with mock.patch.object(endpoint,'_REMOTE',stage._remote_source()):return helper.execute(root,dispatch['remote'],'recovery-status',checked)
            state['failingPublicStatus']=True
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
            state['failingPublicStatus']=False
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=remote):
                result=stage.diagnostic(root,CORRELATION,old,recovery,STAGE,'dda5f802-15c7-41be-82a0-5f84ab7289d9')
                self.assertEqual('unknown',result['state']);self.assertEqual({'code':'CONFLICT','exitDisposition':'matched','final':True},result['publicFailure'])
                self.assertEqual({'phase':'public-status','outcome':'nonzero','stderrClass':'none'},result['commandDiagnostic'])
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
            self.assertEqual(1,len(seen));self.assertEqual([],state['effects'])

    def test_new_distinct_readmission_discovers_current_epoch_then_pins_complete_baseline_and_cleanup(self):
        import inspect,os,ast
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            current='82b3af51-d264-4920-9854-3496f6ae28c2';state['owner']=current;requests=[]
            command=inspect.getclosurevars(observe).nonlocals['command']
            def guarded(argv,**kwargs):
                if argv[0]=='/bin/cli':
                    supplied=argv[argv.index('--controller-id')+1] if '--controller-id' in argv else None
                    if state['uid']=='0':
                        adapter=Path(kwargs['env']['PATH'].split(os.pathsep)[0])/'adb'
                        configuration=json.loads(ast.literal_eval(next(x for x in adapter.read_text().splitlines() if x.startswith('CONFIG=')).removeprefix('CONFIG=')))
                        self.assertEqual(supplied,configuration['owner'])
                    requests.append((fixtures._public_words(argv),supplied))
                    if supplied is not None and supplied!=current:
                        return fixtures.SimpleNamespace(returncode=1,stdout=json.dumps({'schemaVersion':1,'ok':False,'code':'CONFLICT','final':True,'controllerId':current,'configurationRevision':0}).encode(),stderr=b'')
                if argv[3:5]==['shell','-T'] and argv[5:7]==['/system/xbin/su','0,0']:argv=[*argv[:5],*argv[7:]]
                words=argv[5:] if argv[3:5]==['shell','-T'] else []
                if words[:1]==['/system/bin/sh'] and '[ -e ' in words[-1] and CORRELATION in words[-1]:return fixtures.SimpleNamespace(returncode=0,stdout=b'absent' if state.get('retired') else b'present',stderr=b'')
                return command(argv,**kwargs)
            def remote(_root,dispatch,action):
                with mock.patch.object(endpoint,'_REMOTE',stage._remote_source()):return helper.execute(root,dispatch['remote'],'recovery-status',guarded)
            original=(root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+recovery+'.json')).read_bytes()
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=remote):
                result=stage.admit(root,CORRELATION,old,recovery,STAGE)
                self.assertEqual('ready',result['state'],result)
                self.assertEqual((['status'],None),requests[0]);self.assertTrue(all(owner==current for _,owner in requests[1:]))
                self.assertEqual([],state['effects'])
                receipt=json.loads((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json')).read_bytes())
                self.assertEqual(current,receipt['snapshot']['owner']);self.assertEqual(0,receipt['snapshot']['revision'])
                self.assertEqual('cleaned',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
            self.assertEqual(original,(root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+recovery+'.json')).read_bytes())

    def test_fresh_owner_revision_drift_between_full_snapshots_never_creates_receipt_or_effect(self):
        import inspect
        for key,value in (('owner','83b3af51-d264-4920-9854-3496f6ae28c2'),('revision',1)):
            with self.subTest(key=key),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
                state['owner']='82b3af51-d264-4920-9854-3496f6ae28c2';state['reads']=0
                command=inspect.getclosurevars(observe).nonlocals['command']
                def drift(argv,**kwargs):
                    if argv[0]=='/bin/cli' and state['reads']>=12:state[key]=value
                    return command(argv,**kwargs)
                def remote(_root,dispatch,action):
                    with mock.patch.object(endpoint,'_REMOTE',stage._remote_source()):return helper.execute(root,dispatch['remote'],'recovery-status',drift)
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=remote):
                    self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects']);self.assertFalse((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json')).exists())

    def test_forged_fresh_admission_native_and_public_proof_fields_are_rejected_locally(self):
        import copy
        for attack in ('uid','api','rules','namespace','mount-sha','target-inode','principal','private-mode'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root);base=self.remote(root,helper,state,observe)
                def forged(*args):
                    result=base(*args);receipt=copy.deepcopy(result['stageReceipt']);result['stageReceipt']=receipt
                    if attack=='uid':receipt['snapshot']['uid']='2000'
                    elif attack=='api':receipt['snapshot']['api']=True
                    elif attack=='rules':receipt['snapshot']['rulesSha256']='0'*64
                    elif attack=='namespace':receipt['snapshot']['namespaceObservation']='unobserved'
                    elif attack=='mount-sha':receipt['native']['mountinfoSha256']='0'*64
                    elif attack=='target-inode':receipt['native']['targetIdentity']=['64800','65542','0','directory']
                    elif attack=='principal':receipt['principal'][0]='0:0:777:1:1:regular file'
                    else:next(iter(receipt['records'].values()))['fingerprint'][5]=0o644
                    return result
                with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=forged):
                    self.assertEqual('unknown',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual([],state['effects']);self.assertFalse((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json')).exists())

    def test_discovery_conflict_payload_never_adopts_owner_or_publishes_stage_receipt(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            state['failingPublicStatus']=True;state['publicExit']=1
            state['publicStdout']=json.dumps({'schemaVersion':1,'ok':False,'code':'CONFLICT','final':True,'controllerId':'82b3af51-d264-4920-9854-3496f6ae28c2','configurationRevision':0}).encode()
            state['publicStderr']=b''
            before={str(p):p.read_bytes() for p in root.rglob('*.json')}
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                result=stage.admit(root,CORRELATION,old,recovery,STAGE)
            self.assertEqual('unknown',result['state']);self.assertEqual('CONFLICT',result['publicFailure']['code'])
            self.assertFalse((root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json')).exists())
            self.assertEqual([],state['effects'])
            for name,content in before.items():self.assertEqual(content,Path(name).read_bytes(),name)

    def test_cleanup_rejects_valid_replacement_owner_after_immutable_fresh_admission(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            state['owner']='82b3af51-d264-4920-9854-3496f6ae28c2'
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                path=root/'.rag_index/android-endpoint-admission'/('recovered-stage-'+STAGE+'.json');before=path.read_bytes()
                state['owner']='83b3af51-d264-4920-9854-3496f6ae28c2'
                self.assertEqual('unknown',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
            self.assertEqual(before,path.read_bytes());self.assertEqual([],state['effects'])
            self.assertTrue((root/'android-native-device-api29.lease').exists())

    def test_unrooted_public_status_conflict_keeps_actual_phase_and_rejects_stale_owner(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();helper,intent,state,config,old,recovery,observe=self.fixture(root)
            original=(root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+recovery+'.json')).read_bytes()
            with mock.patch.object(endpoint.ssh_transport,'load_config',return_value=config),mock.patch.object(stage,'_remote',side_effect=self.remote(root,helper,state,observe)):
                self.assertEqual('ready',stage.admit(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('cleaned',stage.cleanup_once(root,CORRELATION,old,recovery,STAGE)['state'])
                self.assertEqual('2000',state['uid'])
                effects=list(state['effects'])
                state['failingPublicStatus']=True;state['publicExit']=1;state['publicStderr']=b''
                state['publicStdout']=json.dumps({'schemaVersion':1,'ok':False,'code':'CONFLICT','final':True,'controllerId':'9d2decb9-efdb-4148-b418-c948817e48e4','configurationRevision':0}).encode()
                for call in (stage.status,stage.collect):
                    result=call(root,CORRELATION,old,recovery,STAGE)
                    self.assertEqual('unknown',result['state']);self.assertEqual('CONFLICT',result['publicFailure']['code'])
                    self.assertEqual({'phase':'public-status','outcome':'nonzero','stderrClass':'none'},result['commandDiagnostic'])
            self.assertEqual(effects,state['effects']);self.assertEqual(original,(root/'.rag_index/android-endpoint-admission'/('mount-recovery-'+recovery+'.json')).read_bytes())
            import base64
            capture=json.loads((root/('android-endpoint-'+CORRELATION)/('recovered-stage-'+STAGE+'.command-failure.json')).read_bytes())
            self.assertEqual('public-status',capture['phase']);self.assertEqual(1,capture['returncode'])
            self.assertEqual(state['publicStdout'],base64.b64decode(capture['stdout']))
            argv=json.loads(base64.b64decode(capture['argv']));self.assertEqual('status',argv[-1])
            self.assertNotEqual('9d2decb9-efdb-4148-b418-c948817e48e4',argv[argv.index('--controller-id')+1])


class EmbeddedSourceBindingTest(unittest.TestCase):
    def test_unrelated_definition_does_not_invalidate_reviewed_generator(self):
        baseline=stage._remote_source()
        source=endpoint._REMOTE.replace("try:\n item=job.lstat()","def unrelated_observation_only():\n return 'unused'\ntry:\n item=job.lstat()",1)
        with mock.patch.object(endpoint, '_REMOTE', source):
            generated = stage._remote_source()
        self.assertEqual(baseline,generated)
        self.assertIn('def stage_dispatch()', generated)
        self.assertNotIn('def unrelated_observation_only', generated)

    def test_relevant_definition_drift_is_rejected_before_generation(self):
        source = endpoint._REMOTE.replace("def installed():", "def installed():\n raise ValueError('changed')", 1)
        with mock.patch.object(endpoint, '_REMOTE', source), self.assertRaises(ValueError):
            stage._remote_source()

    def test_required_rewrite_missing_or_duplicated_is_rejected(self):
        for value in ('absent', 'before before'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                stage._replace_once(value, 'before', 'after')

    def test_dynamic_global_lookup_or_duplicate_required_definition_is_rejected(self):
        for change in ("def installed():\n globals()['other']()", "def installed():\n pass\ndef installed():", "@unreviewed\ndef installed():"):
            source=endpoint._REMOTE.replace('def installed():',change,1)
            with self.subTest(change=change), self.assertRaises(ValueError):
                stage._dependency_parts(source)
