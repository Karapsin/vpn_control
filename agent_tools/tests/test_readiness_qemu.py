"""Provider identity fences and finite prelaunch proof boundaries."""
from pathlib import Path
import contextlib
import subprocess
import hashlib
import json
import tempfile
import sys
import types
import time
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools import readiness_qemu as subject


class QemuBackendTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.machine='0f559886-4ff5-4075-ad25-beb805173364'
        self.binding={'root':'/home/owner/vc-r-0f559886','machine':self.machine,'host':'archlinux','target':'qemu-linux:'+self.machine}
        self.backend=subject.QemuLinuxBackend(self.root,self.binding,{},capabilities={'resume'})
        self.observed=readiness.Observation(self.binding['target'],self.machine,connection='original',guest='paused')
        self.rid='a'*64;self.digest='b'*64
    def test_completed_original_body_is_validated_once_causal_red_green(self):
        folder=Path(__file__).with_name('fixtures')/'qemu_submitted_result_before';raw=(folder/'readiness_qemu.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('agent_tools._qemu_returned_body_before');old.__package__='agent_tools';old.__file__=str(folder/'readiness_qemu.py.before.source')
        sys.modules[old.__name__]=old;self.addCleanup(sys.modules.pop,old.__name__,None);exec(compile(raw,old.__file__,'exec'),old.__dict__)
        operation='2835df1e-fc0c-4483-b2c3-66e4893af5f3'
        for module,name in ((old,'before'),(subject,'after')):
            with self.subTest(source=name):
                root=self.root/name;root.mkdir(mode=0o700)
                result=subprocess.CompletedProcess(['original-target'],0,b'{"state":"submitted","action":"resume","recoveryId":"original"}',b'')
                changed=subject.transport.SubmittedResultReadinessChanged(readiness.ReadinessBlocked('connection_generation_changed',operation),result)
                admission=types.SimpleNamespace(revalidate=lambda:None,ready=object())
                with mock.patch.object(module,'_sources',return_value={}):
                    backend=module.QemuLinuxBackend(root,self.binding,{})
                    with mock.patch.object(module.packets,'program',return_value='print("fixed source")'),mock.patch.object(module.transport,'admitted_transport',return_value=contextlib.nullcontext(admission)),mock.patch.object(module.transport,'load_config',return_value=object()),mock.patch.object(module.transport,'build_ssh_argv',return_value=['fixed-ssh']),mock.patch.object(module.transport,'run_ssh',side_effect=changed) as dispatch:
                        if name=='before':
                            with self.assertRaises(subject.transport.SubmittedResultReadinessChanged):backend._run('resume',operation,time.monotonic()+30)
                        else:
                            value,_=backend._run('resume',operation,time.monotonic()+30)
                            self.assertEqual('submitted',value['state'])
                            with self.assertRaisesRegex(ValueError,'already_consumed'):changed.take_submitted_result()
                        dispatch.assert_called_once()

    def test_exact_native_no_launch_receipt_binds_core_attempt(self):
        error=readiness.ReadinessBlocked('connection_generation_changed','original-operation')
        with mock.patch.object(self.backend,'observe',side_effect=error):
            with self.assertRaises(readiness.RecoveryUnsubmitted) as captured:
                self.backend.recover_attempt('resume',self.rid,self.observed,time.monotonic()+30,1,self.digest)
        proof=captured.exception;path=self.root/'.runtime/readiness-qemu/unsubmitted'/self.rid/'1.json'
        body=json.loads(path.read_bytes())
        self.assertEqual({'schemaVersion':1,'recoveryId':self.rid,'attempt':1,'dispatchDigest':self.digest,
            'packetSha256':None,'mutationExecutableStarted':False,'popenCalled':False,'evidence':'admission_before_mutation_dispatch'},body)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),proof.proof_sha256)
    def test_native_readonly_capacity_failure_is_power_unsubmitted_causal_red_green(self):
        fixture=Path(__file__).with_name('fixtures')/'qemu_preparation_unsubmitted_before'
        raw=(fixture/'readiness_qemu.py.before.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._qemu_preparation_before')
        before.__file__=str(fixture/'readiness_qemu.py.before.source');before.__package__='agent_tools'
        sys.modules[before.__name__]=before;self.addCleanup(sys.modules.pop,before.__name__,None)
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        def exercise(module,suffix):
            root=self.root/suffix;root.mkdir(mode=0o700)
            credential=root/'credential';credential.write_text('INERT_TEST_INPUT');credential.chmod(0o600)
            with module.SecretFile(str(credential)) as private:binding={'path':str(credential),'generation':list(private.pin)}
            with mock.patch.object(module,'_sources',return_value={}):
                backend=module.QemuLinuxBackend(root,self.binding,{},capabilities={'start'},credential=binding)
                observed=readiness.Observation(self.binding['target'],self.machine,connection='original',guest='stopped')
                backend.last_facts={'owner':{'operationId':self.machine},'boot':None,'guest':'stopped'}
                with mock.patch.object(backend,'observe',return_value=observed),mock.patch.object(backend,'_run') as mutate, mock.patch.object(module.resources,'prepare_start',side_effect=ValueError('resource_response')):
                    try:backend.recover_attempt('start',self.rid,observed,time.monotonic()+30,1,self.digest)
                    except readiness.RecoveryUnsubmitted as proof:
                        body=json.loads((root/'.runtime/readiness-qemu/unsubmitted'/self.rid/'1.json').read_bytes())
                        self.assertEqual(self.digest,proof.dispatch_digest)
                        self.assertIsNone(body['packetSha256']);self.assertFalse(body['popenCalled'])
                        outcome='power-unsubmitted'
                    except ValueError:outcome='unknown'
                    else:outcome='unexpected-success'
                mutate.assert_not_called()
                return outcome
        # Same actual backend preparation path and failing capacity result. The
        # preserved whole caller demonstrably fails the required assertion.
        with self.assertRaises(AssertionError):self.assertEqual('power-unsubmitted',exercise(before,'before'))
        self.assertEqual('power-unsubmitted',exercise(subject,'after'))

    def test_unsubmitted_receipt_rejects_unqualified_or_malformed_dispatch(self):
        for action,rid,attempt,digest in [('start',self.rid,1,self.digest),('resume','../foreign',1,self.digest),('resume',self.rid,0,self.digest),('resume',self.rid,True,self.digest),('resume',self.rid,1,'not-a-digest')]:
            with self.subTest(action=action,rid=rid,attempt=attempt,digest=digest),mock.patch.object(self.backend,'_recover') as dispatch:
                with self.assertRaises(subject.QemuError):self.backend.recover_attempt(action,rid,self.observed,time.monotonic()+30,attempt,digest)
                dispatch.assert_not_called()
        self.assertFalse((self.root/'.runtime').exists())

    def test_lost_execution_ack_never_becomes_no_launch_proof(self):
        self.backend.last_facts={'owner':{},'boot':None,'guest':'paused'}
        def lost(*args,**kwargs):
            kwargs['dispatch_trace'].update(popenCalled=True,packetSha256='c'*64)
            raise subject.QemuTransportUnavailable('qemu_transport_unavailable')
        with mock.patch.object(self.backend,'observe',return_value=self.observed),mock.patch.object(self.backend,'_run',side_effect=lost):
            with self.assertRaises(subject.QemuTransportUnavailable):
                self.backend.recover_attempt('resume',self.rid,self.observed,time.monotonic()+30,1,self.digest)
        self.assertFalse((self.root/'.runtime/readiness-qemu/unsubmitted').exists())
    def test_shared_prelaunch_guard_refusal_retains_same_attempt_proof(self):
        self.backend.last_facts={'owner':{},'boot':None,'guest':'paused'}
        original=readiness.ReadinessBlocked('connection_generation_changed','original-operation')
        refusal=subject.transport.PrelaunchReadinessRefusal(original,'c'*64)
        def refused(*args,**kwargs):
            kwargs['dispatch_trace'].update(popenCalled=True,packetSha256='d'*64)
            raise refusal
        with mock.patch.object(self.backend,'observe',return_value=self.observed),mock.patch.object(self.backend,'_run',side_effect=refused):
            with self.assertRaises(readiness.RecoveryUnsubmitted) as captured:
                self.backend.recover_attempt('resume',self.rid,self.observed,time.monotonic()+30,2,self.digest)
        self.assertEqual(2,captured.exception.attempt)
        body=json.loads((self.root/'.runtime/readiness-qemu/unsubmitted'/self.rid/'2.json').read_bytes())
        self.assertEqual('d'*64,body['packetSha256']);self.assertFalse(body['mutationExecutableStarted'])

    def test_completed_source_stage_retains_identity_without_claiming_no_transfer(self):
        self.backend.last_facts={'owner':{},'boot':None,'guest':'paused'}
        original=readiness.ReadinessBlocked('connection_generation_changed','original-operation')
        refusal=subject.transport.StagedExecutionUnsubmitted(original,'c'*64,'d'*32,'e'*64)
        def refused(*args,**kwargs):
            kwargs['dispatch_trace'].update(popenCalled=True,packetSha256='f'*64)
            raise refusal
        with mock.patch.object(self.backend,'observe',return_value=self.observed),mock.patch.object(self.backend,'_run',side_effect=refused):
            with self.assertRaises(readiness.RecoveryUnsubmitted):
                self.backend.recover_attempt('resume',self.rid,self.observed,time.monotonic()+30,1,self.digest)
        carrier=json.loads((self.root/'.runtime/readiness-qemu/unsubmitted-carrier'/self.rid/'1.json').read_bytes())
        self.assertTrue(carrier['transferSubmitted']);self.assertFalse(carrier['targetExecutableStarted'])
        self.assertEqual('e'*64,carrier['stageReceiptSha256']);self.assertEqual('d'*32,carrier['correlationId'])
        proof=json.loads((self.root/'.runtime/readiness-qemu/unsubmitted'/self.rid/'1.json').read_bytes())
        self.assertEqual('f'*64,proof['packetSha256']);self.assertFalse(proof['mutationExecutableStarted'])

    def test_stale_identity_is_proven_unsubmitted_and_dispatch_absent(self):
        changed=readiness.Observation(self.binding['target'],self.machine,connection='new',guest='paused')
        with mock.patch.object(self.backend,'observe',return_value=changed),mock.patch.object(self.backend,'_run') as dispatch:
            with self.assertRaises(readiness.RecoveryUnsubmitted):
                self.backend.recover_attempt('resume',self.rid,self.observed,time.monotonic()+30,1,self.digest)
        dispatch.assert_not_called()
    def test_remote_qmp_path_cannot_authorize_local_unix_dispatch(self):
        with self.assertRaises(readiness.AdapterBlocked):self.backend.dispatch_binding('qmp')
    def test_lost_start_ack_reconciles_only_original_actor_once_outside_observer(self):
        from uuid import UUID,uuid5
        from agent_tools.private_credential_file import SecretFile
        credential=self.root/'credential';credential.write_text('INERT_TEST_INPUT');credential.chmod(0o600)
        with SecretFile(str(credential)) as secret:self.backend.credential={'path':str(credential),'generation':list(secret.pin)}
        operation=str(uuid5(UUID(self.machine),self.rid))
        directory=subject._private_directory(self.root/'.rag_index/readiness-resources'/operation)
        self.backend.last_facts={'owner':{'operationId':self.rid,'pid':17,'startTicks':777,'hostBootId':'actual-host-boot'}}
        observed=readiness.Observation(self.binding['target'],self.machine,connection='original',boot='actual-boot',account='uid:1000:recovery')
        ready=readiness.ReadyContext('original-operation',observed.target,observed.machine,observed.connection,observed.boot,observed.account,None,readiness.Requirements({'guest_agent'}))
        def retain(actor):
            self.assertEqual({'pid':17,'startTicks':777},actor)
            with readiness.RecoveryJournal(directory).locked(deadline=time.monotonic()+30) as journal:
                journal.record('running',{'actor':actor,'hostBootId':'actual-host-boot','operationId':operation})
        with mock.patch.object(self.backend,'observe',return_value=observed),mock.patch.object(subject.resources.ResourceAdmission,'running_binding',return_value=True),mock.patch.object(subject.resources.ResourceAdmission,'mark_running',side_effect=retain) as running:
            self.assertTrue(self.backend.reconcile_ready(ready,time.monotonic()+30)['resourceAction'])
            self.assertFalse(self.backend.reconcile_ready(ready,time.monotonic()+30)['resourceAction'])
            running.assert_called_once_with({'pid':17,'startTicks':777})

    def test_bound_resource_noop_uses_exact_actual_context_causal_red_green(self):
        from uuid import UUID,uuid5
        folder=Path(__file__).with_name('fixtures')/'qemu_bookkeeping_observation_before'
        raw=(folder/'readiness_qemu.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._qemu_bookkeeping_before');before.__package__='agent_tools'
        before.__file__=str(folder/'readiness_qemu.py.before.source');sys.modules[before.__name__]=before
        self.addCleanup(sys.modules.pop,before.__name__,None);exec(compile(raw,before.__file__,'exec'),before.__dict__)
        observed=readiness.Observation(self.binding['target'],self.machine,connection='actual-connection',boot='actual-boot',account='uid:1000:recovery',guest='running',guest_agent=True)
        ready=readiness.ReadyContext('original-operation',observed.target,observed.machine,observed.connection,observed.boot,observed.account,None,readiness.Requirements({'guest_agent'}))
        facts={'owner':{'operationId':self.rid,'pid':17,'startTicks':777,'hostBootId':'actual-host-boot'}}
        for module,name in ((before,'before'),(subject,'after')):
            root=self.root/name;root.mkdir(mode=0o700)
            operation=str(uuid5(UUID(self.machine),self.rid));directory=subject._private_directory(root/'.rag_index/readiness-resources'/operation)
            with readiness.RecoveryJournal(directory).locked(deadline=time.monotonic()+30) as journal:journal.record('running',{'actor':{'pid':17,'startTicks':777},'hostBootId':'actual-host-boot'})
            with mock.patch.object(module,'_sources',return_value={}):
                backend=module.QemuLinuxBackend(root,self.binding,{});backend.last_facts=facts;backend._last_actual=(observed,facts)
                with mock.patch.object(subject.resources.ResourceAdmission,'running_binding',return_value=True),mock.patch.object(backend,'observe',side_effect=TimeoutError('full-observation-exceeds-normal-budget')) as extra:
                    if module is before:
                        with self.assertRaises(TimeoutError):backend.reconcile_ready(ready,time.monotonic()+30)
                        extra.assert_called_once()
                    else:
                        self.assertFalse(backend.reconcile_ready(ready,time.monotonic()+30)['resourceAction']);extra.assert_not_called()
                        changed=readiness.ReadyContext('original-operation',observed.target,observed.machine,observed.connection,'different-boot',observed.account,None,ready.requirements)
                        with self.assertRaisesRegex(subject.QemuError,'context_stale'):backend.reconcile_ready(changed,time.monotonic()+30)
                        extra.assert_not_called()

    def test_running_receipt_before_inventory_commit_reconciles_same_actor_causal_red_green(self):
        from uuid import UUID,uuid5
        from agent_tools.private_credential_file import SecretFile
        from agent_tools.tests.test_readiness_resources import ResourceTests,BOOT
        folder=Path(__file__).with_name('fixtures')/'qemu_running_cache_halfcommit_before';raw=(folder/'readiness_qemu.py.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._qemu_running_cache_before');before.__package__='agent_tools';before.__file__=str(folder/'readiness_qemu.py.source')
        sys.modules[before.__name__]=before;self.addCleanup(sys.modules.pop,before.__name__,None);exec(compile(raw,before.__file__,'exec'),before.__dict__)
        for module,old in ((before,True),(subject,False)):
            fixture=ResourceTests('runTest');fixture.setUp()
            try:
                fixture.operation=str(uuid5(UUID(fixture.machine),self.rid))
                binding={'host':'archlinux','root':'/home/owner/vc-r-'+fixture.machine[:8],'machine':fixture.machine,'target':'qemu-linux:'+fixture.machine}
                claim=subject.resources.prepare_start(fixture.root,host='archlinux',machine_uuid=fixture.machine,fixture_root=binding['root'],credential_file='/INERT',operation_id=fixture.operation)
                claim.mark_submitting();fixture.running()
                # Actual durable journal write, followed by the original
                # interrupted inventory commit; no VM mutation is simulated.
                with mock.patch.object(subject.resources.environments,'reserve_environment',side_effect=TimeoutError('controlled_client_loss')):
                    with self.assertRaises(TimeoutError):claim.mark_running(fixture.actor())
                credential=fixture.root/'credential';credential.write_text('INERT_TEST_INPUT');credential.chmod(0o600)
                with SecretFile(str(credential))as secret:private={'path':str(credential),'generation':list(secret.pin)}
                observed=readiness.Observation(binding['target'],fixture.machine,connection='original',guest='running',guest_agent=True,boot='actual-boot',account='uid:1000:recovery')
                facts={'owner':{'operationId':self.rid,'pid':17,'startTicks':777,'hostBootId':BOOT}}
                with mock.patch.object(module,'_sources',return_value={}):
                    backend=module.QemuLinuxBackend(fixture.root,binding,{},credential=private);backend._last_actual=(observed,facts)
                    ready=readiness.ReadyContext('original-operation',observed.target,observed.machine,observed.connection,observed.boot,observed.account,None,readiness.Requirements({'guest_agent'}))
                    with mock.patch.object(backend,'observe',side_effect=AssertionError('must reuse the exact actual context')):
                        result=backend.reconcile_ready(ready,time.monotonic()+30)
                        with subject.resources.environments._LockedState(fixture.root)as locked:row=dict(locked.state['reservations'][0])
                        if old:
                            self.assertFalse(result['resourceAction'])
                            with self.assertRaises(AssertionError):self.assertEqual(('running','active'),(row['allocationState'],row['activeJob']))
                        else:
                            self.assertTrue(result['resourceAction']);self.assertEqual(('running','active'),(row['allocationState'],row['activeJob']))
                            count=len(fixture.calls);self.assertFalse(backend.reconcile_ready(ready,time.monotonic()+30)['resourceAction']);self.assertEqual(count,len(fixture.calls))
            finally:fixture.doCleanups()

    def test_background_status_does_not_require_unused_host_sudo_credential(self):
        credential={'path':str(self.root/'.runtime/missing-host-input'),'generation':[0]*9}
        backend=subject.QemuLinuxBackend(self.root,self.binding,{},capabilities={'start'},credential=credential)
        facts={'guest':'running','boot':'actual-boot','account':'uid:1000:recovery','session':None,'guestAgent':True,
            'idleVisibility':[],'idleBlockers':[],'owner':{'pid':17,'startTicks':777},'qmpInode':71,'guestMachineId':'a'*32}
        with mock.patch.object(backend,'_run',return_value=({'state':'observed','pins':{},'facts':facts},mock.Mock(connection='actual-ssh'))):
            self.assertEqual('running',backend.observe(readiness.Requirements({'guest_agent'},{'start'}),time.monotonic()+30).guest)
            facts.update(guest='stopped',boot=None,account=None,guestAgent=False)
            with self.assertRaises(readiness.AdapterBlocked) as captured:
                backend.observe(readiness.Requirements({'guest_agent'},{'start'}),time.monotonic()+30)
            self.assertEqual('credential_unavailable',captured.exception.reason)
            self.assertEqual('stopped',backend.observe(readiness.Requirements({'transport'}),time.monotonic()+30).guest)

    def test_internal_guest_bridge_accepts_only_fixed_canonical_program(self):
        self.backend.last_facts={'guestMachineId':'a'*32}
        source=subject.guest_jobs.enroll_program(self.binding['target'],self.machine,1000,actual_machine_id='a'*32)
        self.assertEqual('enroll',self.backend._guest_source(source)['mode'])
        with self.assertRaisesRegex(subject.QemuError,'guest_source_changed'):
            self.backend._guest_source(source+'\nprint("untrusted mutation")\n')
        other=subject.guest_jobs.enroll_program('foreign-target',self.machine,1000,actual_machine_id='a'*32)
        with self.assertRaisesRegex(subject.QemuError,'guest_source_changed'):
            self.backend._guest_source(other)

    def test_namespace_key_order_roundtrip_causal_red_green_and_source_fences(self):
        namespace={'schemaVersion':1,'root':'/var/tmp/vc-recovery-jobs','generation':[1,2],'admissionGeneration':[1,3],
            'target':self.binding['target'],'machine':self.machine,'actualMachineId':'a'*32,'account':'1000',
            'ownerSourceSha256':hashlib.sha256(subject.durable_jobs.owner_source()).hexdigest()}
        sorted_namespace=json.loads(json.dumps(namespace,sort_keys=True))
        source=subject.guest_jobs.observe_program(namespace)
        folder=Path(__file__).with_name('fixtures')/'qemu_guest_parameter_order_before'
        raw=(folder/'readiness_qemu.py.before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._qemu_parameter_order_before');before.__package__='agent_tools'
        before.__file__=str(folder/'readiness_qemu.py.before.source');sys.modules[before.__name__]=before
        self.addCleanup(sys.modules.pop,before.__name__,None);exec(compile(raw,before.__file__,'exec'),before.__dict__)
        with mock.patch.object(before,'_sources',return_value={}):
            old=before.QemuLinuxBackend(self.root,self.binding,{})
            with mock.patch.object(old,'load_guest_namespace',return_value=sorted_namespace):
                with self.assertRaisesRegex(before.QemuError,'source_changed'):old._guest_source(source)
        with mock.patch.object(self.backend,'load_guest_namespace',return_value=sorted_namespace):
            self.assertEqual('inventory',self.backend._guest_source(source)['mode'])
            header,_,remainder=source.partition('\n')
            forbidden=[header+';print("injected")\n'+remainder,
                header.replace("{'schemaVersion':", "{'schemaVersion':1,'schemaVersion':",1)+'\n'+remainder,
                header.replace("'schemaVersion': 1", "'schemaVersion': True",1)+'\n'+remainder,
                header.replace("'generation': [1, 2]", "'generation': (1, 2)",1)+'\n'+remainder,
                source+'\nprint("injected")\n']
            for changed in forbidden:
                self.assertNotEqual(source,changed)
                with self.assertRaises(subject.QemuError):self.backend._guest_source(changed)

    def test_wrong_guest_account_and_changed_machine_have_precise_blockers(self):
        for reason,expected in [('guest_account','wrong_account'),('machine_identity','machine_identity_mismatch'),('fixture_changed','integrity_mismatch')]:
            with self.subTest(reason=reason),mock.patch.object(self.backend,'_run',return_value=({'state':'blocked','reason':reason},None)):
                with self.assertRaises(readiness.AdapterBlocked) as captured:
                    self.backend.observe(readiness.Requirements({'guest_agent'}),time.monotonic()+30)
                self.assertEqual(expected,captured.exception.reason)

    def test_headless_policy_and_healthy_observe_never_mutate(self):
        facts={'guest':'running','boot':'actual-boot','account':'uid:1000:recovery','session':None,'guestAgent':True,
            'idleVisibility':[],'idleBlockers':[],'owner':{'pid':17,'startTicks':777},'qmpInode':71,'guestMachineId':'a'*32}
        with mock.patch.object(self.backend,'_run',return_value=({'state':'observed','pins':{},'facts':facts},mock.Mock(connection='actual-ssh'))),mock.patch.object(subject.resources,'prepare_start') as reserve:
            value=self.backend.observe(readiness.Requirements({'guest_agent'}),time.monotonic()+30)
        self.assertIsNone(value.session);self.assertEqual('unknown',value.display);self.assertEqual('actual-boot',value.boot)
        reserve.assert_not_called()


if __name__=='__main__':unittest.main()
