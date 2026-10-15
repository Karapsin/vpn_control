"""Public and batch entry points cannot recreate the purged fixed fixtures."""
import hashlib,json,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as mcp, windows_vm_setup_policy as policy


class SetupPolicyTests(unittest.TestCase):
    def test_preserved_vm_only_policy_admits_old_profile_new_work_current_refuses(self):
        folder=Path(__file__).parent/'fixtures/historical_windows_profiles';raw=(folder/'before.source').read_bytes()
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('historical_policy_before');exec(compile(raw,str(folder/'before.source'),'exec'),before.__dict__)
        actions=('windows-msi-public-start','windows-msi-base-start','windows-msi-target-start',
                 'windows-fixture-server-start','windows-cp117-source-campaign-start',
                 'windows-vm-baseline-inventory','windows-vm-media-fingerprint')
        with mock.patch.object(mcp,'_vm_workflow_impl',side_effect=AssertionError('no old native dispatch')):
            for action in actions:
                with self.subTest(action=action):
                    self.assertIsNone(before.refusal(action))
                    result=mcp.vm_workflow(action,{})
                    self.assertEqual('historical_windows_profile_retired',result['reason'])
                    self.assertFalse(result['nativeActionAllowed']);self.assertFalse(result['replayAllowed'])
                    self.assertEqual(result,mcp._native_fixed_dispatch('vm',action,{}))

    def test_phase_multiplexers_and_transfer_start_cannot_bypass_public_or_batch_fence(self):
        with (mock.patch.object(mcp,'_vm_workflow_impl',side_effect=AssertionError('old native dispatch')),
              mock.patch.object(mcp,'_native_response',side_effect=AssertionError('evidence writes'))):
            for action,phases in policy.RETIRED_TRANSFER_PHASES.items():
                for phase in phases:
                    inputs={'phase':phase,'correlationId':'22222222-2222-4222-8222-222222222222'}
                    with self.subTest(action=action,phase=phase):
                        result=mcp.vm_workflow(action,inputs)
                        self.assertEqual('historical_windows_profile_retired',result['reason'])
                        self.assertEqual(result,mcp._native_fixed_dispatch('vm',action,inputs))
            result=mcp.vm_workflow('windows-msi-base-start-from-transfer',{})
            self.assertEqual('historical_windows_profile_retired',result['reason'])
        for action in policy.RETIRED_TRANSFER_PHASES:
            for phase in ('status','stage-status','collect','cleanup','listener-stop','guest-abort-status','prepare-diagnostic'):
                self.assertIsNone(policy.refusal(action,{'phase':phase}))

    def test_original_history_and_argument_driven_package_builds_remain_available(self):
        for action in ('windows-msi-public-status','windows-msi-public-collect',
                       'windows-cp117-e66-successor-diagnostic','windows-fixture-server-status',
                       'windows-fixture-credentials-failure-detail','windows-msi-base-reconcile',
                       'windows-msi-fixture-dispatch','windows-msi-fixture-status','windows-msi-fixture-failed-log',
                       'windows-vm-deploy-start','windows-vm-deploy-secure','windows-vm-deploy-frame',
                       'windows-input-start','windows-credential-probe-start','windows-credential-recover-start'):
            with self.subTest(action=action):self.assertIsNone(policy.refusal(action))

    def test_all_retired_constructors_refuse_before_dispatch_or_evidence_writes(self):
        with (mock.patch.object(mcp,'_vm_workflow_impl',side_effect=AssertionError('native dispatch')),
              mock.patch.object(mcp,'_native_response',side_effect=AssertionError('evidence mutation'))):
            for action in policy.RETIRED_SETUP_ACTIONS:
                with self.subTest(action=action):
                    result=mcp.vm_workflow(action,{})
                    self.assertEqual('historical_windows_vm_setup_retired',result['reason'])
                    self.assertFalse(result['nativeActionAllowed'])
                    self.assertEqual(result,mcp._native_fixed_dispatch('vm',action,{}))

    def test_original_observers_still_receive_the_original_identity(self):
        identity={'correlationId':'unresolved-original'}
        with (mock.patch.object(mcp,'_vm_workflow_impl',return_value={'state':'unknown'}) as native,
              mock.patch.object(mcp,'_native_response',side_effect=lambda _tool,_action,result,_inputs:result)):
            result=mcp.vm_workflow('windows-vm-fresh-status',identity)
        self.assertEqual('unknown',result['state'])
        native.assert_called_once_with('windows-vm-fresh-status',identity)

    def test_argument_driven_actions_are_never_replaced_with_historical_defaults(self):
        for action in ('windows-vm-deploy-preflight','windows-vm-deploy-resources',
                       'windows-vm-deploy-start','windows-vm-deploy-status'):
            self.assertIsNone(policy.refusal(action))

    def test_old_vnc_open_refuses_and_original_status_still_routes(self):
        with mock.patch.object(mcp,'_ssh_workflow_impl',side_effect=AssertionError('forward mutation')):
            result=mcp.ssh_workflow('forward-open',host='archlinux')
        self.assertEqual('historical_cp117_forward_open_retired',result['reason'])
        self.assertFalse(result['nativeActionAllowed'])
        with (mock.patch.object(mcp,'_ssh_workflow_impl',return_value={'state':'unknown'}) as native,
              mock.patch.object(mcp,'_native_response',side_effect=lambda _tool,_action,result,_inputs:result)):
            mcp.ssh_workflow('forward-status',host='archlinux')
        self.assertEqual('forward-status',native.call_args.args[0])


if __name__=='__main__':unittest.main()
