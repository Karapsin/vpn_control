from pathlib import Path
import os
import stat
import tempfile
import hashlib
import json
from unittest import TestCase, mock

from agent_tools import windows_msi_owner_public_status as first
from agent_tools import windows_msi_owner_public_status_retry as retry


D = ('windows-cp117', '/qga', 1, 2, 'S-1-5-21-1-2-3-1002')


class RetryTests(TestCase):
    def admitted(self):
        return object(), D, 'a' * 64, {'socketPath': '/qga', 'qemuPid': 1, 'startTicks': 2}, 'e' * 64

    def test_fixed_builder_allows_only_two_names_and_retry_uses_account_form(self):
        with self.assertRaises(first.WindowsMsiOwnerPublicStatusError):
            first._remote_for('arbitrary')
        compile(first._remote_for(first._TASK), '<original-public-status-remote>', 'exec')
        compile(first._remote_for(first._RETRY_TASK), '<retry-public-status-remote>', 'exec')
        remote = first._remote_for(first._RETRY_TASK)
        self.assertIn(r"VPNMSIX64\\vpncp117", remote)
        self.assertIn('SID_MISMATCH', remote)
        self.assertIn("New-ScheduledTaskPrincipal -UserId $account", remote)
        for required in ("Get-Service -Name Schedule", "VpnControlCp117OwnerPublicStatusC32",
                         "Name='explorer.exe'", "$x.SessionId -eq 1", "PRIOR_TASK"):
            self.assertIn(required, remote)
        self.assertLess(remote.index("Get-Service -Name Schedule"),
                        remote.index('Register-ScheduledTask'))
        self.assertIn("throw 'PRIOR_TASK'", remote)

    def test_preflight_is_read_only_and_proves_fixed_scheduler_account_session_and_task_facts(self):
        ps = retry._PREFLIGHT
        for required in ("Get-Service -Name Schedule", r"VPNMSIX64\vpncp117",
                         "Translate([Security.Principal.SecurityIdentifier])", "Name='explorer.exe'",
                         "$p.SessionId -eq 1", "VpnControlCp117OwnerPublicStatusC32",
                         "VpnControlCp117OwnerPublicStatusRetryC32", "Get-ScheduledTask"):
            self.assertIn(required, ps)
        self.assertNotIn('Register-ScheduledTask', ps)
        self.assertNotIn('Start-ScheduledTask', ps)

    def test_absent_original_is_required_and_intent_precedes_no_replay_submit(self):
        old = {'state': 'diagnosed', 'phase': 'task', 'task': 'absent', 'replayAllowed': False,
               'nativeActionAllowed': False}
        with tempfile.TemporaryDirectory() as t, \
                mock.patch.object(first, '_admit', return_value=self.admitted()), \
                mock.patch.object(first, 'diagnose', return_value=old), \
                mock.patch.object(retry, '_preflight', return_value={'state': 'ready', 'gate': 'ready'}), \
                mock.patch.object(first, '_run_named', return_value='unknown') as run:
            root = Path(t)
            self.assertEqual(retry.start(root, {'host': 'archlinux'}), retry._UNKNOWN)
            self.assertEqual(retry._read(root)['state'], 'intent')
            self.assertEqual(retry.start(root, {'host': 'archlinux'}), retry._UNKNOWN)
            self.assertEqual([call.args[-2] for call in run.call_args_list], ['start', 'status'])

    def test_preflight_mismatch_or_unknown_denies_before_durable_intent_or_task_submit(self):
        old = {'state': 'diagnosed', 'phase': 'task', 'task': 'absent', 'replayAllowed': False,
               'nativeActionAllowed': False}
        for preflight in ({'state': 'blocked', 'gate': 'account'}, None):
            with self.subTest(preflight=preflight), tempfile.TemporaryDirectory() as t, \
                    mock.patch.object(first, '_admit', return_value=self.admitted()), \
                    mock.patch.object(first, 'diagnose', return_value=old), \
                    mock.patch.object(retry, '_preflight', return_value=preflight), \
                    mock.patch.object(first, '_run_named') as run:
                root = Path(t)
                self.assertEqual(retry.start(root, {'host': 'archlinux'}), retry._UNKNOWN)
                self.assertIsNone(retry._read(root))
                run.assert_not_called()

    def test_write_fsyncs_parent_directory_before_any_submit(self):
        value = {'version': 1, 'correlationId': retry._CORRELATION, 'sourceSha': first.relaunch._SOURCE,
                 'guestGeneration': {'socketPath': '/qga', 'qemuPid': 1, 'startTicks': 2},
                 'evidenceSha256': 'e' * 64, 'state': 'intent'}
        seen = []
        actual = os.fsync
        def record(fd):
            seen.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            actual(fd)
        with tempfile.TemporaryDirectory() as t, mock.patch.object(retry.os, 'fsync', side_effect=record):
            retry._write(Path(t), value)
        self.assertIn(True, seen)

    def test_public_preflight_reports_only_finite_result_and_start_rechecks_it(self):
        old = {'state': 'diagnosed', 'phase': 'task', 'task': 'absent', 'replayAllowed': False,
               'nativeActionAllowed': False}
        with tempfile.TemporaryDirectory() as t, \
                mock.patch.object(first, '_admit', return_value=self.admitted()), \
                mock.patch.object(first, 'diagnose', return_value=old), \
                mock.patch.object(retry, '_preflight', return_value={'state': 'blocked', 'gate': 'scheduler'}):
            self.assertEqual(retry.workflow(Path(t), 'preflight', {'host': 'archlinux'}),
                             {'state': 'blocked', 'gate': 'scheduler', 'replayAllowed': False,
                              'nativeActionAllowed': False})

    def test_diagnose_reads_only_retry_task_and_reports_exact_action_mismatch(self):
        old = {'state': 'diagnosed', 'phase': 'task', 'task': 'absent', 'replayAllowed': False,
               'nativeActionAllowed': False}
        value = {'version': 1, 'correlationId': retry._CORRELATION, 'sourceSha': first.relaunch._SOURCE,
                 'guestGeneration': {'socketPath': '/qga', 'qemuPid': 1, 'startTicks': 2},
                 'evidenceSha256': 'e' * 64, 'state': 'intent'}
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            retry._write(root, value)
            admitted = self.admitted()
            with mock.patch.object(first, '_admit', return_value=admitted), \
                    mock.patch.object(first, 'diagnose', return_value=old), \
                    mock.patch.object(first, '_diagnostic_named',
                                      return_value={'phase': 'task', 'task': 'action-mismatch'}) as diagnostic, \
                    mock.patch.object(first, '_run_named') as submit:
                self.assertEqual(retry.diagnose(root, {'host': 'archlinux'}),
                                 {'state': 'diagnosed', 'phase': 'task', 'task': 'action-mismatch',
                                  'replayAllowed': False, 'nativeActionAllowed': False})
                diagnostic.assert_called_once_with(admitted[0], D, 'a' * 64, first._RETRY_TASK)
                submit.assert_not_called()

    def test_retry_diagnostic_binds_intent_generation_but_not_live_owner_admission(self):
        gen = {'socketPath': '/qga', 'qemuPid': 1, 'startTicks': 2}
        evidence = hashlib.sha256(json.dumps(gen, sort_keys=True).encode()).hexdigest()
        value = {'version': 1, 'correlationId': retry._CORRELATION, 'sourceSha': first.relaunch._SOURCE,
                 'guestGeneration': gen, 'evidenceSha256': evidence, 'state': 'intent'}
        launch = {'state': 'launched', 'sourceSha': first.relaunch._SOURCE,
                  'guestGeneration': gen, 'staleRecoveryEvidenceSha256': evidence}
        bound = (object(), D, first.relaunch._SOURCE, 'a' * 64)
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            retry._write(root, value)
            with mock.patch.object(first.relaunch.liveness, '_admit', return_value=bound), \
                    mock.patch.object(first.relaunch, '_read_intent', return_value=launch), \
                    mock.patch.object(first, '_admit', side_effect=AssertionError('live owner admission used')), \
                    mock.patch.object(first, '_diagnostic_named',
                                      return_value={'phase': 'task', 'task': 'absent'}) as diagnostic:
                self.assertEqual(retry.workflow(root, 'retry-diagnostic', {'host': 'archlinux'}),
                                 {'state': 'diagnosed', 'stage': 'task-observer', 'phase': 'task',
                                  'task': 'absent', 'replayAllowed': False, 'nativeActionAllowed': False})
                diagnostic.assert_called_once_with(bound[0], D, 'a' * 64, first._RETRY_TASK)

    def test_retry_diagnostic_classifies_binding_failure_without_task_observer(self):
        with tempfile.TemporaryDirectory() as t, \
                mock.patch.object(first.relaunch.liveness, '_admit', return_value=None), \
                mock.patch.object(first, '_diagnostic_named') as diagnostic:
            self.assertEqual(retry.retry_diagnostic(Path(t), {'host': 'archlinux'}),
                             {'state': 'blocked', 'stage': 'retry-intent', 'replayAllowed': False,
                              'nativeActionAllowed': False})
            diagnostic.assert_not_called()

    def test_retry_diagnostic_separates_base_binding_from_task_observer(self):
        value = {'version': 1, 'correlationId': retry._CORRELATION, 'sourceSha': first.relaunch._SOURCE,
                 'guestGeneration': {'socketPath': '/qga', 'qemuPid': 1, 'startTicks': 2},
                 'evidenceSha256': 'e' * 64, 'state': 'intent'}
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            retry._write(root, value)
            with mock.patch.object(first.relaunch.liveness, '_admit', return_value=None), \
                    mock.patch.object(first, '_diagnostic_named') as diagnostic:
                self.assertEqual(retry.retry_diagnostic(root, {'host': 'archlinux'}),
                                 {'state': 'blocked', 'stage': 'base-binding', 'replayAllowed': False,
                                  'nativeActionAllowed': False})
                diagnostic.assert_not_called()

    def test_unknown_or_wrong_original_diagnostic_denies_retry(self):
        with tempfile.TemporaryDirectory() as t, \
                mock.patch.object(first, '_admit', return_value=self.admitted()), \
                mock.patch.object(first, 'diagnose', return_value=first._UNKNOWN):
            self.assertEqual(retry.start(Path(t), {'host': 'archlinux'}), retry._UNKNOWN)
