"""Isolation regressions for the current CP117 failed-download recovery."""
from __future__ import annotations

import unittest
from unittest import mock

from agent_tools import windows_update_fixture_download_abort as historical
from agent_tools import windows_update_fixture_download_abort_current as current


class CurrentDownloadAbortTests(unittest.TestCase):
    def test_current_binding_is_exact_and_does_not_mutate_history(self):
        self.assertEqual("07708dc7-6884-40a5-9a78-c75dbb391dbd", current._CORRELATION)
        self.assertEqual("af3360e5-a53b-4cd2-b91a-4c6abfd6b118", historical._CORRELATION)
        with self.assertRaises(ValueError): current.status(".", {"correlationId": historical._CORRELATION})

    def test_task_cleanup_and_abort_forward_only_the_fixed_request(self):
        request = {"correlationId": current._CORRELATION}
        with mock.patch.object(current._impl, "task_cleanup_status", return_value={"state":"diagnosed"}) as status, \
             mock.patch.object(current._impl, "task_cleanup", return_value={"state":"cleaned"}) as cleanup, \
             mock.patch.object(current._impl, "abort", return_value={"state":"retired"}) as abort:
            self.assertEqual("diagnosed", current.task_cleanup_status("/tmp", request)["state"])
            self.assertEqual("cleaned", current.task_cleanup("/tmp", request)["state"])
            self.assertEqual("retired", current.abort("/tmp", request)["state"])
        status.assert_called_once_with("/tmp", request)
        cleanup.assert_called_once_with("/tmp", request)
        abort.assert_called_once_with("/tmp", request)

    def test_response_loss_status_is_delegated_to_isolated_receipt_logic(self):
        request = {"correlationId": current._CORRELATION}
        receipt = {"state":"diagnosed", "phase":"cleaned", "replayAllowed":False,
                   "nativeActionAllowed":False, "productAction":False}
        with mock.patch.object(current._impl, "task_cleanup_status", return_value=receipt):
            self.assertEqual(receipt, current.workflow("/tmp", "task-cleanup-status", request))
        with self.assertRaises(ValueError): current.workflow("/tmp", "unknown", request)
