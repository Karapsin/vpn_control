"""Actual fresh-driver inheritance preserves mutation/readonly admission modes."""
from unittest.mock import patch
import unittest
from agent_tools import ssh_tmux_source_staging_recovery as recovery
from agent_tools import ssh_tmux_session_ssh as old

class EngineeringSnapshotTest(unittest.TestCase):
    def test_actual_current_inherited_snapshot_forwards_admission_and_keeps_none_legacy_call(self):
        driver=object.__new__(recovery.CurrentExactFetchDriver);driver.engineering_context=object()
        for admission in (True,False):
            with self.subTest(admission=admission),patch.object(old.TmuxArchDriver,'_snapshot',return_value={'adapterSource':{'sha256':recovery.CURRENT_ADAPTER_SHA}}) as snapshot:
                value=driver._snapshot({'original':'request'},admission=admission)
                snapshot.assert_called_once_with(driver,{'original':'request'},admission=admission)
                self.assertIn('stagingCompanionSource',value);self.assertIn('stageProgramSha256',value)
        driver.engineering_context=None
        with patch.object(old.TmuxArchDriver,'_snapshot',return_value={'adapterSource':{'sha256':recovery.CURRENT_ADAPTER_SHA}}) as snapshot:
            driver._snapshot({'original':'request'})
            snapshot.assert_called_once_with(driver,{'original':'request'})
