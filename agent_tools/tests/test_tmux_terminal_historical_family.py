"""Actual original three source-chain setup failures and immutable fixtures."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools.tests import ssh_tmux_terminal_historical_fixture as family


class HistoricalFamilyTests(unittest.TestCase):
    def test_complete_original_three_failures_red_then_archive_contexts_green(self):
        sources=(('test_ssh_tmux_bounded_pipe_collection.py','BoundedPipeCollectionTest','test_actual_current_adapter_and_resource_source_chain_never_dispatches','adapter_source_changed'),
                 ('test_ssh_tmux_closure_census_diagnostic.py','DiagnosticTests','test_current_diagnostic_pin_chain_and_changed_bytes_refuse','privileged_source_changed'),
                 ('test_ssh_tmux_privileged_terminal_claim_bridge.py','BridgeActualDurableFlowTests','test_real_bridge_source_pin_drift_refuses_before_fence','privileged_source_changed'))
        records=json.loads((family.BASE/'provenance.json').read_bytes())['beforeTests']
        with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('No original/native dispatch')):
            for name,cls,method,reason in sources:
                raw=(family.BASE/(name+'.before.source')).read_bytes()
                self.assertEqual(records[name],hashlib.sha256(raw).hexdigest())
                module=types.ModuleType('agent_tools._original_chain_'+name.replace('.','_'))
                # The original factory used __file__ solely to locate this
                # checkout. Keep that declared route while compiling its exact
                # unchanged preserved whole source bytes.
                module.__file__=str(Path(__file__).with_name(name));module.__package__='agent_tools'
                with mock.patch.dict(sys.modules,{module.__name__:module}):
                    exec(compile(raw,module.__file__,'exec'),module.__dict__)
                    result=unittest.TestResult();getattr(module,cls)(method).run(result)
                self.assertEqual(1,len(result.errors),(name,result.errors));self.assertEqual([],result.failures)
                self.assertIn(reason,result.errors[0][1])
            from agent_tools.tests import test_ssh_tmux_bounded_pipe_collection as bounded
            from agent_tools.tests import test_ssh_tmux_closure_census_diagnostic as diagnostic
            from agent_tools.tests import test_ssh_tmux_privileged_terminal_claim_bridge as bridge
            for module,(_name,cls,method,_reason)in zip((bounded,diagnostic,bridge),sources):
                result=unittest.TestResult();getattr(module,cls)(method).run(result)
                self.assertTrue(result.wasSuccessful(),(result.errors,result.failures))

    def test_authentic_family_rejects_changed_archive_before_any_effect(self):
        with tempfile.TemporaryDirectory()as tmp:
            target=Path(tmp)
            for path in family.BASE.iterdir():shutil.copyfile(path,target/path.name)
            path=target/'ssh_tmux_mcp_adapter.py.source';path.write_bytes(path.read_bytes()+b'\n# changed\n')
            with mock.patch.object(family,'BASE',target),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('No native dispatch')):
                with self.assertRaisesRegex(ValueError,'historical_source_changed'):
                    with family.archived_family():self.fail('changed historical bytes loaded')


if __name__=='__main__':unittest.main()
