"""Only exact new Mac custody schema selects its source-qualified factory."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
from agent_tools import readiness_fixture_registry as registry


@unittest.skipUnless(os.name == 'posix', 'protected POSIX provider registration files')
class MacRegistryRoutingTests(unittest.TestCase):
    def test_only_exact_qualified_snapshot_kind_selects_original_mac_executor(self):
        with tempfile.TemporaryDirectory() as temporary:
            for kind,qualified,associated in (('qualified-tart-macos-guest-lease-v1',True,None),('qualified-tart-macos-guest-lease-v1',True,'read-only-original'),
                                              ('legacy',False,None),('legacy',False,'read-only-original'),(None,False,None)):
                snapshot={'provider':'tart-macos','kind':kind}
                # Provider-owned active-work association: None (no enrollment) keeps the ordinary original factory;
                # an association is returned as is and never reaches a legacy kind.
                with mock.patch('agent_tools.readiness_tart_macos_lease_executor.OriginalMacLeaseExecutor',return_value='original-mac') as new, \
                     mock.patch('agent_tools.readiness_tart_macos_active_work_original.executor_for_original',return_value=associated) as association, \
                     mock.patch('agent_tools.readiness_tart.lease_executor_from_snapshot',return_value='legacy',create=True) as old:
                    self.assertEqual(registry.lease_executor_from_snapshot(temporary,snapshot),(associated or'original-mac')if qualified else'legacy')
                    self.assertEqual(new.call_count,int(qualified and associated is None));self.assertEqual(old.call_count,int(not qualified))
                    self.assertEqual(association.call_args_list,[mock.call(temporary,snapshot)]*int(qualified))

    def test_exact_mac_schema3_routes_to_factory_and_legacy_providers_keep_their_route(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();directory=root/'.rag_index/readiness-fixtures'
            directory.mkdir(mode=0o700,parents=True)
            path=directory/'explicit-mac.json'
            for provider,schema,is_new in (('tart-macos',3,True),('tart-macos',3.0,False),
                                           ('tart-macos',2,False),('tart-linux',3,False)):
                descriptor={'provider':provider,'schemaVersion':schema};cap=time.monotonic()+60
                path.write_text(json.dumps(descriptor));path.chmod(0o600)
                _,pin=registry._json(path)
                with mock.patch('agent_tools.readiness_tart_macos_registry.load_registered_fixture',return_value='new-factory') as new, \
                     mock.patch('agent_tools.readiness_tart.load_registered_fixture',side_effect=ValueError('legacy-refusal')) as old:
                    if is_new:
                        self.assertEqual(registry.registered_fixture(root,'explicit-mac'),'new-factory')
                        new.assert_called_once_with(root,'explicit-mac',descriptor,pin,deadline=None);old.assert_not_called()
                        # An explicit caller cap reaches only the exact Mac factory, never a fresh default budget.
                        new.reset_mock();self.assertEqual(registry.registered_fixture(root,'explicit-mac',deadline=cap),'new-factory')
                        new.assert_called_once_with(root,'explicit-mac',descriptor,pin,deadline=cap);old.assert_not_called()
                    else:
                        with self.assertRaisesRegex(ValueError,'legacy-refusal'):registry.registered_fixture(root,'explicit-mac')
                        old.assert_called_once_with(root,'explicit-mac',descriptor,pin);new.assert_not_called()
                        old.reset_mock()
                        with self.assertRaisesRegex(ValueError,'legacy-refusal'):registry.registered_fixture(root,'explicit-mac',deadline=cap)
                        old.assert_called_once_with(root,'explicit-mac',descriptor,pin);new.assert_not_called()


if __name__=='__main__':unittest.main()
