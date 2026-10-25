"""Same-content original artifact replacement must invalidate private custody."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest
from uuid import UUID,uuid5

from agent_tools import readiness_windows_host_jobs as current
from agent_tools import durable_remote_job as jobs
from agent_tools.tests import test_windows_host_jobs as owner_tests

FIXTURE=Path(__file__).parent/'fixtures/windows_host_local_custody'


def subject():
    if os.environ.get('VPN_CONTROL_HOST_LOCAL_CUSTODY_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._host_local_custody_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


def replace_same(path):
    raw=path.read_bytes();other=path.with_suffix(path.suffix+'.replacement');other.write_bytes(raw);other.chmod(0o600);os.replace(other,path)


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary source-owned original journals required')
class LocalCustodyTests(unittest.TestCase):
    def test_original_and_namespace_equal_bytes_replaced_inode_causal(self):
        module=subject()
        for artifact in ('original.json','program.source','owner.source','namespace-original.json','namespace-owner.source','namespace-enroll.source'):
            with self.subTest(artifact=artifact):
                fixture=owner_tests.WindowsHostOwnerTests('runTest');fixture.setUp()
                try:
                    if module is not current:fixture.namespace={k:v for k,v in fixture.namespace.items()if k!='intentGeneration'}
                    if artifact.startswith('namespace-'):
                        handle=module.retain_namespace(fixture.root,fixture.bound,fixture.lineage,{'namespace':fixture.namespace})
                        directory=module._NAMESPACES[handle][0];getter=handle.as_dict
                    else:
                        handle=module.retain(fixture.root,fixture.namespace,fixture.operation,fixture.rid,jobs.Program('windows-persisted-raw-start',b'print("public original source")\n'))
                        directory=module._ORIGINALS[handle][0];getter=lambda:module.operation_program(handle)
                    getter();replace_same(directory/artifact)
                    with self.assertRaises(ValueError):getter()
                finally:fixture.doCleanups()

    def test_missing_manifest_never_adopts_old_record_and_live_manifest_is_pinned(self):
        for namespace in (False,True):
            fixture=owner_tests.WindowsHostOwnerTests('runTest');fixture.setUp()
            try:
                if namespace:
                    handle=current.retain_namespace(fixture.root,fixture.bound,fixture.lineage,{'namespace':fixture.namespace})
                    directory=current._NAMESPACES[handle][0];name='namespace-custody.json';getter=handle.as_dict
                    reopen=lambda:current.load_namespace(fixture.root,fixture.bound)
                else:
                    handle=current.retain(fixture.root,fixture.namespace,fixture.operation,fixture.rid,jobs.Program('windows-persisted-raw-start',b'pass\n'))
                    directory=current._ORIGINALS[handle][0];name='custody.json';getter=handle.as_dict
                    binding=fixture.namespace['binding'];reopen=lambda:current.reopen(fixture.root,binding['target'],binding['machine'],fixture.operation)
                replace_same(directory/name)
                with self.assertRaises(ValueError):getter()
                # A fresh process may validate the original immutable artifact
                # manifest, but may never invent one when it is absent.
                reopen();(directory/name).unlink()
                with self.assertRaises(Exception):reopen()
            finally:fixture.doCleanups()


if __name__=='__main__':unittest.main()
