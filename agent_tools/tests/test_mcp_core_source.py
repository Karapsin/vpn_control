"""Physical core-policy imports bypass cached modules and valid old pyc bytes."""
import hashlib
import importlib
import json
import os
import py_compile
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import mcp_server as server


class CoreSourceTests(unittest.TestCase):
    def test_actual_before_imports_reuse_cache_and_pyc_but_capture_reads_new_bytes(self):
        fixtures=Path(__file__).parent/'fixtures/source_loader_lifetime'
        before=(fixtures/'core_imports.before.source').read_bytes()
        provenance=json.loads((fixtures/'core_imports.provenance.json').read_bytes())
        self.assertEqual(provenance['fragmentSha256'],hashlib.sha256(before).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);package='_core_source_physical_fixture'
            parent=types.ModuleType(package);parent.__path__=[str(root)]
            names=('docs_assistant','local_build_environment','managed_check_lease','check_output_retention')
            for name in names:(root/(name+'.py')).write_text("VALUE='OLDER'\n")
            path=root/'docs_assistant.py'
            with mock.patch.dict(sys.modules,{package:parent}):
                loaded=importlib.import_module(package+'.docs_assistant')
                # The managed runner uses -B. Construct the actual old timestamp
                # pyc explicitly so this counterfactual does not depend on flags.
                py_compile.compile(str(path),doraise=True,invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
                metadata=path.stat();path.write_text("VALUE='NEWER'\n")
                os.utime(path,ns=(metadata.st_atime_ns,metadata.st_mtime_ns))
                namespace={'__package__':package,'importlib':importlib}
                exec(compile(before,str(fixtures/'core_imports.before.source'),'exec'),namespace)
                self.assertIs(loaded,namespace['docs_assistant'])
                self.assertEqual('OLDER',namespace['docs_assistant'].VALUE)
                sys.modules.pop(package+'.docs_assistant')
                exec(compile(before,str(fixtures/'core_imports.before.source'),'exec'),namespace)
                self.assertEqual('OLDER',namespace['docs_assistant'].VALUE)
                with mock.patch.object(server,'__file__',str(root/'mcp_server.py')), \
                     mock.patch.object(server,'_MCP_BOOT_TIME_NS',server._MCP_BOOT_TIME_NS+1), \
                     mock.patch.object(server,'_CORE_IMPORT_DIGESTS',{}):
                    fixed=server._captured_core('docs_assistant')
                try:self.assertEqual('NEWER',fixed.VALUE)
                finally:sys.modules.pop(fixed.__name__,None)

    def test_changed_loaded_core_policy_blocks_before_effect(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'policy.py';source.write_text('original\n')
            marker=root/'effect'
            def effect():marker.write_text('effect');return {'ok':True}
            with mock.patch.object(server,'_CHECK_RUNNER_SOURCE_DIGESTS',
                                   {source:hashlib.sha256(source.read_bytes()).hexdigest()}):
                call=server._core_source_request(effect)
                self.assertTrue(call()['ok']);marker.unlink();source.write_text('changed\n')
                self.assertFalse(call()['ok']);self.assertFalse(marker.exists())


if __name__=='__main__':unittest.main()
