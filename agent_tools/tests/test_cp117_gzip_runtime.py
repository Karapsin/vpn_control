"""Historical fixture codec portability keeps original source authority intact."""
from contextlib import nullcontext
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from agent_tools import source_module_loader
from agent_tools import windows_cp117_secure_input_observe as semantic
from agent_tools import windows_cp117_secure_input_tuple_observe as tuple_reader
from agent_tools import windows_cp117_secure_input_geometry_observe as geometry
from agent_tools import windows_cp117_secure_input_descendants_observe as descendants
from agent_tools import windows_cp117_windowless_candidate_observe as candidate
from agent_tools import windows_cp117_windowless_edit_observe as edit
from agent_tools import windows_cp117_windowless_gui_login as role
from agent_tools.tests.fixtures import cp117_gzip_runtime as codec
from agent_tools.tests.fixtures.windows_cp117_historical_factory import context


PRODUCERS = (semantic, tuple_reader, geometry, descendants, candidate, edit, role)
RENDERED = {
    'windows_cp117_secure_input_observe.py': ('0c152f3e671a61dc47ef47355a3ff5509e3c7471ae0153d967d5a74452c78b95', 'a93697d178a3fb79a731b8bc7cc721574f25d16068dd8a24fc46e2f6f98d6994'),
    'windows_cp117_secure_input_tuple_observe.py': ('a4fe4a76bac90129467fc0562247914f00097248cc496587da44b2217a11a95e', 'e889999038cd109299f6e34696f573360493e39d227dc8e656f612aa09acc3b2'),
    'windows_cp117_secure_input_geometry_observe.py': ('1ea028e8de67079798f3a2cb32cbe0d32d4b90517f29ece4df3c8bff37215890', 'dca51cc9defa832098dd0fa35b280adf954614c5e47a524d553d1b40d6d8abe2'),
    'windows_cp117_secure_input_descendants_observe.py': ('4b47b17df0625d93ae939c889c94958a6626b44bc5948a094bc350ce281e3a0c', '95e31b420767174e0d435a02b44db8f538aa7a70bc32d2f6c1f4ad1fd15a9cd5'),
    'windows_cp117_windowless_candidate_observe.py': ('1586cac7448a3ef9c9b727cc55c70012d371acaa9afbe678911c217b3806007e', '35eaaf7573bc900ebffcfa25d73bc0e9d82fa2c947409804844941a6cb378db7'),
    'windows_cp117_windowless_edit_observe.py': ('fad67aa8c9aa2838595c7a25c8d34cd846e5ce4f42f5d337010ad62bb0da4e3b', '7189389d2eb5ee1af60664e0b57f2dcc7ebee4e2d1dfa3ca511fd5f465d1669a'),
    'windows_cp117_windowless_gui_login.py': ('afee661398d235c6a15d2dac957fc469cf4e21c3991e85b541c8e7524d0ae24e', '143e2d9c6f64907e53038c771b7ba6bf30539f937a954515b7fcd68c3a622cc3'),
}


class HistoricalGzipRuntimeTests(unittest.TestCase):
    use_compatibility = True

    def test_all_seven_original_rendered_sources_keep_the_fourteen_fixed_hashes(self):
        scope = codec.historical_gzip_context(*PRODUCERS) if self.use_compatibility else nullcontext()
        with scope:
            for module in PRODUCERS:
                name = Path(module.__file__).name
                with self.subTest(producer=name):
                    expected_child, expected_parent = RENDERED[name]
                    self.assertEqual((expected_child, expected_parent), (module.CHILD_SHA, module.PARENT_SHA))
                    parent, child, child_sha = module.bodies()
                    self.assertEqual(expected_child, child_sha)
                    self.assertEqual(expected_child, hashlib.sha256(child.encode('utf-16le')).hexdigest())
                    self.assertEqual(expected_parent, hashlib.sha256(parent.encode('utf-16le')).hexdigest())
                    print(json.dumps({'historicalGzipRenderedSource': name,
                                      'childSha256': child_sha, 'parentSha256': expected_parent,
                                      'fixtureOnly': True, 'nativeAdmission': False}), flush=True)

    def test_codec_changes_only_os_metadata_and_keeps_payload_crc_and_level(self):
        raw = b'PUBLIC INERT HISTORICAL SOURCE\n' * 23
        original = gzip.compress(raw, compresslevel=9, mtime=0)
        result = codec.canonical_gzip(raw)
        self.assertEqual(original[:9], result[:9])
        self.assertEqual(original[10:], result[10:])
        self.assertEqual(255, result[9])
        self.assertEqual(raw, gzip.decompress(result))
        for arguments in ({'compresslevel': 1}, {'mtime': 1}, {'compresslevel': True}, {'mtime': False}):
            with self.assertRaisesRegex(ValueError, 'historical_gzip_runtime_arguments'):
                codec.canonical_gzip(raw, **arguments)

    def test_stdlib_and_supported_current_request_context_remain_unchanged(self):
        original_module = sys.modules['gzip']
        original_compress = gzip.compress
        original_functions = (gzip.decompress, gzip.GzipFile)
        session = source_module_loader.SourceSession(Path(semantic.__file__).parent, 'ssh_transport')
        prefix = session.prefix
        try:
            current = session.module
            code = current._EXECUTING_CODE
            current_keys = set(vars(current))
            with codec.historical_gzip_context(current, semantic):
                self.assertNotIn('gzip', vars(current))
                self.assertEqual(current_keys, set(vars(current)))
                self.assertIs(code, current._EXECUTING_CODE)
                self.assertIs(original_module, sys.modules['gzip'])
                self.assertIs(original_compress, gzip.compress)
                self.assertEqual(original_functions, (gzip.decompress, gzip.GzipFile))
        finally:
            session.close()
        self.assertFalse(any(name == prefix or name.startswith(prefix + '.') for name in sys.modules))
        self.assertIs(original_compress, gzip.compress)

    def test_actual_private_historical_graph_nested_and_exceptional_cleanup(self):
        private = context.provider()
        targets = codec._targets((private, *PRODUCERS))
        originals = [(module, module.gzip) for module in targets]
        with codec.historical_gzip_context(private, *PRODUCERS):
            outer = [(module, module.gzip) for module in targets]
            self.assertTrue(all(isinstance(view, codec.HistoricalGzipView) for _, view in outer))
            with self.assertRaisesRegex(RuntimeError, 'inert fixture failure'):
                with codec.historical_gzip_context(private, *PRODUCERS):
                    self.assertTrue(all(module.gzip is not view for module, view in outer))
                    raise RuntimeError('inert fixture failure')
            self.assertTrue(all(module.gzip is view for module, view in outer))
        self.assertTrue(all(module.gzip is original for module, original in originals))

    def test_unknown_source_refuses_without_patching_any_dependency(self):
        original = semantic.gzip
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'windows_cp117_secure_input_observe.py'
            path.write_bytes(b'FOREIGN_SOURCE = True\n')
            unknown = types.ModuleType('inert_foreign_source')
            unknown.__file__ = str(path)
            unknown.gzip = gzip
            with self.assertRaisesRegex(ValueError, 'historical_gzip_runtime_source_changed'):
                with codec.historical_gzip_context(semantic, unknown):
                    self.fail('Unknown fixture source must refuse')
        self.assertIs(original, semantic.gzip)

    def test_testcase_entry_refusal_is_an_outcome_error_and_cleans_its_stack(self):
        owner_name = '_inert_cp117_gzip_entry_refusal'
        owner = types.ModuleType(owner_name)
        called = []
        class ProbeCase(codec.HistoricalGzipTestCase):
            def setUp(self):
                called.append('setUp')
            def runTest(self):
                called.append('runTest')
        ProbeCase.__module__ = owner_name
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'windows_cp117_secure_input_observe.py'
            path.write_bytes(b'FOREIGN_SOURCE = True\n')
            unknown = types.ModuleType('inert_foreign_testcase_source')
            unknown.__file__ = str(path)
            unknown.gzip = gzip
            owner.m = unknown
            sys.modules[owner_name] = owner
            try:
                case = ProbeCase()
                result = case.run(unittest.TestResult())
                self.assertEqual(1, result.testsRun)
                self.assertEqual(1, len(result.errors))
                self.assertIn('historical_gzip_runtime_source_changed', result.errors[0][1])
                self.assertEqual([], called)
                self.assertFalse(hasattr(case, '_historical_gzip_stack'))
                self.assertIs(gzip, unknown.gzip)
            finally:
                sys.modules.pop(owner_name, None)

    def test_testcase_actual_setup_rebinding_and_failed_setup_restore_all_views(self):
        for fail_setup in (False, True):
            with self.subTest(failSetup=fail_setup):
                owner_name = '_inert_cp117_gzip_setup_rebinding'
                owner = types.ModuleType(owner_name)
                owner.m = semantic
                private = context.provider()
                originals = [(module, module.gzip) for module in codec._targets((semantic, private))]
                observed = []
                class ProbeCase(codec.HistoricalGzipTestCase):
                    def setUp(self):
                        owner.m = private
                        if fail_setup:
                            raise RuntimeError('inert setup failure')
                    def runTest(self):
                        observed.append(isinstance(owner.m.gzip, codec.HistoricalGzipView))
                        observed.append(all(isinstance(module.gzip, codec.HistoricalGzipView)
                                            for module in codec._targets((private,))))
                ProbeCase.__module__ = owner_name
                sys.modules[owner_name] = owner
                try:
                    case = ProbeCase()
                    result = case.run(unittest.TestResult())
                    self.assertEqual(1, result.testsRun)
                    self.assertEqual(int(fail_setup), len(result.errors))
                    if fail_setup:
                        self.assertIn('inert setup failure', result.errors[0][1])
                    self.assertEqual([] if fail_setup else [True, True], observed)
                    self.assertFalse(hasattr(case, '_historical_gzip_stack'))
                    self.assertTrue(all(module.gzip is original for module, original in originals))
                finally:
                    sys.modules.pop(owner_name, None)

    def test_payload_tamper_still_hits_the_original_generated_source_guard(self):
        original = semantic.gzip
        with codec.historical_gzip_context(semantic):
            view = semantic.gzip
            def corrupted(data, **kwargs):
                raw = bytearray(view.compress(data, **kwargs))
                raw[10] ^= 1
                return bytes(raw)
            with patch.object(semantic, 'gzip', types.SimpleNamespace(compress=corrupted)):
                with self.assertRaisesRegex(ValueError, 'semantic-generated-source'):
                    semantic.bodies()
        self.assertIs(original, semantic.gzip)


if __name__ == '__main__':
    unittest.main()
