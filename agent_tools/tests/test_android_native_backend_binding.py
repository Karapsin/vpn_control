"""Authentic source/TempFS caller controls; never a native/protected constructor."""
import ast
import os
from pathlib import Path
import types
import unittest
from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests import test_android_installer_component_bundle as existing_bundle_tests

SOURCE = (Path(__file__).parent / 'fixtures' /
          'android_native_backend_binding' / 'backend_context.source')

@unittest.skipUnless(os.name == 'posix', 'native binder requires POSIX FD APIs')
class NativeBindingControls(unittest.TestCase):
    def setUp(self):
        self.fixture_owner = existing_bundle_tests.BundleTests()
        self.fixture_owner.setUp()
        self.addCleanup(self.fixture_owner.tearDown)
        self.selected, self.backend, *_ = self.fixture_owner.fixture()
        self.backend['COMPONENT_MODULES'] = self.selected
        self.backend['ast'] = ast
        self.backend['types'] = types
        self.raw = SOURCE.read_bytes()
        bundle._selected_modules(self.fixture_owner.receipt, self.selected)
        exec(compile(self.raw, '<actual-native-backend-binding>', 'exec', dont_inherit=True), self.backend)

    def bind(self):
        # Execute the complete actual emitted binder, including all13 functions.
        self.backend['component_bind_backend_context']()

    def guard(self):
        return bundle._guard_backend(self.selected, self.backend, 'api35')

    def test_actual_native_binder_matches_strict_api35_guard(self):
        self.bind()
        try:
            result = self.guard()
        except ValueError as error:
            self.fail('authentic binder rejected: ' + str(error))
        required = {'component_command', 'command_binary', 'command_request',
                    'command_host_identity', 'command_host_guard', 'command_bounded',
                    'getter_stage', 'child_identity', 'session_guest', 'qemu_fact',
                    'external_file', 'external_jdk', 'external_jdk_guard'}
        self.assertTrue(required.issubset(result))
        self.assertIs(self.backend['getter_stage'].__globals__, self.backend)

    def test_unauthorized_getter_function_still_refused(self):
        self.bind()
        code = compile('def getter_stage(): return {}', '<foreign-getter>', 'exec', dont_inherit=True)
        function = next(value for value in code.co_consts if isinstance(value, types.CodeType))
        self.backend['getter_stage'] = types.FunctionType(function, self.backend)
        with self.assertRaisesRegex(ValueError, 'fixed_backend_required:getter_stage'):
            self.guard()

    def test_foreign_getter_globals_still_refused(self):
        self.bind()
        actual = self.backend['getter_stage']
        self.backend['getter_stage'] = types.FunctionType(actual.__code__, dict(self.backend))
        with self.assertRaisesRegex(ValueError, 'fixed_backend_required:getter_stage'):
            self.guard()

    def test_receipt_unstaged_module_still_refused(self):
        actual = self.selected['getter_api35']
        foreign = types.ModuleType('foreign_getter')
        foreign.__dict__.update(actual.__dict__)
        foreign.__file__ = str(self.fixture_owner.root / 'outside-getter.py')
        self.selected['getter_api35'] = foreign
        with self.assertRaisesRegex(ValueError, 'component_guard_unstaged_module'):
            bundle._selected_modules(self.fixture_owner.receipt, self.selected)

    def test_receipt_mutated_getter_template_still_refused(self):
        self.selected['getter_api35']._GETTER += '\ndef arbitrary_replacement(): return 1\n'
        with self.assertRaisesRegex(ValueError, 'component_guard_getter_source_changed'):
            bundle._selected_modules(self.fixture_owner.receipt, self.selected)

    def test_existing_api29_complete_context_unchanged(self):
        # The owned binder is API35-specific; the canonical API29 selection stays.
        self.fixture_owner.actual_factory_functions(self.backend, 'api29')
        bundle._selected_modules(self.fixture_owner.receipt, self.selected)
        bundle._guard_backend(self.selected, self.backend, 'api29')

if __name__ == '__main__':
    unittest.main()
