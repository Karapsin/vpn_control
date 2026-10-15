"""Authentic fixture IO counterfactuals; CRT model is not a native Windows pass."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
FIXTURES = HERE / 'fixtures/windows_python_io'
VARIANT = os.environ.get('WINDOWS_PYTHON_IO_VARIANT', 'fixed')
if VARIANT not in {'before', 'fixed'}:
    raise ValueError('unknown Python IO fixture variant')


def before(name):
    provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
    row = next(row for row in provenance['sources'] if row['source'] == 'agent_tools/tests/' + name)
    raw = (FIXTURES / row['file']).read_bytes()
    if len(raw) != row['bytes'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
        raise ValueError('original fixture source changed')
    return raw


def candidate(name):
    return before(name) if VARIANT == 'before' else (HERE / name).read_bytes()


def method(raw, name):
    return next(node for node in ast.walk(ast.parse(raw))
                if isinstance(node, ast.FunctionDef) and node.name == name)


def expression(node, namespace):
    return eval(compile(ast.Expression(node), '<actual fixture caller expression>', 'eval'), namespace)


def assigned(node, name):
    return next(row.value for row in ast.walk(node) if isinstance(row, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == name for target in row.targets))


def complete_carrier(public, *, timeout):
    # Build the real source-authenticated packet without starting PowerShell.
    from .test_windows_cp117_base_source_refresh import _complete_windows_fixture_carrier
    return _complete_windows_fixture_carrier(public)


class PythonFixtureIoTests(unittest.TestCase):
    def test_exact_native_owner_caller_retains_both_failure_streams(self):
        from agent_tools import windows_tertiary_guest_stage as stage
        node = method(candidate('test_windows_tertiary_guest_stage.py'),
                      'test_actual_windows_creation_time_owner_and_inherited_custody')
        # Execute this exact caller against an observed nonzero process seam.
        # Removing only its platform decorator permits the diagnostic assertion
        # on every host; no native owner/ACL outcome is inferred or simulated.
        node.decorator_list = []
        scope = {'stage': stage}
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual owner probe caller>', 'exec'), scope)

        def observed_nonzero(argv, **options):
            self.assertIn('TertiaryPrivateStage', argv[-1])
            if options.get('check'):
                raise subprocess.CalledProcessError(1, argv, output=b'PUBLIC_NATIVE_OUT', stderr=b'PUBLIC_NATIVE_ERR')
            return subprocess.CompletedProcess(argv, 1, b'PUBLIC_NATIVE_OUT', b'PUBLIC_NATIVE_ERR')

        with patch('subprocess.run', observed_nonzero):
            with self.assertRaises(AssertionError) as failed:
                scope[node.name](self)
        self.assertIn('PUBLIC_NATIVE_OUT', str(failed.exception))
        self.assertIn('PUBLIC_NATIVE_ERR', str(failed.exception))

    def test_parent_control_directory_is_disjoint_from_its_existing_script(self):
        name = 'test_windows_vm_setup_phase.py'
        node = method(candidate(name), 'test_actual_parent_before_loses_terminal_code_fixed_held_handle_retains_it')
        statements = next(row.body for row in ast.walk(node) if isinstance(row, ast.With))
        index = next(i for i, row in enumerate(statements) if isinstance(row, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == 'root' for target in row.targets))
        # These are the original assignment and mkdir, using a physical existing
        # script exactly as setUp did. No PowerShell/process stub is involved.
        boundary = ast.Module(body=statements[index:index + 2], type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / 'before.ps1'
            script.write_bytes(b'PUBLIC original setup script')
            scope = {'self': SimpleNamespace(root=root), 'filename': 'before.ps1'}
            exec(compile(boundary, '<actual parent case mkdir>', 'exec'), scope)
            self.assertTrue(scope['root'].is_dir())
            self.assertNotEqual(scope['root'], script)
            self.assertEqual(script.read_bytes(), b'PUBLIC original setup script')

    def test_native_preprobe_callers_pass_complete_strict_utf8_bytes(self):
        raw = candidate('test_windows_cp117_preprobe_identity.py')
        public = "[Console]::Out.WriteLine('PUBLIC \u03bb')"
        for name in ('test_actual_native_producers_same_file_old_guard_refuses_ordered_roles',
                     'test_actual_held_native_pin_old_equality_refuses_attribute_only_projection'):
            with self.subTest(name=name):
                call = assigned(method(raw, name), 'proc')
                argv, packet = expression(call, {
                    'script': public,
                    'fixture': SimpleNamespace(_run_complete_windows_fixture=complete_carrier),
                })
                self.assertEqual(int.from_bytes(packet[:4], 'little'), len(public.encode('utf-8')))
                self.assertEqual(packet[4:], public.encode('utf-8', errors='strict'))
                self.assertLess(len(argv[-1]), 30000)

    @staticmethod
    def read_prefix(raw_source, path, binary_projection):
        node = method(raw_source, 'emit')
        script = expression(assigned(node, 'script'), {'source': lambda name: '', 'VARIANT': 'fixed'})
        tree = ast.parse(script)
        # Keep the exact real-file open/fstat/read/finally statements. The
        # imported os object is supplied explicitly to model only CRT text IO.
        code = ast.Module(body=[row for row in tree.body if not isinstance(row, ast.Import)], type_ignores=[])
        real_open, real_read = os.open, os.read
        flags_by_fd = {}
        binary = 0x8000

        def open_file(name, flags):
            # The host read stays binary so the explicit model is the only CRT
            # transformation, including when this control itself runs on Windows.
            fd = real_open(name, (flags & ~binary) | getattr(os, 'O_BINARY', 0))
            flags_by_fd[fd] = flags
            return fd

        def read_file(fd, count):
            data = real_read(fd, count)
            if binary_projection and not flags_by_fd[fd] & binary:
                # Windows CRT text descriptor: SUB terminates input and CRLF
                # becomes LF. This is an explicit model over a physical read.
                data = data.split(b'\x1a', 1)[0].replace(b'\r\n', b'\n')
            return data

        projected_os = SimpleNamespace(open=open_file, read=read_file, fstat=os.fstat,
                                       close=os.close, O_RDONLY=os.O_RDONLY, O_BINARY=binary)
        scope = {'os': projected_os, 'sys': SimpleNamespace(argv=['fixture', str(path)])}
        exec(compile(code, '<actual fixture physical read plus explicit CRT model>', 'exec'), scope)
        return scope['raw']

    def test_binary_fixture_read_preserves_both_actual_failure_payloads(self):
        name = 'test_windows_recent_fixture_failures.py'
        payloads = [
            (hashlib.shake_256(b'inert public image transfer regression').digest(3072016),
             238, '5763a5f113b24a0a1d539b448756f8859ccf9c13edc8023fb61ff50c208df50d'),
            (hashlib.shake_256(b'partial public image').digest(49152 + 17),
             260, 'db93212eb51445f36b55f3dbb6c51e8fb7529319e1ddca0f4682b8cda5492726'),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'PUBLIC.ppm'
            for public, observed_length, observed_hash in payloads:
                with self.subTest(bytes=len(public)):
                    path.write_bytes(public)
                    old = self.read_prefix(before(name), path, True)
                    self.assertEqual(len(old), observed_length)
                    self.assertEqual(hashlib.sha256(old).hexdigest(), observed_hash)
                    fixed = self.read_prefix(candidate(name), path, True)
                    self.assertEqual(fixed, public)

    def test_complete_two_script_parser_uses_authenticated_byte_carrier(self):
        from . import test_windows_tertiary_guest_stage as native_fixture
        from agent_tools import windows_tertiary_guest_stage as stage
        _, source, body, _ = native_fixture.FixtureProvisionFlowTests.flow()
        node = method(candidate('test_windows_tertiary_guest_stage.py'),
                      'test_actual_native_carrier_and_complete_flow_parser_without_effects')
        scope = {'source': source, 'body': body, 'base64': base64, 'json': json}
        scope['scripts'] = expression(assigned(node, 'scripts'), scope)
        scope['parser'] = expression(assigned(node, 'parser'), scope)
        self.assertEqual(json.loads(base64.b64decode(scope['scripts'])), [source, body])
        scope.update(stage=stage, subprocess=SimpleNamespace(run=lambda *args, **kwargs: None),
                     _run_complete_windows_fixture=complete_carrier)
        argv, packet = expression(assigned(node, 'checked'), scope)
        public = scope['parser'].encode('utf-8', errors='strict')
        self.assertEqual(packet[4:], public)
        self.assertEqual(int.from_bytes(packet[:4], 'little'), len(public))
        self.assertLessEqual(len(public), 262144)
        loader = base64.b64decode(argv[-1]).decode('utf-16-le', errors='strict')
        self.assertIn(hashlib.sha256(public).hexdigest(), loader)
        self.assertLess(len(subprocess.list2cmdline(argv)) + 160, 32767)


if __name__ == '__main__':
    unittest.main()
