"""Protected-flow causal readmission tests with controlled public-marker input.

Historical native facts and whole-source provenance remain unchanged. These cases
also run a linked copy of the current source, and linkage covers the definitions
this cohort compiles; native credential input is proved separately.
"""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/windows_login_latest_readmission'

CONSUMED_PROTECTED_DEFINITIONS = (
    'PrivateInputUnknown', 'private_keys', 'enter_private', 'ppm', 'screen_gate',
    'wait_known_field', 'prepare_screen', '_login_flow',
)


def protected_nodes(raw):
    tree = ast.parse(raw)
    selected = []
    for name in CONSUMED_PROTECTED_DEFINITIONS:
        matches = [row for row in tree.body
                   if isinstance(row, (ast.FunctionDef, ast.ClassDef)) and row.name == name]
        if len(matches) != 1:
            raise ValueError('Protected definition missing or duplicated: ' + name)
        selected.append(matches[0])
    return selected


def protected_definition_sources(raw):
    """Exact consumed definitions, including decorators, headers and bodies."""
    lines = raw.splitlines(keepends=True)
    selected = {}
    for node in protected_nodes(raw):
        first = min([node.lineno, *(decorator.lineno for decorator in node.decorator_list)])
        selected[node.name] = b''.join(lines[first - 1:node.end_lineno])
    return selected


def load(name, facts):
    raw = (FIXTURE / name).read_bytes()
    ns = {'hashlib': hashlib, 'json': json, 're': re, 'os': os}
    for node in protected_nodes(raw):
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(FIXTURE / name), 'exec'), ns)
    pixels = bytes((240, 240, 240)) * (320 * 200)
    ns.update(LOGIN_MODE='login-submit', LOGIN_EXPECTED=copy.deepcopy(facts['expected']),
              LOGIN_SID=facts['account'], SPEC={'deploymentId': facts['machine']},
              SETUP={'user': facts['expected']['user']}, OPERATION='117fd197-772d-48d5-9255-ce3006d7fdbd',
              LOGIN_OWNER_SECRET=b'A', LOGIN_ACCOUNT_SCRIPT='controlled-public-account-observer',
              SESSION_SCRIPT='controlled-public-session-observer',
              LOGIN_PROFILE={'width': 320, 'height': 200,
                             'crops': [{'rect': [0, 0, 320, 200], 'sha256': hashlib.sha256(pixels).hexdigest()}]})
    return raw, ns, b'P6\n320 200\n255\n' + pixels


class LatestReadmissionExecution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.facts = json.loads((FIXTURE / 'positive-native-facts.json').read_text())
        cls.provenance = json.loads((FIXTURE / 'provenance.json').read_text())

    def run_flow(self, source, change):
        raw, ns, screen = load(source, self.facts)
        latest = copy.deepcopy(self.facts['fresh'])
        change(latest)
        sent = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def read(name):
                return json.loads((root / name).read_text())

            def save(name, value):
                path = root / name
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump(value, stream)

            def monitor(command, arguments):
                if command == 'screendump':
                    path = Path(arguments['filename'])
                    path.write_bytes(screen)
                    path.chmod(0o600)
                    return {}
                self.assertEqual(command, 'send-key')
                sent.append(command)
                return {}

            def script(label, source):
                if label.startswith('login-account-'):
                    return {'name': ns['SETUP']['user'], 'sid': ns['LOGIN_SID'],
                            'enabled': True, 'loginKeyboard': '00000409'}
                self.assertTrue(label.startswith(('login-admission-', 'login-after-')))
                return copy.deepcopy(latest)

            before = {key: self.facts['expected'][key] for key in ('actor', 'hostBoot', 'controlConnection')}
            error = None
            try:
                ns['_login_flow'](root, read, save, monitor, lambda: None, script,
                                  copy.deepcopy(self.facts['fresh']), before)
            except ValueError as failure:
                error = str(failure)
            admitted = (root / ('login-credential-' + ns['OPERATION'] + '.intent.json')).exists()
        return raw, sent, admitted, error

    def causal(self, change, reason):
        before, sent, admitted, _ = self.run_flow('before.source', change)
        self.assertEqual(hashlib.sha256(before).hexdigest(), self.provenance['beforeSourceSha256'])
        self.assertEqual(sent, ['send-key', 'send-key'], 'original full flow must really reach marker entry')
        self.assertTrue(admitted)
        after, sent, admitted, error = self.run_flow('after.source', change)
        self.assertEqual(hashlib.sha256(after).hexdigest(), self.provenance['afterSourceSha256'])
        self.assertEqual(sent, [])
        self.assertFalse(admitted)
        self.assertEqual(error, reason)
        current, sent, admitted, error = self.run_flow('current.source', change)
        self.assertEqual(hashlib.sha256(current).hexdigest(), self.provenance['currentSourceSha256'])
        self.assertEqual(sent, [])
        self.assertFalse(admitted)
        self.assertEqual(error, reason)

    def test_latest_account_is_no_longer_ordinary_before_any_input(self):
        self.causal(lambda current: current.update(ordinary=False), 'instance_login_account_mismatch')

    def test_latest_expected_sid_changed_before_any_input(self):
        self.causal(lambda current: current.update(expectedSid='S-1-5-21-1-2-3-1000'),
                    'instance_login_account_mismatch')

    def test_same_sid_logon_was_unlocked_before_any_input(self):
        self.causal(lambda current: current['session'].update(Flags=1), 'instance_login_session_changed')

    def test_latest_session_state_changed_before_any_input(self):
        self.causal(lambda current: current['session'].update(State=4), 'instance_login_session_changed')

    def assert_protected_linkage(self, current):
        linked = (FIXTURE / 'current.source').read_bytes()
        self.assertEqual(hashlib.sha256(linked).hexdigest(), self.provenance['currentSourceSha256'])
        self.assertEqual(protected_definition_sources(current), protected_definition_sources(linked))

    def test_historical_afterimage_is_unchanged(self):
        after = (FIXTURE / 'after.source').read_bytes()
        self.assertEqual(hashlib.sha256(after).hexdigest(), self.provenance['afterSourceSha256'])

    def test_current_consumed_protected_definitions_match_linked_source(self):
        production = Path(__file__).parents[1] / 'readiness_windows_login.py'
        self.assert_protected_linkage(production.read_bytes())

    def test_every_consumed_definition_change_breaks_historical_linkage(self):
        production = Path(__file__).parents[1] / 'readiness_windows_login.py'
        current = production.read_bytes()
        current_definitions = protected_definition_sources(current)
        for node in protected_nodes(current):
            with self.subTest(definition=node.name):
                lines = current.splitlines(keepends=True)
                # Alter only this actual protected definition. The current
                # whole source and all other consumed definitions stay intact.
                first = node.body[0]
                insertion = first.end_lineno if (isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)) else first.lineno - 1
                mutation = (b"    changed_protected_fixture_marker = True\n" if isinstance(node, ast.ClassDef)
                    else b"    raise RuntimeError('controlled protected-definition mutation')\n")
                lines.insert(insertion, mutation)
                changed = b''.join(lines)
                differences = {name for name, raw in protected_definition_sources(changed).items()
                    if raw != current_definitions[name]}
                self.assertEqual(differences, {node.name})
                with self.assertRaises(AssertionError):
                    self.assert_protected_linkage(changed)


if __name__ == '__main__':
    unittest.main()
