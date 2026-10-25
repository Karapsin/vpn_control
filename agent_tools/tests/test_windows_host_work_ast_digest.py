"""Reviewed historical AST digests do not depend on the interpreter's ast.dump.

Fast Checks run 40187427911 (CPython 3.12.15) refused the authentic define/start
sources: _REVIEWED holds CPython 3.13/3.14 ast.dump digests, and 3.12 also prints
empty list fields. The preserved whole beforeimage reproduces that refusal under
the 3.12 text on any interpreter; the fix accepts the same sources under both.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import platform
import sys
import types
import unittest
import uuid

from agent_tools import readiness_windows_host_work as current
from agent_tools.tests import test_readiness_windows_host_work as evidence

FIXTURE = Path(__file__).parent / 'fixtures/windows_host_work_ast_digest'
BEFORE = 'readiness_windows_host_work.py.before.source'
PHASES = (('define', 'define.source'), ('start', 'start.source'))
PYTHON_SOURCES = ('define.source', 'start.source', 'documents.source', 'remote.before.source')


def provenance():
    value = json.loads((FIXTURE / 'provenance.json').read_bytes())
    raw = (FIXTURE / BEFORE).read_bytes()
    if (value.get('nativeFailureClaimed') is not False or set(value.get('files', ())) != {BEFORE}
            or hashlib.sha256(raw).hexdigest() != value['files'][BEFORE]['sha256']):
        raise AssertionError('host work AST digest beforeimage changed')
    return value, raw


def before_module():
    _, raw = provenance()
    name = 'agent_tools._host_work_ast_before_' + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.__file__ = str(FIXTURE / BEFORE)
    module.__package__ = 'agent_tools'
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, 'exec'), vars(module))
    finally:
        sys.modules.pop(name, None)
    return module


def shown(node, empty_lists):
    """The running ast.dump with every present field shown (3.13+ need show_empty).

    Fields a form lacks are first removed from a copy: the is_lazy=0 that 3.15
    adds to imports and, for the 3.13 form, the empty list fields 3.12 prints.
    Independent of the fix under test.
    """
    node = copy.deepcopy(node)
    for part in ast.walk(node):
        for name, value in list(ast.iter_fields(part)):
            if name == 'is_lazy' and value == 0 or not empty_lists and value == []:
                delattr(part, name)
    return ast.dump(node, include_attributes=False, **({'show_empty': True} if sys.version_info >= (3, 13) else {}))


def python312_dump(node, annotate_fields=True, include_attributes=False):
    """ast.dump text of CPython 3.12 on 3.12 and later (3.11 has no type_params)."""
    if annotate_fields is not True or include_attributes is not False:
        raise AssertionError('unreviewed ast.dump options')
    return shown(node, True)


def python313_dump(node, annotate_fields=True, include_attributes=False):
    """ast.dump text of CPython 3.13/3.14 on any interpreter: the _REVIEWED form."""
    if annotate_fields is not True or include_attributes is not False:
        raise AssertionError('unreviewed ast.dump options')
    return shown(node, False)


def interpreter(dump):
    """The ast module as a module sees it under another CPython's ast.dump."""
    value = types.ModuleType('ast')
    vars(value).update(vars(ast))
    value.dump = dump
    return value


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def difference(left, right):
    index = next((i for i, pair in enumerate(zip(left, right)) if pair[0] != pair[1]), min(len(left), len(right)))
    return {'offset': index, 'canonical': left[max(0, index - 80):index + 160],
            'python313': right[max(0, index - 80):index + 160], 'lengths': [len(left), len(right)]}


def report(before):
    """Complete interpreter and per-function digest evidence for every failure."""
    expected = provenance()[0]['python312Digests']
    _, payloads = evidence.fixtures()
    syntax = getattr(current, '_syntax', None)
    rows = {}
    for phase, name in PHASES:
        for node in ast.parse(payloads[name]).body:
            if isinstance(node, ast.FunctionDef):
                key = phase + ':' + node.name
                canonical, reviewed = syntax(node) if syntax else None, python313_dump(node)
                rows[key] = {'currentReviewed': current._REVIEWED[phase].get(node.name),
                             'beforeReviewed': before._REVIEWED[phase].get(node.name),
                             'canonical': canonical and sha(canonical), 'python313': sha(reviewed),
                             'python312': sha(python312_dump(node)), 'expectedPython312': expected.get(key),
                             'interpreter': sha(ast.dump(node, include_attributes=False)),
                             'canonicalDifference': None if canonical in (None, reviewed) else difference(canonical, reviewed)}
    return json.dumps({'python': sys.version, 'implementation': platform.python_implementation(),
                       'platform': platform.platform(), 'currentHasCanonicalForm': syntax is not None,
                       'functions': rows}, indent=1, sort_keys=True)


class InterpreterIndependentReviewedDigestTests(unittest.TestCase):
    def setUp(self):
        self.provenance, _ = provenance()
        self.before = before_module()
        self.detail = report(self.before)

    def proofs(self, module, dump):
        case = evidence.HostWorkTests('runTest')
        case.setUp()
        self.addCleanup(case.doCleanups)
        saved = vars(module)['ast']
        vars(module)['ast'] = interpreter(dump)
        try:
            return module.libvirt_lifecycle_proofs(case.root, **case.arguments())
        finally:
            vars(module)['ast'] = saved

    def accepted(self, module, dump, label):
        try:
            return [proof.guard() for proof in self.proofs(module, dump)]
        except ValueError as error:
            self.fail(label + ' refused the authentic sources: ' + str(error) + '\n' + self.detail)

    def test_whole_before_refuses_authentic_sources_under_python312_dump_RED_fixed_accepts_both_GREEN(self):
        # Control: the beforeimage accepts under the text it was reviewed with, so
        # only the interpreter's ast.dump form decides the CI refusal below.
        self.assertEqual(2, len(self.accepted(self.before, python313_dump, 'before under 3.13 ast.dump')), self.detail)
        with self.assertRaisesRegex(ValueError, '^windows_host_work_source_unreviewed$', msg=self.detail):
            self.proofs(self.before, python312_dump)
        accepted = []
        for label, dump in (('python3.12', python312_dump), ('python3.13', python313_dump)):
            with self.subTest(form=label):
                accepted.append(self.accepted(current, dump, 'fixed module under ' + label + ' ast.dump'))
                self.assertEqual(['libvirt-define', 'libvirt-start'], [proof['kind'] for proof in accepted[-1]], self.detail)
        if len(accepted) == 2:
            self.assertEqual(accepted[0], accepted[1], self.detail)

    def test_reviewed_digests_are_the_python313_dump_text_on_every_interpreter(self):
        if getattr(current, '_syntax', None) is None:
            self.fail('readiness_windows_host_work has no interpreter-independent digest form\n' + self.detail)
        _, payloads = evidence.fixtures()
        for phase, name in PHASES:
            for node in ast.parse(payloads[name]).body:
                if not isinstance(node, ast.FunctionDef):
                    continue
                key = phase + ':' + node.name
                with self.subTest(function=key):
                    canonical = sha(current._syntax(node))
                    # Recomputing the reviewed digests in the canonical form keeps their values.
                    self.assertEqual(current._REVIEWED[phase][node.name], canonical, self.detail)
                    self.assertEqual(self.before._REVIEWED[phase][node.name], canonical, self.detail)
                    self.assertNotEqual(canonical, sha(python312_dump(node)), self.detail)
                    if sys.version_info >= (3, 12):
                        self.assertEqual(self.provenance['python312Digests'][key], sha(python312_dump(node)), self.detail)
        sources = [Path(current.__file__).read_bytes(), provenance()[1], *(payloads[name] for name in PYTHON_SOURCES)]
        for raw in sources:
            for node in ast.parse(raw).body:
                canonical, reviewed = current._syntax(node), python313_dump(node)
                if canonical != reviewed:
                    self.fail(json.dumps(difference(canonical, reviewed), indent=1) + '\n' + self.detail)


if __name__ == '__main__':
    unittest.main()
