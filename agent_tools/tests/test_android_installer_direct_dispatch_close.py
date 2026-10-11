"""Selected production AST controls; fake descriptors and no runner imports."""
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import types
import unittest

ROOT = Path(__file__).parents[2]
ATTEMPTS = [99, 13, 12, 11]


def selected(raw, filename, names, namespace):
    tree = ast.parse(raw, filename)
    nodes = [node for node in tree.body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in nodes} != set(names):
        raise AssertionError('Exact selected public functions required')
    # Production function ASTs are selected without modification.
    exec(compile(ast.Module(body=nodes, type_ignores=[]), filename, 'exec'), namespace)
    return namespace


class FakeOS:
    O_RDONLY = 1
    O_NOFOLLOW = 2
    O_NONBLOCK = 4

    def __init__(self, errors, body):
        self.errors = errors
        self.body = body
        self.attempts = []
        self.reads = 0

    def open(self, name, flags, *, dir_fd):
        if (name, flags, dir_fd) != ('journal.json', 7, 13):
            raise AssertionError('Original leaf open observation changed')
        return 99

    def read(self, fd, bound):
        if fd != 99 or bound != (len(self.body) + 1 if self.reads == 0 else 1):
            raise AssertionError('Original bounded leaf read changed')
        self.reads += 1
        return self.body if self.reads == 1 else b''

    def close(self, fd):
        self.attempts.append(fd)
        if fd in self.errors:
            raise self.errors[fd]


class DispatchCloseControl(unittest.TestCase):
    def attempt(self, errors, original):
        body = b'original-source'
        os_seam = FakeOS(errors, body)
        chain = [('/', 11), ('/fixture', 12), ('/fixture/journal', 13)]
        parents = {name: [7, fd, 16832, 503, 20] for name, fd in chain}
        path = PurePosixPath('/fixture/journal/journal.json')
        pin = {'sha256': hashlib.sha256(body).hexdigest(), 'parents': parents}
        bundle_namespace = selected(
            (ROOT / 'agent_tools/android_installer_component_bundle.py').read_bytes(),
            str(ROOT / 'agent_tools/android_installer_component_bundle.py'),
            ['_close'], {'os': os_seam})

        def parents_seam(observed):
            self.assertEqual(observed, path.parent)
            return chain, parents

        bundle = types.SimpleNamespace(_parents=parents_seam,
                                       _close=bundle_namespace['_close'])

        def guard_seam(held):
            self.assertEqual(held, [(path, pin, chain, 99)])
            raise original

        source = ROOT / 'agent_tools/android_installer_direct_transport.py'
        namespace = selected(source.read_bytes(), str(source),
                             ['require', 'canonical', 'equal', 'sha', '_dispatch_hold'],
                             {'os': os_seam, 'bundle': bundle, 'json': json,
                              'hashlib': hashlib, '_dispatch_guard': guard_seam})
        try:
            namespace['_dispatch_hold'](path, pin, body)
        except BaseException as caught:
            return os_seam.attempts, caught
        self.fail('Original guard refusal must propagate')

    def test_leaf_close_error_attempts_every_ancestor(self):
        first = OSError(9, 'leaf-close-injected')
        original = ValueError('guard-injected')
        attempts, caught = self.attempt({99: first}, original)
        self.assertEqual(attempts, ATTEMPTS)
        self.assertIs(caught, first)
        self.assertIs(caught.__cause__, original)

    def test_leaf_and_multiple_ancestor_errors_keep_first_cleanup_identity(self):
        first = RuntimeError('leaf-close-injected')
        original = OSError(9, 'read-guard-injected')
        errors = {99: first, 13: OSError(9, 'nearest-close-injected'),
                  11: RuntimeError('root-close-injected')}
        attempts, caught = self.attempt(errors, original)
        self.assertEqual(attempts, ATTEMPTS)
        self.assertIs(caught, first)
        self.assertIs(caught.__cause__, original)

    def test_ancestor_errors_attempt_remaining_original_descriptors(self):
        first = OSError(9, 'nearest-close-injected')
        original = ValueError('guard-injected')
        attempts, caught = self.attempt(
            {13: first, 12: RuntimeError('parent-close-injected')}, original)
        self.assertEqual(attempts, ATTEMPTS)
        self.assertIs(caught, first)
        self.assertIs(caught.__cause__, original)

    def test_no_cleanup_error_preserves_existing_exception_semantics(self):
        for original in (OSError(9, 'guard-injected'), ValueError('guard-injected'),
                         RuntimeError('guard-injected')):
            with self.subTest(error=type(original).__name__):
                attempts, caught = self.attempt({}, original)
                self.assertEqual(attempts, ATTEMPTS)
                if isinstance(original, (OSError, ValueError)):
                    self.assertIs(type(caught), ValueError)
                    self.assertEqual(str(caught), 'direct_dispatch_changed')
                    self.assertIs(caught.__cause__, original)
                else:
                    self.assertIs(caught, original)

