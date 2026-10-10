"""Source-local causal controls; synthetic principals, never Linux acceptance."""
import argparse
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import traceback
import types
import unittest
ROOT = Path(__file__).resolve().parents[2]
def _bundle_source():
    return (ROOT / 'agent_tools' / 'android_installer_component_bundle.py').read_text()
RESULTS = []
FORBIDDEN = []

def source(name):
    return (ROOT / 'agent_tools' / name).read_text()

def literal(text, name):
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and any((isinstance(t, ast.Name) and t.id == name for t in node.targets)):
            return ast.literal_eval(node.value)
    raise ValueError('fixture_literal_missing:' + name)

def definition(text, name):
    nodes = [n for n in ast.walk(ast.parse(text)) if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1:
        raise ValueError('fixture_definition_not_unique:' + name)
    return ast.unparse(ast.Module(body=nodes, type_ignores=[])) + '\n'

def forbidden(*args, **kwargs):
    FORBIDDEN.append('forbidden_process_or_authority_call')
    raise AssertionError('forbidden fixture call')

class FixtureOS:
    """Real owned TempFS descriptors, explicitly synthetic UID/GID0 metadata."""

    def __init__(self, owned_root):
        # Shared ancestors are outside this synthetic fixture's owned TempFS.
        # Keep their declared volatile directory metadata consistent, while
        # inode/device/type/mode and every owned directory/file remain live.
        volatile = ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        self.external_directory_view = {}
        for parent in owned_root.parents:
            info = parent.stat()
            self.external_directory_view[(info.st_dev, info.st_ino)] = {
                name: getattr(info, name) for name in volatile
            }
        self.live = set()
        self.opens = self.close_attempts = self.read_bytes = 0

    def __getattr__(self, name):
        if name in ('fork', 'kill', 'execv', 'execve', 'setuid', 'seteuid', 'setgid', 'setegid', 'setgroups'):
            return forbidden
        return getattr(os, name)

    def view(self, info):
        names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink')
        values = {name: getattr(info, name) for name in names}
        if stat.S_ISDIR(info.st_mode):
            values.update(self.external_directory_view.get((info.st_dev, info.st_ino), {}))
        return types.SimpleNamespace(**values, st_uid=0, st_gid=0)

    def open(self, *args, **kwargs):
        fd = os.open(*args, **kwargs)
        self.live.add(fd)
        self.opens += 1
        return fd

    def close(self, fd):
        self.close_attempts += 1
        try:
            return os.close(fd)
        finally:
            self.live.discard(fd)

    def fstat(self, fd):
        return self.view(os.fstat(fd))

    def stat(self, *args, **kwargs):
        return self.view(os.stat(*args, **kwargs))

    def read(self, fd, limit):
        raw = os.read(fd, limit)
        self.read_bytes += len(raw)
        return raw

def setup_sources():
    adapter = types.ModuleType('own_fixture_adapter')
    adapter.__dict__['types'] = types
    text = source('android_installer_component_adapter.py')
    adapter.__dict__['_PRODUCTION_IMPORTS'] = literal(text, '_PRODUCTION_IMPORTS')
    exec(compile(definition(text, 'production_imports') + definition(text, '_semantic_code'), '<authentic-public-adapter-functions>', 'exec'), adapter.__dict__)
    bounded = types.SimpleNamespace(_OBSERVER=literal(source('android_api29_current_permission_observation.py'), '_OBSERVER'))
    census = literal(source('android_avd_launch_recovery.py'), '_CENSUS')
    boot = literal(source('android_avd_coldboot.py'), '_BOOT')
    getter = literal(source('android_coldboot_product_observation.py'), '_GETTER')
    remote = literal(source('android_api29_external_java_observation.py'), '_REMOTE')
    reader = types.SimpleNamespace(bounded_source=bounded, getter_source=types.SimpleNamespace(_GETTER=getter, coldboot=types.SimpleNamespace(_BOOT=boot)), proven=types.SimpleNamespace(_REMOTE=remote))
    transport = types.SimpleNamespace(readonly=reader, REMOTE=literal(source('android_component_command_transport.py'), 'REMOTE'))
    namespace = {'ast': ast, 'readonly': reader}
    exec(compile(definition(source('android_component_command_transport.py'), '_bounded_source'), '<authentic-public-bounded-generator>', 'exec'), namespace)
    transport._bounded_source = namespace['_bounded_source']
    return ({'adapter': adapter, 'transport': transport}, census)
SELECTED, CENSUS = setup_sources()

@unittest.skipUnless(all((hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK'))), 'requires POSIX descriptor custody primitives')
class JoinFixture(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='jdk-source-only-')
        self.root = Path(self.temp.name).resolve()
        self.jdk = self.root / 'jdk17'
        files = ('bin/java', 'release', 'lib/libjli.so', 'lib/server/libjvm.so', 'lib/libjava.so', 'lib/modules')
        for index, name in enumerate(files):
            path = self.jdk / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'JAVA_VERSION="17.0.9"\n' if name == 'release' else b'own-fixture-' + str(index).encode())
            path.chmod(448 if name == 'bin/java' else 384)
        self.os = FixtureOS(self.root)
        self.backend = {}
        imports = SELECTED['adapter'].production_imports('api35')
        transport = SELECTED['transport']
        sources = [(transport.REMOTE + '\n' + transport._bounded_source(), ('component_command', 'command_binary', 'command_request', 'command_host_identity', 'command_host_guard', 'command_bounded')), (transport.readonly.getter_source._GETTER.replace('__GETTER__', repr({})), ('getter_stage',)), (transport.readonly.getter_source.coldboot._BOOT.replace('__LAUNCH__', repr({})), ('child_identity', 'session_guest', 'qemu_fact')), (transport.readonly.proven._REMOTE.replace('__EXTERNAL__', repr({})), ('external_file', 'external_jdk', 'external_jdk_guard')), (CENSUS, ('fp', 'parent_fds', 'guard_parents', 'close_parents'))]
        for raw, names in sources:
            for name in names:
                exec(compile(imports + definition(raw, name), '<guard-fixed-function>', 'exec', dont_inherit=True), self.backend)
        self.backend['os'] = self.os
        self.backend['subprocess'] = types.SimpleNamespace(Popen=forbidden, run=forbidden)
        self.backend['EXTERNAL'] = {'candidates': {'jdk17': str(self.jdk), 'jdk21': str(self.root / 'unused-jdk21')}, 'jdkFiles': list(files), 'selectedJdk': None}
        self.backend['EXTERNAL']['selectedJdk'] = self.backend['external_jdk']('jdk17')
        self.helper = {}
        raw = _bundle_source()
        tree = ast.parse(raw)
        names = {'_jdk_source_context', '_jdk_close_source_context', '_jdk_context_code_guard', '_jdk_bind_source_context'}
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names or isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in ('_JDK_FILES', '_JDK_ADAPTER') for target in node.targets)]
        self.helper.update({'ast': ast, 'copy': copy, 'hashlib': hashlib, 'json': json, 'os': os, 're': __import__('re'), 'stat': stat, 'types': types, 'Path': Path})
        exec(compile(ast.unparse(ast.Module(body=nodes, type_ignores=[])), '<actual-canonical-jdk-helper>', 'exec', dont_inherit=True), self.helper)
        exec(compile(definition(_bundle_source(), '_guard_backend'), '<actual-selected-guard>', 'exec', dont_inherit=True), self.helper)
        self.context = None

    def tearDown(self):
        if self.context is not None:
            self.context.close()
        live = sorted(self.os.live)
        for fd in live:
            self.os.close(fd)
        RESULTS.append({'test': self.id().split('.')[-1], 'opens': self.os.opens, 'closeAttempts': self.os.close_attempts, 'liveBeforeEmergencyFixtureClose': len(live), 'liveAfterClose': len(self.os.live), 'readBytes': self.os.read_bytes})
        self.temp.cleanup()
        self.assertEqual(live, [], 'actual context must close every owned descriptor')

    def bind(self):
        self.context = self.helper['_jdk_bind_source_context'](self.backend, 'api35', SELECTED['adapter'])
        return self.context

    def test_original_guard_accepts_actual_original_codes(self):
        pins = self.helper['_guard_backend'](SELECTED, self.backend, 'api35')
        self.assertIs(pins['external_file'][0], self.backend['external_file'])

    def test_join_guard_accepts_exact_pre_pin_adapter(self):
        self.bind()
        try:
            pins = self.helper['_guard_backend'](SELECTED, self.backend, 'api35')
        except ValueError as error:
            self.fail('actual guard refused the enrolled adapter: ' + str(error))
        self.assertIs(pins['external_file'][0], self.backend['external_file'])

    def test_adapter_reuse_refuses_instance_method_shadow(self):
        context = self.bind()
        self.helper['_guard_backend'](SELECTED, self.backend, 'api35')
        path = str(self.jdk / 'bin/java')
        context.external_file = lambda path, limit: ({'fixtureAcceptedShadow': True}, b'')
        with self.assertRaises(ValueError):
            self.backend['external_file'](path, 67108864)

    def test_adapter_reuse_refuses_method_code_mutation(self):
        context = self.bind()
        self.helper['_guard_backend'](SELECTED, self.backend, 'api35')
        method = type(context).external_file
        before = method.__code__

        def factory():
            fail = lambda value, code: None

            def replacement(self, path, limit):
                fail(True, 'own-fixture')
                return (dict(self.rows[str(path)]['fact']), b'')
            return replacement
        try:
            method.__code__ = factory().__code__
            with self.assertRaises(ValueError):
                self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)
        finally:
            method.__code__ = before

    def test_original_namespace_function_mutation_refuses(self):
        context = self.bind()
        context.original_namespace['external_file'] = lambda path, limit: ({}, b'')
        with self.assertRaises(ValueError):
            self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)

    def test_backend_selected_fact_mutation_refuses(self):
        self.bind()
        self.backend['EXTERNAL']['selectedJdk']['version'] = 'own-fixture-changed'
        with self.assertRaises(ValueError):
            self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)

    def test_actual_finish_refuses_rows_removal_and_closes_fds(self):
        context = self.bind()
        original = dict(context.rows)
        namespace = dict(self.helper)
        exec(compile(definition(_bundle_source(), 'finish_jdk_source_context'), '<actual-finish-jdk>', 'exec'), namespace)
        guard = types.SimpleNamespace(jdk_source_context=context, backend=self.backend, modules=SELECTED)
        try:
            context.rows.clear()
            with self.assertRaises(ValueError):
                namespace['finish_jdk_source_context'](guard)
            self.assertEqual(self.os.live, set(), 'actual finish must close every originally held descriptor')
        finally:
            context.rows.update(original)
            context.closed = False
            context.close()

    def test_adapter_reuse_refuses_fail_closure_replacement(self):
        context = self.bind()
        method = type(context).guard
        cell = method.__closure__[method.__code__.co_freevars.index('fail')]
        original = cell.cell_contents
        selected = copy.deepcopy(self.backend['EXTERNAL']['selectedJdk'])
        try:
            cell.cell_contents = lambda value, code: None
            self.backend['EXTERNAL']['selectedJdk']['version'] = 'own-fixture-closure-mutation'
            with self.assertRaises(ValueError):
                self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)
        finally:
            cell.cell_contents = original
            self.backend['EXTERNAL']['selectedJdk'] = selected

    def test_actual_finish_denial_attempts_close_despite_method_shadow(self):
        context = self.bind()
        namespace = dict(self.helper)
        exec(compile(definition(_bundle_source(), 'finish_jdk_source_context'), '<actual-finish-jdk>', 'exec'), namespace)
        guard = types.SimpleNamespace(jdk_source_context=context, backend=self.backend, modules=SELECTED)
        context.close = lambda: None
        try:
            with self.assertRaises(ValueError):
                namespace['finish_jdk_source_context'](guard)
            self.assertEqual(self.os.live, set(), 'actual finish must close held FDs after seal denial')
        finally:
            del context.close
            context.close()

    def test_adapter_returns_copies_and_original_closing_reads_files(self):
        context = self.bind()
        path = str(self.jdk / 'bin/java')
        fact, raw = self.backend['external_file'](path, 67108864)
        fact['generation'][0] = -1
        fact['sha256'] = '0' * 64
        again, unused = self.backend['external_file'](path, 67108864)
        self.assertEqual(again, self.backend['EXTERNAL']['selectedJdk']['files']['bin/java'])
        self.assertIsNot(context.original_namespace['external_file'], self.backend['external_file'])
        before = self.os.read_bytes
        context.closing()
        role_bytes = sum(((self.jdk / name).stat().st_size for name in self.backend['EXTERNAL']['jdkFiles']))
        self.assertEqual(self.os.read_bytes - before, role_bytes * 3, 'six held bodies plus two genuine original six-role passes')

    def test_checker_reference_replacement_refuses(self):
        context = self.bind()
        original = self.backend['_COMPONENT_JDK_SOURCE_CHECK']
        context.external_file = lambda path, limit: ({'fixtureAcceptedShadow': True}, b'')
        self.backend['_COMPONENT_JDK_SOURCE_CHECK'] = lambda: None
        try:
            with self.assertRaises(ValueError):
                self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)
        finally:
            self.backend['_COMPONENT_JDK_SOURCE_CHECK'] = original
            del context.external_file
    def test_checker_code_replacement_refuses(self):
        context = self.bind()
        original = self.backend['_COMPONENT_JDK_SOURCE_CHECK']
        code = original.__code__

        def factory():
            backend = context = guard_code = guard_function = None

            def unchecked():
                unused = (backend, context, guard_code, guard_function)
                return None
            return unchecked
        context.external_file = lambda path, limit: ({'fixtureAcceptedShadow': True}, b'')
        try:
            original.__code__ = factory().__code__
            with self.assertRaises(ValueError):
                self.backend['external_file'](str(self.jdk / 'bin/java'), 67108864)
        finally:
            original.__code__ = code
            del context.external_file


    def test_shared_temp_parent_churn_preserves_declared_fixture_view(self):
        original = self.os.fstat
        parent = self.root.parent.stat()
        identity = (parent.st_dev, parent.st_ino)
        sibling = []
        def interleave(fd):
            info = original(fd)
            actual = os.fstat(fd)
            if (actual.st_dev, actual.st_ino) == identity and not sibling:
                sibling.append(tempfile.TemporaryDirectory(prefix='jdk-source-sibling-control-', dir=self.root.parent))
                after = self.root.parent.stat()
                self.assertTrue(any(getattr(parent, name) != getattr(after, name) for name in
                    ('st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')))
            return info
        self.os.fstat = interleave
        try:
            context = self.bind()
            context.closing()
            self.assertEqual(len(sibling), 1)
        finally:
            self.os.fstat = original
            if self.context is not None:
                self.context.close()
            for item in sibling:
                item.cleanup()

    def test_owned_fixture_directory_churn_still_refuses(self):
        context = self.bind()
        child = self.root / 'owned-directory-change'
        child.mkdir()
        try:
            with self.assertRaisesRegex(ValueError, 'immutable_parent_changed'):
                context.guard()
        finally:
            context.close()
            child.rmdir()

    def test_owned_jdk_role_byte_change_still_refuses(self):
        context = self.bind()
        path = self.jdk / 'lib/libjava.so'
        path.write_bytes(path.read_bytes() + b'-changed')
        try:
            with self.assertRaisesRegex(ValueError, 'immutable_named_changed'):
                context.guard()
        finally:
            context.close()

if __name__ == '__main__':
    unittest.main()
