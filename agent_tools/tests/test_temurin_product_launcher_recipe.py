"""Routine inert image-recipe regressions; no JDK or native tool execution."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zlib

from agent_tools.tests.fixtures import temurin_product_launcher_recipe as fixture
from agent_tools.tests.fixtures import temurin_artifact_continuity as continuity


def namespace():
    ns = {'os': os, 'pathlib': __import__('pathlib'), 'stat': stat,
          'hashlib': hashlib, 'struct': struct, 'time': time, 'overall_deadline': time.monotonic() + 30}
    prerequisites = [n for n in ast.parse(continuity.FIXED_SOURCE).body
                     if isinstance(n, ast.FunctionDef) and n.name in ('fp', 'file_digest', 'elf_build_ids', 'parent_fds', 'guard_parents', 'close_parents')]
    nodes = prerequisites + ast.parse(fixture.RECIPE_SOURCE).body
    # Only principal observations adapt to this inert fixture's actual host.
    for n in ast.walk(ast.Module(body=nodes, type_ignores=[])):
        if isinstance(n, ast.Compare):
            for index, value in enumerate(n.comparators):
                if isinstance(value, ast.List) and len(value.elts) == 2 and all(isinstance(v, ast.Constant) and v.value == 1000 for v in value.elts):
                    n.comparators[index] = ast.parse(repr([os.getuid(), os.getgid()]), mode='eval').body
    exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<exact-image-recipe>', 'exec'), ns)
    return ns


class ProductLauncherRecipeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.ns = namespace()
        self.image = self.root / 'vpn-control'
        self.image.mkdir(mode=0o755)
        parsed = self.ns['recipe_config'](fixture.PINNED_CONFIG)
        # Real files under the exact fixed launcher layout. Their harmless bytes
        # exercise the actual copy/contract code rather than a fake inventory.
        content = {'bin/vpn-control': b'old-elf', 'lib/libapplauncher.so': b'old-dso',
                   'lib/app/vpn-control.cfg': fixture.PINNED_CONFIG,
                   'lib/runtime/release': b'JAVA_VERSION="17.0.20.1"\n',
                   'lib/vpn-control.png': b'inert-icon',
                   'lib/vpn-control-vpn-control.desktop': b'inert-desktop'}
        content.update({'lib/app/' + name: ('inert-' + name).encode() for name in parsed['jars']})
        self.originals = []
        for name, raw in content.items():
            p = self.image / name
            p.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            p.write_bytes(raw)
            mode = 0o755 if name in ('bin/vpn-control', 'lib/libapplauncher.so') else 0o644
            p.chmod(mode)
            self.originals.append({'path': 'opt/vpn-control/' + name, 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode})
        self.directories = [{'path': 'opt/vpn-control' + ('/' + str(p.relative_to(self.image)) if p != self.image else ''), 'mode': stat.S_IMODE(p.stat().st_mode)} for p in [self.image, *self.image.rglob('*')] if p.is_dir()]
        (self.image / 'lib/vpn-control-vpn-control.desktop').unlink()
        # Use retained official ELF bytes; never execute them.
        elf = zlib.decompress(base64.b64decode(continuity.OFFICIAL_TOOL_ELF_ZLIB_BASE64['java']))
        for name in ('bin/vpn-control', 'lib/libapplauncher.so'):
            p = self.image / name
            p.write_bytes(elf)
            p.chmod(0o755)
        self.xml = b'<?xml version="1.0" ?>\n<jpackage-state version="17.0.20.1" platform="linux">\n  <app-version>2.2.2</app-version>\n  <main-launcher>vpn-control</main-launcher>\n  <signed>false</signed></jpackage-state>'
        (self.image / 'lib/app/.jpackage.xml').write_bytes(self.xml)
        (self.image / 'lib/app/.jpackage.xml').chmod(0o644)
        self.hold = None

    def tearDown(self):
        self.ns['recipe_close'](self.hold)
        self.temp.cleanup()

    def capture(self):
        self.hold = self.ns['recipe_walk'](self.image, True)
        return self.hold

    def contract(self):
        return self.ns['recipe_output_contract'](self.hold, self.originals, fixture.PINNED_CONFIG, self.directories)

    def test_actual_config_has_57_exact_ordered_jars_and_four_options(self):
        self.assertEqual(hashlib.sha256(fixture.PINNED_CONFIG).hexdigest(), fixture.PINNED_CONFIG_SHA256)
        observed = self.ns['recipe_config'](fixture.PINNED_CONFIG)
        self.assertEqual(len(observed['jars']), 57)
        self.assertEqual(len(observed['options']), 4)
        for old, new in [(b'2.2.2', b'2.2.3'), (b'configure.swing.globals=true', b'configure.swing.globals=fals'), (b'[Application]', b'[Applicatiox]')]:
            with self.subTest(old=old), self.assertRaises(ValueError):
                self.ns['recipe_config'](fixture.PINNED_CONFIG.replace(old, new))

    def test_fixed_command_keeps_runtime_and_three_explicit_options(self):
        command = self.ns['recipe_argv'](self.root / 'jdk', self.root)
        self.assertEqual(command.count('--java-options'), 3)
        self.assertIn('--runtime-image', command)
        self.assertNotIn('--add-modules', command)
        self.assertNotIn('--add-launcher', command)
        self.assertEqual(command[command.index('--app-version') + 1], '2.2.2')

    def test_actual_complete_image_contract_preserves_inputs(self):
        self.capture()
        result = self.contract()
        self.assertTrue(result['runtimeUnchanged'])
        self.assertTrue(result['configUnchanged'])
        self.assertEqual(result['originalJarCount'], 57)

    def test_full_real_source_fd_copy_then_origin_drift_refusal(self):
        source = self.root / 'source'
        source.write_bytes(b'official-input')
        source.chmod(0o644)
        target = self.root / 'target'
        target.mkdir(mode=0o700)
        sf = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        df = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        row = {'size': 14, 'sha256': hashlib.sha256(b'official-input').hexdigest(), 'mode': 0o644}
        try:
            self.ns['recipe_file_copy'](sf, df, 'copied', row)
            self.assertEqual((target / 'copied').read_bytes(), b'official-input')
            with self.assertRaises(FileExistsError):
                self.ns['recipe_file_copy'](sf, df, 'copied', row)
            source.write_bytes(b'foreign-input!')
            with self.assertRaisesRegex(ValueError, 'recipe_source_changed'):
                self.ns['recipe_file_copy'](sf, df, 'drift', row)
        finally:
            os.close(sf)
            os.close(df)

    def test_contract_refuses_reordered_cfg_even_unchanged_semantic_set(self):
        p = self.image / 'lib/app/vpn-control.cfg'
        lines = fixture.PINNED_CONFIG.splitlines(keepends=True)
        lines[3], lines[4] = lines[4], lines[3]
        p.write_bytes(b''.join(lines))
        self.capture()
        with self.assertRaises(ValueError):
            self.contract()

    def test_contract_refuses_runtime_jar_metadata_elf_and_extra_mutation(self):
        for relative in ('lib/runtime/release', 'lib/app/' + self.ns['recipe_config'](fixture.PINNED_CONFIG)['jars'][0], 'lib/app/.jpackage.xml', 'bin/vpn-control'):
            with self.subTest(relative=relative):
                path = self.image / relative
                old = path.read_bytes()
                path.write_bytes(b'foreign-content')
                hold = self.ns['recipe_walk'](self.image, True)
                try:
                    with self.assertRaises(ValueError):
                        self.ns['recipe_output_contract'](hold, self.originals, fixture.PINNED_CONFIG, self.directories)
                finally:
                    self.ns['recipe_close'](hold)
                    path.write_bytes(old)
        (self.image / 'extra').write_bytes(b'extra')
        self.capture()
        with self.assertRaisesRegex(ValueError, 'recipe_output_catalogue'):
            self.contract()

    def test_generation_closes_early_leaf_after_later_digest_reads(self):
        self.capture()
        (self.image / 'lib/runtime/release').write_bytes(b'foreign-content')
        with self.assertRaisesRegex(ValueError, 'recipe_tree_changed'):
            self.ns['recipe_generation_close'](self.hold)

    def test_late_catalogue_read_cannot_relabel_changed_earlier_native_file(self):
        self.capture()
        original = os.listdir
        trigger = self.hold['directories']['lib/app']
        changed = []
        def listdir(fd):
            names = original(fd)
            if fd == trigger and not changed:
                (self.image / 'bin/vpn-control').write_bytes(b'foreign-native-image')
                changed.append(True)
            return names
        with patch.object(os, 'listdir', listdir), self.assertRaisesRegex(ValueError, 'recipe_tree_changed'):
            self.ns['recipe_generation_close'](self.hold)
        self.assertEqual(changed, [True])

    def test_authenticated_old_closure_accepts_exact_measured_late_mutation(self):
        self.capture()
        self.assertEqual(hashlib.sha256(fixture.OLD_RECIPE_GENERATION_SOURCE.encode()).hexdigest(), fixture.OLD_RECIPE_GENERATION_SHA256)
        exec(compile(fixture.OLD_RECIPE_GENERATION_SOURCE, '<authenticated-held-689d-generation>', 'exec'), self.ns)
        original = os.listdir
        trigger = self.hold['directories']['lib/app']
        changed = []
        def listdir(fd):
            names = original(fd)
            if fd == trigger and not changed:
                (self.image / 'bin/vpn-control').write_bytes(b'foreign-native-image')
                changed.append(True)
            return names
        with patch.object(os, 'listdir', listdir):
            self.ns['recipe_generation_close'](self.hold)
        self.assertEqual(changed, [True])
        self.assertEqual((self.image / 'bin/vpn-control').read_bytes(), b'foreign-native-image')

    @unittest.skipIf(os.name != 'posix', 'POSIX symlinks required')
    def test_real_fifo_symlink_and_directory_replacement_refuse_without_read(self):
        p = self.image / 'lib/runtime/release'
        p.unlink()
        os.mkfifo(p)
        start = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'recipe_tree_shape'):
            self.capture()
        self.assertLess(time.monotonic() - start, 2)
        p.unlink()
        p.symlink_to(self.image / 'lib/vpn-control.png')
        with self.assertRaises(ValueError):
            self.capture()

    def test_expired_copy_refuses_before_any_source_acceptance(self):
        source = self.root / 'source'
        source.write_bytes(b'input')
        sf = os.open(source, os.O_RDONLY)
        df = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        self.ns['overall_deadline'] = time.monotonic() - 1
        try:
            with self.assertRaisesRegex(ValueError, 'recipe_timeout'):
                self.ns['recipe_file_copy'](sf, df, 'expired', {'size': 5, 'sha256': hashlib.sha256(b'input').hexdigest(), 'mode': 0o644})
        finally:
            os.close(sf)
            os.close(df)

    def fixture_parent_namespace(self, ns, root):
        """Install a test-only FD ancestry boundary below the shared temp root.

        The authenticated helper deliberately pins every ancestor.  A routine
        fixture cannot retain the process-wide temporary directory as though it
        were owned: parallel harmless fixture allocation changes its catalogue.
        This boundary starts at this test's already-created root, then preserves
        the exact held/named nine-field generation check for that root and every
        descendant.
        """
        boundary = Path(root).resolve()

        def close_parents(chain):
            for item in reversed(chain):
                os.close(item['fd'])

        def guard_parents(chain):
            for item in chain:
                if item['path'] is None:
                    continue
                if ns['fp'](os.fstat(item['fd'])) != item['pin'] or ns['fp'](os.stat(item['path'], follow_symlinks=False)) != item['pin']:
                    raise ValueError('census_ancestry_changed')

        def parent_fds(path):
            target = Path(path).resolve()
            try:
                relative = target.relative_to(boundary)
            except ValueError:
                raise ValueError('census_ancestry_invalid') from None
            if not relative.parts:
                raise ValueError('census_ancestry_invalid')
            chain = []
            try:
                current = boundary
                fd = os.open(current, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                # SOURCE_RETAINER keys its cache by the absolute component
                # index.  Preserve that ABI with inert duplicate descriptors
                # for ancestors above this test-owned boundary; they never
                # grant a directory-relative operation because the final FD is
                # always the actual owned parent below.
                for _ in range(len(boundary.parts) - 1):
                    duplicate = os.dup(fd)
                    chain.append({'fd': duplicate, 'path': None, 'pin': ns['fp'](os.fstat(duplicate))})
                chain.append({'fd': fd, 'path': current, 'pin': ns['fp'](os.fstat(fd))})
                for name in relative.parts[:-1]:
                    current /= name
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=chain[-1]['fd'])
                    chain.append({'fd': fd, 'path': current, 'pin': ns['fp'](os.fstat(fd))})
                guard_parents(chain)
                return chain, relative.name
            except BaseException:
                close_parents(chain)
                raise

        ns.update(parent_fds=parent_fds, guard_parents=guard_parents, close_parents=close_parents)

    def constructor_namespace(self, precreate=True, fixture_namespace_root=None):
        import pathlib
        stage = self.root / 'stage-root/android-cli-stage-inert'
        source = stage / 'tree'
        source.mkdir(parents=True)
        rows = list(self.originals)
        # The constructor receives the production fixed 155-record carrier
        # shape; harmless retained files fill package records outside its input.
        while len(rows) < 153:
            raw = b'unchanged-extra'
            rows.append({'path': 'extra-' + str(len(rows)), 'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o644})
        pre = {}
        for row in rows:
            target = source / row['path']
            target.parent.mkdir(parents=True, exist_ok=True)
            relative = row['path'].removeprefix('opt/vpn-control/')
            if relative in ('bin/vpn-control', 'lib/libapplauncher.so'):
                raw = b'old-elf' if relative.startswith('bin') else b'old-dso'
            elif relative == 'lib/vpn-control-vpn-control.desktop':
                raw = b'inert-desktop'
            elif row['path'].startswith('extra-'):
                raw = b'unchanged-extra'
            else:
                raw = (self.image / relative).read_bytes()
            target.write_bytes(raw)
            target.chmod(row['mode'])
            pre[row['path']] = {'generation': self.ns['fp'](target.stat())}
        for name in ('intent.json', 'receipt.json'):
            path = stage / name
            path.write_bytes(b'{}')
            pre[name] = {'generation': self.ns['fp'](path.stat())}
        ns = self.ns
        prior = [n for n in ast.parse(continuity.FIXED_SOURCE).body if isinstance(n, ast.FunctionDef) and n.name in ('parent_fds', 'guard_parents', 'close_parents')]
        actual = prior + ast.parse(fixture.SOURCE_RETAINER).body + [n for n in ast.parse(fixture.REPAIR_SOURCE).body if isinstance(n, ast.FunctionDef) and n.name == 'recipe_stage_inputs']
        exec(compile(ast.fix_missing_locations(ast.Module(body=actual, type_ignores=[])), '<actual-retainer-constructor>', 'exec'), ns)
        if fixture_namespace_root is not None:
            self.fixture_parent_namespace(ns, fixture_namespace_root)
        ns.update(ROOT=self.root / 'stage-root', GETTER={'stageId': 'inert', 'manifest': {'files': rows, 'directories': [{'path': 'opt', 'mode': 0o755}, *self.directories]}}, pre=pre, held=[], parent_cache={}, build_root=self.root / 'build', product_copy_origins={})
        ns['build_root'].mkdir(mode=0o700)
        for name in ('input', 'runtime', 'icon', 'audit', 'image') if precreate else ():
            (ns['build_root'] / name).mkdir(mode=0o700)
        ns['retain_stage'](pre)
        return ns

    def close_constructor(self, ns):
        for chain, leaf, fd, pin in ns['held']:
            os.close(fd)
        for row in ns['parent_cache'].values():
            os.close(row['fd'])

    def test_actual_stage_retainer_and_constructor_copy_into_separate_owned_roots(self):
        ns = self.constructor_namespace()
        try:
            observed = ns['recipe_stage_inputs']()
            self.assertEqual(observed, fixture.PINNED_CONFIG)
            self.assertEqual((ns['build_root'] / 'runtime/release').read_bytes(), b'JAVA_VERSION="17.0.20.1"\n')
            self.assertEqual(len(list((ns['build_root'] / 'input').glob('*.jar'))), 57)
            ns['held_guard']()
        finally:
            self.close_constructor(ns)

    def test_fixture_namespace_ignores_outer_temp_churn_but_pins_its_owned_root(self):
        ns = self.constructor_namespace(precreate=False, fixture_namespace_root=self.root)
        chain, _ = ns['parent_fds'](self.root / 'stage-root/android-cli-stage-inert/intent.json')
        try:
            self.assertTrue(any(item['path'] is None for item in chain))
            self.assertEqual(next(item['path'] for item in chain if item['path'] is not None), self.root)
            (self.root / 'owned-root-generation-change').mkdir()
            with self.assertRaisesRegex(ValueError, 'census_ancestry_changed'):
                ns['guard_parents'](chain)
        finally:
            ns['close_parents'](chain)
            self.close_constructor(ns)

    def test_copy_birth_hash_survives_inventory_admission_gap(self):
        source = self.root / 'copy-source'
        source.write_bytes(b'official-app-input')
        dest = self.root / 'copied-input'
        dest.mkdir(mode=0o700)
        sf = os.open(source, os.O_RDONLY)
        df = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
        held = None
        try:
            origin = self.ns['recipe_file_copy'](sf, df, 'app.jar', {'size': 18, 'sha256': hashlib.sha256(b'official-app-input').hexdigest(), 'mode': 0o644})
            origins = {'.': {'type': 'directory', 'generation': self.ns['fp'](os.fstat(df)), 'names': ['app.jar']}, 'app.jar': origin}
            (dest / 'app.jar').write_bytes(b'foreign-app-input')
            held = self.ns['recipe_walk'](dest, True)
            with self.assertRaisesRegex(ValueError, 'recipe_copy_origin_changed'):
                self.ns['recipe_copy_origin_close'](held, origins)
        finally:
            self.ns['recipe_close'](held)
            os.close(sf)
            os.close(df)

    def test_authenticated_old_copy_walk_guard_adopts_reviewed_foreign_bytes(self):
        source = self.root / 'old-copy-source'
        source.write_bytes(b'official-app-input')
        dest = self.root / 'old-copied-input'
        dest.mkdir(mode=0o700)
        ns = namespace()
        self.assertEqual(hashlib.sha256(fixture.OLD_COPIED_INPUT_SOURCE.encode()).hexdigest(), fixture.OLD_COPIED_INPUT_SHA256)
        nodes = ast.parse(fixture.OLD_COPIED_INPUT_SOURCE).body
        for node in ast.walk(ast.Module(body=nodes, type_ignores=[])):
            if isinstance(node, ast.Compare):
                for index, value in enumerate(node.comparators):
                    if isinstance(value, ast.List) and len(value.elts) == 2 and all(isinstance(v, ast.Constant) and v.value == 1000 for v in value.elts):
                        node.comparators[index] = ast.parse(repr([os.getuid(), os.getgid()]), mode='eval').body
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<authenticated-held-23d9-copy-functions>', 'exec'), ns)
        sf = os.open(source, os.O_RDONLY)
        df = os.open(dest, os.O_RDONLY | os.O_DIRECTORY)
        held = None
        try:
            ns['recipe_file_copy'](sf, df, 'app.jar', {'size':18, 'sha256':hashlib.sha256(b'official-app-input').hexdigest(), 'mode':0o644})
            (dest / 'app.jar').write_bytes(b'foreign-app-input')
            held = ns['recipe_walk'](dest, True)
            ns['recipe_generation_close'](held)
            self.assertEqual(held['rows']['app.jar']['sha256'], hashlib.sha256(b'foreign-app-input').hexdigest())
        finally:
            ns['recipe_close'](held)
            os.close(sf)
            os.close(df)

    def whole_producer_barrier(self, mutate, metadata=False):
        # Execute the entire actual run_hello_gate with all physical guards.
        # Only the effect boundary is replaced by a sentinel; there is no Java.
        import resource
        import posixpath
        from uuid import uuid4
        class BarrierReached(Exception):
            pass
        artifact = self.root / 'unit-source'
        artifact.mkdir(mode=0o700)
        (artifact / 'jdk-tree').mkdir(mode=0o700)
        archive = artifact / 'temurin.tar.gz'
        archive.write_bytes(b'owned-unit-archive')
        archive.chmod(0o600)
        boot = self.root / 'measured-fixture-boot'
        boot.write_text(str(uuid4()))
        prior = self.root / 'prior-native'
        if metadata:
            prior.mkdir(mode=0o700)
            (prior / 'audit').mkdir(mode=0o700)
        ns = self.constructor_namespace(precreate=False, fixture_namespace_root=self.root)
        nodes = ast.parse(fixture.KERNEL_RUNNER_SOURCE).body + ast.parse(fixture.REPAIR_SOURCE).body + (ast.parse(fixture.METADATA_SOURCE).body if metadata else [])
        for node in ast.walk(ast.Module(body=nodes, type_ignores=[])):
            if isinstance(node, ast.Constant) and node.value == '/proc/sys/kernel/random/boot_id':
                node.value = str(boot)
            if isinstance(node, ast.Constant) and node.value == '/proc/self/fd' and sys.platform != 'linux':
                node.value = '/dev/fd'
            if isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    if isinstance(key, ast.Constant) and isinstance(value, ast.Constant) and value.value == 1000:
                        value.value = os.getuid() if key.value in ('uid', 'euid') else os.getgid()
            if isinstance(node, ast.Compare):
                for index, value in enumerate(node.comparators):
                    if isinstance(value, ast.List) and len(value.elts) == 2 and all(isinstance(x, ast.Constant) and x.value == 1000 for x in value.elts):
                        node.comparators[index] = ast.parse(repr([os.getuid(), os.getgid()]), mode='eval').body
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute):
                for value in node.comparators:
                    if isinstance(value, ast.Constant) and value.value == 1000:
                        value.value = os.getuid() if node.left.attr == 'st_uid' else os.getgid()
                if sys.platform == 'darwin' and node.left.attr == 'st_nlink':
                    for index, value in enumerate(node.comparators):
                        if isinstance(value, ast.Constant) and value.value == 2:
                            node.comparators[index] = ast.parse('2 + len(os.listdir(audit_fd))', mode='eval').body
        exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<actual-entire-copy-to-jpackage-barrier>', 'exec'), ns)
        ns.update(re=__import__('re'),resource=resource, posixpath=posixpath, json=json, SOURCE_TREE_DIR=artifact, JDK_ROOT_NAME='jdk-17.0.20.1+1', CORRELATION=str(uuid4()), ARTIFACT_SHA=hashlib.sha256(archive.read_bytes()).hexdigest(), EXPECTED_BOOT=boot.read_text(), EXPECTED_GROUPS=os.getgroups(), identity_host={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}, FILE_LIMIT=resource.getrlimit(resource.RLIMIT_FSIZE), FD_LIMIT=resource.getrlimit(resource.RLIMIT_NOFILE), collector_fd_demand=None, product_input_holds=[], product_output_hold=None, product_copy_origins={}, audit_fd=None, role_index=0, producer_pass=False)
        result = ns['build_root']
        result_chain, name = ns['parent_fds'](result)
        result_fd = os.open(result, os.O_RDONLY | os.O_DIRECTORY)
        archive_chain, archive_name = ns['parent_fds'](archive)
        archive_fd = os.open(archive, os.O_RDONLY)
        archive_pin = ns['fp'](os.fstat(archive_fd))
        root_pin = ns['fp']((artifact / 'jdk-tree').stat())
        ns.update(result_chain=result_chain, result_fd=result_fd, result_dir=result, result_identity=ns['fp'](os.fstat(result_fd))[:2]+ns['fp'](os.fstat(result_fd))[5:8], archive_chain=archive_chain, archive_name=archive_name, archive_fd=archive_fd, archive_open_fd=archive_fd, archive_pin=archive_pin, SOURCE_ARCHIVE_PIN=archive_pin, overall_deadline=time.monotonic()+30)
        ns['final_tree'] = ns['hold_tree']({}, [{'path':'.', 'type':'directory', 'generation':root_pin}], ns['overall_deadline'])
        if metadata:
            # Synthetic carrier filler paths are outside the harmless app image.
            ns['GETTER']['manifest']['files'] = self.originals
            observed = ns['recipe_walk'](self.image, True)
            rows = observed['rows']
            contract = ns['recipe_output_contract'](observed, self.originals, fixture.PINNED_CONFIG, self.directories)
            ns['recipe_close'](observed)
            terminal = json.dumps({'inertFixtureOnly': '0'*5000}).encode()
            ns.update(METADATA_PARENT=prior, METADATA_IMAGE=self.image, METADATA_SOURCE_CORRELATION='inert-prior', METADATA_TERMINAL_RAW=terminal, METADATA_TERMINAL_SHA=hashlib.sha256(terminal+b'\n').hexdigest(), METADATA_HELP=fixture.METADATA_HELP, metadata_audit_fd=None, metadata_audit_pin=None, metadata_journal_holds=[],metadata_chain=[],metadata_output_origin={})
            af = os.open(prior/'audit', os.O_RDONLY|os.O_DIRECTORY)
            try:
                for name, raw in [('terminal-proof.json',terminal),('product-image-inventory.json',json.dumps(rows,sort_keys=True,separators=(',',':')).encode()),('product-image-contract.json',json.dumps(contract,sort_keys=True).encode())]:
                    ns['write_record'](af,name,raw)
                os.fsync(af)
            finally:
                os.close(af)
        calls = []
        def barrier(command, **kwargs):
            self.assertEqual(ns['validate_role'](command, kwargs), ('product-version','product-help')[len(calls)] if metadata else 'product-jpackage')
            ns['producer_guards']()
            ns['generated_image_guard']()
            if metadata:
                calls.append(command)
                if mutate == 'metadata-stderr':
                    value = __import__('subprocess').CompletedProcess(command, 0, '2.2.2\n', 'pure virtual method called\n')
                else:
                    value = __import__('subprocess').CompletedProcess(command, 0, '2.2.2\n' if len(calls) == 1 else fixture.METADATA_HELP, '')
                ns['role_index'] += 1
                return value
            journal = result / 'audit'
            manifest = json.loads((journal / 'copied-input-origins.json.manifest.json').read_bytes())
            self.assertEqual(set(manifest), {'bytes', 'sha256', 'partBytes', 'partCount'})
            self.assertEqual(manifest['partBytes'], 4096)
            raw = b''.join((journal / ('copied-input-origins.json.part-' + str(i))).read_bytes() for i in range(manifest['partCount']))
            self.assertEqual(len(raw), manifest['bytes'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), manifest['sha256'])
            recorded = json.loads(raw)
            self.assertEqual(recorded, ns['product_copy_origins'])
            self.assertEqual(set(recorded), {'input', 'runtime', 'icon'})
            self.assertTrue((result / 'audit/product-dispatch-fence.json').is_file())
            calls.append(command)
            raise BarrierReached()
        ns['fixed_runner'] = barrier
        # The hook mutates a completed copy just before its actual inventory
        # scan, reproducing the reviewer's exact admission window.
        actual_walk = ns['recipe_walk']
        def walk(path, hold):
            if metadata and mutate == 'metadata-image-drift' and path == self.image:
                (self.image / 'bin/vpn-control').write_bytes(b'foreign-generated-native')
            if mutate is True and path == result / 'input':
                name = ns['recipe_config'](fixture.PINNED_CONFIG)['jars'][0]
                (path / name).write_bytes(b'foreign-app-input')
            return actual_walk(path, hold)
        ns['recipe_walk'] = walk
        # FD admission is a measured procfs observation. On non-Linux hosts use
        # the physical process FD directory, without asserting a false count.
        fd_path = '/proc/self/fd' if sys.platform == 'linux' else '/dev/fd'
        admit = ast.parse(fixture.RECIPE_SOURCE)
        fn = next(n for n in admit.body if isinstance(n, ast.FunctionDef) and n.name == 'recipe_admit_fds')
        for node in ast.walk(fn):
            if isinstance(node, ast.Constant) and node.value == '/proc/self/fd':
                node.value = fd_path
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])), '<measured-fixture-fd-admission>', 'exec'), ns)
        original_listdir = os.listdir
        late_changed = []
        def listdir(fd):
            names = original_listdir(fd)
            if mutate in ('late-catalogue', 'late-jdk-catalogue') and len(ns['product_input_holds']) == 3 and not late_changed:
                runtime = next(item for item in ns['product_input_holds'] if item['root'].name == 'runtime')
                if (mutate == 'late-catalogue' and fd == runtime['directories']['.']) or (mutate == 'late-jdk-catalogue' and fd == ns['final_tree']['.']['fd'] and sys._getframe(1).f_code.co_name == 'generation_tree_closure' and sys._getframe(2).f_code.co_name == 'generated_image_guard' and any(frame.function == 'barrier' for frame in __import__('inspect').stack())):
                    name = ns['recipe_config'](fixture.PINNED_CONFIG)['jars'][0]
                    (result / 'input' / name).write_bytes(b'foreign-late-app-input')
                    late_changed.append(True)
            return names
        try:
            with patch.object(os, 'listdir', listdir):
                if metadata:
                    if mutate == 'metadata-stderr':
                        with self.assertRaisesRegex(ValueError, 'producer_strict_gate_failed'):
                            ns['run_hello_gate']()
                        self.assertEqual(len(calls), 1)
                    elif mutate == 'metadata-image-drift':
                        with self.assertRaisesRegex(ValueError, 'recipe_copy_origin_changed'):
                            ns['run_hello_gate']()
                        self.assertEqual(calls, [])
                    else:
                        ns['run_hello_gate']()
                        self.assertTrue(ns['producer_pass'])
                        self.assertEqual(calls, [[str(self.image/'bin/vpn-control'),'--version'],[str(self.image/'bin/vpn-control'),'--help']])
                    ns['metadata_journal_close']()
                elif mutate:
                    reason = 'recipe_tree_changed' if mutate in ('late-catalogue', 'late-jdk-catalogue') else 'recipe_copy_origin_changed'
                    with self.assertRaisesRegex(ValueError, reason):
                        ns['run_hello_gate']()
                    self.assertEqual(calls, [])
                    if mutate in ('late-catalogue', 'late-jdk-catalogue'):
                        self.assertEqual(late_changed, [True])
                else:
                    with self.assertRaises(BarrierReached):
                        ns['run_hello_gate']()
                    self.assertEqual(len(calls), 1)
        finally:
            if metadata:
                for _,fd,_ in ns['metadata_journal_holds']:os.close(fd)
                if ns['metadata_audit_fd'] is not None:os.close(ns['metadata_audit_fd'])
                ns['close_parents'](ns['metadata_chain'])
                ns['recipe_close'](ns['product_output_hold'])
            for hold in ns['product_input_holds']:
                ns['recipe_close'](hold)
            ns['close_tree'](ns['final_tree'])
            if ns['audit_fd'] is not None:
                os.close(ns['audit_fd'])
            for fd in (archive_fd, result_fd):
                os.close(fd)
            ns['close_parents'](archive_chain)
            ns['close_parents'](result_chain)
            self.close_constructor(ns)

    def test_whole_copy_walk_guard_to_producer_barrier_has_no_adoption(self):
        self.whole_producer_barrier(True)

    def test_whole_copy_walk_guard_reaches_only_fixed_barrier_with_original_inputs(self):
        self.whole_producer_barrier(False)

    def test_whole_metadata_saved_image_admission_and_two_fixed_roles(self):
        self.whole_producer_barrier(False, metadata=True)

    def test_whole_metadata_image_replacement_refuses_before_version(self):
        self.whole_producer_barrier('metadata-image-drift', metadata=True)

    def test_whole_metadata_preserves_pure_virtual_stderr_refusal(self):
        self.whole_producer_barrier('metadata-stderr', metadata=True)

    def test_whole_jdk_catalogue_cannot_mutate_already_checked_input(self):
        self.whole_producer_barrier('late-jdk-catalogue')

    def test_whole_pre_release_closure_finishes_all_tree_body_reads_first(self):
        self.whole_producer_barrier('late-catalogue')

    def test_actual_complete_cleanup_keeps_audit_parent_until_last_use(self):
        close_tree = next(n for n in ast.parse(continuity.FIXED_SOURCE).body if isinstance(n, ast.FunctionDef) and n.name == 'close_tree')
        guard = ast.parse(fixture.AUDIT_GUARD_SOURCE).body[0]
        for node in ast.walk(guard):
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Attribute) and node.left.attr in ('st_uid', 'st_gid'):
                for index, value in enumerate(node.comparators):
                    if isinstance(value, ast.Constant) and value.value == 1000:
                        node.comparators[index] = ast.Constant(os.getuid() if node.left.attr == 'st_uid' else os.getgid())
        for source, fails in ((fixture.CLEANUP_OLD_SOURCE, True), (fixture.CLEANUP_CURRENT_SOURCE, False)):
            with self.subTest(old=fails):
                root = self.root / ('old-cleanup' if fails else 'current-cleanup')
                root.mkdir(mode=0o700)
                audit = root / 'audit'
                audit.mkdir(mode=0o700)
                result_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                audit_fd = os.open(audit, os.O_RDONLY | os.O_DIRECTORY)
                ns = namespace()
                exec(compile(ast.fix_missing_locations(ast.Module(body=[close_tree, guard], type_ignores=[])), '<actual-audit-cleanup-functions>', 'exec'), ns)
                pin = ns['fp'](os.fstat(audit_fd))
                ns.update(final_tree={}, archive_fd=None, archive_chain=[], held=[], parent_cache={}, result_chain=[], result_fd=result_fd, product_output_hold=None, product_input_holds=[], audit_fd=audit_fd, audit_identity=pin[:2] + pin[5:8])
                try:
                    if fails:
                        with self.assertRaises(OSError):
                            exec(compile(source, '<actual-old-complete-cleanup>', 'exec'), ns)
                    else:
                        exec(compile(source, '<actual-current-complete-cleanup>', 'exec'), ns)
                        for fd in (result_fd, audit_fd):
                            with self.assertRaises(OSError):
                                os.fstat(fd)
                finally:
                    for fd in (result_fd, audit_fd):
                        try:
                            os.close(fd)
                        except OSError:
                            pass

    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'pidfd_open'), 'Actual Linux PIDfd/subreaper kernel required; no native acceptance inferred')
    def test_actual_runner_real_fdpipe_raw_and_timeout_owned_child(self):
        import ctypes
        import resource
        import select
        import signal
        import subprocess
        import tarfile
        import posixpath
        # This is a harmless owned script, never Java/jpackage. Every runner,
        # source, ancestry, boot, principal, archive and cleanup guard is actual.
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                base = self.root / ('timeout-kernel' if timeout else 'raw-kernel')
                base.mkdir(mode=0o700)
                source = base / 'source'
                source.mkdir(mode=0o700)
                result = base / 'result'
                result.mkdir(mode=0o700)
                for name in ('audit', 'home', 'input', 'runtime', 'icon', 'image'):
                    (result / name).mkdir(mode=0o700)
                tool = source / 'jdk-tree/jdk-17.0.20.1+1/bin/jpackage'
                tool.parent.mkdir(parents=True)
                program = '#!' + sys.executable + '\nimport os,time\nos.write(1,b"owned-stdout\\n");os.write(2,b"owned-stderr\\n")\n' + ('time.sleep(30)\n' if timeout else '')
                tool.write_text(program)
                tool.chmod(0o700)
                archive = source / 'temurin.tar.gz'
                archive.write_bytes(b'owned-unit-archive')
                archive.chmod(0o600)
                ns = namespace()
                ns.update(ctypes=ctypes, resource=resource, select=select, signal=signal, subprocess=subprocess, json=json, base64=base64, posixpath=posixpath)
                nodes = ast.parse(fixture.KERNEL_RUNNER_SOURCE).body
                for node in ast.walk(ast.Module(body=nodes, type_ignores=[])):
                    if isinstance(node, ast.Constant) and node.value == 1000:
                        node.value = os.getuid()  # CI fixture UID/GID are equal.
                self.assertEqual(os.getuid(), os.getgid())
                exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])), '<actual-owned-kernel-runner>', 'exec'), ns)
                result_chain, name = ns['parent_fds'](result)
                result_fd = os.open(result, os.O_RDONLY | os.O_DIRECTORY)
                audit_fd = os.open(result / 'audit', os.O_RDONLY | os.O_DIRECTORY)
                archive_chain, archive_name = ns['parent_fds'](archive)
                archive_fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW)
                pin = ns['fp'](os.fstat(archive_fd))
                ns.update(SOURCE_TREE_DIR=source, JDK_ROOT_NAME='jdk-17.0.20.1+1', build_root=result, build_home=result / 'home', CHILD_ENV={'HOME': str(result / 'home'), 'PATH': '/usr/bin:/bin'}, FD_LIMIT=resource.getrlimit(resource.RLIMIT_NOFILE), FILE_LIMIT=resource.getrlimit(resource.RLIMIT_FSIZE), collector_fd_demand=None, EXPECTED_BOOT=Path('/proc/sys/kernel/random/boot_id').read_text().strip(), EXPECTED_GROUPS=os.getgroups(), identity_host={'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':os.getgroups()}, result_dir=result, result_chain=result_chain, result_fd=result_fd, result_identity=ns['fp'](os.fstat(result_fd))[:2]+ns['fp'](os.fstat(result_fd))[5:8], audit_fd=audit_fd, audit_identity=ns['fp'](os.fstat(audit_fd))[:2]+ns['fp'](os.fstat(audit_fd))[5:8], archive_chain=archive_chain, archive_name=archive_name, archive_fd=archive_fd, archive_open_fd=archive_fd, archive_pin=pin, SOURCE_ARCHIVE_PIN=pin, held=[], image_holds=[], product_input_holds=[], product_output_hold=None, role_index=0, command_records=[], producer_raw_bytes=0, overall_deadline=time.monotonic()+12, PRODUCER_KNOWN={'producer_command_timeout','producer_command_unknown','producer_closing_unknown'}, original_subreaper=None, owned_descendants={}, child_deadline=None, wait_status=None, process=None)
                rows = []
                entries = {}
                for path in [source / 'jdk-tree', *sorted((source / 'jdk-tree').rglob('*'))]:
                    relative = str(path.relative_to(source / 'jdk-tree'))
                    info = path.stat()
                    row = {'path': relative, 'type': 'directory' if path.is_dir() else 'file', 'generation': ns['fp'](info)}
                    if path.is_file():
                        row.update(bytes=info.st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(), elf=False, buildIds=[], linkTarget=None)
                    rows.append(row)
                    if relative != '.':
                        entry = tarfile.TarInfo(relative)
                        entry.type = tarfile.DIRTYPE if path.is_dir() else tarfile.REGTYPE
                        entries[relative] = entry
                ns['final_tree'] = ns['hold_tree'](entries, rows, ns['overall_deadline'])
                try:
                    command = ns['recipe_argv'](source / 'jdk-tree/jdk-17.0.20.1+1', result)
                    if timeout:
                        with self.assertRaisesRegex(ValueError, 'producer_command_timeout'):
                            ns['fixed_runner'](command, check=False, capture_output=True, text=True, timeout=300)
                    else:
                        response = ns['fixed_runner'](command, check=False, capture_output=True, text=True, timeout=300)
                        self.assertEqual(response.stdout, 'owned-stdout\n')
                        self.assertEqual(response.stderr, 'owned-stderr\n')
                    record = ns['command_records'][0]
                    self.assertEqual(base64.b64decode(record['stdoutBase64']), b'owned-stdout\n')
                    self.assertEqual(base64.b64decode(record['stderrBase64']), b'owned-stderr\n')
                    self.assertTrue(record['ownershipClosure']['allDescendantsExited'])
                    self.assertEqual(record['ownershipClosure']['finalChildren'], [])
                    self.assertEqual(ns['subreaper_flag'](), record['ownershipClosure']['originalSubreaper'])
                finally:
                    ns['close_tree'](ns['final_tree'])
                    for fd in (archive_fd, audit_fd, result_fd):
                        os.close(fd)
                    ns['close_parents'](archive_chain)
                    ns['close_parents'](result_chain)


if __name__ == '__main__':
    unittest.main()
