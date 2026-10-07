"""Actual fixed recipe and owner-phase guards; no SSH, VM or guest effects."""
import unittest
import uuid

from agent_tools import windows_parallel_vm_launch as launch
from agent_tools import windows_tertiary_vm_recovery as recovery
from agent_tools.tests.test_windows_parallel_vm_launch import controller_boot


class TertiaryRecipeTest(unittest.TestCase):
    def test_actual_source_proven_tertiary_repair_recipe(self):
        guest=launch.fixed_guest('tertiary');corr=str(uuid.uuid4())
        argv=recovery.tertiary_argv(guest,controller_boot(),overlay_fd=5,
            template_fd=6,code_fd=7,vars_fd=8,correlation=corr)
        self.assertIn('ide-hd,drive=owned-disk,bus=ide.0,bootindex=0',argv)
        self.assertIn('e1000e,netdev=owned-net,mac='+guest.mac,argv)
        self.assertIn('unix:'+str(guest.root/('vm-r-'+corr[:8])/'qmp.sock')+',server=on,wait=off',argv)

    def test_secondary_role_cannot_enter_tertiary_recipe(self):
        with self.assertRaisesRegex(ValueError,'tertiary-recipe-scope'):
            recovery.tertiary_argv(launch.fixed_guest('secondary'),controller_boot(),
                overlay_fd=5,template_fd=6,code_fd=7,vars_fd=8,correlation=str(uuid.uuid4()))


class ActualReceiptRoleTest(unittest.TestCase):
    def test_actual_ui_journal_roles_use_real_writer(self):
        import ast, inspect, os, tempfile
        from pathlib import Path
        tree = ast.parse(inspect.getsource(recovery.tertiary_ui_step))
        names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'record_at':
                for index in (0, 1):
                    name = eval(compile(ast.Expression(node.args[1]), 'actual UI receipt role', 'eval'), {'index': index})
                    if name not in names:
                        names.append(name)
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for name in names:
                    recovery.prepare.record_at(fd, name, {'actualRole': True})
                    self.assertTrue((Path(tmp) / name).is_file())
            finally:
                os.close(fd)


class FactoryBindingTest(unittest.TestCase):
    def test_actual_factories_retain_identical_saved_json_and_scope(self):
        import json
        from agent_tools.tests.test_windows_parallel_vm_launch import native_prepared_fixture
        request = {'prepared': native_prepared_fixture(), 'observed': {
            'state': 'boot-observed', 'nativeGuestStarted': False,
            'productAcceptance': False, 'boot': controller_boot()},
            'proof': {'original': {'unknownBase64': '', 'supervisor': {}},
                      'secondary': {'unknownBase64': '', 'supervisor': {}}},
            'correlation': str(uuid.uuid4())}
        reloaded = json.loads(json.dumps(request, sort_keys=True))
        for step in recovery.UI_STEPS:
            self.assertEqual(recovery.ordinary_tertiary_shutdown_program(**request, step=step),
                             recovery.ordinary_tertiary_shutdown_program(**reloaded, step=step))
        self.assertEqual(recovery.tertiary_repair_program(**request),
                         recovery.tertiary_repair_program(**reloaded))
        with self.assertRaisesRegex(ValueError, 'tertiary-ui-step'):
            recovery.ordinary_tertiary_shutdown_program(**request, step='system_powerdown')


class ActualTertiaryPipelineTest(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_windows_parallel_vm_launch import PairProducerTest
        PairProducerTest.setUp(self)
        from unittest.mock import patch
        self.identity_own = patch.object(recovery, 'native_identity', side_effect=launch.native_identity)
        self.identity_own.start()
        self.addCleanup(self.identity_own.stop)
        from types import SimpleNamespace
        # Project only filesystem capacity, like the existing proc-memory and
        # QEMU privilege boundaries. Real TempFS files, FDs and guards remain.
        self.space = patch.object(recovery.os, 'statvfs', return_value=SimpleNamespace(
            f_bavail=(32 * 1024 ** 3) // 4096, f_frsize=4096))
        self.space.start()
        self.addCleanup(self.space.stop)

    def close_originals(self):
        from agent_tools.tests.test_windows_parallel_vm_launch import PairProducerTest
        PairProducerTest.close_originals(self)

    def binding(self):
        guest = self.guests[1]
        state = guest.root / 'vm-state'
        state.mkdir()
        variables = state / 'vars.fd'
        variables.write_bytes(b'ORIGINAL_TERTIARY_VARS')
        variables.chmod(0o600)
        authority = {'parent': {'imageFiles': [{'path': str(variables),
            'generation': launch.inventory.generation(variables.lstat()), 'accessMode': 2}]},
            'secondaryParent': {}, 'secondary': {}}
        return guest, variables, authority, (self.scope[0], (guest,), *self.scope[2:])

    def test_actual_tertiary_entry_starts_one_harmless_child_reuses_vars(self):
        from unittest.mock import patch
        guest, variables, authority, scope = self.binding()
        before = launch.inventory.generation(variables.lstat())
        with patch.object(recovery, 'tertiary_phase', return_value=authority):
            current, observed = recovery.fresh_tertiary_repair(scope, self.prepared, self.observed, {})
            result, run = recovery.launch_tertiary(scope, current, observed, self.correlation)
        self.assertEqual(len(self.children), 1)
        self.assertEqual(result['state'], 'pair-started')
        self.assertEqual(variables.read_bytes(), b'ORIGINAL_TERTIARY_VARS')
        self.assertEqual(launch.inventory.generation(variables.lstat()), before)
        self.assertFalse((self.guests[0].root / 'vm-state').exists())
        self.assertFalse(result['guestAccessVerified'])
        self.assertFalse(result['productAcceptance'])
        self.assertIn('user,id=owned-net,hostfwd=tcp:127.0.0.1:2338-:22', run['identities'][0]['argv'])
        self.assertTrue((run['root'] / 'tertiary-vars-transition.json').exists())
        with self.assertRaisesRegex(ValueError, 'launch-original-run-exists'):
            recovery.launch_tertiary(scope, current, observed, self.correlation)

    def test_actual_foreign_vars_holder_refuses_before_child(self):
        from unittest.mock import patch
        guest, variables, authority, scope = self.binding()
        holder = self.proc / '777'
        (holder / 'fd').mkdir(parents=True)
        (holder / 'fdinfo').mkdir()
        (holder / 'fd/8').symlink_to(variables)
        (holder / 'fdinfo/8').write_text('flags: 0100002\n')
        real_census = recovery.inventory.holder_census
        def census(proc, inode, exclude, deadline, path):
            value = real_census(proc, inode, exclude, deadline, path)
            if path == str(variables):
                value = dict(value, complete=True, argvUsers=[], holders=[{'pid': 777, 'fd': '8', 'startTicks': 1}])
            return value
        with patch.object(recovery, 'tertiary_phase', return_value=authority), patch.object(recovery.inventory, 'holder_census', side_effect=census):
            current, observed = recovery.fresh_tertiary_repair(scope, self.prepared, self.observed, {})
            with self.assertRaises(launch.PairUnknown) as error:
                recovery.launch_tertiary(scope, current, observed, self.correlation)
        self.assertEqual(error.exception.run['handles'], [])
        self.assertEqual(self.children, [])

    def test_phase_refusal_and_secondary_scope_submit_no_child(self):
        from unittest.mock import patch
        guest, variables, authority, scope = self.binding()
        with patch.object(recovery, 'tertiary_phase', side_effect=ValueError('tertiary-not-terminal')):
            with self.assertRaisesRegex(ValueError, 'tertiary-not-terminal'):
                recovery.fresh_tertiary_repair(scope, self.prepared, self.observed, {})
        self.assertEqual(self.children, [])
        with self.assertRaisesRegex(ValueError, 'launch-correlation'):
            recovery.launch_tertiary(self.scope, self.prepared, self.observed, self.correlation)
        self.assertEqual(self.children, [])


    def test_actual_generated_factory_prefix_executes_same_single_entry(self):
        from unittest.mock import patch
        from agent_tools.tests.test_windows_parallel_vm_launch import native_prepared_fixture
        guest, variables, authority, scope = self.binding()
        observation = {'state': 'boot-observed', 'nativeGuestStarted': False,
            'productAcceptance': False, 'boot': controller_boot()}
        with patch.object(launch, 'fixed_guest', self.slots.temp_original), \
             patch.object(launch, 'native_identity', self.identity.temp_original):
            source = recovery.tertiary_repair_program(native_prepared_fixture(), observation,
                {'original': {}, 'secondary': {}}, self.correlation)
        namespace = {}
        exec(compile(source.split('\nPREPARED=', 1)[0], 'actual tertiary factory definitions', 'exec'), namespace)
        namespace['LIVE_LAUNCHES'] = launch.LIVE_LAUNCHES
        namespace['tertiary_phase'] = lambda proc, proof: authority
        namespace['fixed_guest'] = launch.fixed_guest
        namespace['launch'].fixed_guest = launch.fixed_guest
        namespace['native_identity'] = launch.native_identity
        current, observed = namespace['fresh_tertiary_repair'](scope, self.prepared, self.observed, {})
        value, run = namespace['launch_tertiary'](scope, current, observed, self.correlation)
        self.assertEqual(len(run['handles']), 1)
        self.assertEqual(value['state'], 'pair-started')
        self.assertFalse((self.guests[0].root / 'vm-state').exists())
        self.assertEqual(variables.read_bytes(), b'ORIGINAL_TERTIARY_VARS')

    def test_actual_post_submission_refusal_retains_original_and_blocks_replay(self):
        import json
        from unittest.mock import patch
        guest, variables, authority, scope = self.binding()
        with patch.object(recovery, 'tertiary_phase', return_value=authority):
            current, observed = recovery.fresh_tertiary_repair(scope, self.prepared, self.observed, {})
            with patch.object(recovery, 'native_identity', side_effect=OSError('inert boundary refusal')):
                with self.assertRaises(launch.PairUnknown) as error:
                    recovery.launch_tertiary(scope, current, observed, self.correlation)
            run = error.exception.run
            self.assertEqual(len(run['handles']), 1)
            self.assertIs(run['handles'][0], self.children[0])
            self.assertIsNone(run['handles'][0].poll())
            row = json.loads((run['root'] / 'unknown.json').read_bytes())
            self.assertEqual(row['originalPids'], [self.children[0].pid])
            self.assertFalse(row['replayAllowed'])
            with self.assertRaisesRegex(ValueError, 'launch-original-run-exists'):
                recovery.launch_tertiary(scope, current, observed, self.correlation)
            self.assertEqual(len(self.children), 1)

    def test_actual_low_disk_guard_refuses_before_submission(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        guest, variables, authority, scope = self.binding()
        with patch.object(recovery, 'tertiary_phase', return_value=authority):
            current, observed = recovery.fresh_tertiary_repair(scope, self.prepared, self.observed, {})
            with patch.object(recovery.os, 'statvfs', return_value=SimpleNamespace(f_bavail=0, f_frsize=4096)):
                with self.assertRaises(launch.PairUnknown) as error:
                    recovery.launch_tertiary(scope, current, observed, self.correlation)
        self.assertEqual(str(error.exception.__cause__), 'launch-resource-headroom')
        self.assertEqual(error.exception.run['handles'], [])
        self.assertEqual(self.children, [])


class OriginalParentExitTest(unittest.TestCase):
    def test_original_parent_may_exit_only_after_both_original_children(self):
        import base64, hashlib, json, tempfile
        from pathlib import Path
        from unittest.mock import patch
        old = {'state': 'unknown', 'nativeGuestStarted': True,
            'originalPids': [3474305, 3474306], 'identities': [
                {'pid': 3474305, 'startTicks': 21163511, 'uid': 1000},
                {'pid': 3474306, 'startTicks': 21163512, 'uid': 1000}]}
        current = {'state': 'unknown', 'nativeGuestStarted': True,
            'originalPids': [3726886], 'identities': [
                {'pid': 3726886, 'startTicks': 21863571, 'uid': 1000}]}
        raw = json.dumps(old).encode(); current_raw = json.dumps(current).encode()
        proof = {'original': {'unknownBase64': base64.b64encode(raw).decode(), 'supervisor': {
            'pid': 3474300, 'startTicks': 21163499, 'uid': 0,
            'programSha256': 'f3bcd78753ac455926a68e5629beb3fea83acacab6d3b2d077434efc28b49ac6'}},
            'secondary': {'unknownBase64': base64.b64encode(current_raw).decode(), 'supervisor': {
            'pid': 3726881, 'startTicks': 21863561, 'uid': 0,
            'programSha256': recovery.SECONDARY_PROGRAM_SHA}}}
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp)
            for pid, parent in [(3726881, 1), (3726886, 3726881)]:
                entry = proc / str(pid); entry.mkdir()
                (entry / 'stat').write_text(str(pid) + ' (fixture) R ' + str(parent) + ' 0' * 20)
            def observed(proc, row, program_sha=None):
                # Kernel process birth/uid/code projection only; actual phase,
                # raw hashes/DTOs, positive absence and parent read run unchanged.
                if not (proc / str(row['pid'])).exists():
                    raise ValueError('repair-original-process')
            with patch.object(recovery, 'ORIGINAL_UNKNOWN_SHA', hashlib.sha256(raw).hexdigest()), \
                 patch.object(recovery, 'SECONDARY_UNKNOWN_SHA', hashlib.sha256(current_raw).hexdigest()), \
                 patch.object(launch, 'observed_process', side_effect=observed):
                value = recovery.tertiary_phase(proc, proof)
                self.assertEqual(value['secondary']['pid'], 3726886)
                (proc / '3474306').mkdir()
                with self.assertRaises(ValueError):
                    recovery.tertiary_phase(proc, proof)
                with self.assertRaises(ValueError):
                    recovery.tertiary_phase(proc, proof, require_off=False)
                (proc / '3474306').rmdir()
                (proc / '3474305').mkdir()
                with self.assertRaises(ValueError):
                    recovery.tertiary_phase(proc, proof)
                (proc / '3474305').rmdir()
                (proc / '3726886/stat').unlink(); (proc / '3726886').rmdir()
                with self.assertRaises(ValueError):
                    recovery.tertiary_phase(proc, proof)


class ActualUiDecisionTest(unittest.TestCase):
    def test_actual_current_frame_and_peer_refusals_send_no_key(self):
        import hashlib, json, os, socket, struct, tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        for wrong_peer in (True, False):
            with self.subTest(wrong_peer=wrong_peer), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); guest_root = root / 'tertiary'; state = guest_root / 'vm-state'
                state.mkdir(parents=True); template = root / 'template.qcow2'; template.write_bytes(b'TEMPLATE')
                sockpath = state / 'qmp.sock'; original_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                original_socket.bind(str(sockpath)); original_socket.close()
                guest = launch.Guest('tertiary', guest_root, 2338, 5938, '52:54:00:57:50:22')
                prepared = {'template': str(template), 'templateGeneration': launch.inventory.generation(template.lstat()),
                    'overlays': [{'path': str(guest_root / 'disk.qcow2'), 'guestGeneration': launch.inventory.parent_identity(guest_root.lstat())}]}
                raw = json.dumps({'identities': [{}, {'pid': 3474306, 'startTicks': 21163512}]}).encode()
                proof = {'original': {'unknownBase64': __import__('base64').b64encode(raw).decode()}}
                commands = []
                class Connection:
                    def __enter__(self): return self
                    def __exit__(self, *args): pass
                    def settimeout(self, timeout): pass
                    def connect(self, path): self.path = path
                    def getsockopt(self, *args): return struct.pack('3i', 777 if wrong_peer else 3474306, 1000, 1000)
                    def sendall(self, raw):
                        self.request = json.loads(raw); commands.append(self.request['execute'])
                        if self.request['execute'] == 'screendump':
                            Path(self.request['arguments']['filename']).write_bytes(b'ACTUAL_WRONG_FRAME')
                connection = Connection()
                class Framer:
                    frames = 0
                    def bind(self, *args): return self
                    def _read_qmp_response(self, conn, deadline):
                        self.frames += 1
                        if self.frames == 1: return b'{"QMP":{}}'
                        request = conn.request
                        return json.dumps({'id': request['id'], 'return': {'status': 'running'} if request['execute'] == 'query-status' else {}}).encode()
                real_lstat = Path.lstat; real_hash = launch.file_hash
                def projected_lstat(path):
                    result = real_lstat(path)
                    if path == sockpath or path.suffix == '.png':
                        values = {name: getattr(result, name) for name in ['st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns']}
                        values.update(st_uid=1000, st_gid=1000)
                        return SimpleNamespace(**values)
                    return result
                def projected_hash(fd, maximum):
                    result = real_hash(fd, maximum)
                    result['generation'][3:5] = [1000, 1000]
                    return result
                # Project root/SO_PEERCRED and Windows-user UID boundaries only;
                # actual UI source, receipt writer, file bytes/hash/namespace and
                # decisions execute. No socket to a guest is opened.
                with patch.object(os, 'geteuid', return_value=0), \
                     patch.object(recovery, 'tertiary_phase', return_value={}), \
                     patch.object(launch, 'fixed_guest', return_value=guest), \
                     patch.object(launch, 'AccessClient', side_effect=lambda *a, **kw: Framer()), \
                     patch.object(socket, 'socket', return_value=connection), \
                     patch.object(socket, 'SO_PEERCRED', 17, create=True), \
                     patch.object(Path, 'lstat', projected_lstat), \
                     patch.object(launch, 'file_hash', side_effect=projected_hash):
                    value = recovery.tertiary_ui_step(prepared, proof, str(uuid.uuid4()), 'advanced')
                self.assertEqual(value['state'], 'unknown')
                self.assertEqual(value['reason'], 'tertiary-ui-peer' if wrong_peer else 'tertiary-ui-current-screen')
                self.assertNotIn('send-key', commands)
                journals = list(root.glob('tertiary-ui-*/unknown.json'))
                self.assertEqual(len(journals), 1)
                self.assertFalse(json.loads(journals[0].read_bytes())['replayAllowed'])
