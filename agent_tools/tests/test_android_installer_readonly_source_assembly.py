"""Causal ticks-join controls using public sources and an owned proc fixture.

Only selected authentic functions are compiled; canonical programmes are never
imported or executed. TempFS models Linux proc paths on every host. The declared
readlink/socket/backend seams have no native effects. This tests the source join,
not real principal, installer, credential, ADB or process-lifecycle admission.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import types
import unittest

from agent_tools.android_installer_readonly_source_assembly import scoped_fixture_read_definitions


_SOURCES = {
    "dispatch": "agent_tools/android_installer_dispatch.py",
    "census": "agent_tools/android_avd_launch_recovery.py",
    "coldboot": "agent_tools/android_avd_coldboot.py",
    "bundle": "agent_tools/android_installer_component_bundle.py",
}


def _repository_root():
    for parent in Path(__file__).resolve().parents:
        if all((parent / relative).is_file() for relative in _SOURCES.values()):
            return parent
    raise RuntimeError("public_reader_sources_missing")


def _literal(raw, name):
    assignments = [node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("public_reader_literal_missing")
    return ast.literal_eval(assignments[0].value)


def _selected(raw, names):
    nodes = [copy.deepcopy(node) for node in ast.parse(raw).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    if len(nodes) != len(names) or {node.name for node in nodes} != set(names):
        raise ValueError("public_reader_symbols_missing")
    return ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[]))


def _dispatch_nodes(raw):
    assignment = next(node for node in ast.parse(raw).body if isinstance(node, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "_REMOTE" for target in node.targets))
    remote = next(node.value for node in ast.walk(assignment.value)
                  if isinstance(node, ast.Constant) and type(node.value) is str
                  and "def fixture_stopped(" in node.value)
    return _selected(remote, {"ticks", "fixture_stopped"})


class AfterIdentity(Exception):
    """The genuine physical comparison passed; stop before guest property IO."""


class _OwnedProc:
    def __init__(self, root, census, coldboot):
        self.proc = root / "proc"
        boot = self.proc / "sys/kernel/random"
        boot.mkdir(parents=True)
        (boot / "boot_id").write_text("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")
        self.actor = self.proc / "37"
        self.actor.mkdir()
        # /proc/exe readlink is an explicit portable seam. Its target file and
        # generation/stat, command, boot ID and birth field are real TempFS IO.
        (self.actor / "exe").write_bytes(b"owned executable")
        (self.actor / "cmdline").write_bytes(b"OWNED-CONTROL\0")
        self.write_ticks(777)

        def proc_path(value):
            if not str(value).startswith("/proc/"):
                raise AssertionError("control_non_proc_path_refused")
            # Only the declared public PID maps to its owned file. A canonical
            # path supplied to the wrong reader must miss on Windows as well;
            # joining its drive path could otherwise escape/reset this root.
            if str(value) == "/proc/37/stat":
                return self.actor / "stat"
            return self.proc / "missing-public-pid" / "stat"

        def readlink(path):
            if path != self.actor / "exe":
                raise AssertionError("control_foreign_executable_refused")
            return str(root / "owned-executable")

        def unknown(reason):
            raise ValueError(reason)

        self.namespace = {
            "PROC": self.proc, "os": types.SimpleNamespace(readlink=readlink),
            "hashlib": hashlib, "re": re, "Path": Path,
            "pathlib": types.SimpleNamespace(Path=proc_path), "json": json, "unknown": unknown,
        }
        exec(compile(_selected(census, {"fp", "boot", "ticks"}), "<authentic-census-readers>",
                     "exec", dont_inherit=True), self.namespace)
        exec(compile(_selected(coldboot, {"child_identity"}), "<authentic-coldboot-reader>",
                     "exec", dont_inherit=True), self.namespace)

    def write_ticks(self, birth):
        fields = ["S"] + ["0"] * 18 + [str(birth)] + ["0"] * 6
        (self.actor / "stat").write_text("37 (own child) " + " ".join(fields) + "\n")


class ScopedFixtureReadDefinitionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = _repository_root()
        cls.sources = {name: (root / relative).read_bytes() for name, relative in _SOURCES.items()}
        cls.census = _literal(cls.sources["census"], "_CENSUS")
        cls.coldboot = _literal(cls.sources["coldboot"], "_BOOT")

    def _join(self, fixture):
        source, audit = scoped_fixture_read_definitions(self.sources["dispatch"])
        exec(compile(source, "<selected-original-fixture-readers>", "exec", dont_inherit=True),
             fixture.namespace)
        return source, audit

    def test_authentic_current_physical_comparison_survives_original_pid_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _OwnedProc(Path(temporary), self.census, self.coldboot)
            namespace = fixture.namespace
            canonical_ticks = namespace["ticks"]
            expected_child = namespace["child_identity"](37)
            self._join(fixture)
            observed_child = namespace["child_identity"](37)

            guard = next(node for node in ast.parse(self.sources["bundle"]).body
                         if isinstance(node, ast.ClassDef) and node.name == "CurrentGuard")
            physical = copy.deepcopy(next(node for node in guard.body
                                          if isinstance(node, ast.FunctionDef) and node.name == "_physical"))
            physical_tree = ast.fix_missing_locations(ast.Module(body=[physical], type_ignores=[]))
            context = {"load": lambda unused: None, "_PROPERTIES": (("sdk", "own"),)}
            exec(compile(physical_tree, "<authentic-CurrentGuard-physical>", "exec", dont_inherit=True), context)
            guest = {"owned": "guest"}
            backend = dict(namespace, GETTER={"generation": {"child": expected_child, "guest": guest}},
                           command_host_guard=lambda: None, external_jdk_guard=lambda: None,
                           command_host_identity=lambda: {"owned": True}, getter_stage=lambda: {"own": True},
                           qemu_fact=lambda: {"own": True}, session_guest=lambda child, ready: guest)
            attempted_guest_reads = []

            def stop_after_identity(words):
                attempted_guest_reads.append(words)
                raise AfterIdentity()

            # Explicit backend fixtures satisfy the unrelated admission inputs.
            # The real child comparison and error branch are never replaced.
            target = types.SimpleNamespace(receipt={}, _task_guard=lambda: None, backend=backend,
                                           measurement={"api": 35, "avd": "own"}, function_pins={},
                                           host={"owned": True}, stage={"own": True}, _text=stop_after_identity)
            refusal = None
            passed_identity = False
            try:
                context["_physical"](target)
            except AfterIdentity:
                passed_identity = True
            except ValueError as error:
                if error.args != ("component_guard_owned_process_changed",):
                    raise
                refusal = error.args[0]
            self.assertTrue(passed_identity, (refusal, observed_child["startTicks"]))
            self.assertEqual(attempted_guest_reads, [["shell", "-T", "getprop", "own"]])
            self.assertEqual(observed_child, expected_child)
            self.assertIs(namespace["ticks"], canonical_ticks)
            self.assertEqual(namespace["_facts_original_ticks"](37), 777)

    def test_fixture_stopped_uses_scoped_pid_ticks_and_owned_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _OwnedProc(root, self.census, self.coldboot)
            canonical_ticks = fixture.namespace["ticks"]
            self._join(fixture)
            self.assertIs(fixture.namespace["ticks"], canonical_ticks)
            output = root / "fixture"
            output.mkdir()
            identity = {"pid": 37, "startTicks": 777, "port": 12345, "correlationId": "owned-fixture"}
            for name, value in (
                ("fixture-identity.json", identity),
                ("worker-finished.json", {**identity, "state": "fixture_stopped"}),
                ("fixture-receipt.json", {"state": "ready", "pid": 37, "port": 12345}),
                ("ready.json", {"port": 12345}),
            ):
                (output / name).write_text(json.dumps(value))

            def private(path, limit):
                self.assertEqual(path.parent, output)
                raw = path.read_bytes()
                self.assertLessEqual(len(raw), limit)
                return raw

            probes = []

            def refuse(address, timeout):
                probes.append((address, timeout))
                raise ConnectionRefusedError()

            def path_reader_must_not_be_called(unused):
                raise AssertionError("fixture_predicate_called_canonical_path_ticks")

            fixture.namespace.update(private=private, correlation="owned-fixture",
                                     socket=types.SimpleNamespace(create_connection=refuse),
                                     ticks=path_reader_must_not_be_called)
            with self.assertRaisesRegex(ValueError, "^fixture_server_live$"):
                fixture.namespace["fixture_stopped"](output)
            self.assertEqual(probes, [])
            fixture.write_ticks(778)
            self.assertIsNone(fixture.namespace["fixture_stopped"](output))
            self.assertEqual(probes, [(("127.0.0.1", 12345), .5)])

    def test_scope_inverse_is_the_exact_two_authentic_dispatch_functions(self):
        source, audit = scoped_fixture_read_definitions(self.sources["dispatch"])
        emitted = ast.parse(source)
        self.assertEqual([node.name for node in emitted.body], ["_facts_original_ticks", "fixture_stopped"])
        inverse = copy.deepcopy(emitted)
        for node in ast.walk(inverse):
            if isinstance(node, ast.FunctionDef) and node.name == "_facts_original_ticks":
                node.name = "ticks"
            elif isinstance(node, ast.Name) and node.id == "_facts_original_ticks":
                node.id = "ticks"
        originals = _dispatch_nodes(self.sources["dispatch"])
        self.assertEqual(ast.dump(inverse, include_attributes=False), ast.dump(originals, include_attributes=False))
        self.assertTrue(audit["dispatchScopeInverseVerified"])
        self.assertEqual(audit["originalTickScopedName"], "_facts_original_ticks")
        self.assertFalse(audit["exclusiveCustodyConstructed"])
        self.assertFalse(audit["retirementEntrySelected"])

    def test_selector_refuses_ambiguous_symbols_and_existing_scoped_name(self):
        remote = "def ticks(pid):\n return pid\ndef fixture_stopped(output):\n return ticks(output)\n"
        for literal, reason in (
            (remote + "def ticks(pid):\n return pid\n", "facts_original_read_symbols_changed"),
            (remote.replace("return ticks(output)", "return _facts_original_ticks(output)"),
             "facts_original_tick_scope_collision"),
        ):
            raw = ("_REMOTE = " + repr(literal) + "\n").encode()
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                scoped_fixture_read_definitions(raw)




"""Pure emitters on own held TempFS bytes; mocked principals are not Linux proof.

No canonical module imports, actual body/controller execution, private retained
programme/auth reads, driver main, route, process, sudo or device operations.
The sole retained-source pin substitution binds a declared harmless own fixture.
"""
import ast
import contextlib
import errno
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock

ROOT = _repository_root()
ASSETS = Path(__file__).resolve().parent / "fixtures/android_installer_readonly_source"
RAW = {name: (ROOT / relative).read_bytes() for name, relative in {
 'coldboot': 'agent_tools/android_avd_coldboot.py',
 'census': 'agent_tools/android_avd_launch_recovery.py',
 'owner': 'agent_tools/android_api35_coldboot_product_observation.py',
 'collector': 'agent_tools/android_installer_asset_collection.py',
 'direct': 'agent_tools/android_installer_direct_transport.py',
 'bundle': 'agent_tools/android_installer_component_bundle.py',
}.items()}
RAW.update({name: (ASSETS / relative).read_bytes() for name, relative in {
 'identity': 'identity-assembly-current.source',
 'before': 'identity-assembly-uid1000-before.source',
 'bridge': 'bridge-assembly-current.source',
}.items()})
from agent_tools import android_installer_readonly_source_assembly as assembly
OBSERVATIONS = []
FALSE_FLAGS = {key: False for key in ('nativeActionAllowed', 'admitAllowed',
    'replayAllowed', 'releaseAllowed', 'retirementAllowed', 'installerAllowed',
    'productAcceptance', 'originalOutcomeKnown')}
FINITE = dict(state='UNKNOWN', fixture='own-harmless-emission', **FALSE_FLAGS)
OWN_BODY = ('def identity_diagnostic_run():\n return ' + repr(FINITE) + '\n').encode()
OWN_CONTROL = ('def linux_crossprincipal_run():\n'
    ' assert all(callable(globals()[name]) for name in '
    + repr(('fp', 'parent_fds', 'guard_parents', 'close_parents', 'boot', 'ticks',
            'child_identity', 'qemu_fact', 'session_guest'))
    + ')\n return ' + repr(FINITE) + '\n').encode()
ROOT_INSERT = (
    "    dispatch = next(node for node in ast.parse(templates['coldboot']).body if isinstance(node,ast.FunctionDef) and node.name=='coldboot_dispatch')\n"
    '    context = dispatch.body[0]\n'
    '    if ast.unparse(context) != "if os.getuid() != 0 or os.geteuid() != 0:\\n    raise ValueError(\'coldboot_root_required\')":raise ValueError(\'identity_root_context_changed\')\n'
    "    source += ast.get_source_segment(templates['coldboot'],context) + '\\n'\n")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def definitions(raw, names, label):
    rows = [node for node in ast.parse(raw).body
            if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in rows} == set(names)
    return compile(ast.Module(body=rows, type_ignores=[]), label, 'exec', dont_inherit=True)


def namespace(name):
    # Public helper functions, with an explicitly synthetic retained pin only.
    return vars(assembly).copy()


def direct_read_namespace():
    return assembly.direct


class SourceFixture:
    """Owned finite bytes; descriptor custody is tested separately on POSIX."""
    def __init__(self, rows):
        self.bytes = dict(rows)
        self.pins = {name: sha(raw) for name, raw in rows.items()}
    def guard(self):
        assert {name: sha(raw) for name, raw in self.bytes.items()} == self.pins
    def close(self):
        self.guard()

class HeldFixture:
    def __init__(self, rows):
        self.tmp = tempfile.TemporaryDirectory(prefix='own-routine-source-only-')
        self.root = Path(self.tmp.name).resolve()
        self.direct = direct_read_namespace()
        self.held = []
        self.bytes = {}
        try:
            for name, raw in rows.items():
                path = self.root / (name + '.source')
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    self.assert_write(fd, raw)
                finally:
                    os.close(fd)
                observed, pin = self.direct.snapshot(path, private=True, limit=32 << 20)
                self.held.append(self.direct._dispatch_hold(path, pin, observed))
                self.bytes[name] = observed
            self.guard()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def assert_write(fd, raw):
        offset = 0
        while offset < len(raw):
            wrote = os.write(fd, raw[offset:])
            assert wrote > 0
            offset += wrote

    def guard(self):
        self.direct._dispatch_guard(self.held)
        for _, pin, _, fd in self.held:
            assert sha(os.pread(fd, pin['generation'][6] + 1, 0)) == pin['sha256']

    def close(self):
        fds = set()
        errors = []
        for _, _, chain, fd in reversed(self.held):
            for candidate in (fd, *(row[1] for row in reversed(chain))):
                if candidate in fds:
                    continue
                fds.add(candidate)
                try:
                    os.close(candidate)
                except OSError as error:
                    if error.errno != errno.EBADF:
                        errors.append(type(error).__name__)
        closed = True
        for fd in fds:
            try:
                os.fstat(fd)
                closed = False
            except OSError as error:
                assert error.errno == errno.EBADF
        self.tmp.cleanup()
        OBSERVATIONS.append(dict(ownTempFS=True, heldDescriptorCount=len(fds),
            closeAttempts=len(fds), closeErrors=errors, allDescriptorsClosed=closed,
            liveHolders=0 if closed else None, nativeEffects=0))
        assert closed and not errors


@contextlib.contextmanager
def mocked_principal(uid):
    # These are pure getter stubs, not a UID switch or Linux access experiment.
    with mock.patch.multiple(os, create=True, getuid=lambda: uid, geteuid=lambda: uid,
                             getgid=lambda: uid, getegid=lambda: uid,
                             getgroups=lambda: [uid]):
        yield


def execute_harmless(programme, uid):
    captured = io.StringIO()
    with mocked_principal(uid), contextlib.redirect_stdout(captured):
        exec(compile(programme, '<own-harmless-emitted-stub-only>', 'exec'), {})
    return captured.getvalue().encode('utf-8')


def context_and_helpers(programme, template, names):
    original = ast.parse(template)
    emitted = ast.parse(programme)
    dispatch = next(node for node in original.body
                    if isinstance(node, ast.FunctionDef) and node.name == 'coldboot_dispatch')
    context = dispatch.body[0]
    checks = [node for node in emitted.body if isinstance(node, ast.If)
              and ast.dump(node, include_attributes=False) == ast.dump(context, include_attributes=False)]
    assert len(checks) == 1
    for name in names:
        orig = next(node for node in original.body if isinstance(node, ast.FunctionDef) and node.name == name)
        actual = next(node for node in emitted.body if isinstance(node, ast.FunctionDef) and node.name == name)
        assert ast.dump(orig, include_attributes=False) == ast.dump(actual, include_attributes=False)
        assert ast.get_source_segment(template, orig) == ast.get_source_segment(programme.decode(), actual)


class RoutineSourceTests(unittest.TestCase):
    def identity_emission(self):
        ns = namespace('identity')
        expected = ns['assignment'](ast.parse(RAW['owner']), 'FIXED_GENERATION')
        retained = ('LAUNCH=' + repr(dict(qemuPath='/own-synthetic-uninvoked-qemu',
            avd=expected['device']['bootAvd'], port=5682)) + '\nGETTER='
            + repr(dict(generation=expected)) + '\n').encode()
        # Explicit own fixture namespace binding; real retained3367 is never read.
        ns['SOURCE_PINS'] = dict(ns['SOURCE_PINS'], retained=sha(retained))
        ns['emit_identity'] = types.FunctionType(assembly.emit_identity.__code__, ns)
        fixture = SourceFixture(dict(coldboot=RAW['coldboot'], census=RAW['census'],
            owner=RAW['owner'], retained=retained, body=OWN_BODY))
        try:
            fixture.guard()
            programme, audit = ns['emit_identity'](*(fixture.bytes[name] for name in
                ('coldboot', 'census', 'owner', 'retained', 'body')))
            fixture.guard()
            return programme, audit
        finally:
            fixture.close()

    def test_current_owner_identity_matches_authenticated_pre_streaming_emission(self):
        old_owner=(ASSETS/'owner-api35-before-streaming.source').read_bytes()
        self.assertEqual(sha(old_owner),'3588b0abd238cd594df0bad1cb0bb1b296c5ade4a9330b47f1f66abcd4a6462c')
        expected=assembly.assignment(ast.parse(old_owner),'FIXED_GENERATION')
        self.assertEqual(expected,assembly.assignment(ast.parse(RAW['owner']),'FIXED_GENERATION'))
        retained=('LAUNCH='+repr(dict(qemuPath='/own-synthetic-uninvoked-qemu',
            avd=expected['device']['bootAvd'],port=5682))+'\nGETTER='+repr(dict(generation=expected))+'\n').encode()
        legacy=vars(assembly).copy()
        legacy['SOURCE_PINS']=dict(assembly.SOURCE_PINS,owner=sha(old_owner),retained=sha(retained))
        old_emit=types.FunctionType(assembly.emit_identity.__code__,legacy)
        before=old_emit(RAW['coldboot'],RAW['census'],old_owner,retained,OWN_BODY)
        current=vars(assembly).copy()
        current['SOURCE_PINS']=dict(assembly.SOURCE_PINS,retained=sha(retained))
        current_emit=types.FunctionType(assembly.emit_identity.__code__,current)
        after=current_emit(RAW['coldboot'],RAW['census'],RAW['owner'],retained,OWN_BODY)
        self.assertEqual(before,after)

    def test_current_owner_source_byte_and_generation_mutations_refuse(self):
        expected=assembly.assignment(ast.parse(RAW['owner']),'FIXED_GENERATION')
        retained=('LAUNCH='+repr(dict(qemuPath='/own-synthetic-uninvoked-qemu',
            avd=expected['device']['bootAvd'],port=5682))+'\nGETTER='+repr(dict(generation=expected))+'\n').encode()
        scope=vars(assembly).copy();scope['SOURCE_PINS']=dict(assembly.SOURCE_PINS,retained=sha(retained))
        emit=types.FunctionType(assembly.emit_identity.__code__,scope)
        for foreign in (RAW['owner']+b'\n',RAW['owner'].replace(b"'sdk': '35'",b"'sdk': '29'",1)):
            with self.subTest(hash=sha(foreign)),self.assertRaisesRegex(ValueError,'identity_fixed_source_changed'):
                emit(RAW['coldboot'],RAW['census'],foreign,retained,OWN_BODY)

    def test_identity_exact_byte_and_ast_inverse(self):
        current = RAW['identity'].decode()
        self.assertEqual(current.count(ROOT_INSERT), 1)
        needle = 'if IDENTITY_PRINCIPAL[:4]!=(0,0,0,0)'
        self.assertEqual(current.count(needle), 1)
        inverse = current.replace(ROOT_INSERT, '', 1).replace(needle,
            'if IDENTITY_PRINCIPAL[:4]!=(1000,1000,1000,1000)', 1).encode()
        self.assertEqual(inverse, RAW['before'])
        self.assertEqual(ast.dump(ast.parse(inverse), include_attributes=False),
                         ast.dump(ast.parse(RAW['before']), include_attributes=False))
        OBSERVATIONS.append(dict(identityByteInverse=True, identityAstInverse=True,
            changedIntervals=['principalTuple1000To0', 'exactCanonicalFirstRootIfSelection']))

    def test_identity_actual_emission_root_stub_and_exact_helpers(self):
        programme, audit = self.identity_emission()
        ns = namespace('identity')
        templates = {name: ns['assignment'](ast.parse(RAW[name]), symbol)
                     for name, symbol in [('coldboot', '_BOOT'), ('census', '_CENSUS')]}
        try:
            output = execute_harmless(programme, 0)
        except ValueError as error:
            self.fail('Root emission refused: ' + str(error))
        context_and_helpers(programme, templates['coldboot'], ns['READS']['coldboot'])
        for name in ns['READS']['census']:
            orig = next(node for node in ast.parse(templates['census']).body
                        if isinstance(node, ast.FunctionDef) and node.name == name)
            emitted = next(node for node in ast.parse(programme).body
                           if isinstance(node, ast.FunctionDef) and node.name == name)
            self.assertEqual(ast.dump(orig, include_attributes=False), ast.dump(emitted, include_attributes=False))
        expected = (json.dumps(FINITE, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
        self.assertEqual(output, expected)
        self.assertEqual(len(audit['functions']), 9)
        self.assertTrue(all(audit[key] is False for key in ('nativeSubmitted', 'nativeActionAllowed', 'replayAllowed')))
        OBSERVATIONS.append(dict(identityProgrammeBytes=len(programme), identityProgrammeSha256=sha(programme),
            exactlyNineUnchangedHelpers=True, rootFirstIfAstAndBytesExact=True,
            ownMockRootHarmlessEmission=True, exactlyOneFiniteOutput=True, linuxProof=False))

    def test_identity_actual_emission_mock_uid1000_refuses(self):
        programme, _ = self.identity_emission()
        with self.assertRaisesRegex(ValueError, '^identity_uid_unknown$'):
            execute_harmless(programme, 1000)
        OBSERVATIONS.append(dict(mockUid1000AdmissionRefused=True,
            actualLinuxPermissionExperiment=False, canonicalReaderInvocation=False))

    def test_bridge_collector_full_source_pin_refuses_foreign_bytes(self):
        # A valid current source must reach both genuine bridge entry points.
        # These foreign modules retain the embedded transport templates; only
        # the fixed full-module pin may distinguish them from admitted bytes.
        programme, bootstrap, _ = assembly.emit_control(
            RAW['coldboot'], RAW['census'], RAW['collector'], OWN_CONTROL, sha(OWN_CONTROL))
        assembly.receiver_source(RAW['collector'], programme, bootstrap)
        changed_default = RAW['collector'].replace(
            b'def collector(*,deadline_seconds=1250):',
            b'def collector(*,deadline_seconds=1249):', 1)
        self.assertNotEqual(changed_default, RAW['collector'])
        for foreign in (RAW['collector'] + b'\n', changed_default):
            with self.subTest(hash=sha(foreign)):
                self.assertEqual(assembly.literal(foreign, 'COLLECTOR_SOURCE'),
                                 assembly.literal(RAW['collector'], 'COLLECTOR_SOURCE'))
                with self.assertRaisesRegex(ValueError, '^control_authentic_source_changed$'):
                    assembly.emit_control(RAW['coldboot'], RAW['census'], foreign,
                                          OWN_CONTROL, sha(OWN_CONTROL))
                with self.assertRaisesRegex(ValueError, '^control_authentic_source_changed$'):
                    assembly.receiver_source(foreign, programme, bootstrap)

    def test_bridge_exact_root_and_remote_inverse_harmless_emission(self):
        ns = namespace('bridge')
        fixture = SourceFixture(dict(coldboot=RAW['coldboot'], census=RAW['census'],
            collector=RAW['collector'], control=OWN_CONTROL))
        try:
            fixture.guard()
            programme, bootstrap, audit = ns['emit_control'](fixture.bytes['coldboot'],
                fixture.bytes['census'], fixture.bytes['collector'], fixture.bytes['control'], sha(OWN_CONTROL))
            remote = ns['receiver_source'](fixture.bytes['collector'], programme, bootstrap)
            fixture.guard()
        finally:
            fixture.close()
        collector = ns['literal'](RAW['collector'], 'COLLECTOR_SOURCE')
        root = ns['literal'](collector, 'ROOT_BOOT')
        original_remote = ns['literal'](collector, 'REMOTE')
        canonical_bootstrap = root.replace('__BYTES__', str(len(programme))).replace('__SHA__', repr(sha(programme)))
        self.assertEqual(bootstrap, canonical_bootstrap)
        self.assertEqual(ast.dump(ast.parse(bootstrap), include_attributes=False),
                         ast.dump(ast.parse(canonical_bootstrap), include_attributes=False))
        substituted_original = original_remote.replace('__BYTES__', str(len(programme))).replace(
            '__SHA__', repr(sha(programme))).replace('__BOOT__', repr(bootstrap))
        self.assertEqual(substituted_original.count('deadline=collection_started+1200'), 1)
        inverse = remote.replace('deadline=collection_started+50', 'deadline=collection_started+1200')
        self.assertEqual(inverse, substituted_original)
        self.assertEqual(ast.dump(ast.parse(inverse), include_attributes=False),
                         ast.dump(ast.parse(substituted_original), include_attributes=False))
        cold = ns['literal'](RAW['coldboot'], '_BOOT')
        context_and_helpers(programme, cold, ns['READS']['coldboot'])
        self.assertEqual(execute_harmless(programme, 0),
            (json.dumps(FINITE, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode())
        with self.assertRaisesRegex(ValueError, '^coldboot_root_required$'):
            execute_harmless(programme, 1000)
        self.assertEqual(len(audit['helpers']), 9)
        OBSERVATIONS.append(dict(bridgeProgrammeSha256=sha(programme), bridgeProgrammeBytes=len(programme),
            rootBootSha256=sha(root.encode()), rootBootBytes=len(root.encode()), rootBootByteAndAstInverse=True,
            remoteByteAndAstInverse=True, onlyRemoteDeadline1200To50=True,
            bridgeHelpers=9, mockedRootFinite=True, mocked1000Refused=True,
            rootBootOrRemoteExecuted=False, linuxProof=False))




_POSIX_CUSTODY = (os.name == 'posix' and all(hasattr(os, name) for name in
    ('getuid', 'geteuid', 'getgid', 'getegid', 'getgroups', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_DIRECTORY', 'pread'))
    and os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd)


def _canonical_nul_guard(template):
    rows = [node for node in ast.walk(ast.parse(template)) if isinstance(node, ast.If)
            and any(isinstance(child, ast.Constant) and child.value == b'\0'
                    for child in ast.walk(node.test))]
    if len(rows) != 1:
        raise AssertionError('canonical_nul_guard_changed')
    return rows[0]


class PublicExtractionInverseTest(unittest.TestCase):
    def test_identity_and_bridge_functions_match_authentic_public_archive(self):
        import inspect
        for name, archive, original in (
            ('assignment', 'identity', 'assignment'),
            ('emit_identity', 'identity', 'emit'),
            ('literal', 'bridge', 'literal'),
            ('emit_control', 'bridge', 'emit_control'),
            ('receiver_source', 'bridge', 'receiver_source'),
            ('prepare_receiver_frame', 'bridge', 'prepare_receiver_frame'),
        ):
            current = ast.parse(inspect.getsource(getattr(assembly, name))).body[0]
            current.name = original
            archived = next(node for node in ast.parse(RAW[archive]).body
                            if isinstance(node, ast.FunctionDef) and node.name == original)
            self.assertEqual(ast.dump(current, include_attributes=False),
                             ast.dump(archived, include_attributes=False))
        current = inspect.getsource(assembly.prepare_auth_frame)
        archived = next(node for node in ast.parse(RAW['bridge']).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'prepare_auth_frame')
        before = ast.get_source_segment(RAW['bridge'].decode(), archived)
        self.assertEqual(current.count(r" or b'\0' in credential"), 1)
        self.assertEqual(current.rstrip().replace(r" or b'\0' in credential", '', 1), before)


@unittest.skipUnless(_POSIX_CUSTODY, 'genuine POSIX descriptor custody API unavailable')
class PrivateFrameCustodyTest(unittest.TestCase):
    def _credential(self, fixture, raw):
        path = fixture.root / 'synthetic.private'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            fixture.assert_write(fd, raw)
        finally:
            os.close(fd)
        return path

    def _fixture(self):
        return HeldFixture({'programme': OWN_CONTROL})

    def test_nul_own_credential_refused_before_frame(self):
        collector = assembly.literal(RAW['collector'], 'COLLECTOR_SOURCE')
        credential = b'OWN-SYNTHETIC\0CREDENTIAL'
        for name, operand, value, enum in (
            ('ROOT_BOOT', 'first', credential, 'baseline_root_credential_frame_unknown'),
            ('REMOTE', 'secret', credential + b'\n', 'baseline_credential_envelope_unknown')):
            node = _canonical_nul_guard(assembly.literal(collector, name))
            with self.assertRaisesRegex(ValueError, '^' + enum + '$'):
                exec(compile(ast.Module(body=[node], type_ignores=[]),
                             '<canonical-refusal-only>', 'exec'), {operand: value})
        fixture = self._fixture()
        try:
            path = self._credential(fixture, credential)
            refusal = None
            frame = None
            try:
                frame = assembly.prepare_receiver_frame(path, fixture.held, fixture.guard, OWN_CONTROL)
            except ValueError as error:
                refusal = str(error)
            fixture.guard()
            self.assertEqual(refusal, 'control_private_auth_shape')
            self.assertIsNone(frame)
        finally:
            fixture.close()

    def test_valid_frame_and_length_crlf_shape_controls(self):
        for raw, valid in ((b'SYNTHETIC', True), (b'SYNTHETIC\r\n', True),
                           (b'A' * 512, True), (b'', False), (b'A' * 513, False),
                           (b'A\nB', False), (b'A\rB', False)):
            with self.subTest(length=len(raw), valid=valid):
                fixture = self._fixture()
                try:
                    path = self._credential(fixture, raw)
                    if valid:
                        frame = assembly.prepare_auth_frame(path, fixture.held, fixture.guard, OWN_CONTROL)
                        expected_header = ('VPNCONTROL_COMPONENT_SOURCE_V1 ' + str(len(OWN_CONTROL))
                                           + ' ' + sha(OWN_CONTROL) + '\n').encode('ascii')
                        self.assertEqual(frame, raw.rstrip(b'\r\n') + b'\n' + expected_header + OWN_CONTROL)
                    else:
                        with self.assertRaisesRegex(ValueError, '^control_private_auth_shape$'):
                            assembly.prepare_auth_frame(path, fixture.held, fixture.guard, OWN_CONTROL)
                finally:
                    fixture.close()

    def test_snapshot_refuses_mode_link_and_symlink_and_guarded_uid(self):
        for change in ('mode', 'link', 'symlink', 'uid'):
            with self.subTest(change=change):
                fixture = self._fixture()
                try:
                    path = self._credential(fixture, b'SYNTHETIC')
                    if change == 'mode':
                        os.chmod(path, 0o644)
                    elif change == 'link':
                        os.link(path, fixture.root / 'hardlink')
                    elif change == 'symlink':
                        target = fixture.root / 'real.private'
                        path.rename(target)
                        path.symlink_to(target)
                    if change == 'uid':
                        with mock.patch.object(os, 'getuid', return_value=os.getuid() + 1):
                            with self.assertRaisesRegex(ValueError, '^direct_file_invalid$'):
                                assembly.direct.snapshot(path, private=True, limit=514)
                    else:
                        with self.assertRaises((ValueError, OSError)):
                            assembly.direct.snapshot(path, private=True, limit=514)
                finally:
                    fixture.close()

    def test_source_and_held_generation_mutations_refused(self):
        for stage in ('source', 'held_body', 'held_generation'):
            with self.subTest(stage=stage):
                fixture = self._fixture()
                try:
                    path = self._credential(fixture, b'SYNTHETIC')
                    count = 0
                    def guard():
                        nonlocal count
                        count += 1
                        if count == 3:
                            if stage == 'source':
                                raise ValueError('own_source_changed')
                            if stage == 'held_body':
                                path.write_bytes(b'MUTATIONS')
                            else:
                                os.chmod(path, 0o400)
                        # Body hash check below must detect a mutated held body.
                        # Generation check below detects the changed permission.
                    enum = {'source': 'own_source_changed', 'held_body': 'control_held_body_changed',
                            'held_generation': 'direct_dispatch_changed'}[stage]
                    with self.assertRaisesRegex(ValueError, '^' + enum + '$'):
                        assembly.prepare_auth_frame(path, fixture.held, guard, OWN_CONTROL)
                finally:
                    fixture.close()

    def test_attempt_all_descriptor_close_after_one_failure(self):
        fixture = self._fixture()
        expected = {fd for _, _, chain, leaf in fixture.held for fd in (leaf, *(row[1] for row in chain))}
        real_close = os.close
        attempts = []
        injected = False
        def close(fd):
            nonlocal injected
            attempts.append(fd)
            real_close(fd)
            if not injected:
                injected = True
                raise OSError(errno.EBADF, 'own injected close observation')
        with mock.patch.object(os, 'close', side_effect=close):
            fixture.close()
        self.assertTrue(injected)
        self.assertEqual(set(attempts[:len(expected)]), expected)
        self.assertEqual(len(attempts[:len(expected)]), len(set(attempts[:len(expected)])))
        self.assertGreater(len(expected), 1)
        self.assertTrue(OBSERVATIONS[-1]['allDescriptorsClosed'])


if __name__ == '__main__':
    unittest.main()
