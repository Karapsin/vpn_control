"""Portable causal controls for the native same-UID proc permission failure."""
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import SimpleNamespace, ModuleType
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/integration/linux_owner_lifecycle_scenario.py'
spec = importlib.util.spec_from_file_location('owned_gui_cleanup', SOURCE)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class PrivilegedCleanupTests(unittest.TestCase):
    workspace = Path('/home/owned/scenario/workspace')
    boot = '818f8b4d-ebfb-4002-a1e5-402de3bbd5b4'

    def setUp(self):
        # Model the admitted Linux UID even on hosts lacking Unix UID APIs.
        for name in ('getuid', 'geteuid'):
            patcher = mock.patch.object(driver.os, name, return_value=1000, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)

    def permission_fixture(self):
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(mock.patch.object(driver.Path, 'iterdir', return_value=[Path('/proc/5533')]))
        stack.enter_context(mock.patch.object(driver.os, 'stat', return_value=SimpleNamespace(st_uid=os.geteuid(), st_mode=stat.S_IFDIR)))
        stack.enter_context(mock.patch.object(driver.os, 'readlink', side_effect=PermissionError(13, 'same-UID nondumpable systemd')))
        stack.enter_context(mock.patch.object(driver.Path, 'read_bytes', return_value=b'ordinary-user-systemd'))
        tail = ['0'] * 20
        tail[0] = 'S'
        tail[19] = '111149'
        stack.enter_context(mock.patch.object(driver.Path, 'read_text', autospec=True, side_effect=lambda p, *a, **k: self.boot if p.name == 'boot_id' else '5533 (systemd) ' + ' '.join(tail)))
        stack.enter_context(mock.patch.object(driver, 'birth', return_value=111149))
        return stack

    def producer(self, argv, **kwargs):
        self.assertEqual(argv[:3], ['/usr/bin/sudo', '-n', driver.sys.executable] if hasattr(driver, 'sys') else ['/usr/bin/sudo', '-n', __import__('sys').executable])
        self.assertEqual(argv[3:5], ['-I', '-c'])
        self.assertIn('root_read_capability_required', argv[5])
        request = json.loads(argv[6])
        self.assertEqual(request['workspace'], str(self.workspace))
        self.assertEqual(request['uid'], os.getuid())
        self.assertEqual(kwargs, {'capture_output': True, 'timeout': 15})
        self.request = request
        response = {k: request[k] for k in ('uid', 'caller', 'ticks', 'boot')}
        response.update(schemaVersion=1, complete=True, referencesAbsent=True)
        return SimpleNamespace(returncode=0, stderr=b'', stdout=json.dumps(response).encode())

    def test_actual_assertion_permission_failure_gets_complete_privileged_read(self):
        with self.permission_fixture(), mock.patch.object(driver.subprocess, 'run', side_effect=self.producer):
            result = driver.assert_no_workspace_refs(self.workspace)
        self.assertTrue(result['complete'])
        self.assertTrue(self.request['excludeCaller'])

    def test_actual_fd_scan_permission_failure_preserves_exact_owned_fd(self):
        with self.permission_fixture(), mock.patch.object(driver.subprocess, 'run', side_effect=self.producer):
            result = driver._no_process_uses_workspace(self.workspace, owned_cleanup_fd=17)
        self.assertTrue(result['referencesAbsent'])
        self.assertEqual(self.request['ownedFd'], 17)
        self.assertFalse(self.request['excludeCaller'])

    def test_unavailable_or_warning_privilege_refuses(self):
        for result in (SimpleNamespace(returncode=1, stderr=b'', stdout=b''), SimpleNamespace(returncode=0, stderr=b'warning', stdout=b'{}')):
            with self.subTest(result=result), self.permission_fixture(), mock.patch.object(driver.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(driver.ScenarioError, 'privileged_cleanup_census_unavailable'):
                    driver.assert_no_workspace_refs(self.workspace)

    def test_incomplete_or_wrong_identity_receipt_refuses(self):
        for change in ({'complete': False}, {'referencesAbsent': False}, {'schemaVersion': True}, {'uid': -1}):
            def changed(argv, **kwargs):
                result = self.producer(argv, **kwargs)
                value = json.loads(result.stdout)
                value.update(change)
                result.stdout = json.dumps(value).encode()
                return result
            with self.subTest(change=change), self.permission_fixture(), mock.patch.object(driver.subprocess, 'run', side_effect=changed):
                with self.assertRaises(driver.ScenarioError):
                    driver.assert_no_workspace_refs(self.workspace)

    def test_private_proc_fixture_never_triggers_privilege(self):
        with self.permission_fixture(), mock.patch.object(driver.subprocess, 'run') as run:
            with self.assertRaises(RuntimeError):
                driver._no_process_uses_workspace(self.workspace, proc=Path('/owned/proc-fixture'))
        run.assert_not_called()


class ActualRootCensusTests(unittest.TestCase):
    """Execute the exact emitted root observer, modeling only OS primitives."""
    def run_census(self, *, reference=None, owned_fd=None, caller_ticks=55,
                   boot='818f8b4d-ebfb-4002-a1e5-402de3bbd5b4', root_uid=0,
                   replaced_workspace=False, changed_process=False, capability=False):
        import contextlib
        import io
        workspace = '/home/owned/scenario/workspace'
        seen = {}
        class FakePath:
            def __init__(self, value): self.value = PurePosixPath(value)
            def __truediv__(self, part): return FakePath(self.value / part)
            def __str__(self): return str(self.value)
            def __eq__(self, other): return str(self) == str(other)
            @property
            def name(self): return self.value.name
            @property
            def parent(self): return FakePath(self.value.parent)
            def is_absolute(self): return self.value.is_absolute()
            def resolve(self, strict=False): return self
            def is_dir(self): return True
            def stat(self):
                path = str(self)
                seen[path] = seen.get(path, 0) + 1
                inode = 10 if replaced_workspace and path == workspace and seen[path] > 1 else 9
                return SimpleNamespace(st_uid=1000, st_mode=stat.S_IFDIR, st_dev=5, st_ino=inode)
            def read_text(self):
                if self.name == 'boot_id': return '818f8b4d-ebfb-4002-a1e5-402de3bbd5b4'
                path = str(self)
                seen[path] = seen.get(path, 0) + 1
                tail = ['0'] * 20
                tail[0] = 'S'
                tail[19] = '56' if changed_process and '/5533/' in path and seen[path] > 1 else '55'
                return self.parent.name + ' (owned) ' + ' '.join(tail)
            def read_bytes(self):
                if reference == 'cmdline' and self.parent.name == '7777': return workspace.encode()
                return b'ordinary-owned-process'
            def iterdir(self):
                if str(self) == '/proc': return [FakePath('/proc/' + p) for p in ('4242', '5533', '7777')]
                if str(self) == '/proc/4242/fd' and owned_fd is not None:
                    return [self / str(owned_fd)]
                if str(self) == '/proc/7777/fd' and reference == 'fd': return [self / '8']
                return []
        def readlink(path):
            path = str(path)
            if path == '/proc/4242/fd/' + str(owned_fd): return workspace if reference != 'wrong-owned-fd' else '/other/workspace'
            if reference == 'cwd' and path == '/proc/7777/cwd': return workspace
            if reference == 'fd' and path == '/proc/7777/fd/8': return workspace + '/runtime.json'
            return '/'
        module = ModuleType('pathlib')
        module.Path = FakePath
        request = dict(workspace=workspace, uid=1000, caller=4242, ticks=caller_ticks,
                       boot=boot, ownedFd=owned_fd, excludeCaller=False)
        if capability:
            request = {k:request[k] for k in ('uid','caller','ticks','boot')}
        output = io.StringIO()
        with mock.patch.dict(sys.modules, {'pathlib': module}), \
             mock.patch.object(os, 'geteuid', return_value=root_uid, create=True), \
             mock.patch.object(os, 'getuid', return_value=root_uid, create=True), \
             mock.patch.object(os, 'readlink', side_effect=readlink, create=True), \
             mock.patch.object(sys, 'argv', ['fixed-root-census', json.dumps(request)]), \
             contextlib.redirect_stdout(output):
            body = driver.PRIVILEGED_READ_CAPABILITY if capability else driver.PRIVILEGED_CENSUS
            exec(compile(body, 'actual-fixed-root-census', 'exec'), {})
        return json.loads(output.getvalue())

    def test_actual_body_completes_reference_free_census(self):
        value = self.run_census()
        self.assertTrue(value['complete'])
        self.assertTrue(value['referencesAbsent'])
        self.assertEqual(value['processCount'], 3)

    def test_actual_body_refuses_active_references(self):
        for kind in ('cwd', 'fd', 'cmdline'):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'workspace_.*reference'):
                self.run_census(reference=kind)

    def test_actual_body_accepts_only_exact_owned_descriptor(self):
        self.assertTrue(self.run_census(owned_fd=17)['complete'])
        with self.assertRaisesRegex(RuntimeError, 'census_owned_fd_changed'):
            self.run_census(owned_fd=17, reference='wrong-owned-fd')

    def test_actual_body_refuses_wrong_identity_or_capability(self):
        for arguments, reason in (({'caller_ticks':56}, 'census_caller_changed'),
                                  ({'boot':'other-boot'}, 'census_boot_changed'),
                                  ({'root_uid':1000}, 'root_read_capability_required')):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(RuntimeError, reason):
                self.run_census(**arguments)

    def test_actual_body_refuses_generation_changes(self):
        for arguments, reason in (({'replaced_workspace':True}, 'census_workspace_generation_changed'),
                                  ({'changed_process':True}, 'census_process_generation_changed')):
            with self.subTest(arguments=arguments), self.assertRaisesRegex(RuntimeError, reason):
                self.run_census(**arguments)

    def test_actual_read_capability_body_qualifies_root_boot_and_caller(self):
        value = self.run_census(capability=True)
        self.assertEqual((value['effectiveUid'],value['realUid'],value['callerUid']), (0,0,1000))
        self.assertEqual(value['observedProcesses'], 3)
        for kwargs in ({'root_uid':1000}, {'boot':'other-boot'}, {'caller_ticks':56}, {'changed_process':True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.run_census(capability=True, **kwargs)


class ReadCapabilityAdmissionTests(unittest.TestCase):
    setUp = PrivilegedCleanupTests.setUp
    permission_fixture = PrivilegedCleanupTests.permission_fixture
    boot = PrivilegedCleanupTests.boot
    workspace = PrivilegedCleanupTests.workspace
    def produce_capability(self, argv, **kwargs):
        request = json.loads(argv[-1])
        self.assertIn('read_capability_root_required', argv[-2])
        value = dict(schemaVersion=1, complete=True, effectiveUid=0, realUid=0,
                     boot=request['boot'], caller=request['caller'], callerUid=request['uid'],
                     ticks=request['ticks'], observedProcesses=3)
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(value).encode())

    def test_read_capability_admitted_before_following_admission(self):
        class GateObserved(Exception): pass
        class LaterAdmission(Exception): pass
        guest=dict(schema='vpn-control.linux-owner-gui.guest',schemaVersion=1,host='owned',environment='owned',
                   bootId=self.boot,uid=1000,allocation={},ownedRoot='/home/owned/scenarios')
        admissions=dict(guest=guest,display={},fixture={},protected={},source={})
        with self.permission_fixture(), mock.patch.object(driver.sys,'platform','linux'), \
             mock.patch.object(driver,'_admit_privileged_read_capability',side_effect=GateObserved,create=True) as gate, \
             mock.patch.object(driver,'private_directory',side_effect=LaterAdmission):
            with self.assertRaises(GateObserved): driver.admission_probe({},admissions)
        gate.assert_called_once_with()

    def test_read_capability_response_is_exact_and_fail_closed(self):
        with self.permission_fixture(),mock.patch.object(driver.subprocess,'run',side_effect=self.produce_capability):
            self.assertTrue(driver._admit_privileged_read_capability()['complete'])
        changes = ({'effectiveUid':1000},{'callerUid':1},{'ticks':1},{'boot':'other'}, {'complete':False},
                   {'schemaVersion':True},{'caller':float(os.getpid())})
        for change in changes:
            def changed(argv,**kwargs):
                p=self.produce_capability(argv,**kwargs);v=json.loads(p.stdout);v.update(change);p.stdout=json.dumps(v).encode();return p
            with self.subTest(change=change),self.permission_fixture(),mock.patch.object(driver.subprocess,'run',side_effect=changed):
                with self.assertRaises(driver.ScenarioError): driver._admit_privileged_read_capability()
        failures=(SimpleNamespace(returncode=1,stderr=b'',stdout=b''),
                  SimpleNamespace(returncode=0,stderr=b'warning',stdout=b'{}'),
                  SimpleNamespace(returncode=0,stderr=b'',stdout=b'not JSON'))
        for failure in failures:
            with self.subTest(failure=failure),self.permission_fixture(),mock.patch.object(driver.subprocess,'run',return_value=failure):
                with self.assertRaises(driver.ScenarioError): driver._admit_privileged_read_capability()


if __name__ == '__main__':
    unittest.main()
