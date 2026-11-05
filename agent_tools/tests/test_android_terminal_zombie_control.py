"""Pure composed-control tests. No subprocess, privilege change or Linux call."""
import ast
import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import types
import unittest

PACKET = Path(__file__).parent / 'fixtures/android_terminal_zombie_retry'


def need(value, code):
    if not value:
        raise ValueError(code)


def definition(tree, name):
    return next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == name)


class NativeControlSourceTests(unittest.TestCase):
    def source(self, before=False):
        path = PACKET / ('native-control.phase-before-receiver-close.source' if before
                         else 'native-control.phase.py')
        return path.read_bytes()

    def test_control_import_performs_no_action_and_has_no_signal_or_poll(self):
        raw = self.source()
        namespace = {}
        exec(compile(raw, 'held-source-only-native-control', 'exec'), namespace)
        self.assertIn('run_control', namespace)
        calls = [node for node in ast.walk(ast.parse(raw)) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Attribute)
                             and node.func.attr in ('kill', 'terminate', 'send_signal', 'poll', 'killpg')
                             for node in calls))

    def test_real_child_source_drops_exact_custody_then_accepts_only_EOF(self):
        namespace = {}
        exec(compile(self.source(), 'held-control-child-definition', 'exec'), namespace)
        calls = []
        fake_os = types.SimpleNamespace(
            setgroups=lambda value:calls.append(('setgroups', value)),
            setgid=lambda value:calls.append(('setgid', value)),
            setuid=lambda value:calls.append(('setuid', value)),
            getpid=lambda:501, getuid=lambda:1000, geteuid=lambda:1000,
            getgid=lambda:1000, getegid=lambda:1000, getgroups=lambda:[1000], getsid=lambda pid:501)
        fake_sys = types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=io.BytesIO(b'')))
        original = builtins.__import__
        def imported(name, *args, **kwargs):
            if name == 'os':return fake_os
            if name == 'sys':return fake_sys
            return original(name, *args, **kwargs)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(namespace['TERMINAL_CHILD_SOURCE'], 'actual-child-source-pure-import-seam', 'exec'),
                 {'__builtins__':dict(vars(builtins), __import__=imported)})
        self.assertEqual(calls, [('setgroups',[1000]),('setgid',1000),('setuid',1000)])
        lines = list(map(json.loads, output.getvalue().splitlines()))
        self.assertEqual(lines[0], {'kind':'owned-terminal-ready','pid':501,'uid':1000,'euid':1000,
                                   'gid':1000,'egid':1000,'groups':[1000],'sid':501})
        self.assertEqual(lines[1], {'kind':'owned-terminal-eof','bytes':0})

    def test_actual_terminal_selection_uses_EOF_then_two_Z_without_reap(self):
        raw = self.source()
        node = definition(ast.parse(raw), 'select_terminal')
        events = []
        stdin = types.SimpleNamespace(close=lambda:events.append('EOF'))
        state = {'child':types.SimpleNamespace(pid=501,stdin=stdin), 'ready':{'startTicks':601},
                 'triggered':False}
        queue = iter(['R','S','Z','Z'])
        def kernel_stat(pid):
            events.append('stat')
            return {'pid':pid,'state':next(queue),'startTicks':601}
        scope = {'state':state, 'need':need, 'birth':lambda pid:601, 'kernel_stat':kernel_stat,
                 'time':types.SimpleNamespace(monotonic=lambda:0, sleep=lambda value:events.append('sleep'))}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-select-terminal-source-pure-seams','exec'),scope)
        scope['select_terminal']()
        self.assertTrue(state['triggered'])
        self.assertEqual(events, ['EOF','stat','sleep','stat','sleep','stat','stat'])
        self.assertIsNone(state['child'].stdin)

    def test_actual_prereap_boundary_requires_two_same_birth_Z_and_returns_real_stat(self):
        node = definition(ast.parse(self.source()), 'observed')
        identity = object()
        events = []
        namespace = {}
        child = types.SimpleNamespace(wait=lambda timeout:(events.append('wait') or 0))
        state = {'ready':{'pid':501,'startTicks':601},'namespace':namespace,'opens':12,
                 'reapedDuringClosing':False,'child':child}
        def kernel_stat(pid):
            events.append('stat')
            return {'state':'Z','startTicks':601}
        scope = {'real':types.SimpleNamespace(stat=lambda *a,**k:(events.append('path') or identity)),
                 'state':state,'CONTROL_CASE':'current-pre-reaped','module':object(),
                 'current_namespace':lambda module:namespace,'kernel_stat':kernel_stat,'need':need}
        exec(compile(ast.Module(body=[node],type_ignores=[]),'actual-prereap-source-pure-seams','exec'),scope)
        self.assertIs(scope['observed']('/proc/501/stat',follow_symlinks=False), identity)
        self.assertTrue(state['reapedDuringClosing'])
        self.assertEqual(events,['path','stat','stat','wait'])
        state['reapedDuringClosing'] = False
        scope['kernel_stat'] = lambda pid:{'state':'Z','startTicks':602}
        events.clear()
        with self.assertRaisesRegex(ValueError,'not_exact_Z'):
            scope['observed']('/proc/501/stat',follow_symlinks=False)
        self.assertNotIn('wait',events)

    def test_original_control_code_and_actual_typed_refusal_are_preserved(self):
        before = os.environ.get('TERMINAL_CONTROL_REFUSAL_BEFORE') == '1'
        raw = ((PACKET / 'native-control.phase-before-fixed-refusal.source').read_bytes()
               if before else self.source())
        if before:
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             '71cc0b3014c4a7e0e8331f2354b5ef3a2b65185e0c3c21c400947cc7fd6764ee')
        producer = (PACKET / 'native-control.control-code.source').read_bytes()
        self.assertEqual(hashlib.sha256(producer).hexdigest(),
                         '857157269d0b519bbe4913b142d7d44eb91f38449d8d40163f3f92a29ee9858d')
        class CurrentIntervalRefusal(ValueError):pass
        def fail():raise CurrentIntervalRefusal('current_interval_nonretryable')
        module = types.SimpleNamespace(installer_host_preflight=fail,
                                       CurrentIntervalRefusal=CurrentIntervalRefusal)
        tree = ast.parse(raw)
        actual = next(node for node in ast.walk(definition(tree, 'terminal_kernel_phase'))
                      if isinstance(node,ast.Try) and any(isinstance(child,ast.Assign)
                          and any(isinstance(n,ast.Constant) and n.value == 'hostFailure'
                                  for n in ast.walk(child)) for handler in node.handlers for child in handler.body))
        scope = {'module':module,'result':{},'re':re}
        exec(compile(producer,'authentic-original-error-producer','exec'),scope)
        exec(compile(ast.Module(body=[actual],type_ignores=[]),'actual-host-catch-with-owned-exception','exec'),scope)
        self.assertIsNone(scope['host'])
        self.assertEqual(scope['result']['hostFailure']['code'],'CurrentIntervalRefusal')
        self.assertEqual(scope['result']['hostFailure'].get('fixedRefusalCode'),'current_interval_nonretryable')

    @unittest.skipUnless(os.name == 'posix', 'real owned descriptor closure requires POSIX')
    def test_authentic_receiver_parent_four_tuple_close_preserves_manifest(self):
        before = os.environ.get('TERMINAL_CONTROL_RECEIVER_BEFORE') == '1'
        raw = self.source(before)
        if before:
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             'd7e73381a014384f6a9037433e59a3c5ad23fe61051639f4f3fc9377c9691462')
        with tempfile.TemporaryDirectory() as directory:
            opened = [os.open(directory,os.O_RDONLY | os.O_DIRECTORY) for _ in range(3)]
            receiver = types.SimpleNamespace(ROOT_FD=opened[0],
                PARENTS=[(opened[1],'/',[],False),(opened[2],'/var',[],False)], guard_root=lambda:None)
            scope = {'os':os,'json':json,'OPERATION_ID':'00000000-0000-4000-8000-000000000001',
                     'need':need,'control_code':str}
            exec(compile(raw,'actual-whole-native-control-source-with-inert-phase','exec'),scope)
            scope['prepare_control_root'] = lambda:(receiver,{}, {'state':'owned-inert-prepared'})
            scope['terminal_kernel_phase'] = lambda *args:{'state':'unknown','nativeKernelAcceptance':False}
            output = io.StringIO()
            try:
                with contextlib.redirect_stdout(output):scope['run_control']()
                answer = json.loads(output.getvalue())
                self.assertEqual(answer['state'],'unknown')
                self.assertFalse(answer['report']['nativeKernelAcceptance'])
                self.assertIsNone(receiver.ROOT_FD)
                for fd in opened:
                    with self.assertRaises(OSError):os.fstat(fd)
            finally:
                for fd in opened:
                    with contextlib.suppress(OSError):os.close(fd)


if __name__ == '__main__':
    unittest.main()
