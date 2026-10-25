"""Actual pipe/private metadata negatives; NEVER executes GUI/credential bodies."""
import ast
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest

from agent_tools import private_inventory_lock as private


def need(value,reason):
    if not value:raise RuntimeError(reason)


class ProtectedUnlockCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=(Path(__file__).parent/'fixtures/tart_macos_protected_unlock_caller.source').read_bytes()
        if hashlib.sha256(cls.raw).hexdigest()!='032d5c6966d1ed15f486a828b990cf7ef0bbacff419b46ec012d222f249b6267':
            raise AssertionError('prepared source custody changed')
        cls.tree=ast.parse(cls.raw)
        observer=next(n for n in cls.tree.body if isinstance(n,ast.ClassDef)and n.name=='SessionObserver')
        cls.scope={'need':need,'time':time,'os':os,'select':select,'json':json}
        exec(compile(ast.Module(body=[observer],type_ignores=[]),'<prepared-observer-only>','exec'),cls.scope)
        cls.observer=cls.scope['SessionObserver']
        unlock=next(n for n in cls.tree.body if isinstance(n,ast.FunctionDef)and n.name=='unlock_once')
        cls.record_ast=next(n for n in ast.walk(unlock)if isinstance(n,ast.FunctionDef)and n.name=='record')
        cls.code_guard=next(n for n in ast.walk(unlock)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)
            and isinstance(n.value.func,ast.Name)and n.value.func.id=='need'and any(
                isinstance(item,ast.Name)and item.id=='_EXECUTING_CODE'for item in ast.walk(n)))
    def setUp(self):
        if os.name!='posix':self.skipTest('private Mac pipe/directory caller requires POSIX host')
        self.expected={'target':'selected-mac','machine':'selected-machine','boot':'selected-boot','rawBoot':'SELECTED-BOOT',
            'uid':502,'principal':'toolrecovery','home':'/Users/toolrecovery','agent':{'pid':17,'birth':'darwin:100:1','uid':502},
            'console':{'uid':502,'name':'toolrecovery','session':'100237','onConsole':True,'loginDone':True,'locked':True},'display':'ready'}
    def read(self,raw,expired=False):
        reader,writer=os.pipe()
        try:
            os.write(writer,raw);os.close(writer);writer=None
            stream=os.fdopen(reader,'rb',buffering=0);reader=None
            try:
                observer=object.__new__(self.observer);observer.process=SimpleNamespace(stdout=stream)
                observer.buffer=bytearray();observer.deadline=time.monotonic()+1 if not expired else time.monotonic()-1
                observer.expected=self.expected
                value=observer.read()
                need(value['state']=='observed','ordinary_observer_reply_invalid')
                return observer.validate(value['observation'])
            finally:stream.close()
        finally:
            if reader is not None:os.close(reader)
            if writer is not None:os.close(writer)
    def test_actual_pipe_duplicate_nested_nan_schema_overflow_and_timeout_never_echo_private(self):
        valid=json.dumps({'state':'observed','observation':self.expected}).encode()
        variants=[b'{"state":"observed","state":"PRIVATE","observation":{}}\n',
            b'{"state":"observed","observation":{"machine":"PRIVATE","machine":"again"}}\n',
            b'{"state":"observed","observation":NaN}\n',b'{"state":"observed","observation":Infinity}\n',
            b'{"state":"observed","observation":{},"PRIVATE":"unexpected"}\n',b'PRIVATE'+b'x'*17000]
        for raw in variants:
            with self.subTest(length=len(raw)),self.assertRaises(RuntimeError)as error:self.read(raw)
            self.assertNotIn('PRIVATE',str(error.exception));self.assertLess(len(str(error.exception)),80)
        with self.assertRaisesRegex(RuntimeError,'ordinary_observer_deadline'):self.read(b'PRIVATE',expired=True)
        self.assertEqual(self.expected,self.read(valid+b'\n'))
    def test_wrong_target_session_account_or_nonbool_lock_stops_before_input(self):
        for key,value in (('target','another'),('machine','another'),('rawBoot','another'),('uid',True)):
            packet={**self.expected,key:value}
            with self.subTest(key=key),self.assertRaises(RuntimeError):
                self.read(json.dumps({'state':'observed','observation':packet}).encode()+b'\n')
        for key,value in (('locked',1),('session','another'),('loginDone',False)):
            packet={**self.expected,'console':{**self.expected['console'],key:value}}
            with self.subTest(console=key),self.assertRaises(RuntimeError):
                self.read(json.dumps({'state':'observed','observation':packet}).encode()+b'\n')
    def test_actual_create_only_record_never_overwrites_receipt_or_follows_symlink(self):
        with tempfile.TemporaryDirectory()as temporary,ExitStack()as held:
            root=Path(temporary).resolve();root.chmod(0o700);directory=held.enter_context(private.Directory(root))
            scope={'directory':directory,'os':os,'json':json}
            exec(compile(ast.Module(body=[self.record_ast],type_ignores=[]),'<prepared-record-only>','exec'),scope)
            record=scope['record'];before=b'original-PRIVATE-receipt';path=root/'phase-unknown.json';path.write_bytes(before)
            with self.assertRaises(FileExistsError):record(path.name,{'state':'changed'})
            self.assertEqual(before,path.read_bytes())
            external=root/'external';external.write_bytes(before);(root/'symlink.json').symlink_to(external)
            with self.assertRaises(FileExistsError):record('symlink.json',{'state':'changed'})
            self.assertEqual(before,external.read_bytes())
            record('new.json',{'state':'unknown_no_replay'})
            self.assertEqual(0o600,stat.S_IMODE((root/'new.json').stat().st_mode))
            self.assertEqual({'state':'unknown_no_replay'},json.loads((root/'new.json').read_bytes()))
    def test_missing_changed_source_and_old_unpinned_helper_do_not_execute_or_record(self):
        with tempfile.TemporaryDirectory()as temporary,ExitStack()as held:
            self.assertFalse(any(isinstance(node,ast.Name)and node.id=='runpy'for node in ast.walk(self.tree)))
            self.assertNotIn(b'macos-provision-ui-helper.py',self.raw)
            root=Path(temporary).resolve();root.chmod(0o700);directory=held.enter_context(private.Directory(root))
            path=root/'unlock-once.py';loaded=compile(self.raw,str(path),'exec',dont_inherit=True,optimize=sys.flags.optimize)
            scope={'need':need,'_EXECUTING_CODE':loaded,'__file__':str(path),'sys':sys};events=[]
            def guarded():
                with private.Snapshot(directory,path.name)as source:
                    scope['source']=source
                    exec(compile(ast.Module(body=[self.code_guard],type_ignores=[]),'<prepared-code-guard>','exec'),scope)
                    events.append('safe_after_guard')
            with self.assertRaises((FileNotFoundError,ValueError,RuntimeError)):guarded()
            path.write_bytes(b'raise RuntimeError("PRIVATE changed source must not execute")\n');path.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError,'ordinary_executed_source_changed'):guarded()
            self.assertEqual([],events)
            path.write_bytes(self.raw)
            # Removed runpy helper is irrelevant; neither missing nor altered
            # unrelated helper may be loaded by the selected current guard.
            guarded();(root/'macos-provision-ui-helper.py').write_bytes(b'raise RuntimeError("PRIVATE")')
            guarded();self.assertEqual(['safe_after_guard','safe_after_guard'],events)
            self.assertFalse(any(root.glob('phase-*.json')))


if __name__=='__main__':unittest.main()
