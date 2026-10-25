"""Actual generated saved-program callers retain private keys without hashing."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import types
import unittest
import uuid
from unittest import mock

from agent_tools import ssh_automatic_program as automatic
from agent_tools import ssh_transport as transport
from agent_tools.tests import test_ssh_automatic_program as fixtures

BASE=Path(__file__).with_name('fixtures')/'tmux_private_transport_v2'
BEFORE_SHA='91ab9f37a5fdd21a069e481fec65142adcbb4c53d0afbfd8d69584da206926f8'
TOOLS=Path(automatic.__file__).parent


@unittest.skipUnless(os.name=='posix','protected POSIX key ownership')
class KeyCustodyTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.AutomaticProgramTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root;self.peer=self.fixture.peer
        self.key=self.root/'inert-key';self.secret=secrets.token_hex(24).encode()
        self.key.write_bytes(self.secret)

    @contextmanager
    def before(self):
        raw=(BASE/'ssh_automatic_program.py.before.source').read_bytes()
        self.assertEqual(BEFORE_SHA,hashlib.sha256(raw).hexdigest())
        directory=self.root/'original-public-automatic';directory.mkdir()
        path=directory/'ssh_automatic_program.py';path.write_bytes(raw)
        for name in ('native_review_source_closure.py','private_config_custody.py','ssh_privileged_program.py'):
            shutil.copyfile(TOOLS/name,directory/name)
        name='agent_tools._private_key_before_'+uuid.uuid4().hex
        module=types.ModuleType(name);module.__file__=str(path);module.__package__='agent_tools';sys.modules[name]=module
        try:
            exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
            yield module
        finally:sys.modules.pop(name,None)

    def bind(self,module):
        config=transport.load_config(self.root);command=fixtures.long_command('KEY_CUSTODY')
        argv=transport._build_ssh_argv(config,'explicit-peer',5,command,str(self.peer.binary),str(self.peer.binary))
        return module.bind(config,'explicit-peer',5,command,str(self.peer.binary),str(self.peer.binary),argv,force_file=True)

    def spy(self):
        original=hashlib.sha256;seen=[]
        def digest(raw=b'',*args,**kwargs):
            if self.secret in raw:seen.append(True)
            return original(raw,*args,**kwargs)
        return mock.patch.object(hashlib,'sha256',side_effect=digest),seen

    def execute(self,module):
        plan=self.bind(module)
        with self.peer.environment(),module.automatic_submission(plan)as argv:
            completed=transport.run_ssh(argv,input=b'PUBLIC payload',capture_output=True,timeout=10)
        self.assertEqual(0,completed.returncode,completed.stderr)
        self.assertEqual('KEY_CUSTODY',json.loads(completed.stdout)['marker'])
        return plan

    def test_authentic_before_full_generated_caller_key_hash_red_current_nohash_green(self):
        with self.before()as before:
            patch,seen=self.spy()
            with patch:old=self.execute(before)
            self.assertTrue(seen)
            self.assertIn(str(self.key),dict(old.source_pins))
        patch,seen=self.spy()
        with patch:plan=self.execute(automatic)
        self.assertEqual([],seen)
        self.assertNotIn(str(self.key),dict(plan.source_pins))
        self.assertIn(str(self.root/'inert-known'),dict(plan.source_pins))
        self.assertEqual([],plan.key_custody._fds);self.assertEqual([],plan.config_custody._fds)
        for path in (self.root/'.rag_index/ssh-automatic-program').rglob('*'):
            if path.is_file():self.assertNotIn(self.secret,path.read_bytes())

    def test_inline_private_key_replaced_or_changed_blocks_before_any_child(self):
        for kind in ('replace','inplace'):
            with self.subTest(kind=kind):
                config=transport.load_config(self.root)
                argv=transport.build_ssh_argv(config,'explicit-peer',5,('python3','-c','print(1)'),str(self.peer.binary),str(self.peer.binary))
                self.assertIsInstance(argv,transport.BoundInlineArgv)
                raw=self.key.read_bytes()
                if kind=='replace':
                    new=self.root/'replacement';new.write_bytes(raw);new.chmod(0o600);new.replace(self.key)
                else:self.key.write_bytes(raw+b' changed')
                with mock.patch.object(subprocess,'Popen')as child:
                    with self.assertRaises(ValueError):transport.run_ssh(argv,capture_output=True,timeout=1)
                    child.assert_not_called()
                argv.saved_plan.close();self.key.write_bytes(raw)

    def test_key_change_after_real_transfer_preserves_stage_without_target_execution(self):
        plan=self.bind(automatic);stage=automatic._stage
        def changed(*args,**kwargs):
            result=stage(*args,**kwargs);self.key.write_bytes(self.secret+b' changed');return result
        with self.peer.environment(),mock.patch.object(automatic,'_stage',side_effect=changed):
            with self.assertRaises(ValueError):
                with automatic.automatic_submission(plan):self.fail('target dispatch must not be yielded')
        directory=self.root/'.rag_index/ssh-automatic-program'/plan.correlation
        self.assertTrue((directory/'staged.json').is_file())
        self.assertFalse((directory/'execution-intent.json').exists())
        self.assertEqual([],plan.key_custody._fds)

    def test_bind_exception_explicit_close_and_cancellation_release_both_owners(self):
        owners=[];helper=automatic._private_config();original=helper.PrivateConfigCustody
        def create(*args,**kwargs):
            owner=original(*args,**kwargs);owners.append(owner);return owner
        with mock.patch.object(automatic,'_private_config',return_value=helper),mock.patch.object(helper,'PrivateConfigCustody',side_effect=create),mock.patch.object(automatic,'_preflight',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.bind(automatic)
        self.assertEqual(2,len(owners))
        for owner in owners:self.assertEqual([],owner._fds)
        plan=self.bind(automatic);plan.close();plan.close()
        self.assertEqual([],plan.key_custody._fds)
        with self.assertRaises(ValueError):plan.check_source_custody()
        plan=self.bind(automatic)
        with self.peer.environment():
            with self.assertRaises(KeyboardInterrupt):
                with automatic.automatic_submission(plan):raise KeyboardInterrupt
        self.assertEqual([],plan.key_custody._fds);self.assertEqual([],plan.config_custody._fds)


if __name__=='__main__':unittest.main()
