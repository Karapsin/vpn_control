import ast
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
from contextlib import ExitStack
import unittest
from unittest import mock
from agent_tools import ssh_nested_socket_owned_home_observation as new
from agent_tools import ssh_nested_socket_noninteractive_observation as previous
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools.tests import test_ssh_nested_socket_retirement as old_tests


class OwnedHomeObserverTests(unittest.TestCase):
    def functions(self,source):
        tree=ast.parse(source);nodes=[n for n in tree.body if not isinstance(n,ast.Expr)]
        # Omit only the fixed entrypoint assignment after definitions.
        nodes=[n for n in nodes if not isinstance(n,ast.Assign) or not any(isinstance(t,ast.Name) and t.id=='spec' for t in n.targets)]
        ns={};exec(compile(ast.Module(body=nodes,type_ignores=[]),'generated','exec'),ns);return ns

    def test_captured_home_identity_form_passes_generated_effective_route(self):
        ns=self.functions(new.remote_source())
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        response=subprocess.CompletedProcess([],0,b'identityfile ~/.ssh/fixture_key01\n',b'')
        with mock.patch.object(subprocess,'run',return_value=response),mock.patch.object(os.path,'lexists',return_value=True),mock.patch.dict(ns,{'file_pin':mock.Mock(return_value={'generation':[1]*9}),'owned_home_identity':lambda value:{'path':'/owned/home/.ssh/fixture_key01','home':None,'homePin':None}}):
            value=ns['effective_route'](spec)
        self.assertIn('/owned/home/.ssh/fixture_key01',value['keyMetadata'])

    def test_exact_home_owned_by_uid_and_only_literal_home_form(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            home=Path(tmp).resolve()
            with mock.patch.object(new.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(home))):
                expanded=new.owned_home_identity('~/.ssh/fixture_key01')
                self.assertEqual(str(home/'.ssh/fixture_key01'),expanded['path'])
                self.assertEqual(new.generation(home.stat()),expanded['homePin'])
                for key in ('~other/key','%d/key','~/key%token','key','./key','~/../key','~/key\n'):
                    with self.subTest(key=key),self.assertRaises(ValueError):new.owned_home_identity(key)
                home.chmod(0o777)
                with self.assertRaisesRegex(ValueError,'effective_home_foreign'):new.owned_home_identity('~/key')
            home.chmod(0o700)
            link=home/'home-link';link.symlink_to(home,target_is_directory=True)
            with mock.patch.object(new.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(link))),self.assertRaisesRegex(ValueError,'effective_home_foreign'):
                new.owned_home_identity('~/key')

    def full_fixture(self,root):
        spec=old_tests.ObserverTests().fixture(root)
        home=root/'home';home.mkdir(mode=0o700);ssh=home/'.ssh';ssh.mkdir(mode=0o700)
        key=ssh/'fixture_key01';key.write_bytes(b'inert fixture, never read');key.chmod(0o600)
        stdout=b'hostname target.example\nidentityfile ~/.ssh/fixture_key01\n'
        return spec,home,key,stdout

    def test_full_generated_flow_with_home_options_preserves_all_orphan_guards(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
            root=Path(tmp).resolve();spec,home,key,stdout=self.full_fixture(root);ns=self.functions(new.remote_source())
            # Simulate the safe Linux ancestry of this Mac-hosted fixture only.
            stack.enter_context(old_tests.ObserverTests().controlled()[0])
            stack.enter_context(mock.patch.object(new.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(home))))
            ns['read_table']=lambda:frozen.HEADER;ns['net_namespace']=lambda:{'link':'net:[1]','generation':[1]*9}
            calls=[]
            def ssh(argv,**kwargs):
                calls.append(argv)
                self.assertIn('-T',argv)
                if '-G' in argv:return subprocess.CompletedProcess(argv,0,stdout,b'')
                self.assertEqual(['-O','check','target'],argv[-3:])
                return subprocess.CompletedProcess(argv,255,b'',('Control socket connect('+spec['controlPath']+'): Connection refused\n').encode())
            original_open=os.open
            def no_key_body(path,*args,**kwargs):
                if str(path)==key.name:raise AssertionError('private key opened')
                return original_open(path,*args,**kwargs)
            stack.enter_context(mock.patch.object(subprocess,'run',side_effect=ssh));stack.enter_context(mock.patch.object(os,'open',side_effect=no_key_body))
            result=ns['observe_remote'](spec)
            self.assertEqual('owned-orphan-observed',result['state']);self.assertEqual(2,len(result['observations']))
            self.assertFalse(result['credentialRead']);self.assertEqual(5,len(calls))
            self.assertIn(str(key),result['effectiveRoute']['keyMetadata'])

    def test_generated_key_symlink_and_home_change_fail_closed(self):
        for attack in ('key-symlink','home-change','key-parent-symlink'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp,ExitStack() as stack:
                root=Path(tmp).resolve();spec,home,key,stdout=self.full_fixture(root);ns=self.functions(new.remote_source())
                stack.enter_context(mock.patch.object(new.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir=str(home))))
                if attack=='key-symlink':key.rename(key.with_name('saved'));key.symlink_to('saved')
                elif attack=='key-parent-symlink':key.parent.rename(home/'saved');(home/'.ssh').symlink_to(home/'saved',target_is_directory=True)
                else:
                    real=ns['file_pin']
                    def change(*args,**kwargs):
                        value=real(*args,**kwargs);home.chmod(0o500);home.chmod(0o700);return value
                    ns['file_pin']=change
                stack.enter_context(mock.patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout,b'')))
                with self.assertRaises(ValueError):ns['effective_route'](spec)

    def test_source_closed_rewrite_preserves_other_remote_and_local_guards(self):
        source=new.remote_source();before=self.functions(previous.remote_source());after=self.functions(source)
        old_nodes={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(previous.remote_source()).body if isinstance(n,ast.FunctionDef)}
        new_nodes={n.name:ast.dump(n,include_attributes=False) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}
        for name,value in old_nodes.items():
            if name!='effective_route':self.assertEqual(value,new_nodes[name],name)
        self.assertEqual(set(old_nodes)|{'owned_home_identity'},set(new_nodes))
        self.assertTrue(callable(new._build_observe()))
        with self.assertRaisesRegex(ValueError,'rewrite_count_changed'):new._replace_once('aa','a','b')
        for forbidden in ('os.unlink','os.rename','os.kill','passphrase'):self.assertNotIn(forbidden,source)
        with self.assertRaisesRegex(ValueError,'separate_archive_proof_review_required'):new.retire(None)
