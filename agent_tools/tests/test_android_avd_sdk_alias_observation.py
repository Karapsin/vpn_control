import ast
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import android_avd_sdk_alias_observation as observation
from agent_tools import android_avd_launch_recovery as census

class SdkAliasTests(unittest.TestCase):
    def scope(self):
        old=[n for n in ast.parse(census._CENSUS).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        extra=[n for n in ast.parse(observation._ALIAS).body if isinstance(n,ast.FunctionDef) and n.name=='alias_fact']
        scope={};exec(compile(ast.Module(body=old+extra,type_ignores=[]),'<actual-sdk-alias-probe>','exec'),scope);return scope
    def fixture(self,scope,base):
        parent=base/'private-sdk';parent.mkdir();target=base/'known-system-images';target.mkdir();leaf=target/'kernel-ranchu';leaf.write_bytes(b'kernel');alias=parent/'system-images';alias.symlink_to(target,target_is_directory=True)
        chain,name=scope['parent_fds'](alias)
        try:ancestors=[x['pin'] for x in chain[1:]]
        finally:scope['close_parents'](chain)
        scope['ALIAS']={'path':str(alias),'target':str(target),'generation':scope['fp'](alias.lstat()),'ancestors':ancestors,'leaves':{'kernel-ranchu':scope['facts'](leaf,16777216)}}
        return alias,target,leaf
    def test_actual_legitimate_alias_rejected_by_frozen_reader_but_observed_explicitly(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            alias,target,leaf=self.fixture(scope,Path(tmp).resolve())
            with self.assertRaises(OSError):scope['read_fixed'](alias/'kernel-ranchu',16777216)
            result=scope['alias_fact']();self.assertTrue(result['targetMatchesKnownSDK']);self.assertTrue(result['allLeavesMatchHistorical'])
            self.assertEqual(str(target),result['normalizedTarget'])
    def test_same_target_link_generation_exchange_rejects(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            alias,target,leaf=self.fixture(scope,Path(tmp).resolve());alias.unlink();alias.symlink_to(target,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'alias_(link|ancestor)_changed'):scope['alias_fact']()
    def test_target_leaf_generation_exchange_during_read_rejects(self):
        scope=self.scope();real=os.read;changed=[]
        with tempfile.TemporaryDirectory() as tmp:
            alias,target,leaf=self.fixture(scope,Path(tmp).resolve())
            def exchange(fd,n):
                raw=real(fd,n)
                if not changed:leaf.rename(leaf.with_name('old'));leaf.write_bytes(b'kernel');changed.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=exchange),self.assertRaisesRegex(ValueError,'census_(file|ancestry)_changed'):scope['alias_fact']()
    def test_unapproved_target_is_reported_without_following_it(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            alias,target,leaf=self.fixture(scope,Path(tmp).resolve());scope['ALIAS']['target']=str(target.parent/'other-fixed-known-target')
            with mock.patch.dict(scope,{'facts':lambda *args:(_ for _ in ()).throw(AssertionError('unexpected target read'))}):result=scope['alias_fact']()
            self.assertFalse(result['targetMatchesKnownSDK']);self.assertFalse(result['allLeavesMatchHistorical']);self.assertEqual({},result['leaves'])
