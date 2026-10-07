import ast
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import android_avd_launch_recovery as frozen
from agent_tools import android_avd_census_diagnostic as diagnostic
from agent_tools import android_avd_sdk_alias_census as recovery

class AdmittedAliasCensusTests(unittest.TestCase):
    def scope(self,base):
        nodes=[n for n in ast.parse(frozen._CENSUS).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        scope={'ROOT':base};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-frozen-census>','exec'),scope);exec(diagnostic._TRACE,scope)
        return scope
    def fixture(self,base):
        scope=self.scope(base);parent=base/'private-sdk';parent.mkdir();target=base/'known-system-images';target.mkdir();leaf=target/'kernel-ranchu';leaf.write_bytes(b'kernel');alias=parent/'system-images';alias.symlink_to(target,target_is_directory=True)
        correlation='11111111-1111-4111-8111-111111111111';capsule=base/('android-avd-privileged-census-'+correlation+'.json');capsule.write_bytes(b'authenticated alias proof');pin=scope['read_fixed'](capsule,524288);pin.pop('raw')
        chain,name=scope['parent_fds'](alias)
        try:ancestors=[x['pin'] for x in chain[1:]]
        finally:scope['close_parents'](chain)
        entry=scope['facts'](leaf,16777216);known={'path':str(alias),'ancestors':ancestors,'linkGeneration':scope['fp'](alias.lstat()),'linkText':str(target),'target':str(target),'targetDirectoryGeneration':scope['fp'](target.stat()),'files':{str(alias/'kernel-ranchu'):{'canonical':str(leaf),'facts':entry}},'correlationId':correlation,'capturePin':pin}
        return scope,known,alias,target,leaf,capsule
    def install(self,scope,known):exec(recovery._SAFE.replace('__KNOWN__',repr(known)),scope)
    def test_actual_frozen_enotdir_then_only_proven_alias_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve())
            with self.assertRaises(OSError):scope['read_fixed'](alias/'kernel-ranchu',16777216)
            self.install(scope,known);actual=scope['read_fixed'](alias/'kernel-ranchu',16777216)
            self.assertEqual(b'kernel',actual['raw']);self.assertEqual(known['files'][str(alias/'kernel-ranchu')]['facts']['generation'],actual['generation'])
    def test_exchanged_same_target_alias_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve());self.install(scope,known);alias.unlink();alias.symlink_to(target,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'alias_(ancestor|link)_changed'):scope['read_fixed'](alias/'kernel-ranchu',16777216)
    def test_exchanged_same_bytes_target_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve());self.install(scope,known);leaf.rename(leaf.with_name('old'));leaf.write_bytes(b'kernel')
            with self.assertRaisesRegex(ValueError,'alias_(target|leaf)_changed'):scope['read_fixed'](alias/'kernel-ranchu',16777216)
    def test_target_exchange_during_actual_leaf_read_rejects(self):
        real=os.read;changed=[]
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve());self.install(scope,known);wanted=leaf.stat().st_ino
            def exchange(fd,n):
                raw=real(fd,n)
                if os.fstat(fd).st_ino==wanted and not changed:leaf.rename(leaf.with_name('old'));leaf.write_bytes(b'kernel');changed.append(True)
                return raw
            with mock.patch.object(scope['os'],'read',side_effect=exchange),self.assertRaisesRegex(ValueError,'(?:census_(?:file|ancestry)_changed|alias_ancestor_changed)'):scope['read_fixed'](alias/'kernel-ranchu',16777216)
    def test_other_alias_never_receives_follow_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve());foreign=target.parent/'foreign';foreign.symlink_to(target,target_is_directory=True)
            # Refresh only this inert fixture's existing parent generations after setup.
            chain,name=scope['parent_fds'](alias)
            try:known['ancestors']=[x['pin'] for x in chain[1:]]
            finally:scope['close_parents'](chain)
            self.install(scope,known)
            with self.assertRaises(OSError):scope['read_fixed'](foreign/'kernel-ranchu',16777216)
    def test_alias_capture_same_bytes_generation_exchange_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope,known,alias,target,leaf,capsule=self.fixture(Path(tmp).resolve());self.install(scope,known);raw=capsule.read_bytes();capsule.rename(capsule.with_name('old'));capsule.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'alias_history_changed'):scope['read_fixed'](alias/'kernel-ranchu',16777216)
