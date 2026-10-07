"""Synthetic private-inventory regressions; never inspect coordinator inventory."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import native_vm_baseline_config as config
from agent_tools import native_vm_baseline_inventory as inventory


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'Strict private inventory requires POSIX nofollow')
class BaselineInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.vmroot = self.root / 'private-vms'
        self.vmroot.mkdir(mode=0o700)
        self.entry = {'provider':'qemu', 'sourceRoot':str(self.vmroot),
                      'sourcePath':str(self.vmroot/'fixture.qcow2'), 'generation':'generation-one',
                      'providerName':'private-provider-sentinel',
                      **{k:str(self.root/(k+'.json')) for k in
                         ('preparationReceiptPath','accessReceiptPath','dependencyReceiptPath','installerJobReceiptPath')}}
        self.doc = {'schemaVersion':1, 'hosts':{'secret-host':{'credential':'credential-sentinel-never-project'}},
                    'nativeBaselines':{'schemaVersion':1,'sources':{'source-one':self.entry}}}
        self.path = self.root / config.ssh_transport.CONFIG_FILENAME
        self.write()

    def write(self):
        self.path.write_text(json.dumps(self.doc))
        self.path.chmod(0o600)

    def observe(self):
        return inventory.configured_source_metadata(self.root)

    def test_exact_finite_projection_without_private_fields_or_native_reads(self):
        with patch.object(config, '_proofs', side_effect=AssertionError('proof read')), \
             patch.object(config, '_fixed_qemu_stopped', side_effect=AssertionError('native probe')), \
             patch.object(config, '_fixed_tart_stopped', side_effect=AssertionError('native probe')), \
             patch.object(config.subprocess, 'run', side_effect=AssertionError('native subprocess')):
            value = self.observe()
        self.assertEqual(value, {'schemaVersion':1, 'scope':'CONFIGURATION_METADATA_ONLY',
                                'sources':[{'sourceId':'source-one','provider':'qemu','generation':'generation-one'}],
                                'nativeActionAllowed':False,'readinessVerified':False})
        raw = json.dumps(value)
        for secret in ('credential-sentinel','private-provider-sentinel',str(self.root),'sourcePath','sourceSha256','inventorySha256'):
            self.assertNotIn(secret, raw)
        self.assertFalse((self.root/'.rag_index').exists())

    def test_tart_and_qemu_projection_sorted_without_source_or_receipt_reads(self):
        tartroot=self.root/'tart';tartroot.mkdir(mode=0o700)
        self.doc['nativeBaselines']['sources']['mac-one']={**self.entry,'provider':'tart',
            'sourceRoot':str(tartroot),'sourcePath':str(tartroot/'secret-vm'),'providerName':'secret-vm','generation':'generation-two'}
        self.write()
        self.assertEqual([v['sourceId'] for v in self.observe()['sources']], ['mac-one','source-one'])

    def test_unsafe_ids_generations_and_provider_refused_with_finite_error(self):
        original=json.loads(json.dumps(self.doc))
        for field,value in (('sourceId','../escape'),('generation','../escape'),('provider','shell'),('provider',True)):
            self.doc=json.loads(json.dumps(original))
            if field=='sourceId':self.doc['nativeBaselines']['sources']={value:self.entry}
            else:self.doc['nativeBaselines']['sources']['source-one'][field]=value
            self.write()
            with self.subTest(field=field,value=value), self.assertRaises(inventory.BaselineInventoryError) as caught:self.observe()
            self.assertEqual(str(caught.exception),'Configured baseline source metadata is unavailable.')

    def test_boolean_or_float_schema_versions_refused_by_actual_loader(self):
        original=json.loads(json.dumps(self.doc))
        for scope in ('top','nativeBaselines'):
            for version in (True,1.0):
                self.doc=json.loads(json.dumps(original))
                target=self.doc if scope=='top' else self.doc['nativeBaselines']
                target['schemaVersion']=version
                self.write()
                with self.subTest(scope=scope,version=version), self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_explicit_public_labels_preserved_without_string_secret_heuristics(self):
        self.doc['nativeBaselines']['sources']={'public-label-one':{**self.entry,'generation':'public-generation-one'}}
        self.write()
        self.assertEqual(self.observe()['sources'],[{'sourceId':'public-label-one','provider':'qemu','generation':'public-generation-one'}])

    def test_actual_parser_finite_reason_categories(self):
        original=json.loads(json.dumps(self.doc))
        cases=(('absent','baselines_not_configured'),('empty','baselines_not_configured'),
               ('malformed','baselines_not_configured'),('bad-schema','invalid_inventory'),
               ('bad-json','invalid_inventory'),('unsafe-root','invalid_source_configuration'),
               ('dangling-root','metadata_unavailable'))
        for case,reason in cases:
            self.doc=json.loads(json.dumps(original))
            if case=='absent':del self.doc['nativeBaselines']
            elif case=='empty':self.doc['nativeBaselines']['sources']={}
            elif case=='malformed':self.doc['nativeBaselines']='private-sensitive-sentinel'
            elif case=='bad-schema':self.doc['schemaVersion']=True
            elif case=='unsafe-root':self.doc['nativeBaselines']['sources']['source-one']['sourceRoot']='relative-private-sentinel'
            elif case=='dangling-root':
                entry=self.doc['nativeBaselines']['sources']['source-one']
                entry['sourceRoot']=str(self.root/'absent-root')
                entry['sourcePath']=str(self.root/'absent-root'/'fixture.qcow2')
            self.write()
            if case=='bad-json':self.path.write_text('{"private-sensitive-sentinel":')
            with self.subTest(case=case),self.assertRaises(inventory.BaselineInventoryError) as caught:self.observe()
            self.assertEqual(str(caught.exception),'Configured baseline source metadata is unavailable.')
            self.assertEqual(caught.exception.reason,reason)
            self.assertNotIn('sentinel',repr(caught.exception.__dict__))

    def test_unrecognized_private_exception_text_stays_generic(self):
        with patch.object(config,'_configured_providers',side_effect=config.BaselineConfigError('private-sensitive-sentinel')):
            with self.assertRaises(inventory.BaselineInventoryError) as caught:self.observe()
        self.assertEqual(caught.exception.reason,'metadata_unavailable')
        self.assertNotIn('sentinel',str(caught.exception))

    def test_duplicate_keys_and_malformed_sources_refused(self):
        for raw in ('{"schemaVersion":1,"schemaVersion":1,"hosts":{}}',json.dumps({**self.doc,'nativeBaselines':{'schemaVersion':1,'sources':{}}})):
            self.path.write_text(raw);self.path.chmod(0o600)
            with self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_mode_symlink_and_hardlink_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(inventory.BaselineInventoryError):self.observe()
        self.path.chmod(0o600);other=self.root/'copy';self.path.rename(other);self.path.symlink_to(other)
        with self.assertRaises(inventory.BaselineInventoryError):self.observe()
        self.path.unlink();os.link(other,self.path)
        with self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_foreign_ownership_refused_before_provider_read(self):
        original=inventory.os.fstat
        def foreign(fd):
            st=original(fd)
            if (st.st_dev,st.st_ino)==(self.path.stat().st_dev,self.path.stat().st_ino):
                from types import SimpleNamespace
                return SimpleNamespace(**{k:getattr(st,k) for k in dir(st) if k.startswith('st_') and isinstance(getattr(st,k),(int,float))}|{'st_uid':os.getuid()+1})
            return st
        with patch.object(inventory.os,'fstat',side_effect=foreign),patch.object(config,'_configured_providers') as loader:
            with self.assertRaises(inventory.BaselineInventoryError):self.observe()
            loader.assert_not_called()

    def test_actual_inventory_mutation_after_trusted_reader_refused(self):
        original=config._private_json
        def mutate(path):
            value=original(path);self.path.write_text(json.dumps(self.doc)+' ');return value
        with patch.object(config,'_private_json',side_effect=mutate):
            with self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_actual_last_parent_stat_unlink_refuses(self):
        original = os.stat
        changed = []
        def unlink_after_parent_observation(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.root.name and kwargs.get('dir_fd') is not None and not changed:
                self.path.unlink()
                changed.append(True)
            return result
        with patch.object(os, 'stat', side_effect=unlink_after_parent_observation), \
             patch.object(config.subprocess, 'run', side_effect=AssertionError('native subprocess')):
            with self.assertRaises(inventory.BaselineInventoryError):
                self.observe()
        self.assertEqual([True], changed)
        self.assertFalse(self.path.exists())

    def test_actual_named_file_replacement_after_trusted_reader_refused(self):
        original=config._private_json
        def replace(path):
            value=original(path);replacement=self.root/'replacement';replacement.write_bytes(self.path.read_bytes());replacement.chmod(0o600);replacement.replace(self.path);return value
        with patch.object(config,'_private_json',side_effect=replace):
            with self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_actual_parent_replacement_after_trusted_reader_refused(self):
        nested=self.root/'nested';nested.mkdir(mode=0o700);self.path.rename(nested/self.path.name);self.root=nested;self.path=self.root/self.path.name;original=config._configured_providers
        def replace(root):
            value=original(root);old=root.with_name('old');root.rename(old);root.mkdir(mode=0o700);(root/self.path.name).write_bytes((old/self.path.name).read_bytes());(root/self.path.name).chmod(0o600);return value
        with patch.object(config,'_configured_providers',side_effect=replace):
            with self.assertRaises(inventory.BaselineInventoryError):self.observe()

    def test_legacy_unclosed_trusted_loader_causal_acceptance(self):
        original=config._private_json
        def mutate(path):
            value=original(path);self.path.write_text(json.dumps(self.doc)+' ');return value
        with patch.object(config,'_private_json',side_effect=mutate):
            _, providers=config._configured_providers(self.root)
        self.assertEqual(providers['qemu'].sources['source-one'].generation,'generation-one')
        self.assertTrue(self.path.read_text().endswith(' '))

    def test_causal_missing_closing_guard_misses_actual_mutation(self):
        with patch.object(inventory._InventoryHold, 'finish', return_value=None):
            result=unittest.TestResult()
            BaselineInventoryTests('test_actual_inventory_mutation_after_trusted_reader_refused').run(result)
        self.assertEqual(len(result.failures),1)
        self.assertEqual(result.errors,[])
        self.assertIn('BaselineInventoryError not raised',result.failures[0][1])

    def test_script_import_on_synthetic_inventory(self):
        code='import sys,json;sys.path.insert(0,sys.argv[1]);import native_vm_baseline_inventory as m;print(json.dumps(m.configured_source_metadata(sys.argv[2])))'
        r=subprocess.run([sys.executable,'-c',code,str(Path(inventory.__file__).parent),str(self.root)],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr.decode())
        self.assertEqual(json.loads(r.stdout)['sources'][0]['sourceId'],'source-one')
        self.assertNotIn(b'credential-sentinel',r.stdout)


if __name__ == '__main__':unittest.main()
