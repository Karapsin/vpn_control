"""Protected-source shape diagnosis cannot supply service-purpose authority."""
import json
import errno
import os
import stat
import types
import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_catalog_read_diagnostics as diagnostic
from agent_tools import tart_macos_service_census as service


class CatalogDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.volume=service.Volume((1,2),True,True,1,True)
        self.native=SimpleNamespace(volume=lambda:self.volume)
    def test_catalog_failure_keeps_independent_real_volume_fact_and_finite_tag(self):
        with patch.object(service,'Catalog',side_effect=service.ServiceUnavailable('macos_service_source_invalid')),\
                patch.object(diagnostic,'scan',return_value={'state':'observed'}):
            result=diagnostic.inspect(self.native,service,502)
        self.assertEqual('observed',result['volume']['state'])
        self.assertEqual('readonly_apfs_snapshot',result['volume']['rootMount'])
        self.assertEqual({'state':'unavailable','reason':'macos_service_source_invalid'},result['catalog'])
    def test_authentic_original_combined_try_erased_positive_volume_red_independent_stage_green(self):
        fixture=Path(__file__).parent/'fixtures/macos_catalog_volume_before.source';raw=fixture.read_bytes()
        self.assertEqual('07c9cd91e9b1f2b7c619c79c9b1d962f7b4482749804c39b68c1e8bde7373ca1',hashlib.sha256(raw).hexdigest())
        collect=next(row for row in ast.parse(raw).body if isinstance(row,ast.FunctionDef)and row.name=='collect')
        blocks=[row for row in collect.body if isinstance(row,ast.Try)
                and 'catalog = service.Catalog' in ast.unparse(row)]
        self.assertEqual(1,len(blocks))
        namespace={'native':self.native,'service':service,'uid':502,'missing':set()}
        with patch.object(service,'Catalog',side_effect=service.ServiceUnavailable('macos_service_source_invalid')),\
                patch.object(diagnostic,'scan',return_value={'state':'observed'}):
            exec(compile(ast.fix_missing_locations(ast.Module(body=blocks,type_ignores=[])),str(fixture),'exec'),namespace)
            current=diagnostic.inspect(self.native,service,502)
        def require_volume(value):self.assertEqual('readonly_apfs_snapshot',value['rootMount'])
        with self.assertRaises((KeyError,AssertionError)):require_volume(namespace['public_volume'])
        require_volume(current['volume'])
        self.assertEqual('macos_service_source_invalid',current['catalog']['reason'])
    def test_native_or_unknown_error_never_echoes_path_argv_environment_or_hash(self):
        self.native.volume=lambda:(_ for _ in ()).throw(OSError('PRIVATE-PATH-ARGV-HASH'))
        result=diagnostic.inspect(self.native,service,502)
        self.assertEqual({'state':'unavailable','reason':'native_or_source_unavailable'},result['volume'])
        self.assertEqual('not_attempted',result['catalog']['state'])
        self.assertNotIn('PRIVATE',str(result))
        result=diagnostic._reason(service.ServiceUnavailable('PRIVATE'),service)
        self.assertEqual('native_or_source_unavailable',result)
    def test_shape_counts_retain_no_unexpected_labels_paths_or_arguments(self):
        counts={key:0 for key in diagnostic._SHAPES};labels=set()
        rows=[{'Label':'PRIVATE','BundleProgram':'PRIVATE-PATH'},
              {'Label':'PRIVATE','ProgramArguments':[]},
              {'Label':'PRIVATE','ProgramArguments':['relative-PRIVATE']},
              {'Label':'OTHER-PRIVATE','ProgramArguments':['/PRIVATE','PRIVATE-ARG'],'EnvironmentVariables':{'PRIVATE':'PRIVATE-ENV'}},
              {'Label':'BAD-PRIVATE','ProgramArguments':[123]},[]]
        for row in rows:diagnostic.shape(row,'system_daemon',labels,counts)
        diagnostic.shape({'Label':'PRIVATE','Program':'/PRIVATE'},'system_agent',labels,counts)
        self.assertEqual(1,counts['bundle_program_present'])
        self.assertEqual(2,counts['duplicate_label_same_domain'])
        self.assertEqual(1,counts['duplicate_label_cross_domain'])
        self.assertEqual(1,counts['arguments_empty']);self.assertEqual(1,counts['arguments_invalid'])
        self.assertEqual(1,counts['program_invalid']);self.assertEqual(1,counts['dictionary_invalid'])
        self.assertNotIn('PRIVATE',json.dumps(counts))
    def test_unqualified_volume_cannot_open_source_tree_for_shape_scan(self):
        self.native.volume=lambda:service.Volume((1,2),False,True,1,True)
        with patch.object(diagnostic,'scan',side_effect=AssertionError('must not read unqualified tree')):
            result=diagnostic.inspect(self.native,service,502)
        self.assertEqual('not_attempted',result['sourceShapes']['state'])
        self.assertEqual('macos_system_source_volume_unqualified',result['catalog']['reason'])
    @staticmethod
    def _metadata(info,**changes):
        fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
        return SimpleNamespace(**({**{key:getattr(info,key)for key in fields},**changes}))
    def test_actual_hardlink_whole_before_generic_red_finite_subtype_green(self):
        fixture=Path(__file__).parent/'fixtures/macos_catalog_read_diagnostic_before.source';raw=fixture.read_bytes()
        self.assertEqual('dd708693b59b970fa386c8bee64a942ff28a161f8bef406557c90e130c780f37',hashlib.sha256(raw).hexdigest())
        old=types.ModuleType('_catalog_read_before');sys.modules[old.__name__]=old
        try:exec(compile(raw,str(fixture),'exec'),old.__dict__)
        finally:sys.modules.pop(old.__name__,None)
        real_lstat=Path.lstat;real_fstat=os.fstat
        # Real files/descriptors; only root-owner metadata is a controlled seam.
        # This does not qualify the coordinator's files as guest SSV sources.
        def root_lstat(path):return self._metadata(real_lstat(path),st_uid=0)
        def root_fstat(fd):return self._metadata(real_fstat(fd),st_uid=0)
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);path=root/'private.plist';path.write_bytes(b'PRIVATE-ARGV')
            os.link(path,root/'retained')
            volume=service.Volume((1,2),True,True,root.stat().st_dev,True)
            with patch.object(service.Catalog,'_DIRECTORIES',((directory,'system_daemon'),)),\
                    patch.object(Path,'lstat',root_lstat),patch.object(os,'fstat',root_fstat),\
                    patch.object(os,'read',side_effect=AssertionError('bad metadata must not read content')):
                before=old.scan(volume,service);after=diagnostic.scan(volume,service)
            def require_subtype(value):self.assertEqual(1,value['protectedReadFailures']['link_count'])
            with self.assertRaises(KeyError):require_subtype(before)
            require_subtype(after)
            self.assertEqual(1,after['shapeCounts']['protected_read_unavailable'])
            self.assertNotIn('PRIVATE',json.dumps(after));self.assertNotIn(directory,json.dumps(after))
    def test_real_fifo_whole_before_blocks_red_current_refuses_before_open_green(self):
        if not hasattr(os,'mkfifo'):self.skipTest('requires real POSIX FIFO')
        fixture=Path(__file__).parent/'fixtures/macos_catalog_fifo_before.source';raw=fixture.read_bytes()
        self.assertEqual('77f87bb91eda373f40bb29d159ac5ffdc9701e6f9efc972a48661759975941c9',hashlib.sha256(raw).hexdigest())
        import signal
        with tempfile.TemporaryDirectory()as directory:
            fifo=Path(directory)/'private.plist';os.mkfifo(fifo,0o600)
            # Each source runs in its own original child, with a kernel timer;
            # the unfixed blocking open cannot signal any unrelated actor.
            prefix='import signal,json,types\nfrom pathlib import Path\nfrom agent_tools import tart_macos_service_census as service\n'
            suffix=("\nsignal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(1)\n"
                +"value=module.protected_read(Path("+repr(str(fifo))+"),service.Volume((1,2),True,True,0,True),service)\n"
                +"print(json.dumps(value))\n")
            outputs=[]
            for producer in (raw,Path(diagnostic.__file__).read_bytes()):
                program=prefix+"module=types.ModuleType('_fifo_test');exec(compile("+repr(producer)+",'<fixed-fifo>','exec'),module.__dict__)"+suffix
                outputs.append(subprocess.run([sys.executable,'-c',program],capture_output=True,timeout=5))
            self.assertEqual(-signal.SIGALRM,outputs[0].returncode)
            self.assertEqual(b'',outputs[0].stdout);self.assertEqual(b'',outputs[0].stderr)
            self.assertEqual(0,outputs[1].returncode);self.assertEqual([None,['file_type']],json.loads(outputs[1].stdout))
            self.assertEqual(b'',outputs[1].stderr)
            with patch.object(os,'open',side_effect=AssertionError('nonregular must not open')):
                self.assertEqual((None,('file_type',)),diagnostic.protected_read(fifo,self.volume,service))
    def test_read_metadata_reasons_are_finite_and_precede_content_read(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'private.plist';path.write_bytes(b'PRIVATE-ARGV')
            actual=path.lstat();volume=service.Volume((1,2),True,True,actual.st_dev,True)
            for changes,reason in (({'st_uid':123},'owner'),({'st_mode':stat.S_IFREG|0o666},'writable_mode'),
                    ({'st_nlink':2},'link_count'),({'st_dev':actual.st_dev+1},'device'),
                    ({'st_size':0},'size'),({'st_mode':stat.S_IFDIR|0o700},'file_type')):
                value=self._metadata(actual,st_uid=0,**changes)if 'st_uid'not in changes else self._metadata(actual,**changes)
                with self.subTest(reason=reason),patch.object(Path,'lstat',return_value=value),\
                        patch.object(os,'fstat',return_value=value),\
                        patch.object(os,'read',side_effect=AssertionError('must not read')):
                    self.assertEqual((None,(reason,)),diagnostic.protected_read(path,volume,service))
    def test_real_symlink_permission_and_named_fd_changes_do_not_disclose_input(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'private.plist';path.write_bytes(b'PRIVATE-ARGV')
            link=Path(directory)/'link.plist';link.symlink_to(path)
            volume=service.Volume((1,2),True,True,path.stat().st_dev,True)
            with patch.object(os,'open',side_effect=AssertionError('must not follow')):
                self.assertEqual((None,('symlink',)),diagnostic.protected_read(link,volume,service))
            for code,reason in ((errno.EACCES,'read_permission'),(errno.EPERM,'read_permission'),
                    (errno.ELOOP,'symlink'),(errno.ENOENT,'missing'),(errno.EIO,'read_unavailable')):
                with patch.object(os,'open',side_effect=OSError(code,'PRIVATE-PATH')):
                    self.assertEqual((None,(reason,)),diagnostic.protected_read(path,volume,service))
            value=self._metadata(path.lstat(),st_uid=0)
            for key in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'):
                changed=self._metadata(value,**{key:getattr(value,key)+1})
                with self.subTest(field=key),patch.object(Path,'lstat',return_value=value),\
                        patch.object(os,'fstat',return_value=changed),\
                        patch.object(os,'read',side_effect=AssertionError('changed fd must not read')):
                    self.assertEqual((None,('changed',)),diagnostic.protected_read(path,volume,service))
    def test_successful_read_revalidates_named_file_and_fd_after_actual_content_read(self):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'private.plist';path.write_bytes(b'PUBLIC')
            value=self._metadata(path.lstat(),st_uid=0);volume=service.Volume((1,2),True,True,value.st_dev,True)
            with patch.object(Path,'lstat',return_value=value),patch.object(os,'fstat',return_value=value):
                self.assertEqual((b'PUBLIC',()),diagnostic.protected_read(path,volume,service))
            changed=self._metadata(value,st_ino=value.st_ino+1)
            with patch.object(Path,'lstat',side_effect=[value,changed]),patch.object(os,'fstat',return_value=value):
                self.assertEqual((None,('changed',)),diagnostic.protected_read(path,volume,service))
            with patch.object(Path,'lstat',return_value=value),patch.object(os,'fstat',side_effect=[value,changed]):
                self.assertEqual((None,('changed',)),diagnostic.protected_read(path,volume,service))
    def test_complete_generated_wrong_argument_refuses_before_frameworks_or_source_reads(self):
        if diagnostic.os.name!='posix':self.skipTest('Mac source renderer requires POSIX nofollow')
        inputs=dict(machine='11111111-1111-4111-8111-111111111111',boot='22222222-2222-4222-8222-222222222222',
            uid=502,principal='toolrecovery',agent=(5,502,1,1000,1))
        raw=diagnostic.source(**inputs)
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'diagnostic.py';path.write_bytes(raw)
            result=subprocess.run([sys.executable,str(path),'forbidden'],capture_output=True,timeout=10)
        self.assertEqual(3,result.returncode);self.assertEqual(b'',result.stderr)
        self.assertEqual({'state':'blocked','reason':'macos_catalog_diagnostic_unavailable'},json.loads(result.stdout))
        with patch.object(diagnostic,'_EXECUTING_CODE',None):
            with self.assertRaises(diagnostic.CatalogDiagnosticUnavailable):diagnostic.source(**inputs)


if __name__=='__main__':unittest.main()
