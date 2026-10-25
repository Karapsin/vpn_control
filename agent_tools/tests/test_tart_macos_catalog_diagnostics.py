"""Protected-source shape diagnosis cannot supply service-purpose authority."""
import json
import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import tart_macos_catalog_diagnostics as diagnostic
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
