"""Actual diagnostic classifiers over finite memory replies; no guest actions."""
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

from agent_tools import windows_msi_base_prepare as base


FIXTURE=Path(__file__).parent/'fixtures/msi_base_diagnostic_output'


def preserved_source():
    raw=(FIXTURE/'before.source').read_bytes()
    provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
    if len(raw)!=provenance['sourceBytes']or hashlib.sha256(raw).hexdigest()!=provenance['sourceSha256']:
        raise ValueError('diagnostic_before_source_changed')
    return raw.decode()


def current_source():
    tree=ast.parse(base._DIAGNOSTIC)
    names=('unknown_proof','dispatch_absent_proof')
    nodes={node.name:node for node in tree.body if isinstance(node,ast.FunctionDef)and node.name in names}
    if set(nodes)!=set(names):raise ValueError('diagnostic_function_source_changed')
    return '\n\n'.join(ast.get_source_segment(base._DIAGNOSTIC,nodes[name])for name in names)+'\n'


def classify(source,raw):
    calls=[]
    def call(sock,command,args):
        calls.append((sock,command,args))
        if command=='guest-exec':return {'pid':7}
        if command=='guest-exec-status':
            return {'exited':True,'exitcode':0,'out-truncated':False,'err-truncated':False,
                    'out-data':base64.b64encode(raw).decode()}
        raise AssertionError('unexpected diagnostic operation')
    namespace={'json':json,'base64':base64,'re':re,'corr':'05fd80ad-b93f-4450-a3e5-a67d14f24478',
               'sid':'S-1-5-21-1-2-3-1002','sock':'inert-memory-qga','decode':lambda value:value.decode(),'call':call}
    exec(compile(source,'<actual-diagnostic-functions>','exec'),namespace)
    result=namespace['dispatch_absent_proof']()
    return result,calls


def assert_malformed(case,source):
    for raw in (b'not-json',b'noise\n',b'{}\n{}\n',b'{bad}\n',b'',b'x'*2049):
        result,calls=classify(source,raw)
        case.assertEqual('powershell-empty-or-malformed-output',result[1])
        case.assertEqual('unavailable',result[2])
        case.assertEqual(['guest-exec','guest-exec-status'],[row[1]for row in calls])


class DiagnosticOutputTests(unittest.TestCase):
    def test_malformed_output_is_classified_before_schema_projection(self):
        assert_malformed(self,current_source())

    def test_preserved_actual_classifier_has_same_assertion_red(self):
        result=unittest.TestResult()
        unittest.FunctionTestCase(lambda:assert_malformed(self,preserved_source())).run(result)
        self.assertEqual(1,len(result.failures));self.assertEqual([],result.errors)
        self.assertIn('powershell-empty-or-malformed-output',result.failures[0][1])
        self.assertIn('projection',result.failures[0][1])

    def test_valid_object_with_missing_fields_retains_schema_projection(self):
        for source in (preserved_source(),current_source()):
            result,calls=classify(source,b'{"version":1}')
            self.assertEqual(('projection','unavailable','missing-or-extra-fields'),result[1:4])
            self.assertEqual({'presenceMask':'100000000','extraFieldCount':0},result[4])
            self.assertEqual(['guest-exec','guest-exec-status'],[row[1]for row in calls])


if __name__=='__main__':
    if '--legacy-red'in sys.argv:
        result=unittest.TextTestRunner(verbosity=2).run(unittest.FunctionTestCase(
            lambda:assert_malformed(unittest.TestCase(),preserved_source())))
        raise SystemExit(not result.wasSuccessful())
    unittest.main()
