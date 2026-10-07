import ast
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import unittest
from unittest import mock
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools import ssh_nested_socket_noninteractive_observation as new
from agent_tools import ssh_nested_socket_route_diagnostic as diagnostic


class NoninteractiveObserverTests(unittest.TestCase):
    def options(self,source):
        function=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='ssh_options')
        namespace={};exec(compile(ast.Module(body=[function],type_ignores=[]),'options','exec'),namespace)
        return namespace['ssh_options']({'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'})

    def test_measured_installed_ssh_warning_repaired_by_exact_t_only_argv(self):
        original=self.options(frozen.remote_source());actual=self.options(new.remote_source())
        self.assertEqual([original[0],'-T',*original[1:]],actual)

    def test_causal_frozen_effective_route_rejects_warning_new_exact_args_pass(self):
        source=new.remote_source();functions=[n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name in ('ssh_options','effective_route')]
        namespace={'subprocess':subprocess,'hashlib':hashlib,'Path':Path,'os':os,'file_pin':mock.Mock(return_value={'generation':[1]*9})}
        exec(compile(ast.Module(body=functions,type_ignores=[]),'effective','exec'),namespace)
        spec={'configFile':'/private/config','controlPath':'/private/r-123456789abcdef/m','remoteHostAlias':'target'}
        def installed(argv,**kwargs):
            return subprocess.CompletedProcess(argv,0,b'identityfile /private/key\n',b'' if '-T' in argv else diagnostic.WARNING)
        with mock.patch.object(subprocess,'run',side_effect=installed),mock.patch.object(os.path,'lexists',return_value=True):
            with self.assertRaisesRegex(ValueError,'effective_route_unknown'):frozen.effective_route(spec)
            result=namespace['effective_route'](spec)
        self.assertEqual({'generation':[1]*9},result['keyMetadata']['/private/key'])
        namespace['file_pin'].assert_called_once_with('/private/key',private=True)

    def test_entire_remote_source_diff_is_exact_one_t_insertion(self):
        source=frozen.remote_source();repaired=new.remote_source()
        old="return ['ssh','-F',spec['configFile']";replacement="return ['ssh','-T','-F',spec['configFile']"
        self.assertEqual(1,repaired.count(replacement));self.assertEqual(source,repaired.replace(replacement,old,1))
        self.assertIn('def parent_guard',repaired);self.assertIn('kernel_endpoint_present',repaired)
        self.assertIn('orphan_admission_changed',repaired)
        for forbidden in ('os.unlink','os.rename','os.kill','passphrase'):self.assertNotIn(forbidden,repaired)
        with self.assertRaisesRegex(ValueError,'separate_archive_proof_review_required'):new.retire(None)

    def fixture(self):
        intent={'correlationId':new.MEASURED,'failedCorrelationId':diagnostic.FAILED,'remoteSourceSha256':new.DIAGNOSTIC_REMOTE_SHA,'host':'nested','observerRetried':False,'mutationPerformed':False}
        captures={'stdout':diagnostic.captured(b'mock effective options'),'stderr':diagnostic.captured(diagnostic.WARNING)}
        result={'correlationId':new.MEASURED,'remoteSourceSha256':new.DIAGNOSTIC_REMOTE_SHA,'host':'nested','intent':copy.deepcopy(new.MEASURED_PINS['intent.json']),
                'result':{'state':'fixed-route-diagnostic','returnCode':0,'category':'exact-nonterminal-warning','fixedArgsWithoutTTYOverride':True,'observerRetried':False,'mutationPerformed':False,**captures}}
        return intent,result,{name:{k:cap[k] for k in ('bytes','sha256')} for name,cap in captures.items()}

    def test_exact_positive_measured_warning_and_bindings_required(self):
        intent,result,pins=self.fixture()
        with mock.patch.dict(new.OUTPUT_PINS,pins):self.assertEqual(result['result'],new.measured_value(intent,result))
        for attack in ('bool-exit','exit','category','warning','capture','intent','source','correlation','mutation','host'):
            with self.subTest(attack=attack):
                intent,result,pins=self.fixture();value=result['result']
                if attack=='bool-exit':value['returnCode']=False
                elif attack=='exit':value['returnCode']=255
                elif attack=='category':value['category']='stderr-present'
                elif attack=='warning':value['stderr']=diagnostic.captured(b'other warning')
                elif attack=='capture':value['stdout']['sha256']='0'*64
                elif attack=='intent':result['intent']['generation'][1]+=1
                elif attack=='source':result['remoteSourceSha256']='0'*64
                elif attack=='correlation':result['correlationId']=diagnostic.FAILED
                elif attack=='mutation':value['mutationPerformed']=True
                else:result['host']='foreign'
                with mock.patch.dict(new.OUTPUT_PINS,pins),self.assertRaises(ValueError):new.measured_value(intent,result)

    def test_consumed_sources_unchanged_and_rewrite_dependency_drift_blocks(self):
        for module,expected in ((frozen,new.FROZEN_SHA),(diagnostic,new.DIAGNOSTIC_SHA)):
            self.assertEqual(expected,hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest())
        with mock.patch.object(frozen,'remote_source',return_value=frozen.remote_source()+'\n'),self.assertRaisesRegex(ValueError,'consumed_remote_changed'):new.remote_source()
