"""Actual codec method; stop emitted code before SOURCE exec or native custody."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import types
import unittest
import zlib

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).resolve().parent/'fixtures/linux_gui_source_custody'
BEFORE=(FIXTURE/'codec-driver.before.source').read_bytes()
CURRENT=(ROOT/'scripts/integration/linux_owner_lifecycle_scenario.py').read_bytes()
ORIGINAL=(FIXTURE/'normal-capsule.source').read_bytes()
assert hashlib.sha256(BEFORE).hexdigest()=='c094d68cf9a9dc871ced17183d66571e6a2de279b2759abe43a80a4be816ecc8'
assert hashlib.sha256(ORIGINAL).hexdigest()=='5f8d4cffb0c69439b703e13729c0ea5aa687c1a5d37e0386ddaf50065beefe0c'

def method(source):
    tree=ast.parse(source)
    owner=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='FixedGuiSourceCustody')
    actual=next(n for n in owner.body if isinstance(n,ast.FunctionDef)and n.name=='python_command')
    required=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='ScenarioError' or isinstance(n,ast.FunctionDef)and n.name=='require']
    ns={'json':json,'sys':sys}
    exec(compile(ast.Module(body=required+[actual],type_ignores=[]),'actual_selected_codec_method','exec'),ns)
    paths={}
    for n in owner.body:
        if isinstance(n,ast.Assign):
            for target in n.targets:
                if isinstance(target,ast.Name)and target.id in ['DRIVER','SOCKS']:
                    paths[target.id]=ast.literal_eval(n.value)
    return ns['python_command'],ns['ScenarioError'],paths

def model(raw,paths):
    return types.SimpleNamespace(_serialized=raw,_seal=hashlib.sha256(raw).hexdigest(),**paths)

def prefix(command):
    tree=ast.parse(command)
    boundary=next(i for i,n in enumerate(tree.body)if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='exec')
    # No compile/exec of captured SOURCE, constructor, filesystem or main allowed.
    ns={}
    exec(compile(ast.Module(body=tree.body[:boundary],type_ignores=[]),'actual_emitted_pre_exec_codec','exec'),ns)
    return ns

class LinuxGuiCapsuleCodecTests(unittest.TestCase):
    def test_full_actual_six_role_capsule_fits_original_command_bound(self):
        fn,error,paths=method(BEFORE if __import__('os').environ.get('CAPSULE_CODEC_PHASE')=='before' else CURRENT)
        argv=fn(model(ORIGINAL,paths),['--input','inert-spec','--admissions','inert-admissions','--receipt','inert-receipt'])
        self.assertLess(len(argv[4].encode()),65536)
        self.assertEqual(['--input','inert-spec','--admissions','inert-admissions','--receipt','inert-receipt'],argv[5:])
        self.assertEqual(ORIGINAL,prefix(argv[4])['raw'])

    def test_original_seal_and_every_source_body_are_byte_identical(self):
        fn,error,paths=method(CURRENT);argv=fn(model(ORIGINAL,paths),['--fixture-worker','inert'])
        decoded=prefix(argv[4]);self.assertEqual(ORIGINAL,decoded['raw']);self.assertEqual(hashlib.sha256(ORIGINAL).hexdigest(),hashlib.sha256(decoded['raw']).hexdigest())
        original=json.loads(ORIGINAL);self.assertEqual(6,len(original['inputs']))
        for a,b in zip(original['inputs'],decoded['capsule']['inputs']):
            self.assertEqual(a,b);self.assertEqual(base64.b64decode(a['body'],validate=True),base64.b64decode(b['body'],validate=True))

    def test_new_driver_capsule_child_method_inherits_same_fix(self):
        fn,error,paths=method(CURRENT);capsule=json.loads(ORIGINAL)
        row=next(x for x in capsule['inputs']if x['path']==paths['DRIVER'])
        row['body']=base64.b64encode(CURRENT).decode();row['sha256']=hashlib.sha256(CURRENT).hexdigest();row['generation'][6]=len(CURRENT)
        raw=(json.dumps(capsule,sort_keys=True,separators=(',',':'))+'\n').encode()
        decoded=prefix(fn(model(raw,paths),['--fixture-worker','inert'])[4])
        self.assertEqual(CURRENT,decoded['source']);self.assertEqual(raw,decoded['raw'])
        child_fn,_,child_paths=method(decoded['source'])
        child=child_fn(model(raw,child_paths),['--wm-close-helper','inert'])
        self.assertLess(len(child[4].encode()),65536);self.assertEqual(raw,prefix(child[4])['raw'])

    def test_tampered_wire_refused_before_captured_source_execution(self):
        fn,error,paths=method(CURRENT);command=fn(model(ORIGINAL,paths),[])[4];tree=ast.parse(command)
        encoded_call=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and n.func.attr=='b64decode'and n.args and isinstance(n.args[0],ast.Constant))
        wire=json.loads(zlib.decompress(base64.b64decode(encoded_call.args[0].value)));wire['inputs'][0]['body']+='\n# inert tamper\n'
        encoded_call.args[0].value=base64.b64encode(zlib.compress(json.dumps(wire,sort_keys=True,separators=(',',':')).encode())).decode()
        with self.assertRaises(AssertionError):prefix(ast.unparse(tree))

    def test_invalid_arguments_and_non_utf8_fixed_source_refuse(self):
        fn,error,paths=method(CURRENT)
        for args in [True,('x',),[1]]:
            with self.subTest(args=args),self.assertRaises(error):fn(model(ORIGINAL,paths),args)
        capsule=json.loads(ORIGINAL);capsule['inputs'][0]['body']=base64.b64encode(b'\xff').decode();raw=(json.dumps(capsule,sort_keys=True,separators=(',',':'))+'\n').encode()
        with self.assertRaises(UnicodeDecodeError):fn(model(raw,paths),[])

if __name__=='__main__':unittest.main(verbosity=2)
