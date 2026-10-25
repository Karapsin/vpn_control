"""Portable actual-file causal controls; no network/controller/private histories."""
from pathlib import Path
from types import SimpleNamespace
from contextlib import contextmanager
import ast,hashlib,json,os,stat,tempfile,unittest
HERE=Path(__file__).resolve().parent;F=HERE/'fixtures'/'ssh_acceptance_package_closure'
PINS={'boundary.source':'5d6302ff641514e68b07da39a2c7abd5a7dbe7abd2a0ffd64aedf393dd833488','controller.before.source':'1528b117c2dc742c8a89585ad16331a503e44b44d44bc45d9f7af98cc83fd860','package_preflight.source':'e7e8a75c7e4d526d39fe3bcbc2062ce1ca98ec8f6ccb6a8b14f71a76d13d6b61','retention.source':'2c5f60321c667a9db4ae27f04103609318fbaff26c47fc140ea986c2fa9a426f','stage.before.source':'977848b6b776e53a46435d2ef63e8aa91cd6423e6779274a1b152b34680f020f','stage.fixed.source':'926d8562a6bbd4282effb5c1ffa796d453aac7143ab99417ac4fba58d003f695'}
def raw(name):
 value=(F/name).read_bytes();assert hashlib.sha256(value).hexdigest()==PINS[name];return value

def save(path,body):
 path.parent.mkdir(parents=True,mode=0o700,exist_ok=True);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(body)

def project_setup(here,fixed):
 tree=ast.parse(raw('stage.fixed.source'if fixed else'stage.before.source'));nodes=[]
 targets={"HERE / 'ordinary_retention.py'","HERE / 'bin/ssh'"}
 for n in ast.walk(tree):
  if isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and isinstance(n.value.func,ast.Name)and n.value.func.id=='save'and ast.unparse(n.value.args[0])in targets:nodes.append(n)
  elif isinstance(n,ast.Expr)and isinstance(n.value,ast.Call)and ast.unparse(n.value.func)=='os.chmod'and ast.unparse(n.value.args[0])=="HERE / 'bin/ssh'":nodes.append(n)
 nodes.sort(key=lambda n:(n.lineno,n.col_offset));assert len(nodes)==(3 if fixed else 1)
 ns={'HERE':here,'save':save,'hp':SimpleNamespace(raw=raw('retention.source')),'ssh_boundary':SimpleNamespace(raw=raw('boundary.source')),'os':os}
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'authenticated-stage-dependency-projection','exec'),ns)

def authentic_preflight(here):
 tree=ast.parse(raw('controller.before.source'));selected=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name in('fingerprint','SourceHold')]
 ns={'Path':Path,'os':os,'stat':stat};exec(compile(ast.Module(body=selected,type_ignores=[]),'authenticated-controller-sourcehold','exec'),ns)
 main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');loop=next(n for n in ast.walk(main)if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id=='p'and isinstance(n.iter,ast.Tuple))
 ns.update({'HERE':here,'root':here/'direct','__file__':str(here/'controller.py'),'holders':[]})
 try:exec(compile(ast.Module(body=[loop],type_ignores=[]),'authentic-controller-required-input-loop','exec'),ns)
 finally:
  for held in ns['holders']:held.close()
 return ns['SourceHold']

@contextmanager
def packaged(fixed=True):
 with tempfile.TemporaryDirectory(prefix='counter-package-closure-')as td:
  here=Path(td);save(here/'controller.py',raw('controller.before.source'))
  files={'agent_tools/public.py':b'PUBLIC = 1\n','scripts/public.sh':b'#!/bin/sh\nexit 0\n'}
  for rel,body in files.items():save(here/'direct'/rel,body)
  save(here/'public-source-manifest.json',json.dumps({'sources':{rel:hashlib.sha256(body).hexdigest()for rel,body in files.items()}}).encode())
  save(here/'direct/route-template.private.json',b'{"schemaVersion":1,"hosts":{}}')
  save(here/'direct/planned-operation.json',b'{"mode":"direct"}')
  project_setup(here,fixed);yield here

@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW')and hasattr(os,'getuid'),'requires owned POSIX filesystem/socket custody')
class PackageClosureTests(unittest.TestCase):
 def check(self,here):
  sourcehold=authentic_preflight(here);held=[]
  def hold(path):
   item=sourcehold(path);held.append(item);return item
  ns={};exec(compile(raw('package_preflight.source'),'held-package-preflight','exec'),ns)
  try:return ns['check'](here,'direct',hold,PINS['controller.before.source'],PINS['boundary.source'],PINS['retention.source'])
  finally:
   for item in held:item.close()
 def test_actual_original_missing_boundary_red_fixed_green(self):
  with packaged(False)as here:
   self.assertFalse((here/'bin/ssh').exists())
   with self.assertRaises(FileNotFoundError)as caught:authentic_preflight(here)
   self.assertEqual(Path(caught.exception.filename),here/'bin/ssh')
  with packaged()as here:
   result=self.check(here);self.assertEqual(result['requiredControllerInputs'],6);self.assertEqual(result['manifestedSourceCopies'],2)
 def test_every_required_real_file_and_manifest_source_missing_blocks(self):
  for rel in('controller.py','ordinary_retention.py','bin/ssh','public-source-manifest.json','direct/route-template.private.json','direct/planned-operation.json','direct/agent_tools/public.py','direct/scripts/public.sh'):
   with self.subTest(rel=rel),packaged()as here:
    (here/rel).unlink()
    with self.assertRaises(FileNotFoundError):self.check(here)
 def test_changed_fixed_inputs_and_source_blocks(self):
  for rel in('controller.py','ordinary_retention.py','bin/ssh','direct/agent_tools/public.py','direct/scripts/public.sh'):
   with self.subTest(rel=rel),packaged()as here:
    with(here/rel).open('ab')as f:f.write(b'\n')
    with self.assertRaises(ValueError):self.check(here)
 def test_boundary_requires_executable_mode_and_regular_nofollow(self):
  with packaged()as here:
   os.chmod(here/'bin/ssh',0o600)
   with self.assertRaisesRegex(ValueError,'package_executable_custody'):self.check(here)
  with packaged()as here:
   (here/'bin/ssh').rename(here/'boundary');(here/'bin/ssh').symlink_to(here/'boundary')
   with self.assertRaises(OSError):self.check(here)
 def test_duplicate_or_escape_manifest_blocks(self):
  for body in(b'{"sources":{"a":"'+b'0'*64+b'","a":"'+b'0'*64+b'"}}',json.dumps({'sources':{'../escape':'0'*64}}).encode()):
   with self.subTest(body=body),packaged()as here:
    (here/'public-source-manifest.json').write_bytes(body)
    with self.assertRaises(ValueError):self.check(here)
 def test_fixture_provenance_exact(self):
  provenance=json.loads((F/'provenance.json').read_bytes());self.assertEqual(provenance['pins'],PINS)
  for name in PINS:raw(name)
if __name__=='__main__':unittest.main()
