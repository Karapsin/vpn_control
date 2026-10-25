"""Real private filesystem/low-FD controls; no payload, namespace, SSH or network."""
from pathlib import Path
import ast,copy,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
HERE=Path(__file__).resolve().parent

def load(name,path):
 raw=path.read_bytes();value=type(sys)(name);value.__file__=str(path);value.__package__=None;sys.modules[name]=value;exec(compile(raw,str(path),'exec'),value.__dict__);return value
builder=load('_actual_fixed_controller_builder',HERE/'build_controller_program_v2.py')
local=load('_actual_fixed_local_wrapper',HERE/'local-owner-source/local_owner_v2.py')
class SourceBuilderTests(unittest.TestCase):
 def test_real_low_fd_complete_held_source_loop_before_emfile_red_shared_ancestor_scope_green(self):
  # Same original Held implementation and source list, isolated fixed child so
  # lowering its FD limit cannot affect the coordinator or unrelated workers.
  code='''from pathlib import Path
from contextlib import ExitStack
import importlib.util,json,os,resource,sys,tempfile

def load(name,path):
 raw=path.read_bytes();m=type(sys)(name);m.__file__=str(path);m.__package__=None;sys.modules[name]=m;exec(compile(raw,str(path),'exec'),m.__dict__);return m
root=Path(sys.argv[1]);local=load('_low_fd_local',root/'local-owner-source/local_owner_v2.py');builder=load('_low_fd_builder',root/'build_controller_program_v2.py')
with tempfile.TemporaryDirectory()as temporary:
 directory=Path(temporary).resolve();paths=[]
 for n in range(40):
  p=directory/('public-'+str(n)+'.py');p.write_bytes(b'# fixed harmless public fixture\\n');p.chmod(0o600);paths.append(p)
 current=resource.getrlimit(resource.RLIMIT_NOFILE);resource.setrlimit(resource.RLIMIT_NOFILE,(96,current[1]))
 red=False
 try:
  with ExitStack()as stack:
   for p in paths:stack.enter_context(local.Held(p))
 except OSError as error:
  if error.errno!=24:raise
  red=True
 with builder.SharedSourceScope(local.Held)as shared:
  all_sources=[shared.hold(p)for p in paths]
  for s in all_sources:s.guard()
  held_dirs=len(shared.directories)
 print(json.dumps({'actualEmfileBefore':red,'completeFilesAfter':len(all_sources),'sharedAncestorCount':held_dirs,'limit':96,'payloads':0}))
'''
  result=subprocess.run([sys.executable,'-I','-B','-c',code,str(HERE)],stdin=subprocess.DEVNULL,capture_output=True,timeout=8)
  self.assertEqual((0,b''),(result.returncode,result.stderr));value=json.loads(result.stdout)
  self.assertTrue(value['actualEmfileBefore']);self.assertEqual(40,value['completeFilesAfter']);self.assertLess(value['sharedAncestorCount'],20)
 def test_shared_full_generation_guard_same_bytes_replacement_still_blocks(self):
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();path=root/'public.py';path.write_bytes(b'# fixed public source\n');path.chmod(0o600)
   scope=builder.SharedSourceScope(local.Held);value=scope.hold(path)
   replacement=root/'replacement.py';replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);os.replace(replacement,path)
   with self.assertRaisesRegex(local.LocalOwnerBlocked,'local_source_changed'):value.guard()
   with self.assertRaisesRegex(local.LocalOwnerBlocked,'local_source_changed'):scope.__exit__(None,None,None)
 def test_actual_before_chained_inequality_red_current_full_equal_generation_green(self):
  with tempfile.TemporaryDirectory()as temporary:
   path=Path(temporary).resolve()/'public.py';path.write_bytes(b'# fixed source\n');path.chmod(0o600);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
   try:
    original=os.fstat(fd);path.write_bytes(b'# changed public source\n')
    before=ast.parse((HERE/'build_controller_program.generation-before.source').read_bytes());current=ast.parse((HERE/'build_controller_program_v2.py').read_bytes())
    for tree,old in((before,True),(current,False)):
     fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='build')
     node=next(n for n in ast.walk(fn)if isinstance(n,ast.If)and any(isinstance(v,ast.Constant)and v.value=='fixed_wrapper_generation_changed'for v in ast.walk(n)))
     scope={'module':local,'module_generation':local.generation,'os':os,'fd':fd,'path':path,'i':original}
     if old:exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)],type_ignores=[])),'<authentic-before-predicate>','exec'),scope)
     else:
      with self.assertRaisesRegex(ValueError,'fixed_wrapper_generation_changed'):exec(compile(ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)],type_ignores=[])),'<current-predicate>','exec'),scope)
   finally:os.close(fd)
 def test_mode_rejected_before_any_program_builder_artifact_access(self):
  for mode in('',None,False,'other'):
   with self.assertRaisesRegex(ValueError,'fixed_controller_mode'):builder.build(mode)
if __name__=='__main__':unittest.main()
