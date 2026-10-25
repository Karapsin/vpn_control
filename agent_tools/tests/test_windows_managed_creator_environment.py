"""Actual POSIX subprocess environment from complete selected tool-run caller.
Before fixture is SHA-authenticated whole producer data. Only the exact nested
_creator_main.run FunctionDef executes; outer imports/main/VM/media code do not.
Current producer is the explicit imported module, never an ignored-runtime path.
Linux fd executable dispatch maps at an asserted boundary to the same owned
Python source, retaining real subprocess/env/pass_fds/stdin behavior. No fake
CompletedProcess, native installer, framework, libvirt, secret, or VM is used.
"""
import ast,hashlib,json,os,subprocess,sys,tempfile,types,unittest
from agent_tools import readiness_windows_managed_create as creator
from pathlib import Path
HERE=Path(__file__).resolve().parent/'fixtures/windows_managed_creator_environment'
BEFORE_SHA='711318c27f3a4a59615c338eb2d82abc00df0c7bcda4ddfc8555fa9041b6bd44'
def raw(name):
 if name=='managed_create.current.source':return Path(creator.__file__).read_bytes()
 if name!='managed_create.before.source':raise ValueError('finite_creator_environment_input')
 b=(HERE/'before.source').read_bytes()
 if hashlib.sha256(b).hexdigest()!=BEFORE_SHA:raise ValueError('creator_before_source_changed')
 provenance=json.loads((HERE/'provenance.json').read_text())
 if provenance['sourceSha256']!={'before.source':BEFORE_SHA}:raise ValueError('creator_before_manifest_changed')
 return b
class ManagedCreatorEnvironmentTests(unittest.TestCase):
 def run_caller(self,current,home_present=True):
  if os.name!='posix':self.skipTest('managed creator POSIX pass_fds subprocess boundary; source/URI/AutoLogon check remains portable')
  source=raw('managed_create.current.source'if current else'managed_create.before.source');tree=ast.parse(source);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_creator_main');node=next(n for n in ast.walk(main)if isinstance(n,ast.FunctionDef)and n.name=='run')
  inherited=dict(os.environ)
  if not home_present:inherited.pop('HOME',None)
  expected=inherited.get('HOME');inherited['LIBVIRT_DEFAULT_URI']='qemu:///forbidden-ambient';inherited['XDG_CONFIG_HOME']='/controlled-ambient-config'
  # HOME is never changed in the parent or assigned to a synthetic path.
  with tempfile.TemporaryDirectory(prefix='creator-env-')as td:
   root=Path(td)/'new-vm';root.mkdir();tool=Path(td)/'public-tool.py'
   body='import json,os\nprint(json.dumps({"homePresent":"HOME"in os.environ,"homeMatchesInherited":os.environ.get("HOME")=='+repr(expected)+',"fixedPath":os.environ.get("PATH")=="/usr/bin:/bin","localeC":os.environ.get("LANG")==os.environ.get("LC_ALL")=="C","ambientLibvirtAbsent":"LIBVIRT_DEFAULT_URI"not in os.environ,"ambientConfigAbsent":"XDG_CONFIG_HOME"not in os.environ}))\n';tool.write_text(body);tool.chmod(0o700);fd=os.open(tool,os.O_RDONLY);calls=[];guards=[]
   def require(value,reason):
    if not value:raise ValueError(reason)
   class ProcessBoundary:
    @staticmethod
    def run(argv,**kw):
     # Original Linux fd-argv is asserted; only executable dispatch maps to
     # the same fixed source file on this platform, never a fake result.
     assert argv==['/proc/self/fd/'+str(fd),'public-argument']
     calls.append({'argvMatches':True,'passedFd':fd in kw['pass_fds'],'closeInput':kw['stdin']==subprocess.DEVNULL})
     return subprocess.run([sys.executable,'-I','-B',str(tool),'public-argument'],**kw)
   ProcessBoundary.DEVNULL=subprocess.DEVNULL;ProcessBoundary.PIPE=subprocess.PIPE
   ns={'manager_guard':lambda:guards.append('guard'),'binaries':{'qemu-img':fd},'assets':{},'root':root,'subprocess':ProcessBoundary,'os':types.SimpleNamespace(environ=inherited),'require':require}
   try:
    exec(compile(ast.Module(body=[node],type_ignores=[]),'authentic-nested-tool-run','exec'),ns);reply=json.loads(ns['run']('qemu-img',['public-argument']))
   finally:os.close(fd)
   self.assertEqual(len(guards),2);self.assertEqual(len(calls),1);self.assertTrue(calls[0]['passedFd']and calls[0]['closeInput']);return reply
 def test_before_repurposes_home_current_retains_actual_inherited_value(self):
  if 'HOME'not in os.environ:self.skipTest('actual inherited HOME absent; omission case covered separately')
  before=self.run_caller(False);current=self.run_caller(True)
  with self.assertRaises(AssertionError):self.assertTrue(before['homeMatchesInherited'])
  self.assertTrue(current['homeMatchesInherited']and current['homePresent'])
 def test_absent_home_is_not_invented(self):
  before=self.run_caller(False,False);current=self.run_caller(True,False)
  self.assertTrue(before['homePresent']);self.assertFalse(current['homePresent']);self.assertTrue(current['homeMatchesInherited'])
 def test_fixed_tool_environment_keeps_ambient_config_and_uri_out(self):
  for current in(False,True):
   reply=self.run_caller(current)
   self.assertTrue(reply['fixedPath']and reply['localeC']and reply['ambientLibvirtAbsent']and reply['ambientConfigAbsent'])
 def test_explicit_uri_no_autologon_and_environment_expression_contract(self):
  before=raw('managed_create.before.source');current=raw('managed_create.current.source')
  a=b"env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(root.parent)}";b=b"env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',**{key:value for key,value in os.environ.items()if key=='HOME'}}"
  self.assertEqual(1,before.count(a));self.assertEqual(1,current.count(b));self.assertNotIn(a,current);tree=ast.parse(current);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='_creator_main');call=next(n for n in ast.walk(main)if isinstance(n,ast.Call)and ast.unparse(n.func)=='libvirt.open');self.assertEqual(ast.unparse(call.args[0]),"PLAN['binding']['uri']")
  answer=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='private_answer');self.assertIn('AutoLogon',ast.unparse(answer));self.assertIn('component.remove(node)',ast.unparse(answer))
if __name__=='__main__':unittest.main(verbosity=2)
