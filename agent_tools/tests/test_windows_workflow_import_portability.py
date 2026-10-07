import subprocess,sys,unittest
from pathlib import Path
class WindowsWorkflowImportPortabilityTests(unittest.TestCase):
 def test_actual_selected_workflow_tests_load_without_fcntl_from_fresh_startup(self):
  script='''import importlib.abc,sys
assert "fcntl" not in sys.modules
assert not any(n.startswith("agent_tools.windows_") for n in sys.modules)
class NoFcntl(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=="fcntl": raise ModuleNotFoundError("No module named fcntl")
sys.meta_path.insert(0,NoFcntl())
import agent_tools.tests.test_windows_cp117_c32_absence
import agent_tools.tests.test_windows_cp117_windowless_dismiss_observe
'''
  result=subprocess.run([sys.executable,'-S','-c',script],cwd=Path(__file__).parents[2],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=10,check=False)
  self.assertEqual(0,result.returncode,result.stderr)
if __name__=='__main__':unittest.main()

class BoundArchiveDefaultTests(unittest.TestCase):
 def test_unavailable_base_refuses_before_root_access(self):
  from agent_tools import windows_cp117_bound_absence_completion as m
  class Root:
   def __truediv__(self,other): raise AssertionError('filesystem access')
  old=m.closure.base
  try:
   m.closure.base=None
   self.assertFalse(m._readonly_unknown_archive(Root(),None,None,None))
  finally:m.closure.base=old
 def test_supported_default_uses_original_constant(self):
  from agent_tools import windows_cp117_bound_absence_completion as m
  calls=[]
  class Base:
   _UNKNOWN_CLOSURE_CORRELATION='original-default'
   def _unknown_recovery_profile(self,c):calls.append(c);return None
  old=m.closure.base
  try:
   m.closure.base=Base();self.assertFalse(m._readonly_unknown_archive(None,None,None,None));self.assertEqual(['original-default'],calls)
  finally:m.closure.base=old
 def test_explicit_correlation_is_unchanged(self):
  from agent_tools import windows_cp117_bound_absence_completion as m
  calls=[]
  class Base:
   _UNKNOWN_CLOSURE_CORRELATION='original-default'
   def _unknown_recovery_profile(self,c):calls.append(c);return None
  old=m.closure.base
  try:
   m.closure.base=Base();self.assertFalse(m._readonly_unknown_archive(None,None,None,None,'explicit'));self.assertEqual(['explicit'],calls)
  finally:m.closure.base=old
