"""Finite actual preparation/harness beforeimages; no native/transport callbacks."""
from pathlib import Path
import ast,copy,os,stat,sys,tempfile,unittest
HERE=Path(__file__).resolve().parent
OLD=HERE
class PreparationCausals(unittest.TestCase):
 def test_original_audit_wrong_host_key_scope_red_exact_gateway_local_scope_green(self):
  for name,old in(('audit_prepared_sources.remote-path.before.source',True),('audit_prepared_sources.py',False)):
   tree=ast.parse((OLD/name).read_bytes())
   functions=[copy.deepcopy(n)for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in('gen','chain','hold')]
   loop=next(copy.deepcopy(n)for n in ast.walk(tree)if isinstance(n,ast.For)and isinstance(n.target,ast.Name)and n.target.id=='path'and any(isinstance(v,ast.Call)and isinstance(v.func,ast.Name)and v.func.id=='hold'for v in ast.walk(n)))
   with tempfile.TemporaryDirectory()as temporary:
    root=Path(temporary).resolve();localkey=root/'local-key';trust=root/'local-trust'
    for path in(localkey,trust):path.write_bytes(b'fixed-public-fixture');path.chmod(0o600)
    remote=root/'remote-host-path';remote.write_bytes(b'not-a-local-directory');remote.chmod(0o600)
    scope={'Path':Path,'os':os,'stat':stat,'held':[],'directories':{},'input_metadata':[],
     'config':{'hosts':{'gateway':{'identityFile':str(localkey),'knownHostsFile':str(trust)},'archlinux':{'identityFile':str(remote/'key'),'knownHostsFile':str(remote/'trust')}}}}
    try:
     code=compile(ast.fix_missing_locations(ast.Module(body=functions+[loop],type_ignores=[])),'<actual-private-audit-key-boundary>','exec')
     if old:
      with self.assertRaisesRegex(ValueError,'audit_non_directory_parent'):exec(code,scope)
     else:exec(code,scope);self.assertEqual(2,len(scope['input_metadata']))
    finally:
     for fd,*_ in reversed(scope['held']):os.close(fd)
     for fd,_ in reversed(list(scope['directories'].values())):os.close(fd)
 def test_actual_epoch_generator_parser_before_red_current_compile_green_zeroexecution(self):
  with self.assertRaises(SyntaxError):compile((OLD/'prepare_absolute_epoch.syntax-before.source').read_bytes(),'<actual-preserved-parser-failure>','exec')
  compile((OLD/'prepare_absolute_epoch.py').read_bytes(),'<actual-fixed-generator>','exec')
 def test_actual_missing_fake_binding_assertion_before_red_corrected_boundary_green(self):
  for path,old in((OLD/'local-owner-source/test_local_owner.missing-binding.before.source',True),(HERE/'local-owner-source/test_local_owner_v2.py',False)):
   raw=path.read_bytes();module=type(sys)('_source_fixture_case_'+str(old));module.__file__=str(path);module.__package__=None;sys.modules[module.__name__]=module
   exec(compile(raw,str(path),'exec'),module.__dict__)
   case=module.AdmissionDeadlineBoundaryTests('test_actual_predeadline_submit_callback_cost_red_current_consumed_index_no_child_green')
   result=unittest.TestResult();case.run(result)
   self.assertEqual(1 if old else 0,len(result.failures));self.assertEqual([],result.errors)
if __name__=='__main__':unittest.main()
