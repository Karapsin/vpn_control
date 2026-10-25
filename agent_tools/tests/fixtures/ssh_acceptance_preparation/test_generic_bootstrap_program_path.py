"""Actual f3b bootstrap; full original/current payload with finite local bindings.

Only constants bind to a controlled namespace and inert controller source. No
real SSH controller or remote/native action can be called by these projections.
"""
from pathlib import Path
from dataclasses import asdict
import ast,hashlib,json,os,shutil,sys,tempfile,time,unittest,uuid
HERE=Path(__file__).resolve().parent
path=HERE/'local-owner-source/local_owner_v2.py';local=type(sys)('_bootstrap_fixed_local');local.__file__=str(path);local.__package__=None;sys.modules[local.__name__]=local;exec(compile(path.read_bytes(),str(path),'exec'),local.__dict__)
class GenericBootstrapProgramPathTests(unittest.TestCase):
 def project(self,version,parent,op):
  raw=(HERE/('ordinary-controller-direct-'+version+'.source')).read_bytes();tree=ast.parse(raw)
  control=parent/'controller.py';marker=parent/'called-fixed-local-controller'
  control.write_text('from pathlib import Path\nimport time\ndef main(args,*,absolute_deadline=None):\n assert args.mode=="direct" and args.count==1600 and args.budget==600 and args.interval==.15 and args.native_go is True\n assert type(absolute_deadline)in(int,float)and time.monotonic()<absolute_deadline\n Path('+repr(str(marker))+').write_text("local-only")\n print("fixed-projected-controller",flush=True)\n');control.chmod(0o600)
  wrapper=HERE/'local-owner-source/local_owner_v2.py';artifacts=[]
  for source in(wrapper,control):artifacts.append({'path':str(source),'generation':local.generation(os.lstat(source)),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()})
  campaign={'kind':'ordinary-ssh-acceptance','mode':'direct','remoteOperationId':str(uuid.uuid4())}
  replacements={'ROOT':str(parent),'LOCAL_OPERATION':op,'ARTIFACTS':artifacts,'CAMPAIGN':campaign,'WRAPPER':str(wrapper)}
  changed=[]
  for node in tree.body:
   if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in replacements:
    name=node.targets[0].id;node.value=ast.parse(repr(replacements[name]),mode='eval').body;changed.append(name)
  self.assertEqual(set(replacements),set(changed))
  # Apart from these finite input bindings the complete actual payload executes.
  return(ast.unparse(ast.fix_missing_locations(tree))+'\n').encode(),campaign,marker
 def test_actual_generic_owner_omits_file_before_nameerror_red_fixed_saved_source_green(self):
  for version,old in(('v2',True),('v3',False)):
   parent=Path(tempfile.mkdtemp(prefix='vc-program-path-')).resolve();parent.chmod(0o700);op=str(uuid.uuid4());api,held=local.owner_api();complete=False
   try:
    binding=asdict(api.current_binding('controlled-fixture','owned-bootstrap-fixture'));root=parent/'local-owner-direct';local.initialize(root,binding,source_guard=lambda:None)
    payload,campaign,marker=self.project(version,parent,op);program=api.Program('ordinary-ssh-acceptance-controller',payload,4194304)
    with local.Namespace(root)as namespace:namespace.submit_once(op,program,campaign=campaign,source_guard=lambda:None,budget_seconds=600)
    end=time.monotonic()+8
    with local.Namespace(root)as namespace:
     while time.monotonic()<end:
      value=namespace.observe(op)
      if value['state']=='terminal':break
      time.sleep(.01)
     self.assertEqual('terminal',value['state']);status,leaf=namespace.collect(op,closing_guard=lambda:None)
    output=(leaf/'stdout.bin').read_bytes();error=(leaf/'stderr.bin').read_bytes()
    self.assertEqual(1 if old else 0,status['terminal']['exitCode'])
    if old:self.assertIn(b"name '__file__' is not defined",error);self.assertEqual(b'',output);self.assertFalse(marker.exists())
    else:self.assertEqual(b'fixed-projected-controller\n',output);self.assertEqual(b'',error);self.assertEqual('local-only',marker.read_text())
    identity=status['owner'];end=time.monotonic()+3
    while api._birth(identity['pid'])==identity['birth']and time.monotonic()<end:time.sleep(.01)
    self.assertNotEqual(identity['birth'],api._birth(identity['pid']));complete=True
   finally:
    held.close()
    if complete:shutil.rmtree(parent)
  for mode in('direct','nested'):self.assertFalse((HERE/('local-owner-'+mode)).exists())
 def test_rendered_source_only_one_owned_source_path_delta_and_original_lineage_preserved(self):
  for mode in('direct','nested'):
   old=(HERE/('ordinary-controller-'+mode+'-v2.source')).read_bytes();new=(HERE/('ordinary-controller-'+mode+'-v3.source')).read_bytes()
   expected=old.replace(b"  own=stack.enter_context(Held(Path(__file__)))",b"  own=stack.enter_context(Held(Path(ROOT)/('local-owner-'+MODE)/'jobs'/LOCAL_OPERATION/'program.py'))")
   self.assertEqual(expected,new)
   self.assertFalse((HERE/mode/'.rag_index').exists());self.assertFalse((HERE/mode/'operation.json').exists())
 def test_original_relocated_projection_wrong_wrapper_key_red_scoped_projection_green(self):
  before=type(sys)('_original_relocated_projection');before.__file__=str(HERE/'test_generic_bootstrap_program_path.py');before.__package__=None;sys.modules[before.__name__]=before
  exec(compile((HERE/'test_generic_bootstrap_program_path.port-before.source').read_bytes(),before.__file__,'exec'),before.__dict__)
  with tempfile.TemporaryDirectory()as temporary:
   for case,old in((before.GenericBootstrapProgramPathTests(),True),(self,False)):
    parent=Path(temporary).resolve()/str(old);parent.mkdir(mode=0o700)
    raw,_,_=case.project('v2',parent,str(uuid.uuid4()));tree=ast.parse(raw)
    values={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('WRAPPER','ARTIFACTS')}
    # This is the complete original key expression reached before any wrapper
    # execution; only source custody values are used, without pathname lookup.
    expression=next(n for n in ast.walk(tree)if isinstance(n,ast.Subscript)and isinstance(n.value,ast.Name)and n.value.id=='held'and isinstance(n.slice,ast.Name)and n.slice.id=='WRAPPER')
    scope={'held':{v['path']:v for v in values['ARTIFACTS']},'WRAPPER':values['WRAPPER']}
    code=compile(ast.Expression(expression),'<actual-bootstrap-fixture-key>','eval')
    if old:
     with self.assertRaises(KeyError):eval(code,scope)
    else:self.assertEqual(str(HERE/'local-owner-source/local_owner_v2.py'),eval(code,scope)['path'])
if __name__=='__main__':unittest.main()
