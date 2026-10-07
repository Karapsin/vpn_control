"""Whole actual receiver protocol real-child timeout diagnosis, local only.
Seams: finite 2400s->0.2s clock; fixed sudo/root worker replaced by harmless
Python child; explicit local UID/GID503→1000 primitive metadata projection. No source/guest/fence authority claimed.
"""
import ast,base64,copy,hashlib,json,subprocess,sys,unittest,tempfile,uuid
from pathlib import Path
from agent_tools.tests.fixtures import android_component_receiver_timeout as fixture
SHA=fixture.ORIGIN_RECEIVER_SHA256
class ReceiverTimeout(unittest.TestCase):
 def exercise(self,child,payload=b'nonsecret-fixture-source',receiver_source=None):
  raw=fixture.REMOTE_SOURCE.encode();self.assertEqual(hashlib.sha256(raw).hexdigest(),SHA);tree=ast.parse(raw if receiver_source is None else receiver_source)
  assignments={'EXPECTED_BYTES':len(payload),'EXPECTED_SHA':hashlib.sha256(payload).hexdigest(),'ROOT_BOOT':'unused-local-fixture'}
  counts={name:0 for name in assignments};popen=0;deadline=0;principal=0
  for node in ast.walk(tree):
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and isinstance(node.func.value,ast.Name)and node.func.value.id=='os'and node.func.attr in ('getuid','geteuid','getgid','getegid','getgroups'):
    node.func=ast.parse('(lambda: [1000])'if node.func.attr=='getgroups'else'(lambda: 1000)',mode='eval').body;principal+=1
   if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in assignments:
    name=node.targets[0].id;node.value=ast.Constant(assignments[name]);counts[name]+=1
   if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and isinstance(node.func.value,ast.Name)and node.func.value.id=='subprocess'and node.func.attr=='Popen':
    self.assertEqual([ast.literal_eval(x)for x in node.args[0].elts[:-1]],['/usr/bin/sudo','-S','-p','','--','/usr/bin/python3','-I','-B','-c']);node.args[0]=ast.parse(repr([sys.executable,'-I','-B','-c',child]),mode='eval').body;popen+=1
   if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id=='deadline'and isinstance(node.value,ast.BinOp)and isinstance(node.value.right,ast.Constant)and node.value.right.value==2400:
    node.value.right=ast.Constant(.2);deadline+=1
  self.assertEqual(counts,{name:1 for name in assignments});self.assertEqual((popen,deadline,principal),(1,1,5));ast.fix_missing_locations(tree)
  result=subprocess.run([sys.executable,'-I','-B','-c',ast.unparse(tree)],input=b'nonsecret-password-fixture\n'+payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
  self.assertEqual(result.returncode,0,result.stderr.decode());self.receiver_stdout=result.stdout;self.receiver_stderr=result.stderr
  if receiver_source is None:self.assertEqual(result.stderr,b'')
  lines=result.stdout.splitlines();terminal=json.loads(lines[0]);streams={b'out':bytearray(),b'err':bytearray()}
  for line in lines[1:]:name,data=line.split(b':',1);streams[name].extend(base64.b64decode(data,validate=True))
  return terminal,streams
 def test_buffered_native_progress_is_lost_before_final_print(self):
  terminal,streams=self.exercise("import sys,time;sys.stdin.buffer.read();sys.stdout.write('BUFFERED-NONSECRET');time.sleep(1)")
  self.assertEqual((terminal['failure'],terminal['returncode'],terminal['stdoutBytes']),('ValueError',-9,0));self.assertEqual(streams[b'out'],b'');self.assertNotIn('baseline_remote_collection_timeout',str(terminal))
 def test_flushed_progress_survives_same_timeout(self):
  terminal,streams=self.exercise("import sys,time;sys.stdin.buffer.read();print('FLUSHED-NONSECRET',flush=True);time.sleep(1)")
  self.assertEqual((terminal['failure'],terminal['returncode']),('ValueError',-9));self.assertEqual(streams[b'out'],b'FLUSHED-NONSECRET\n');self.assertEqual(terminal['stdoutBytes'],18)
 def test_complete_child_closes_protocol_without_timeout(self):
  terminal,streams=self.exercise("import sys;sys.stdin.buffer.read();print('COMPLETE-NONSECRET',flush=True)")
  self.assertEqual((terminal['failure'],terminal['returncode']),(None,0));self.assertEqual(streams[b'out'],b'COMPLETE-NONSECRET\n')
 def root_child(self,payload,root_source=None):
  raw=fixture.REMOTE_SOURCE.encode();self.assertEqual(hashlib.sha256(raw).hexdigest(),SHA)
  root=next(ast.literal_eval(n.value)for n in ast.parse(raw).body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='ROOT_BOOT')
  tree=ast.parse(root if root_source is None else root_source);counts={'get':0,'set':0,'fstat':0,'principal':0}
  class Transform(ast.NodeTransformer):
   def visit_Assign(inner,n):
    inner.generic_visit(n)
    if len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in ('EXPECTED_BYTES','EXPECTED_SHA'):
     n.value=ast.Constant(len(payload)if n.targets[0].id=='EXPECTED_BYTES'else hashlib.sha256(payload).hexdigest())
    return n
   def visit_Call(inner,n):
    inner.generic_visit(n)
    if isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name):
     module,name=n.func.value.id,n.func.attr
     if module=='os'and name in ('getuid','geteuid','getgid','getegid','getgroups'):
      n.func=ast.parse('(lambda: [0])'if name=='getgroups'else'(lambda: 0)',mode='eval').body;counts['principal']+=1
     if module=='os'and name=='fstat':n.func=ast.Name(id='fixture_fstat',ctx=ast.Load());counts['fstat']+=1
     if root_source is not None and module=='os'and name=='stat':n.func=ast.Name(id='fixture_stat',ctx=ast.Load())
     if module=='resource'and name=='getrlimit':n.func=ast.parse('(lambda key: LIMIT_STATE[0])',mode='eval').body;counts['get']+=1
     if module=='resource'and name=='setrlimit':n.func=ast.parse('(lambda key,value: LIMIT_STATE.__setitem__(0,value))',mode='eval').body;counts['set']+=1
    return n
  tree=Transform().visit(tree);ast.fix_missing_locations(tree);self.assertEqual(counts['principal'],5);self.assertGreater(counts['fstat'],0);self.assertEqual((counts['get'],counts['set']),(3,2))
  prefix="import os\nLIMIT_STATE=[(4096,4096)]\nclass StatPrincipal:\n def __init__(self,value):self.value=value\n def __getattr__(self,name):return 1000 if name in ('st_uid','st_gid') else 1 if name=='st_nlink' else getattr(self.value,name)\ndef fixture_fstat(fd):return StatPrincipal(os.fstat(fd))\n"
  if root_source is not None:
   prefix="import os,stat\nLIMIT_STATE=[(4096,4096)]\nclass StatPrincipal:\n def __init__(self,value):self.value=value\n def __getattr__(self,name):return (1000 if stat.S_ISFIFO(self.value.st_mode)else 0) if name in ('st_uid','st_gid') else 1 if name=='st_nlink' and stat.S_ISFIFO(self.value.st_mode) else getattr(self.value,name)\ndef fixture_fstat(fd):return StatPrincipal(os.fstat(fd))\ndef fixture_stat(*args,**kwargs):return StatPrincipal(os.stat(*args,**kwargs))\n"
  return prefix+'exec('+repr(ast.unparse(tree))+',globals())'
 def test_whole_root_boot_withholds_flushed_native_stdout_on_receiver_timeout(self):
  payload=b"print('NATIVE-FLUSHED-NONSECRET',flush=True);__import__('time').sleep(1)"
  terminal,streams=self.exercise(self.root_child(payload),payload)
  self.assertEqual((terminal['failure'],terminal['returncode'],terminal['stdoutBytes']),('ValueError',-9,0));self.assertEqual(streams[b'out'],b'')
 def test_whole_root_boot_releases_output_after_checked_close(self):
  payload=b"print('NATIVE-FLUSHED-NONSECRET',flush=True)"
  terminal,streams=self.exercise(self.root_child(payload),payload)
  self.assertEqual((terminal['failure'],terminal['returncode']),(None,0),streams[b'err'].decode());self.assertEqual(streams[b'out'],b'NATIVE-FLUSHED-NONSECRET\n')
class FiniteReceiverDiagnostic(unittest.TestCase):
 exercise=ReceiverTimeout.exercise
 def composer(self):
  raw=fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE.encode()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),fixture.FINITE_DIAGNOSTIC_COMPOSER_SHA256)
  namespace={'__name__':'__source_bound_composer__'}
  exec(compile(raw,'<source-bound-carrier-composer>','exec',dont_inherit=True),namespace)
  return namespace['retain_receiver_failure_code']
 def diagnostic(self):
  marker=b'VPNCONTROL_COMPONENT_DIAGNOSTIC_V1 '
  self.assertTrue(self.receiver_stderr.startswith(marker));self.assertEqual(self.receiver_stderr.count(b'\n'),1)
  return json.loads(self.receiver_stderr[len(marker):])
 def test_actual_receiver_timeout_literal_retained_without_terminal_schema_change(self):
  child="import sys,time;sys.stdin.buffer.read();time.sleep(1)"
  old,_=self.exercise(child)
  self.assertEqual(self.receiver_stderr,b'');self.assertNotIn('baseline_remote_collection_timeout',str(old))
  new,_=self.exercise(child,receiver_source=self.composer()(fixture.REMOTE_SOURCE))
  self.assertEqual(set(old),set(new));self.assertEqual(new['failure'],'ValueError')
  self.assertEqual(self.diagnostic(),{'schema':1,'kind':'component-carrier-failure-diagnostic','stage':'native-collection','type':'ValueError','code':'baseline_remote_collection_timeout','authorityGranted':False})
 def test_private_exception_text_is_not_emitted(self):
  changed=self.composer()(fixture.REMOTE_SOURCE)
  needle="raise ValueError('baseline_remote_collection_timeout')"
  self.assertEqual(changed.count(needle),1)
  for expression,kind in (("ValueError('PRIVATE-FIXTURE-TEXT')",'ValueError'),("TypeError('PRIVATE-FIXTURE-TEXT')",'TypeError')):
   native=changed.replace(needle,'raise '+expression)
   self.exercise("import sys,time;sys.stdin.buffer.read();time.sleep(1)",receiver_source=native)
   self.assertEqual(self.diagnostic()['type'],kind);self.assertIsNone(self.diagnostic()['code']);self.assertNotIn(b'PRIVATE-FIXTURE-TEXT',self.receiver_stderr)
 def test_success_keeps_stderr_and_terminal_unchanged(self):
  source=self.composer()(fixture.REMOTE_SOURCE)
  value,streams=self.exercise("import sys;sys.stdin.buffer.read();print('COMPLETE-NONSECRET',flush=True)",receiver_source=source)
  self.assertEqual(self.receiver_stderr,b'');self.assertEqual((value['returncode'],value['failure']),(0,None));self.assertEqual(streams[b'out'],b'COMPLETE-NONSECRET\n')
 def test_exception_boundary_drift_is_refused(self):
  with self.assertRaisesRegex(ValueError,'carrier_receiver_exception_boundary_changed'):
   self.composer()(fixture.REMOTE_SOURCE.replace('except Exception as error:failure=type(error).__name__','except Exception as error:failure=None'))

class DurableRootOutput(unittest.TestCase):
 exercise=ReceiverTimeout.exercise
 root_child=ReceiverTimeout.root_child
 composer=FiniteReceiverDiagnostic.composer
 def root_source(self):
  return next(ast.literal_eval(n.value)for n in ast.parse(fixture.REMOTE_SOURCE).body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id=='ROOT_BOOT')
 def retained_root(self,path,correlation):
  raw=fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE.encode();self.assertEqual(hashlib.sha256(raw).hexdigest(),fixture.FINITE_DIAGNOSTIC_COMPOSER_SHA256)
  n={};exec(compile(raw,'<source-bound-carrier-composer>','exec',dont_inherit=True),n)
  return n['retain_root_output'](self.root_source(),str(path),correlation,('entry','checked'))
 def retained_chunks(self,directory):
  values=[]
  for metadata in sorted(directory.glob('chunk-*.json')):
   item=json.loads(metadata.read_bytes());raw=metadata.with_suffix('.raw').read_bytes()
   self.assertEqual(item['bytes'],len(raw));self.assertEqual(item['sha256'],hashlib.sha256(raw).hexdigest());self.assertLessEqual(len(raw),524288);self.assertIs(item['authorityGranted'],False)
   self.assertEqual((metadata.stat().st_mode&0o777,metadata.with_suffix('.raw').stat().st_mode&0o777),(0o600,0o600));values.append((item['role'],raw))
  return values
 def test_actual_root_boot_retains_flushed_raw_before_receiver_kill(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());payload=b"CARRIER_RECORD_PHASE('entry');print('NATIVE-RETAINED-NONSECRET',flush=True);__import__('time').sleep(1)"
   terminal,streams=self.exercise(self.root_child(payload,self.retained_root(root,correlation)),payload)
   self.assertEqual((terminal['returncode'],terminal['failure'],terminal['stdoutBytes']),(-9,'ValueError',0));self.assertEqual(streams[b'out'],b'')
   directory=root/('android-component-carrier-raw-'+correlation);self.assertEqual(directory.stat().st_mode&0o777,0o700)
   intent=json.loads((directory/'intent.json').read_bytes());self.assertEqual(intent['correlationId'],correlation);self.assertIs(intent['authorityGranted'],False)
   chunks=self.retained_chunks(directory);self.assertEqual(b''.join(raw for role,raw in chunks if role=='stdout'),b'NATIVE-RETAINED-NONSECRET\n')
   phase=json.loads(next(raw for role,raw in chunks if role=='phase'));self.assertEqual(phase['stage'],'entry');self.assertIs(phase['authorityGranted'],False);self.assertIn(b'VPNCONTROL_COMPONENT_PHASE_V1 ',streams[b'err'])
 def test_actual_root_boot_close_preserves_stdout_and_chunk_bound(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());payload=b"print('x'*600000,end='',flush=True)"
   terminal,streams=self.exercise(self.root_child(payload,self.retained_root(root,correlation)),payload)
   self.assertEqual((terminal['returncode'],terminal['failure']),(0,None),streams[b'err'].decode());self.assertEqual(streams[b'out'],b'x'*600000)
   chunks=self.retained_chunks(root/('android-component-carrier-raw-'+correlation));self.assertEqual(b''.join(raw for role,raw in chunks if role=='stdout'),streams[b'out']);self.assertEqual(len(chunks),2)
 def test_failed_closing_still_releases_raw_but_is_not_success(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());payload=b"print('FAILED-CLOSE-NONSECRET',flush=True)"
   source=self.retained_root(root,correlation);needle='if resource.getrlimit(resource.RLIMIT_FSIZE)!=original_limit or '
   self.assertEqual(source.count(needle),1);source=source.replace(needle,'if resource.getrlimit(resource.RLIMIT_FSIZE)!=original_limit or True or ')
   terminal,streams=self.exercise(self.root_child(payload,source),payload)
   self.assertEqual(terminal['returncode'],1);self.assertEqual(streams[b'out'],b'FAILED-CLOSE-NONSECRET\n');self.assertIn(b'baseline_root_closing_unknown',streams[b'err'])

 def test_directory_exchange_refuses_and_preserves_both_locations(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());directory=root/('android-component-carrier-raw-'+correlation);moved=root/'preserved-original'
   code="print('ORIGINAL-NONSECRET',flush=True);__import__('os').rename("+repr(str(directory))+","+repr(str(moved))+");__import__('os').mkdir("+repr(str(directory))+",0o700);print('FOREIGN-MUST-NOT-WRITE',flush=True)"
   payload=code.encode();terminal,streams=self.exercise(self.root_child(payload,self.retained_root(root,correlation)),payload)
   self.assertEqual(terminal['returncode'],1);self.assertIn(b'carrier_raw_directory_changed',streams[b'err']);self.assertEqual(list(directory.iterdir()),[])
   chunks=self.retained_chunks(moved);self.assertEqual(b''.join(raw for role,raw in chunks if role=='stdout'),b'ORIGINAL-NONSECRET\n');self.assertNotIn(b'FOREIGN-MUST-NOT-WRITE',streams[b'out'])
 def test_same_owned_directory_is_create_only(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());directory=root/('android-component-carrier-raw-'+correlation);directory.mkdir(mode=0o700);sentinel=directory/'foreign';sentinel.write_bytes(b'PRESERVED-NONSECRET')
   payload=b"print('NOT-RETAINED',flush=True)";terminal,streams=self.exercise(self.root_child(payload,self.retained_root(root,correlation)),payload)
   self.assertEqual(terminal['returncode'],1);self.assertEqual(sentinel.read_bytes(),b'PRESERVED-NONSECRET');self.assertEqual(sorted(p.name for p in directory.iterdir()),['foreign']);self.assertEqual(streams[b'out'],b'')

 def test_structural_parent_allows_original_flow_new_sibling_children(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4());code="print('FIRST-NONSECRET',flush=True);__import__('os').mkdir("+repr(str(root/'actual-child-guard-output'))+",0o700);print('SECOND-NONSECRET',flush=True)";payload=code.encode()
   terminal,streams=self.exercise(self.root_child(payload,self.retained_root(root,correlation)),payload)
   self.assertEqual((terminal['returncode'],terminal['failure']),(0,None),streams[b'err'].decode()[-512:]);self.assertEqual(streams[b'out'],b'FIRST-NONSECRET\nSECOND-NONSECRET\n')

 def test_owned_progress_actual_raw_cache_retains_one_record_and_two_references(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);correlation=str(uuid.uuid4())
   source="import json,hashlib\nCOMPONENT_RELEASE_FAILURE_STAGES=('entry','checked')\nCOMPONENT_RETIRE_RAW_INDEX={}\nCOMPONENT_RETIRE_RAW_RECORDS=[]\nCLAIM_OBSERVATIONS=[]\n"+fixture.OWNED_RAW_CACHE_FUNCTION+'\n'+fixture.OWNED_RAW_CACHE_FUNCTION+"\nglobals()['COMPONENT_RELEASE_FAILURE_STAGE']='entry'\nrecord={'path':'nonsecret-source-shaped-record','generation':[1,2,33152,0,0,1,2,3,4],'sha256':hashlib.sha256(b'{}').hexdigest(),'bytes':2,'parents':{},'rawBase64':'e30='}\ncomponent_retirement_record_raw(record)\ncomponent_retirement_record_raw(record)\nassert len(COMPONENT_RETIRE_RAW_RECORDS)==1 and len(CLAIM_OBSERVATIONS)==2\nprint('CACHE-NONSECRET',flush=True)\n"
   n={};exec(compile(fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE,'<held-carrier-composer>','exec',dont_inherit=True),n);payload,stages,count=n['retain_owned_progress'](source.encode())
   self.assertEqual((stages,count),(('entry','checked'),1))
   boot=n['retain_root_output'](self.root_source(),str(root),correlation,stages);terminal,streams=self.exercise(self.root_child(payload,boot),payload)
   self.assertEqual((terminal['returncode'],terminal['failure']),(0,None),streams[b'err'].decode()[-512:]);chunks=self.retained_chunks(root/('android-component-carrier-raw-'+correlation));rows=[json.loads(raw)for role,raw in chunks if role=='record'];self.assertEqual(len(rows),1);self.assertEqual(rows[0]['bytes'],2);self.assertEqual(rows[0]['sha256'],hashlib.sha256(b'{}').hexdigest())

if __name__=='__main__':unittest.main()

class PhaseParserIngress(unittest.TestCase):
 exercise=ReceiverTimeout.exercise
 root_child=ReceiverTimeout.root_child
 retained_root=DurableRootOutput.retained_root
 root_source=DurableRootOutput.root_source
 def parser_namespace(self):
  import math
  n={'json':json,'hashlib':hashlib,'math':math,'base64':base64,'CHUNK':524288,'STREAM_LIMIT':201326592}
  exec(compile('import json\nimport math\nimport base64\n'+fixture.TERMINAL_PARSER_SOURCE,'<held-terminal-parser>','exec',dont_inherit=True),n)
  return n
 def capture(self,root):
  from agent_tools.windows_diagnostic_authority_capture import AuthorityCapture
  root=root.resolve();parent=root/'.runtime/parity-evidence';parent.mkdir(parents=True,mode=0o700,exist_ok=True)
  leaf=str(uuid.uuid4());(parent/leaf).mkdir(mode=0o700)
  return AuthorityCapture(root,leaf)
 def test_old_actual_phase_escape_and_parser_red_retains_raw(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);corr=str(uuid.uuid4());payload=b"CARRIER_RECORD_PHASE('entry');print('{}',flush=True)"
   n={};exec(compile(fixture.OLD_PHASE_COMPOSER_SOURCE,'<old-phase-composer>','exec',dont_inherit=True),n)
   boot=n['retain_root_output'](self.root_source(),str(root),corr,('entry','checked'))
   header,streams=self.exercise(self.root_child(payload,boot),payload)
   self.assertEqual((header['returncode'],header['failure']),(0,None))
   self.assertTrue(streams[b'err'].endswith(b'\n'));self.assertFalse(streams[b'err'].endswith(b'\\n'))
   capture=self.capture(root)
   try:
    with self.assertRaisesRegex(ValueError,'baseline_component_terminal_unknown_raw_retained'):
     self.parser_namespace()['parse_terminal'](self.receiver_stdout,{'source':payload,'capture':capture})
    self.assertTrue((capture.path/'remote-terminal.json').exists())
    self.assertEqual(json.loads((capture.path/'remote-stderr-manifest.json').read_bytes())['sha256'],hashlib.sha256(streams[b'err']).hexdigest())
   finally:capture.close()
 def completed_wire(self,root,payload=b"CARRIER_RECORD_PHASE('entry');CARRIER_RECORD_PHASE('checked');print('{}',flush=True)"):
  corr=str(uuid.uuid4());boot=self.retained_root(root,corr)
  header,streams=self.exercise(self.root_child(payload,boot),payload)
  n={};exec(compile(fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE,'<held-composer>','exec',dont_inherit=True),n)
  parser=n['bind_phase_terminal_parser'](self.parser_namespace()['parse_terminal'],corr,payload,('entry','checked'))
  return payload,header,streams,parser
 def wire(self,header,streams):
  h=dict(header)
  for name,label in ((b'out','stdout'),(b'err','stderr')):
   h[label+'Bytes']=len(streams[name]);h[label+'Sha256']=hashlib.sha256(streams[name]).hexdigest()
  return json.dumps(h,sort_keys=True,separators=(',',':')).encode()+b'\n'+b''.join(name+b':'+base64.b64encode(bytes(raw[start:start+524288]))+b'\n'for name,raw in streams.items()for start in range(0,len(raw),524288))
 def parsed(self,root,payload,parser,wire,refuse=False):
  capture=self.capture(root)
  try:
   if refuse:
    with self.assertRaisesRegex(ValueError,'baseline_component_terminal_unknown_raw_retained'):parser(wire,{'source':payload,'capture':capture})
    self.assertTrue((capture.path/'remote-terminal.json').exists());self.assertTrue((capture.path/'remote-stderr-manifest.json').exists())
   else:self.assertEqual(parser(wire,{'source':payload,'capture':capture}),b'{}\n')
  finally:capture.close()
 def test_complete_actual_phase_emitter_receiver_parser_green(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);payload,h,streams,parser=self.completed_wire(root)
   self.assertEqual((h['returncode'],h['failure']),(0,None));self.assertEqual(bytes(streams[b'err']).count(b'\n'),2)
   self.parsed(root,payload,parser,self.receiver_stdout)
   self.assertIsNot(parser.__globals__,self.parser_namespace()['parse_terminal'].__globals__)
 def test_actual_phase_wire_strict_refusals_archive_before_classification(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);payload,h,streams,parser=self.completed_wire(root)
   lines=bytes(streams[b'err']).splitlines();prefix=b'VPNCONTROL_COMPONENT_PHASE_V1 ';record=json.loads(lines[0][len(prefix):])
   for field,value in [('schema',True),('kind','foreign'),('correlationId',str(uuid.uuid4())),('sourceSha256','0'*64),('sourceBytes',True),('stage','foreign'),('elapsedSeconds',True),('elapsedSeconds',float('nan')),('elapsedSeconds',-1.0),('elapsedSeconds',1201.0),('authorityGranted',True)]:
    with self.subTest(field=field,value=value):
     item=dict(record);item[field]=value;changed=dict(streams);changed[b'err']=prefix+json.dumps(item,sort_keys=True,separators=(',',':')).encode()+b'\n'+lines[1]+b'\n'
     self.parsed(root,payload,parser,self.wire(h,changed),True)
   for raw in [b'PRIVATE-NON-PHASE\n'+bytes(streams[b'err']),bytes(streams[b'err'])+b'PRIVATE-NON-PHASE\n',bytes(streams[b'err'])[:-1],b'\n',prefix+b'{}\n',bytes(streams[b'err'])*4097]:
    changed=dict(streams);changed[b'err']=raw;self.parsed(root,payload,parser,self.wire(h,changed),True)
   second=json.loads(lines[1][len(prefix):]);second['elapsedSeconds']=0.0
   changed=dict(streams);changed[b'err']=lines[0]+b'\n'+prefix+json.dumps(second,sort_keys=True,separators=(',',':')).encode()+b'\n';self.parsed(root,payload,parser,self.wire(h,changed),True)
   for changes in ({'returncode':1},{'returncode':True},{'failure':'ValueError'}):
    altered=dict(h);altered.update(changes);self.parsed(root,payload,parser,self.wire(altered,streams),True)
 def test_actual_root_failure_and_closing_failure_never_accept_phase_raw(self):
  for closing in (False,True):
   with tempfile.TemporaryDirectory()as temp:
    root=Path(temp);corr=str(uuid.uuid4());payload=b"CARRIER_RECORD_PHASE('entry');print('{}',flush=True)" if closing else b"CARRIER_RECORD_PHASE('entry');raise ValueError('NONSECRET-FAILURE')"
    boot=self.retained_root(root,corr)
    if closing:boot=boot.replace('if resource.getrlimit(resource.RLIMIT_FSIZE)!=original_limit','if True or resource.getrlimit(resource.RLIMIT_FSIZE)!=original_limit')
    h,streams=self.exercise(self.root_child(payload,boot),payload);self.assertNotEqual(h['returncode'],0)
    n={};exec(fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE,n);parser=n['bind_phase_terminal_parser'](self.parser_namespace()['parse_terminal'],corr,payload,('entry','checked'))
    self.parsed(root,payload,parser,self.receiver_stdout,True)

class OriginalEffectPlaneGate(unittest.TestCase):
 """Exact emitted readers/projector on TempFS; no native authority.
 Declared seams: fixed /proc location and host UID/GID principal sets only.
 Separate prior descriptor witness is read before the guard's later two reads.
 """
 def make_plane(self):
  import os,stat
  from agent_tools import android_installer_component_bundle as bundle
  for name in ('NATIVE_GUARD','PROCESS','PROJECTOR','BOUNDARY','CLAIM'):
   source=getattr(fixture,'EFFECT_PLANE_'+name+'_SOURCE');self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),getattr(fixture,'EFFECT_PLANE_'+name+'_SOURCE_SHA256'))
  t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);root=Path(t.name).resolve();root.chmod(0o700);proc=root/'proc';proc.mkdir(mode=0o700)
  boot=proc/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text('25515f23-b966-4c3a-ae63-d38452375578\n')
  paths=['lease','canonical-lease','intent','canonical-intent','fence','quarantine','quarantine/captured-original-lease.json','quarantine/held-original-snapshot.json']
  lease=root/'lease';lease.write_bytes(b'nonsecret-original-lease');lease.chmod(0o600)
  python=b'/usr/bin/python3\0-I\0-B\0-c\0source-fixed-test-programme\0';sudo=b'/usr/bin/sudo\0-S\0-p\0\0--\0'+python
  binding={'expectedRootArgvBase64':base64.b64encode(python).decode(),'expectedSudoArgvBase64':base64.b64encode(sudo).decode()}
  n={'ROOT':root,'COMPONENT_BUNDLE':bundle,'BASELINE_BASE64':base64,'os':os,'stat':stat,'re':__import__('re'),'hashlib':hashlib,'json':json,'COMPONENT_RETIRE_OBSERVATIONS':[],'component_retirement_record_raw':lambda row:None}
  tree=ast.parse(fixture.EFFECT_PLANE_CLAIM_SOURCE);count=0
  for node in ast.walk(tree):
   if isinstance(node,ast.Tuple)and len(node.elts)==2 and all(isinstance(v,ast.Constant)for v in node.elts)and [v.value for v in node.elts]==[0,1000]:node.elts.extend([ast.Constant(os.getuid()),ast.Constant(os.getgid())]);count+=1
  self.assertEqual(count,4);ast.fix_missing_locations(tree);exec(compile(tree,'<actual-claim-reader-host-principal-seam>','exec'),n)
  b={'ROOT':root,'COMPONENT_BUNDLE':bundle,'os':os,'stat':stat,'claim_record':n['claim_record'],'BOUNDARY_PATHS':paths,'BOUNDARY_PASSES':[],'BOUNDARY_CURRENT':None}
  exec(fixture.EFFECT_PLANE_BOUNDARY_SOURCE,b);prior=copy.deepcopy(b['boundary_pass']())
  n['EFFECT_PLANE_FIXED']={'processSource':fixture.EFFECT_PLANE_PROCESS_SOURCE,'validatorSource':fixture.EFFECT_PLANE_PROJECTOR_SOURCE,'boundarySource':fixture.EFFECT_PLANE_BOUNDARY_SOURCE,'binding':binding,'paths':paths,'priorPass':prior}
  source=fixture.EFFECT_PLANE_NATIVE_GUARD_SOURCE;self.assertEqual(source.count("ROOT.__class__('/proc')"),1);source=source.replace("ROOT.__class__('/proc')",'ROOT.__class__('+repr(str(proc))+')')
  exec(compile(source,'<actual-native-gate-proc-location-seam>','exec'),n)
  return n,proc,lease,python
 def test_real_source_reader_two_interval_positive_without_historical_identity(self):
  n,proc,lease,python=self.make_plane();record=n['component_release_effect_plane_current_guard']()
  self.assertEqual(record['passes'][0],record['passes'][1]);self.assertEqual([r['state']for r in record['passes'][0]],['present','absent','absent','absent','absent','absent','parent-absent','parent-absent']);self.assertTrue(all(p['censusComplete']and not p['matches']for p in record['workerPasses']))
  self.assertEqual(n['COMPONENT_RETIRE_OBSERVATIONS'],[record]);self.assertEqual(lease.read_bytes(),b'nonsecret-original-lease')
 def test_real_source_guard_refuses_changed_lease_without_effect(self):
  n,proc,lease,python=self.make_plane();lease.write_bytes(b'foreign-replacement')
  with self.assertRaisesRegex(ValueError,'effect_plane_footprint_changed'):n['component_release_effect_plane_current_guard']()
  self.assertEqual(lease.read_bytes(),b'foreign-replacement')
 def test_real_source_guard_refuses_original_matching_actor(self):
  n,proc,lease,python=self.make_plane();p=proc/'73';p.mkdir(mode=0o700);(p/'cmdline').write_bytes(python);(p/'status').write_bytes(b'Uid: 0 0 0 0\nGid: 0 0 0 0\n');(p/'stat').write_text('73 (python3) S '+' '.join(['1']+['0']*17+['12345']+['0']*5)+'\n')
  with self.assertRaisesRegex(ValueError,'effect_plane_current_interval_unknown'):n['component_release_effect_plane_current_guard']()
  self.assertEqual(lease.read_bytes(),b'nonsecret-original-lease')

class ReceiverCollectorDiagnosticIngress(unittest.TestCase):
 """Actual finite receiver -> real raw child -> unchanged create-only collect.
 Only transport argv is a harmless Python child forwarding produced wire bytes.
 """
 exercise=ReceiverTimeout.exercise
 composer=FiniteReceiverDiagnostic.composer
 capture=PhaseParserIngress.capture
 def actual_collector(self):
  import os,select,time,math
  self.assertEqual(hashlib.sha256(fixture.COLLECTOR_SOURCE.encode()).hexdigest(),fixture.COLLECTOR_SOURCE_SHA256)
  n={'os':os,'select':select,'time':time,'subprocess':subprocess,'json':json,'hashlib':hashlib,'base64':base64,'math':math,'CHUNK':524288,'STREAM_LIMIT':201326592}
  exec(compile(fixture.TERMINAL_PARSER_SOURCE+'\n'+fixture.COLLECTOR_SOURCE,'<actual-source-bound-collector>','exec',dont_inherit=True),n)
  return n['collect']
 def produced_wire(self):
  self.exercise("import sys,time;sys.stdin.buffer.read();time.sleep(1)",receiver_source=self.composer()(fixture.REMOTE_SOURCE))
  return self.receiver_stdout,self.receiver_stderr
 def state(self,root,out,err):
  code="import base64,sys;sys.stdin.buffer.read();sys.stdout.buffer.write(base64.b64decode(%r));sys.stdout.flush();sys.stderr.buffer.write(base64.b64decode(%r));sys.stderr.flush()"%(base64.b64encode(out).decode(),base64.b64encode(err).decode())
  self.current_corr=str(uuid.uuid4())
  return {'capture':self.capture(root),'argv':[sys.executable,'-I','-B','-c',code],'source':b'nonsecret-fixture-source','request':{'correlationId':self.current_corr}}
 def test_old_actual_receiver_diagnostic_blocks_collect_before_parser(self):
  out,err=self.produced_wire()
  with tempfile.TemporaryDirectory()as temp:
   state=self.state(Path(temp),out,err)
   try:
    with self.assertRaisesRegex(ValueError,'baseline_ssh_stderr_unknown_raw_retained'):self.actual_collector()(state,b'nonsecret-fixture-credential\n')
    path=Path(state['capture'].path)
    self.assertEqual(json.loads((path/'exit.json').read_bytes()),{'returncode':0,'failure':None})
    self.assertEqual(json.loads((path/'stderr-manifest.json').read_bytes())['sha256'],hashlib.sha256(err).hexdigest())
    self.assertFalse((path/'receiver-finite-failure.json').exists())
   finally:state['capture'].close()

 def bound(self,collect,source):
  self.assertEqual(hashlib.sha256(fixture.RECEIVER_COLLECTOR_BINDER_SOURCE.encode()).hexdigest(),fixture.RECEIVER_COLLECTOR_BINDER_SHA256)
  n={'COLLECTOR_SOURCE':fixture.COLLECTOR_SOURCE}
  exec(compile(fixture.RECEIVER_COLLECTOR_BINDER_SOURCE,'<actual-diagnostic-collector-binder>','exec',dont_inherit=True),n)
  return n['bind_receiver_diagnostic_collector'](collect,collect.__globals__.get('parse_terminal')or self.actual_collector().__globals__['parse_terminal'],self.current_corr,source)
 def test_actual_timeout_diagnostic_is_retained_but_never_success(self):
  out,err=self.produced_wire()
  with tempfile.TemporaryDirectory()as temp:
   state=self.state(Path(temp),out,err)
   try:
    original=self.actual_collector();bound=self.bound(original,state['source'])
    with self.assertRaisesRegex(ValueError,'baseline_remote_collection_timeout'):bound(state,b'nonsecret-fixture-credential\n')
    path=Path(state['capture'].path);record=json.loads((path/'receiver-finite-failure.json').read_bytes())
    self.assertEqual(record['diagnostic']['code'],'baseline_remote_collection_timeout');self.assertEqual(record['effectOutcome'],'unknown');self.assertFalse(record['acceptanceComplete']);self.assertFalse(record['replayAllowed']);self.assertFalse(record['closingAuthenticated'])
    self.assertTrue((path/'remote-terminal.json').exists());self.assertTrue((path/'remote-stderr-manifest.json').exists())
   finally:state['capture'].close()
 def test_mixed_private_unknown_type_and_wrong_source_stderr_stay_refused(self):
  out,err=self.produced_wire();prefix=b'VPNCONTROL_COMPONENT_DIAGNOSTIC_V1 ';record=json.loads(err[len(prefix):]);cases=[(out,err+b'PRIVATE-NONFRAME\n'),(out,b'PRIVATE-NONFRAME\n'+err)]
  for field,value in [('schema',True),('type','TypeError'),('code',None),('code','PRIVATE-CODE'),('stage','foreign'),('authorityGranted',True)]:
   changed=dict(record);changed[field]=value;cases.append((out,prefix+json.dumps(changed,sort_keys=True,separators=(',',':')).encode()+b'\n'))
  first,*rest=out.splitlines();header=json.loads(first);header['sourceSha256']='0'*64;cases.append((json.dumps(header).encode()+b'\n'+b'\n'.join(rest)+b'\n',err))
  for wire,stderr in cases:
   with self.subTest(stderrBytes=len(stderr)),tempfile.TemporaryDirectory()as temp:
    state=self.state(Path(temp),wire,stderr)
    try:
     bound=self.bound(self.actual_collector(),state['source'])
     with self.assertRaisesRegex(ValueError,'baseline_ssh_stderr_unknown_raw_retained'):bound(state,b'nonsecret-fixture-credential\n')
     path=Path(state['capture'].path);self.assertTrue((path/'stdout-manifest.json').exists());self.assertTrue((path/'stderr-manifest.json').exists());self.assertFalse((path/'receiver-finite-failure.json').exists())
    finally:state['capture'].close()
 def test_success_empty_stderr_unchanged_and_collector_code_drift_refused(self):
  self.exercise("import sys;sys.stdin.buffer.read();print('COMPLETE-NONSECRET',flush=True)",receiver_source=self.composer()(fixture.REMOTE_SOURCE));out,err=self.receiver_stdout,self.receiver_stderr
  with tempfile.TemporaryDirectory()as temp:
   state=self.state(Path(temp),out,err)
   try:self.assertEqual(self.bound(self.actual_collector(),state['source'])(state,b'nonsecret-fixture-credential\n'),out)
   finally:state['capture'].close()
  def foreign(state,credential):return b''
  with self.assertRaisesRegex(ValueError,'carrier_receiver_collector_source_changed'):self.bound(foreign,b'nonsecret-fixture-source')


class CarrierIntentBoundary(unittest.TestCase):
 """Actual source writer→reader; explicit host UID/GID→root metadata seam."""
 def produced(self,reader):
  import io,time,os,stat,types
  from unittest import mock
  from agent_tools import android_installer_component_bundle as b
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name).resolve();root.chmod(0o700)
  proxy=types.SimpleNamespace(**{name:getattr(os,name)for name in dir(os)if not name.startswith('__')})
  class Principal:
   def __init__(self,value):self.value=value
   def __getattr__(self,name):return 0 if name in('st_uid','st_gid')else getattr(self.value,name)
  for name in('stat','fstat','lstat'):
   fn=getattr(os,name);setattr(proxy,name,lambda *args,_fn=fn,**kwargs:Principal(_fn(*args,**kwargs)))
  bundle=types.SimpleNamespace(**{name:getattr(b,name)for name in dir(b)if not name.startswith('__')})
  def parents(path):
   with mock.patch.object(b,'os',proxy):return b._parents(path)
  bundle._parents=parents
  corr=str(uuid.uuid4());name='android-component-carrier-raw-'+corr
  n={'ROOT':root,'CARRIER_TARGET':name,'CARRIER_PASSES':[],'COMPONENT_BUNDLE':bundle,'os':proxy,'stat':stat,'re':__import__('re'),'hashlib':hashlib,'BASELINE_BASE64':base64,'json':json,'io':io,'time':time,'CARRIER_RAW_ROOT':str(root),'CARRIER_RAW_CORRELATION':corr,'CARRIER_RAW_NAME':name,'EXPECTED_SHA':hashlib.sha256(b'nonsecret-programme').hexdigest(),'EXPECTED_BYTES':len(b'nonsecret-programme'),'CARRIER_PHASES':('entry',)}
  composer={};exec(compile(fixture.FINITE_DIAGNOSTIC_COMPOSER_SOURCE,'<actual-durable-writer-origin>','exec',dont_inherit=True),composer)
  exec(compile(composer['DURABLE_OUTPUT_SOURCE'],'<actual-durable-writer>','exec',dont_inherit=True),n)
  n['CARRIER_EXPECTED_INTENT']={'schema':1,'kind':'component-carrier-raw-observation','correlationId':corr,'sourceSha256':n['EXPECTED_SHA'],'sourceBytes':n['EXPECTED_BYTES'],'authorityGranted':False}
  writer=n['CarrierDurableOutput']();writer.raw_record('record',b'NONSECRET-RAW-RECORD')
  self.addCleanup(writer.close)
  exec(compile(reader,'<actual-observer-carrier-reader>','exec',dont_inherit=True),n)
  return n,root/name
 def test_actual_writer_intent_rejected_by_old_reader(self):
  n,folder=self.produced(fixture.CARRIER_READER_RED_SOURCE)
  self.assertEqual(sorted(p.name for p in folder.iterdir()),['chunk-00000.json','chunk-00000.raw','intent.json'])
  with self.assertRaisesRegex(ValueError,'carrier_observation_inventory_unsafe'):n['carrier_pass']()
  self.assertEqual((folder/'chunk-00000.raw').read_bytes(),b'NONSECRET-RAW-RECORD');self.assertEqual(n['CARRIER_PASSES'][0]['state'],'unknown')

 def test_actual_writer_fixed_reader_and_projector_accept_exact_intent(self):
  n,folder=self.produced(fixture.CARRIER_READER_FIXED_SOURCE);n['carrier_pass']();row=n['CARRIER_PASSES'][0]
  self.assertEqual(row['state'],'present');self.assertTrue(row['closingStable']);self.assertEqual([x['name']for x in row['files']],['chunk-00000.json','chunk-00000.raw','intent.json'])
  native='/home/kardinal/.vpn-control-mcp-fixtures';mapped=copy.deepcopy(row);mapped['path']=native+'/'+folder.name
  outer=sorted(row['parents'],key=lambda x:len(Path(x).parts));mapped['parents']={name:row['parents'][key]for name,key in zip(['/','/home','/home/kardinal',native],outer[-4:])}
  n.update(CARRIER_NAME=folder.name,re=__import__('re'),base64=base64);exec(compile(fixture.CARRIER_PROJECTOR_FIXED_SOURCE,'<actual-carrier-projector>','exec',dont_inherit=True),n)
  self.assertEqual(n['validate_carrier']([mapped]),[{'state':'present','files':3,'closingStable':True}])
  intent=next(x for x in mapped['files']if x['name']=='intent.json');bad=copy.deepcopy(mapped);item=next(x for x in bad['files']if x['name']=='intent.json');value=json.loads(base64.b64decode(item['rawBase64']));value['authorityGranted']=0;raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();item.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),rawBase64=base64.b64encode(raw).decode());item['generation'][6]=len(raw)
  with self.assertRaisesRegex(ValueError,'current_carrier_intent_changed'):n['validate_carrier']([bad])
 def test_actual_writer_fixed_reader_refuses_intent_drift_and_foreign_entry(self):
  for field,value in [('authorityGranted',0),('sourceBytes',False),('sourceSha256','0'*64),('correlationId',str(uuid.uuid4()))]:
   with self.subTest(field=field):
    n,folder=self.produced(fixture.CARRIER_READER_FIXED_SOURCE);path=folder/'intent.json';data=json.loads(path.read_bytes());data[field]=value;path.write_bytes(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
    with self.assertRaisesRegex(ValueError,'carrier_observation_intent_changed'):n['carrier_pass']()
    self.assertEqual(n['CARRIER_PASSES'][0]['state'],'unknown');self.assertTrue(path.exists())
  n,folder=self.produced(fixture.CARRIER_READER_FIXED_SOURCE);(folder/'foreign.json').write_bytes(b'FOREIGN-RETAINED')
  with self.assertRaisesRegex(ValueError,'carrier_observation_inventory_unsafe'):n['carrier_pass']()
  self.assertEqual((folder/'foreign.json').read_bytes(),b'FOREIGN-RETAINED')

 def test_actual_stable_reader_intervals_unknown_or_drift_stay_incomplete(self):
  n,folder=self.produced(fixture.CARRIER_READER_FIXED_SOURCE);n['carrier_pass']();n['carrier_pass']()
  exec(compile(fixture.CARRIER_INTERVAL_STABILITY_SOURCE,'<actual-interval-stability>','exec',dont_inherit=True),n)
  rows=n['CARRIER_PASSES'];self.assertTrue(n['carrier_intervals_stable'](rows))
  for field,value in [('state','unknown'),('closingStable',False)]:
   mutant=copy.deepcopy(rows);mutant[0][field]=value;self.assertFalse(n['carrier_intervals_stable'](mutant))
  mutant=copy.deepcopy(rows);mutant[1]['files'][0]['sha256']='0'*64;self.assertFalse(n['carrier_intervals_stable'](mutant));self.assertFalse(n['carrier_intervals_stable'](rows[:1]))


class LateArrivalWorkerBoundary(unittest.TestCase):
 """Actual emitted functions/real FD reads; Linux proc bytes on host TempFS.
 A real harmless child arrives at closing listing; its Linux stat/status shape
 is an explicit portability seam, not measured native birth or authority.
 """
 def produced(self,source,mode='foreign'):
  import os,stat,types,shutil
  from agent_tools import android_installer_component_bundle as b
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name).resolve()
  boot=root/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_bytes(b'25515f23-b966-4c3a-ae63-d38452375578\n')
  child=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(.1)'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.addCleanup(lambda:child.communicate(timeout=3));pid=child.pid;command=b'\0'.join(x.encode()for x in child.args)+b'\0'
  fields=[str(os.getpid())]+['0']*17+['17']+['0']*4
  def materialize(selected=pid):
   folder=root/str(selected);folder.mkdir();(folder/'cmdline').write_bytes(command);(folder/'stat').write_bytes((str(selected)+' (harmless) S '+' '.join(fields)+'\n').encode());(folder/'status').write_bytes(('Name: harmless\nUid: '+(' '.join([str(os.getuid())]*4))+'\nGid: '+(' '.join([str(os.getgid())]*4))+'\n').encode())
  proxy=types.SimpleNamespace(**{name:getattr(os,name)for name in dir(os)if not name.startswith('__')});calls=0;spawned=[pid];reappeared=False;stat_opens=0
  def listing(path):
   nonlocal calls
   calls+=1
   if calls==1:return ['sys']
   if calls==2:
    if mode=='over-cap':return [str(pid+i)for i in range(33)]
    materialize();return ['sys',str(pid)]
   if mode=='churn'and calls in(3,4):
    extra=subprocess.Popen(child.args,stdout=subprocess.PIPE,stderr=subprocess.PIPE);self.addCleanup(lambda child=extra:child.communicate(timeout=3));spawned.append(extra.pid);materialize(extra.pid)
   if mode=='reappeared'and calls==3:materialize()
   return ['sys']if mode=='vanished'else ['sys',*map(str,spawned)]
  proxy.listdir=listing
  real_open=os.open
  def opening(path,*args,**kwargs):
   nonlocal reappeared,stat_opens
   if mode=='birth-drift'and Path(path).parent.name==str(pid)and Path(path).name=='stat':
    stat_opens+=1
    if stat_opens==3:
     changed=list(fields);changed[18]='18';Path(path).write_bytes((str(pid)+' (harmless) S '+' '.join(changed)+'\n').encode())
   if Path(path).parent.name==str(pid)and Path(path).name=='cmdline':
    if mode=='reappeared'and not reappeared:reappeared=True;shutil.rmtree(root/str(pid));raise FileNotFoundError(2,'inert fixture')
    if mode=='permission':raise PermissionError(13,'inert fixture')
    if mode=='vanished':child.communicate(timeout=3);shutil.rmtree(root/str(pid));raise FileNotFoundError(2,'inert fixture')
   return real_open(path,*args,**kwargs)
  proxy.open=opening
  binding={'expectedRootArgvBase64':base64.b64encode(command if mode=='matching'else b'/fixed-original-python\0').decode(),'expectedSudoArgvBase64':base64.b64encode(b'/fixed-original-sudo\0').decode()}
  n={'PROC_ROOT':root,'COMPONENT_BUNDLE':b,'os':proxy,'stat':stat,'re':__import__('re'),'hashlib':hashlib,'STAGE_BASE64':base64,'ATTEMPT_BINDING':binding,'ATTEMPT_PROC_RAW':[]}
  exec(compile(source,'<actual-source-worker-census>','exec',dont_inherit=True),n);self.last_worker_namespace=n;scan=n['attempt_workers']();return n,scan,pid
 def test_actual_old_new_closing_pid_is_incomplete_red(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_OLD_PROCESS_SOURCE)
  self.assertEqual(row['newPids'],[pid]);self.assertFalse(row['censusComplete']);self.assertEqual(row['readCount'],0)
 def test_actual_bounded_source_reads_and_identifies_late_child(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE)
  self.assertTrue(row['censusComplete']);self.assertEqual(row['newPids'],[pid]);self.assertEqual(row['lateRounds'],[[pid]]);self.assertEqual(row['lateReadCount'],1);self.assertEqual(row['unresolvedNewPids'],[])
  identity=row['lateIdentities'][0];self.assertEqual(identity['pid'],pid);self.assertEqual(identity['startTicks'],17);self.assertEqual(identity['ppid'],__import__('os').getpid());self.assertIsNone(identity['role']);self.assertEqual(len(n['ATTEMPT_PROC_RAW']),14)
 def test_actual_matching_late_child_is_preserved_as_match(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,'matching');self.assertTrue(row['censusComplete']);self.assertEqual(row['matches'][0]['pid'],pid);self.assertEqual(row['matches'][0]['role'],'python')
 def test_actual_permission_and_over_cap_stay_incomplete(self):
  for mode in('permission','over-cap'):
   with self.subTest(mode=mode):
    n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,mode);self.assertFalse(row['censusComplete']);self.assertEqual(row['lateIdentities'],[])
 def test_actual_disappeared_late_child_retains_positive_errno(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,'vanished');self.assertTrue(row['censusComplete']);self.assertEqual(row['resolved'],[{'pid':pid,'errno':2,'closingErrno':2,'state':'rechecked-absent'}]);self.assertEqual(row['lateIdentities'],[])

 def projector(self,n):
  import stat,ast
  from agent_tools import android_installer_component_bundle as b
  scope=dict(n,bundle=b,base64=base64,ast=ast,stat=stat,PROCESS_SOURCE=fixture.LATE_WORKER_PROCESS_SOURCE)
  exec(compile(fixture.LATE_WORKER_PROJECTOR_SOURCE,'<actual-bounded-source-projector>','exec',dont_inherit=True),scope)
  return scope['validate_workers']
 def test_actual_producer_projector_positive_absent_present_unknown(self):
  for mode,count,complete in [('foreign',0,True),('matching',1,True),('permission',0,False),('over-cap',0,False),('vanished',0,True)]:
   with self.subTest(mode=mode):
    n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,mode);counts=self.projector(n)(n['ATTEMPT_PROC_RAW'],[row],n['ATTEMPT_BINDING']);self.assertEqual(counts,[{'python':count,'sudo':0}]);self.assertIs(row['censusComplete'],complete)
 def test_actual_producer_projector_rejects_coverage_identity_round_type_drift(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE);project=self.projector(n)
  mutants=[]
  for field,value in [('lateReadCount',False),('lateRounds',[]),('unresolvedNewPids',[pid]),('censusComplete',False)]:
   q=copy.deepcopy(row);q[field]=value;mutants.append(q)
  q=copy.deepcopy(row);q['lateIdentities'][0]['startTicks']=18;mutants.append(q)
  q=copy.deepcopy(row);q['lateClosingIdentities']=[];mutants.append(q)
  for mutant in mutants:
   with self.assertRaises(ValueError):project(n['ATTEMPT_PROC_RAW'],[mutant],n['ATTEMPT_BINDING'])

 def test_actual_two_round_limit_preserves_unobserved_newer_pid(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,'churn');self.assertEqual(len(row['lateRounds']),2);self.assertEqual(len(row['unresolvedNewPids']),1);self.assertFalse(row['censusComplete']);self.assertEqual(self.projector(n)(n['ATTEMPT_PROC_RAW'],[row],n['ATTEMPT_BINDING']),[{'python':0,'sudo':0}])
 def test_actual_late_birth_change_refuses_before_complete_output(self):
  with self.assertRaisesRegex(ValueError,'plane_late_identity_changed'):self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,'birth-drift')
  self.assertGreaterEqual(len(self.last_worker_namespace['ATTEMPT_PROC_RAW']),13)
 def test_actual_late_reappeared_pid_is_not_reused(self):
  n,row,pid=self.produced(fixture.LATE_WORKER_PROCESS_SOURCE,'reappeared');self.assertEqual(row['reappearedPids'],[pid]);self.assertFalse(row['censusComplete']);self.assertEqual(row['lateIdentities'],[]);self.assertEqual(self.projector(n)(n['ATTEMPT_PROC_RAW'],[row],n['ATTEMPT_BINDING']),[{'python':0,'sudo':0}])


class CurrentRetirementEffectPlaneGate(OriginalEffectPlaneGate):
 """Production-emitted gate uses the separately bound exact attempt matcher.
 TempFS/host principal seams are inherited; argv are explicit inert test data.
 Actual native1e15/9da argv causal replay remains separate retained evidence.
 """
 def make_current_plane(self):
  n,proc,lease,old_python=self.make_plane()
  source=fixture.CURRENT_RETIREMENT_GATE_SOURCE
  self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),fixture.CURRENT_RETIREMENT_GATE_SOURCE_SHA256)
  source=source.replace("ROOT.__class__('/proc')",'ROOT.__class__('+repr(str(proc))+')')
  fixed=copy.deepcopy(n['EFFECT_PLANE_FIXED']);python=b'/usr/bin/python3\0-I\0-B\0-c\0source-fixed-later-test-programme\0'
  fixed['binding']={'expectedRootArgvBase64':base64.b64encode(python).decode(),'expectedSudoArgvBase64':base64.b64encode(b'/usr/bin/sudo\0-S\0-p\0\0--\0'+python).decode()}
  fixed.update(processSource=fixture.LATE_WORKER_PROCESS_SOURCE,validatorSource=fixture.LATE_WORKER_PROJECTOR_SOURCE)
  n['CURRENT1E15_EFFECT_PLANE_FIXED']=fixed;exec(compile(source,'<actual-emitted-current-retirement-gate-proc-seam>','exec',dont_inherit=True),n)
  return n,proc,lease,python
 def test_prior_matcher_does_not_admit_later_attempt_actor(self):
  n,proc,lease,python=self.make_current_plane();p=proc/'73';p.mkdir(mode=0o700)
  (p/'cmdline').write_bytes(python);(p/'status').write_bytes(b'Uid: 0 0 0 0\nGid: 0 0 0 0\n');(p/'stat').write_text('73 (python3) S '+' '.join(['1']+['0']*17+['12345']+['0']*5)+'\n')
  old=n['component_release_effect_plane_current_guard']();self.assertTrue(all(not row['matches']for row in old['workerPasses']))
  with self.assertRaisesRegex(ValueError,'effect_plane_current_interval_unknown'):n['component_release_current1e15_effect_plane_guard']()
  self.assertEqual(lease.read_bytes(),b'nonsecret-original-lease')
 def test_later_actual_reader_projector_complete_and_lease_drift(self):
  n,proc,lease,python=self.make_current_plane();row=n['component_release_current1e15_effect_plane_guard']();self.assertTrue(all(scan['censusComplete']for scan in row['workerPasses']))
  self.assertEqual(row['kind'],'original1e15-current-effect-plane');self.assertEqual(row['binding'],n['CURRENT1E15_EFFECT_PLANE_FIXED']['binding'])
  lease.write_bytes(b'foreign-retained-data')
  with self.assertRaisesRegex(ValueError,'effect_plane_footprint_changed'):n['component_release_current1e15_effect_plane_guard']()


class ReceiverModuleContextDiagnosticIngress(ReceiverCollectorDiagnosticIngress):
 """Actual module compile context, canonical failure stays typed UNKNOWN.
 The imported module declarations are authenticated source fixture bytes only.
 """
 def actual_collector(self):
  original=super().actual_collector();n=dict(original.__globals__)
  exec(compile(fixture.COLLECTOR_IMPORT_SOURCE+fixture.TERMINAL_PARSER_SOURCE+'\n'+fixture.COLLECTOR_SOURCE,'<actual-module-context-collector>','exec',dont_inherit=True),n)
  return n['collect']
 def bound(self,collect,source):
  self.assertEqual(hashlib.sha256(fixture.SOURCE_CONTEXT_RECEIVER_BINDER_SOURCE.encode()).hexdigest(),fixture.SOURCE_CONTEXT_RECEIVER_BINDER_SHA256)
  n={'COLLECTOR_SOURCE':fixture.COLLECTOR_SOURCE,'COLLECTOR_IMPORT_SOURCE':fixture.COLLECTOR_IMPORT_SOURCE}
  exec(compile(fixture.SOURCE_CONTEXT_RECEIVER_BINDER_SOURCE,'<actual-module-context-binder>','exec',dont_inherit=True),n)
  return n['bind_receiver_diagnostic_collector'](collect,collect.__globals__.get('parse_terminal')or self.actual_collector().__globals__['parse_terminal'],self.current_corr,source)
 def test_old_standalone_authentication_rejects_real_module_code(self):
  self.current_corr=str(uuid.uuid4())
  with self.assertRaisesRegex(ValueError,'carrier_receiver_collector_source_changed'):
   ReceiverCollectorDiagnosticIngress.bound(self,self.actual_collector(),b'nonsecret-fixture-source')
 def test_changed_real_collector_body_still_refuses(self):
  self.current_corr=str(uuid.uuid4());original=self.actual_collector();n=dict(original.__globals__)
  changed=fixture.COLLECTOR_SOURCE.replace('deadline=time.monotonic()+1250','deadline=time.monotonic()+1251')
  exec(compile(fixture.COLLECTOR_IMPORT_SOURCE+changed,'<mutated-deadline-refusal>','exec',dont_inherit=True),n)
  with self.assertRaisesRegex(ValueError,'carrier_receiver_collector_source_changed'):self.bound(n['collect'],b'nonsecret-fixture-source')

class RoutingActorClosingPopulation(unittest.TestCase):
 """Actual emitted producer/projector, real TempFS proc files, no native calls.

 Seams are fixed fixture argv/archive bindings, root metadata projection and
 listdir populations. The tested process readers and guards are exact source
 snapshots. This proves current census typing only, never native authority.
 """
 def produce(self,old=False,reappear=True,disappear=False):
  import os,re,stat,time,types
  from unittest import mock
  from agent_tools import android_installer_component_bundle as bundle
  for name in ('READERS','KERNEL','ACTORS_OLD','ACTORS_FIXED','PROJECTOR_OLD','PROJECTOR_FIXED','ROLE_NAMES'):
   value=getattr(fixture,'ROUTING_POPULATION_'+name)
   self.assertEqual(hashlib.sha256(repr(value).encode()).hexdigest(),getattr(fixture,'ROUTING_POPULATION_'+name+'_SHA256'))
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();proc=root/'proc';(proc/'sys/kernel/random').mkdir(parents=True);(proc/'sys/kernel/random/boot_id').write_text('00000000-0000-4000-8000-000000000001\n');directory=root/'metadata';directory.mkdir()
  expected={role:base64.b64encode(('/fixture/'+role+'\0').encode()).decode()for role in ('1e15-python','1e15-sudo','7310-python','7310-sudo')}
  for pid,ppid,cmd in ((73,1,base64.b64decode(expected['7310-python'])),(74,73,b'/usr/bin/true\0')):
   folder=proc/str(pid);folder.mkdir();(folder/'cmdline').write_bytes(cmd);(folder/'status').write_bytes(b'Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n');(folder/'stat').write_text(str(pid)+' (fixture) S '+str(ppid)+' '+' '.join(['0']*17)+' 9901\n')
  model=types.SimpleNamespace(**vars(os))
  def projected(info):return types.SimpleNamespace(**{**{k:getattr(info,k)for k in dir(info)if k.startswith('st_')},'st_uid':0,'st_gid':0})
  model.stat=lambda *a,**k:projected(os.stat(*a,**k));model.fstat=lambda fd:projected(os.fstat(fd));model.getuid=lambda:0
  bs=dict(vars(bundle),os=model);clone=types.SimpleNamespace(**vars(bundle))
  for name in ('_pin','_parents','_close','_read','_directory'):bs[name]=types.FunctionType(getattr(bundle,name).__code__,bs,argdefs=getattr(bundle,name).__defaults__)
  for name in ('_pin','_parents','_close','_read','_directory'):setattr(clone,name,bs[name])
  readers=fixture.ROUTING_POPULATION_READERS
  n=dict(os=model,stat=stat,time=time,re=re,hashlib=hashlib,json=json,Path=Path,PROC_ROOT=proc,STAGE_BASE64=base64,ATTEMPT_BINDING=expected,EXPECTED_EFFECT_ARGV=expected,COMPONENT_BUNDLE=clone,ATTEMPT_PROC_RAW=[],ROUTING_CORRELATION='00000000-0000-4000-8000-000000000002',ROUTING_ROLE_ROOT=str(directory),ROUTING_ROLE_NAMES=fixture.ROUTING_POPULATION_ROLE_NAMES,METADATA_EXPECTED_OWNER='fixture')
  actor=fixture.ROUTING_POPULATION_ACTORS_OLD if old else fixture.ROUTING_POPULATION_ACTORS_FIXED
  exec(compile(readers+'\n'+fixture.ROUTING_POPULATION_KERNEL+'\n'+actor,'<authenticated-routing-census-snapshot>','exec',dont_inherit=True),n)
  rows=n['routing_metadata_pass']();calls=0
  def population(path):
   nonlocal calls
   result=os.listdir(path)
   if Path(path)==proc:
    calls+=1
    if disappear and calls==3:
     folder=proc/'74'
     for p in folder.iterdir():p.unlink()
     folder.rmdir();return [p for p in result if p!='74']
    if reappear and calls==3:return [p for p in result if p!='74']
    if reappear and calls==4:
     p=proc/'74/stat';p.write_bytes(p.read_bytes().replace(b'9901',b'9902'))
   return result
  with mock.patch.object(model,'listdir',population):one=n['routing_actor_pass']();two=n['routing_actor_pass']()
  request={'correlationId':'00000000-0000-4000-8000-000000000003'};proof={'fixtureArchive':True}
  document={'schema':1,'kind':'original-routing-metadata-readonly','correlationId':request['correlationId'],'attemptSources':proof,'routingCorrelationId':n['ROUTING_CORRELATION'],'physicalClosingEqual':True,'metadata':[rows,n['routing_metadata_pass']()],'actors':[one,two],'procRaw':n['ATTEMPT_PROC_RAW'],**{k:False for k in ('nativeEffectsGranted','claimGranted','releaseGranted','captureGranted','currentOwnerAdmitted','runtimeOffAdmitted','acceptanceComplete')}}
  scope=dict(ast=ast,base64=base64,hashlib=hashlib,json=json,Path=Path,bundle=clone,ROLE_ROOT=str(directory),ROLE_NAMES=fixture.ROUTING_POPULATION_ROLE_NAMES,ROUTE=n['ROUTING_CORRELATION'],readers=lambda inputs:readers)
  code=fixture.ROUTING_POPULATION_PROJECTOR_OLD if old else fixture.ROUTING_POPULATION_PROJECTOR_FIXED
  exec(compile(code,'<authenticated-routing-census-projector>','exec',dont_inherit=True),scope)
  return document,lambda doc:scope['validate_document'](doc,request,expected,proof)
 def test_retained_old_false_complete_red_then_fixed_unknown(self):
  old,project=self.produce(old=True)
  self.assertTrue(project(old)['actors'][0]['censusComplete']);self.assertEqual(old['actors'][0]['reappearedPids'],[])
  fixed,project=self.produce()
  self.assertEqual(fixed['actors'][0]['reappearedPids'],[74]);self.assertFalse(project(fixed)['actors'][0]['censusComplete'])
  self.assertEqual(fixed['actors'][0]['identities'][1]['startTicks'],9901);self.assertEqual(fixed['actors'][1]['identities'][1]['startTicks'],9902)
  self.assertFalse(project(fixed)['captureGranted'])
 def test_forged_old_complete_relation_refuses(self):
  fixed,project=self.produce();fixed['actors'][0]['reappearedPids']=[];fixed['actors'][0]['censusComplete']=True
  with self.assertRaisesRegex(ValueError,'routing_actor_complete_unknown'):project(fixed)
 def test_actual_closing_disappearance_conservative_projection_refusal(self):
  # Retained producer-positive/consumer-refusal: one surviving PID creates an
  # overlapping third six-record candidate. No production relaxation here.
  doc,project=self.produce(reappear=False,disappear=True)
  self.assertEqual(doc['actors'][0]['identityClosingPids'],[73]);self.assertEqual(doc['actors'][0]['closingPids'],[73]);self.assertTrue(doc['actors'][0]['censusComplete'])
  with self.assertRaisesRegex(ValueError,'routing_actor_identity_unknown'):project(doc)
 def test_actual_stable_population_positive(self):
  doc,project=self.produce(reappear=False)
  self.assertTrue(project(doc)['actors'][0]['censusComplete']);self.assertFalse(project(doc)['captureGranted'])
