"""Routine causal checks for source-owned Mac diagnostic evidence.

These fixtures contain complete authored public programs, never captured target
paths or native receipts. Native framework/VM acceptance is separate: controlled
checks use real local FDs, links and callbacks with explicit ownership/BSD seams.
"""
from pathlib import Path
import ast,hashlib,json,os,stat,subprocess,sys,tempfile,types,unittest
from agent_tools import private_inventory_lock as private
BASE=Path(__file__).parent/'fixtures/macos_diagnostic_retention'
NEW=BASE/'driver.current.source'
BEFORE=BASE/'driver.before.source'
def load(path):
 raw=path.read_bytes();module=types.ModuleType('_retention_'+path.stem);module.__file__=str(path)
 exec(compile(raw,str(path),'exec'),module.__dict__);return module,ast.parse(raw)
def root_block(tree):return next(node for node in ast.walk(tree)if isinstance(node,ast.FunctionDef)and node.name=='root_probe')
def catalog_block(tree):
 context=next(node for node in ast.walk(tree)if isinstance(node,ast.With)and 'backend.guest_job_executor' in ast.unparse(node.items[0].context_expr))
 start=next(i for i,node in enumerate(context.body)if isinstance(node,ast.Expr)and isinstance(node.value,ast.Call)and node.value.func.id=='record'and isinstance(node.value.args[0],ast.Constant)and node.value.args[0].value=='source-capsule-before.json')+1
 stop=next(i for i,node in enumerate(context.body)if isinstance(node,ast.Assign)and any(isinstance(target,ast.Name)and target.id=='after'for target in node.targets))
 return context.body[start:stop]
@unittest.skipUnless(os.name=='posix','requires actual POSIX FD custody')
class RetentionTests(unittest.TestCase):
 def test_whole_original_guard_drift_drops_callback_red_new_retains_actual_bytes_green(self):
  self.assertEqual('35b8639a19323755641bb6ffc8436015cc7b410fe35c02438c2a19ee00227676',hashlib.sha256(BEFORE.read_bytes()).hexdigest())
  for producer in (BEFORE,NEW):
   for label in ('root-before','root-after','catalog'):
    with self.subTest(producer=producer.name,label=label),tempfile.TemporaryDirectory()as name:
     root=Path(name).resolve();output=root/'output';output.mkdir(mode=0o700)
     selected=root/'held-source.py';selected.write_bytes(b'x=1\n');selected.chmod(0o600)
     module,tree=load(producer)
     with private.Directory(root)as parent,private.Snapshot(parent,selected.name)as source,private.Directory(output)as out:
      def guard():source.guard();out.guard()
      def record(name,value):
       guard();data=value if isinstance(value,bytes)else json.dumps(value).encode()
       if producer==NEW:module.output_record(out,name,data,1048576)
       else:
        with(output/name).open('xb')as f:f.write(data)
       guard()
      class Executor:
       def execute(self,argv,*,payload):
        # Real callback process. The caller's own held source changes
        # only after actual stdout/stderr/returncode have returned from it.
        result=subprocess.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(b"PUBLIC-STDOUT");sys.stderr.buffer.write(b"PUBLIC-STDERR");raise SystemExit(7)'],capture_output=True,timeout=5)
        selected.write_bytes(b'x=2\n');return result
      namespace=dict(module.__dict__);namespace.update(out=out,guard=guard,record=record,executor=Executor(),
       protocol=types.SimpleNamespace(stdin_command=lambda value:(('python','-c','FIXED-GATE'),value.encode())),
       source=b'print("FIXED-GET")\n',
       backend=types.SimpleNamespace(binding=None,custody=types.SimpleNamespace(guest_proof={'prefix':'PUBLIC','publicFiles':{}})),
       mac_registry=types.SimpleNamespace(guest_probe_source=lambda *a,**k:b'print("FIXED-GET")\n'))
      if label=='catalog':body=catalog_block(tree)
      else:body=[root_block(tree)]
      code=compile(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])),str(producer),'exec')
      with self.assertRaises(ValueError):
       exec(code,namespace)
       if label!='catalog':namespace['root_probe'](label)
      if producer==BEFORE:
       self.assertFalse((output/(label+'.stdout.json')).exists())
       self.assertFalse((output/(label+'.stderr.txt')).exists())
      else:
       self.assertEqual(b'PUBLIC-STDOUT',(output/(label+'.stdout.json')).read_bytes())
       self.assertEqual(b'PUBLIC-STDERR',(output/(label+'.stderr.txt')).read_bytes())
       receipt=json.loads((output/(label+'.callback.json')).read_bytes())
       self.assertEqual(7,receipt['returncode']);self.assertTrue(receipt['completeRaw'])
       self.assertEqual('pending',receipt['sourceValidation']);self.assertEqual('pending',receipt['semanticValidation'])
       self.assertEqual(b'print("FIXED-GET")\n',(output/(label+'.request.stdin')).read_bytes())
       self.assertEqual(['python','-c','FIXED-GATE'],json.loads((output/(label+'.request.argv.json')).read_bytes()))
       self.assertEqual(module.VM,json.loads((output/(label+'.request-context.json')).read_bytes())['vmName'])
       self.assertFalse((output/'source-capsule-closed.json').exists())
 def test_raw_record_checks_only_output_custody_and_rejects_output_parent_replacement(self):
  module,_=load(NEW)
  with tempfile.TemporaryDirectory()as name:
   root=Path(name).resolve();output=root/'output';output.mkdir(mode=0o700)
   with private.Directory(output)as out:
    module.output_record(out,'actual.stdout',b'PUBLIC',10)
    self.assertEqual(b'PUBLIC',(output/'actual.stdout').read_bytes())
    with self.assertRaises(FileExistsError):module.output_record(out,'actual.stdout',b'REPLACEMENT',20)
    output.rename(root/'original');output.mkdir(mode=0o700)
    with self.assertRaises(ValueError):module.output_record(out,'wrong.stdout',b'PUBLIC',10)
    self.assertFalse((output/'wrong.stdout').exists())
 def test_raw_callback_overflow_is_retained_and_explicit_never_complete(self):
  module,_=load(NEW)
  with tempfile.TemporaryDirectory()as name:
   root=Path(name).resolve()
   with private.Directory(root)as out:
    result=types.SimpleNamespace(stdout=b'P'*(8*1024*1024+1),stderr=b'PUBLIC-ERR',returncode=9)
    with self.assertRaisesRegex(RuntimeError,'catalog_raw_retention_overflow'):module.callback_record(out,'catalog',result)
   receipt=json.loads((root/'catalog.callback.json').read_bytes())
   self.assertFalse(receipt['completeRaw']);self.assertEqual(9,receipt['returncode'])
   self.assertEqual(8*1024*1024,(root/'catalog.stdout.json').stat().st_size)
   self.assertEqual(b'PUBLIC-ERR',(root/'catalog.stderr.txt').read_bytes())


import ctypes as C
from contextlib import ExitStack
from unittest.mock import patch
from agent_tools import tart_macos_probe as probe
from agent_tools import tart_macos_service_census as service

def component_load(path):
 raw=path.read_bytes();module=types.ModuleType('_failure_'+path.parent.name);module.__file__=str(path)
 exec(compile(raw,str(path),'exec'),module.__dict__);return module,raw
@unittest.skipUnless(os.name=='posix','requires actual POSIX links and metadata getters')
class FailureTests(unittest.TestCase):
 def test_complete_whole_649_drops_first_component_context_red_new_retains_bounded_private_metadata_green(self):
  self.assertEqual('649fb4858cc243cfaa6523976a968cc8dff69e11c65a493d0e6f7648677c4562',hashlib.sha256((BASE/'component.before.source').read_bytes()).hexdigest())
  for original in (True,False):
   module,_=component_load(BASE/'component.before.source'if original else BASE/'component.current.source')
   for failure in ('owner','mode','type'):
    with self.subTest(original=original,failure=failure),ExitStack()as stack:
     root=Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
     blocked=root/'PRIVATE-COMPONENT'
     if failure=='type':blocked.write_bytes(b'PRIVATE-NEVER-READ')
     else:blocked.mkdir(mode=0o777 if failure=='mode'else 0o755)
     blocked.chmod(0o777 if failure=='mode'else 0o755)
     alias=root/'PRIVATE-SOURCE.plist';alias.symlink_to(str(blocked/'PRIVATE-TARGET.plist'))
     actual_stat=os.stat;actual_lstat=os.lstat;actual_fstat=os.fstat;inode=blocked.stat().st_ino
     def metadata(value):
      fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
      row={field:getattr(value,field)for field in fields};row['st_uid']=0
      if stat.S_ISDIR(row['st_mode'])and row['st_ino']!=inode:row['st_mode']&=~0o022
      if row['st_ino']==inode and failure=='owner':row['st_uid']=501
      return types.SimpleNamespace(**row)
     stack.enter_context(patch.object(os,'stat',side_effect=lambda *a,**k:metadata(actual_stat(*a,**k))))
     stack.enter_context(patch.object(os,'lstat',side_effect=lambda *a,**k:metadata(actual_lstat(*a,**k))))
     stack.enter_context(patch.object(os,'fstat',side_effect=lambda *a,**k:metadata(actual_fstat(*a,**k))))
     stack.enter_context(patch.object(os,'geteuid',return_value=502));stack.enter_context(patch.object(os,'getppid',return_value=5))
     stack.enter_context(patch.object(module.pwd,'getpwuid',return_value=types.SimpleNamespace(pw_name=module.PRINCIPAL)))
     actual_open=os.open;opened=[]
     def directory_only(*args,**kwargs):
      self.assertTrue(args[1]&os.O_DIRECTORY,'no target file may be opened')
      fd=actual_open(*args,**kwargs);opened.append(fd);return fd
     stack.enter_context(patch.object(os,'open',side_effect=directory_only))
     stack.enter_context(patch.object(os,'read',side_effect=AssertionError('no target content may be read')))
     def pidinfo(pid,flavor,unused,pointer,size):
      row=C.cast(pointer,C.POINTER(probe._Bsd)).contents
      row.pid,row.uid,row.ppid,row.start_seconds,row.start_microseconds=(5,502,1,1000,1);return C.sizeof(row)
     base=types.SimpleNamespace(machine=lambda:module.MACHINE,boot=lambda:(module.BOOT,None),proc=types.SimpleNamespace(proc_pidinfo=pidinfo))
     volume=service.Volume((1,2),True,True,alias.stat(follow_symlinks=False).st_dev,True)
     native=types.SimpleNamespace(volume=lambda:volume,statfs=lambda *a:self.fail('no statfs past rejected component'))
     native_service=types.SimpleNamespace(NativeServices=lambda *a:native,Volume=service.Volume,_Statfs=service._Statfs,generation=service.generation)
     reader=types.SimpleNamespace(paths=lambda:(((str(alias),'system_agent'),),()),stable=lambda _:True)
     native_index=types.SimpleNamespace(NativeSSVReader=lambda _:reader)
     native_probe=types.SimpleNamespace(Native=lambda:base,_Bsd=probe._Bsd)
     envelope=module.collect(native_probe,native_service,native_index,(5,502,1,1000,1))
     for fd in opened:
      with self.assertRaises(OSError):os.fstat(fd)
     encoded=json.dumps(envelope).encode();self.assertLessEqual(len(encoded),1048576)
     self.assertEqual(1,envelope['public']['failureCounts']['target_component_unqualified'])
     self.assertEqual(0,envelope['public']['targetMetadataVerified'])
     self.assertFalse(envelope['public']['targetContentRead']);self.assertFalse(envelope['public']['idleAuthority'])
     envelope=json.loads(encoded) # Complete emitted getter envelope, not helper-only syntax.
     def required_failure(value):return value['privateTargetProof']['items'][0]['failure']
     if original:
      with self.assertRaises(IndexError):required_failure(envelope) # Actual causal RED: missing metadata.
     else:
      context=required_failure(envelope)
      self.assertEqual(str(blocked),context['firstRejectedComponentPath'])
      self.assertEqual(str(alias),context['sourcePath']);self.assertTrue(context['observedOnly'])
      self.assertEqual('stable',context['observationRevalidation'])
      self.assertEqual({'owner':'component_owner','mode':'component_mode','type':'parent_type'}[failure],context['stage'])
      self.assertEqual(501 if failure=='owner'else 0,context['uid'])
      self.assertEqual(0o777 if failure=='mode'else 0o755,context['mode'])
      self.assertEqual(9,len(context['identity']));self.assertTrue(context['priorSymlinkChain'])
      self.assertNotIn('PRIVATE',json.dumps(envelope['public']))
      counts=envelope['public']['componentFailureCounts'];self.assertEqual(1,sum(counts['kind'].values()))
      self.assertEqual(1,counts['rootOwner']['no'if failure=='owner'else'yes'])
 def test_public_filter_excludes_failure_paths_and_metadata_resolver_never_reads_contents(self):
  import ast
  driver_path=BASE/'driver.current.source'
  driver,_=component_load(driver_path);module,_=component_load(BASE/'component.current.source')
  resolver=next(node for node in ast.parse((BASE/'component.current.source').read_bytes()).body
                if isinstance(node,ast.FunctionDef)and node.name=='resolve_metadata')
  self.assertFalse(any(isinstance(node,ast.Call)and ast.unparse(node.func)=='os.read'for node in ast.walk(resolver)))
  value={'schemaVersion':1,'state':'diagnostic','machine':driver.MACHINE,'boot':module.BOOT,'uid':502,
   'nativeQualified':False,'idleAuthority':False,'targetContentRead':False,
   'volume':{'rootMount':'readonly_apfs_snapshot','authenticatedRootPolicy':'enabled','systemIntegrityPolicy':'standard'},
   'sourceSymlinksObserved':1,'targetMetadataVerified':0,'namespaceCounts':dict.fromkeys(module.NAMESPACES,0),
   'mountCounts':dict.fromkeys(module.MOUNTS,0),'filesystemRelationships':dict.fromkeys(
    ('sameRootFilesystem','sameRootDevice','apfs','readonly','snapshot'),0),'failureCounts':dict.fromkeys(module.REASONS,0),
   'targetAuthentication':'unqualified','componentFailureCounts':{
    'kind':{'directory':1,'regular':0,'symlink':0,'other':0},'rootOwner':{'yes':1,'no':0},
    'writableCategory':{'group_or_other':1,'owner_only':0}}}
  value['failureCounts']['target_component_unqualified']=1
  envelope={'public':value,'privateTargetProof':{'items':[{'failure':{'firstRejectedComponentPath':'PRIVATE'}}]}}
  self.assertNotIn('PRIVATE',json.dumps(driver.public_reply(envelope,module)))
  value['unexpectedSourcePath']='PRIVATE'
  with self.assertRaisesRegex(RuntimeError,'catalog_target_public_invalid'):driver.public_reply(envelope,module)


class ProvenanceTests(unittest.TestCase):
 def test_exact_authored_sources_and_finite_native_observations_remain_bound(self):
  manifest=json.loads((BASE/'provenance.json').read_bytes())
  self.assertFalse(manifest['privatePayloadsIncluded']);self.assertTrue(manifest['nativeSourceClosed'])
  self.assertEqual({'component.before.source','component.current.source','driver.before.source','driver.current.source'},set(manifest['files']))
  for name,digest in manifest['files'].items():
   self.assertEqual(digest,hashlib.sha256((BASE/name).read_bytes()).hexdigest())
  native=manifest['nativeFiniteObservation'];self.assertEqual(9,native['sourceSymlinksObserved'])
  self.assertEqual(0,native['targetMetadataVerified']);self.assertFalse(native['targetContentRead'])
  self.assertFalse(native['idleAuthority']);self.assertFalse(native['nativeQualified'])
  self.assertEqual('unqualified',native['targetAuthentication'])
  self.assertEqual(9,native['failureCounts']['target_component_unqualified'])
  self.assertEqual({'directory':9,'regular':0,'symlink':0,'other':0},native['componentFailureCounts']['kind'])
  self.assertEqual({'yes':9,'no':0},native['componentFailureCounts']['rootOwner'])
  self.assertEqual({'group_or_other':9,'owner_only':0},native['componentFailureCounts']['writableCategory'])

if __name__=='__main__':unittest.main()
