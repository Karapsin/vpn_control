"""Local causal actual constructor/entry; API29 OS-child portability fixture only.
No native calls, no Guard stand-in, full production constructor and mkdir.
"""
import ast,copy,json,unittest
from pathlib import Path
from agent_tools import android_installer_component_bundle as b
from agent_tools.tests import test_android_installer_component_bundle as bundle_tests
OWNER=bundle_tests.OWNER
CORRELATION=bundle_tests.CORRELATION
from agent_tools.tests.fixtures.android_component_retirement_collectors import SESSION_INVENTORY_SOURCE
class ActualCollectorComposition(unittest.TestCase):
 def test_actual_session_inventory_after_outer_guard(self):
  case=bundle_tests.BundleTests();case.setUp()
  try:
   selected,backend,args,state,log,_,_=case.fixture()
   request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,'sourceSha':b._PRODUCT_SHA,'expectedOwner':OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
   actual=b.BaselineGuard(case.receipt,selected,backend,request)
   pin=b._directory(actual.args.output);before=log.read_bytes()
   node=next(n for n in ast.parse(SESSION_INVENTORY_SOURCE).body if isinstance(n,ast.FunctionDef)and n.name=='claim_inventory')
   backend.update(COMPONENT_BUNDLE=b,COMPONENT_RECEIPT=case.receipt,BASELINE_REQUEST=request)
   exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-session-inventory>','exec'),backend)
   with self.assertRaises(FileExistsError)as caught:backend['claim_inventory']()
   self.assertEqual(actual.args.output.name,caught.exception.filename)
   self.assertEqual(pin,b._directory(actual.args.output));self.assertEqual(before,log.read_bytes())
   print('CAUSAL_RED actual nested session constructor FileExistsError; no external child dispatched')
  finally:case.tearDown()
 def test_actual_routing_backup_after_outer_guard(self):
  from agent_tools.tests.test_android_installer_routing_backup import BackupTests
  fixture=BackupTests();fixture.setUp()
  try:
   backend,request,state,log=fixture.fixture()
   selected=b.modules(fixture.case.receipt)
   actual=b.BaselineGuard(fixture.case.receipt,selected,backend,request)
   pin=b._directory(actual.args.output);before=log.read_bytes()
   with self.assertRaises(FileExistsError)as caught:b.routing_backup(fixture.case.receipt,backend,request)
   self.assertEqual(actual.args.output.name,caught.exception.filename)
   self.assertEqual(pin,b._directory(actual.args.output));self.assertEqual(before,log.read_bytes())
   self.assertFalse((actual.args.output/'routing-backup').exists())
   print('CAUSAL_RED actual authenticated routing entry second constructor FileExistsError')
  finally:fixture.tearDown()
 def test_actual_child_collectors_session_then_routing(self):
  import base64,hashlib,os,re,subprocess,sys,types
  from agent_tools.tests.test_android_installer_routing_backup import BackupTests
  from agent_tools import android_installer_routing_backup as backup
  from agent_tools.tests.fixtures.android_component_retirement_collectors import SESSION_PARSERS_SOURCE,COLLECTOR_COMPOSITION_SOURCE,RETIREMENT_TAIL_SOURCE,COLLECTOR_BASE_SOURCE,COLLECTOR_PRINT_SOURCE,COLLECTOR_PROJECTION_SOURCE,KNOWN_FAILURE_SOURCE
  fixture=BackupTests();fixture.setUp()
  try:
   backend,request,state,log=fixture.fixture()
   outer=b.BaselineGuard(fixture.case.receipt,b.modules(fixture.case.receipt),backend,request)
   outer_pin=b._directory(outer.args.output)
   composer={'ast':ast};exec(compile(COLLECTOR_COMPOSITION_SOURCE,'<exact-caller-collector-composition>','exec'),composer)
   source=KNOWN_FAILURE_SOURCE+'BASELINE_REQUEST='+repr(request)+'\n'+SESSION_PARSERS_SOURCE+SESSION_INVENTORY_SOURCE.replace('def claim_inventory():','def session_inventory():')+'\n'+RETIREMENT_TAIL_SOURCE+'\n'+COLLECTOR_BASE_SOURCE+'\n'+COLLECTOR_PRINT_SOURCE
   program,children=composer['compose_collectors'](source,request)
   session=next(n for n in ast.parse(program).body if isinstance(n,ast.FunctionDef)and n.name=='session_inventory')
   job=fixture.case.root/'android-installer-original';(job/'output').mkdir(parents=True,mode=0o700);job.chmod(0o700)
   phase=job/'output/phase-check.json';phase.write_text(json.dumps({'correlationId':'original','phase':'check'}));phase.chmod(0o600)
   intent=job/'output/intent.json';intent.write_text('{}');intent.chmod(0o600)
   def record(path):
    raw,pin=b._read(path,True);return {'state':'present','generation':pin['generation'],'sha256':pin['sha256'],'bytes':len(raw),'rawBase64':base64.b64encode(raw).decode()}
   entries=[];pieces=[]
   for index,phase_name in enumerate(('INSTALLED','FAILED','CANCELLED')):
    ident='10000000-0000-4000-8000-'+str(index+1).zfill(12)
    value={'id':ident,'nonce':ident,'sessionId':index,'version':'2.2.3','build':16860,'sha256':'a'*64,'byteCount':12,'phase':phase_name,'createdAt':index,'confirmation':None,'signers':['b'*64]}
    raw=json.dumps(value).encode();generation='1|'+str(index+1)+'|'+str(len(raw))+'|fixed'
    entries.append({'name':ident+'.json','generation':generation})
    pieces.extend(['F',ident+'.json',generation,hashlib.sha256(raw).hexdigest(),base64.b64encode(raw).decode()])
   session_bytes=('\x00'.join([*pieces,'DONE',''])).encode()
   metadata={'no_backup/control-install-sessions':{'entries':entries}}
   os_dump=b'Active install sessions:\n\nFinalized install sessions:\n\nHistorical install sessions:\n\nLegacy install sessions:\n'
   def external_read(argv,timeout,limit):
    data=session_bytes if argv==['sessions']else json.dumps(metadata).encode()if argv==['metadata']else os_dump
    done=subprocess.run([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],input=data,capture_output=True,timeout=timeout)
    self.assertEqual(done.returncode,0);self.assertEqual(done.stderr,b'');self.assertLessEqual(len(done.stdout),limit)
    return done.stdout.decode()
   # Only external Android command/protocol replies are portable fixture seams;
   # all actual BaselineGuard constructors/checks and session parsers execute.
   protocol="def native():return None,'fixture'\ndef parse_installer_metadata_census(raw):return json.loads(raw)\ndef authenticated_privileged_read(shell,script):return fixed_run([script],5,16384)\n"
   backend.update(COMPONENT_BUNDLE=b,COMPONENT_RECEIPT=fixture.case.receipt,BASELINE_REQUEST=request,COMPONENT_SESSION_REQUEST=children['sessions'],ROOT=fixture.case.root,CLAIM_ORIGINAL='original',BASELINE_BASE64=base64,READINESS_RETIREMENT_SOURCE=protocol,ReadinessSubprocess=subprocess,READINESS_QUOTE=__import__('shlex'),readiness_run=external_read,SESSION_HELPER={'fixture':True},SESSION_METADATA=metadata,SESSION_READ_SCRIPT='sessions',READINESS_METADATA_SCRIPT='metadata',SESSION_PHASE_PIN=record(phase),READINESS_ORIGINAL_RECORDS={str(intent):record(intent)},claim_record=record,READINESS_OBSERVATIONS=[],SESSION_PHASES=('INSTALLED','FAILED','CANCELLED'),SESSION_TERMINAL=('INSTALLED','FAILED','CANCELLED'))
   exec(compile(SESSION_PARSERS_SOURCE,'<actual-session-parsers>','exec'),backend)
   exec(compile(ast.Module(body=[session],type_ignores=[]),'<actual-composed-session-entry>','exec'),backend)
   result=backend['session_inventory']()
   self.assertEqual(result['collectorRequest'],children['sessions']);self.assertEqual(len(result['passes']),2)
   self.assertEqual(result['outputPin'],b._directory(fixture.case.root/('android-installer-component-baseline-'+children['sessions']['correlationId'])))
   seams=fixture.assembly_seams()
   with seams[0],seams[1],seams[2]:routing=backup.create(fixture.case.receipt,backend,children['routing'])
   self.assertEqual(routing['request'],children['routing']);self.assertEqual(routing['readCount'],2);backup._backup_guard(routing)
   self.assertEqual(outer_pin,b._directory(outer.args.output))
   self.assertEqual(len({request['correlationId'],*(v['correlationId']for v in children.values())}),3)
   # Execute the exact final raw child collector, then project only host
   # UID/GID metadata to native root0 for the private projection boundary.
   backend.update(COMPONENT_BACKUP_REQUEST=children['routing'],FAILURE=None,FAILURE_DETAIL=None)
   exec(compile(composer['CHILD_COLLECTOR'],'<actual-child-raw-collector>','exec'),backend)
   self.assertIsNone(backend['FAILURE'])
   proof={'collectorRequests':children,'collectorOutputs':copy.deepcopy(backend['collector_outputs']),'collectorRows':copy.deepcopy(backend['collector_rows'])}
   for entry in [*proof['collectorOutputs'],*proof['collectorRows']]:
    pin=entry['pin'];pin['generation'][3:5]=[0,0]
    for parent in pin['parents'].values():
     if parent[3]not in(0,1000):parent[3]=0
     if parent[4]not in(0,1000):parent[4]=0
   validators={'json':json,'Path':Path,'REMOTE_ROOT':str(fixture.case.root),'stat':__import__('stat'),'base64':base64,'hashlib':hashlib,'re':re}
   validators['ast']=ast
   exec(compile(COLLECTOR_COMPOSITION_SOURCE+'\n'+COLLECTOR_PROJECTION_SOURCE,'<actual-child-private-projection>','exec'),validators)
   validators['validate_collectors']({'request':request},proof)
   mutations=[lambda bad:bad['collectorRequests']['sessions'].update(expectedRevision=False),lambda bad:bad['collectorOutputs'][0].update(path='/foreign'),lambda bad:bad['collectorRows'].append(copy.deepcopy(bad['collectorRows'][0])),lambda bad:bad['collectorRows'][0]['pin']['generation'].__setitem__(6,False),lambda bad:bad['collectorOutputs'][0]['pin']['generation'].__setitem__(3,1000)]
   for mutate in mutations:
    changed=copy.deepcopy(proof);mutate(changed)
    with self.assertRaises(ValueError):validators['validate_collectors']({'request':request},changed)
  finally:fixture.tearDown()
class ActualReleasePhaseCorrelation(unittest.TestCase):
 def test_old_local_capture_consumes_actual_directory_pin_wrongly(self):
  import hashlib,os,tempfile
  from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_LOCAL_CAPTURE_SOURCE
  fixture=ComponentTerminalHistoryTest()
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();root.chmod(0o700)
   helper,lease,pin,proof,corr,remote,fresh=fixture.release_fixture(root)
   result=helper['release_component_fenced'](lease,pin,proof,corr,fresh,'local-original',remote)
   # Explicit historical archive-binding seam: the real TempFS proof digest
   # and its admission nonce replace only the operational archive constants.
   source=OLD_LOCAL_CAPTURE_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',hashlib.sha256(helper['_canonical'](proof)).hexdigest()).replace('6b616c2f-6c36-4ac0-836e-4465c78bfc92',proof['retirementCorrelationId'])
   scope={'bundle':b,'Path':Path,'__import__':__import__}
   exec(compile(source,'<actual-old-local-capture>','exec'),scope)
   with self.assertRaises(KeyError)as caught:scope['validate_local_capture'](lease,result,pin,helper,corr)
   self.assertEqual(slice(2,5),caught.exception.args[0])
   captured=Path(result['retiredEvidence']['path']);self.assertTrue(captured.is_file());self.assertFalse(lease.exists())
   self.assertIs(type(b._directory(captured.parent)),dict)
 def test_fixed_local_capture_accepts_actual_directory_pin(self):
  import hashlib,tempfile
  from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
  from agent_tools.tests.fixtures.android_component_retirement_collectors import FIXED_LOCAL_CAPTURE_SOURCE
  fixture=ComponentTerminalHistoryTest()
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();root.chmod(0o700)
   helper,lease,pin,proof,corr,remote,fresh=fixture.release_fixture(root)
   result=helper['release_component_fenced'](lease,pin,proof,corr,fresh,'local-original',remote)
   source=FIXED_LOCAL_CAPTURE_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',hashlib.sha256(helper['_canonical'](proof)).hexdigest()).replace('6b616c2f-6c36-4ac0-836e-4465c78bfc92',proof['retirementCorrelationId'])
   scope={'bundle':b,'Path':Path,'__import__':__import__};exec(compile(source,'<actual-fixed-local-capture>','exec'),scope)
   observed=scope['validate_local_capture'](lease,result,pin,helper,corr)
   self.assertIs(True,observed['leaseCapturedNotDeleted']);self.assertIs(False,observed['newClaimGranted'])
   captured=Path(result['retiredEvidence']['path']);captured.chmod(0o644)
   with self.assertRaises(ValueError):scope['validate_local_capture'](lease,result,pin,helper,corr)
 def test_fixed_actual_phase_derivation_creates_distinct_real_directories(self):
  import uuid
  from agent_tools.tests.fixtures.android_component_retirement_collectors import FIXED_RELEASE_PHASE_DERIVATION_SOURCE
  case=bundle_tests.BundleTests();case.setUp()
  try:
   selected,backend,args,state,log,_,_=case.fixture()
   request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,'sourceSha':b._PRODUCT_SHA,'expectedOwner':OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
   closing_parent=str(uuid.uuid5(uuid.UUID(CORRELATION),'closing-test'))
   outputs=[]
   for parent in(CORRELATION,closing_parent):
    scope={'__import__':__import__,'dict':dict,'str':str,'OWNER_ADMISSION_REQUEST':dict(request,correlationId=parent),'COMPONENT_RELEASE_CORRELATION':CORRELATION,'CERTIFICATE':{'controllerId':OWNER,'configurationRevision':0}}
    exec(compile(FIXED_RELEASE_PHASE_DERIVATION_SOURCE,'<actual-fixed-release-request-derivation>','exec'),scope)
    self.assertEqual(CORRELATION,scope['COMPONENT_RELEASE_CORRELATION'])
    self.assertEqual(parent,scope['BASELINE_REQUEST']['correlationId'])
    for key in('owner_request','BASELINE_REQUEST','COMPONENT_SESSION_REQUEST','COMPONENT_BACKUP_REQUEST'):
     derived=scope[key]
     self.assertEqual({k:v for k,v in request.items()if k!='correlationId'},{k:v for k,v in derived.items()if k!='correlationId'})
     guard=b.BaselineGuard(case.receipt,selected,backend,derived)
     outputs.append((guard.args.output,b._directory(guard.args.output)))
   self.assertEqual(8,len({str(path)for path,pin in outputs}))
   for path,pin in outputs:self.assertEqual(pin,b._directory(path))
  finally:case.tearDown()
 def test_old_actual_phase_derivation_reuses_real_constructor_directory(self):
  import uuid
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_RELEASE_PHASE_DERIVATION_SOURCE
  case=bundle_tests.BundleTests();case.setUp()
  try:
   selected,backend,args,state,log,_,_=case.fixture()
   request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,'sourceSha':b._PRODUCT_SHA,'expectedOwner':OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
   def derive(parent):
    scope={'__import__':__import__,'dict':dict,'str':str,'OWNER_ADMISSION_REQUEST':dict(request,correlationId=parent),'COMPONENT_RELEASE_CORRELATION':CORRELATION,'CERTIFICATE':{'controllerId':OWNER,'configurationRevision':0}}
    exec(compile(OLD_RELEASE_PHASE_DERIVATION_SOURCE,'<actual-old-release-request-derivation>','exec'),scope)
    return scope
   first=derive(CORRELATION);closing=derive(str(uuid.uuid4()))
   for key in('owner_request','BASELINE_REQUEST','COMPONENT_SESSION_REQUEST','COMPONENT_BACKUP_REQUEST'):self.assertEqual(first[key],closing[key])
   guard=b.BaselineGuard(case.receipt,selected,backend,first['owner_request']);pin=b._directory(guard.args.output);before=log.read_bytes()
   with self.assertRaises(FileExistsError)as caught:b.BaselineGuard(case.receipt,selected,backend,closing['owner_request'])
   self.assertEqual(guard.args.output.name,caught.exception.filename);self.assertEqual(pin,b._directory(guard.args.output));self.assertEqual(before,log.read_bytes())
  finally:case.tearDown()

class StageDiagnosticRetention(unittest.TestCase):
 def test_actual_stage_fd_predicate_code_retained(self):
  import base64,hashlib,os,subprocess,sys,tempfile
  from agent_tools.tests.fixtures import android_component_retirement_collectors as fixture
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();directory=root/'android-cli-stage-fixture';tree=directory/'tree';(tree/'lib').mkdir(parents=True,mode=0o700)
   directory.chmod(0o700);tree.chmod(0o700);(tree/'lib').chmod(0o700)
   target=tree/'lib/content';target.write_bytes(b'actual-fd-content');target.chmod(0o644)
   manifest={'directories':[{'path':'lib','mode':0o700}],'files':[{'path':'lib/content','mode':0o644,'size':target.stat().st_size,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}]}
   getter={'stageId':'fixture','manifestSha256':'a'*64,'rpmSha256':'b'*64,'manifest':manifest,'cli':str(target)}
   intent={**getter,'manifest':{**manifest,'foreign':True}}
   for name,value in [('intent.json',intent),('receipt.json',{**getter,'state':'published','cliPath':str(target)})]:
    path=directory/name;path.write_text(json.dumps(value));path.chmod(0o600)
   # Actual inherited reader/getter bodies execute in a real OS child. Only
   # returned host UID/GID metadata is projected to the source's UID1000 ABI.
   setup="""
import copy,hashlib,json,os,pathlib,re,stat,types
REAL_OS=os
def projected(info):
 values={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};values['st_uid']=values['st_gid']=1000
 return types.SimpleNamespace(**values)
OS=types.SimpleNamespace(**vars(os))
OS.fstat=lambda fd:projected(REAL_OS.fstat(fd))
OS.stat=lambda *args,**kwargs:projected(REAL_OS.stat(*args,**kwargs))
os=OS
ROOT=pathlib.Path(__ROOT__);GETTER=__GETTER__
""".replace('__ROOT__',repr(str(root))).replace('__GETTER__',repr(getter))
   delegate="""
STAGE_RAW=[];ORIGINAL_READ_FIXED=read_fixed
def read_fixed(path,limit):
 value=ORIGINAL_READ_FIXED(path,limit);STAGE_RAW.append(copy.deepcopy(value));return value
FAILURE=None;FAILURE_DETAIL=None
"""
   codes=getattr(fixture,'STAGE_ALLOWED_CODES',fixture.STAGE_ORIGINAL_CODES)
   source=setup+fixture.STAGE_READER_SOURCE+'\n'+delegate+fixture.STAGE_GETTER_SOURCE+'\nKNOWN_FAILURE_CODES='+repr(codes)+'\nKNOWN_FAILURE_FUNCTIONS='+repr(fixture.STAGE_ORIGINAL_FUNCTIONS)+'\n'+fixture.STAGE_FAILURE_CAPTURE_SOURCE+"\nprint(json.dumps({'failure':FAILURE,'detail':FAILURE_DETAIL,'rawCount':len(STAGE_RAW),'rawRetained':bool(STAGE_RAW and STAGE_RAW[0]['raw'])}))\n"
   result=subprocess.run([sys.executable,'-I','-c',source],capture_output=True,timeout=5)
   self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'')
   proof=json.loads(result.stdout);self.assertTrue(proof['rawRetained']);self.assertEqual(proof['rawCount'],1)
   self.assertEqual(proof['failure'],'ValueError')
   self.assertEqual(proof['detail']['code'],'getter_stage_manifest_changed')

class ActualStageAliasPrincipal(unittest.TestCase):
 def test_actual_alias_reader_mixed_principal_red_green(self):
  import base64,hashlib,os,pathlib,re,stat,tempfile,types
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  with tempfile.TemporaryDirectory()as temporary:
   root=Path(temporary).resolve();lease=root/'android-native-device-api35.lease'
   original={'owner':'android-installer','host':'archlinux','device':'api35','correlationId':'0dd55704-1e80-4d62-8d9d-2f0a123e0c3b'}
   lease.write_bytes((json.dumps(original,sort_keys=True,separators=(',',':'))+'\n').encode());lease.chmod(0o600)
   # The exact production functions run over real FDs. Only returned stat
   # UID/GID/getuid are projected to root worker + original UID1000 lease.
   real_os=os
   def projected(info):
    values={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};values['st_uid']=values['st_gid']=1000;return types.SimpleNamespace(**values)
   model=types.SimpleNamespace(**vars(os));model.getuid=lambda:0;model.fstat=lambda fd:projected(real_os.fstat(fd));model.stat=lambda *a,**k:projected(real_os.stat(*a,**k))
   scope={'ROOT':root,'pathlib':pathlib,'Path':Path,'os':model,'stat':stat,'hashlib':hashlib,'json':json,'re':re,'STAGE_BASE64':base64,'STAGE_ALIAS_READS':[],'LIMIT':1048576}
   exec(compile(f.STAGE_BUNDLE_READER_SOURCE,'<actual-root-only-reader>','exec'),scope);scope['COMPONENT_BUNDLE']=types.SimpleNamespace(_read=scope['_read'])
   exec(compile(f.STAGE_READER_SOURCE,'<actual-UID1000-reader>','exec'),scope)
   exec(compile(f.STAGE_ALIAS_ORIGINAL_SOURCE,'<actual-original-alias-function>','exec'),scope)
   with self.assertRaisesRegex(ValueError,'component_bundle_file_unsafe'):scope['stage_aliases']()
   self.assertEqual(scope['STAGE_ALIAS_READS'],[[]])
   exec(compile(f.STAGE_ALIAS_REPAIRED_SOURCE,'<actual-repaired-alias-function>','exec'),scope)
   records=scope['stage_aliases']();self.assertEqual(len(records),4);self.assertEqual(records[0]['pin']['generation'][2:7],[0o100600,1000,1000,1,121]);self.assertEqual(records[0]['pin']['sha256'],'44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a');self.assertEqual([r['state']for r in records],['present','absent','absent','absent']);self.assertTrue(records[0]['pin']['parents'])
   lease.write_bytes(b'foreign');lease.chmod(0o600)
   with self.assertRaisesRegex(ValueError,'stage_diagnostic_alias_changed'):scope['stage_aliases']()
   self.assertEqual(base64.b64decode(scope['STAGE_ALIAS_READS'][-1][0]['rawBase64']),b'foreign')
   lease.write_bytes((json.dumps(original,sort_keys=True,separators=(',',':'))+'\n').encode());lease.chmod(0o644)
   with self.assertRaisesRegex(ValueError,'stage_diagnostic_alias_changed'):scope['stage_aliases']()
   self.assertEqual(scope['STAGE_ALIAS_READS'][-1][0]['pin']['generation'][2],0o100644)
   print('CAUSAL_RED root-only FD consumer/mixed principal; GREEN exact fixed alias read/full ordered pin plus drift/raw-before-guard')

class StageAdmissionComposition(unittest.TestCase):
 def test_actual_composer_retains_stage_predicate_and_preserves_getter(self):
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  ns={'ast':ast};exec(f.STAGE_ADMISSION_COMPOSE_STAGE_GUARD_SOURCE,ns)
  original=("KNOWN_FAILURE_CODES=()\nKNOWN_FAILURE_FUNCTIONS=()\n"+f.STAGE_GETTER_SOURCE+"\ndef claim_inventory():\n  def current():\n   certificate_guard();guard()\n  return current\nvalue={'componentRetirementRows':component_retirement_rows,}\n")
  # Exact source-backed alias slice; actual assembly/source seals are exercised
  # independently by the complete full-factory native-context checks.
  source=('REMOTE='+repr(f.STAGE_ALIAS_REPAIRED_SOURCE)).encode()
  changed=ns['compose_stage_guard'](original,source);tree=ast.parse(changed)
  values={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('KNOWN_FAILURE_CODES','KNOWN_FAILURE_FUNCTIONS')}
  self.assertEqual(ast.literal_eval(ast.parse(original).body[0].value),())
  self.assertIn('getter_stage_manifest_changed',values['KNOWN_FAILURE_CODES']);self.assertIn('getter_stage',values['KNOWN_FAILURE_FUNCTIONS'])
  old=next(n for n in ast.parse(original).body if isinstance(n,ast.FunctionDef)and n.name=='getter_stage');new=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='getter_stage');self.assertEqual(ast.dump(old),ast.dump(new))
  outer=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='claim_inventory');self.assertEqual(ast.unparse(outer.body[0].body[-1]),'component_stage_alias_guard()')
  self.assertIn("'componentStageAliasReads':STAGE_ALIAS_READS",changed)
  with self.assertRaisesRegex(ValueError,'component_stage_alias_factory_changed'):ns['compose_stage_guard'](original.replace('def claim_inventory():','def foreign_inventory():'),source)

class ClosingRoutingRoleLimit(unittest.TestCase):
 def test_actual_fd_consumer_native_scale_and_named_role_caps(self):
  import base64,hashlib,os,stat,tempfile,types
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  class PrincipalOS:
   def __getattr__(self,name):return getattr(os,name)
   def project(self,s):
    class S:
     def __getattr__(self,name):
      if name=='st_uid':return 0 if s.st_uid==os.getuid()else s.st_uid
      if name=='st_gid':return 0 if s.st_gid==os.getgid()else s.st_gid
      return getattr(s,name)
    return S()
   def fstat(self,fd):return self.project(os.fstat(fd))
   def stat(self,*a,**k):return self.project(os.stat(*a,**k))
  # Exact descriptor implementation and consumer; only503→0 FD metadata is
  # portable. CI payload is nonsecret, exact measured native byte extent.
  captured=[];scope={'os':PrincipalOS(),'Path':Path,'stat':stat,'hashlib':hashlib,'BASELINE_BASE64':base64,'component_retirement_record_raw':captured.append}
  exec(f.CLOSING_ROUTE_READERS_SOURCE,scope);scope['COMPONENT_BUNDLE']=types.SimpleNamespace(**{n:scope[n]for n in ('_pin','_parents','_close')});exec(f.CLOSING_ROUTE_CLAIM_RECORD_SOURCE,scope)
  with tempfile.TemporaryDirectory()as folder:
   path=Path(folder).resolve()/'closing-route.json';path.parent.chmod(0o700);data=b'x'*f.CLOSING_ROUTE_NATIVE_BYTES;path.write_bytes(data);path.chmod(0o600)
   name='closing-component-routing.json';old=eval(f.CLOSING_ROUTE_OLD_LIMIT_SOURCE,{}, {'name':name});new=eval(f.CLOSING_ROUTE_REPAIRED_LIMIT_SOURCE,{}, {'name':name})
   initial=scope['claim_record'](path,33554432)
   with self.assertRaisesRegex(ValueError,'claim_record_unsafe'):scope['claim_record'](path,old)
   closing=scope['claim_record'](path,new);self.assertEqual(initial,closing);self.assertEqual(closing['bytes'],11480195);self.assertEqual(closing['sha256'],hashlib.sha256(data).hexdigest());self.assertEqual(len(captured),2)
   for role,expected in [('opening-routing.json',67108864),('closing-component-routing.json',33554432),('unknown.json',4194304),('terminal-history.json',4194304)]:self.assertEqual(eval(f.CLOSING_ROUTE_REPAIRED_LIMIT_SOURCE,{}, {'name':role}),expected)
   with path.open('wb')as out:out.truncate(33554433)
   with self.assertRaisesRegex(ValueError,'claim_record_unsafe'):scope['claim_record'](path,new)
   path.write_bytes(data);path.chmod(0o644)
   with self.assertRaisesRegex(ValueError,'claim_record_unsafe'):scope['claim_record'](path,new)
   path.chmod(0o600)
   model=scope['os'];changed=False
   def drift_read(fd,count):
    nonlocal changed
    part=os.read(fd,count)
    if not changed:
     changed=True;s=os.stat(path);os.utime(path,ns=(s.st_atime_ns,s.st_mtime_ns+1))
    return part
   model.read=drift_read;before_count=len(captured)
   with self.assertRaisesRegex(ValueError,'claim_record_changed'):scope['claim_record'](path,new)
   self.assertEqual(len(captured),before_count+1) # full raw retained before closing FD rejection
   print('CAUSAL_RED closing11480195B initial32/current4; GREEN namedclosing32 fullFD/hash +32MiB+1/mode/FDdrift refuse, generic4 preserved')

if __name__=='__main__':unittest.main()

class ActualReleaseOwnerInventory(unittest.TestCase):
 def test_actual_owner_producer_rejected_by_old_release_catalog(self):
  from agent_tools.tests.test_android_api35_current_owner_admission import AdmissionTests
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_RELEASE_OWNER_INVENTORY_SOURCE
  import base64,re
  case=AdmissionTests();case.setUp()
  try:
   guard=case.create();directory=guard.args.output;names=sorted(p.name for p in directory.iterdir())
   self.assertIn('admission.json',names);self.assertTrue(any(name.startswith('read-read-') for name in names))
   scope={'owner_names':names,'owner_directory':directory,'owner_rows':[],'COMPONENT_BUNDLE':b,'BASELINE_BASE64':base64,'re':re}
   with self.assertRaisesRegex(ValueError,'component_release_owner_inventory_changed'):
    exec(compile(OLD_RELEASE_OWNER_INVENTORY_SOURCE,'<actual-old-release-owner-inventory>','exec'),scope)
   self.assertTrue((directory/'admission.json').is_file())
   print('CAUSAL_RED actual OwnerAdmissionGuard producer rejected by actual release inventory loop')
  finally:case.doCleanups()

 def test_actual_owner_catalog_fullpin_foreign_and_drift(self):
  from agent_tools.tests.test_android_api35_current_owner_admission import AdmissionTests
  from agent_tools.tests.fixtures.android_component_retirement_collectors import FIXED_RELEASE_OWNER_INVENTORY_SOURCE
  import base64,os
  case=AdmissionTests();case.setUp()
  try:
   guard=case.create();directory=guard.args.output
   scope={'owner_directory':directory,'owner_result':{'certificatePin':guard.certificatePin},'COMPONENT_BUNDLE':b,'BASELINE_BASE64':base64,'json':json,'os':os}
   exec(compile(FIXED_RELEASE_OWNER_INVENTORY_SOURCE,'<actual-fixed-release-owner-inventory>','exec'),scope)
   self.assertEqual(sorted(['admission.json',*guard.certificate['responsePins']]),[r['name'] for r in scope['owner_rows']])
   foreign=directory/'read-foreign.json';b._write(foreign,b._raw({'foreign':True}))
   with self.assertRaisesRegex(ValueError,'component_release_owner_inventory_changed'):
    exec(compile(FIXED_RELEASE_OWNER_INVENTORY_SOURCE,'<actual-fixed-release-owner-inventory>','exec'),scope)
   foreign.unlink();response=directory/next(iter(guard.certificate['responsePins']));saved=response.read_bytes();response.write_bytes(saved+b' ')
   with self.assertRaisesRegex(ValueError,'component_release_owner_inventory_changed'):
    exec(compile(FIXED_RELEASE_OWNER_INVENTORY_SOURCE,'<actual-fixed-release-owner-inventory>','exec'),scope)
  finally:case.doCleanups()

class ActualNativeReleaseClosure(unittest.TestCase):
 def produced(self):
  import tempfile,os,types,hashlib,base64,uuid
  from agent_tools import android_installer_failed_check_retirement as retirement
  from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
  from agent_tools.tests.fixtures.android_component_retirement_collectors import NATIVE_CLOSURE_CLAIM_RECORD_SOURCE
  temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name).resolve();root.chmod(0o700)
  local=root/'local';local.mkdir(mode=0o700);remote=root/'remote';remote.mkdir(mode=0o700)
  fixture=ComponentTerminalHistoryTest();helper,lease,local_pin,proof,oldcorr,_,_=fixture.release_fixture(local)
  remote_lease=remote/'android-native-device-api35.lease';remote_lease.write_bytes(lease.read_bytes());remote_lease.chmod(0o600)
  paths={}
  def projected(info,path):
   fields={name:getattr(info,name)for name in dir(info)if name.startswith('st_')}
   uid=1000 if path in(remote,remote_lease)or(path.name=='captured-original-lease.json'and remote in path.parents)else 0
   fields.update(st_uid=uid,st_gid=uid)
   if path.is_dir():fields['st_nlink']=2+sum(child.is_dir()for child in path.iterdir())
   return types.SimpleNamespace(**fields)
  def opened(path,flags,*args,**kwargs):
   fd=os.open(path,flags,*args,**kwargs);parent=paths.get(kwargs.get('dir_fd'));paths[fd]=(parent/str(path)if parent is not None else Path(path)).absolute();return fd
  def named(path,*args,**kwargs):
   parent=paths.get(kwargs.get('dir_fd'));full=(parent/str(path)if parent is not None else Path(path)).absolute();return projected(os.stat(path,*args,**kwargs),full)
  def closed(fd):paths.pop(fd,None);os.close(fd)
  proxy=types.SimpleNamespace(**vars(os));proxy.open=opened;proxy.stat=named;proxy.fstat=lambda fd:projected(os.fstat(fd),paths[fd]);proxy.close=closed;proxy.getuid=proxy.getgid=lambda:0
  def fp(i):return [i.st_dev,i.st_ino,i.st_mode,i.st_uid,i.st_gid,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns]
  chain=[Path('/'),*reversed([remote,*list(remote.parents)[:-1]])];parents=[fp(projected(path.stat(),path))[:5]for path in chain[1:]]
  generation=fp(projected(remote_lease.stat(),remote_lease));pin={'generation':generation,'sha256':local_pin['sha256'],'parents':parents}
  proof['files']['remote-lease.json']={'principal':'historical-worker','format':'descriptor9','generation':generation,'sha256':pin['sha256']}
  raw=Path(retirement.__file__).read_bytes();native={};exec(retirement.component_release_source(raw,hashlib.sha256(raw).hexdigest()),native);native['os']=proxy
  corr=str(uuid.uuid4());result=native['release_component_fenced'](remote_lease,pin,proof,corr,lambda:copy.deepcopy(proof),'remote-original')
  digest=hashlib.sha256(native['_canonical'](proof)).hexdigest()
  scope={'ROOT':remote,'CLAIM_ORIGINAL':proof['originalCorrelationId'],'BASELINE_REQUEST':{'correlationId':corr},'COMPONENT_RELEASE_ADMITTED_PROOF':proof,'COMPONENT_RETIRE_NAMESPACE':native,'COMPONENT_BUNDLE':b,'COMPONENT_RELEASE_QUARANTINE_PIN':None,'COMPONENT_RELEASE_SNAPSHOT_PIN':None,'COMPONENT_RELEASE_REMOTE_RESULT':result,'COMPONENT_RELEASE_PROGRESS':{},'BASELINE_BASE64':base64,'os':proxy,'json':json,'hashlib':hashlib,'stat':__import__('stat'),'component_retirement_record_raw':lambda row:None}
  exec(NATIVE_CLOSURE_CLAIM_RECORD_SOURCE,scope);scope['component_retirement_capture_record']=scope['claim_record']
  return scope,result,digest,proxy
 def test_old_native_guard_dict_projection_red(self):
  from unittest import mock
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_NATIVE_RETIRED_GUARD_SOURCE
  scope,result,digest,proxy=self.produced();source=OLD_NATIVE_RETIRED_GUARD_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',digest);exec(source,scope)
  with mock.patch.object(b,'os',proxy):
   with self.assertRaises(KeyError)as error:scope['component_release_retired_evidence_guard'](result)
  self.assertEqual(slice(2,5,None),error.exception.args[0]);self.assertTrue(Path(result['retiredEvidence']['path']).exists())
 def test_fixed_native_guard_exact_fd_positive_and_pin_drift(self):
  from unittest import mock
  from agent_tools.tests.fixtures.android_component_retirement_collectors import FIXED_NATIVE_RETIRED_GUARD_SOURCE
  scope,result,digest,proxy=self.produced();source=FIXED_NATIVE_RETIRED_GUARD_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',digest);exec(source,scope)
  with mock.patch.object(b,'os',proxy):
   scope['component_release_retired_evidence_guard'](result);scope['component_release_retired_evidence_guard'](result)
   wrong=copy.deepcopy(result);wrong['retiredEvidence']['generation'][1]+=1
   with self.assertRaises(ValueError):scope['component_release_retired_evidence_guard'](wrong)
   wrong=copy.deepcopy(result);wrong['retiredEvidence']['leaseCapturedNotDeleted']=1
   with self.assertRaises(ValueError):scope['component_release_retired_evidence_guard'](wrong)
  self.assertTrue(Path(result['retiredEvidence']['path']).exists())
 def test_actual_native_captured_file_ancestry_red(self):
  from unittest import mock
  from agent_tools.tests.fixtures.android_component_retirement_collectors import PARTIAL_NATIVE_RETIRED_GUARD_SOURCE
  scope,result,digest,proxy=self.produced();source=PARTIAL_NATIVE_RETIRED_GUARD_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',digest);exec(source,scope)
  with mock.patch.object(b,'os',proxy):
   with self.assertRaises(NotADirectoryError):scope['component_release_retired_evidence_guard'](result)
  self.assertTrue(Path(result['retiredEvidence']['path']).is_file())
 def test_actual_native_parent_schema4_versus5_red(self):
  from unittest import mock
  from agent_tools.tests.fixtures.android_component_retirement_collectors import PARENT4_NATIVE_RETIRED_GUARD_SOURCE
  scope,result,digest,proxy=self.produced();source=PARENT4_NATIVE_RETIRED_GUARD_SOURCE.replace('93ff56ef99d2496aef690ea1ae44e0e7ff4136386e6718fa81e8f0ff21e2e6ed',digest);exec(source,scope)
  with mock.patch.object(b,'os',proxy):
   measured=scope['COMPONENT_RETIRE_NAMESPACE']['_ancestry'](Path(result['retiredEvidence']['path']).parent)
   self.assertTrue(all(len(row)==4 for row in measured));self.assertTrue(all(len(row)==5 for row in result['retiredEvidence']['parents']))
   with self.assertRaisesRegex(ValueError,'component_release_captured_parent_changed'):scope['component_release_retired_evidence_guard'](result)
  self.assertTrue(Path(result['retiredEvidence']['path']).is_file())


class ActualReadonlyBoundaryPhase(unittest.TestCase):
 """Causal finite ingress gate only; whole operational transport is separate."""
 def namespace(self,fixed=False):
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_READONLY_BOUNDARY_PHASE_SOURCE,FIXED_READONLY_BOUNDARY_PHASE_SOURCE
  namespace={'bundle':b};exec(FIXED_READONLY_BOUNDARY_PHASE_SOURCE if fixed else OLD_READONLY_BOUNDARY_PHASE_SOURCE,namespace);return namespace
 def test_original_actual_readonly_phase_refusal_red(self):
  namespace=self.namespace()
  with self.assertRaisesRegex(ValueError,'component_release_operator_phase_invalid'):namespace['bind_transport']({},b'pass\n','original-effect-boundary-readonly')
  with self.assertRaisesRegex(ValueError,'component_release_operator_not_bound'):namespace['execute_bound_phase']({'base':{},'capture':None,'dispatchReady':True,'releasePhase':'original-effect-boundary-readonly'},lambda:None)
 def test_fixed_actual_phase_reaches_next_real_gate_and_foreign_refuses(self):
  namespace=self.namespace(True)
  with self.assertRaisesRegex(ValueError,'component_release_operator_programme_changed'):namespace['bind_transport']({},None,'original-effect-boundary-readonly')
  # A valid phase alone does not grant credential/source/native authority.
  with self.assertRaises(KeyError)as error:namespace['execute_bound_phase']({'base':{},'capture':None,'dispatchReady':True,'releasePhase':'original-effect-boundary-readonly'},lambda:None)
  self.assertEqual(error.exception.args,('credentialPath',))
  with self.assertRaisesRegex(ValueError,'component_release_operator_phase_invalid'):namespace['bind_transport']({},b'pass\n','foreign-phase')
 def test_exact_two_tuple_changes_all_remaining_ast_identical(self):
  import ast
  from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_READONLY_BOUNDARY_PHASE_SOURCE,FIXED_READONLY_BOUNDARY_PHASE_SOURCE
  before=ast.parse(OLD_READONLY_BOUNDARY_PHASE_SOURCE);after=ast.parse(FIXED_READONLY_BOUNDARY_PHASE_SOURCE);found=0
  for node in ast.walk(after):
   if isinstance(node,ast.Tuple)and all(isinstance(n,ast.Constant)and type(n.value)is str for n in node.elts)and ast.literal_eval(node)==('remote-original-capture','post-remote-readonly-closing','original-effect-boundary-readonly'):node.elts.pop();found+=1
  self.assertEqual(found,2);self.assertEqual(ast.dump(before,include_attributes=False),ast.dump(after,include_attributes=False))

class ActualObserverFixtureAncestry(unittest.TestCase):
 """Actual FP9 reader; outer-host timestamp seam grants no native authority."""
 def observe(self,stable=False,inside=False):
  import types,pathlib,tempfile,os,stat,hashlib
  from agent_tools.tests.fixtures.android_component_retirement_collectors import STAGE_READER_SOURCE
  with tempfile.TemporaryDirectory()as temporary:
   parent=Path(temporary).resolve();root=parent/'owned';root.mkdir(mode=0o700);path=root/'lease';path.write_bytes(b'actual-original-fixture');path.chmod(0o600)
   proxy=types.SimpleNamespace(**vars(os));initial={p.stat().st_ino:p.stat()for p in root.parents}
   def projected(info):
    if stable and info.st_ino in initial:
     fields={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};fields.update({name:getattr(initial[info.st_ino],name)for name in ('st_size','st_mtime_ns','st_ctime_ns','st_nlink')});return types.SimpleNamespace(**fields)
    return info
   proxy.fstat=lambda fd:projected(os.fstat(fd));proxy.stat=lambda *a,**k:projected(os.stat(*a,**k))
   once=[False]
   def read(fd,size):
    value=os.read(fd,size)
    if not once[0]:once[0]=True;((root if inside else parent)/'unrelated-sibling').mkdir(mode=0o700)
    return value
   proxy.read=read;scope={'os':proxy,'pathlib':pathlib,'stat':stat,'hashlib':hashlib};exec(STAGE_READER_SOURCE,scope)
   if not stable or inside:
    with self.assertRaisesRegex(ValueError,'census_ancestry_changed'):scope['read_fixed'](path,1024)
   else:self.assertEqual(scope['read_fixed'](path,1024)['raw'],b'actual-original-fixture')
   self.assertEqual(path.read_bytes(),b'actual-original-fixture')
 def test_real_outer_ancestor_full_generation_noise_red(self):self.observe(False)
 def test_narrow_outer_seam_positive_and_namespace_drift_refusal(self):self.observe(True);self.observe(True,True)

class ActualReleaseOwnerRequest(unittest.TestCase):
 """Actual generated statement and consumer; source-shaped certificate fixture only.

 The output producer is always emitted by the exact source statement, never
 supplied as a passing DTO. Retained native4954 coverage is a separate local
 test; this portable fixture conveys no native principal or admission proof.
 """
 def setup_boundary(self):
  import types
  from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
  from agent_tools import android_installer_failed_check_retirement as helper
  certificate_input=ComponentTerminalHistoryTest().component_producer()
  scope={'owner_result':certificate_input['result'],'owner_rows':certificate_input['rows'],
   'owner_request':certificate_input['request'],
   'os':types.SimpleNamespace(getuid=lambda:0,geteuid=lambda:0,getgid=lambda:0,getegid=lambda:0,getgroups=lambda:[0])}
  return scope,helper
 def test_actual_statement_old_request_omission_red(self):
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  scope,helper=self.setup_boundary()
  exec(compile(f.OLD_RELEASE_OWNER_PRODUCER_SOURCE,'<exact-old-generated-owner-producer>','exec'),scope)
  with self.assertRaisesRegex(ValueError,'component_certificate_product_invalid'):
   helper.validate_component_certificate(scope['COMPONENT_RETIRE_PRODUCER'],scope['owner_result']['certificatePin'])
 def test_actual_statement_fixed_request_and_foreign_refusal(self):
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  scope,helper=self.setup_boundary()
  exec(compile(f.FIXED_RELEASE_OWNER_PRODUCER_SOURCE,'<exact-fixed-generated-owner-producer>','exec'),scope)
  certificate=helper.validate_component_certificate(scope['COMPONENT_RETIRE_PRODUCER'],scope['owner_result']['certificatePin'])
  self.assertEqual(certificate['request'],scope['owner_request'])
  scope['owner_request']=dict(scope['owner_request'],correlationId='ffffffff-ffff-4fff-8fff-ffffffffffff')
  exec(compile(f.FIXED_RELEASE_OWNER_PRODUCER_SOURCE,'<exact-fixed-generated-owner-producer>','exec'),scope)
  with self.assertRaisesRegex(ValueError,'component_certificate_product_invalid'):
   helper.validate_component_certificate(scope['COMPONENT_RETIRE_PRODUCER'],scope['owner_result']['certificatePin'])

class ActualReleaseFailureDiagnostics(unittest.TestCase):
 """Exact source factories, real child output and typed failure projection.

 Missing Any is an eager-annotation constructor contract; forcing annotation
 evaluation on Python3.14 tests that same dependency. No native historical
 exception class, interpreter version, footprint or replay is inferred.
 """
 def factory(self,fixed=True):
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  scope={'ast':ast}
  exec(compile(f.FIXED_RELEASE_FAILURE_FACTORY_SOURCE if fixed else f.OLD_RELEASE_FAILURE_FACTORY_SOURCE,'<actual-release-failure-factory>','exec'),scope)
  return scope['finalized_remote_entry']
 def child_document(self,entry,fixed=True,definitions=()):
  import subprocess,sys,os
  source=self.factory(fixed)(entry,definitions)
  prefix="import json\nBASELINE_REQUEST={}\nCOMPONENT_RELEASE_CORRELATION='10000000-0000-4000-8000-000000000001'\nGETTER_RECORDS={}\n"
  result=subprocess.run([sys.executable,'-I','-B','-c',prefix+source],stdin=subprocess.DEVNULL,capture_output=True,timeout=5,env={k:v for k,v in os.environ.items()if k!='DYLD_INSERT_LIBRARIES'})
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,b'')
  return json.loads(result.stdout),result.stdout
 def test_actual_old_builtin_class_loss_red(self):
  document,raw=self.child_document("raise NameError('PRIVATE_ERROR_TEXT')\n",False)
  self.assertEqual(document['primaryFailure'],{'type':'Exception','code':None})
  self.assertNotIn(b'PRIVATE_ERROR_TEXT',raw)
 def test_actual_fixed_builtin_class_stage_version_and_unknown_refuse_leaks(self):
  for kind in('NameError','FileNotFoundError','PermissionError','KeyError','TypeError','RuntimeError'):
   document,raw=self.child_document("COMPONENT_RELEASE_FAILURE_STAGE='restoration-protocol'\nraise "+kind+"('PRIVATE_ERROR_TEXT')\n")
   failure=document['primaryFailure'];self.assertEqual(failure['type'],kind);self.assertEqual(failure['stage'],'restoration-protocol');self.assertIsNone(failure['code'])
   self.assertEqual(len(failure['interpreterVersion']),3);self.assertTrue(all(type(x)is int and x>=0 for x in failure['interpreterVersion']));self.assertNotIn(b'PRIVATE_ERROR_TEXT',raw)
  document,raw=self.child_document("class ForeignError(Exception):pass\nCOMPONENT_RELEASE_FAILURE_STAGE='PRIVATE_STAGE'\nraise ForeignError('PRIVATE_ERROR_TEXT')\n")
  self.assertEqual(document['primaryFailure']['type'],'Exception');self.assertEqual(document['primaryFailure']['stage'],'unknown');self.assertNotIn(b'PRIVATE_',raw)
  document,_=self.child_document("COMPONENT_RELEASE_RESULT={'state':'local-only-source-output'}\n")
  self.assertIsNone(document['primaryFailure']);self.assertFalse(document['claimGranted']);self.assertFalse(document['localLeaseRetired']);self.assertFalse(document['acceptanceComplete']);self.assertFalse(document['replayAllowed'])
 def test_actual_fixed_literal_codes_only(self):
  source="def causal_source():raise ValueError('component_release_known_guard')"
  document,_=self.child_document("raise ValueError('component_release_known_guard')\n",definitions=(source,))
  self.assertEqual(document['primaryFailure']['code'],'component_release_known_guard')
  document,raw=self.child_document("raise ValueError('PRIVATE_ERROR_TEXT')\n",definitions=(source,))
  self.assertIsNone(document['primaryFailure']['code']);self.assertNotIn(b'PRIVATE_ERROR_TEXT',raw)
 def test_actual_protocol_namespace_annotation_red_green(self):
  import os,stat,hashlib,re,shlex,subprocess
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  definitions="namespace={'__name__':'fixed_session_read_protocol','json':json,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'shlex':READINESS_QUOTE,'subprocess':ReadinessSubprocess,'fixed_run':readiness_run,'su_pin':SESSION_HELPER}\nprotocol={'__name__':'fixed_restoration_read_protocol','json':json,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'shlex':READINESS_QUOTE,'subprocess':ReadinessSubprocess,'fixed_run':readiness_run,'su_pin':SESSION_HELPER}\n"
  called=[]
  def native_read(*args,**kwargs):called.append(args);raise AssertionError('constructor must not dispatch')
  scope={'json':json,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'READINESS_QUOTE':shlex,'ReadinessSubprocess':subprocess,'readiness_run':native_read,'SESSION_HELPER':None}
  exec(definitions,scope)
  for name in('namespace','protocol'):
   with self.assertRaises(NameError):
    exec(compile(f.RELEASE_RESTORATION_PROTOCOL_SOURCE,'<actual-unbound-annotation-protocol>','exec',dont_inherit=True),scope[name])
    scope[name]['parse_installer_metadata_census'].__annotations__
  binding={};exec(f.RELEASE_PROTOCOL_BINDING_SOURCE,binding)
  exec(binding['bind_release_protocol_annotations'](definitions),scope)
  for name in('namespace','protocol'):
   exec(compile(f.RELEASE_RESTORATION_PROTOCOL_SOURCE,'<actual-bound-annotation-protocol>','exec',dont_inherit=True),scope[name])
   self.assertEqual(set(scope[name]['parse_installer_metadata_census'].__annotations__),{'text','return'})
   self.assertEqual(scope[name]['parse_installer_metadata_census']('D\x00no_backup/control-install-sessions\x00absent\x00\x00Z\x00D\x00files/control-installs\x00absent\x00\x00Z\x00DONE\x00'),{'no_backup/control-install-sessions':{'kind':'absent','generation':'','entries':[]},'files/control-installs':{'kind':'absent','generation':'','entries':[]}})
  self.assertEqual(called,[])
  with self.assertRaisesRegex(ValueError,'component_release_protocol_annotation_factory_changed'):binding['bind_release_protocol_annotations'](definitions.replace('fixed_session_read_protocol','foreign'))
 def test_exact_native194_reader_fixture_equality_and_diagnostic_body_only(self):
  from agent_tools.tests.fixtures import android_component_retirement_collectors as f
  self.assertEqual(f.CLOSING_ROUTE_CLAIM_RECORD_SOURCE,f.NATIVE_CLOSURE_CLAIM_RECORD_SOURCE)
  scope={};exec(f.RELEASE_STAGE_FACTORY_SOURCE,scope)
  fixed=scope['diagnostic_release_measurement'](f.RELEASE_NATIVE_INVENTORY_SOURCE)
  before=ast.parse(f.RELEASE_NATIVE_INVENTORY_SOURCE);after=ast.parse(fixed)
  class RemoveOnlyFixedDiagnosticAssignments(ast.NodeTransformer):
   def visit_Assign(self,node):
    if len(node.targets)==1 and isinstance(node.targets[0],ast.Subscript)and isinstance(node.targets[0].value,ast.Call)and isinstance(node.targets[0].value.func,ast.Name)and node.targets[0].value.func.id=='globals'and node.targets[0].value.args==[]and isinstance(node.targets[0].slice,ast.Constant)and node.targets[0].slice.value=='COMPONENT_RELEASE_FAILURE_STAGE':return None
    return self.generic_visit(node)
  after=RemoveOnlyFixedDiagnosticAssignments().visit(after)
  self.assertEqual(ast.dump(before,include_attributes=False),ast.dump(after,include_attributes=False))


class ActualCertificateQuoteBoundary(unittest.TestCase):
 """Actual emitted function bodies; only external OS/ADB/source replies seam.
 Synthetic values are independent of private native captures. Byte/pin and
 complete package/process/app comparisons execute in the original functions.
 """
 def namespace(self):
  import base64,copy,hashlib,json,re,shlex
  from pathlib import Path
  from agent_tools import android_installer_component_bundle as bundle
  from agent_tools.tests.fixtures.android_component_retirement_collectors import RELEASE_CERTIFICATE_FUNCTION_SOURCES
  fields=' '.join(['S']+['0']*18+['123'])
  processes='adbd\t11\t11 (adbd) '+fields+'\nzygote64\t12\t12 (main) '+fields
  app={'pid':20,'uid':10209,'name':'com.kardinal.vpncontrol','comm':'app','startTicks':123,'guestBootId':'boot'}
  facts={'sdk':'35','abi':'x86_64','kernelAvd':'test','bootAvd':'test','bootCompleted':'1','shellUid':'2000','guestBootId':'boot','processes':bundle._process_facts(processes),'packagePath':'/data/app/test/base.apk','packageSha256':'a'*64}
  cert={'host':{'uid':1000},'stage':{'fixed':'source'},'backendBinding':{'fixed':'jdk'},'facts':facts,'appProcess':app,'bundleReceipt':{'fixed':'receipt'}}
  raw=json.dumps(cert,sort_keys=True).encode();pin={'generation':[1,2,33152,1000,1000,1,len(raw),3,4],'sha256':hashlib.sha256(raw).hexdigest()}
  class ExternalReplay:
   _PROPERTIES=bundle._PROPERTIES;_PROCESS_READ=bundle._PROCESS_READ;_process_facts=staticmethod(bundle._process_facts)
   def _read(self,path,private):
    assert path==Path('/retained/certificate.json') and private;return raw,copy.deepcopy(pin)
   def load(self,receipt):assert receipt==cert['bundleReceipt']
  replies={('shell','-T','getprop',prop):facts[key]for key,prop in bundle._PROPERTIES}
  replies.update({('shell','-T','id','-u'):'2000',('shell','-T','cat','/proc/sys/kernel/random/boot_id'):'boot',('shell','-T','sh -c '+shlex.quote(bundle._PROCESS_READ)):processes,('shell','-T','pm','path','com.kardinal.vpncontrol'):'package:/data/app/test/base.apk',('shell','-T','sha256sum','/data/app/test/base.apk'):'a'*64+' /data/app/test/base.apk',('shell','-T','pidof','com.kardinal.vpncontrol'):'20',('shell','-T','ps','-A','-o','PID,UID,NAME'):'PID UID NAME\n20 10209 com.kardinal.vpncontrol',('shell','-T','cat','/proc/20/stat'):'20 (app) '+fields})
  reads=[]
  def binary(path,generation,argv,environment,limit,timeout):
   assert argv[:2]==['-s','emulator-5682'] and limit==16384 and timeout==20
   words=tuple(argv[2:]);reads.append(words);return {'returncode':0,'stderrRaw':'','stdoutRaw':replies[words]}
  n={'Path':Path,'ROOT':Path('/retained'),'hashlib':hashlib,'re':re,'BASELINE_BASE64':base64,'COMPONENT_BUNDLE':ExternalReplay(),'COMPONENT_RECEIPT':cert['bundleReceipt'],'CERTIFICATE_PATH':'/retained/certificate.json','CERTIFICATE_RAW':raw,'CERTIFICATE_PIN':pin,'CERTIFICATE':cert,'CERTIFICATE_OBSERVATIONS':[],'GETTER_RECORDS':{},'EXTERNAL':cert['backendBinding'],'command_host_guard':lambda:None,'external_jdk_guard':lambda:None,'command_host_identity':lambda:copy.deepcopy(cert['host']),'getter_stage':lambda:copy.deepcopy(cert['stage']),'getter_generation':lambda path:{'fixed':'generation'},'command_binary':binary,'LAUNCH':{'correlationId':'synthetic','adbPath':'/synthetic-adb','adbFacts':{'generation':[]},'environment':{}}}
  for text in RELEASE_CERTIFICATE_FUNCTION_SOURCES.values():exec(compile(text,'<actual-emitted-certificate>','exec'),n)
  return n,reads
 def test_actual_missing_quote_binding_red_before_fix(self):
  n,reads=self.namespace()
  with self.assertRaises(NameError)as caught:n['certificate_guard']()
  self.assertEqual(caught.exception.name,'SHLEX_HELPER');self.assertEqual(len(reads),7)
 def test_one_quote_binding_full_original_guard_green_and_drift_refuses(self):
  import shlex
  n,reads=self.namespace();n['SHLEX_HELPER']=shlex;n['certificate_guard']();self.assertEqual(len(reads),13)
  n['CERTIFICATE_RAW']=b'foreign'
  with self.assertRaisesRegex(ValueError,'backup_certificate_changed'):n['certificate_guard']()
 def test_recursive_emitted_global_dependency_omission(self):
  import builtins,dis,types,shlex
  n,_=self.namespace()
  def names(code):
   result={i.argval for i in dis.get_instructions(code)if i.opname=='LOAD_GLOBAL'}
   for v in code.co_consts:
    if isinstance(v,types.CodeType):result|=names(v)
   return result
  self.assertEqual(names(n['certificate_guard'].__code__)-n.keys()-vars(builtins).keys(),{'SHLEX_HELPER'})
  n['SHLEX_HELPER']=shlex
  for name in('certificate_guard','certificate_text','certificate_app'):
   self.assertEqual(names(n[name].__code__)-n.keys()-vars(builtins).keys(),set())


class ActualRestorationDependencyClosure(unittest.TestCase):
 def test_actual_protocol_globals_nested_and_annotations_Any_omission(self):
  import builtins,dis,types,json,os,stat,hashlib,re,shlex,subprocess,typing
  from agent_tools.tests.fixtures.android_component_retirement_collectors import RELEASE_RESTORATION_PROTOCOL_SOURCE
  # Exact source executes in its source-declared protocol namespace. expected
  # and binding are the two globals the emitted caller sets after construction.
  n={'json':json,'os':os,'stat':stat,'hashlib':hashlib,'re':re,'shlex':shlex,'subprocess':subprocess,'fixed_run':lambda *a:None,'su_pin':None,'Any':typing.Any,'expected':{},'binding':{}}
  exec(compile(RELEASE_RESTORATION_PROTOCOL_SOURCE,'<actual-restoration-protocol>','exec'),n)
  def used(c):
   result={i.argval for i in dis.get_instructions(c)if i.opname in('LOAD_GLOBAL','LOAD_NAME')}
   for v in c.co_consts:
    if isinstance(v,types.CodeType):result|=used(v)
   return result
  def dependencies():
   result=set()
   for value in n.values():
    if isinstance(value,types.FunctionType)and value.__globals__ is n:
     result|=used(value.__code__)
     annotation=getattr(value,'__annotate__',None)
     if annotation:result|=used(annotation.__code__)
   return result
  self.assertEqual(dependencies()-n.keys()-vars(builtins).keys(),set())
  # Lazy-annotation interpreters need the annotation code included in audit.
  if hasattr(n['parse_installer_metadata_census'],'__annotate__'):
   old=dict(n);old.pop('Any');self.assertEqual(dependencies()-old.keys()-vars(builtins).keys(),{'Any'})
  self.assertIs(n['parse_installer_metadata_census'].__annotations__['return'].__args__[1],typing.Any)


class ActualTerminalSessionDiagnostics(unittest.TestCase):
    """Actual emitted statements, injected failures only; no pass DTO authority."""
    def factories(self):
        from agent_tools.tests.fixtures.android_component_retirement_collectors import SESSION_DIAGNOSTIC_FACTORY,SESSION_FAILURE_FACTORY,SESSION_NATIVE_SOURCE
        import ast
        scope={'ast':ast};exec(SESSION_DIAGNOSTIC_FACTORY+'\n'+SESSION_FAILURE_FACTORY,scope)
        return scope,SESSION_NATIVE_SOURCE
    def test_actual_session_statements_unchanged_except_fixed_stage_assignments(self):
        import ast
        scope,original=self.factories();changed=scope['diagnostic_session_protocol'](original)
        tree=ast.parse(changed)
        class Strip(ast.NodeTransformer):
            def visit_Assign(self,node):
                if ast.dump(node.targets[0]).startswith("Subscript(value=Call(func=Name(id='globals'") and isinstance(node.value,ast.Constant) and str(node.value.value).startswith('session-'):return None
                return self.generic_visit(node)
        self.assertEqual(ast.dump(Strip().visit(tree),include_attributes=False),ast.dump(ast.parse(original),include_attributes=False))
        self.assertEqual(changed.count("globals()['COMPONENT_RELEASE_FAILURE_STAGE']="),16)
    def test_actual_first_statement_old_broad_stage_new_exact_stage(self):
        import ast,json,types,io
        from contextlib import redirect_stdout
        scope,original=self.factories()
        class FailureOnlyBundle:
            def modules(self,receipt):raise TypeError("'NoneType' object is not callable")
        for fixed in(False,True):
            source=scope['diagnostic_session_protocol'](original)if fixed else original
            ns={'COMPONENT_BUNDLE':FailureOnlyBundle(),'COMPONENT_RECEIPT':{},'json':json,'GETTER_RECORDS':{},'BASELINE_REQUEST':{},'COMPONENT_RELEASE_CORRELATION':'unit-only'}
            exec(source,ns)
            from agent_tools.tests.fixtures.android_component_retirement_collectors import OLD_SESSION_FAILURE_FACTORY
            old_scope={'ast':ast};exec(OLD_SESSION_FAILURE_FACTORY,old_scope)
            wrapper=scope['finalized_remote_entry']if fixed else old_scope['finalized_remote_entry']
            wrapped=wrapper("COMPONENT_RELEASE_FAILURE_STAGE='terminal-sessions'\nsession_inventory()\n",())
            buffer=io.StringIO()
            with redirect_stdout(buffer):exec(wrapped,ns)
            result=json.loads(buffer.getvalue());failure=result['primaryFailure']
            self.assertEqual(failure['type'],'TypeError');self.assertEqual(failure['code'],'type_error_nonetype_not_callable'if fixed else None)
            self.assertEqual(failure['stage'],'session-modules'if fixed else'terminal-sessions')
            self.assertIsNone(result['result']);self.assertIsNone(result['capturedResult']);self.assertFalse(result['claimGranted'])
    def test_unknown_private_typeerror_text_never_projected(self):
        import json,io
        from contextlib import redirect_stdout
        scope,_=self.factories();private='private/path/token must not appear'
        wrapped=scope['finalized_remote_entry']("COMPONENT_RELEASE_FAILURE_STAGE='session-protocol-compile'\nraise TypeError(PRIVATE_UNIT_ONLY)\n",())
        ns={'PRIVATE_UNIT_ONLY':private,'json':json,'GETTER_RECORDS':{},'BASELINE_REQUEST':{},'COMPONENT_RELEASE_CORRELATION':'unit-only'};out=io.StringIO()
        with redirect_stdout(out):exec(wrapped,ns)
        self.assertNotIn(private,out.getvalue());self.assertIsNone(json.loads(out.getvalue())['primaryFailure']['code'])


class ActualSessionOriginalRecordTable(unittest.TestCase):
    """Exact producer/FD-reader/consumer; synthetic bytes convey no authority."""
    def boundary(self,mode='fixed'):
        import base64,hashlib,json,os,stat,tempfile,types
        from pathlib import Path
        from agent_tools import android_installer_component_bundle as bundle
        from agent_tools.tests.fixtures import android_component_retirement_collectors as f
        class PrincipalMetadata:
            def __getattr__(self,name):return getattr(os,name)
            def projected(self,value):
                fields={n:getattr(value,n)for n in dir(value)if n.startswith('st_')};fields.update(st_uid=0,st_gid=0);return types.SimpleNamespace(**fields)
            def fstat(self,fd):return self.projected(os.fstat(fd))
            def stat(self,*a,**k):return self.projected(os.stat(*a,**k))
            def lstat(self,*a,**k):return self.projected(os.lstat(*a,**k))
        actor=types.ModuleType('held_session_table_fixture');actor.__file__=bundle.__file__
        exec(compile(Path(bundle.__file__).read_bytes(),bundle.__file__,'exec'),actor.__dict__)
        proxy=PrincipalMetadata();actor.os=proxy
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            job=root/'android-installer-0dd55704-1e80-4d62-8d9d-2f0a123e0c3b';(job/'output').mkdir(parents=True,mode=0o700);job.chmod(0o700)
            path=job/'output/intent.json';path.write_bytes(b'{"kind":"source-shaped-test-intent"}');path.chmod(0o600)
            ns={'COMPONENT_BUNDLE':actor,'os':proxy,'stat':stat,'json':json,'hashlib':hashlib,'BASELINE_BASE64':base64,'COMPONENT_RETIRE_RAW_INDEX':{},'COMPONENT_RETIRE_RAW_RECORDS':[],'CLAIM_OBSERVATIONS':[],'job':job}
            exec(f.SESSION_TABLE_RECORD_RAW_SOURCE+'\n'+f.NATIVE_CLOSURE_CLAIM_RECORD_SOURCE,ns)
            exec(f.SESSION_TABLE_OLD_PRODUCER if mode=='old'else f.SESSION_TABLE_FIXED_PRODUCER,ns)
            # This earlier guarded read is separate from the subsequent fresh
            # consumer read. No fresh observation is assigned to both sides.
            ns['retained']={'output/intent.json':ns['claim_record'](path)}
            if mode!='old':exec(f.SESSION_TABLE_GUARDED_SEED,ns)
            if mode=='missing':ns['READINESS_ORIGINAL_RECORDS'].clear()
            if mode=='type':ns['READINESS_ORIGINAL_RECORDS']=[]
            if mode=='drift':path.write_bytes(b'{"kind":"changed-test-intent"}')
            exec(f.SESSION_TABLE_READER_CALL,ns)
            self.assertEqual(ns['original']['state'],'present')
            exec(f.SESSION_TABLE_LOOKUP,ns)
            self.assertEqual(ns['original'],ns['retained']['output/intent.json'])
            self.assertEqual(len(ns['COMPONENT_RETIRE_RAW_RECORDS']),1)
            return {'priorReadIndependent':True,'tableEntries':len(ns['READINESS_ORIGINAL_RECORDS'])}
    def test_actual_old_producer_real_read_then_typeerror(self):
        with self.assertRaisesRegex(TypeError,'list indices must be integers'):self.boundary('old')
    def test_fixed_guarded_prior_read_and_fresh_consumer(self):
        self.assertEqual(self.boundary(),{'priorReadIndependent':True,'tableEntries':1})
    def test_missing_type_and_fresh_record_drift_refuse(self):
        for mode,kind in [('missing',KeyError),('type',TypeError),('drift',ValueError)]:
            with self.subTest(mode=mode):
                with self.assertRaises(kind):self.boundary(mode)
