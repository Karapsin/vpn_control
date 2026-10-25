"""Whole retained parent pipeline/child with real detached public counter.

Only normal-facade REPLY fixtures are injected. Public controllers and frontend
loss use actual subprocesses, durable owners, streams and kernel generations.
No VM, input, credential, lease assertion or host setting operation occurs.
"""
import ast,base64,hashlib,json,os,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest import mock
ROOT=Path(__file__).resolve().parents[2];FIXTURE=Path(__file__).parent/'fixtures/tart_macos_parent_budget'
PROJECT=ROOT;sys.path.insert(0,str(ROOT))
from agent_tools import durable_remote_job as J,private_inventory_lock as P,readiness_tart_macos_registry as R
BASE=FIXTURE;OLD=FIXTURE/'parent.before.source';NEW=FIXTURE/'parent.current.source'
EXPECTED={'parent.before.source': '6e835dfd6fc979a2b6cb2884030a34e22efed5122bb1356636d4d85d73798ce2', 'parent.current.source': '0d5899a0556ce96278ca6e8b32415d15a1edbce565b0d531f356c1b4310590f7', 'public.current.source': 'cc06ec0d0144d7fed7a64bc024daddcb2730738049cb7af0efee5a703f3a3028'}
for name,digest in EXPECTED.items():assert hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest()==digest
def nodes(raw,names):return[n for n in ast.walk(ast.parse(raw))if isinstance(n,ast.FunctionDef)and n.name in names]
def pipeline(raw):
 top=next(n for n in ast.parse(raw).body if isinstance(n,ast.With))
 index=next(i for i,n in enumerate(top.body)if isinstance(n,ast.Try)and any(isinstance(a,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='acquire_mono'for t in a.targets)for a in n.body))
 return top.body[index:]
RESULTS=[]
class Checks(unittest.TestCase):
 def exercise(self,current,mode):
  with tempfile.TemporaryDirectory(prefix='parent-lostack-')as temporary:
   folder=Path(temporary).resolve();folder.chmod(0o700);jobroot=folder/'jobs';jobroot.mkdir(mode=0o700)
   source=(NEW if current else OLD).read_bytes();binding=J.current_binding('controlled-explicit-vm','controlled-host');generation=J.root_generation(jobroot)
   operation='07110b57-2828-4f20-a0cc-b8caea05c334';lease='847bc27d-4436-4a16-8d81-e79e2808801a';wake='084e1c45-0468-58ca-9922-71a5fb523d73'
   marker=folder/'executed-once';public_folder=folder/('native-v12-public136-'+operation)
   complete={'operationId':operation,'checks':136,'ordinaryCredentialReaderOpened':False,'observerJobsStarted':False,'genericGuiCapabilityEnabled':False}
   program_source=("import os,time,pathlib,json\n"+f"p=pathlib.Path({str(marker)!r});fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'one');os.close(fd)\n"+"print('counter-start',flush=True)\nfor i in range(12):\n print(i,flush=True);time.sleep(.04)\n"+f"p=pathlib.Path({str(public_folder)!r});p.mkdir(mode=0o700);(p/'complete.json').write_text({json.dumps(complete)!r})\n"+"print('counter-end',flush=True)\n").encode()
   program=J.Program('native_macos_public136_v12',program_source,262144)
   cap=types.ModuleType('held_capture');exec(compile((Path(__file__).parent/'fixtures/tart_macos_parent_recovery/sources/capture.source').read_bytes(),str(BASE/'sources/capture.source'),'exec'),cap.__dict__)
   original_capture=cap.PublicRpcCapture
   class Accelerated(original_capture):
    def run(self,argv,payload,*,deadline,**kw):
     deadline-=clock.offset # translate virtual parent clock to actual local subprocess deadline
     if(argv[-1]=='start'and mode=='lost_ack')or(argv[-1]=='status'and mode=='status_ack_lost'and helper_actions.count('status')==0)or(argv[-1]=='collect'and mode=='collect_ack_lost'and helper_actions.count('collect')==0):deadline=min(deadline,time.monotonic()+.2)
     return super().run(argv,payload,deadline=deadline,**kw)
   cap.PublicRpcCapture=Accelerated
   class Clock:
    offset=0.0
    def monotonic(self):return time.monotonic()+self.offset
    def time(self):return time.time()+self.offset
    def sleep(self,n):time.sleep(n)
   clock=Clock()
   facade_calls=[];helper_actions=[];children=[];first_frontend={'pid':None};cancelled={'value':False};cleanup_statuses={'count':0}
   def value(state,**extra):
    native='unknown'if state=='starting'else state
    reason={'active':'original_lease_owner_running','starting':'original_owner_running','expired':'lease_deadline_reached','cancelled':'original_lease_cancelled','unknown':'original_lease_cancelled'}[state]
    v={'schemaVersion':1,'fixtureId':'controlled-v12','operationId':lease,'provider':'tart-macos','qualificationScope':'registered_guest_executor','ok':True,'state':state,'nativeState':native,'jobState':'terminal'if state in{'expired','cancelled'}else'running','reason':reason,'replayAllowed':False,'nextAction':'none'if state in{'expired','cancelled'}else'observe_original'}
    if state in{'expired','cancelled'}:v['restored']=True
    v.update(extra);return v
   def facade(action):
    facade_calls.append(action)
    if action=='acquire':
     if mode=='external':raise RuntimeError('SYNTHETIC_UNEXPECTED_MESSAGE')
     if mode in{'delay_ack','insufficient'}:
      clock.offset+=65.665867 if mode=='delay_ack' else 151.0
      return value('unknown',nativeState='unknown',jobState='unknown',reason='original_owner_ack_pending',nativeReason='record_unavailable')
     if mode=='ack_pending':return value('unknown',nativeState='unknown',jobState='unknown',reason='original_owner_ack_pending',nativeReason='record_unavailable')
     return value('starting'if mode=='starting'else'active')
    if action=='cancel':
     cancelled['value']=True
     if mode=='restore_pending':return value('unknown',nativeState='restore_pending',restored=True)
     return value('cancelled')
    if mode in{'starting','ack_pending','delay_ack','insufficient'}and not scope['public_attempted']:return value('active')
    if mode=='restore_pending'and cancelled['value']:
     cleanup_statuses['count']+=1
     if cleanup_statuses['count']<2:return value('unknown',nativeState='restore_pending',restored=True)
     return value('cancelled')
    if mode in{'missing_actor','unsubmitted'}:
     cleanup_statuses['count']+=1
     return value('expired'if cleanup_statuses['count']>=2 else'active')
    # A lostACK before the fix exits phase without observing the controller;
    # accelerated natural expiry is returned, never a new acquisition.
    if not current and mode=='lost_ack':return value('expired')
    return value('active')
   def need(v,r):
    if not v:raise RuntimeError(r)
   def wake_call():
    path=folder/('native-known-session-wake-'+wake);path.mkdir(mode=0o700)
    (path/'complete.json').write_text(json.dumps({'operationId':wake,'after':{'display':'ready','console':{'uid':502,'locked':True}},'ordinaryCredentialReaderOpened':False}))
   with P.Directory(folder)as out:
    scope={'time':clock,'json':json,'os':os,'sys':sys,'base64':base64,'hashlib':hashlib,'J':J,'R':R,'capture':cap,'out':out,'guard':lambda:None,'need':need,
      'sources':types.SimpleNamespace(),'descriptor':{},'args':types.SimpleNamespace(target='tart:explicit-controlled'),'FIXTURE':'controlled-v12','LEASE':lease,'PUBLIC':operation,'PARENT':'controlled-parent','WAKE':wake,
      'PROJECT':PROJECT,'directory':types.SimpleNamespace(path=BASE),'CHILD_FILE':'controlled-client.py','CHILD_SHA':'controlled','record':None,'deadline':clock.monotonic()+600,'sequence':0,'native_callbacks':[],'helper_callbacks':[],'capture_attempts':[],
      'cleanup':None,'public_collected':None,'acquired':False,'cancelled':False,'wake_attempted':False,'public_attempted':False,'phase_failure':None,'jobroot':jobroot,'binding':binding,'generation':generation,'lifecycle':folder,
      'acquire_mono':None,'acquire_wall':None,'facade':facade,'wake_with_held_session':wake_call,'closure':lambda:{'controlled_source_closure':True},'original_evidence':lambda:{'controlled_original_terminal_restored':True}}
    names={'need','record','label','join_capture','attempt_closed','capture_closure','active','terminal','observing','remaining','child','read_public','public_terminal_status','public_closed_for_cancel'}
    setup=[node for node in ast.parse(source).body if isinstance(node,ast.ClassDef)and node.name=='ParentGuard'or isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id in{'_PARENT_GUARD_CODES','_PARENT_STAGES','pipeline_phase'}for t in node.targets)]
    exec(compile(ast.Module(body=setup,type_ignores=[]),str(NEW if current else OLD),'exec'),scope)
    exec(compile(ast.Module(body=nodes(source,names),type_ignores=[]),str(NEW if current else OLD),'exec'),scope)
    real_popen=subprocess.Popen;real_birth=J._birth
    def launch(argv,**kw):
     if not(len(argv)>2 and argv[2].endswith('controlled-client.py')):return real_popen(argv,**kw)
     action=argv[-1];helper_actions.append(action)
     common="import sys,pathlib,json,base64,time;sys.path.insert(0,"+repr(str(PROJECT))+");from agent_tools import durable_remote_job as J;root=pathlib.Path("+repr(str(jobroot))+");binding=J.MachineBinding.from_dict("+repr(binding.__dict__)+");generation="+repr(generation)+";op="+repr(operation)+";"
     if action=='start':
      code=common
      if mode!='unsubmitted':code+="p=J.Program("+repr(program.purpose)+",base64.b64decode("+repr(base64.b64encode(program.source).decode())+"),262144);result=J.submit(root,op,binding,p,generation=generation);"
      else:code+="result=J.observe(root,op,binding,generation=generation);"
      code+="print(json.dumps({'status':result,'replayAllowed':False}),flush=True);"
      if mode=='lost_ack':code+='time.sleep(30);'
     elif action=='status':code=common+"print(json.dumps({'status':J.observe(root,op,binding,generation=generation),'replayAllowed':False}),flush=True)"
     else:code=common+"s,o,e=J.collect(root,op,binding,generation=generation);print(json.dumps({'status':s,'stdout':base64.b64encode(o).decode(),'stderr':base64.b64encode(e).decode(),'replayAllowed':False}),flush=True)"
     if(action=='status'and mode=='status_ack_lost'and helper_actions.count('status')==1)or(action=='collect'and mode=='collect_ack_lost'and helper_actions.count('collect')==1):code+=';time.sleep(30)'
     child=real_popen([sys.executable,'-B','-c',code],**kw);children.append(child)
     if action=='start':first_frontend['pid']=child.pid
     return child
    def birth(pid):
     if mode=='missing_actor'and pid==first_frontend['pid']:return None
     return real_birth(pid)
    failure=None
    try:
     with mock.patch.object(subprocess,'Popen',launch),mock.patch.object(J,'_birth',birth):
      try:exec(compile(ast.Module(body=pipeline(source),type_ignores=[]),str(NEW if current else OLD),'exec'),scope)
      except BaseException as error:failure=type(error).__name__
    finally:
     for child in children:
      if child.poll()is None:child.kill();child.wait()
     # No fixture/controller is left active on test failure.
     stop=time.monotonic()+3
     while (jobroot/operation).exists()and time.monotonic()<stop:
      status=J.observe(jobroot,operation,binding,generation=generation)
      if status['state']=='terminal'and J._birth(status['owner']['pid'])!=status['owner']['birth']:break
      time.sleep(.02)
    records={p.name:json.loads(p.read_bytes())for p in folder.glob('*.json')if p.name not in{'complete.json'}and p.stat().st_size and p.name.endswith(('.attempt.json','closure.json'))}
    phase_record=json.loads((folder/'phase-unknown.json').read_bytes())if(folder/'phase-unknown.json').exists()else None
    RESULTS.append({'current':current,'mode':mode,'failureClass':failure,'phaseRecord':phase_record,'acquireCount':facade_calls.count('acquire'),'cancelCount':facade_calls.count('cancel'),'startCount':helper_actions.count('start'),'publicCollected':scope['public_collected']is not None,'counterOnce':marker.exists(),'allControlledChildrenExited':all(c.poll()is not None for c in children),'allCaptureAttemptsClosed':scope['capture_closure']()['allAttemptsClosed']})
    return {'phaseRecord':json.loads((folder/'phase-unknown.json').read_bytes())if(folder/'phase-unknown.json').exists()else None,'failure':failure,'scope':scope,'facadeCalls':facade_calls,'helperActions':helper_actions,'records':records,'marker':marker.read_bytes()if marker.exists()else None}
 def test_authentic65s_ack_interval_old180_blocked_new300_one_acquire_green(self):
  old=self.exercise(False,'delay_ack');self.assertIsNotNone(old['failure']);self.assertIsNone(old['scope']['public_collected']);self.assertEqual(old['helperActions'],[]);self.assertEqual(old['phaseRecord']['failureClass'],'RuntimeError');self.assertNotIn('guardReason',old['phaseRecord'])
  new=self.exercise(True,'delay_ack');self.assertIsNone(new['failure']);self.assertIsNotNone(new['scope']['public_collected']);self.assertEqual(new['facadeCalls'].count('acquire'),1);self.assertEqual(new['facadeCalls'].count('cancel'),1);self.assertEqual(new['helperActions'].count('start'),1);self.assertEqual(new['marker'],b'one')
 def test_insufficient_remaining_still_refuses_with_finite_reason_before_cleanup(self):
  new=self.exercise(True,'insufficient');self.assertIsNotNone(new['failure']);self.assertEqual(new['helperActions'],[]);self.assertEqual(new['phaseRecord']['failureClass'],'ParentGuard');self.assertEqual(new['phaseRecord']['guardReason'],'parent_lease_active_or_budget_blocked');self.assertEqual(new['phaseRecord']['guardStage'],'lease_observe');self.assertEqual(new['facadeCalls'].count('acquire'),1);self.assertEqual(new['facadeCalls'].count('cancel'),1)
 def test_non_parent_exception_stays_class_only_unknown(self):
  new=self.exercise(True,'external');self.assertIsNotNone(new['failure']);self.assertEqual(new['phaseRecord']['failureClass'],'RuntimeError');self.assertNotIn('guardReason',new['phaseRecord']);self.assertNotIn('guardStage',new['phaseRecord']);self.assertNotIn('SYNTHETIC_UNEXPECTED_MESSAGE',json.dumps(new['phaseRecord']));self.assertEqual(new['helperActions'],[])
 def test_guard_allowlist_exact_and_unrecognized_text_not_retained(self):
  raw=NEW.read_bytes();tree=ast.parse(raw);setup=[node for node in tree.body if isinstance(node,ast.ClassDef)and node.name=='ParentGuard'or isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id in{'_PARENT_GUARD_CODES','_PARENT_STAGES','pipeline_phase'}for t in node.targets)]
  scope={};exec(compile(ast.Module(body=setup+nodes(raw,{'need'}),type_ignores=[]),str(NEW),'exec'),scope)
  codes={node.args[1].value for node in ast.walk(tree)if isinstance(node,ast.Call)and isinstance(node.func,ast.Name)and node.func.id=='need'};self.assertEqual(codes,scope['_PARENT_GUARD_CODES'])
  scope['pipeline_phase']='UNRECOGNIZED_STAGE'
  with self.assertRaises(scope['ParentGuard'])as caught:scope['need'](False,'SYNTHETIC_UNEXPECTED_MESSAGE')
  self.assertEqual(caught.exception.reason,'unclassified_parent_guard');self.assertEqual(caught.exception.stage,'unknown_phase');self.assertNotIn('SYNTHETIC_UNEXPECTED_MESSAGE',str(caught.exception))
 def test_public_strict_admission300_and_normal_caps_remain180_30(self):
  raw=(FIXTURE/'public.current.source').read_text();self.assertIn("lease_value['ttlSeconds']==300",raw);self.assertIn('deadline=time.monotonic()+180',raw);self.assertIn('timeout=30',raw)
  parent=NEW.read_text();self.assertIn("'stockFacadeSeparateLockBudgetSeconds':180",parent);self.assertIn("'stockFacadeSeparateExecutorBudgetSeconds':180",parent);self.assertIn("remaining()>=150",parent);self.assertIn("remaining()>=100",parent)
if __name__=='__main__':unittest.main(verbosity=2)
