"""Receipt-bound first READY and original SDK topology; no channel creation."""
from pathlib import Path
from contextlib import ExitStack
import hashlib,json,os,subprocess,time,uuid
from agent_tools import native_review_source_closure as closure
from agent_tools import ssh_channel_keeper_entry as entry
from agent_tools import private_inventory_lock as private
from agent_tools import ssh_channel_keeper as core
from agent_tools.ssh_keeper_process_owner import save,load,clean_environment
ROOT=Path(__file__).resolve().parents[1]
SERVER_SHA="5298fca440b8c6a0bf1ea49b8df06f88e13a24d425f358cecebd298c28d2a52d"
def producer_actor(pid):
 # Exact reviewed relay producer format: SHA of raw uid+lstart stdout.
 if type(pid)is not int or pid<=0:raise ValueError('sdk_actor_schema')
 r=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=','-o','lstart='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,env={**clean_environment(ROOT),'LC_ALL':'C'},check=False)
 if r.returncode or r.stderr or not r.stdout.split() or r.stdout.split()[0]!=str(os.getuid()).encode():raise ValueError('sdk_actor_unproved')
 return {'pid':pid,'uid':os.getuid(),'sessionId':os.getsid(pid),'birthSha256':hashlib.sha256(r.stdout).hexdigest()}

def parent_pid(pid):
 if type(pid)is not int or pid<=0:raise ValueError('sdk_actor_schema')
 r=subprocess.run(['/bin/ps','-p',str(pid),'-o','ppid='],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,env={**clean_environment(ROOT),'LC_ALL':'C'},check=False)
 if r.returncode or r.stderr or not r.stdout.strip().isdigit():raise ValueError('sdk_lineage_unproved')
 return int(r.stdout.strip())

def typed_equal(a,b):return json.dumps(a,sort_keys=True,separators=(',',':'))==json.dumps(b,sort_keys=True,separators=(',',':'))

def consumer_actors(sdk,keeper):
 """Recheck both original normalized actors, after upstream SDK custody admission.

 This is an identity selector only. It earns no ancestry, freshness or channel
 authority and intentionally makes no equal-birth/session assumption.
 """
 for original in (sdk,keeper):
  if type(original)is not dict or set(original)!={'pid','uid','sessionId','birthSha256'} or any(type(original[k])is not int or original[k]<0 for k in ('pid','uid','sessionId')) or original['pid']<=0 or type(original['birthSha256'])is not str or len(original['birthSha256'])!=64 or any(ch not in '0123456789abcdef' for ch in original['birthSha256']):raise ValueError('consumer_actor_schema')
 for original in (sdk,keeper):
  if not typed_equal(entry.actor(original['pid']),original):raise ValueError('consumer_original_actor')
 return None

class SDKCustody:
 """Original immutable SDK request, relay/server producer actors and ancestry.

 Numeric ancestry is joined to both producer-defined actor formats. No session
 equality across the SDK's intentional start_new_session boundary is assumed.
 """
 def __init__(self,session,corr,receipt,digest,sdk,pipeline,launch):
  self.stack=ExitStack();self.sdk=sdk;self.pipeline=pipeline;self.launch=launch
  try:
   self.directory=self.stack.enter_context(private.Directory(session))
   self.client=self.stack.enter_context(private.Snapshot(self.directory,'client-intent.json'))
   self.server=self.stack.enter_context(private.Snapshot(self.directory,'server-intent.json'))
   self.records=[self.client,self.server]
   request={'action':'connection-channel-keep','host':'archlinux','timeout_seconds':1800,'identity':{'correlationId':corr,'receiptSha256':receipt,'sourceManifestSha256':digest}}
   expected={'mode':'call_once','request':request,'clientPid':sdk['pid'],'sourceSha256':SERVER_SHA,'sdkVersion':'1.29.1','automaticReplay':False}
   if not typed_equal(load(self.client.body),expected):raise ValueError('sdk_client_intent_binding')
   self.server_value=load(self.server.body)
   if type(self.server_value)is not dict or set(self.server_value)!={'schema','serverActor','relayActor','sourceSha256','action','automaticReplay'} or not typed_equal({k:v for k,v in self.server_value.items() if k not in ('serverActor','relayActor')},{'schema':1,'sourceSha256':SERVER_SHA,'action':'serve','automaticReplay':False}):raise ValueError('sdk_server_intent_binding')
   for name in ('serverActor','relayActor'):
    actor=self.server_value[name]
    if type(actor)is not dict or set(actor)!={'pid','uid','sessionId','birthSha256'} or any(type(actor[k])is not int or actor[k]<0 for k in ('pid','uid','sessionId')) or actor['pid']<=0 or type(actor['birthSha256'])is not str:raise ValueError('sdk_actor_schema')
   self.guard()
  except BaseException:self.stack.close();raise
 def __enter__(self):return self
 def __exit__(self,*args):self.stack.close()
 def guard(self,local=None):
  for original in (self.sdk,self.pipeline,self.launch):
   if not typed_equal(entry.actor(original['pid']),original):raise ValueError('sdk_original_birth')
  server=self.server_value['serverActor'];relay=self.server_value['relayActor']
  for original in (server,relay):
   if not typed_equal(producer_actor(original['pid']),original):raise ValueError('sdk_producer_birth')
  if relay['sessionId']!=relay['pid'] or server['sessionId']!=relay['sessionId'] or parent_pid(server['pid'])!=relay['pid'] or parent_pid(relay['pid'])!=self.sdk['pid'] or parent_pid(self.sdk['pid'])!=self.pipeline['pid'] or parent_pid(self.pipeline['pid'])!=self.launch['pid'] or self.sdk['sessionId']!=self.pipeline['sessionId'] or self.pipeline['sessionId']!=self.launch['sessionId']:raise ValueError('sdk_original_lineage')
  if local is not None:
   if not typed_equal(entry.actor(local['pid']),local) or local['uid']!=self.sdk['uid'] or local['sessionId']!=relay['sessionId'] or parent_pid(local['pid'])!=server['pid']:raise ValueError('sdk_keeper_lineage')
  self.client.guard();self.server.guard()

def retain_first_ready_refusal(output,corr,receipt,actor,exc,guard,emit):
 # No message/path or inferred historical exception is published.
 names={'sdk_client_intent_binding','sdk_server_intent_binding','sdk_actor_schema','sdk_actor_unproved','sdk_lineage_unproved','sdk_original_birth','sdk_producer_birth','sdk_original_lineage','sdk_keeper_lineage','keeper_original_actor','keeper_first_query_terminal','keeper_first_ready','keeper_first_ready_freshness','keeper_intent_binding','keeper_original_terminal','keeper_first_query_absent','keeper_receipt_binding'}
 reason=str(exc) if type(exc)is ValueError and str(exc)in names else 'unclassified'
 value={'stage':'FIRST_READY_REFUSED','state':'unknown','correlationId':corr,'receiptSha256':receipt,'sdkActor':actor,'reason':reason,'exceptionClass':type(exc).__name__ if type(exc)in (ValueError,OSError,FileNotFoundError,KeyError,TypeError) else 'Exception','nativeActionAllowed':False,'replayAllowed':False}
 save(output/'first-ready-refusal.json',value)
 with private.Directory(output) as directory:
  with private.Snapshot(directory,'first-ready-refusal.json') as record:
   entry.close_records([record],guard,source_holders=(guard.holder,));emit(value)
   entry.close_records([record],guard,source_holders=(guard.holder,))

def first_ready(root,corr,receipt,digest,p,start,client_actor,guard,*,clock=time.time,sleep=time.sleep,emit=lambda v:print(json.dumps(v,sort_keys=True),flush=True),custody=None,custody_factory=None):
 compact=uuid.UUID(corr).hex;output=entry.output_path(root,compact)
 for _ in range(200):
  if p.poll()is not None:raise ValueError('keeper_first_query_terminal')
  try:
   with ExitStack() as stack:
    active_custody=custody
    if active_custody is None and custody_factory is not None:active_custody=stack.enter_context(custody_factory())
    directory=stack.enter_context(private.Directory(output))
    intent=stack.enter_context(private.Snapshot(directory,'intent.json'))
    query=stack.enter_context(private.Snapshot(directory,'query-0000.json'))
    i=load(intent.body);q=load(query.body)
    expected={'correlationId':compact,'receiptSha256':receipt,'sourceManifestSha256':digest,'sourceSha256':core.SOURCE_SHA,'remoteSourceSha256':core.REMOTE_SHA,'action':'same_channel_readonly_status','durationSeconds':1800,'intervalSeconds':15,'maxIntervalSeconds':20,'newConnectionAllowed':False,'applicationReplayAllowed':False,'nativeActionAllowed':False}
    if any(type(i.get(k))is not type(v) or i.get(k)!=v for k,v in expected.items()):raise ValueError('keeper_intent_binding')
    local=i['localActor']
    if active_custody is None:
     if entry.actor(local['pid'])!=local or local['uid']!=client_actor['uid'] or local['sessionId']!=client_actor['sessionId'] or entry.actor(p.pid)!=client_actor:raise ValueError('keeper_original_actor')
    else:
     if not typed_equal(active_custody.sdk,client_actor) or p.pid!=client_actor['pid']:raise ValueError('keeper_original_actor')
     active_custody.guard(local)
    if q.get('correlationId')!=compact or q.get('receiptSha256')!=receipt or q.get('state')!='ready' or q.get('stopReason')is not None or q.get('status')!={'state':'ready'} or q.get('nativeActionAllowed')is not False or q.get('newConnectionAllowed')is not False or q.get('applicationReplayAllowed')is not False:raise ValueError('keeper_first_ready')
    if type(q.get('elapsedSeconds'))not in (int,float) or not 0<=q['elapsedSeconds']<20 or not 0<=clock()-start<20:raise ValueError('keeper_first_ready_freshness')
    receipt_guard=core.bind_receipt(root,compact,receipt,stack)
    journal=stack.enter_context(private.Directory(core.channel._journal(root,False)))
    original_intent=stack.enter_context(private.Snapshot(journal,compact+'.intent.json'));original_ready=stack.enter_context(private.Snapshot(journal,compact+'.ready.json'))
    if original_ready.digest!=receipt:raise ValueError('keeper_receipt_binding')
    source=entry.SourceGuard(root,compact,digest);stack.callback(source.close)
    # External source population joins private original receipt/output closure.
    def all_sources():
     if active_custody is not None:active_custody.guard(local)
     guard();source.guard()
    records=[intent,query,original_intent,original_ready]+([] if active_custody is None else active_custody.records)
    entry.close_records(records,all_sources,receipt_guard,source_holders=(source.held,guard.holder))
    if p.poll()is not None or entry.actor(p.pid)!=client_actor or entry.actor(local['pid'])!=local:raise ValueError('keeper_original_terminal')
    all_sources();entry.close_records(records,all_sources,receipt_guard,source_holders=(source.held,guard.holder))
    value={'stage':'FIRST_READY','correlationId':corr,'receiptSha256':receipt,'sourceManifestSha256':digest,'keeperStartedEpoch':start,'keeperPid':local['pid'],'sdkActor':client_actor,'remaining':start+1800-clock(),'freshReadyObservationOnly':True,'nativeActionAllowed':False,'replayAllowed':False}
    emit(value)
    entry.close_records(records,all_sources,receipt_guard,source_holders=(source.held,guard.holder))
    return value
  except FileNotFoundError:sleep(.1)
 raise ValueError('keeper_first_query_absent')
