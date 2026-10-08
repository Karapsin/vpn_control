"""Receipt-bound readonly observation core; fixed source guard is supplied by owner.

No MCP/CLI dispatch, launch, renewal or implicit retry is supplied here.
The caller must retain actual source ownership through the owning child.
"""
import hashlib,json,re,time
from pathlib import Path
from contextlib import ExitStack
from . import ssh_fresh_nested_channel as original,private_inventory_lock as private
from .check_output_retention import retain_observation_capture

channel=original
from .ssh_channel_inventory_diagnostics import is_busy,retain
SOURCE_SHA=original._source();REMOTE_SHA=hashlib.sha256(original._REMOTE.encode()).hexdigest()
INTERVAL_SECONDS=15;MAX_INTERVAL_SECONDS=20;DURATION_SECONDS=1800;MAX_QUERIES=120
def _keep_bound(root,corr,receipt,retain,publish,guard,clock=time.monotonic,sleep=time.sleep,*,retain_inventory=None):
 channel._corr(corr)
 if not isinstance(receipt,str) or re.fullmatch('[0-9a-f]{64}',receipt) is None:raise ValueError('receipt')
 started=clock();count=0;stop='duration';last='unobserved';last_query_start=None
 for index in range(MAX_QUERIES):
  target=started+index*INTERVAL_SECONDS
  remaining=target-clock()
  if remaining>0:sleep(remaining)
  now=clock()
  if now-started>=DURATION_SECONDS:break
  try:guard()
  except (OSError,ValueError):stop='source_changed';break
  query_start=clock()
  if query_start-started>DURATION_SECONDS-35:stop='duration';break
  if last_query_start is not None and query_start-last_query_start>MAX_INTERVAL_SECONDS:stop='late_query';break
  last_query_start=query_start
  captured=[];capture_failed=[False];inventory=[];inventory_failed=[False]
  def capture(raw):
   try:retain(index,raw)
   except (OSError,ValueError):capture_failed[0]=True;raise
   captured.append({key:raw[key] for key in ('pid','returnCode','complete','counts','eof','timeout','overflow','readError')})
  def diagnostic(event):
   try:inventory.append(retain_inventory(index,event))
   except (OSError,ValueError,TypeError):inventory_failed[0]=True;raise
  result=channel.status(root,'archlinux',corr,_private_capture=capture,_private_inventory_diagnostic=diagnostic);count+=1
  try:guard()
  except (OSError,ValueError):stop='source_changed';break
  last=result.get('state','unknown')
  if capture_failed[0] or inventory_failed[0]:stop='capture_retention'
  elif last=='unknown':stop=None if result.get('failurePhase')=='inventory' and not captured and is_busy(inventory) else 'unknown'
  elif last=='ended':stop='ended'
  elif last!='ready' or result.get('correlationId')!=corr or result.get('receiptSha256')!=receipt:stop='receipt_mismatch'
  elif clock()-query_start>=MAX_INTERVAL_SECONDS:stop='late_query'
  else:stop=None
  status=channel.validated_unknown({**result,'correlationId':result.get('correlationId',corr)}) if last=='unknown' else {'state':last}
  try:publish(index,{'correlationId':corr,'receiptSha256':receipt,'state':last,'status':status,'transport':captured,'inventoryDiagnostics':inventory,'inventoryRetentionFailed':inventory_failed[0],'elapsedSeconds':clock()-started,'stopReason':stop,'nativeActionAllowed':False,'newConnectionAllowed':False,'applicationReplayAllowed':False})
  except (OSError,ValueError):stop='capture_retention';break
  try:guard()
  except (OSError,ValueError):stop='source_changed';last='unknown';break
  if stop is not None:break
 try:guard()
 except (OSError,ValueError):stop='source_changed';last='unknown'
 return {'correlationId':corr,'receiptSha256':receipt,'queryCount':count,'lastState':last,'stopReason':stop or 'duration','durationLimitSeconds':DURATION_SECONDS,'intervalSeconds':INTERVAL_SECONDS,'maxIntervalSeconds':MAX_INTERVAL_SECONDS,'nativeActionAllowed':False,'newConnectionAllowed':False,'applicationReplayAllowed':False}

def bind_receipt(root,corr,receipt,stack):
 channel._corr(corr)
 if original._source()!=SOURCE_SHA:raise ValueError('provider_source_changed')
 if type(receipt)is not str or re.fullmatch('[0-9a-f]{64}',receipt)is None:raise ValueError('receipt_binding')
 directory=stack.enter_context(private.Directory(channel._journal(Path(root).resolve(strict=True),False)))
 intent=stack.enter_context(private.Snapshot(directory,corr+'.intent.json'))
 ready=stack.enter_context(private.Snapshot(directory,corr+'.ready.json'))
 if ready.digest!=receipt:raise ValueError('receipt_binding')
 record=json.loads(ready.body,object_pairs_hook=channel.transport._reject_duplicate_keys)
 value=json.loads(intent.body,object_pairs_hook=channel.transport._reject_duplicate_keys)
 if type(record)is not dict or set(record)!={'intent','result'}:raise ValueError('receipt_binding')
 pin=record['intent'];actual=intent.pin()
 if type(pin)is not dict or set(pin)!=set(actual)or type(pin['generation'])is not list or len(pin['generation'])!=9 or any(type(x)is not int for x in pin['generation'])or type(pin['size'])is not int or type(pin['sha256'])is not str or pin!=actual:raise ValueError('receipt_binding')
 if type(value)is not dict or value.get('correlationId')!=corr or value.get('sourceSha256')!=SOURCE_SHA or value.get('remoteSourceSha256')!=REMOTE_SHA:raise ValueError('receipt_binding')
 result=record['result']
 if type(result)is not dict or set(result)!={'state','correlationId','master','arch','controlPath'}or result['state']!='ready'or result['correlationId']!=corr or result['controlPath']!='/tmp/vpn-channel-'+corr+'/m'or not channel._master_shape(result['master']):raise ValueError('receipt_binding')
 if type(result['arch'])is not dict or set(result['arch'])!={'uid','boot'}or type(result['arch']['uid'])is not int or result['arch']!={'uid':channel.EXPECTED_UID,'boot':channel.EXPECTED_BOOT}:raise ValueError('receipt_binding')
 def close():directory.guard();intent.guard();ready.guard();directory.guard();intent.guard();ready.guard()
 close();return close


def bound_keep(root,corr,receipt,retain,publish,guard,clock=time.monotonic,sleep=time.sleep,*,retain_inventory=None):
 with ExitStack() as stack:
  try:receipt_guard=bind_receipt(root,corr,receipt,stack)
  except (OSError,ValueError,KeyError,TypeError):
   return {'correlationId':corr,'receiptSha256':receipt,'queryCount':0,'lastState':'unobserved','stopReason':'receipt_binding','durationLimitSeconds':DURATION_SECONDS,'intervalSeconds':INTERVAL_SECONDS,'maxIntervalSeconds':MAX_INTERVAL_SECONDS,'newConnectionAllowed':False,'applicationReplayAllowed':False}
  def bound_guard():
   guard()
   if original._source()!=SOURCE_SHA:raise ValueError('provider_source_changed')
   receipt_guard()
   guard()
  return _keep_bound(root,corr,receipt,retain,publish,bound_guard,clock,sleep,retain_inventory=retain_inventory)


def keep(root,corr,receipt,output,publish,source_guard,clock=time.monotonic,sleep=time.sleep):
 if not callable(source_guard):raise TypeError("source_guard_required")
 retain_inventory=lambda i,e:retain(output,i,e)
 return bound_keep(root,corr,receipt,lambda i,raw:retain_observation_capture(output,label='query-%04d'%i,capture=raw,source_fingerprint=original._source()),publish,source_guard,clock,sleep,retain_inventory=retain_inventory)
