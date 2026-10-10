"""Retention-only scoped official status callback for one selected builder.
Original status result/guards/deadlines are unchanged. Caller owns every held
FD appended here through its later transport/publication/final closing.
"""
import hashlib,os,types
from pathlib import Path
from agent_tools import ssh_fresh_nested_channel as channel
from agent_tools import ssh_direct_nested_channel as direct_channel
from agent_tools import ssh_channel_inventory_diagnostics as inventory_diagnostics
from agent_tools import android_installer_asset_collection as collection
from agent_tools import android_capture_result_publication as publication
from agent_tools import android_installer_direct_transport as direct
MAX=channel.recovery._SOCKET_CAPTURE_BYTES+1

def shape(value):
 required={'stdout','stderr','counts','eof','returnCode','complete','overflow','timeout','readError'}
 if type(value)is not dict or not required<=set(value) or not set(value)<=required|{'pid'}:raise ValueError('route_capture_shape')
 for key in ('stdout','stderr'):
  if type(value[key])is not bytes or len(value[key])>MAX:raise ValueError('route_capture_stream')
 if type(value['counts'])is not dict or set(value['counts'])!={'stdout','stderr'} or any(type(v)is not int or v<0 for v in value['counts'].values()):raise ValueError('route_capture_counts')
 if type(value['eof'])is not dict or set(value['eof'])!={'stdout','stderr'} or any(type(v)is not bool for v in value['eof'].values()):raise ValueError('route_capture_eof')
 if any(type(value[k])is not bool for k in ('complete','overflow','timeout','readError')) or (value['returnCode']is not None and(type(value['returnCode'])is not int or not -2147483648<=value['returnCode']<=2147483647)):raise ValueError('route_capture_flags')
 if 'pid'in value and(type(value['pid'])is not int or not 0<value['pid']<=2147483647):raise ValueError('route_capture_pid')
 if value['complete']and(not all(value['eof'].values())or type(value['returnCode'])is not int or value['overflow']or value['timeout']or value['readError']):raise ValueError('route_capture_complete')
 return value

def build(builder,state,capture,*,source_custody,held,root,correlation_id,diagnostic,runtime):
 """One ORIGINAL builder; official callback executes within provider held guards.
No status query is added and no argv is executed here. Raw precedes projection.
"""
 channel._corr(correlation_id)
 if not callable(builder)or not callable(source_custody)or type(held)is not list:raise ValueError('route_capture_custody_required')
 original_statuses=((channel,channel.status),(direct_channel,direct_channel.status))
 for provider,original in original_statuses:
  if type(original)is not types.FunctionType or original.__globals__ is not vars(provider):raise ValueError('route_capture_original_status_required')
 root=Path(root);source_custody();direct._dispatch_guard(held);calls=0;raw_calls=0;raw_retained=False
 base=collection.collector()
 def hold(name,body,created):
  raw,pin=direct.snapshot(Path(capture.path)/name,limit=len(body)+1,private=True)
  if raw!=body or not publication.matches(pin,created):raise ValueError('route_capture_publication_changed')
  held.append(direct._dispatch_hold(Path(capture.path)/name,pin,raw))
 def record(name,body):hold(name,body,capture.create(name,body))
 def retain(value):
  nonlocal raw_calls,raw_retained
  if raw_calls:raise ValueError('route_capture_duplicate')
  raw_calls+=1;shape(value);source_custody();direct._dispatch_guard(held)
  for stream in ('stdout','stderr'):
   created={}
   def create(name,body):
    if name in created:raise ValueError('route_capture_duplicate')
    created[name]=capture.create(name,body);hold(name,body,created[name]);return created[name]
   manifest=base['archive'](types.SimpleNamespace(create=create),'selected-status-'+stream,value[stream])
   if manifest['bytes']!=len(value[stream])or manifest['sha256']!=hashlib.sha256(value[stream]).hexdigest():raise ValueError('route_capture_archive_changed')
  metadata={k:value[k]for k in value if k not in ('stdout','stderr')}
  metadata.update(schema=1,stdoutBytes=len(value['stdout']),stderrBytes=len(value['stderr']),stdoutSha256=hashlib.sha256(value['stdout']).hexdigest(),stderrSha256=hashlib.sha256(value['stderr']).hexdigest(),nativeActionAllowed=False,replayAllowed=False)
  record('selected-status-capture.private',direct.canonical(metadata))
  source_custody();direct._dispatch_guard(held);raw_retained=True
 def scoped_status(original):
  def status(check_root,host,corr,*,_private_capture=None,_private_inventory_diagnostic=None):
   nonlocal calls
   if calls or Path(check_root)!=root or host!=channel.HOST or corr!=correlation_id:raise ValueError('route_capture_query_binding')
   if _private_capture is not None and not callable(_private_capture):raise ValueError('route_capture_callback_invalid')
   if _private_inventory_diagnostic is not None and not callable(_private_inventory_diagnostic):raise ValueError('route_capture_inventory_callback_invalid')
   calls+=1
   inventory_attempts=0;inventory_retained=False;inventory_failure_class=None
   def callback(value):
    retain(value)
    if _private_capture is not None:_private_capture(value)
    source_custody();direct._dispatch_guard(held)
   def inventory_callback(event):
    nonlocal inventory_attempts,inventory_retained,inventory_failure_class
    inventory_attempts+=1
    try:
     if inventory_attempts!=1:raise ValueError('route_capture_inventory_duplicate')
     inventory_diagnostics.validate(event)
     body=direct.canonical({'schema':1,'event':event,'nativeActionAllowed':False,'replayAllowed':False})
     if len(body)>1024:raise ValueError('route_capture_inventory_bound')
     source_custody();direct._dispatch_guard(held)
     record('selected-inventory-finite.json',body)
     source_custody();direct._dispatch_guard(held);inventory_retained=True
     if _private_inventory_diagnostic is not None:_private_inventory_diagnostic(event)
    except Exception as error:
     inventory_failure_class=type(error).__name__ if type(error)in(OSError,ValueError,TypeError)else'Other'
     raise
   result=original(check_root,host,corr,_private_capture=callback,_private_inventory_diagnostic=inventory_callback)
   # The exact original result remains private; diagnostics never change its DTO.
   record('selected-status-result.private',direct.canonical(result))
   finite={'schema':1,'state':result.get('state')if type(result)is dict and result.get('state')in('ready','unknown','ended')else'unknown','originalStatusCalled':True,'originalRawRetained':raw_retained,'nativeActionAllowed':False,'replayAllowed':False}
   if type(result)is dict and result.get('state')=='unknown':
    try:known=channel.validated_unknown(result)
    except(ValueError,TypeError):
     known={}
     if set(result)=={'state','failurePhase','nativeActionAllowed','replayAllowed'} and result['state']=='unknown'and result['nativeActionAllowed']is False and result['replayAllowed']is False and type(result['failurePhase'])is str and result['failurePhase']in channel._PUBLIC_PHASES:known={'failurePhase':result['failurePhase']}
    for key in ('failurePhase','failureReason','exceptionClass','errno'):
     if key in known:finite[key]=known[key]
   if inventory_attempts:
    finite.update(inventoryDiagnosticRetained=inventory_retained,inventoryDiagnosticPublicationFailureClass=inventory_failure_class)
   record('selected-status-finite.json',direct.canonical(finite));source_custody();direct._dispatch_guard(held)
   return result
  return status
 scoped_statuses=tuple((provider,scoped_status(original))for provider,original in original_statuses)
 original_reuse=channel.session.reuse_only_options
 if type(original_reuse)is not types.FunctionType or original_reuse.__globals__ is not vars(channel.session):raise ValueError('route_capture_original_reuse_required')
 def reuse(*args,**kwargs):
  try:return original_reuse(*args,**kwargs)
  except Exception as error:
   # Retention only: the exact original exception is re-raised unchanged.
   # Provider may mask it afterwards; private original context survives here.
   try:
    def retained_create(name,body):
     created=capture.create(name,body);hold(name,body,created);return created
    retained_capture=types.SimpleNamespace(path=capture.path,create=retained_create)
    finite=diagnostic.retain(error,retained_capture,'copy-collect',source_custody,runtime,extra_held=held)
   except Exception:
    finite={'schema':1,'state':'unknown','originalExceptionRetained':False,'nativeActionAllowed':False,'replayAllowed':False}
   try:record('outer-reuse-finite.json',direct.canonical(finite))
   except Exception:pass
   raise
 for provider,status in scoped_statuses:provider.status=status
 channel.session.reuse_only_options=reuse
 try:
  value=builder(state);source_custody();direct._dispatch_guard(held);return value
 finally:
  changed=any(provider.status is not status for provider,status in scoped_statuses)or channel.session.reuse_only_options is not reuse
  for provider,original in original_statuses:provider.status=original
  channel.session.reuse_only_options=original_reuse
  if changed:raise ValueError('route_capture_status_replaced')
