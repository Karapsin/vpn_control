"""Ledger-neutral current API29 owner census; no export or mutation authority."""
from __future__ import annotations
import ast
import hashlib
from pathlib import Path
from . import android_api29_current_permission_observation as original
from . import android_device_availability as availability
ORIGINAL_SHA='818fef810405e93f06f7665252044ffdf4440d1e8388029ffa4a80b4c1623838'
_OBSERVER=r'''
def owner_envelope(record,owner=None,revision=None):
 value=record.get('stdout')
 if type(record.get('returncode'))is not int or record['returncode']!=0 or not isinstance(value,dict) or value.get('ok')is not True or value.get('final')is not True or value.get('code')!='OK' or record.get('stderrRaw','')!='':raise ValueError('owner_public_unavailable')
 found=value.get('controllerId');rev=value.get('configurationRevision')
 if not isinstance(found,str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',found) or type(rev)is not int or rev<0:raise ValueError('owner_identity_unknown')
 if owner is not None and (found!=owner or rev!=revision):raise ValueError('owner_identity_changed')
 if not isinstance(value.get('data'),dict):raise ValueError('owner_public_shape')
 return value

def owner_status(record,owner=None,revision=None):
 value=owner_envelope(record,owner,revision);data=value['data']
 if data.get('runtimeRunning')is not False or data.get('runtimeObservation')!='stopped' or data.get('configuredMode')!='vpn':raise ValueError('owner_runtime_not_off')
 return value

def owner_operations(record,owner,revision):
 value=owner_envelope(record,owner,revision);rows=value['data'].get('operations')
 if not isinstance(rows,list) or any(not isinstance(row,dict) for row in rows):raise ValueError('owner_ledger_unknown')
 return rows

def observed_getter(directory):
 global GETTER_RECORDS
 GETTER_RECORDS={};stage=[];owner=None;revision=None;ledger=None;failure=None;closing=False;stable=False;observed=None
 try:
  stage.append(getter_stage());getter_generation(directory)
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  try:
   # Discover the current epoch without binding an expired historical owner.
   GETTER_RECORDS['statusDiscovery']=getter_cli(['status']);first=owner_status(GETTER_RECORDS['statusDiscovery']);owner=first['controllerId'];revision=first['configurationRevision'];observed=first['data']
   GETTER_RECORDS['operationsBefore']=getter_cli(['operations','list'],owner);ledger=owner_operations(GETTER_RECORDS['operationsBefore'],owner,revision)
   GETTER_RECORDS['statusPinned']=getter_cli(['status'],owner);second=owner_status(GETTER_RECORDS['statusPinned'],owner,revision)
   GETTER_RECORDS['operationsAfter']=getter_cli(['operations','list'],owner);after=owner_operations(GETTER_RECORDS['operationsAfter'],owner,revision)
   GETTER_RECORDS['statusFinal']=getter_cli(['status'],owner);last=owner_status(GETTER_RECORDS['statusFinal'],owner,revision)
   if first['data']!=second['data'] or second['data']!=last['data']:raise ValueError('owner_status_changed')
   if ledger!=after:raise ValueError('owner_ledger_changed')
   stable=True
  except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:owner|permission|getter)_[a-z_]{1,72}',str(error)) else 'owner_read_unknown'
  # A failed public read does not bypass current APK/stage/guest closure.
  if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')
  getter_generation(directory);stage.append(getter_stage())
  if stage[0]!=stage[1]:raise ValueError('getter_stage_generation_changed')
  closing=True
 except (ValueError,OSError,KeyError,TypeError,UnicodeError,subprocess.TimeoutExpired) as error:failure=str(error) if isinstance(error,ValueError) and re.fullmatch(r'(?:owner|permission|getter|coldboot|census|alias)_[a-z_]{1,72}',str(error)) else 'owner_guard_rejected'
 admitted=failure is None and stable and closing
 return {'state':'current-owner-observed' if admitted else 'diagnostic-only','reason':failure,'ownerObserved':admitted,'controllerId':owner,'configurationRevision':revision,'runtimeStatus':observed,'operations':ledger,'ledgerEmpty':admitted and ledger==[],'closingGuardsVerified':closing,'records':GETTER_RECORDS,'cliStagePins':stage,'permissionObserved':False,'exportSubmitted':False,'endpointAdmitted':False,'productAdmitted':False,'acceptanceComplete':False,'replayAllowed':False,'historicalUnknownsPreserved':True}
'''

def compose(program,own_raw):
 tree=ast.parse(program);remove={'permission_diagnostics','permission_public','permission_parse','observed_getter'}
 if {n.name for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in remove}!=remove or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('owner_composition_changed')
 tree.body=[n for n in tree.body if not isinstance(n,ast.FunctionDef) or n.name not in remove];tree.body.pop()
 template=ast.literal_eval(next(n.value for n in ast.parse(own_raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
 result=ast.unparse(tree)+'\n'+template+'\ncoldboot_dispatch()\n'
 for node in ast.walk(ast.parse(result)):
  if isinstance(node,ast.Call) and (ast.unparse(node.func) in {'os.mkdir','os.makedirs','os.write','os.fork','os.execve','os.system','os.replace','os.unlink','journal_write','admit_once','launch_once'} or any(isinstance(p,ast.Attribute) and p.attr in {'O_CREAT','O_TRUNC','O_EXCL','O_WRONLY'} for p in ast.walk(node))):raise ValueError('owner_readonly_required')
 compile(result,'<current-api29-owner>','exec');return result

def prepare(root:Path,reservation:dict)->dict:
 root=Path(root).absolute();path=Path(original.__file__).absolute();snapshot=availability._snapshot(path)
 if hashlib.sha256(snapshot[1]).hexdigest()!=ORIGINAL_SHA:raise ValueError('owner_original_source_changed')
 prepared=original.prepare(root,reservation)
 if availability._snapshot(path)!=snapshot or prepared['snapshots'].get(path)!=snapshot:raise ValueError('owner_original_source_changed')
 own=Path(__file__).absolute();saved=availability._snapshot(own);prepared['snapshots'][own]=saved
 prepared['program']=compose(prepared['program'],saved[1]);guard_prepared(prepared);return prepared

def guard_prepared(prepared):original.guard_prepared(prepared)
def ssh_carrier(prepared):return original.ssh_carrier(prepared)
