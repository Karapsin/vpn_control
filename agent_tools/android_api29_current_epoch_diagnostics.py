"""One new current-owner diagnostics epoch, preserving consumed old history."""
from __future__ import annotations
import ast,hashlib,json,os,stat,uuid
from contextlib import ExitStack
from pathlib import Path
from . import android_api29_current_permission_diagnostics as old
from . import android_external_java_component_transport as component
from . import android_device_availability as availability
from . import private_inventory_lock as private
historical=old.historical
OLD_SHA='6da2fc354811b870095eac994252359fd28d3b218b9d1a8ed5818c26bf6cda94'
COMPONENT_SHA='c466a58180280fc0606481b423f19e51f9900b82ea09718df4f3b8b504ad7782'
OWNER='6373d143-1372-4835-a89b-baafb0959b9f'
OLD_CORRELATION='337cc983-5ad7-48fc-bd26-b51b722adc47'
BOOT='be2586cb-8b65-4f50-ba47-8f87d5c7ce73'
RESULT='.runtime/parity-evidence/android-api29-owned-permission-1c2d8865-399b-4da8-a7b6-863b1db3378f/result-0.private'
RESULT_SHA='0806ee389b408c05e78c96bf02e08ca6e65106fdd6cc65bd355fcbdac170a503'
OLD_LEAVES={'intent.json':'abad158acf19d49364b22fdb6f0c86b7d3376ad001fffe80d0aa0737f3d9cf77','capture.json':'abc61d08a590873c00b4122be7108774acd85e285aee44af0dbe8b8922c5f44f','terminal.json':'6096845ecc95f917a6dc29792a70d23565b1d0d6fca7235af5669083bd319de0'}
_EPOCH_REMOTE=r'''
def epoch_old_effect_absent(root_chain):
 guard_parents(root_chain)
 try:os.stat('android-api29-owned-diagnostics-'+DIAGNOSTIC['currentBootCorrelation'],dir_fd=root_chain[-1]['fd'],follow_symlinks=False)
 except FileNotFoundError:pass
 else:raise ValueError('diagnostic_old_remote_effect_unknown')
 guard_parents(root_chain)
'''

def validate_old(value):
 if type(value)is not dict or value.get('correlationId')!=OLD_CORRELATION or value.get('reason')!='diagnostic_public_unknown' or value.get('permissionObserved')is not False or any(value.get(k)is not None for k in ('intentPin','ownedTerminal','ownedOperation')) or set(value.get('records',{}))!={'captures','statusBefore'}:raise ValueError('epoch_old_submission_unknown')
 record=value['records']['statusBefore'];reply=record.get('stdout',{})
 if type(record.get('returncode'))is not int or record['returncode']!=1 or reply.get('ok')is not False or reply.get('code')!='CONFLICT' or reply.get('controllerId')!=OWNER or type(reply.get('configurationRevision'))is not int or reply['configurationRevision']!=0:raise ValueError('epoch_old_phase_changed')
 return True

def _sources(root,prepared):
 def saved(path,sha):
  path=Path(path).absolute();snapshot=availability._snapshot(path)
  if hashlib.sha256(snapshot[1]).hexdigest()!=sha:raise ValueError('epoch_history_source_changed')
  if path in prepared['snapshots'] and prepared['snapshots'][path]!=snapshot:raise ValueError('epoch_history_source_changed')
  prepared['snapshots'][path]=snapshot;return snapshot
 result=saved(root/RESULT,RESULT_SHA);validate_old(json.loads(result[1]));pins={}
 base=root/'.rag_index/android-api29-owned-permission-diagnostics'/BOOT
 for name,sha in OLD_LEAVES.items():
  snap=saved(base/name,sha);pins[name]={'snapshot':list(snap[0]),'sha256':sha,'bytes':len(snap[1])}
 intent=json.loads(prepared['snapshots'][base/'intent.json'][1]);terminal=json.loads(prepared['snapshots'][base/'terminal.json'][1]);capture=json.loads(prepared['snapshots'][base/'capture.json'][1])
 getter=component._assignment(ast.parse(prepared['program']),'GETTER')
 if intent['binding']['correlationId']!=OLD_CORRELATION or intent['binding']['controllerId']!=old.OWNER or intent['binding']['generation']!=getter['generation'] or terminal.get('binding')!=intent['binding'] or capture.get('binding')!=intent['binding'] or terminal.get('replayAllowed')is not False or capture.get('replayAllowed')is not False:raise ValueError('epoch_old_local_binding_changed')
 return {'resultSha256':RESULT_SHA,'resultSnapshot':list(result[0]),'oldLocalPins':pins}

def compose(program,binding):
 tree=ast.parse(program)
 for name,value in (('DIAGNOSTIC',binding),('PERMISSION_OWNER',OWNER)):
  assignments=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)]
  if len(assignments)!=1:raise ValueError('epoch_composition_changed')
  assignments[0].value=ast.parse(repr(value),mode='eval').body
 functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
 if len([n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='diagnostic_fence'])!=1 or ast.unparse(tree.body[-1])!='coldboot_dispatch()':raise ValueError('epoch_composition_changed')
 fence=functions['diagnostic_fence'];assignments=[n for n in ast.walk(fence) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='name' for t in n.targets)]
 if len(assignments)!=1 or ast.unparse(assignments[0].value)!="'android-api29-owned-diagnostics-' + DIAGNOSTIC['currentBootCorrelation']":raise ValueError('epoch_fence_changed')
 assignments[0].value=ast.parse("'android-api29-current-epoch-diagnostics-'+DIAGNOSTIC['currentBootCorrelation']+'-'+PERMISSION_OWNER",mode='eval').body
 observed=functions['observed_getter'];tries=[n for n in observed.body if isinstance(n,ast.Try)]
 if len(tries)!=1:raise ValueError('epoch_observer_changed')
 main=tries[0];first=next(i for i,n in enumerate(main.body) if ast.unparse(n).startswith("GETTER_RECORDS['statusBefore']"));main.body.insert(first,ast.parse('epoch_old_effect_absent(root_chain)').body[0])
 at=next(i for i,n in enumerate(main.body) if ast.unparse(n).startswith('chain, intent_pin = diagnostic_fence'))
 main.body[at:at]=ast.parse("epoch_old_effect_absent(root_chain)\nGETTER_RECORDS['statusAdmission']=getter_cli(['status'],PERMISSION_OWNER)\nif diagnostic_public(GETTER_RECORDS['statusAdmission'],'status')!=before:raise ValueError('diagnostic_status_changed')\nGETTER_RECORDS['operationsAdmission']=getter_cli(['operations','list'],PERMISSION_OWNER)\ndiagnostic_public(GETTER_RECORDS['operationsAdmission'],'operations')").body
 # Close the fixed generation/APK/stage even if the initial public guard fails.
 handler=main.handlers[0]
 handler.body+=ast.parse("\ntry:\n if getter_apk()!=GETTER['packageSha256']:raise ValueError('getter_package_changed')\n getter_generation(directory)\n if not stage or getter_stage()!=stage[0]:raise ValueError('getter_stage_generation_changed')\n closing=True\nexcept (ValueError,OSError,KeyError,TypeError,UnicodeError):\n closing=False\n").body
 status=functions['diagnostic_operation_status'];replacement=ast.parse("def diagnostic_operation_status(operation):\n return getter_cli(['operations','status',operation],PERMISSION_OWNER)\n").body[0];tree.body[tree.body.index(status)]=replacement
 tree.body[-1:-1]=ast.parse(_EPOCH_REMOTE).body
 result=ast.unparse(ast.fix_missing_locations(tree))+'\n';compile(result,'<current-api29-owned-epoch>','exec');return result

def prepare(root:Path,reservation:dict,correlation:str):
 root=Path(root).absolute();old._identifier(correlation)
 sources={}
 for module,sha in ((old,OLD_SHA),(component,COMPONENT_SHA)):
  path=Path(module.__file__).absolute();snap=availability._snapshot(path)
  if hashlib.sha256(snap[1]).hexdigest()!=sha:raise ValueError('epoch_dependency_changed')
  sources[path]=snap
 prepared=old.prepare(root,reservation,correlation)
 for path,snap in sources.items():
  if availability._snapshot(path)!=snap:raise ValueError('epoch_dependency_changed')
  prepared['snapshots'][path]=snap
 own=Path(__file__).absolute();snapshot=availability._snapshot(own);prepared['snapshots'][own]=snapshot
 proof=_sources(root,prepared);binding=dict(prepared['ownedDiagnostic']);binding.update(kind='one-owned-current-api29-epoch',controllerId=OWNER,sourceSha256=hashlib.sha256(snapshot[1]).hexdigest(),oldSourceSha256=OLD_SHA,oldEffectProof=proof)
 request=json.loads(binding['requestBytes']);request['controllerId']=OWNER;binding['requestBytes']=json.dumps(request,sort_keys=True,separators=(',',':'))
 prepared['program']=compose(prepared['program'],binding)
 backend=component.prepare_binding(root,prepared,'android-api29');component.install(prepared,backend);binding['componentBinding']=backend
 # DIAGNOSTIC includes the complete immutable backend authority as well.
 tree=ast.parse(prepared['program']);next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='DIAGNOSTIC' for t in n.targets)).value=ast.parse(repr(binding),mode='eval').body
 prepared['program']=ast.unparse(tree)+'\n';prepared['ownedDiagnostic']=binding;prepared['diagnosticProgramSha256']=hashlib.sha256(prepared['program'].encode()).hexdigest();component.guard(prepared);return prepared

# Reuse the exact reviewed local receipt machinery with only its fixed epoch path changed.
def _install_local():
 raw=availability._snapshot(Path(old.__file__).absolute())[1]
 if hashlib.sha256(raw).hexdigest()!=OLD_SHA:raise ValueError('epoch_dependency_changed')
 names={'_local_directory','_local_write','arm','guard_prepared','ssh_carrier','retain','status','_local_capture_pin'}
 tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
 if len(nodes)!=len(names):raise ValueError('epoch_local_generator_changed')
 directory=next(n for n in nodes if n.name=='_local_directory');text=ast.unparse(directory)
 if text.count("'android-api29-owned-permission-diagnostics'")!=1 or text.count('name = historical.original.CORRELATION')!=1:raise ValueError('epoch_local_generator_changed')
 text=text.replace("'android-api29-owned-permission-diagnostics'","'android-api29-current-epoch-diagnostics'").replace('name = historical.original.CORRELATION',"name = BOOT + '-' + OWNER")
 nodes[nodes.index(directory)]=ast.parse(text).body[0];exec(compile(ast.Module(body=nodes,type_ignores=[]),'<fixed-current-epoch-local-receipts>','exec'),globals())
_install_local()
