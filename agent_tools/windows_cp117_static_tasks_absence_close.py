"""Fixed current-absence closure, never a receipt for the original batch outcome."""
from __future__ import annotations
import hashlib
import base64
import gzip
import inspect
import time
import uuid
import json
import os
import stat
import re
from contextlib import nullcontext, contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Mapping
from . import windows_cp117_static_tasks_retire as original

history=original.history
base=original.base
wire=original.wire
_CLOSE='8a3e6cf1-0cf8-4873-aade-bc07c42a4f30'
_DIR='.rag_index/windows-cp117-static-tasks-absence-close'
_ROOT=r'C:\ProgramData\VpnControlCp117-retirement-'+_CLOSE
_LEAVES=('binding.json','terminal.json')
_PHASES=frozenset({'platform','history','generation','active-lease','original-intent','original-proof','race','parser','intent','base-route','binding','terminal','journal','complete','snapshot','dispatch'} | set(original._PHASES))
# Preserve dispatch bytes when read-only diagnostic phases evolve.
_DISPATCH_PHASES=_PHASES
_PHASES=_PHASES | frozenset({'original-observer-shape','original-envelope','original-binding','original-terminal','original-absence','original-progress-shape','original-snapshots','original-progress-binding','original-history-local','original-history-c32','original-history-recovery','original-history-transient'} | {'original-observer-'+p for p in original._PHASES})
_HOST_CHECKPOINTS=frozenset({'root','lock','admission','observer','original-intent','parse','probe','archive','validation','steady','identity','plan','status','absence-root','reservation','intent-write','binding-dispatch','terminal-dispatch'})
_HOST_KINDS=frozenset({'json','encoding','missing','permission','os','value','type','key','index','eof','attribute','runtime','overflow','other'})
_PHASES=_PHASES | frozenset('host-'+p+'-'+k for p in _HOST_CHECKPOINTS for k in _HOST_KINDS)
_FLAGS=dict(original._FLAGS)
class Blocked(ValueError):
    def __init__(self,phase):self.phase=phase if phase in _PHASES else 'journal';super().__init__(self.phase)
def _result(state,phase):
    assert state in {'not-started','ready','blocked','unknown','closed'} and phase in _PHASES
    return {'state':state,'phase':phase,'closureCorrelationId':_CLOSE,'originalRetirementCorrelationId':original._RETIREMENT,'proof':'current-absence' if state=='closed' else 'none',**_FLAGS}
def _digest(value):return original._digest(value)
def _parser_command(source):
    packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
    parser=history._PARSER.replace('@PACKED@',packed)
    # Preserve the parser's exact text while carrying no SSH control characters.
    # This executes only the parser; the packed prospective source stays data.
    literal=parser.replace('`','``').replace('$','`$').replace('"','`"').replace('\r','`r').replace('\n','`n').replace('\t','`t')
    command='&([scriptblock]::Create("'+literal+'"))'
    if not 0<len(command)<30000:raise ValueError('Windows command bound')
    return command
def _parser_observe(root,descriptor,closed,command):
    # Only the fixed parser command travels through the existing guarded reader.
    # The packed prospective source is parsed, never executed by this route.
    config,target,current=base._descriptor(root)
    if current!=descriptor or descriptor!=wire.observer._GENERATION:return wire._probe_failure('descriptor')
    raw=base._remote(config,original._REMOTE,(str(target.fixture_transfer_root),*wire.observer._remote_arguments(descriptor,closed),command),None,90)
    if raw is None:return wire._probe_failure('transport')
    if not isinstance(raw,(bytes,str)) or not 0<len(raw)<=16384:return wire._probe_failure('envelope')
    try:value=json.loads(raw,object_pairs_hook=history._unique)
    except (ValueError,TypeError):return wire._probe_failure('json')
    value=wire._unpack(value)
    if isinstance(value,dict) and set(value)=={'state','receipt'} and value['state']=='observed':return value['receipt']
    return wire._probe_failure('shape')
def _parse(root,descriptor,closed,source):
    return _parser_observe(root,descriptor,closed,_parser_command(source))=={'version':1,'code':'OK'}

def _fresh_terminal(item,nonce,source_sha,child):
    """Return original envelope with a proved header removed, or no fresh proof."""
    if (not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',nonce)
        or not isinstance(source_sha,str) or not re.fullmatch('[0-9a-f]{64}',source_sha)
        or type(child)is not int or child<=0):raise ValueError('execution binding')
    if not isinstance(item,dict) or item.get('exited') is not True:raise ValueError('terminal binding')
    encoded=item.get('out-data','')
    if not isinstance(encoded,str) or len(encoded)>68000:raise ValueError('terminal bound')
    raw=base64.b64decode(encoded,validate=True)
    if len(raw)>50300:raise ValueError('terminal bound')
    header=('VPNCONTROL-READ '+nonce+' '+source_sha+' '+str(child)).encode('ascii')
    if raw.startswith(header+b'\r\n'):payload=raw[len(header)+2:]
    elif raw.startswith(header+b'\n'):payload=raw[len(header)+1:]
    else:return None
    return {**item,'out-data':base64.b64encode(payload).decode('ascii')}

def _fresh_reject_reason(raw,nonce,source_sha,child):
    line=raw.split(b'\n',1)[0].rstrip(b'\r')
    if not line.startswith(b'VPNCONTROL-READ '):return 'header-missing'
    fields=line.split(b' ')
    if len(fields)!=4:return 'header-malformed'
    if fields[1]!=nonce.encode('ascii'):return 'nonce-mismatch'
    if fields[2]!=source_sha.encode('ascii'):return 'source-mismatch'
    if fields[3]!=str(child).encode('ascii'):return 'child-mismatch'
    return 'header-malformed'

def _fresh_call(delegate,mode,program,source_sha,nonce,save,command_cap):
    """One exact read submission; unbound terminals consume only its status budget."""
    if mode not in {'-Command','-EncodedCommand'} or not isinstance(program,str) or not 0<len(program)<command_cap:raise ValueError('fixed program')
    # Validate binding arguments before submission even if no terminal arrives.
    _fresh_terminal({'exited':True},nonce,source_sha,1)
    header="[Console]::Out.WriteLine('VPNCONTROL-READ "+nonce+' '+source_sha+" '+$PID);\n"
    if mode=='-Command':bound=header+program
    else:bound=base64.b64encode((header+base64.b64decode(program,validate=True).decode('utf-16le')).encode('utf-16le')).decode('ascii')
    if not 0<len(bound)<command_cap:raise ValueError('bound command size')
    child=None;child_sock=None;poll_count=0
    def call(sock,command,args):
        nonlocal child,child_sock,poll_count
        if command=='guest-exec':
            if child is not None or args!={'path':'powershell.exe','arg':['-NoProfile','-NonInteractive',mode,program],'capture-output':True}:raise ValueError('fixed read submission')
            result=delegate(sock,command,{**args,'arg':['-NoProfile','-NonInteractive',mode,bound]})
            if not isinstance(result,dict) or set(result)!={'pid'} or type(result['pid'])is not int or result['pid']<=0:raise ValueError('child binding')
            child=result['pid'];child_sock=sock;save({'kind':'submitted','childPid':child,'nonce':nonce,'sourceSha256':source_sha});return result
        if command!='guest-exec-status' or child is None or sock!=child_sock or args!={'pid':child}:raise ValueError('fixed read status')
        poll_count+=1;begin=time.monotonic()
        try:item=delegate(sock,command,args)
        except Exception as error:
            save({'kind':'poll-exception','childPid':child,'poll':poll_count,'exception':'socket-timeout' if isinstance(error,TimeoutError) else 'shape' if isinstance(error,(ValueError,TypeError,KeyError)) else 'transport','elapsedMs':max(0,round((time.monotonic()-begin)*1000))})
            raise
        exited=item.get('exited') if isinstance(item,dict) else None
        save({'kind':'poll-observed','childPid':child,'poll':poll_count,'exited':exited if type(exited)is bool else None,'shape':'dictionary' if isinstance(item,dict) else 'other','elapsedMs':max(0,round((time.monotonic()-begin)*1000))})
        if isinstance(item,dict) and item.get('exited') is True:
            try:
                fresh=_fresh_terminal(item,nonce,source_sha,child)
                raw=base64.b64decode(item.get('out-data',''),validate=True)
            except Exception as error:
                save({'kind':'terminal-invalid','childPid':child,'poll':poll_count,'exception':'shape' if isinstance(error,(ValueError,TypeError,KeyError)) else 'other'})
                raise
            save({'kind':'execution-bound' if fresh is not None else 'execution-binding-pending','childPid':child,'poll':poll_count,'reason':'verified' if fresh is not None else _fresh_reject_reason(raw,nonce,source_sha,child),'outputBytes':len(raw),'outputSha256':hashlib.sha256(raw).hexdigest()})
            # This is pending execution identity, not a claim that a process lives.
            return fresh if fresh is not None else {'exited':False}
        return item
    return call

def _fresh_program(remote,mode,program,source_sha,nonce,command_cap):
    if not remote.startswith(base._QGA):raise Blocked('generation')
    # Construct once locally to reject malformed identity and command overflow
    # before the original guarded remote body can reach guest-exec.
    _fresh_call(lambda *args:None,mode,program,source_sha,nonce,lambda event:None,command_cap)
    setup="\nimport re\n"+inspect.getsource(_fresh_terminal)+'\n'+inspect.getsource(_fresh_reject_reason)+'\n'+inspect.getsource(_fresh_call)+"\ndef fresh_save(event):\n print('EXECUTION-BINDING '+json.dumps(event,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)\n"
    setup+='call=_fresh_call(call,'+repr(mode)+','+repr(program)+','+repr(source_sha)+','+repr(nonce)+',fresh_save,'+repr(command_cap)+')\n'
    return base._QGA+setup+remote[len(base._QGA):]

def _fresh_c32_program(source,nonce):
    from . import windows_cp117_c32_absence as absence
    if source!=absence._script(absence._C32):raise Blocked('generation')
    encoded=base64.b64encode(source.encode('utf-16le')).decode('ascii')
    return _fresh_program(absence._REMOTE,'-EncodedCommand',encoded,hashlib.sha256(source.encode('utf-16le')).hexdigest(),nonce,30000)

def _fresh_recovery_program(source,nonce):
    from . import windows_cp117_guest_agent_recovery as recovery
    if source!=base._fixed_recovery_task_status_script():raise Blocked('generation')
    return _fresh_program(recovery._REMOTE_PS,'-Command',recovery._launcher(source),hashlib.sha256(source.encode('utf-16le')).hexdigest(),nonce,28000)

def _fresh_retained_c32_program(root,remote,command,nonce):
    from . import windows_cp117_c32_absence as absence
    intent=base._private_intent(root,absence._C32)
    if not isinstance(intent,Mapping):raise Blocked('generation')
    strict=absence._retained_script(intent)
    diagnostic=absence._retained_script(intent,diagnostic=True)
    post=absence._post_retirement_leaf_script(intent)
    if remote==absence._RETAINED_PARSE_REMOTE:
        allowed=[absence._retained_parse_script(strict,diagnostic),absence._retained_parse_script(post,post)]
        if command not in allowed:raise Blocked('generation')
        source=command;mode='-Command'
    elif remote in {absence._RETAINED_REMOTE,absence._RETAINED_DIAG_REMOTE}:
        allowed=[strict,post] if remote==absence._RETAINED_REMOTE else [diagnostic]
        sources={base64.b64encode(source.encode('utf-16le')).decode():source for source in allowed}
        if command not in sources:raise Blocked('generation')
        source=sources[command];mode='-EncodedCommand'
    else:raise Blocked('generation')
    return _fresh_program(remote,mode,command,hashlib.sha256(source.encode('utf-16le')).hexdigest(),nonce,30000)

def _fresh_static_program(command,expected,nonce,proof=None):
    if expected!=original._expected():raise Blocked('generation')
    sources=[original._diagnostic_reader(expected),original._reader(expected),_root_absence(expected)]
    if proof is not None:
        binding=_binding(wire.observer._GENERATION,proof)
        first,final,_=_scripts(binding,expected,proof)
        sources.append(_reader(expected,proof))
        # Effect bodies are admitted only as data to the fixed parser route.
        parsable=sources+[first,final]
    else:parsable=sources
    allowed={wire._command(source):source for source in sources}
    allowed.update({_parser_command(source):_parser_command(source) for source in parsable})
    for source in sources:
        packed=base64.b64encode(gzip.compress(source.encode('utf-16le'),mtime=0)).decode()
        parser=history._PARSER.replace('@PACKED@',packed)
        # Only the unchanged original reader uses this older parser carrier.
        # Larger closure readers use the reviewed single-packing parser route.
        try:legacy_command=wire._command(parser)
        except ValueError:continue
        allowed[legacy_command]=parser
    if command not in allowed:raise Blocked('generation')
    return _fresh_program(original._REMOTE,'-Command',command,hashlib.sha256(allowed[command].encode('utf-16le')).hexdigest(),nonce,30000)

_FRESH_READ_SCOPE=ContextVar('windows_absence_fresh_read_scope',default=None)

@contextmanager
def _fresh_read_scope(root,action):
    """Bind only this closure's exact readers; retain every effect source byte."""
    from . import windows_cp117_c32_absence as absence
    from . import windows_cp117_guest_agent_recovery as recovery
    if _FRESH_READ_SCOPE.get() is not None:raise Blocked('generation')
    config,target,descriptor=base._descriptor(root)
    if descriptor!=wire.observer._GENERATION:raise Blocked('generation')
    scope={'root':root,'action':action,'expected':original._expected(),'proof':None}
    token=_FRESH_READ_SCOPE.set(scope);delegate=base._remote
    def remote(c,program,args,stdin,timeout):
        # Other threads do not inherit this closure's source authority.
        if _FRESH_READ_SCOPE.get() is not scope:return delegate(c,program,args,stdin,timeout)
        retained={absence._RETAINED_PARSE_REMOTE,absence._RETAINED_REMOTE,absence._RETAINED_DIAG_REMOTE}
        if program not in {original._REMOTE,absence._REMOTE,recovery._REMOTE_PS,*retained}:return delegate(c,program,args,stdin,timeout)
        if c!=config or stdin is not None or not isinstance(args,(tuple,list)):raise Blocked('generation')
        nonce=str(uuid.uuid4())
        if program==absence._REMOTE:
            source=absence._script(absence._C32)
            encoded=base64.b64encode(source.encode('utf-16le')).decode()
            if tuple(args)!=(descriptor[1],str(descriptor[2]),str(descriptor[3]),encoded) or timeout!=30:raise Blocked('generation')
            bound=_fresh_c32_program(source,nonce)
        elif program in retained:
            if len(args)!=4 or tuple(args[:3])!=(descriptor[1],str(descriptor[2]),str(descriptor[3])) or timeout!=60:raise Blocked('generation')
            bound=_fresh_retained_c32_program(root,program,args[-1],nonce)
        elif program==recovery._REMOTE_PS:
            source=base._fixed_recovery_task_status_script()
            if tuple(args)!=(str(descriptor[1]),str(descriptor[2]),str(descriptor[3]),recovery._launcher(source)) or timeout!=60:raise Blocked('generation')
            bound=_fresh_recovery_program(source,nonce)
        else:
            # The original remote body itself retains all closed journal,
            # generation and lock checks; this adds exact command recognition.
            if len(args)!=9 or args[0]!=str(target.fixture_transfer_root) or timeout!=90:raise Blocked('generation')
            if tuple(args[1:7])!=tuple(wire.observer._remote_arguments(descriptor,{})[:6]):raise Blocked('generation')
            command=args[-1];proof=scope['proof']
            if proof is not None and action=='start':
                binding=_binding(descriptor,proof);first,final,intent=_scripts(binding,scope['expected'],proof)
                if command in (wire._command(first),wire._command(final)):
                    if _read_private(root/_DIR/'intent.json')!=intent:raise Blocked('intent')
                    return delegate(c,program,args,stdin,timeout)
            bound=_fresh_static_program(command,scope['expected'],nonce,proof)
        return delegate(c,bound,args,stdin,timeout)
    base._remote=remote
    try:yield scope
    finally:
        base._remote=delegate;_FRESH_READ_SCOPE.reset(token)

def _recovery_call(delegate,sock,command,args,save,clock):
    if command not in {'guest-exec','guest-exec-status'}:raise ValueError('diagnostic command')
    begin=clock()
    try:result=delegate(sock,command,args)
    except Exception as error:
        if command=='guest-exec-status':
            kind='socket-timeout' if isinstance(error,TimeoutError) else 'malformed' if isinstance(error,(ValueError,TypeError,KeyError)) else 'transport'
            save({'kind':'poll','pid':args['pid'],'outcome':kind,'elapsedMs':max(0,round((clock()-begin)*1000))})
        raise
    elapsed=max(0,round((clock()-begin)*1000))
    if command=='guest-exec':
        if not isinstance(result,dict) or set(result)!={'pid'} or type(result['pid']) is not int or result['pid']<=0:raise ValueError('diagnostic child')
        save({'kind':'child','pid':result['pid']})
    else:
        valid=isinstance(result,dict) and type(result.get('exited')) is bool
        event={'kind':'poll','pid':args['pid'],'outcome':'exited' if valid and result['exited'] else 'running' if valid else 'malformed','elapsedMs':elapsed}
        if valid and result['exited'] and type(result.get('exitcode')) is int:event['exitcode']=result['exitcode']
        save(event)
    return result

def _validate_recovery_source(root,config,descriptor,script):
    current_config,target,current=base._descriptor(Path(root).resolve(strict=True))
    if current!=descriptor or descriptor!=wire.observer._GENERATION or current_config!=config or script!=base._fixed_recovery_task_status_script():raise Blocked('generation')
    return True

def _static_trace_delegate(delegate,observe):
    """Capture a delegate once; a diagnostic must never follow later rebinding."""
    def wrapped(*args,_delegate=delegate,_observe=observe,**kwargs):
        result=_delegate(*args,**kwargs)
        _observe(args,kwargs,result)
        return result
    return wrapped

def _static_boundary_program(source,expected,correlation):
    """Trace one fixed read without replacing its source, polls or predicates."""
    if source!=original._diagnostic_reader(expected) or str(uuid.UUID(correlation))!=correlation:raise Blocked('generation')
    command=wire._command(source)
    binding={'correlationId':correlation,'sourceSha256':hashlib.sha256(source.encode('utf-16le')).hexdigest(),'commandSha256':hashlib.sha256(command.encode()).hexdigest()}
    return base._QGA+_boundary_trace(binding)+original._REMOTE_BODY,binding

def _boundary_trace(binding):
    return r'''
_trace_binding=BINDING
_trace_count=0
_trace_delegate=call
def call(sock,command,args,_delegate=_trace_delegate):
 global _trace_count
 _trace_count+=1
 event={'correlationId':_trace_binding['correlationId'],'call':_trace_count,'command':command}
 if command=='guest-exec':
  event.update(_trace_binding)
  event['requestedCommandSha256']=hashlib.sha256(args['arg'][-1].encode()).hexdigest()
 elif command=='guest-exec-status':event['queriedPid']=args['pid']
 try:result=_delegate(sock,command,args)
 except Exception as error:
  event['outcome']='socket-timeout' if isinstance(error,TimeoutError) else 'failure'
  print('STATIC-READ-TRACE '+json.dumps(event,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)
  raise
 if command=='guest-exec':event['returnedPid']=result.get('pid') if isinstance(result,dict) else None
 elif isinstance(result,dict) and result.get('exited') is True:
  event['exited']=True;event['exitcode']=result.get('exitcode')
  try:
   raw=base64.b64decode(result.get('out-data',''),validate=True)
   event['outputBytes']=len(raw);event['outputSha256']=hashlib.sha256(raw).hexdigest()
   try:
    value=json.loads(decode(raw))
    event['outputKeys']=sorted(value) if isinstance(value,dict) else []
   except Exception:event['outputKeys']=[]
  except Exception:event['metadataOutcome']='malformed'
 print('STATIC-READ-TRACE '+json.dumps(event,sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)
 return result
'''.replace('BINDING',repr(binding),1)

def _c32_boundary_program(source,correlation):
    from . import windows_cp117_c32_absence as absence
    if source!=absence._script(absence._C32) or str(uuid.UUID(correlation))!=correlation:raise Blocked('generation')
    command=base64.b64encode(source.encode('utf-16le')).decode()
    binding={'correlationId':correlation,'sourceSha256':hashlib.sha256(source.encode('utf-16le')).hexdigest(),'commandSha256':hashlib.sha256(command.encode()).hexdigest()}
    body=absence._REMOTE[len(base._QGA):]
    # Phase labels are observations only; retain every original predicate/return.
    replacements=(
        ("try:\n if not live", "_boundary_phase='generation'\ntry:\n if not live"),
        (" child=call(sock,'guest-exec'", " _boundary_phase='guest-exec'\n child=call(sock,'guest-exec'"),
        (" if type(child)is not int", " _boundary_phase='child-identity'\n if type(child)is not int"),
        (" for _ in range(80):", " _boundary_phase='guest-status'\n for _ in range(80):"),
        (" if (set(item)-", " _boundary_phase='terminal-shape'\n if (set(item)-"),
        (" raw=base64.b64decode", " _boundary_phase='output-bytes'\n raw=base64.b64decode"),
        (" value=json.loads", " _boundary_phase='output-json'\n value=json.loads"),
        (" if not isinstance(value,dict)", " _boundary_phase='receipt-shape'\n if not isinstance(value,dict)"),
        ("except Exception:out({'state':'unknown'})", "except Exception as error:\n kind=type(error).__name__;kind=kind if kind in {'TimeoutError','ValueError','TypeError','KeyError','OSError','JSONDecodeError','UnicodeDecodeError','Error'} else 'other'\n print('STATIC-READ-TRACE '+json.dumps({'correlationId':_trace_binding['correlationId'],'phase':_boundary_phase,'exception':kind},sort_keys=True,separators=(',',':')),file=sys.stderr,flush=True)\n out({'state':'unknown'})"),
    )
    for before,after in replacements:
        if body.count(before)!=1:raise Blocked('generation')
        body=body.replace(before,after,1)
    return base._QGA+_boundary_trace(binding)+body,binding

def _process_gate_receipt(value,correlation,source_sha256,child_pid):
    if not isinstance(correlation,str) or not base._UUID.fullmatch(correlation) or not isinstance(source_sha256,str) or not base._HASH.fullmatch(source_sha256):raise Blocked('generation')
    fields={'correlationId','selfPid','selfSourceSha256','guard','otherCount','processes'}
    if not isinstance(value,dict) or set(value)!=fields or value['correlationId']!=correlation or type(child_pid) is not int or child_pid<=0 or type(value['selfPid']) is not int or value['selfPid']!=child_pid or value['selfSourceSha256']!=source_sha256 or value['guard'] not in {'ready','principal','process','installer','task','other'} or type(value['otherCount']) is not int or value['otherCount']<0 or not isinstance(value['processes'],list) or len(value['processes'])!=min(value['otherCount'],16):raise Blocked('generation')
    for item in value['processes']:
        if not isinstance(item,dict) or set(item)!={'pid','parentPid','creationTicks','name','commandSha256','sourceSha256','osState','osCreationTicks'} or type(item['pid']) is not int or item['pid']<=0 or item['pid']==child_pid or type(item['parentPid']) is not int or item['parentPid']<0 or (item['creationTicks'] is not None and (type(item['creationTicks']) is not int or not 0<item['creationTicks']<=3155378975999999999)) or item['name'] not in {'powershell.exe','pwsh.exe','vpn-control.exe','vpn-control-cli.exe','sing-box.exe','msiexec.exe','consent.exe'} or not isinstance(item['commandSha256'],str) or len(item['commandSha256'])!=64 or any(c not in '0123456789abcdef' for c in item['commandSha256']) or (item['sourceSha256'] is not None and (not isinstance(item['sourceSha256'],str) or len(item['sourceSha256'])!=64 or any(c not in '0123456789abcdef' for c in item['sourceSha256']))):raise Blocked('generation')
        if item['osState'] not in {'live','exited','absent','unknown'} or (item['osCreationTicks'] is not None and (type(item['osCreationTicks']) is not int or not 0<item['osCreationTicks']<=3155378975999999999)) or (item['osState']=='live' and item['osCreationTicks'] is None) or (item['osState'] in {'absent','unknown'} and item['osCreationTicks'] is not None):raise Blocked('generation')
    if len({item['pid'] for item in value['processes']})!=len(value['processes']):raise Blocked('generation')
    return value

def _process_gate_source(correlation,expected):
    if str(uuid.UUID(correlation))!=correlation or expected!=original._expected():raise Blocked('generation')
    common=original._common(expected).split('function Snapshot(',1)[0]
    snapshot=" $all=@(Get-CimInstance Win32_Process -ErrorAction Stop)"
    if common.count(snapshot)!=1:raise Blocked('generation')
    common=common.replace(snapshot,snapshot+"; $script:ObservedAll=$all",1)
    metadata=r'''
function SourceDigest($command) {
 try {
  if(-not $command -or $command.Length -gt 30000){return $null}
  $m=[regex]::Match($command,'FromBase64String\(''(?<data>[A-Za-z0-9+/=]+)''\)')
  if($m.Success){
   $bytes=[Convert]::FromBase64String($m.Groups['data'].Value)
   $inputStream=[IO.MemoryStream]::new([byte[]]$bytes);$gzip=[IO.Compression.GzipStream]::new($inputStream,[IO.Compression.CompressionMode]::Decompress);$outputStream=[IO.MemoryStream]::new()
   try{$chunk=[byte[]]::new(2048);while(($n=$gzip.Read($chunk,0,$chunk.Length)) -gt 0){if($outputStream.Length+$n -gt 260000){return $null};$outputStream.Write($chunk,0,$n)};return (Hash $outputStream.ToArray())}finally{$gzip.Dispose();$inputStream.Dispose();$outputStream.Dispose()}
  }
  $m=[regex]::Match($command,'(?i)-EncodedCommand\s+"?(?<data>[A-Za-z0-9+/=]+)')
  if($m.Success){return (Hash ([Convert]::FromBase64String($m.Groups['data'].Value)))}
  return $null
 }catch{return $null}
}
$script:ObservedAll=@();$guard='ready'
try{Idle}catch{$guard=$_.Exception.Message;if($guard -notin @('principal','process','installer','task')){$guard='other'}}
$self=@(Get-CimInstance Win32_Process -Filter ("ProcessId="+$PID) -ErrorAction Stop)
if($self.Count -ne 1){throw 'identity'}
$others=@($script:ObservedAll|Where-Object {$_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh|vpn-control|vpn-control-cli|sing-box|msiexec|consent)\.exe$'}|Sort-Object ProcessId)
$facts=@();foreach($p in @($others|Select-Object -First 16)){
 $ticks=$null;try{if($null -ne $p.CreationDate){$ticks=$p.CreationDate.ToUniversalTime().Ticks}}catch{}
 $command=[string]$p.CommandLine
 $osState='unknown';$osTicks=$null;$ownedProcess=$null
 try {
  $ownedProcess=[Diagnostics.Process]::GetProcessById([int]$p.ProcessId)
  if($ownedProcess.HasExited){$osState='exited'}else{$osTicks=$ownedProcess.StartTime.ToUniversalTime().Ticks;$osState=if($ownedProcess.HasExited){'exited'}else{'live'}}
 }catch{
  $osTicks=$null;$cause=$_.Exception
  if($cause -is [ArgumentException] -or $cause.InnerException -is [ArgumentException]){$osState='absent'}else{$osState='unknown'}
 }finally{if($null -ne $ownedProcess){$ownedProcess.Dispose()}}
 $facts+=@{pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;creationTicks=$ticks;name=$p.Name.ToLowerInvariant();commandSha256=(Hash ([Text.Encoding]::UTF8.GetBytes($command)));sourceSha256=(SourceDigest $command);osState=$osState;osCreationTicks=$osTicks}
}
[Console]::Out.WriteLine((@{correlationId='@CORRELATION@';selfPid=[int]$PID;selfSourceSha256=(SourceDigest ([string]$self[0].CommandLine));guard=$guard;otherCount=$others.Count;processes=@($facts)}|ConvertTo-Json -Depth 5 -Compress))
'''.replace('@CORRELATION@',correlation)
    return common+metadata

def _recovery_diagnostic_program():
    from . import windows_cp117_guest_agent_recovery as recovery
    setup=r'''
import fcntl,time
root,correlation,action,request_text,launcher,anchor_text=sys.argv[1:]
request=json.loads(request_text);descriptor=request['generation']
anchor=json.loads(anchor_text)
def directory(path):
 info=os.lstat(path)
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 return (info.st_dev,info.st_ino)
def read(path):
 if directory(root)!=root_identity or directory(job)!=job_identity:raise ValueError()
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  info=os.fstat(fd);current=os.lstat(path)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=8192 or (info.st_dev,info.st_ino)!=(current.st_dev,current.st_ino):raise ValueError()
  raw=os.read(fd,8193);after=os.fstat(fd);current=os.lstat(path)
  if len(raw)!=info.st_size or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns) or (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns):raise ValueError()
  if directory(root)!=root_identity or directory(job)!=job_identity:raise ValueError()
  return json.loads(raw)
 finally:os.close(fd)
def write(name,value):
 if directory(root)!=root_identity or directory(job)!=job_identity:raise ValueError()
 fd=os.open(os.path.join(job,name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  raw=json.dumps(value,separators=(',',':'),sort_keys=True).encode();offset=0
  while offset<len(raw):offset+=os.write(fd,raw[offset:])
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
root_identity=directory(root)
if not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',correlation) or request.get('correlationId')!=correlation or descriptor!=['windows-cp117','/home/kardinal/vpn-control-windows-msi-acceptance-cp117/cp135-launch/qga.sock',589342,520739,'S-1-5-21-2404255130-2183793310-3766671872-1002'] or action not in ('start','poll','status','result') or request.get('launcherSha256')!=hashlib.sha256(launcher.encode()).hexdigest() or not live(descriptor[1],str(descriptor[2]),str(descriptor[3])):raise ValueError()
job=os.path.join(root,'windows-recovery-read-diagnostic-'+correlation)
if action=='start':
 os.mkdir(job,0o700)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
job_identity=directory(job)
lockpath=os.path.join(job,'lock')
if action=='start':
 fd=os.open(lockpath,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
lock=os.open(lockpath,os.O_RDONLY|os.O_NOFOLLOW)
info=os.fstat(lock)
if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:raise ValueError()
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
if action=='start':write('request.json',request)
elif read(os.path.join(job,'request.json'))!=request:raise ValueError()
sequence=sum(1 for name in os.listdir(job) if re.fullmatch('poll-[0-9]{3}.json',name))
def save(event):
 global sequence
 if event['kind']=='child':write('child.json',{'requestSha256':hashlib.sha256(request_text.encode()).hexdigest(),**event})
 else:
  if sequence>=160:raise ValueError()
  write('poll-%03d.json'%sequence,event);sequence+=1
delegate=call
def fingerprint(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
def child_anchor():
 path=os.path.join(job,'child.json');before=os.lstat(path);child=read(path);after=os.lstat(path)
 if fingerprint(before)!=fingerprint(after):raise ValueError()
 return {'requestSha256':hashlib.sha256(request_text.encode()).hexdigest(),'child':child,'fingerprint':fingerprint(after),'rootIdentity':list(root_identity),'jobIdentity':list(job_identity)}
def bound_child():
 if child_anchor()!=anchor:raise ValueError()
 child=anchor['child']
 if child.get('requestSha256')!=hashlib.sha256(request_text.encode()).hexdigest() or child.get('kind')!='child' or type(child.get('pid')) is not int or child['pid']<=0:raise ValueError()
 return child
def call(sock,command,args):
 if command=='guest-exec-status' and args!={'pid':bound_child()['pid']}:raise ValueError()
 result=_recovery_call(delegate,sock,command,args,save,time.monotonic)
 if command=='guest-exec-status' and isinstance(result,dict) and result.get('exited') is True:
  packet={'child':bound_child(),'status':result}
  if len(json.dumps(packet).encode())>8192:raise ValueError()
  write('terminal.json',packet)
 return result
def summary():
 child=bound_child()
 event=read(os.path.join(job,'poll-%03d.json'%(sequence-1))) if sequence else None
 return {'state':'diagnosed','childPid':child['pid'],'pollCount':sequence,'lastObservation':event,'replayAllowed':False,'productAction':False}
'''
    finish=r'''
if action=='result':
 phase='powershell-terminal'
 try:
  packet=read(os.path.join(job,'terminal.json'))
  if set(packet)!={'child','status'} or packet['child']!=bound_child():raise ValueError()
  item=packet['status']
  if item.get('exitcode')!=0 or item.get('out-truncated',False) is not False or item.get('err-truncated',False) is not False:raise ValueError()
  phase='json-shape';value=json.loads(decode(base64.b64decode(item.get('out-data',''),validate=True)))
  if not isinstance(value,dict):raise ValueError()
  output={'state':'observed','receipt':value}
 except Exception:output={'state':'diagnosed','phase':phase}
 print(json.dumps(output,sort_keys=True,separators=(',',':')))
elif action=='start':
 if anchor!={}:raise ValueError()
 call(descriptor[1],'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-Command',launcher],'capture-output':True})
 print(json.dumps({'state':'retained','anchor':child_anchor()},sort_keys=True,separators=(',',':')))
else:
 child=bound_child()
 for _ in range(80 if action=='poll' else 1):
  try:item=call(descriptor[1],'guest-exec-status',{'pid':child['pid']})
  except Exception:break
  if not isinstance(item,dict) or item.get('exited') is not False:break
  time.sleep(.25)
 print(json.dumps(summary(),sort_keys=True,separators=(',',':')))
'''
    return base._QGA+inspect.getsource(_recovery_call)+setup+finish

def recovery_read_diagnostic(root,correlation,action):
    from . import windows_cp117_guest_agent_recovery as recovery
    if action not in {'start','status'} or not isinstance(correlation,str) or str(uuid.UUID(correlation))!=correlation:raise ValueError('fixed diagnostic inputs')
    root=Path(root).resolve(strict=True)
    with history._history_lock(root):
        descriptor,closed,expected=original._admit_local(root)
        config,target,current=base._descriptor(root)
        if current!=descriptor:raise Blocked('generation')
        script=base._fixed_recovery_task_status_script();launcher=recovery._launcher(script)
        if len(launcher)>28000:raise ValueError('diagnostic command bound')
        request={'version':1,'correlationId':correlation,'generation':list(descriptor),'sourceSha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scriptSha256':hashlib.sha256(script.encode('utf-16le')).hexdigest(),'launcherSha256':hashlib.sha256(launcher.encode()).hexdigest()}
        directory=root/'.rag_index/windows-recovery-read-diagnostic'
        if not directory.exists():os.mkdir(directory,0o700)
        history._directory(directory)
        path=directory/(correlation+'.json')
        if action=='start':wire.guards.secure_write_create(path,request)
        elif _read_private(path)!=request:raise Blocked('intent')
        anchor_path=directory/(correlation+'.child.json')
        receipt_path=directory/(correlation+'.child.receipt.json')
        seal_path=directory/(correlation+'.child.seal.json')
        request_text=json.dumps(request,separators=(',',':'),sort_keys=True)
        args=(str(target.fixture_transfer_root),correlation,action,request_text,launcher)
        if action=='start':
            raw=base._remote(config,_recovery_diagnostic_program(),args+('{}',),None,60)
            if raw is None:return {'state':'unknown','replayAllowed':False,'productAction':False}
            retained=json.loads(raw,object_pairs_hook=history._unique)
            if not isinstance(retained,dict) or set(retained)!={'state','anchor'} or retained['state']!='retained':raise Blocked('journal')
            anchor=retained['anchor']
            if not isinstance(anchor,dict) or set(anchor)!={'requestSha256','child','fingerprint','rootIdentity','jobIdentity'} or anchor['requestSha256']!=hashlib.sha256(request_text.encode()).hexdigest() or not isinstance(anchor['child'],dict) or set(anchor['child'])!={'kind','pid','requestSha256'} or anchor['child']['kind']!='child' or type(anchor['child']['pid']) is not int or anchor['child']['pid']<=0 or anchor['child']['requestSha256']!=anchor['requestSha256'] or not isinstance(anchor['fingerprint'],list) or len(anchor['fingerprint'])!=8 or any(type(x) is not int for x in anchor['fingerprint']) or any(not isinstance(anchor[k],list) or len(anchor[k])!=2 or any(type(x) is not int for x in anchor[k]) for k in ('rootIdentity','jobIdentity')):raise Blocked('journal')
            wire.guards.secure_write_create(anchor_path,anchor)
            current,request_identity=_anchor_read(path)
            stored_anchor,anchor_identity=_anchor_read(anchor_path)
            if current!=request or stored_anchor!=anchor:raise Blocked('intent')
            wire.guards.secure_write_create(receipt_path,{'request':request_identity,'anchor':anchor_identity,'correlationId':correlation,'guestGeneration':request['generation'],'sourceSha256':request['sourceSha256']})
            receipt,receipt_identity=_anchor_read(receipt_path)
            wire.guards.secure_write_create(seal_path,{'receipt':receipt_identity,'request':request_identity,'correlationId':correlation,'guestGeneration':request['generation']})
            seal,seal_identity=_anchor_read(seal_path)
            wire.guards.secure_write_create(seal_path.with_suffix('.authority.json'),{'seal':seal_identity,'request':request_identity,'correlationId':correlation,'guestGeneration':request['generation']})
        else:
            anchor,_=_anchor_authority(path,anchor_path,receipt_path,seal_path,request)
        anchor,authority=_anchor_authority(path,anchor_path,receipt_path,seal_path,request)
        raw=base._remote(config,_recovery_diagnostic_program(),(str(target.fixture_transfer_root),correlation,'poll' if action=='start' else 'status',request_text,launcher,json.dumps(anchor,separators=(',',':'),sort_keys=True)),None,60)
        if _anchor_authority(path,anchor_path,receipt_path,seal_path,request)!=(anchor,authority):raise Blocked('intent')
        if raw is None:return {'state':'unknown','replayAllowed':False,'productAction':False}
        value=json.loads(raw,object_pairs_hook=history._unique)
        if not isinstance(value,dict) or set(value)!={'state','childPid','pollCount','lastObservation','replayAllowed','productAction'} or value['state']!='diagnosed' or type(value['childPid']) is not int or value['childPid']<=0 or type(value['pollCount']) is not int or not 0<=value['pollCount']<=160 or value['replayAllowed'] is not False or value['productAction'] is not False:raise Blocked('journal')
        event=value['lastObservation']
        if event is None:
            if value['pollCount']!=0:raise Blocked('journal')
        elif (not isinstance(event,dict) or set(event) not in ({'kind','pid','outcome','elapsedMs'},{'kind','pid','outcome','elapsedMs','exitcode'}) or event.get('kind')!='poll' or type(event.get('pid')) is not int or event['pid']!=value['childPid'] or event.get('outcome') not in {'socket-timeout','malformed','transport','exited','running'} or type(event.get('elapsedMs')) is not int or not 0<=event['elapsedMs']<=60000 or ('exitcode' in event and (event['outcome']!='exited' or type(event['exitcode']) is not int))):raise Blocked('journal')
        return value

def retained_recovery_observe(root,config,descriptor,script,correlation):
    """Profile one actual fixed read; preserve its original receipt semantics."""
    _validate_recovery_source(root,config,descriptor,script)
    root=Path(root).resolve(strict=True)
    diagnostic=recovery_read_diagnostic(root,correlation,'start')
    if diagnostic.get('state')!='diagnosed':return None,diagnostic
    event=diagnostic.get('lastObservation')
    if not isinstance(event,dict) or event.get('outcome')!='exited':return {'_phase':'guest-status'},diagnostic
    directory=root/'.rag_index/windows-recovery-read-diagnostic'
    path=directory/(correlation+'.json');anchor_path=directory/(correlation+'.child.json')
    receipt_path=directory/(correlation+'.child.receipt.json');seal_path=directory/(correlation+'.child.seal.json')
    request,_=_anchor_read(path)
    with history._history_lock(root):
        _validate_recovery_source(root,config,descriptor,script)
        anchor,authority=_anchor_authority(path,anchor_path,receipt_path,seal_path,request)
        current_config,target,current=base._descriptor(root)
        from . import windows_cp117_guest_agent_recovery as recovery
        launcher=recovery._launcher(script)
        raw=base._remote(current_config,_recovery_diagnostic_program(),(str(target.fixture_transfer_root),correlation,'result',json.dumps(request,separators=(',',':'),sort_keys=True),launcher,json.dumps(anchor,separators=(',',':'),sort_keys=True)),None,60)
        if _anchor_authority(path,anchor_path,receipt_path,seal_path,request)!=(anchor,authority):raise Blocked('intent')
        _validate_recovery_source(root,config,descriptor,script)
        if raw is None:return None,diagnostic
        value=json.loads(raw,object_pairs_hook=history._unique)
        if isinstance(value,dict) and set(value)=={'state','receipt'} and value['state']=='observed' and isinstance(value['receipt'],dict):return value['receipt'],diagnostic
        if isinstance(value,dict) and set(value)=={'state','phase'} and value['state']=='diagnosed' and value['phase'] in {'powershell-terminal','json-shape'}:return {'_phase':value['phase']},diagnostic
        return None,diagnostic
def _check(value):
    try:return original._checked(value)
    except original.Blocked as error:raise Blocked(error.phase) from error

def _host_phase(checkpoint,error):
    assert checkpoint in _HOST_CHECKPOINTS
    kinds=((json.JSONDecodeError,'json'),(UnicodeError,'encoding'),(FileNotFoundError,'missing'),(PermissionError,'permission'),(OSError,'os'),(TypeError,'type'),(KeyError,'key'),(IndexError,'index'),(EOFError,'eof'),(AttributeError,'attribute'),(OverflowError,'overflow'),(ValueError,'value'),(RuntimeError,'runtime'))
    kind=next((kind for cls,kind in kinds if isinstance(error,cls)),'other')
    return 'host-'+checkpoint+'-'+kind

def _host_call(checkpoint,function,*args):
    try:return function(*args)
    except (Blocked,original.Blocked):raise
    except Exception as error:raise Blocked(_host_phase(checkpoint,error)) from error

def _read_private(path):
    if not os.path.lexists(path):return None
    parents=[(p,history._directory(p)) for p in (path.parent.parent,path.parent)]
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd);current=path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or not 0<before.st_size<=16384
                or (before.st_dev,before.st_ino)!=(current.st_dev,current.st_ino)):raise Blocked('intent')
        raw=os.read(fd,16385)
        after=os.fstat(fd);current=path.lstat()
        if (len(raw)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
                or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(current.st_dev,current.st_ino,current.st_size,current.st_mtime_ns,current.st_ctime_ns)):raise Blocked('intent')
        for parent,old in parents:
            now=history._directory(parent)
            if (old.st_dev,old.st_ino)!=(now.st_dev,now.st_ino):raise Blocked('intent')
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=history._unique)
        if not isinstance(value,dict):raise Blocked('intent')
        return value
    finally:os.close(fd)

def _anchor_generation(info):
    return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]

def _anchor_read(path):
    """Retain full local authority identity, rejecting hardlinks before bytes."""
    parents=[(p,history._directory(p)) for p in (path.parent.parent,path.parent)]
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=16384 or _anchor_generation(before)!=_anchor_generation(path.lstat()):raise Blocked('intent')
        raw=os.read(fd,16385)
        if len(raw)!=before.st_size or _anchor_generation(before)!=_anchor_generation(os.fstat(fd)) or _anchor_generation(before)!=_anchor_generation(path.lstat()):raise Blocked('intent')
        for parent,old in parents:
            if _anchor_generation(history._directory(parent))!=_anchor_generation(old):raise Blocked('intent')
        value=json.loads(raw,object_pairs_hook=history._unique)
        if not isinstance(value,dict):raise Blocked('intent')
        return value,{'sha256':hashlib.sha256(raw).hexdigest(),'generation':_anchor_generation(before)}
    finally:os.close(fd)

def _anchor_authority(path,anchor_path,receipt_path,seal_path,request):
    current,request_identity=_anchor_read(path)
    anchor,anchor_identity=_anchor_read(anchor_path)
    receipt,receipt_identity=_anchor_read(receipt_path)
    seal,seal_identity=_anchor_read(seal_path)
    authority,authority_identity=_anchor_read(seal_path.with_suffix('.authority.json'))
    expected={'request':request_identity,'anchor':anchor_identity,'correlationId':request['correlationId'],'guestGeneration':request['generation'],'sourceSha256':request['sourceSha256']}
    if current!=request or receipt!=expected or seal!={'receipt':receipt_identity,'request':request_identity,'correlationId':request['correlationId'],'guestGeneration':request['generation']} or authority!={'seal':seal_identity,'request':request_identity,'correlationId':request['correlationId'],'guestGeneration':request['generation']}:raise Blocked('intent')
    return anchor,(request_identity,anchor_identity,receipt_identity,seal_identity,authority_identity)

def _validate_original(intent,value,expected):
    if (not isinstance(intent,dict) or set(intent)!={'binding','bindingSha256','actionSha256'} or not isinstance(intent['binding'],dict)
            or original._plan(intent['binding'],expected)[1]!=intent):raise Blocked('original-intent')
    if not isinstance(value,dict) or set(value)!={'binding','terminal','archivesPacket','progress','absent','terminalAbsent'}:raise Blocked('original-envelope')
    if value['binding']!=intent:raise Blocked('original-binding')
    if value['terminal'] is not None or value['terminalAbsent'] is not True:raise Blocked('original-terminal')
    if value['absent'] is not True:raise Blocked('original-absence')
    if not isinstance(value['progress'],list) or len(value['progress'])!=5:raise Blocked('original-progress-shape')
    b=intent['binding'];fields={'retirementCorrelationId','generation','originalProductSourceSha','historicalRecordSha256','taskArgumentSha256','taskToolSourceSha256','snapshots'}
    if (set(b)!=fields or b['retirementCorrelationId']!=original._RETIREMENT or b['generation']!=list(wire.observer._GENERATION) or b['originalProductSourceSha']!=original._SOURCE
            or b['historicalRecordSha256']!=original._RECORDS or b['taskArgumentSha256']!=list(original._ARGUMENT_HASHES) or b['taskToolSourceSha256']!=[e['toolSourceSha256'] for e in expected]
            or not isinstance(b['snapshots'],list) or len(b['snapshots'])!=5):raise Blocked('original-intent')
    rows=_host_call('archive',original._unpack_archives,value['archivesPacket'])
    snapshots=[_host_call('archive',original._archive,row,e) for row,e in zip(rows,expected)]
    if snapshots!=intent['binding']['snapshots']:raise Blocked('original-snapshots')
    for i,(progress,snapshot) in enumerate(zip(value['progress'],snapshots)):
        if (progress!={'retirementCorrelationId':original._RETIREMENT,'index':i,'bindingSha256':intent['bindingSha256'],'xmlSha256':snapshot['xmlSha256'],'state':'removed'} or type(progress.get('index')) is not int):raise Blocked('original-progress-binding')
    return {'originalIntent':intent,'archivePayloadSha256':value['archivesPacket']['sha256'],'progress':value['progress']}

def _history_failure(root,descriptor,closed,expected):
    """Fresh localization never replaces or admits the failed observation."""
    try:current=_host_call('admission',original._admit_local,root)
    except original.Blocked as error:
        if error.phase=='history':raise Blocked('original-history-local') from error
        raise
    if current!=(descriptor,closed,expected):raise Blocked('generation')
    if _host_call('steady',base._fixed_c32_task_terminal,root,descriptor,original._RETIREMENT) is not True:raise Blocked('original-history-c32')
    if _host_call('steady',base._fixed_recovery_task_terminal,root,descriptor) is not True:raise Blocked('original-history-recovery')
    # Both later checks passing cannot erase the earlier unknown observation.
    raise Blocked('original-history-transient')

def _proof(root):
    descriptor,closed,expected=_host_call('admission',original._admit_local,root)
    observation=_host_call('observer',original.diagnose,root,{})
    if observation==original._result('unknown','history'):
        _history_failure(root,descriptor,closed,expected)
    if observation!=original._result('unknown','diagnostic-terminal-absent-verified'):
        if isinstance(observation,dict) and set(observation)==set(original._result('unknown','history')) and observation.get('phase') in original._PHASES and observation.get('state') in {'blocked','unknown'}:
            raise Blocked('original-observer-'+observation['phase'])
        raise Blocked('original-observer-shape')
    intent=_host_call('original-intent',_read_private,root/original._DIR/'intent.json')
    source=_host_call('plan',original._diagnostic_reader,expected)
    if not _host_call('parse',_parse,root,descriptor,closed,source):raise Blocked('parser')
    observations=[]
    for _ in range(2):
        value=_check(_host_call('probe',original._run,root,descriptor,closed,source))
        observations.append(_host_call('validation',_validate_original,intent,value,expected))
    if observations[0]!=observations[1]:raise Blocked('race')
    scope=_FRESH_READ_SCOPE.get()
    if scope is not None:
        if scope['root']!=root or scope['expected']!=expected:raise Blocked('generation')
        scope['proof']=observations[0]
    _host_call('steady',original._steady,root,descriptor)
    if _host_call('identity',original._admit_local,root)!=(descriptor,closed,expected):raise Blocked('generation')
    return descriptor,closed,expected,observations[0]

# Structural comparison avoids dependence on unordered PS hashtable output.
_EQUAL=r'''
function EqualJson($a,$b) {
 if($null -eq $a -or $null -eq $b){return ($null -eq $a -and $null -eq $b)}
 if($b -is [string]){return ($a -is [string] -and $a -ceq $b)}
 if($b -is [bool]){return ($a -is [bool] -and $a -eq $b)}
 if($b -is [long] -or $b -is [int]){return (($a -is [long] -or $a -is [int]) -and $a -eq $b)}
 if($b -is [array]){if($a -isnot [array] -or $a.Count -ne $b.Count){return $false};for($j=0;$j -lt $b.Count;$j++){if(-not (EqualJson $a[$j] $b[$j])){return $false}};return $true}
 if($b -isnot [Management.Automation.PSCustomObject] -or $a -isnot [Management.Automation.PSCustomObject]){return $false}
 $an=@($a.PSObject.Properties.Name|Sort-Object);$bn=@($b.PSObject.Properties.Name|Sort-Object)
 if($an.Count -ne $bn.Count){return $false};for($j=0;$j -lt $bn.Count;$j++){if($an[$j] -cne $bn[$j] -or -not (EqualJson $a.($bn[$j]) $b.($bn[$j]))){return $false}};return $true
}
'''
def _original_guard(expected,proof):
    # Reuse the reviewed fixed reader, excluding only its envelope and output.
    source=_host_call('plan',original._diagnostic_reader,expected)
    body=source.split('try{\n',1)[1].rsplit('\n}catch{',1)[0]
    output='[Console]::Out.WriteLine((@{binding=$binding;terminal=$terminal;archivesPacket='
    body=body[:body.index(output)]
    data=json.dumps(proof,separators=(',',':'),sort_keys=True).replace("'","''")
    return body+_EQUAL+"\n$proof=ConvertFrom-Json '"+data+"'\n"+r'''
if(-not $terminalAbsent -or $null -ne $terminal -or -not (EqualJson $binding $proof.originalIntent) -or $progress.Count -ne 5){throw 'original-proof'}
$packet=Read-SecureJson 'archive.json'
if($packet.sha256 -cne $proof.archivePayloadSha256){throw 'original-proof'}
for($j=0;$j -lt 5;$j++){if(-not (EqualJson $progress[$j] $proof.progress[$j])){throw 'original-proof'};Same $archives[$j] $proof.originalIntent.binding.snapshots[$j]}
Idle
'''

def _scripts(binding,expected,proof):
    guard=_original_guard(expected,proof)
    own=original.journal.powershell(_ROOT,_LEAVES).replace('[Text.Encoding]::UTF8.GetString($bytes)','[Text.UTF8Encoding]::new($false,$true).GetString($bytes)')
    literal=json.dumps(binding,separators=(',',':'),sort_keys=True).replace("'","''")
    expected_binding="$closureBinding=ConvertFrom-Json '"+literal+"';$bindingSha='"+_digest(binding)+"';$actionSha='@ACTION_SHA@'\n"
    first=guard+own+expected_binding+r'''
if(Test-Path -LiteralPath $JournalRoot){throw 'binding'}
Initialize-SecureJournal
Write-SecureJsonCreate 'binding.json' ((@{binding=$closureBinding;bindingSha256=$bindingSha;actionSha256=$actionSha})|ConvertTo-Json -Depth 12 -Compress)
[Console]::Out.WriteLine('{"bound":true}')
'''
    final=guard+own+expected_binding+r'''
$stored=Read-SecureJson 'binding.json'
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force).Count -ne 1 -or -not (EqualJson $stored.binding $closureBinding) -or $stored.bindingSha256 -cne $bindingSha -or $stored.actionSha256 -cne $actionSha){throw 'binding'}
for($j=0;$j -lt 5;$j++){Absent $expected[$j]};Idle
Write-SecureJsonCreate 'terminal.json' ((@{closureCorrelationId='@CLOSE@';originalRetirementCorrelationId='@OLD@';bindingSha256=$bindingSha;actionSha256=$actionSha;state='closed';proof='current-absence';originalOutcome='unknown'})|ConvertTo-Json -Compress)
[Console]::Out.WriteLine('{"closed":true}')
'''
    first=original._guest(first,_DISPATCH_PHASES);final=original._guest(final.replace('@CLOSE@',_CLOSE).replace('@OLD@',original._RETIREMENT),_DISPATCH_PHASES)
    action=hashlib.sha256((first+'\0'+final).replace('@ACTION_SHA@','').encode('utf-16le')).hexdigest()
    return first.replace('@ACTION_SHA@',action),final.replace('@ACTION_SHA@',action),{'binding':binding,'bindingSha256':_digest(binding),'actionSha256':action}

def _reader(expected,proof):
    own=original.journal.powershell(_ROOT,_LEAVES).replace('[Text.Encoding]::UTF8.GetString($bytes)','[Text.UTF8Encoding]::new($false,$true).GetString($bytes)')
    begin=own.index('function Initialize-SecureJournal ');end=own.index('function Read-SecureJson(',begin)
    own=own[:begin]+own[end:];own=own[:own.index('function Write-SecureJsonCreate(')]
    return original._guest(_original_guard(expected,proof)+own+r'''
$stored=Read-SecureJson 'binding.json';$terminal=Read-SecureJson 'terminal.json'
if(@(Get-ChildItem -LiteralPath $JournalRoot -Force).Count -ne 2){throw 'journal'};for($j=0;$j -lt 5;$j++){Absent $expected[$j]};Idle
[Console]::Out.WriteLine((@{binding=$stored;terminal=$terminal}|ConvertTo-Json -Depth 12 -Compress))
''',_PHASES)

def _root_absence(expected):
    return original._guest(original._common(expected)+"\nIdle;if(Test-Path -LiteralPath '"+_ROOT+"'){throw 'binding'};Idle;[Console]::Out.WriteLine('{\"absent\":true}')",_PHASES)

def _binding(descriptor,proof):
    i=proof['originalIntent']
    return {'version':1,'closureCorrelationId':_CLOSE,'originalRetirementCorrelationId':original._RETIREMENT,'generation':list(descriptor),
            'proof':'current-absence','originalOutcome':'unknown','originalIntentSha256':_digest(i),'originalBindingSha256':i['bindingSha256'],
            'originalActionSha256':i['actionSha256'],'archivePayloadSha256':proof['archivePayloadSha256'],
            'progressSha256':[_digest(p) for p in proof['progress']]}

def _recheck(root,descriptor,closed,expected,proof):
    if os.path.lexists(root/base.campaign_lease._DIR/'active.json'):raise Blocked('active-lease')
    if _host_call('identity',original._admit_local,root)!=(descriptor,closed,expected) or _read_private(root/original._DIR/'intent.json')!=proof['originalIntent']:raise Blocked('generation')
    _host_call('steady',original._steady,root,descriptor)

def _status(root):
    intent=_host_call('status',_read_private,root/_DIR/'intent.json')
    if intent is None:return _result('not-started','intent')
    descriptor,closed,expected,proof=_host_call('validation',_proof,root)
    binding=_binding(descriptor,proof)
    if _scripts(binding,expected,proof)[2]!=intent:raise Blocked('intent')
    source=_host_call('plan',_reader,expected,proof)
    if not _host_call('parse',_parse,root,descriptor,closed,source):raise Blocked('parser')
    value=_check(_host_call('probe',original._run,root,descriptor,closed,source))
    terminal={'closureCorrelationId':_CLOSE,'originalRetirementCorrelationId':original._RETIREMENT,'bindingSha256':intent['bindingSha256'],'actionSha256':intent['actionSha256'],'state':'closed','proof':'current-absence','originalOutcome':'unknown'}
    if not isinstance(value,dict) or set(value)!={'binding','terminal'} or value['binding']!=intent or value['terminal']!=terminal:raise Blocked('terminal')
    _recheck(root,descriptor,closed,expected,proof)
    return _result('closed','complete')

def workflow(root:Path|str,action:str,inputs:Mapping[str,Any]):
    if not isinstance(inputs,Mapping) or dict(inputs)!={} or action not in {'preflight','diagnose','start','status'}:raise ValueError('Fixed absence closure takes no inputs.')
    if not history._supported() or base is None:return _result('blocked','platform')
    consumed=False;checkpoint='root'
    try:
        root=Path(root).resolve(strict=True)
        fresh=action=='start' and not os.path.lexists(root/_DIR/'intent.json')
        checkpoint='lock'
        with (original._start_admission(root) if fresh else nullcontext()):
            with history._history_lock(root),_fresh_read_scope(root,action):
                consumed=os.path.lexists(root/_DIR/'intent.json')
                if os.path.lexists(root/base.campaign_lease._DIR/'active.json'):raise Blocked('active-lease')
                if consumed or action=='status':return _host_call('status',_status,root)
                descriptor,closed,expected,proof=_host_call('validation',_proof,root)
                absence=_host_call('plan',_root_absence,expected)
                if not _host_call('parse',_parse,root,descriptor,closed,absence):raise Blocked('parser')
                if _check(_host_call('absence-root',original._run,root,descriptor,closed,absence))!={'absent':True}:raise Blocked('binding')
                binding=_binding(descriptor,proof);first,final,intent=_host_call('plan',_scripts,binding,expected,proof)
                for source in (first,final,_reader(expected,proof)):
                    if not _host_call('parse',_parse,root,descriptor,closed,source):raise Blocked('parser')
                _recheck(root,descriptor,closed,expected,proof)
                if action!='start':return _result('ready','snapshot')
                config,target,current=_host_call('reservation',base._descriptor,root)
                if current!=descriptor:raise Blocked('generation')
                try:base._require_base_route_free(root,config,target,current)
                except (OSError,ValueError) as error:raise Blocked('base-route') from error
                checkpoint='intent-write'
                if not (root/_DIR).exists():
                    os.mkdir(root/_DIR,0o700)
                    fd=os.open(root/'.rag_index',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                    try:os.fsync(fd)
                    finally:os.close(fd)
                history._directory(root/_DIR)
                wire.guards.secure_write_create(root/_DIR/'intent.json',intent);consumed=True
                _recheck(root,descriptor,closed,expected,proof)
                if _check(_host_call('binding-dispatch',original._run,root,descriptor,closed,first))!={'bound':True}:raise Blocked('dispatch')
                # A new full observation precedes terminal creation. No later call
                # resumes this branch when an intent has already been consumed.
                d,c,e,p=_host_call('validation',_proof,root)
                if (d,c,e,p)!=(descriptor,closed,expected,proof):raise Blocked('generation')
                _recheck(root,descriptor,closed,expected,proof)
                if _check(_host_call('terminal-dispatch',original._run,root,descriptor,closed,final))!={'closed':True}:raise Blocked('dispatch')
                return _host_call('status',_status,root)
    except (Blocked,original.Blocked) as error:return _result('unknown' if consumed else 'blocked',error.phase)
    except Exception as error:return _result('unknown' if consumed else 'blocked',_host_phase(checkpoint,error))
def preflight(root,value):return workflow(root,'preflight',value)
def diagnose(root,value):return workflow(root,'diagnose',value)
def start(root,value):return workflow(root,'start',value)
def status(root,value):return workflow(root,'status',value)
