"""Fixed Linux packaging MCP adapter with bounded pipes for every query.

No public release or arbitrary command. Inherited clean same-Git source admission,
remote stage/anchor/gate and verified collection remain authoritative. Query births
are durable and phase typed: early phases never manufacture remote runtime pins.
The namespace assumes one cooperating operator; it is not external-writer CAS.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
from . import ssh_tmux_session_ssh as old
from . import ssh_tmux_session as session
from . import linux_package_fixture_build as build
from . import ssh_transport
if os.name=='posix':
    from . import ssh_tmux_source_staging_recovery as recovery
    from . import ssh_tmux_bounded_pipe_collection as pipe
else:
    recovery=pipe=None

AdapterError=old.AdapterError
CollectionError=AdapterError
need=old.need
MAX_STDOUT=2*1024**2
MAX_STDERR=65536
PIPE_SHA='32995897f304e57d5a6848184e5873a02e0e3c9287d4683d895ec78eeeef5402'
BaseDriver=recovery.CurrentExactFetchDriver if recovery is not None else object

def _capsule(root):return pipe._capsule(root)
def _write_once(path,data):return pipe._write_once(path,data)

def _sources(root):
    need(pipe is not None,'unsupported_coordinator_platform')
    values=pipe._current_sources(root)
    need(values[str(Path(pipe.__file__).absolute())]['sha256']==PIPE_SHA,'pipe_source_changed')
    path=Path(__file__).absolute();values[str(path)]=pipe._read(path,262144,False)[1]
    return values

def _capture(root,*,authority,launch,payload,guard,timeout_seconds=95):
    """One nonblocking duplex query; durable finite outcome even on response loss."""
    need(type(authority)is dict and set(authority)=={'phase','snapshot','sources','transport','local','argvSha256'} and authority['phase'] in ('availability','stage','prepare','release','status','collect'),'capture_authority_invalid')
    need(type(payload)is bytes and len(payload)<=131072 and type(timeout_seconds)in (int,float) and 0<timeout_seconds<=95,'capture_payload_invalid')
    try:guard()
    except Exception:raise CollectionError('authority_changed') from None
    capsule=_capsule(root);intent=_write_once(capsule/'intent.json',session.canonical({'authority':authority,'payloadSha256':hashlib.sha256(payload).hexdigest(),'replayAllowed':False}))
    process=None;selector=None;stdout=bytearray();stderr=bytearray();written=0;failure=None;timed_out=False;capped=False;code=None
    try:
        guard();process=launch();need(all(getattr(process,k,None)is not None for k in ('stdin','stdout','stderr')),'pipe_launch_unknown')
        selector=selectors.DefaultSelector()
        for stream,label in ((process.stdout,'stdout'),(process.stderr,'stderr'),(process.stdin,'stdin')):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_WRITE if label=='stdin' else selectors.EVENT_READ,label)
        deadline=time.monotonic()+timeout_seconds
        while selector.get_map():
            left=deadline-time.monotonic()
            if left<=0:timed_out=True;failure='query_timeout';break
            for key,_ in selector.select(min(.2,left)):
                label=key.data;stream=key.fileobj
                if label=='stdin':
                    if written==len(payload):selector.unregister(stream);stream.close();continue
                    try:count=os.write(stream.fileno(),memoryview(payload)[written:written+65536])
                    except (BlockingIOError,InterruptedError):continue
                    need(count>0,'stdin_write_unknown');written+=count
                else:
                    sink,limit=(stdout,MAX_STDOUT) if label=='stdout' else (stderr,MAX_STDERR)
                    try:block=os.read(stream.fileno(),min(65536,limit+1-len(sink)))
                    except (BlockingIOError,InterruptedError):continue
                    if not block:selector.unregister(stream);stream.close()
                    else:
                        sink.extend(block)
                        if len(sink)>limit:capped=True;failure='query_output_limit';break
            if failure:break
        if not failure:
            code=process.wait(timeout=max(.01,min(2,deadline-time.monotonic())))
            if code!=0:failure='query_exit_unknown'
    except subprocess.TimeoutExpired:
        timed_out=True;failure='query_timeout'
    except Exception:
        if failure is None:failure='query_transport_unknown'
    finally:
        if selector is not None:selector.close()
        if process is not None:
            try:
                if process.poll()is None:process.kill()
                code=process.wait(timeout=2)
            except (OSError,subprocess.SubprocessError):failure=failure or 'query_reap_unknown'
            for name in ('stdin','stdout','stderr'):
                stream=getattr(process,name,None)
                if stream is not None:
                    try:stream.close()
                    except OSError:pass
        try:guard()
        except Exception:failure='authority_changed'
        out_pin=_write_once(capsule/'stdout',bytes(stdout));err_pin=_write_once(capsule/'stderr',bytes(stderr))
        receipt={'schemaVersion':1,'intentPin':intent,'stdoutPin':out_pin,'stderrPin':err_pin,'exitCode':code,'capped':capped,'timedOut':timed_out,'stdinBytesWritten':written,'failure':failure,'replayAllowed':False}
        receipt_pin=_write_once(capsule/'receipt.json',session.canonical(receipt))
    return {'state':'captured' if code==0 and failure is None and written==len(payload) else 'unknown','receiptPin':receipt_pin,'replayAllowed':False,'nativeActionAllowed':False},capsule


class McpTmuxDriver(BaseDriver):
    def __init__(self,root,*,source_root=None):
        need(os.name=='posix' and recovery is not None,'unsupported_coordinator_platform')
        super().__init__(root,source_root=source_root)

    def _phase(self,program,payload,job):
        need(type(payload)is dict,'invalid_query_payload')
        if program==old._AVAILABILITY:
            need(not payload and job is None,'invalid_availability_request')
            return 'availability',None,{}
        need(program in (old._STAGE,old._ACTION),'unsupported_program')
        value=payload.get('request');need(type(value)is dict,'invalid_purpose')
        request=build._request({key:value.get(key) for key in ('sourceSha','baseVersion','targetVersion','correlationId')})
        need(value==old.purpose(request) and job==self._job(request),'invalid_purpose')
        snapshot=self._snapshot(request)
        raw,intent=pipe._read(job/'tmux-adapter-intent.json')
        need(json.loads(raw)==snapshot,'adapter_intent_changed')
        local={'job':session.private_dir(job),'intentPin':intent}
        if program==old._STAGE:
            tools=self._tools()
            need(set(payload)=={'request','build','tool'} and payload['build']==base64.b64encode(tools['linux_package_fixture_build.py']['raw']).decode() and payload['tool']==base64.b64encode(tools['ssh_tmux_session.py']['raw']).decode(),'invalid_stage_payload')
            return 'stage',snapshot,local
        action=payload.get('action');need(action in ('prepare','release','status','collect'),'unsupported_internal_action')
        keys={'request','action','stagePin'}|({'anchorPin'} if action!='prepare' else set())|({'terminalPin','offset','limit','resultPin'} if action=='collect' else set())
        need(set(payload)==keys and session._valid_pin(payload['stagePin']),'invalid_action_payload')
        unused,saved=self._saved(request);need(saved==snapshot,'adapter_intent_changed')
        raw,pin=pipe._read(job/'tmux-stage.json');stage=json.loads(raw)
        need(stage=={'state':'staged','correlationId':request['correlationId'],'stagePin':payload['stagePin']},'stage_authority_changed');local['stagePin']=pin
        if action!='prepare':
            raw,pin=pipe._read(job/'tmux-anchor.json');anchor=json.loads(raw)
            need(anchor=={'state':'prepared','correlationId':request['correlationId'],'anchorPin':payload['anchorPin'],'replayAllowed':False,'artifactVerification':'required'} and anchor['replayAllowed']is False and session._valid_pin(payload['anchorPin']),'anchor_authority_changed');local['anchorPin']=pin
        if action=='release':
            raw,pin=pipe._read(job/'tmux-release-intent.json');need(json.loads(raw)=={'request':request},'release_intent_changed');local['releaseIntentPin']=pin
        if action=='collect':
            need(type(payload['offset'])is int and 0<=payload['offset']<=session.MAX_RESULT and type(payload['limit'])is int and 1<=payload['limit']<=1048576 and session._valid_pin(payload['terminalPin']) and (payload['resultPin']is None or session._valid_pin(payload['resultPin'])),'invalid_collection_payload')
            raw,pin=pipe._read(job/'tmux-collection.json');need(json.loads(raw)=={'request':request,'terminalPin':payload['terminalPin']},'terminal_authority_changed');local['terminalPin']=pin
            if payload['resultPin']is not None:need(old.result_record(job)==payload['resultPin'],'result_authority_changed')
        birth=job/'tmux-mcp-adapter-birth.json'
        if os.path.lexists(birth):
            raw,pin=pipe._read(birth);value=json.loads(raw)
            seal_raw,seal_pin=pipe._read(job/'tmux-mcp-adapter-birth-seal.json')
            need(json.loads(seal_raw)=={'birthPin':pin} and value=={'snapshot':snapshot,'sources':_sources(self.root)},'adapter_birth_changed');local['birthPin']=pin;local['birthSealPin']=seal_pin
        else:need(action in ('status','collect') and not os.path.lexists(job/'tmux-mcp-adapter-birth-seal.json'),'adapter_birth_missing')
        return action,snapshot,local

    def _query(self,program,payload,*,job=None,guard=None):
        phase,snapshot,local=self._phase(program,payload,job)
        need(phase=='availability' or callable(guard),'query_guard_missing')
        sources=_sources(self.root);config,transport=self._transport()
        connection=ssh_transport.connection_host(config,'archlinux');need(connection.password is None,'password_transport_not_supported')
        if phase=='stage':
            birth=job/'tmux-mcp-adapter-birth.json'
            birth_pin=_write_once(birth,session.canonical({'snapshot':snapshot,'sources':sources}))
            local['birthPin']=birth_pin
            local['birthSealPin']=_write_once(job/'tmux-mcp-adapter-birth-seal.json',session.canonical({'birthPin':birth_pin}))
        fixed=recovery.STAGE_V2 if program==old._STAGE else program
        argv=ssh_transport.build_ssh_argv(config,'archlinux',10,command=recovery.command(fixed))
        def exact_guard():
            need(_sources(self.root)==sources and self._transport()[1]==transport,'query_authority_changed')
            current_phase,current_snapshot,current_local=self._phase(program,payload,job)
            # Stage birth is written once before this guard and is bound separately.
            if phase=='stage':
                raw,pin=pipe._read(job/'tmux-mcp-adapter-birth.json');need(json.loads(raw)=={'snapshot':snapshot,'sources':sources} and pin==local['birthPin'],'adapter_birth_changed');current_local['birthPin']=pin
                seal_raw,seal_pin=pipe._read(job/'tmux-mcp-adapter-birth-seal.json');need(json.loads(seal_raw)=={'birthPin':pin} and seal_pin==local['birthSealPin'],'adapter_birth_changed');current_local['birthSealPin']=seal_pin
            need((current_phase,current_snapshot,current_local)==(phase,snapshot,local),'query_authority_changed')
            if guard:guard()
        authority={'phase':phase,'snapshot':snapshot,'sources':sources,'transport':transport,'local':local,'argvSha256':hashlib.sha256(session.canonical(argv)).hexdigest()}
        def launch():
            exact_guard();return subprocess.Popen(argv,cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
        outcome,capsule=_capture(self.root,authority=authority,launch=launch,payload=session.canonical(payload),guard=exact_guard)
        need(outcome['state']=='captured','transport_unknown')
        raw,pin=pipe._read(capsule/'receipt.json');need(pin==outcome['receiptPin'],'capture_receipt_changed');receipt=json.loads(raw)
        raw,pin=pipe._read(capsule/'stdout',MAX_STDOUT)
        need(pin==receipt['stdoutPin'] and pipe._read(capsule/'stderr',MAX_STDERR)[1]==receipt['stderrPin'],'capture_stream_changed')
        try:result=json.loads(raw,object_pairs_hook=ssh_transport._reject_duplicate_keys)
        except (ValueError,UnicodeError):raise AdapterError('transport_unknown') from None
        need(type(result)is dict,'invalid_remote_reply');exact_guard();return result


def operate(root,action,raw,*,source_root=None):
    """Only five fixed public actions; caller applies its finite public projection."""
    need(type(action)is str and action in ('availability','preflight','start','status','collect'),'unsupported_action')
    need(type(raw)is dict,'invalid_request')
    if action=='availability':need(not raw,'invalid_availability_request')
    elif action in ('preflight','start'):build._request(raw)
    else:need(set(raw)=={'correlationId'} and build._correlation(raw['correlationId']),'invalid_correlation_request')
    driver=McpTmuxDriver(root,source_root=source_root)
    if action=='availability':return driver.availability()
    if action=='preflight':return driver.preflight(raw)
    if action=='start':return build.start(root,raw,driver=driver,source_root=source_root,admission=lambda unused,request:driver.preflight(request))
    if action=='status':return build.status(root,raw,driver=driver)
    directory=build._directory(driver.root,False);need(directory is not None,'coordinator_journal_missing')
    record=build._read(directory/(raw['correlationId']+'.json'));need(record is not None,'coordinator_intent_missing')
    request=build._request(record);driver._saved(request)
    return driver.collect_existing(request)
