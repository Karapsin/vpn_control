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
import sys
import time
import uuid
import weakref
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
PIPE_SHA='9e5d5e629c03c7cdefb42882f2d4459c7bcbafcb27455a407340e64b9d1d27f8'
BaseDriver=recovery.CurrentExactFetchDriver if recovery is not None else object
_EXECUTING_CODE=sys._getframe().f_code
_TRANSPORT_PURPOSE='mcp-tmux-private-transport-v2'

def _guard_self():
    need(_EXECUTING_CODE==compile(Path(__file__).read_bytes(),__file__,'exec',dont_inherit=True),'adapter_executing_source_changed')

def _private_metadata(path):
    value=Path(path).stat(follow_symlinks=False)
    return [value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,
            value.st_nlink,value.st_mtime_ns,value.st_ctime_ns]

def _valid_transport(value):
    return (type(value)is dict and set(value)=={'version','purpose','host','publicRouteSha256','privateFiles','publicFiles','privateCustodySourceSha256'}
            and type(value['version'])is int and value['version']==2
            and value['purpose']==_TRANSPORT_PURPOSE and value['host']=='archlinux'
            and type(value['publicRouteSha256'])is str and len(value['publicRouteSha256'])==64
            and all(c in '0123456789abcdef' for c in value['publicRouteSha256'])
            and type(value['privateCustodySourceSha256'])is str and len(value['privateCustodySourceSha256'])==64
            and all(c in '0123456789abcdef' for c in value['privateCustodySourceSha256'])
            and type(value['privateFiles'])is dict and 1<=len(value['privateFiles'])<=2
            and all(type(k)is str and k.startswith('/') and type(v)is list and len(v)==8
                    and all(type(n)is int for n in v) for k,v in value['privateFiles'].items())
            and type(value['publicFiles'])is dict and len(value['publicFiles'])==1
            and all(type(k)is str and k.startswith('/') and session._valid_pin(v)
                    for k,v in value['publicFiles'].items()))

def _close_private(owners):
    for owner in owners.values():owner.close()
    owners.clear()

def _capsule(root):return pipe._capsule(root)
def _write_once(path,data):return pipe._write_once(path,data)

def _sources(root):
    _guard_self()
    need(pipe is not None,'unsupported_coordinator_platform')
    values=pipe._current_sources(root)
    need(values[str(Path(pipe.__file__).absolute())]['sha256']==PIPE_SHA,'pipe_source_changed')
    path=Path(__file__).absolute();values[str(path)]=pipe._read(path,262144,False)[1]
    return values

def _capture(root,*,authority,launch,payload,guard,timeout_seconds=95,private_payload=False,public_reply=None):
    """One nonblocking duplex query; durable finite outcome even on response loss."""
    need(type(authority)is dict and set(authority)=={'phase','snapshot','sources','transport','local','argvSha256'} and authority['phase'] in ('availability','stage','prepare','release','status','collect'),'capture_authority_invalid')
    need(type(payload)is bytes and len(payload)<=131072 and type(timeout_seconds)in (int,float) and 0<timeout_seconds<=95,'capture_payload_invalid')
    try:guard()
    except Exception:raise CollectionError('authority_changed') from None
    need(type(private_payload)is bool,'capture_private_payload_invalid')
    need(not private_payload or callable(public_reply),'capture_private_reply_validator_required')
    input_binding=({'privatePayload':True,'inputNonce':str(uuid.uuid4())}
                   if private_payload else {'payloadSha256':hashlib.sha256(payload).hexdigest()})
    capsule=_capsule(root);intent=_write_once(capsule/'intent.json',session.canonical({'authority':authority,**input_binding,'replayAllowed':False}))
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
        if private_payload:
            # Private input may be echoed by failed authentication or an
            # unexpected child. Never retain/hash that echo or an incomplete
            # private-input capture (which could end midway through a secret).
            private_line=payload.partition(b'\n')[0]
            if private_line and (private_line in stdout or private_line in stderr):
                failure='private_input_echo'
            if failure is None:
                # Both finite private-input callers require a JSON object and
                # empty stderr. Reject malformed/partial replies before stream
                # hashes rather than retaining a partial credential fragment.
                try:
                    value=json.loads(bytes(stdout),object_pairs_hook=ssh_transport._reject_duplicate_keys)
                    if type(value) is not dict:
                        raise ValueError('private_reply_shape')
                except (ValueError,UnicodeError):failure='private_reply_malformed'
                if stderr:failure='private_reply_stderr'
                if failure is None:
                    # Only the fixed caller's closed public schema can cross
                    # the private pipe boundary. Raw JSON may contain an echo
                    # even when it parses successfully.
                    try:
                        value=public_reply(value)
                        need(type(value)is dict,'private_reply_shape')
                        stdout[:]=session.canonical(value)
                    except Exception:failure='private_reply_unrecognized'
            if failure is not None:
                stdout.clear();stderr.clear()
        out_pin=_write_once(capsule/'stdout',bytes(stdout));err_pin=_write_once(capsule/'stderr',bytes(stderr))
        input_receipt=({'privateInputComplete':written==len(payload)} if private_payload else {'stdinBytesWritten':written})
        receipt={'schemaVersion':1,'intentPin':intent,'stdoutPin':out_pin,'stderrPin':err_pin,'exitCode':code,'capped':capped,'timedOut':timed_out,**input_receipt,'failure':failure,'replayAllowed':False}
        receipt_pin=_write_once(capsule/'receipt.json',session.canonical(receipt))
        ssh_transport.finish_ssh(process,failed=failure is not None)
    return {'state':'captured' if code==0 and failure is None and written==len(payload) else 'unknown','receiptPin':receipt_pin,'replayAllowed':False,'nativeActionAllowed':False},capsule


class McpTmuxDriver(BaseDriver):
    def __init__(self,root,*,source_root=None,engineering_context=None):
        need(os.name=='posix' and recovery is not None,'unsupported_coordinator_platform')
        super().__init__(root,source_root=source_root,engineering_context=engineering_context)
        self._private_owners={};self._private_closed=False
        self._private_finalizer=weakref.finalize(self,_close_private,self._private_owners)

    def close(self):
        self._private_closed=True
        self._private_finalizer()

    def _private_owner(self,path):
        need(not self._private_closed,'transport_custody_closed')
        path=str(Path(path).absolute())
        owner=self._private_owners.get(path)
        if owner is None:
            owner=ssh_transport._automatic_module()._private_config().PrivateConfigCustody(path)
            self._private_owners[path]=owner
        owner.check()
        return owner

    def _transport(self):
        # Private inventory and keys are compared through retained descriptors,
        # never through a content digest or a serializable private snapshot.
        _guard_self()
        automatic=ssh_transport._automatic_module()
        automatic._private_config() # Revalidate the held-byte helper source on every boundary.
        config_path=self.root/'.vm-hosts.local.json'
        owner=self._private_owner(config_path)
        config=ssh_transport.load_config(self.root)
        need(owner.matches_text(ssh_transport._read_private_config(config_path)),'transport_changed')
        connection=ssh_transport.connection_host(config,'archlinux')
        need(isinstance(connection.identity_file,Path) and isinstance(connection.known_hosts_file,Path),'outer_file_not_local')
        paths=(config_path,connection.identity_file)
        for path in paths:self._private_owner(path).check()
        private={str(Path(path).absolute()):_private_metadata(path) for path in paths}
        public={str(connection.known_hosts_file):old.blob(connection.known_hosts_file)[1]}
        route=automatic._config_sha(config)
        for path in paths:self._private_owner(path).check()
        value={'version':2,'purpose':_TRANSPORT_PURPOSE,'host':'archlinux','publicRouteSha256':route,'privateFiles':private,'publicFiles':public,'privateCustodySourceSha256':automatic._PRIVATE_CONFIG_SHA}
        need(_valid_transport(value),'transport_identity_invalid')
        return config,value

    def _public_intent_data(self,request,*,admission=False):
        _guard_self()
        path=self._job(request)/'tmux-adapter-intent.json'
        # Do this before inherited readers hash the complete intent. Legacy
        # private-derived receipts retain their original helper and authority.
        owner=self._private_owner(path)
        raw=ssh_transport._read_private_config(path)
        need(owner.matches_text(raw),'adapter_intent_changed')
        try:value=json.loads(raw,object_pairs_hook=ssh_transport._reject_duplicate_keys)
        except (ValueError,UnicodeError):raise AdapterError('legacy_transport_snapshot_blocker') from None
        need(type(value)is dict and _valid_transport(value.get('transport')),'legacy_transport_snapshot_blocker')
        need(value.get('request')==request,'adapter_intent_changed')
        # A v2 marker alone is not authority to hash arbitrary old contents.
        # Every byte must be the current source-owned public snapshot first.
        expected=self._snapshot(request,admission=admission)
        need(value==expected,'adapter_intent_changed')
        owner.check()
        # Hash only these already validated in-memory public bytes. Never
        # reopen the pathname in an inherited hashing reader after this gate.
        generation=session.generation(os.fstat(owner._file))
        public_raw=raw.encode('utf-8')
        pin={'generation':generation,'sha256':hashlib.sha256(public_raw).hexdigest()}
        owner.check()
        return public_raw,pin,value

    def _public_intent(self,request,*,admission=False):
        return self._public_intent_data(request,admission=admission)[2]

    def _public_intent_pin(self,request):
        pin=self._public_intent_data(request)[1]
        self._private_owner(self._job(request)/'tmux-adapter-intent.json').check()
        return pin

    def _publish_public_intent(self,request,value):
        path=self._job(request)/'tmux-adapter-intent.json';raw=session.canonical(value)
        # Original create-only admission, with held lexical directory custody.
        # A consumed/partial intent is never reopened for a replacement write.
        with pipe.Directory(path.parent)as directory:
            directory.guard()
            fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory.fd)
            try:
                view=memoryview(raw)
                while view:
                    count=os.write(fd,view);need(count>0,'record_write_failed');view=view[count:]
                os.fsync(fd);generation=session.generation(os.fstat(fd))
                directory.guard()
                need(generation==session.generation(os.stat(path.name,dir_fd=directory.fd,follow_symlinks=False)),'local_authority_changed')
                os.fsync(directory.fd)
                pin=self._public_intent_data(request,admission=self.engineering_context is not None)[1]
                need(pin['generation']==generation,'local_authority_changed')
                directory.guard()
                self._private_owner(path).check()
                need(session.generation(os.fstat(fd))==generation,'local_authority_changed')
                return pin
            finally:os.close(fd)

    def _saved(self,request,*,admission=False):
        value=self._public_intent_data(request,admission=admission)[2]
        job=self._job(request);self._private_owner(job/'tmux-adapter-intent.json').check()
        return job,value

    # Exact original submit/action control flow; only the four intent
    # publication/read boundaries use the validated public v2 owner below.
    def submit(self, raw):
        request = build._request(raw)
        # Reuse mandatory clean exact origin/dev version admission, including the
        # existing same-Git managed worktree constraint; no dirty-source bypass.
        if self.engineering_context is None:
            build._source_preflight(self.source_root, request)
        else:
            build._source_preflight(self.source_root, request, engineering_context=self.engineering_context)
            need(self.root == self.engineering_context.coordinator_root, "engineering_storage_root_changed")
            self.engineering_context.require_native_consumers((Path(old.__file__), Path(build.__file__),
                Path(session.__file__), Path(ssh_transport.__file__)))
        original = (self._snapshot(request) if self.engineering_context is None else
                    self._snapshot(request, admission=True))
        job = self._job(request)
        job.mkdir(mode=0o700)  # Any existing/partial attempt is consumed.
        intent_pin = self._publish_public_intent(request, original)
        job_pin = session.private_dir(job)
        tools = self._tools()
        payload = {"request": old.purpose(request), "build": base64.b64encode(tools["linux_package_fixture_build.py"]["raw"]).decode(),
                   "tool": base64.b64encode(tools["ssh_tmux_session.py"]["raw"]).decode()}
        def guard():
            if self.engineering_context is None:
                self._guard(request, original)
            else:
                self._guard(request, original, admission=True)
            need(session.private_dir(job) == job_pin and
                 self._public_intent_pin(request) == intent_pin, "local_authority_changed")
        stage = self._query(old._STAGE, payload, job=job, guard=guard)
        need(set(stage) == {"state", "correlationId", "stagePin"} and stage["state"] == "staged" and
             stage["correlationId"] == request["correlationId"] and session._valid_pin(stage["stagePin"]), "invalid_stage_reply")
        session.write_once(job / "tmux-stage.json", session.canonical(stage))
        value = self._action(request, "prepare")
        need(set(value) == {"state", "correlationId", "anchorPin", "replayAllowed", "artifactVerification"} and
             value["state"] == "prepared" and value["correlationId"] == request["correlationId"] and
             session._valid_pin(value["anchorPin"]) and value["replayAllowed"] is False and
             value["artifactVerification"] == "required", "invalid_prepare_reply")
        # Original authority is retained locally BEFORE release can start a build.
        session.write_once(job / "tmux-anchor.json", session.canonical(value))
        self.release(request)
        return {"state": "submitted", "correlationId": request["correlationId"]}

    def _action(self, request, action, **fields):
        mutation = action in {"prepare", "release"}
        job, original = (self._saved(request) if self.engineering_context is None else
                         self._saved(request, admission=mutation))
        job_pin = session.private_dir(job)
        intent_pin = self._public_intent_pin(request)
        stage_raw, stage_pin = session.read(job / "tmux-stage.json")
        stage = json.loads(stage_raw)
        payload = {"action": action, "request": old.purpose(request), "stagePin": stage["stagePin"]}
        pins = {"stage": stage_pin}
        if action != "prepare":
            anchor_raw, anchor_pin = session.read(job / "tmux-anchor.json")
            payload["anchorPin"] = json.loads(anchor_raw)["anchorPin"]; pins["anchor"] = anchor_pin
        payload.update(fields)
        def guard():
            if self.engineering_context is None:
                self._guard(request, original)
            else:
                self._guard(request, original, admission=mutation)
            need(session.private_dir(job) == job_pin and
                 self._public_intent_pin(request) == intent_pin, "local_authority_changed")
            need(session.read(job / "tmux-stage.json")[1] == pins["stage"] and
                 ("anchor" not in pins or session.read(job / "tmux-anchor.json")[1] == pins["anchor"]), "external_authority_changed")
        return self._query(old._ACTION, payload, job=job, guard=guard)


    def _code_root(self):
        return self.source_root if self.engineering_context is not None else self.root

    def _phase(self,program,payload,job):
        need(type(payload)is dict,'invalid_query_payload')
        if program==old._AVAILABILITY:
            need(not payload and job is None,'invalid_availability_request')
            return 'availability',None,{}
        need(program in (old._STAGE,old._ACTION),'unsupported_program')
        value=payload.get('request');need(type(value)is dict,'invalid_purpose')
        request=build._request({key:value.get(key) for key in ('sourceSha','baseVersion','targetVersion','correlationId')})
        need(value==old.purpose(request) and job==self._job(request),'invalid_purpose')
        raw,intent,original=self._public_intent_data(request)
        snapshot=self._snapshot(request)
        need(original==snapshot,'adapter_intent_changed')
        self._private_owner(job/'tmux-adapter-intent.json').check()
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
            need(json.loads(seal_raw)=={'birthPin':pin} and value=={'snapshot':snapshot,'sources':_sources(self._code_root())},'adapter_birth_changed');local['birthPin']=pin;local['birthSealPin']=seal_pin
        else:need(action in ('status','collect') and not os.path.lexists(job/'tmux-mcp-adapter-birth-seal.json'),'adapter_birth_missing')
        return action,snapshot,local

    def _query(self,program,payload,*,job=None,guard=None):
        phase,snapshot,local=self._phase(program,payload,job)
        need(phase=='availability' or callable(guard),'query_guard_missing')
        sources=_sources(self._code_root());config,transport=self._transport()
        connection=ssh_transport.connection_host(config,'archlinux');need(connection.password is None,'password_transport_not_supported')
        if phase=='stage':
            birth=job/'tmux-mcp-adapter-birth.json'
            birth_pin=_write_once(birth,session.canonical({'snapshot':snapshot,'sources':sources}))
            local['birthPin']=birth_pin
            local['birthSealPin']=_write_once(job/'tmux-mcp-adapter-birth-seal.json',session.canonical({'birthPin':birth_pin}))
        fixed=recovery.STAGE_V2 if program==old._STAGE else program
        argv=ssh_transport.build_ssh_argv(config,'archlinux',10,command=recovery.command(fixed))
        def exact_guard():
            need(_sources(self._code_root())==sources and self._transport()[1]==transport,'query_authority_changed')
            current_phase,current_snapshot,current_local=self._phase(program,payload,job)
            # Stage birth is written once before this guard and is bound separately.
            if phase=='stage':
                raw,pin=pipe._read(job/'tmux-mcp-adapter-birth.json');need(json.loads(raw)=={'snapshot':snapshot,'sources':sources} and pin==local['birthPin'],'adapter_birth_changed');current_local['birthPin']=pin
                seal_raw,seal_pin=pipe._read(job/'tmux-mcp-adapter-birth-seal.json');need(json.loads(seal_raw)=={'birthPin':pin} and seal_pin==local['birthSealPin'],'adapter_birth_changed');current_local['birthSealPin']=seal_pin
            need((current_phase,current_snapshot,current_local)==(phase,snapshot,local),'query_authority_changed')
            if guard:guard()
        authority={'phase':phase,'snapshot':snapshot,'sources':sources,'transport':transport,'local':local,'argvSha256':ssh_transport.argv_sha256(argv)}
        def launch():
            exact_guard();return ssh_transport.popen_ssh(argv,cwd=self.root,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
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
    try:
        if action=='availability':return driver.availability()
        if action=='preflight':return driver.preflight(raw)
        if action=='start':return build.start(root,raw,driver=driver,source_root=source_root,admission=lambda unused,request:driver.preflight(request))
        if action=='status':return build.status(root,raw,driver=driver)
        directory=build._directory(driver.root,False);need(directory is not None,'coordinator_journal_missing')
        record=build._read(directory/(raw['correlationId']+'.json'));need(record is not None,'coordinator_intent_missing')
        request=build._request(record);driver._saved(request)
        return driver.collect_existing(request)
    finally:
        driver.close()
