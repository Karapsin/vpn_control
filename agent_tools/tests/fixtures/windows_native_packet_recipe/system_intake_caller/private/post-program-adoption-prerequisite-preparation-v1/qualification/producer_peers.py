"""Inert boundary models copied from frozen qualifiers; no caller authority.
The old top-level qualifier suites are never imported or executed.
"""
import base64,builtins,hashlib,json,os,re,stat,sys,types
from pathlib import Path,PureWindowsPath
import _bf05_whole_protocol_boundary as peer

BOUNDARY_COPY_RECORDS=[{'path': '/Users/karapsin_de/projects/vpn_control/.runtime/windows-parity-20261019/windows-fixture/qualify-kernel-boot-probe.py', 'sha256': '8386ff5ddd1d83e8d8a16dedeb18bfa4c285fdf13de49504030c425fabcff3a8', 'copiedBoundaryPeerClass': 'KernelWorld', 'wholeSourceExecuted': False, 'callerAuthority': False}, {'path': '/Users/karapsin_de/projects/vpn_control/.runtime/windows-parity-20261019/windows-fixture/qualify-native-causal-packet.py', 'sha256': '37ca17ce4c8f002332785693ae34aaad0ed0c24d8d3d229119ab180b0366f597', 'copiedBoundaryPeerClass': 'NativeWorld', 'wholeSourceExecuted': False, 'callerAuthority': False}, {'path': '/Users/karapsin_de/projects/vpn_control/.runtime/windows-parity-20261019/windows-fixture/xml-policy-native-preparation-v1/qualify_packet.py', 'sha256': '7db236092ad24486813e2c0bcc1ae079e840a2efd0b4da3200c489df50afc8dd', 'copiedBoundaryPeerClass': 'PolicyWorld', 'wholeSourceExecuted': False, 'callerAuthority': False}]

def install_common_boundary(module):
 global peer
 peer=module

class KernelWorld(peer.ProtocolWorld):
    def __init__(self, declarations, destination, kernel_fault=None):
        self.kernel_fault = kernel_fault
        super().__init__(declarations, destination, fault="python-c", seed_endpoint_receipt=False)

    def rpc_reply(self, request):
        command = request["execute"]
        args = request.get("arguments", {})
        if command != "guest-exec":
            if command == "guest-exec-status" and self.kernel_fault == "status-missing-ack":
                self.defer_command = command
            return super().rpc_reply(request)
        self.record(command, args)
        assert "input-data" not in args
        script = base64.b64decode(args["arg"][-1], validate=True).decode("utf-16le")
        assert "NtQuerySystemInformation(90" in script
        assert "kernelGuidClosing=$admitted" in script
        assert "CreateDirectory" not in script and "CreateNew" not in script
        assert len(self.executions) == 0
        pid = 9000
        opening = {
            "InformationClass": 90, "NtStatus": 0, "NtStatusHex": "00000000",
            "ReturnLength": 32, "StructureSize": 32, "PointerSize": 8,
            "GuidOffset": 0, "FirmwareOffset": 16, "FlagsOffset": 24,
            "BootIdentifier": "10e1a582-3373-4c83-92d5-c78ef0967f77",
            "FirmwareType": 2, "BootFlags": "0",
        }
        closing = dict(opening)
        admitted = True
        if self.kernel_fault == "query-failure":
            opening.update(NtStatus=-1073741822, NtStatusHex="c0000002", ReturnLength=0,
                           BootIdentifier=None, FirmwareType=-1, BootFlags=None)
            closing = dict(opening)
            admitted = False
        elif self.kernel_fault == "wrong-return-length":
            opening["ReturnLength"] = closing["ReturnLength"] = 24
            admitted = False
        elif self.kernel_fault == "zero-guid":
            opening["BootIdentifier"] = closing["BootIdentifier"] = "00000000-0000-0000-0000-000000000000"
            admitted = False
        elif self.kernel_fault == "guid-changed":
            closing["BootIdentifier"] = "dbf7ee16-0b57-495d-a497-98d670c57b59"
            admitted = False
        result = dict(state="observed", query="kernel-boot-context", kernelOpening=opening,
                      kernelClosing=closing, kernelBootAdmitted=admitted, kernelGuidClosing=admitted,
                      readOnly=True, productOperation=False, taskOperation=False,
                      **self.actor_fields(pid))
        if self.kernel_fault == "actor-pid":
            result["bootstrapOpening"]["pid"] = result["bootstrapClosing"]["pid"] = pid + 1
        terminal = {"exited": True, "exitcode": 0,
                    "out-data": base64.b64encode(json.dumps(result).encode()).decode(), "err-data": ""}
        self.executions.append({"pid": pid, "arguments": args, "result": terminal})
        if self.kernel_fault == "exec-missing-ack":
            self.defer_command = command
        return {"pid": pid}

class NativeWorld(peer.ProtocolWorld):
    def __init__(self, declarations, destination, native_fault=None):
        self.native_fault = native_fault
        super().__init__(declarations, destination, fault="python-c", seed_endpoint_receipt=False)
        self.os.name = "posix"

    def import_peer(self, name, globals=None, locals=None, fromlist=(), level=0):
        if name == "agent_tools":
            self.imports.append(name)
            assert fromlist == ("windows_artifact_transfer",)
            return sys.modules[name]
        if name in {"ast", "copy", "unittest", "xml.etree.ElementTree"}:
            self.imports.append(name)
            return builtins.__import__(name, globals, locals, fromlist, level)
        return super().import_peer(name, globals, locals, fromlist, level)

    def rpc_reply(self, request):
        command = request["execute"]
        args = request.get("arguments", {})
        if command != "guest-exec":
            if command == "guest-exec-status" and self.native_fault == "status-missing-ack" and len(self.executions) == 1:
                self.defer_command = command
            return super().rpc_reply(request)
        self.record(command, args)
        launch = base64.b64decode(args["arg"][-1], validate=True).decode("utf-16le")
        saved = "input-data" in args
        if saved:
            payload = base64.b64decode(args["input-data"], validate=True)
            script = payload.decode("utf-8-sig")
            binding = re.search(r"\$path='([^']+)';\$parent='([^']+)';\$length=([0-9]+);\$expected='([0-9a-f]{64})';\$phase='([^']+)'", launch)
            assert binding
            saved_path, workspace, length, saved_digest, phase = binding.groups()
            assert workspace == self.declarations["GUEST_CONTEXT"]["sourceWorkspace"]
            assert saved_path == workspace + "\\infra-" + phase + ".ps1"
            assert int(length) == len(payload) and saved_digest == hashlib.sha256(payload).hexdigest()
            assert phase in self.declarations["NATIVE_PHASE_IDS"].values()
        else:
            script = launch
        match = re.search(r"state='regression-observed';case='([^']+)';scopeId='([^']+)'", script)
        assert match
        case, scope = match.groups()
        assert case == self.declarations["CASE_ORDER"][len(self.executions)]
        assert scope == self.declarations["SCOPE_IDS"][case]
        assert ("$ProgressPreference='SilentlyContinue'" not in script) if case == "progress-before" else ("$ProgressPreference='SilentlyContinue'" in script)
        pid = 9000 + len(self.executions)
        root = "C:\\ProgramData\\VpnControlInfrastructureRegression-" + scope
        identity = "11223344:0000000012345678"
        stderr = b""
        if case.startswith("progress"):
            value = {"state": "progress-check"}
            if case == "progress-before":
                stderr = b'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress"><PR><AV>VPN Control regression</AV></PR></Obj></Objs>'
                if self.native_fault == "mixed-progress-error":
                    stderr = stderr.replace(b"</Objs>", b'<S S="Error">unexpected</S></Objs>')
        elif case.startswith("atomic"):
            current = case.endswith("current")
            value = dict(state="atomic-check", created=current,
                         errorClass=None if current else "System.Management.Automation.MethodException",
                         errorId=None if current else "MethodCountCouldNotFindBest",
                         repeatedRefused183=current, rootPath=root,
                         rootIdentity=identity if current else None,
                         rootIdentityClosing=True, probeAssetsRetained=current)
            if current and self.native_fault == "atomic-missing-identity":
                value["rootIdentity"] = None
        else:
            current = case.endswith("current")
            value = dict(state="owner-check", originalOwnerSid="S-1-5-32-544",
                         ownerSid="S-1-5-18" if current else "S-1-5-32-544",
                         strictValidatorRejected=not current, reason=None if current else "TOKEN_SOURCE_ACL",
                         rootPath=root, rootIdentity=identity, filePath=root + "\\owned.bin",
                         fileIdentity="11223344:0000000012345679", rootIdentityClosing=True,
                         fileIdentityClosing=True, probeAssetsRetained=True)
            if self.native_fault == "owner-wrong-file-path":
                value["filePath"] = root + "\\unexpected.bin"
        proof = dict(state="regression-observed", case=case, scopeId=scope, caseResult=value,
                     **self.actor_fields(pid))
        if self.native_fault == "actor-pid":
            proof["bootstrapOpening"]["pid"] = proof["bootstrapClosing"]["pid"] = pid + 100
        if saved:
            outer = self.actor_fields(pid)
            held = {"phaseId": phase, "path": saved_path, "identity": "11223344:00000000abcdef01",
                    "bytes": len(payload), "sha256": saved_digest, "ownerSid": "S-1-5-18",
                    "sddl": peer.NATIVE_SOURCE_SDDL, "createNew": True, "heldReadOnly": True,
                    "writeOpenError": 32, "deleteOpenError": 32, "parserErrors": 0,
                    "bootstrapOpening": outer["bootstrapOpening"], "launch": "held-saved-file-scriptblock",
                    "originalOwnerSid": "S-1-5-32-544", "explicitOwnerGreen": True,
                    "productOperation": False, "sourceClosing": True, "finalSourceSha256": saved_digest}
            if self.native_fault == "saved-source-hash":
                held["finalSourceSha256"] = "0" * 64
            if self.native_fault == "saved-actor-split":
                proof["bootstrapOpening"]["birthFileTimeUtc"] = proof["bootstrapClosing"]["birthFileTimeUtc"] = "134368714165275650"
            proof = {"state": "protocol-completed", "protocolResult": proof, "heldSource": held,
                     "sourceClosing": True, "bootstrapOpening": outer["bootstrapOpening"],
                     "bootstrapClosing": outer["bootstrapClosing"]}
        terminal = {"exited": True, "exitcode": 0,
                    "out-data": base64.b64encode(json.dumps(proof).encode()).decode(),
                    "err-data": base64.b64encode(stderr).decode()}
        self.executions.append({"pid": pid, "arguments": args, "result": terminal})
        if self.native_fault == "exec-missing-ack" and len(self.executions) == 1:
            self.defer_command = command
        return {"pid": pid}

class PolicyWorld(peer.ProtocolWorld):
 def __init__(self,declarations,destination,policy_fault=None):
  self.policy_fault=policy_fault;self.transports=[];self.old_packages={name:sys.modules.get(name)for name in ('agent_tools','agent_tools.tests','agent_tools.windows_ordinary_task','agent_tools.tests.test_windows_ordinary_task')}
  assert all(m is None for m in self.old_packages.values()),'standalone qualifier requires fresh canonical package namespace'
  super().__init__(declarations,destination,fault='python-c',seed_endpoint_receipt=False)
  self.os.mkdir=self.mkdir
  world=self
  class VfsPath(type(Path())):
   def resolve(self,strict=False):
    assert self.is_absolute();return self
   def open(self,mode='r',*args,**kwargs):return world.builtin_open(self,mode,*args,**kwargs)
   def read_bytes(self):
    with self.open('rb')as f:return f.read()
   def read_text(self,encoding=None,errors=None):
    with self.open('r',encoding=encoding,errors=errors)as f:return f.read()
  self.pathlib=types.ModuleType('pathlib');self.pathlib.Path=VfsPath;self.pathlib.PureWindowsPath=PureWindowsPath
 def mkdir(self,path,mode=0o777,*,dir_fd=None):
  p=self.resolve(path,dir_fd);assert p.startswith(self.root+'/xml-policy-proof-')and mode==0o700
  assert p not in self.nodes;assert stat.S_ISDIR(self.info(str(Path(p).parent)).st_mode);self.node(p,mode=stat.S_IFDIR|mode);self.events.append(['mkdir',p])
 def import_peer(self,name,globals=None,locals=None,fromlist=(),level=0):
  if name=='pathlib':self.imports.append(name);return self.pathlib
  if name=='shutil':
   result=super().import_peer(name,globals,locals,fromlist,level);result.which=lambda executable:None;return result
  if name in {'copy','unittest','xml.etree.ElementTree','agent_tools'}:
   self.imports.append({'name':name,'fromlist':list(fromlist or()),'level':level});return __import__(name,globals,locals,fromlist,level)
  return super().import_peer(name,globals,locals,fromlist,level)
 def rpc_reply(self,request):
  command=request['execute'];args=request.get('arguments',{})
  if command!='guest-exec':
   if command=='guest-exec-status'and self.policy_fault=='status-missing-ack'and not getattr(self,'lost_status',False):self.defer_command=command;self.lost_status=True
   return super().rpc_reply(request)
  self.record(command,args);launch=base64.b64decode(args['arg'][-1],validate=True).decode('utf-16le');saved='input-data'in args
  if saved:
   payload=base64.b64decode(args['input-data'],validate=True);script=payload.decode('utf-8-sig')
   bound=re.search(r"\$path='([^']+)';\$parent='([^']+)';\$length=([0-9]+);\$expected='([0-9a-f]{64})';\$phase='([^']+)'",launch);assert bound;saved_path,workspace,length,digest,phase=bound.groups()
   assert workspace==self.declarations['GUEST_CONTEXT']['sourceWorkspace']and int(length)==len(payload)and digest==hashlib.sha256(payload).hexdigest()and phase==self.declarations['NATIVE_PHASE_IDS']['after']
  else:
   opening='$protocolResult= & {\n';closing='\n};[Console]::WriteLine(($protocolResult|ConvertTo-Json -Depth 12 -Compress))\n';assert launch.startswith(opening)and launch.endswith(closing);script=launch[len(opening):-len(closing)];payload=script.encode('utf-8-sig')
  mode='before'if len(self.executions)==0 else'after';assert mode==('after'if saved else'before')
  assert "[Console]::SetOut($captureOut)"in script and 'POLICY_FINAL_OUTPUT_BOUND'in script and 'POLICY_UNEXPECTED_PIPELINE'in script
  assert script.index('GUEST_BOOT_OR_ACTOR_MISMATCH')<script.index('VpnPolicyBoundedWriter')and script.index('BOOTSTRAP_ACTOR_OR_BOOT_CLOSING')<script.index('POLICY_FINAL_OUTPUT_BOUND')
  assert 'Register-ScheduledTask'not in script and 'Start-ScheduledTask'not in script and 'msiexec'not in script and 'CreateDirectory'not in script
  encoded=re.search(r"\$policyBytes=\[Convert\]::FromBase64String\('([^']+)'\)",script);original=base64.b64decode(encoded.group(1),validate=True);assert hashlib.sha256(original).hexdigest()==self.declarations['POLICY_PROGRAMS'][mode]['sha256']
  pid=9000+len(self.executions);self.transports.append({'mode':mode,'transport':'saved-source'if saved else'inline','payloadSha256':hashlib.sha256(payload).hexdigest(),'payloadBytes':len(payload),'originalSourceSha256':hashlib.sha256(original).hexdigest()})
  thrown=None;stdout=b''
  if mode=='before':
   thrown={key:'inert genuine ErrorRecord field'for key in ['message','fullyQualifiedErrorId','category','scriptStackTrace','positionMessage','exceptionType','errorRecordText']};thrown.update(message='TOKEN_TASK_XML',fullyQualifiedErrorId='TOKEN_TASK_XML',errorRecordText='TOKEN_TASK_XML')
   if self.policy_fault=='wrong-before-throw':thrown['message']='UNEXPECTED_OLD_ACCEPTANCE'
   if self.policy_fault=='before-stdout':stdout=b'unexpected'
  else:
   controls=[{'name':name,'expected':accept,'accepted':accept,'reason':None if accept else'TOKEN_XML_AMBIGUOUS'}for name,accept in self.declarations['POLICY_EXPECTED_CONTROLS']]
   if self.policy_fault=='missing-control':controls.pop()
   if self.policy_fault=='extra-action-accepted':next(x for x in controls if x['name']=='xml-extra-action')['accepted']=True
   if self.policy_fault=='duplicate-control':controls[-1]['name']=controls[0]['name']
   stdout=json.dumps({'schemaVersion':1,'phase':'ordinary-task-policy-causal','fixedValidator':'GREEN','controls':controls,'productOperation':False,'nativeActionAllowed':False}).encode()
  result=dict(state='observed',query='ordinary-task-policy-causal',probeId=self.declarations['PROBE_ID'],mode=mode,originalSourceSha256=hashlib.sha256(original).hexdigest(),originalSourceBytes=len(original),stdoutBase64=base64.b64encode(stdout).decode(),stderrBase64='',thrown=thrown,pipelineCount=0,captureWithinBound=True,readOnly=True,taskOperation=False,productOperation=False,nativeActionAllowed=False,**self.actor_fields(pid))
  if self.policy_fault=='actor-pid':result['bootstrapOpening']['pid']=result['bootstrapClosing']['pid']=pid+1
  if self.policy_fault=='wrong-boot':result['bootstrapOpening']['boot']['lastBootUpTimeFileTimeUtc']=result['bootstrapClosing']['boot']['lastBootUpTimeFileTimeUtc']='134368653075000000'
  if self.policy_fault=='pipeline-output':result['pipelineCount']=1
  if self.policy_fault=='capture-overflow':result={'exited':True,'exitcode':1,'out-data':'','err-data':base64.b64encode(b'POLICY_CAPTURE_BOUND').decode()}
  if saved:
   outer=self.actor_fields(pid);held={'phaseId':phase,'path':saved_path,'identity':'11223344:00000000abcdef01','bytes':len(payload),'sha256':digest,'ownerSid':'S-1-5-18','sddl':peer.NATIVE_SOURCE_SDDL,'createNew':True,'heldReadOnly':True,'writeOpenError':32,'deleteOpenError':32,'parserErrors':0,'bootstrapOpening':outer['bootstrapOpening'],'launch':'held-saved-file-scriptblock','originalOwnerSid':'S-1-5-32-544','explicitOwnerGreen':True,'productOperation':False,'sourceClosing':True,'finalSourceSha256':digest}
   if self.policy_fault=='saved-inner-outer-split':result['bootstrapOpening']['birthFileTimeUtc']=result['bootstrapClosing']['birthFileTimeUtc']=str(int(result['bootstrapOpening']['birthFileTimeUtc'])+1)
   if self.policy_fault=='saved-source-hash':held['finalSourceSha256']='0'*64
   result={'state':'protocol-completed','protocolResult':result,'heldSource':held,'sourceClosing':True,'bootstrapOpening':outer['bootstrapOpening'],'bootstrapClosing':outer['bootstrapClosing']}
  self.executions.append({'pid':pid,'arguments':args,'result':result})
  if self.policy_fault=='exec-missing-ack'and mode=='before':self.defer_command=command
  return {'pid':pid}
 def harness_cleanup(self):
  super().harness_cleanup()
  for name,old in self.old_packages.items():
   if old is None:sys.modules.pop(name,None)
   else:sys.modules[name]=old
