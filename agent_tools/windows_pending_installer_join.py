"""PRIVATE existing public operation -> pre-UAC install correlation join.

Only the existing authenticated read-only operations list is executed. It cannot
start a controller, submit installation, approve a prompt or replay a mutation.
The ordinary task retains both inspection children and its original install CLI.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import PureWindowsPath
import uuid
import ctypes
import re


def need(value, code):
    if not value:
        raise ValueError(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "public-list-duplicate-key")
        result[key] = value
    return result


def uid(value):
    need(type(value) is str and str(uuid.UUID(value)) == value, "pending-actual-uuid")
    return value


def parse_list(stdout, controller):
    need(type(stdout) is str and 0 < len(stdout.encode()) <= 65536, "public-list-bound")
    envelope = json.loads(stdout, object_pairs_hook=unique)
    keys = {"schemaVersion", "controllerId", "requestId", "ok", "code", "message", "messageKey",
            "messageArgs", "final", "operationId", "configurationRevision", "restartRequired", "data", "warnings"}
    need(type(envelope) is dict and set(envelope) == keys and type(envelope["schemaVersion"]) is int and envelope["schemaVersion"] == 1 and envelope["controllerId"] == uid(controller)
         and envelope["ok"] is True and envelope["code"] == "OK" and envelope["final"] is True
         and envelope["operationId"] is None and type(envelope["data"]) is dict
         and set(envelope["data"]) == {"operations"}, "authenticated-public-list-envelope")
    uid(envelope["requestId"])  # Inspection request ID; NEVER install origin.
    rows = envelope["data"]["operations"]
    need(type(rows) is list and len(rows) <= 256, "public-list-row-bound")
    seen = set()
    for row in rows:
        need(type(row) is dict and row.get("controllerId") == controller, "public-list-owner")
        uid(row.get("id"));uid(row.get("requestId"))
        need(row["id"] not in seen, "public-list-duplicate-operation")
        seen.add(row["id"])
    return envelope, rows


@dataclass
class PublicSnapshot:
    owner: object
    child: object
    controller: str
    workspace: str
    envelope: dict
    rows: list
    stdout_sha256: str


def observe_list(owner, workspace, controller):
    """Run one finite read-only command against the already running controller."""
    uid(controller)
    owner.guard()
    child = owner.child("read-only-pre-uac-operations-list", [owner.request["cliPath"], "--state-dir", str(workspace),
        "--json", "--controller-id", controller, "operations", "list"])
    result = child.completed()
    owner.guard()
    need(child in owner.children and child.owner is owner and result.returncode == 0
         and child.terminal is not None and child.terminal["exitCode"] == 0
         and child.eof == {"stdout": True, "stderr": True} and not child.errors
         and result.stderr == "", "retained-public-list-terminal-eof")
    envelope, rows = parse_list(result.stdout, controller)
    return PublicSnapshot(owner, child, controller, str(workspace), envelope, rows,
                          hashlib.sha256(result.stdout.encode()).hexdigest())


def select_original_pending(owner, before, current, original_install_cli):
    """Join the sole new RUNNING install while retaining the original CLI.

    The owned isolated workspace and coordinator's one-mutator scope remain
    native admission prerequisites. A list row alone exposes no submitting PID.
    """
    need(type(before) is PublicSnapshot and type(current) is PublicSnapshot
         and before.owner is owner and current.owner is owner
         and before.controller == current.controller and before.workspace == current.workspace
         and before.child is not current.child and before.child in owner.children and current.child in owner.children,
         "actual-before-and-current-original-inspections")
    need(original_install_cli in owner.children and original_install_cli.owner is owner
         and type(original_install_cli.pid) is int and original_install_cli.pid > 0
         and str(owner.native.birth(int(original_install_cli.process._handle))) == str(original_install_cli.birth),
         "exact-original-install-cli-handle")
    argv = original_install_cli.argv
    need(argv[0].casefold() == owner.request["cliPath"].casefold()
         and argv[1:3] == ("--state-dir", before.workspace)
         and any(argv[i:i+2] == ("updates", "install") for i in range(len(argv)-1))
         and any(argv[i:i+2] == ("--controller-id", before.controller) for i in range(len(argv)-1)),
         "original-install-cli-workspace-owner-arguments")
    owner.guard()
    old = {row["id"] for row in before.rows}
    candidates = [row for row in current.rows if row["id"] not in old
                  and row.get("operation") == "updates.install"]
    need(len(candidates) == 1, "sole-fresh-public-install-candidate")
    row = candidates[0]
    need(row.get("phase") == "running" and row.get("final") is False
         and row.get("code") == "ACCEPTED" and row.get("handoffReady") is False
         and row.get("jobId") is None, "actual-pre-grant-install-state")
    # If the async original is already terminal, terminal+EOF remain mandatory.
    # A synchronous original may still be waiting at the same pending prompt.
    if original_install_cli.process.poll() is not None:
        need(original_install_cli.observe() is not None and all(original_install_cli.eof.values()),
             "original-async-cli-terminal-eof")
    return {"ordinaryTaskOperationId": uid(owner.request["operationId"]),
            "productOperationId": row["id"], "originRequestId": row["requestId"],
            "controllerId": before.controller,
            "originalCli": {"pid": original_install_cli.pid, "creationFileTime": str(original_install_cli.birth)},
            "inspections": {"beforeRequestId": before.envelope["requestId"],
                "currentRequestId": current.envelope["requestId"],
                "beforeStdoutSha256": before.stdout_sha256, "currentStdoutSha256": current.stdout_sha256}}


def correlation_path_and_record(actual_resolved_workspace, task_binding, actual_job_id):
    """Use the actual JVM-resolved path string; do not normalize or guess case."""
    path = PureWindowsPath(actual_resolved_workspace)
    need(type(actual_resolved_workspace) is str and path.is_absolute() and not path.drive.startswith("\\\\")
         and ".." not in path.parts, "actual-resolved-workspace-required")
    for key in ("ordinaryTaskOperationId", "productOperationId", "originRequestId", "controllerId"):
        uid(task_binding[key])
    uid(actual_job_id)
    filename_bytes = json.dumps({"controllerId": task_binding["controllerId"],
        "operationId": task_binding["productOperationId"]}, separators=(",", ":"), ensure_ascii=False).encode()
    leaf = ".install-correlation-"+hashlib.sha256(filename_bytes).hexdigest()+".json"
    record = dict(version=1, controllerId=task_binding["controllerId"], requestId=task_binding["originRequestId"],
        operationId=task_binding["productOperationId"], jobId=actual_job_id,
        workspaceKey=hashlib.sha256(actual_resolved_workspace.encode()).hexdigest())
    return str(path/leaf), record


def observe_installer_files(owner, task_binding, workspace, serve_child, target):
    """Actual ordinary-token native reads; no worker/credential/input launch.

    Retain each object before opening; use no-delete parent handles and read-only
    leaf handles, observe exact identity/security/hash, and check every close.
    Package hashing is streamed. Records contain no control token or password.
    """
    need(serve_child in owner.children and serve_child.owner is owner
         and str(owner.native.birth(int(serve_child.process._handle))) == str(serve_child.birth)
         and serve_child.process.poll() is None, "current-persistent-serve-handle")
    need(type(target) is dict and set(target) == {"sha256", "sizeBytes", "launcher", "frontendPid", "frontendStartedAtEpochMillis"}
         and type(target["sizeBytes"]) is int and target["sizeBytes"] > 0, "source-bound-actual-target")
    owner.guard()
    if not hasattr(owner, "pending_installer_read_leases"):
        owner.pending_installer_read_leases = []
    lease = {"taskBinding": task_binding, "handles": [], "records": [], "closed": False}
    owner.pending_installer_read_leases.append(lease)
    invalid = ctypes.c_void_p(-1).value
    native = owner.native
    def open_native(path, directory):
        handle = native.k.CreateFileW(str(path), 0x20080 if directory else 0x80020000,
            3 if directory else 1, None, 3, 0x02200000, None)
        need(handle != invalid, "current-pending-file-open")
        lease["handles"].append(handle)
        return handle
    def native_id(info):
        return format(info["volumeSerial"],"08x")+":"+format(info["fileIndex"],"016x")
    def read_exact(path, maximum, *, private=False, body=False):
        need(type(maximum) is int and maximum > 0, "finite-native-file-bound")
        parents = list(PureWindowsPath(path).parents)
        need(len(parents) <= 20, "pending-parent-depth")
        for parent in reversed(parents):
            h=open_native(parent,True)
            identity=native.identity(h,True);security=native.security(h)
            lease["records"].append((h,str(parent),True,identity,security))
        h=open_native(path,False);identity=native.identity(h);security=native.security(h)
        need(0 < identity["sizeBytes"] <= maximum and security["ownerSid"] == owner.request["context"]["ordinarySid"],
             "pending-native-private-owner-size")
        if private:
            sid=owner.request["context"]["ordinarySid"]
            need(re.fullmatch(re.escape("O:"+sid)+r"D:P(?:AI)?"+re.escape("(A;;FA;;;"+sid+")"),security["sddl"]) is not None, "actual-owner-only-correlation-acl")
        lease["records"].append((h,str(path),False,identity,security))
        digest=hashlib.sha256();chunks=[];count=0
        for block in native.read_blocks(h):
            count+=len(block);need(count<=maximum,"pending-file-read-bound");digest.update(block)
            if body:chunks.append(block)
        need(count==identity["sizeBytes"] and native.identity(h)==identity and native.security(h)==security,
             "pending-held-full-read-closing")
        return dict(path=str(path),sha256=digest.hexdigest(),sizeBytes=count,nativeIdentity=native_id(identity),security=security),b"".join(chunks)
    try:
        workspace_handle=open_native(workspace,True)
        lease["records"].append((workspace_handle,str(workspace),True,native.identity(workspace_handle,True),native.security(workspace_handle)))
        # Actual kernel normalized DOS path, then validate it against the actual
        # product journal workspaceKey. Never guess drive-letter or path case.
        final=native.k.GetFinalPathNameByHandleW
        from ctypes import wintypes as W
        final.argtypes=(W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD);final.restype=W.DWORD
        name=ctypes.create_unicode_buffer(32768);size=final(workspace_handle,name,len(name),0)
        need(0<size<len(name) and name.value.startswith("\\\\?\\") and not name.value.startswith("\\\\?\\UNC\\"),
             "actual-native-resolved-workspace")
        resolved=name.value[4:]
        identity_bytes=json.dumps({"controllerId":task_binding["controllerId"],"operationId":task_binding["productOperationId"]},
                                  separators=(",",":")).encode()
        correlation_path=str(PureWindowsPath(resolved)/(".install-correlation-"+hashlib.sha256(identity_bytes).hexdigest()+".json"))
        correlation,raw=read_exact(correlation_path,4096,private=True,body=True)
        record=json.loads(raw,object_pairs_hook=unique)
        need(type(record) is dict and set(record)=={"version","controllerId","requestId","operationId","jobId","workspaceKey"},
             "native-correlation-closed-schema")
        wanted_path,wanted_record=correlation_path_and_record(resolved,task_binding,record["jobId"])
        need(record==wanted_record and wanted_path==correlation_path,"public-operation-native-correlation")
        correlation.update(record=record,resolvedWorkspace=resolved)
        job=record["jobId"]
        root=PureWindowsPath(owner.request["context"]["localAppData"])/"vpn-control-install-inputs"/job
        pending,raw=read_exact(str(root/"request.json"),65536,body=True)
        request=json.loads(raw,object_pairs_hook=unique)
        keys={"version","jobId","principalSid","ownerPid","ownerStartedAtEpochMillis","launcher","packageFile","packageSha256","packageSize","stateDirectory"}
        if target["frontendPid"] is not None:keys|={"frontendPid","frontendStartedAtEpochMillis"}
        need(type(request) is dict and set(request)==keys and request["version"]==1 and request["jobId"]==job
             and request["principalSid"]==owner.request["context"]["ordinarySid"] and request["ownerPid"]==serve_child.pid
             and request["ownerStartedAtEpochMillis"]==int(serve_child.birth)//10000-11644473600000
             and request["launcher"].casefold()==target["launcher"].casefold()
             and request["packageFile"]==str(root/"package.msi") and request["packageSha256"]==target["sha256"]
             and request["packageSize"]==target["sizeBytes"] and request["stateDirectory"]==resolved,
             "actual-native-pending-request-source-target-serve-join")
        if target["frontendPid"] is not None:
            need(all(request[k]==target[k] for k in ("frontendPid","frontendStartedAtEpochMillis")),"native-request-gui-origin")
        pending.update({key:request[key] for key in ("jobId","ownerPid","ownerStartedAtEpochMillis","principalSid","launcher")})
        package,_=read_exact(str(root/"package.msi"),target["sizeBytes"])
        need(package["sizeBytes"]==target["sizeBytes"] and package["sha256"]==target["sha256"],"actual-native-pending-msi-full-hash")
        owner.guard()
        for h,path,directory,identity,security in lease["records"]:
            need(native.identity(h,directory)==identity and native.security(h)==security,"native-pending-handles-closing")
        result=dict(pendingRequest=pending,correlationRecord=correlation,packageFile=package)
        owner.event("current-pre-uac-native-operation-files",{"taskBinding":task_binding,**result})
        return result
    finally:
        for h in reversed(lease["handles"]):
            if not native.k.CloseHandle(h):
                owner.park("original-pre-uac-native-read-close-unknown")
        lease["closed"]=True
