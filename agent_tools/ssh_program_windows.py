"""Effect-free plans for the proven V5 SYSTEM infrastructure ScriptBlock loader.

This is deliberately not an ordinary-token executor. A supplied program must
explicitly choose SYSTEM and the V5 held-source parameter contract. Arguments
and a requested working directory are unsupported. The existing durable owner
must retain the returned plan before its one submission, admit the deployment
again, and keep the original guest-exec identity after an uncertain outcome.

``binding.guard()`` is an internal live-admission capability, never request JSON.
It must independently join the original deployment, host/QEMU epoch, QGA peer,
guest boot, ordinary account/session and protected existing workspace, returning
the exact expected target record plus ``host``. No readiness boolean is used.
This module does not connect, read a credential, create a task or launch a child.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import PureWindowsPath
import re
import subprocess
import uuid

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
MAX_COMMAND_UTF16_UNITS = 32767
MAX_REQUEST_BYTES = 60000
MAX_SOURCE_BYTES = 32768
HELD_PARAMETER_HEADER = (
    "param([Parameter(Mandatory=$true)][string]$ExpectedSourceSha256,"
    "[Parameter(Mandatory=$true)][IO.FileStream]$HeldSource,"
    "[Parameter(Mandatory=$true)][string]$SourcePath)\n"
)
_CONTEXT_FIELDS = frozenset((
    "kind", "executionPrincipal", "deploymentId", "hostBootId", "qemuPid",
    "qemuStartTicks", "guestBootTime", "ordinarySid", "ordinarySessionId",
    "workspace", "credentialPath",
))


def _uuid(value, reason):
    try:
        if type(value) is not str or str(uuid.UUID(value)) != value:
            raise ValueError()
    except (ValueError, AttributeError):
        raise ValueError(reason) from None
    return value


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _workspace(value):
    # The proven loader admits an existing protected single workspace below
    # ProgramData. It does not create one or resolve caller-selected providers.
    if (type(value) is not str or re.fullmatch(
            r"C:\\ProgramData\\VpnControl[A-Za-z0-9-]{1,96}", value) is None
            or str(PureWindowsPath(value)) != value):
        raise ValueError("windows_program_workspace")
    return value


def parent_sddl(ordinary_sid):
    return ("O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
            "(A;OICI;0x1200a9;;;" + ordinary_sid + ")")


def validate(program):
    if type(program) is not dict or set(program) != {"language", "source", "args", "cwd", "targetContext"}:
        raise ValueError("windows_program_schema")
    if program["language"] != "powershell-scriptblock":
        raise ValueError("windows_program_language")
    source = program["source"]
    if (type(source) is not str or not source.startswith(HELD_PARAMETER_HEADER)
            or "\0" in source or not 0 < len(source.encode("utf-8", "strict")) + 3 <= MAX_SOURCE_BYTES):
        raise ValueError("windows_program_held_source_contract")
    if type(program["args"]) is not list or program["args"]:
        raise ValueError("windows_program_arguments_unsupported")
    if program["cwd"] is not None:
        raise ValueError("windows_program_cwd_unsupported")
    context = program["targetContext"]
    if type(context) is not dict or set(context) != _CONTEXT_FIELDS:
        raise ValueError("windows_program_target_fields")
    if context["kind"] != "windows-deployment" or context["executionPrincipal"] != "system":
        raise ValueError("windows_program_explicit_system_required")
    _uuid(context["deploymentId"], "windows_program_deployment")
    _uuid(context["hostBootId"], "windows_program_host_epoch")
    if any(type(context[name]) is not int or context[name] <= 0
           for name in ("qemuPid", "qemuStartTicks", "ordinarySessionId")):
        raise ValueError("windows_program_process_session")
    if (type(context["ordinarySid"]) is not str or re.fullmatch(
            r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", context["ordinarySid"]) is None):
        raise ValueError("windows_program_ordinary_sid")
    if (type(context["guestBootTime"]) is not str or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{7}Z",
            context["guestBootTime"]) is None):
        raise ValueError("windows_program_guest_epoch")
    _workspace(context["workspace"])
    credential = context["credentialPath"]
    if (type(credential) is not str or not credential.startswith("/")
            or len(credential.encode("utf-8")) > 4096
            or any(part in ("", ".", "..") for part in credential.split("/")[1:])
            or any(ord(char) < 32 for char in credential)):
        raise ValueError("windows_program_credential_reference")
    return program


def command_bounds(path, args, input_bytes=None):
    """Measure the actual Windows argv and complete guest-exec JSON separately.

    These are the V5 caller's limits and wire serializer. They are not estimates
    based on source length, Base64 length or a POSIX command rendering.
    """
    if (type(path) is not str or type(args) not in (tuple, list)
            or not path or any(type(arg) is not str or "\0" in arg for arg in (path, *args))):
        raise ValueError("instance_windows_argv")
    command_line = subprocess.list2cmdline([path, *args])
    encoded_command = command_line.encode("utf-16le", "strict")
    units = len(encoded_command) // 2 + 1
    if units > MAX_COMMAND_UTF16_UNITS:
        raise ValueError("instance_windows_command_chars")
    arguments = {"path": path, "arg": list(args), "capture-output": True}
    if input_bytes is not None:
        if type(input_bytes) is not bytes or len(input_bytes) > MAX_SOURCE_BYTES:
            raise ValueError("instance_windows_input_bound")
        arguments["input-data"] = base64.b64encode(input_bytes).decode("ascii")
    request = (json.dumps({"execute": "guest-exec", "arguments": arguments}, separators=(",", ":")) + "\n").encode("utf-8")
    if len(request) > MAX_REQUEST_BYTES:
        raise ValueError("instance_windows_transport_bytes")
    return arguments, {
        "commandUtf16UnitsIncludingNul": units,
        "serializedRequestBytes": len(request),
        "commandSha256Utf16le": hashlib.sha256(encoded_command).hexdigest(),
    }


@dataclass(frozen=True)
class WindowsProgramPlan:
    operation_id: str
    source_bytes: bytes
    bootstrap_bytes: bytes
    guest_arguments_json: bytes
    expected_binding_json: bytes
    measurements_json: bytes

    @property
    def source_sha256(self):
        return hashlib.sha256(self.source_bytes).hexdigest()

    def guest_exec_arguments(self):
        return json.loads(self.guest_arguments_json)

    def public_record(self):
        return {
            "schemaVersion": 1, "operationId": self.operation_id,
            "language": "powershell-scriptblock", "executionPrincipal": "system",
            "executionSemantics": "held-saved-file-scriptblock-v5",
            "sourceSha256": self.source_sha256, "sourceBytes": len(self.source_bytes),
            "bootstrapSha256": hashlib.sha256(self.bootstrap_bytes).hexdigest(),
            "targetBindingSha256": hashlib.sha256(self.expected_binding_json).hexdigest(),
            "transport": "qga-input-data-held-source", "replayAllowed": False,
            **json.loads(self.measurements_json),
        }


def build_plan(root, host, operation_id, program, source_context, binding):
    """Return immutable bytes; credential admission and launch stay with owner.

    ``root`` is accepted for the shared owner seam and is never inspected here.
    The source and live-target capabilities must bracket rendering. A later
    launch must invoke both again; this plan is not a persistent readiness token.
    """
    del root
    validate(program)
    _uuid(operation_id, "windows_program_operation")
    if type(host) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", host) is None:
        raise ValueError("windows_program_host")
    if not callable(getattr(source_context, "guard", None)) or not callable(getattr(binding, "guard", None)):
        raise ValueError("windows_program_admission_capability")
    source_context.guard()
    context = program["targetContext"]
    expected = {key: value for key, value in context.items() if key != "credentialPath"}
    expected["host"] = host
    expected["workspaceSddl"] = parent_sddl(context["ordinarySid"])
    if binding.guard() != expected:
        raise ValueError("windows_program_target_changed")
    raw = b"\xef\xbb\xbf" + program["source"].encode("utf-8", "strict")
    path = context["workspace"] + "\\program-" + operation_id + ".ps1"
    bootstrap = render_bootstrap(raw, path=path, workspace=context["workspace"],
                                 ordinary_sid=context["ordinarySid"], phase_id=operation_id)
    args = ("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand",
            base64.b64encode(bootstrap.decode("utf-8-sig").encode("utf-16le")).decode("ascii"))
    arguments, measurements = command_bounds(POWERSHELL, args, raw)
    source_context.guard()
    if binding.guard() != expected:
        raise ValueError("windows_program_target_changed")
    return WindowsProgramPlan(operation_id, raw, bootstrap, _json(arguments), _json(expected), _json(measurements))


def render_bootstrap(raw, *, path, workspace, ordinary_sid, phase_id):
    """Parameterize only V5 data literals; no supplied source enters argv."""
    _workspace(workspace)
    _uuid(phase_id, "windows_program_operation")
    if (type(raw) is not bytes or not 3 < len(raw) <= MAX_SOURCE_BYTES
            or not raw.startswith(b"\xef\xbb\xbf")):
        raise ValueError("windows_program_source_encoding")
    raw[3:].decode("utf-8", "strict")
    if (type(ordinary_sid) is not str or re.fullmatch(
            r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", ordinary_sid) is None):
        raise ValueError("windows_program_ordinary_sid")
    if (type(path) is not str or not path.startswith(workspace + "\\")
            or re.fullmatch(r"[A-Za-z0-9-]+\.ps1", path[len(workspace) + 1:]) is None):
        raise ValueError("windows_program_source_path")
    source = _BOOTSTRAP
    for token, value in (("@@PATH@@", path), ("@@WORKSPACE@@", workspace),
                         ("@@LENGTH@@", str(len(raw))),
                         ("@@SHA256@@", hashlib.sha256(raw).hexdigest()),
                         ("@@PHASE@@", phase_id), ("@@SID@@", ordinary_sid)):
        source = source.replace(token, value)
    return b"\xef\xbb\xbf" + source.encode("utf-8")


# Full V5 source, with only admitted literal data replaced.
_BOOTSTRAP = '$ErrorActionPreference=\'Stop\';$ProgressPreference=\'SilentlyContinue\';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n$path=\'@@PATH@@\';$parent=\'@@WORKSPACE@@\';$length=@@LENGTH@@;$expected=\'@@SHA256@@\';$phase=\'@@PHASE@@\'\nif([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne \'S-1-5-18\'){throw \'TOKEN_STAGE_SYSTEM\'}\n$item=Get-Item -LiteralPath $parent -Force;for($part=$item;$null -ne $part;$part=$part.Parent){if(($part.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){throw \'TOKEN_STAGE_PARENT_REPARSE\'}}\nif((Get-Acl -LiteralPath $parent).Sddl -cne \'O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;@@SID@@)\'){throw \'TOKEN_STAGE_PARENT_ACL\'}\nif(Test-Path -LiteralPath $path){throw \'TOKEN_STAGE_ALREADY_EXISTS\'}\nAdd-Type -TypeDefinition @\'\nusing System;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;\npublic static class VpnHeldProgram {\n [StructLayout(LayoutKind.Sequential)]struct Info { public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }\n [DllImport("kernel32.dll")]static extern IntPtr GetCurrentProcess();\n [DllImport("kernel32.dll",SetLastError=true)]static extern bool DuplicateHandle(IntPtr process,SafeFileHandle source,IntPtr target,out SafeFileHandle result,uint access,bool inherit,uint options);\n [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle source,out Info result);\n [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);\n public static SafeFileHandle ReadOnly(SafeFileHandle source){SafeFileHandle result;if(!DuplicateHandle(GetCurrentProcess(),source,GetCurrentProcess(),out result,0x120089,false,0))throw new Win32Exception(Marshal.GetLastWin32Error());return result;}\n public static string Identity(SafeFileHandle source){Info r;if(!GetFileInformationByHandle(source,out r))throw new Win32Exception(Marshal.GetLastWin32Error());if(r.Links!=1)throw new InvalidOperationException("program-link-count");return r.Volume.ToString("x8")+":"+r.IndexHigh.ToString("x8")+r.IndexLow.ToString("x8");}\n public static int Refusal(string path,uint access){using(SafeFileHandle h=CreateFile(path,access,7,IntPtr.Zero,3,128,IntPtr.Zero)){return h.IsInvalid?Marshal.GetLastWin32Error():0;}}\n}\n\'@ -ReferencedAssemblies @(\'System\',\'System.Core\')\n$inputStream=[Console]::OpenStandardInput();$buffer=New-Object byte[] 6144;$writer=$null;$reader=$null;$duplicate=$null\ntry{\n $writer=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read);$total=0\n while($total -lt $length){$count=$inputStream.Read($buffer,0,[Math]::Min($buffer.Length,$length-$total));if($count -le 0){throw \'TOKEN_STAGE_TRUNCATED\'};$writer.Write($buffer,0,$count);$total+=$count};if($inputStream.ReadByte() -ne -1){throw \'TOKEN_STAGE_TRAILING\'};$writer.Flush($true)\n $security=Get-Acl -LiteralPath $path;$beforeOwner=$security.GetOwner([Security.Principal.SecurityIdentifier]).Value;$security.SetOwner([Security.Principal.SecurityIdentifier]::new(\'S-1-5-18\'));[IO.File]::SetAccessControl($path,$security)\n $id=[VpnHeldProgram]::Identity($writer.SafeFileHandle);$duplicate=[VpnHeldProgram]::ReadOnly($writer.SafeFileHandle);$writer.Dispose();$writer=$null\n $reader=[IO.FileStream]::new($duplicate,[IO.FileAccess]::Read,6144,$false);$duplicate=$null\n if(-not $reader.CanRead -or $reader.CanWrite -or $reader.Length -ne $length -or [VpnHeldProgram]::Identity($reader.SafeFileHandle) -cne $id){throw \'TOKEN_SOURCE_CAPABILITY\'}\n $reader.Position=0;$bytes=New-Object byte[] $length;$offset=0;while($offset -lt $length){$count=$reader.Read($bytes,$offset,$length-$offset);if($count -le 0){throw \'TOKEN_SOURCE_READ\'};$offset+=$count};$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($bytes))).Replace(\'-\',\'\').ToLowerInvariant()}finally{$h.Dispose()};if($actual -cne $expected){throw \'TOKEN_SOURCE_HASH\'}\n $writeRefusal=[VpnHeldProgram]::Refusal($path,0x40000000);$deleteRefusal=[VpnHeldProgram]::Refusal($path,0x10000);if($writeRefusal -ne 32 -or $deleteRefusal -ne 32){throw \'TOKEN_SOURCE_SHARING_REFUSAL\'}\n $acl=Get-Acl -LiteralPath $path;$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;$rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));if($owner -cne \'S-1-5-18\' -or $rules.Count -ne 3){throw \'TOKEN_SOURCE_ACL\'}\n $seen=@{};foreach($rule in $rules){$sid=$rule.IdentityReference.Value;if($seen.ContainsKey($sid) -or $rule.AccessControlType -ne \'Allow\' -or -not $rule.IsInherited){throw \'TOKEN_SOURCE_RULE\'};$seen[$sid]=$true;$rights=if($sid -ceq \'S-1-5-18\' -or $sid -ceq \'S-1-5-32-544\'){0x1f01ff}elseif($sid -ceq \'@@SID@@\'){0x1200a9}else{throw \'TOKEN_SOURCE_RULE_SID\'};if([int]$rule.FileSystemRights -ne $rights){throw \'TOKEN_SOURCE_RULE_RIGHTS\'}}\n if($bytes[0] -ne 239 -or $bytes[1] -ne 187 -or $bytes[2] -ne 191){throw \'TOKEN_SOURCE_BOM\'};$text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes,3,$bytes.Length-3);$tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors);if(@($errors).Count -ne 0){throw \'TOKEN_SOURCE_PARSE\'};$program=[scriptblock]::Create($text)\n $receipt=[ordered]@{phaseId=$phase;path=$path;identity=$id;bytes=$length;sha256=$actual;ownerSid=$owner;sddl=$acl.Sddl;createNew=$true;heldReadOnly=$true;writeOpenError=$writeRefusal;deleteOpenError=$deleteRefusal;parserErrors=@($errors).Count;launch=\'held-saved-file-scriptblock\';originalOwnerSid=$beforeOwner;explicitOwnerGreen=($owner -ceq \'S-1-5-18\');productOperation=$false};$raw=[Text.UTF8Encoding]::new($false).GetBytes(($receipt|ConvertTo-Json -Depth 8 -Compress));$r=[IO.File]::Open((Join-Path $parent (\'held-source-\'+$phase+\'.json\')),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$r.Write($raw,0,$raw.Length);$r.Flush($true)}finally{$r.Dispose()}\n & $program -ExpectedSourceSha256 $expected -HeldSource $reader -SourcePath $path\n if([VpnHeldProgram]::Identity($reader.SafeFileHandle) -cne $id){throw \'TOKEN_SOURCE_FINAL_IDENTITY\'};$reader.Position=0;$h=[Security.Cryptography.SHA256]::Create();try{$closing=([BitConverter]::ToString($h.ComputeHash($reader))).Replace(\'-\',\'\').ToLowerInvariant()}finally{$h.Dispose()};if($closing -cne $expected){throw \'TOKEN_SOURCE_FINAL_HASH\'}\n}finally{foreach($owned in @($writer,$reader,$duplicate)){if($null -ne $owned){$owned.Dispose()}}}\n'
