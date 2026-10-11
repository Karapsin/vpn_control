"""Shared validation for task-owned Windows native fixture launchers."""
from pathlib import Path, PureWindowsPath
import re
import uuid
from xml.etree import ElementTree


def native_install_helper_fixture_inputs(repository_root: Path) -> tuple[str, ...]:
    """Return the bounded, declared inputs for an InstallHelper fixture build.

    This is deliberately an inventory reader, not an MSBuild evaluator.  The
    helper project supports only literal ApplicationManifest and Compile Include
    declarations, keeping fixture staging tied to the production project without
    silently accepting expressions or paths outside the repository.
    """
    root = Path(repository_root).resolve()
    project = (root / "desktopApp/native/windows/InstallHelper/InstallHelper.csproj").resolve()
    try:
        project_relative = project.relative_to(root)
    except ValueError as error:
        raise ValueError("InstallHelper project must remain under the repository root") from error
    if not project.is_file():
        raise FileNotFoundError(f"InstallHelper project is missing: {project_relative.as_posix()}")

    try:
        xml_root = ElementTree.parse(project).getroot()
    except ElementTree.ParseError as error:
        raise ValueError("InstallHelper project XML is invalid") from error

    declarations: list[str] = []
    manifests = [element.text for element in xml_root.findall(".//ApplicationManifest")]
    if len(manifests) != 1 or not manifests[0] or not manifests[0].strip():
        raise ValueError("InstallHelper must declare exactly one ApplicationManifest")
    declarations.append(manifests[0].strip())
    for element in xml_root.findall(".//Compile"):
        include = element.get("Include")
        if include is None or not include.strip():
            raise ValueError("InstallHelper Compile entries require a literal Include")
        declarations.append(include.strip())

    inputs = [project, project.parent.parent / "Directory.Build.props", project.parent.parent / "global.json"]
    for declaration in declarations:
        if "$" in declaration or "*" in declaration or "?" in declaration:
            raise ValueError(f"unsupported InstallHelper input expression: {declaration}")
        candidate = (project.parent / Path(declaration.replace("\\", "/"))).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise ValueError(f"InstallHelper input escapes repository root: {declaration}") from error
        inputs.append(candidate)

    relative_inputs: list[str] = []
    for input_path in inputs:
        if not input_path.is_file():
            raise FileNotFoundError(f"InstallHelper fixture input is missing: {input_path.relative_to(root).as_posix()}")
        relative = input_path.relative_to(root).as_posix()
        if relative not in relative_inputs:
            relative_inputs.append(relative)
    return tuple(relative_inputs)

_TASK_NAME = re.compile(
    r"^VpnInstaller(?:Entry|Close|Preflight)32-"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$",
    re.IGNORECASE,
)
_INTERACTIVE_USER_SID = re.compile(
    r"^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$",
    re.IGNORECASE,
)


def trusted_powershell_file_arguments(script_path: str, arguments: tuple[str, ...]) -> tuple[str, ...]:
    """Build the fixed, process-scoped PowerShell invocation for a trusted fixture file.

    Passing the file path and each argument as discrete argv values keeps spaces
    and Unicode literal.  ``-ExecutionPolicy Bypass`` applies to this PowerShell
    process only; this helper must never emit a persistent policy command.
    """
    if type(script_path) is not str or "\x00" in script_path:
        raise ValueError("trusted PowerShell fixture script path must be a string without NUL")
    path = PureWindowsPath(script_path)
    if not path.is_absolute() or path.suffix.lower() != ".ps1":
        raise ValueError("trusted PowerShell fixture script path must be absolute and end in .ps1")
    if not isinstance(arguments, tuple) or any(type(argument) is not str or "\x00" in argument for argument in arguments):
        raise ValueError("trusted PowerShell fixture arguments must be a tuple of strings without NUL")
    return (
        "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script_path,
    ) + arguments


def private_task_root(task_name: str, local_app_data: str) -> str:
    """Return the exact private LocalAppData root for an allowed task name."""
    if not isinstance(task_name, str) or not isinstance(local_app_data, str):
        raise ValueError("task name and LocalAppData must be strings")
    match = _TASK_NAME.fullmatch(task_name)
    if match is None:
        raise ValueError("unsupported Windows native fixture task name")
    try:
        uuid.UUID(match.group(1))
    except ValueError as error:
        raise ValueError("invalid Windows native fixture task UUID") from error
    parent = PureWindowsPath(local_app_data)
    if not parent.is_absolute() or parent.name.lower() != "local":
        raise ValueError("LocalAppData must be an absolute Local directory")
    return str(parent / task_name)


def _validate_expected_recipient(expected_sid: str, expected_session_id: int) -> None:
    if not isinstance(expected_sid, str) or _INTERACTIVE_USER_SID.fullmatch(expected_sid) is None:
        raise ValueError("expected SID must be a canonical interactive user SID")
    if type(expected_session_id) is not int or expected_session_id <= 0:
        raise ValueError("expected session must be a positive integer")


def original_recipient_actor_classifier(expected_sid: str, expected_session_id: int) -> str:
    """Generate the sole PowerShell classifier used before a per-user install."""
    _validate_expected_recipient(expected_sid, expected_session_id)
    return (
        "function Assert-VpnFixtureOriginalRecipientActor {\n"
        "  param([string]$ActualSid,[object]$ActualSession)\n"
        f"  $expectedSid='{expected_sid}'\n"
        "  if($ActualSid -eq 'S-1-5-18'){throw 'SYSTEM must not install a per-user fixture'}\n"
        "  if($ActualSid -notmatch '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$')"
        "{throw 'service or non-user SID must not install a per-user fixture'}\n"
        "  if($ActualSession -isnot [int] -or $ActualSession -le 0)"
        "{throw 'interactive recipient session must be a positive integer'}\n"
        f"  if($ActualSid -ne $expectedSid -or $ActualSession -ne {expected_session_id})"
        "{throw 'interactive recipient actor did not match'}\n"
        "}\n"
    )


def original_recipient_actor_guard(expected_sid: str, expected_session_id: int) -> str:
    """Generate the pre-msiexec PowerShell guard for an InteractiveToken fixture."""
    return (
        original_recipient_actor_classifier(expected_sid, expected_session_id)
        +
        "$actualSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
        "$actualSession=(Get-Process -Id $PID).SessionId\n"
        "Assert-VpnFixtureOriginalRecipientActor -ActualSid $actualSid -ActualSession $actualSession\n"
    )


FIXTURE_READ_COMMAND = "Read-VpnFixtureExact"
FIXTURE_OUTPUT_RECEIPT_COMMAND = "Read-VpnFixtureOutputReceipt"


def fixture_stream_reader() -> str:
    """Exact-byte reader shared by the native SOCKS fixture and its quick check."""
    return f"function {FIXTURE_READ_COMMAND} " + r"""{
    param([System.IO.Stream]$Stream, [int]$Count)
    if ($Count -lt 0) { throw 'negative fixture read length' }
    $bytes = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($bytes, $offset, $Count - $offset)
        if ($read -le 0) { throw 'fixture stream ended early' }
        $offset += $read
    }
    return ,$bytes
}
"""


def fixture_output_receipt_reader() -> str:
    """Read native capture files into a receipt without losing empty output.

    ``Get-Content -Raw`` emits no pipeline value for an empty file.  Native
    fixtures need an explicit .NET file read so a receipt preserves an empty
    stdout or stderr value alongside the direct child's exit code.
    """
    return f"function {FIXTURE_OUTPUT_RECEIPT_COMMAND} " + r'''{
    param(
        [Parameter(Mandatory = $true)][string]$StandardOutputPath,
        [Parameter(Mandatory = $true)][string]$StandardErrorPath,
        [Parameter(Mandatory = $true)][int]$ExitCode
    )
    foreach ($path in @($StandardOutputPath, $StandardErrorPath)) {
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'native fixture receipt path is required' }
        if (-not [IO.File]::Exists($path)) { throw "native fixture receipt file is missing: $path" }
    }
    return [pscustomobject]@{
        Stdout = [IO.File]::ReadAllText($StandardOutputPath)
        Stderr = [IO.File]::ReadAllText($StandardErrorPath)
        ExitCode = $ExitCode
    }
}
'''


def fixture_proxy_port_selector() -> str:
    """Select the public listener, excluding the separate management listener."""
    return r"""function Get-VpnFixtureProxyPort {
    param([object]$Configuration)
    $public = @($Configuration.inbounds | Where-Object {
        $_.type -eq 'mixed' -and $_.tag -eq 'mixed-in' -and $_.listen -eq '127.0.0.1'
    })
    if ($public.Count -ne 1) { throw 'public fixture listener count' }
    $port = $public[0].listen_port
    if ($port -isnot [int] -and $port -isnot [long]) { throw 'invalid fixture port type' }
    if ($port -lt 1 -or $port -gt 65535) { throw 'invalid fixture port range' }
    return $port
}
"""


def fixture_native_process_capture() -> str:
    """Generate the PS5.1-safe native process capture used by Windows fixtures.

    Native stderr is data, rather than a PowerShell error stream.  A directly
    owned Process has a stable child handle; its stdout and stderr are copied
    concurrently into files, and that child's ExitCode decides success.
    ProcessStartInfo.ArgumentList is unavailable on Windows PowerShell 5.1, so
    the helper builds a Windows-quoted command line explicitly.
    """
    return r'''function ConvertTo-VpnFixtureNativeArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Argument)
    if ($Argument.Length -eq 0) { return '""' }
    if ($Argument -notmatch '[\s"]') { return $Argument }

    $quoted = New-Object System.Text.StringBuilder
    [void]$quoted.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq '\') {
            $backslashes++
        } elseif ($character -eq '"') {
            [void]$quoted.Append('\', ($backslashes * 2) + 1)
            [void]$quoted.Append('"')
            $backslashes = 0
        } else {
            if ($backslashes -gt 0) { [void]$quoted.Append('\', $backslashes) }
            [void]$quoted.Append($character)
            $backslashes = 0
        }
    }
    if ($backslashes -gt 0) { [void]$quoted.Append('\', $backslashes * 2) }
    [void]$quoted.Append('"')
    return $quoted.ToString()
}

function Invoke-VpnFixtureNativeProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$StandardOutputPath,
        [Parameter(Mandatory = $true)][string]$StandardErrorPath
    )
    if ([string]::IsNullOrWhiteSpace($FilePath)) { throw 'native fixture file path is required' }
    foreach ($path in @($StandardOutputPath, $StandardErrorPath)) {
        if ([string]::IsNullOrWhiteSpace($path)) { throw 'native fixture capture path is required' }
        $parent = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path))
        if (-not [IO.Directory]::Exists($parent)) { throw "native fixture capture directory is missing: $parent" }
        if (Test-Path -LiteralPath $path) { throw "native fixture capture path already exists: $path" }
    }
    if ([IO.Path]::GetFullPath($StandardOutputPath) -eq [IO.Path]::GetFullPath($StandardErrorPath)) {
        throw 'native fixture stdout and stderr capture paths must differ'
    }
    $argumentLine = (($Arguments | ForEach-Object {
        if ($null -eq $_) { throw 'native fixture arguments cannot be null' }
        ConvertTo-VpnFixtureNativeArgument ([string]$_)
    }) -join ' ')

    $process = New-Object Diagnostics.Process
    $stdoutFile = $null
    $stderrFile = $null
    try {
        $stdoutFile = [IO.File]::Open($StandardOutputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $stderrFile = [IO.File]::Open($StandardErrorPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
        $startInfo = New-Object Diagnostics.ProcessStartInfo
        $startInfo.FileName = $FilePath
        $startInfo.Arguments = $argumentLine
        $startInfo.WorkingDirectory = $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw 'native fixture process did not start' }

        # Copy both pipes before waiting. Sequential draining can deadlock when
        # a child fills the other pipe, while CopyToAsync keeps output bounded.
        $stdoutCopy = $process.StandardOutput.BaseStream.CopyToAsync($stdoutFile)
        $stderrCopy = $process.StandardError.BaseStream.CopyToAsync($stderrFile)
        $process.WaitForExit()
        [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdoutCopy, $stderrCopy))
        return [pscustomobject]@{ ExitCode = [int]$process.ExitCode }
    } finally {
        if ($null -ne $stdoutFile) { $stdoutFile.Dispose() }
        if ($null -ne $stderrFile) { $stderrFile.Dispose() }
        $process.Dispose()
    }
}
'''


def fixture_progress_only_stderr() -> str:
    """Emit the bounded fixture-only progress classifier; retain raw stderr separately.

    This is data classification, not process/result authority. The caller must
    still bind exact exit code, stdout, principal, source and capture custody.
    """
    return r'''function Test-VpnFixtureProgressOnlyStderr {
 param([AllowEmptyCollection()][byte[]]$Bytes)
 if($null -eq $Bytes){return $false}
 if($Bytes.Length -eq 0){return $true}
 if($Bytes.Length -gt 8192){return $false}
 $reader=$null;$inputReader=$null
 try{
  $text=([Text.UTF8Encoding]::new($false,$true)).GetString($Bytes)
  if(-not $text.StartsWith('#< CLIXML',[StringComparison]::Ordinal) -or $text.Contains('<!DOCTYPE') -or $text.Contains('<!ENTITY')){return $false}
  $body=$text.Substring(9).TrimStart([char[]]"`r`n")
  $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null;$settings.MaxCharactersInDocument=8192
  $inputReader=[IO.StringReader]::new($body);$reader=[Xml.XmlReader]::Create($inputReader,$settings)
  $doc=[Xml.XmlDocument]::new();$doc.XmlResolver=$null;$doc.PreserveWhitespace=$true;$doc.Load($reader)
  $ns='http://schemas.microsoft.com/powershell/2004/04';$xmlns='http://www.w3.org/2000/xmlns/'
  $root=$doc.DocumentElement
  if($null -eq $root -or $root.LocalName -cne 'Objs' -or $root.NamespaceURI -cne $ns){return $false}
  $attrs=@($root.Attributes|Where-Object {$_.NamespaceURI -cne $xmlns})
  if($attrs.Count -ne 1 -or $attrs[0].Name -cne 'Version' -or $attrs[0].Value -cne '1.1.0.1'){return $false}
  foreach($n in $doc.ChildNodes){if($n -ne $root -and $n.NodeType -notin @([Xml.XmlNodeType]::Whitespace,[Xml.XmlNodeType]::SignificantWhitespace)){return $false}}
  $entries=@($root.ChildNodes|Where-Object {$_.NodeType -eq [Xml.XmlNodeType]::Element})
  if($entries.Count -lt 1 -or $entries.Count -gt 32){return $false}
  foreach($n in $root.ChildNodes){if($n.NodeType -ne [Xml.XmlNodeType]::Element -and ($n.NodeType -notin @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::Whitespace,[Xml.XmlNodeType]::SignificantWhitespace) -or -not [string]::IsNullOrWhiteSpace($n.Value))){return $false}}
  foreach($entry in $entries){
   $attrs=@($entry.Attributes|Where-Object {$_.NamespaceURI -cne $xmlns})
   if($entry.LocalName -cne 'Obj' -or $entry.NamespaceURI -cne $ns -or $attrs.Count -ne 2 -or @($attrs|Where-Object {$_.Name -cnotin @('S','RefId')}).Count -ne 0 -or $entry.GetAttribute('S') -cne 'progress' -or $entry.GetAttribute('RefId') -cnotmatch '\A[0-9]{1,8}\z'){return $false}
  }
  $pending=[Collections.Generic.Stack[object]]::new();$pending.Push(@{node=$root;depth=0});$count=0
  while($pending.Count -gt 0){
   $item=$pending.Pop();$n=$item.node;$count++
   if($count -gt 256 -or $item.depth -gt 16 -or $n.NamespaceURI -cne $ns){return $false}
   if($n.HasAttribute('S') -and $n.GetAttribute('S') -cne 'progress'){return $false}
   if(@($n.Attributes|Where-Object {$_.NamespaceURI.Length -ne 0 -and $_.NamespaceURI -cne $xmlns}).Count -ne 0){return $false}
   foreach($child in $n.ChildNodes){
    if($child.NodeType -eq [Xml.XmlNodeType]::Element){$pending.Push(@{node=$child;depth=$item.depth+1})}
    elseif($child.NodeType -notin @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::Whitespace,[Xml.XmlNodeType]::SignificantWhitespace)){return $false}
   }
  }
  return $true
 }catch{return $false}
 finally{try{if($null -ne $reader){$reader.Dispose()}}finally{if($null -ne $inputReader){$inputReader.Dispose()}}}
}
'''


def fixture_hashtable_sum_after_oracle() -> str:
    """Emit the exact paired SUM AFTER predicate used after owned raw capture."""
    return "if($case -eq 'after' -and ($r.ExitCode -ne 0 -or $stdout.Trim() -cne '500' -or -not (Test-VpnFixtureProgressOnlyStderr -Bytes ([IO.File]::ReadAllBytes($err))))){throw 'TYPED_AFTER_NOT_GREEN'}"
