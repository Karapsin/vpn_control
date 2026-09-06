$ErrorActionPreference = "Stop"

# Load only the assertion helper. Never execute package extraction or launch an app.
$Source = Join-Path $PSScriptRoot "test_windows_desktop_package.ps1"
$ParseTokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($Source, [ref]$ParseTokens, [ref]$ParseErrors)
if ($ParseErrors.Count -ne 0) { throw "Package validation script failed to parse" }
$Helper = $Ast.Find({ param($Node)
    $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq "Assert-FileExists"
}, $true)
if ($null -eq $Helper) { throw "Missing package assertion helper" }
. ([scriptblock]::Create($Helper.Extent.Text))

function Assert-FailureMessage {
    param([scriptblock]$Action, [string]$Expected)
    $Message = $null
    try { & $Action } catch { $Message = $_.Exception.Message }
    if ($Message -ne $Expected) { throw "Expected '$Expected', got '$Message'" }
}

Assert-FailureMessage { Assert-FileExists "MSI payload is missing its console launcher" $null } `
    "MSI payload is missing its console launcher"

$TaskDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("vpn-package-assert-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TaskDirectory | Out-Null
try {
    $Empty = New-Item -ItemType File -Path (Join-Path $TaskDirectory "empty")
    Assert-FailureMessage { Assert-FileExists "Artifact" $Empty } "Artifact is empty at $($Empty.FullName)"
    [System.IO.File]::WriteAllText((Join-Path $TaskDirectory "present"), "fixture")
    Assert-FileExists "Artifact" (Get-Item (Join-Path $TaskDirectory "present"))
} finally {
    Remove-Item -LiteralPath $TaskDirectory -Recurse -Force
}
Write-Host "[vpn-control] Windows package assertion regressions passed"
