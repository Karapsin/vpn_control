[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$Dotnet,
    [Parameter(Mandatory = $true)][string]$Python,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string[]]$AllowedImport,
    [switch]$ValidateOnly
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$native = Join-Path $root 'desktopApp\native\windows'
$inventoryTool = Join-Path $root 'scripts\windows_native_helpers.py'
$project = Join-Path $native 'InstallHelper\InstallHelper.csproj'
$required = @(
    (Join-Path $native 'global.json'),
    (Join-Path $native 'Directory.Build.props'),
    (Join-Path $native 'toolchain.lock.json'),
    (Join-Path $native 'import-policy.json'),
    $project,
    (Join-Path $native 'InstallHelper\loader.manifest'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-native.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper-protocol.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper.cs')
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Native helper input missing: $path" }
}
$Dotnet = (Get-Command -Name $Dotnet -CommandType Application -ErrorAction Stop).Source
$Python = (Get-Command -Name $Python -CommandType Application -ErrorAction Stop).Source
if (-not (Test-Path -LiteralPath $inventoryTool -PathType Leaf)) { throw "Inventory tool missing: $inventoryTool" }

$output = [IO.Path]::GetFullPath($OutputRoot)
[IO.Directory]::CreateDirectory($output) | Out-Null
$inventory = Join-Path $output 'native-helper-sources.json'
& $Python $inventoryTool sources --output $inventory $required
if ($LASTEXITCODE -ne 0) { throw 'Native helper source inventory failed' }
if ($ValidateOnly) { return }
$publish = Join-Path $output 'publish'
Push-Location $native
try {
    # SDK resolution follows the working directory, not the --project operand.
    $lock = Get-Content -LiteralPath (Join-Path $native 'toolchain.lock.json') -Raw | ConvertFrom-Json
    $sdk = & $Dotnet --version
    if ($LASTEXITCODE -ne 0 -or $sdk.Trim() -ne $lock.sdkVersion) { throw 'Pinned native helper SDK is unavailable' }
    & $Dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishAot=true -p:TreatWarningsAsErrors=true -p:ILLinkTreatWarningsAsErrors=true -p:IlcTreatWarningsAsErrors=true -o $publish
    if ($LASTEXITCODE -ne 0) { throw 'Native helper publish failed' }
} finally { Pop-Location }
$binary = Join-Path $publish 'vpn-control-install-helper.exe'
$manifest = Join-Path $output 'native-helpers.json'
& $Python $inventoryTool verify-product --output $binary --manifest $manifest $(foreach ($import in $AllowedImport) { '--allowed-import'; $import })
if ($LASTEXITCODE -ne 0) { throw 'Native helper artifact validation failed' }
