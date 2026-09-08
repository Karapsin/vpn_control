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
$projects = @(
    (Join-Path $native 'InstallHelper\InstallHelper.csproj'),
    (Join-Path $native 'VpnBroker\VpnBroker.csproj')
)
$required = @(
    (Join-Path $native 'global.json'),
    (Join-Path $native 'Directory.Build.props'),
    (Join-Path $native 'toolchain.lock.json'),
    (Join-Path $native 'import-policy.json'),
    $projects[0],
    $projects[1],
    (Join-Path $native 'InstallHelper\loader.manifest'),
    (Join-Path $native 'VpnBroker\loader.manifest'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-native.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper-protocol.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper-roles.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper-msi.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-install-helper.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-broker-main.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-helper-admission.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-broker.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-user-files.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-cache-resources.cs'),
    (Join-Path $root 'desktopApp\src\main\resources\windows-vpn-config.cs')
)
foreach ($path in $required) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Native helper input missing: $path" }
}
$Dotnet = (Get-Command -Name $Dotnet -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$Python = (Get-Command -Name $Python -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
if (-not (Test-Path -LiteralPath $inventoryTool -PathType Leaf)) { throw "Inventory tool missing: $inventoryTool" }

$output = [IO.Path]::GetFullPath($OutputRoot)
[IO.Directory]::CreateDirectory($output) | Out-Null
$inventory = Join-Path $output 'native-helper-sources.json'
& $Python $inventoryTool sources --output $inventory $required
if ($LASTEXITCODE -ne 0) { throw 'Native helper source inventory failed' }
if ($ValidateOnly) { return }
$runtime = Join-Path $root 'desktopApp\src\main\resources\bin\windows-amd64\sing-box.exe'
$authoritySource = Join-Path $output 'VpnBrokerRuntimeAuthority.g.cs'
& $Python $inventoryTool runtime-authority --runtime $runtime --output $authoritySource
if ($LASTEXITCODE -ne 0) { throw 'Bundled runtime authority generation failed' }
& $Python $inventoryTool sources --output $inventory $required $runtime $authoritySource
if ($LASTEXITCODE -ne 0) { throw 'Native helper runtime/source inventory failed' }
$publish = Join-Path $output 'publish'
Push-Location $native
try {
    # SDK resolution follows the working directory, not the --project operand.
    $lock = Get-Content -LiteralPath (Join-Path $native 'toolchain.lock.json') -Raw | ConvertFrom-Json
    $sdk = & $Dotnet --version
    if ($LASTEXITCODE -ne 0 -or $sdk.Trim() -ne $lock.sdkVersion) { throw 'Pinned native helper SDK is unavailable' }
    foreach ($project in $projects) {
        & $Dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishAot=true -p:TreatWarningsAsErrors=true -p:ILLinkTreatWarningsAsErrors=true -p:IlcTreatWarningsAsErrors=true "-p:VpnBrokerRuntimeAuthoritySource=$authoritySource" -o $publish
        if ($LASTEXITCODE -ne 0) { throw 'Native helper publish failed' }
    }
} finally { Pop-Location }
$binary = Join-Path $publish 'vpn-control-install-helper.exe'
$broker = Join-Path $publish 'vpn-control-vpn-broker.exe'
$manifest = Join-Path $output 'native-helpers.json'
& $Python $inventoryTool verify-product --output $binary --output $broker --manifest $manifest --runtime $runtime --authority-source $authoritySource $(foreach ($import in $AllowedImport) { '--allowed-import'; $import })
if ($LASTEXITCODE -ne 0) { throw 'Native helper artifact validation failed' }
