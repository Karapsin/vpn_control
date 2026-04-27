param(
    [Parameter(Mandatory = $true)]
    [string]$HostBaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$WorkRoot,
    [Parameter(Mandatory = $true)]
    [string]$RepoRoot,
    [switch]$SkipTests,
    [switch]$SkipPackageRegressionTests,
    [switch]$SkipInstalledPackageRegressionTests
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$LogDir = Join-Path $WorkRoot "logs"
$ResultStage = Join-Path $WorkRoot "result"
$ResultZip = Join-Path $WorkRoot "windows-package-result.zip"
$BuildLog = Join-Path $LogDir "windows-package-build.log"
$SummaryFile = Join-Path $ResultStage "summary.txt"
$ToolRoot = Join-Path (Split-Path -Parent $WorkRoot) "vpn-control-vm-build-tools"
$ExitCode = 0

if (Test-Path $ResultStage) {
    Remove-Item -Path $ResultStage -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $LogDir, $ResultStage, $ToolRoot | Out-Null

function Write-BuildLog {
    param([string]$Message)
    $Line = "$(Get-Date -Format o) $Message"
    $Line | Out-Host
    Add-Content -Path $BuildLog -Value $Line -Encoding UTF8
}

function Invoke-LoggedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    Write-BuildLog "[vpn-control] running: $FilePath $($Arguments -join ' ')"
    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $FilePath @Arguments 2>&1 | ForEach-Object {
            $Line = $_.ToString()
            $Line | Out-Host
            Add-Content -Path $BuildLog -Value $Line -Encoding UTF8
        }
        $ProcessExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }
    if ($ProcessExitCode -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed with exit code $ProcessExitCode"
    }
}

function Invoke-LoggedPowerShellScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [string[]]$Arguments = @()
    )

    Write-BuildLog "[vpn-control] running: $ScriptPath $($Arguments -join ' ')"
    & $ScriptPath @Arguments *>&1 | ForEach-Object {
        $Line = $_.ToString()
        $Line | Out-Host
        Add-Content -Path $BuildLog -Value $Line -Encoding UTF8
    }
    if (-not $?) {
        throw "$ScriptPath $($Arguments -join ' ') failed"
    }
}

function Invoke-LoggedPackageScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$DistDir
    )

    $SwitchText = @()
    if ($SkipTests) {
        $SwitchText += "-SkipTests"
    }
    if ($SkipPackageRegressionTests) {
        $SwitchText += "-SkipPackageRegressionTests"
    }
    if ($SkipInstalledPackageRegressionTests) {
        $SwitchText += "-SkipInstalledPackageRegressionTests"
    }
    Write-BuildLog "[vpn-control] running: $ScriptPath -DistDir $DistDir $($SwitchText -join ' ')"

    & {
        $PackageArguments = @{
            DistDir = $DistDir
        }
        if ($SkipTests) {
            $PackageArguments.SkipTests = $true
        }
        if ($SkipPackageRegressionTests) {
            $PackageArguments.SkipPackageRegressionTests = $true
        }
        if ($SkipInstalledPackageRegressionTests) {
            $PackageArguments.SkipInstalledPackageRegressionTests = $true
        }
        & $ScriptPath @PackageArguments *>&1
    } | ForEach-Object {
        $Line = $_.ToString()
        $Line | Out-Host
        Add-Content -Path $BuildLog -Value $Line -Encoding UTF8
    }

    if (-not $?) {
        throw "$ScriptPath -DistDir $DistDir failed"
    }
}

function Ensure-Jdk17 {
    $ExistingJava = Get-Command "java.exe" -ErrorAction SilentlyContinue
    if ($ExistingJava) {
        Write-BuildLog "[vpn-control] using existing Java at $($ExistingJava.Source)"
        Invoke-LoggedNative -FilePath "java.exe" -Arguments @("-version")
        return
    }

    $JdkRoot = Join-Path $ToolRoot "jdk-17"
    $JavaExe = Join-Path $JdkRoot "bin\java.exe"
    if (-not (Test-Path $JavaExe)) {
        $Archive = Join-Path $ToolRoot "temurin-jdk17.zip"
        $ExtractRoot = Join-Path $ToolRoot "jdk-extract"
        $JdkUrl = "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x64/jdk/hotspot/normal/eclipse?project=jdk"

        Write-BuildLog "[vpn-control] downloading portable JDK 17"
        Invoke-WebRequest -Uri $JdkUrl -OutFile $Archive -UseBasicParsing

        if (Test-Path $ExtractRoot) {
            Remove-Item -Path $ExtractRoot -Recurse -Force
        }
        New-Item -ItemType Directory -Force -Path $ExtractRoot | Out-Null
        Expand-Archive -Path $Archive -DestinationPath $ExtractRoot -Force

        $ExtractedJdk = Get-ChildItem -Path $ExtractRoot -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName "bin\java.exe") } |
            Select-Object -First 1
        if (-not $ExtractedJdk) {
            throw "Downloaded JDK archive did not contain bin\java.exe"
        }

        if (Test-Path $JdkRoot) {
            Remove-Item -Path $JdkRoot -Recurse -Force
        }
        Move-Item -Path $ExtractedJdk.FullName -Destination $JdkRoot
    }

    $env:JAVA_HOME = $JdkRoot
    $env:PATH = "$JdkRoot\bin;$env:PATH"
    Write-BuildLog "[vpn-control] using portable JDK at $JdkRoot"
    Invoke-LoggedNative -FilePath "java.exe" -Arguments @("-version")
}

try {
    Write-BuildLog "[vpn-control] Windows VM packaging worker started"
    Write-BuildLog "[vpn-control] repo root: $RepoRoot"
    Ensure-Jdk17

    $PackageScript = Join-Path $RepoRoot "scripts\package_windows_desktop.ps1"
    if (-not (Test-Path $PackageScript)) {
        throw "Package script not found: $PackageScript"
    }

    $DistDir = Join-Path $RepoRoot "dist\windows"
    $env:VPN_CONTROL_SING_BOX_CACHE_DIR = Join-Path $ToolRoot "sing-box"
    Invoke-LoggedPackageScript -ScriptPath $PackageScript -DistDir $DistDir
    Write-BuildLog "[vpn-control] Windows VM packaging worker completed successfully"
} catch {
    $ExitCode = 1
    Write-BuildLog "[vpn-control] ERROR: $($_.Exception.Message)"
    Write-BuildLog ($_.ScriptStackTrace | Out-String)
} finally {
    New-Item -ItemType Directory -Force -Path $ResultStage | Out-Null
    "exit_code=$ExitCode" | Out-File -FilePath $SummaryFile -Encoding ascii
    "repo_root=$RepoRoot" | Out-File -FilePath $SummaryFile -Encoding ascii -Append
    "work_root=$WorkRoot" | Out-File -FilePath $SummaryFile -Encoding ascii -Append
    "skip_tests=$SkipTests" | Out-File -FilePath $SummaryFile -Encoding ascii -Append
    "skip_package_regression_tests=$SkipPackageRegressionTests" | Out-File -FilePath $SummaryFile -Encoding ascii -Append
    "skip_installed_package_regression_tests=$SkipInstalledPackageRegressionTests" | Out-File -FilePath $SummaryFile -Encoding ascii -Append

    Copy-Item -Path $BuildLog -Destination (Join-Path $ResultStage "windows-package-build.log") -Force -ErrorAction SilentlyContinue

    $DistDir = Join-Path $RepoRoot "dist\windows"
    if (Test-Path $DistDir) {
        $ArtifactTarget = Join-Path $ResultStage "dist\windows"
        New-Item -ItemType Directory -Force -Path $ArtifactTarget | Out-Null
        Copy-Item -Path (Join-Path $DistDir "*") -Destination $ArtifactTarget -Recurse -Force
    }

    if (Test-Path $ResultZip) {
        Remove-Item -Path $ResultZip -Force
    }
    Compress-Archive -Path (Join-Path $ResultStage "*") -DestinationPath $ResultZip -Force

    try {
        Write-BuildLog "[vpn-control] uploading result zip to host"
        Invoke-WebRequest `
            -Uri "$HostBaseUrl/upload/windows-package-result.zip" `
            -Method Put `
            -InFile $ResultZip `
            -UseBasicParsing | Out-Null
    } catch {
        Write-BuildLog "[vpn-control] failed to upload result zip: $($_.Exception.Message)"
        if ($ExitCode -eq 0) {
            $ExitCode = 1
        }
    }
}

exit $ExitCode
