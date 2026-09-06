package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdateLogic
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withTimeoutOrNull

internal data class DesktopUpdateCheck(val updateAvailable: Boolean, val asset: UpdateAsset?, val releaseNotesUrl: String)

internal class DesktopUpdateService(
    private val stateProvider: () -> MainUiState,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val updateDirectory: Path,
    private val buildInfo: DesktopBuildInfo = DesktopBuildInfo.current(),
    private val osName: String = System.getProperty("os.name"),
    private val osArchitecture: String = System.getProperty("os.arch"),
    private val currentCommand: String? = ProcessHandle.current().info().command().orElse(null),
    private val manifestUrl: String = AppUpdateLogic.LATEST_MANIFEST_URL,
    private val trustUrl: (String) -> Boolean = AppUpdateLogic::isTrustedGithubUrl,
    private val workspaceDirectory: Path = DesktopWorkspacePaths.root(),
) {
    private var preparedPackage: Path? = null
    private var installerCancelFile: Path? = null
    private var checkedUpdate: DesktopUpdateCheck? = null
    private val operationMutex = kotlinx.coroutines.sync.Mutex()
    private val httpClient by lazy {
        HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20))
            .followRedirects(HttpClient.Redirect.NORMAL).build()
    }

    private suspend fun <T> exclusive(action: suspend () -> Result<T>): Result<T> {
        if (!operationMutex.tryLock()) return Result.failure(IllegalStateException("BUSY"))
        return try {
            if (stateProvider().appUpdate.phase == AppUpdatePhase.INSTALLING) Result.failure(IllegalStateException("BUSY"))
            else action()
        } finally { operationMutex.unlock() }
    }

    fun checkedStatus(): DesktopUpdateCheck? = checkedUpdate

    /** Manifest-only operation: no package download, installer, or runtime effect. */
    suspend fun check(): Result<DesktopUpdateCheck> = exclusive { checkInternal() }

    private suspend fun checkInternal(): Result<DesktopUpdateCheck> {
        checkedUpdate = null
        preparedPackage = null
        updateAppState { AppUpdateState(showDialog = it.showDialog, phase = AppUpdatePhase.CHECKING,
            currentVersion = buildInfo.displayVersion) }
        return try {
            val manifest = AppUpdateLogic.parseManifest(fetchText(manifestUrl), trustUrl)
            val available = AppUpdateLogic.isUpdateAvailable(buildInfo.buildNumber, manifest)
            val asset = if (!available) null else currentPlatformSelection().let { selection ->
                AppUpdateLogic.selectAsset(manifest, selection.platform, setOf(osArchitecture), selection.packageTypes)
            }
            val result = DesktopUpdateCheck(available, asset, manifest.releaseNotesUrl)
            checkedUpdate = result
            updateAppState { it.copy(
                phase = if (!available) AppUpdatePhase.UP_TO_DATE else if (asset == null) AppUpdatePhase.UNSUPPORTED else AppUpdatePhase.IDLE,
                availableVersion = asset?.displayVersion.orEmpty(), releaseNotesUrl = manifest.releaseNotesUrl,
            ) }
            Result.success(result)
        } catch (cancelled: CancellationException) {
            updateAppState { it.copy(phase = AppUpdatePhase.IDLE) }
            throw cancelled
        } catch (_: Exception) {
            updateAppState { it.copy(phase = AppUpdatePhase.FAILED, message = "UPDATE_CHECK_FAILED") }
            Result.failure(IllegalStateException("UPDATE_CHECK_FAILED"))
        }
    }

    suspend fun downloadChecked(): Result<Unit> = exclusive { downloadInternal() }

    private suspend fun downloadInternal(): Result<Unit> {
        val asset = checkedUpdate?.asset
            ?: return Result.failure(IllegalStateException("NO_UPDATE_AVAILABLE"))
        preparedPackage = null
        return try {
            updateAppState { it.copy(phase = AppUpdatePhase.DOWNLOADING, availableVersion = asset.displayVersion,
                downloadedBytes = 0, totalBytes = asset.sizeBytes, preparedAsset = null) }
            val packageFile = download(asset)
            updateAppState { it.copy(phase = AppUpdatePhase.VERIFYING) }
            require(packageFile.sha256() == asset.sha256) { "Checksum mismatch" }
            preparedPackage = packageFile
            updateAppState { it.copy(phase = AppUpdatePhase.READY, downloadedBytes = asset.sizeBytes,
                totalBytes = asset.sizeBytes, preparedAsset = asset) }
            Result.success(Unit)
        } catch (cancelled: CancellationException) {
            cleanupPartialDownloads()
            updateAppState { it.copy(phase = AppUpdatePhase.IDLE, preparedAsset = null) }
            throw cancelled
        } catch (_: Exception) {
            cleanupPartialDownloads()
            updateAppState { it.copy(phase = AppUpdatePhase.FAILED, message = "UPDATE_DOWNLOAD_FAILED", preparedAsset = null) }
            Result.failure(IllegalStateException("UPDATE_DOWNLOAD_FAILED"))
        }
    }

    suspend fun checkAndDownload() {
        exclusive { checkAndDownloadInternal(); Result.success(Unit) }
    }

    private suspend fun checkAndDownloadInternal() {
        preparedPackage = null
        updateAppState {
            AppUpdateState(
                showDialog = true,
                phase = AppUpdatePhase.CHECKING,
                currentVersion = buildInfo.displayVersion,
            )
        }
        try {
            val checked = checkInternal().getOrThrow()
            if (!checked.updateAvailable) {
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.UP_TO_DATE,
                        releaseNotesUrl = checked.releaseNotesUrl,
                    )
                }
                return
            }
            val asset = checked.asset
            if (asset == null) {
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.UNSUPPORTED,
                        releaseNotesUrl = checked.releaseNotesUrl,
                    )
                }
                return
            }
            updateAppState {
                it.copy(
                    phase = AppUpdatePhase.DOWNLOADING,
                    availableVersion = asset.displayVersion,
                    releaseNotesUrl = checked.releaseNotesUrl,
                    totalBytes = asset.sizeBytes,
                )
            }
            downloadInternal().getOrThrow()
        } catch (_: CancellationException) {
            cleanupPartialDownloads()
            throw CancellationException("Update canceled")
        } catch (error: Throwable) {
            cleanupPartialDownloads()
            updateAppState {
                it.copy(
                    phase = AppUpdatePhase.FAILED,
                    message = error.message.orEmpty(),
                    preparedAsset = null,
                )
            }
        }
    }

    fun dismiss(): Result<Unit> {
        if (!operationMutex.tryLock()) return Result.failure(IllegalStateException("BUSY"))
        try {
        if (stateProvider().appUpdate.phase == AppUpdatePhase.INSTALLING) return Result.failure(IllegalStateException("BUSY"))
        checkedUpdate = null
        preparedPackage = null
        cleanupPartialDownloads()
        updateAppState { AppUpdateState(currentVersion = buildInfo.displayVersion) }
        return Result.success(Unit)
        } finally { operationMutex.unlock() }
    }

    fun reportInstallFailure(message: String) {
        cancelPreparedInstaller()
        updateAppState {
            it.copy(
                phase = AppUpdatePhase.READY,
                message = message,
            )
        }
    }

    suspend fun authorizeInstallerAndWaitUntilReady(currentPid: Long): Result<Unit> = withContext(Dispatchers.IO) {
        exclusive { authorizeInstallerInternal(currentPid) }
    }

    private suspend fun authorizeInstallerInternal(currentPid: Long): Result<Unit> = withContext(Dispatchers.IO) {
        val packageFile = preparedPackage?.takeIf(Files::isRegularFile)
            ?: return@withContext Result.failure(IllegalStateException("No verified update is ready"))
        val asset = stateProvider().appUpdate.preparedAsset
            ?: return@withContext Result.failure(IllegalStateException("Update package metadata is unavailable"))
        val stillVerified = runCatching {
            !Files.isSymbolicLink(packageFile) && Files.size(packageFile) == asset.sizeBytes && packageFile.sha256() == asset.sha256
        }.getOrDefault(false)
        if (!stillVerified) {
            preparedPackage = null
            updateAppState { it.copy(phase = AppUpdatePhase.FAILED, preparedAsset = null, message = "UPDATE_PACKAGE_CHANGED") }
            return@withContext Result.failure(IllegalStateException("UPDATE_PACKAGE_CHANGED"))
        }
        val launcher = preferredLauncher()
            ?: return@withContext Result.failure(IllegalStateException("Could not determine the desktop launcher path"))
        updateAppState { it.copy(phase = AppUpdatePhase.INSTALLING, message = "") }
        Files.createDirectories(updateDirectory)
        val readyFile = updateDirectory.resolve("installer-${ProcessHandle.current().pid()}.ready")
        val errorFile = updateDirectory.resolve("installer-${ProcessHandle.current().pid()}.error")
        val cancelFile = updateDirectory.resolve("installer-${ProcessHandle.current().pid()}.cancel")
        Files.deleteIfExists(readyFile)
        Files.deleteIfExists(errorFile)
        Files.deleteIfExists(cancelFile)
        installerCancelFile = cancelFile
        val started = when (asset.platform) {
            UpdatePlatform.WINDOWS -> launchWindowsHelper(packageFile, launcher, currentPid, readyFile, errorFile, cancelFile)
            UpdatePlatform.LINUX -> launchLinuxHelper(
                packageFile, asset.packageType, asset.sha256, launcher, currentPid, readyFile, errorFile, cancelFile,
            )
            UpdatePlatform.MACOS -> launchMacHelper(packageFile, asset.sha256, launcher, currentPid, readyFile, errorFile, cancelFile)
            UpdatePlatform.ANDROID -> false
        }
        if (!started) {
            installerCancelFile = null
            updateAppState { it.copy(phase = AppUpdatePhase.READY, message = "Could not launch the system installer") }
            return@withContext Result.failure(IllegalStateException("Could not launch the system installer"))
        }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90)
        while (System.nanoTime() < deadline) {
            if (Files.exists(readyFile)) return@withContext Result.success(Unit)
            if (Files.exists(errorFile)) {
                val message = runCatching { Files.readString(errorFile) }.getOrDefault("Installer authorization failed")
                updateAppState { it.copy(phase = AppUpdatePhase.READY, message = message.trim()) }
                return@withContext Result.failure(IllegalStateException(message))
            }
            Thread.sleep(250)
        }
        cancelPreparedInstaller()
        updateAppState { it.copy(phase = AppUpdatePhase.READY, message = "Installer authorization timed out") }
        Result.failure(IllegalStateException("Installer authorization timed out"))
    }

    fun cancelPreparedInstaller() {
        installerCancelFile?.let { path -> runCatching { Files.writeString(path, "cancel\n") } }
        installerCancelFile = null
    }

    private suspend fun fetchText(url: String): String = withTimeoutOrNull(300_000) {
        runInterruptible(Dispatchers.IO) {
            openResponse(url, "application/json").bufferedReader(Charsets.UTF_8).use { it.readText() }
        }
    } ?: error("Update network deadline exceeded")

    private suspend fun download(asset: UpdateAsset): Path = withTimeoutOrNull(300_000) {
        val operationContext = currentCoroutineContext()
        runInterruptible(Dispatchers.IO) {
            Files.createDirectories(updateDirectory)
            val partial = updateDirectory.resolve("${asset.fileName}.part")
            val completed = updateDirectory.resolve(asset.fileName)
            Files.deleteIfExists(partial)
            Files.deleteIfExists(completed)
            openResponse(asset.downloadUrl, "application/octet-stream").use { input ->
                var copied = 0L
                Files.newOutputStream(partial, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        operationContext.ensureActive()
                        val read = input.read(buffer)
                        if (read < 0) break
                        require(read.toLong() <= asset.sizeBytes - copied) { "Update exceeds declared size" }
                        output.write(buffer, 0, read)
                        copied += read
                        updateAppState { it.copy(downloadedBytes = copied, totalBytes = asset.sizeBytes) }
                    }
                }
            }
            require(Files.size(partial) == asset.sizeBytes) { "Downloaded update size does not match the release manifest" }
            Files.move(partial, completed, StandardCopyOption.REPLACE_EXISTING)
            completed
        }
    } ?: error("Update network deadline exceeded")

    private fun currentPlatformSelection(): DesktopUpdateSelection {
        val normalized = osName.lowercase(Locale.ROOT)
        return when {
            "windows" in normalized -> DesktopUpdateSelection(UpdatePlatform.WINDOWS, listOf(UpdatePackageType.MSI))
            "mac" in normalized || "darwin" in normalized ->
                DesktopUpdateSelection(UpdatePlatform.MACOS, listOf(UpdatePackageType.DMG))
            "linux" in normalized -> DesktopUpdateSelection(UpdatePlatform.LINUX, linuxPackagePreference())
            else -> error("Desktop updates are not supported on $osName")
        }
    }

    private fun linuxPackagePreference(): List<UpdatePackageType> {
        val osRelease = runCatching { Files.readString(Path.of("/etc/os-release")).lowercase(Locale.ROOT) }.getOrDefault("")
        return when {
            "arch" in osRelease || commandExists("pacman") -> listOf(UpdatePackageType.ARCH_BUNDLE)
            "debian" in osRelease || "ubuntu" in osRelease || commandExists("dpkg") -> listOf(UpdatePackageType.DEB)
            else -> listOf(UpdatePackageType.RPM)
        }
    }

    private fun launchLinuxHelper(
        packageFile: Path,
        packageType: UpdatePackageType,
        expectedSha256: String,
        launcher: String,
        currentPid: Long,
        readyFile: Path,
        errorFile: Path,
        cancelFile: Path,
    ): Boolean {
        val installedFile = updateDirectory.resolve("installer-${ProcessHandle.current().pid()}.installed")
        Files.deleteIfExists(installedFile)
        val watcher = linuxRelaunchCommand(currentPid, launcher, installedFile, errorFile, cancelFile)
        val authorization = listOf(
            "/bin/sh", "-c", linuxAuthorizationLauncher(), "vpn-control-update-authorizer",
            linuxRootHelper(),
            packageFile.toString(),
            packageType.wireName,
            currentPid.toString(),
            readyFile.toString(),
            errorFile.toString(),
            cancelFile.toString(),
            installedFile.toString(),
            expectedSha256,
        )
        return runCatching {
            ProcessBuilder(watcher).start()
            ProcessBuilder(authorization).start()
            true
        }.getOrDefault(false)
    }

    private fun launchWindowsHelper(
        packageFile: Path,
        launcher: String,
        currentPid: Long,
        readyFile: Path,
        errorFile: Path,
        cancelFile: Path,
    ): Boolean {
        val helper = writeText("windows-update.ps1", windowsHelper())
        return runCatching {
            ProcessBuilder(windowsHelperCommand(helper, packageFile, launcher, currentPid, readyFile, errorFile, cancelFile)).start()
            true
        }.getOrDefault(false)
    }

    private fun launchMacHelper(
        packageFile: Path,
        expectedSha256: String,
        launcher: String,
        currentPid: Long,
        readyFile: Path,
        errorFile: Path,
        cancelFile: Path,
    ): Boolean {
        val helper = writeExecutable("macos-update.sh", macHelper())
        return runCatching {
            ProcessBuilder(
                "/bin/sh", helper.toString(), packageFile.toString(), launcher, currentPid.toString(),
                readyFile.toString(), errorFile.toString(), cancelFile.toString(), workspaceDirectory.toString(), expectedSha256,
            ).start()
            true
        }.getOrDefault(false)
    }

    private fun writeExecutable(name: String, content: String): Path {
        val path = writeText(name, content)
        path.toFile().setExecutable(true, true)
        return path
    }

    private fun writeText(name: String, content: String): Path {
        Files.createDirectories(updateDirectory)
        return Files.writeString(
            updateDirectory.resolve(name),
            content,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE,
        )
    }

    private fun cleanupPartialDownloads() {
        runCatching {
            if (Files.isDirectory(updateDirectory)) {
                Files.list(updateDirectory).use { paths ->
                    paths.filter { it.fileName.toString().endsWith(".part") }.forEach(Files::deleteIfExists)
                }
            }
        }
    }

    private fun updateAppState(transform: (AppUpdateState) -> AppUpdateState) {
        updateState { state -> state.copy(appUpdate = transform(state.appUpdate)) }
    }

    private fun openResponse(url: String, accept: String): InputStream {
        val request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(5))
            .header("Accept", accept).header("User-Agent", "VPNControlDesktop/${buildInfo.displayVersion}").GET().build()
        val response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream())
        val code = response.statusCode()
        if (code !in 200..299) {
            response.body().close()
            error("Update request failed: HTTP $code")
        }
        return response.body()
    }

    private fun Path.sha256(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(this).buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun commandExists(command: String): Boolean {
        return runCatching {
            ProcessBuilder("/bin/sh", "-c", "command -v \"\$1\" >/dev/null 2>&1", "sh", command)
                .start().waitFor() == 0
        }.getOrDefault(false)
    }

    private fun preferredLauncher(): String? {
        val normalized = osName.lowercase(Locale.ROOT)
        if ("linux" in normalized) {
            listOf(Path.of("/usr/local/bin/vpn-control"), Path.of("/usr/bin/vpn-control"))
                .firstOrNull { Files.isExecutable(it) }
                ?.let { return it.toString() }
        }
        return currentCommand?.takeIf(String::isNotBlank)
    }

    private data class DesktopUpdateSelection(
        val platform: UpdatePlatform,
        val packageTypes: List<UpdatePackageType>,
    )

    private fun linuxAuthorizationLauncher(): String = """
set -eu
root_script=§1
package_file=§2
package_type=§3
pid=§4
ready_file=§5
error_file=§6
cancel_file=§7
installed_file=§8
expected_sha256=§9
if ! command -v pkexec >/dev/null 2>&1; then
  printf '%s\n' 'pkexec is required to authorize this update.' > "§error_file"
  exit 1
fi
if ! pkexec /bin/sh -c "§root_script" vpn-control-update-root \
  "§package_file" "§package_type" "§pid" "§ready_file" "§error_file" \
  "§cancel_file" "§installed_file" "§expected_sha256"; then
  if [ -f "§cancel_file" ]; then exit 0; fi
  printf '%s\n' 'The system installer failed or authorization was canceled.' > "§error_file"
  exit 1
fi
""".replace('§', '$')

    internal fun linuxRelaunchCommand(
        currentPid: Long, launcher: String, installedFile: Path, errorFile: Path, cancelFile: Path,
    ): List<String> = listOf(
        "/bin/sh", "-c", linuxRelaunchWatcher(), "vpn-control-update-watcher",
        currentPid.toString(), launcher, installedFile.toString(), errorFile.toString(), cancelFile.toString(),
        workspaceDirectory.toString(),
    )

    private fun linuxRelaunchWatcher(): String = """
set -eu
pid=§1
launcher=§2
installed_file=§3
error_file=§4
cancel_file=§5
state_dir=§6
relaunch() { nohup "§launcher" --state-dir "§state_dir" >/dev/null 2>&1 & }
while kill -0 "§pid" >/dev/null 2>&1; do
  if [ -f "§cancel_file" ] || [ -f "§error_file" ]; then exit 0; fi
  sleep 1
done
attempt=0
while [ ! -f "§installed_file" ]; do
  if [ -f "§cancel_file" ]; then exit 0; fi
  if [ -f "§error_file" ]; then relaunch; exit 0; fi
  attempt=§((attempt + 1))
  if [ "§attempt" -ge 300 ]; then exit 1; fi
  sleep 1
done
relaunch
""".replace('§', '$')

    private fun linuxRootHelper(): String = """
set -eu
package_file=§1
package_type=§2
pid=§3
ready_file=§4
error_file=§5
cancel_file=§6
installed_file=§7
expected_sha256=§8
temp_dir=§(mktemp -d)
cleanup() { rm -rf "§temp_dir"; }
trap cleanup EXIT
verified_package="§temp_dir/update-package"
cp "§package_file" "§verified_package"
actual_sha256=§(sha256sum "§verified_package" | awk '{print §1}')
if [ "§actual_sha256" != "§expected_sha256" ]; then
  printf '%s\n' 'The update package changed after verification.' > "§error_file"
  exit 1
fi
: > "§ready_file"
while kill -0 "§pid" >/dev/null 2>&1; do
  if [ -f "§cancel_file" ]; then exit 3; fi
  sleep 1
done
if [ -f "§cancel_file" ]; then exit 3; fi
case "§package_type" in
  deb) dpkg -i "§verified_package" ;;
  rpm) rpm -Uvh --replacepkgs "§verified_package" ;;
  arch-bundle)
    tar -xzf "§verified_package" -C "§temp_dir"
    /bin/sh "§temp_dir/vpn-control-arch-update/install.sh" "§temp_dir/vpn-control-arch-update"
    ;;
  *) exit 2 ;;
esac
: > "§installed_file"
""".replace('§', '$')

    internal fun windowsHelperCommand(
        helper: Path, packageFile: Path, launcher: String, currentPid: Long,
        readyFile: Path, errorFile: Path, cancelFile: Path,
    ): List<String> = listOf(
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper.toString(),
        packageFile.toString(), launcher, currentPid.toString(), readyFile.toString(), errorFile.toString(),
        cancelFile.toString(), java.util.Base64.getEncoder().encodeToString(workspaceDirectory.toString().toByteArray(Charsets.UTF_8)),
    )

    internal fun windowsHelper(): String = """param(
  [string]§PackageFile, [string]§Launcher, [long]§ParentProcessId,
  [string]§ReadyFile, [string]§ErrorFile, [string]§CancelFile,
  [string]§StateDirectoryBase64, [switch]§Elevated
)
§ErrorActionPreference = 'Stop'
function Quote-NativeArgument([string]§ArgumentText) {
  §escaped = [regex]::Replace(§ArgumentText, '(\\*)"', '§1§1\"')
  §escaped = [regex]::Replace(§escaped, '(\\+)§', '§1§1')
  return '"' + §escaped + '"'
}
try {
  if (-not §Elevated) {
    §helperArguments = @('-NoProfile','-ExecutionPolicy','Bypass','-File',§PSCommandPath,§PackageFile,§Launcher,§ParentProcessId,§ReadyFile,§ErrorFile,§CancelFile,§StateDirectoryBase64,'-Elevated')
    §helperCommandLine = (§helperArguments | ForEach-Object { Quote-NativeArgument ([string]§_) }) -join ' '
    §process = Start-Process powershell.exe -Verb RunAs -ArgumentList §helperCommandLine -Wait -PassThru
    if (§process.ExitCode -ne 0) { throw "Installer failed with exit code §(§process.ExitCode)" }
    §stateDirectory = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(§StateDirectoryBase64))
    §quotedStateDirectory = Quote-NativeArgument §stateDirectory
    Start-Process -FilePath §Launcher -ArgumentList @('--state-dir', §quotedStateDirectory)
    exit 0
  }
  New-Item -ItemType File -Force -Path §ReadyFile | Out-Null
  while (Get-Process -Id §ParentProcessId -ErrorAction SilentlyContinue) {
    if (Test-Path §CancelFile) { exit 3 }
    Start-Sleep -Milliseconds 500
  }
  if (Test-Path §CancelFile) { exit 3 }
  §installer = Start-Process msiexec.exe -ArgumentList @('/i',(Quote-NativeArgument §PackageFile),'/passive','/norestart') -Wait -PassThru
  exit §installer.ExitCode
} catch {
  §_.Exception.Message | Out-File -FilePath §ErrorFile -Encoding utf8
  exit 1
}
""".replace('§', '$')

    internal fun macHelper(): String = """#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
dmg=§1
launcher=§2
pid=§3
ready_file=§4
error_file=§5
cancel_file=§6
state_dir=§7
expected_sha256=§8
worker_mode=§{9:-}
app_path=§(printf '%s' "§launcher" | sed 's#\([.]app\)/Contents/MacOS/.*#\1#')
if [ "§app_path" = "§launcher" ]; then
  printf '%s\n' 'Could not locate the installed macOS app bundle.' > "§error_file"
  exit 1
fi
# Authorization belongs to the live application handoff. The worker alone writes
# ready, after the OS has granted required privileges. Relaunch stays unprivileged.
if [ -z "§worker_mode" ]; then
  worker_source=§(cat "§0")
  if [ -w "§(dirname "§app_path")" ]; then
    if ! /bin/sh -c "§worker_source" vpn-control-update-worker "§dmg" "§launcher" "§pid" "§ready_file" "§error_file" "§cancel_file" "§state_dir" "§expected_sha256" --local-worker; then
      if [ ! -f "§cancel_file" ]; then printf '%s\n' 'The update worker failed.' > "§error_file"; fi
      exit 1
    fi
  else
    if ! /usr/bin/osascript \
      -e 'on run argv' \
      -e 'set commandText to "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh"' \
      -e 'repeat with argumentText in argv' \
      -e 'set commandText to commandText & " " & quoted form of (contents of argumentText)' \
      -e 'end repeat' \
      -e 'do shell script commandText with administrator privileges' \
      -e 'end run' \
      -- -c "§worker_source" vpn-control-update-worker "§dmg" "§launcher" "§pid" "§ready_file" "§error_file" "§cancel_file" "§state_dir" "§expected_sha256" --authorized-worker; then
      if [ ! -f "§cancel_file" ]; then printf '%s\n' 'Installer authorization failed or the update worker failed.' > "§error_file"; fi
      exit 1
    fi
  fi
  if [ -f "§cancel_file" ] || [ -f "§error_file" ]; then exit 1; fi
  open "§app_path" --args --state-dir "§state_dir"
  exit 0
fi
case "§worker_mode" in
  --authorized-worker)
    if [ "§(id -u)" -ne 0 ]; then printf '%s\n' 'Installer authorization is required.' > "§error_file"; exit 1; fi
    ;;
  --local-worker)
    if [ ! -w "§(dirname "§app_path")" ]; then printf '%s\n' 'Installer authorization is required.' > "§error_file"; exit 1; fi
    ;;
  *) printf '%s\n' 'Invalid update worker mode.' > "§error_file"; exit 1 ;;
esac
if [ -f "§cancel_file" ]; then exit 3; fi
case "§expected_sha256" in *[!0-9a-f]*|'') printf '%s\n' 'Invalid update digest.' > "§error_file"; exit 1 ;; esac
if [ "§{#expected_sha256}" -ne 64 ]; then printf '%s\n' 'Invalid update digest.' > "§error_file"; exit 1; fi
umask 077
payload_dir=§(mktemp -d)
mount_dir=''
cleanup() {
  if [ -n "§mount_dir" ]; then hdiutil detach "§mount_dir" -quiet >/dev/null 2>&1 || true; rm -rf "§mount_dir"; fi
  rm -rf "§payload_dir"
}
trap cleanup EXIT
verified_dmg="§payload_dir/update.dmg"
cp "§dmg" "§verified_dmg"
actual_sha256=§(shasum -a 256 "§verified_dmg" | awk '{print §1}')
if [ "§actual_sha256" != "§expected_sha256" ]; then
  printf '%s\n' 'The update package changed after verification.' > "§error_file"
  exit 1
fi
: > "§ready_file"
while kill -0 "§pid" >/dev/null 2>&1; do
  if [ -f "§cancel_file" ]; then exit 3; fi
  sleep 1
done
if [ -f "§cancel_file" ]; then exit 3; fi
mount_dir=§(mktemp -d)
hdiutil attach "§verified_dmg" -nobrowse -readonly -mountpoint "§mount_dir" -quiet
source_app=§(find "§mount_dir" -maxdepth 2 -type d -name '*.app' | head -n 1)
if [ -z "§source_app" ]; then printf '%s\n' 'The update DMG contains no app bundle.' > "§error_file"; exit 1; fi
rm -rf "§app_path.previous"
mv "§app_path" "§app_path.previous"
if ! ditto "§source_app" "§app_path"; then
  rm -rf "§app_path"
  mv "§app_path.previous" "§app_path"
  exit 1
fi
rm -rf "§app_path.previous"
""".replace('§', '$')
}
