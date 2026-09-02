package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdateLogic
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import java.net.HttpURLConnection
import java.net.URL
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
) {
    private var preparedPackage: Path? = null
    private var installerCancelFile: Path? = null

    suspend fun checkAndDownload() {
        preparedPackage = null
        updateAppState {
            AppUpdateState(
                showDialog = true,
                phase = AppUpdatePhase.CHECKING,
                currentVersion = buildInfo.displayVersion,
            )
        }
        try {
            val manifest = AppUpdateLogic.parseManifest(fetchText(manifestUrl), trustUrl)
            if (!AppUpdateLogic.isUpdateAvailable(buildInfo.buildNumber, manifest)) {
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.UP_TO_DATE,
                        releaseNotesUrl = manifest.releaseNotesUrl,
                    )
                }
                return
            }
            val selection = currentPlatformSelection()
            val asset = AppUpdateLogic.selectAsset(
                manifest = manifest,
                platform = selection.platform,
                architectureAliases = setOf(osArchitecture),
                preferredPackageTypes = selection.packageTypes,
            )
            if (asset == null) {
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.UNSUPPORTED,
                        releaseNotesUrl = manifest.releaseNotesUrl,
                    )
                }
                return
            }
            updateAppState {
                it.copy(
                    phase = AppUpdatePhase.DOWNLOADING,
                    availableVersion = asset.displayVersion,
                    releaseNotesUrl = manifest.releaseNotesUrl,
                    totalBytes = asset.sizeBytes,
                )
            }
            val packageFile = download(asset)
            updateAppState { it.copy(phase = AppUpdatePhase.VERIFYING) }
            require(packageFile.sha256() == asset.sha256) { "Downloaded update checksum does not match" }
            preparedPackage = packageFile
            updateAppState {
                it.copy(
                    phase = AppUpdatePhase.READY,
                    downloadedBytes = asset.sizeBytes,
                    totalBytes = asset.sizeBytes,
                    preparedAsset = asset,
                )
            }
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

    fun dismiss() {
        cleanupPartialDownloads()
        updateAppState { AppUpdateState(currentVersion = buildInfo.displayVersion) }
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
        val packageFile = preparedPackage?.takeIf(Files::isRegularFile)
            ?: return@withContext Result.failure(IllegalStateException("No verified update is ready"))
        val asset = stateProvider().appUpdate.preparedAsset
            ?: return@withContext Result.failure(IllegalStateException("Update package metadata is unavailable"))
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
            UpdatePlatform.MACOS -> launchMacHelper(packageFile, launcher, currentPid, readyFile, errorFile, cancelFile)
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

    private suspend fun fetchText(url: String): String = withContext(Dispatchers.IO) {
        openConnection(url, "application/json").useConnection { connection ->
            connection.inputStream.bufferedReader().use { it.readText() }
        }
    }

    private suspend fun download(asset: UpdateAsset): Path = withContext(Dispatchers.IO) {
        Files.createDirectories(updateDirectory)
        val partial = updateDirectory.resolve("${asset.fileName}.part")
        val completed = updateDirectory.resolve(asset.fileName)
        Files.deleteIfExists(partial)
        Files.deleteIfExists(completed)
        openConnection(asset.downloadUrl, "application/octet-stream").useConnection { connection ->
            var copied = 0L
            connection.inputStream.use { input ->
                Files.newOutputStream(partial, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        currentCoroutineContext().ensureActive()
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        copied += read
                        updateAppState { it.copy(downloadedBytes = copied, totalBytes = asset.sizeBytes) }
                    }
                }
            }
        }
        require(Files.size(partial) == asset.sizeBytes) { "Downloaded update size does not match the release manifest" }
        Files.move(partial, completed, StandardCopyOption.REPLACE_EXISTING)
        completed
    }

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
        val watcher = listOf(
            "/bin/sh", "-c", linuxRelaunchWatcher(), "vpn-control-update-watcher",
            currentPid.toString(), launcher, installedFile.toString(), errorFile.toString(), cancelFile.toString(),
        )
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
            ProcessBuilder(
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helper.toString(),
                packageFile.toString(), launcher, currentPid.toString(), readyFile.toString(), errorFile.toString(),
                cancelFile.toString(),
            ).start()
            true
        }.getOrDefault(false)
    }

    private fun launchMacHelper(
        packageFile: Path,
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
                readyFile.toString(), errorFile.toString(), cancelFile.toString(),
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

    private fun openConnection(url: String, accept: String): HttpURLConnection {
        val connection = URL(url).openConnection() as HttpURLConnection
        connection.instanceFollowRedirects = true
        connection.connectTimeout = 20_000
        connection.readTimeout = 300_000
        connection.setRequestProperty("Accept", accept)
        connection.setRequestProperty("User-Agent", "VPNControlDesktop/${buildInfo.displayVersion}")
        val code = connection.responseCode
        if (code !in 200..299) {
            connection.disconnect()
            error("Update request failed: HTTP $code")
        }
        return connection
    }

    private inline fun <T> HttpURLConnection.useConnection(block: (HttpURLConnection) -> T): T {
        return try {
            block(this)
        } finally {
            disconnect()
        }
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

    private fun linuxRelaunchWatcher(): String = """
set -eu
pid=§1
launcher=§2
installed_file=§3
error_file=§4
cancel_file=§5
while kill -0 "§pid" >/dev/null 2>&1; do
  if [ -f "§cancel_file" ] || [ -f "§error_file" ]; then exit 0; fi
  sleep 1
done
attempt=0
while [ ! -f "§installed_file" ]; do
  if [ -f "§cancel_file" ]; then exit 0; fi
  if [ -f "§error_file" ]; then nohup "§launcher" >/dev/null 2>&1 & exit 0; fi
  attempt=§((attempt + 1))
  if [ "§attempt" -ge 300 ]; then nohup "§launcher" >/dev/null 2>&1 & exit 0; fi
  sleep 1
done
nohup "§launcher" >/dev/null 2>&1 &
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

    private fun windowsHelper(): String = """param(
  [string]§PackageFile, [string]§Launcher, [long]§Pid,
  [string]§ReadyFile, [string]§ErrorFile, [string]§CancelFile, [switch]§Elevated
)
§ErrorActionPreference = 'Stop'
try {
  if (-not §Elevated) {
    §args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',§PSCommandPath,§PackageFile,§Launcher,§Pid,§ReadyFile,§ErrorFile,§CancelFile,'-Elevated')
    §process = Start-Process powershell.exe -Verb RunAs -ArgumentList §args -Wait -PassThru
    if (§process.ExitCode -ne 0) { throw "Installer failed with exit code §(§process.ExitCode)" }
    Start-Process -FilePath §Launcher
    exit 0
  }
  New-Item -ItemType File -Force -Path §ReadyFile | Out-Null
  while (Get-Process -Id §Pid -ErrorAction SilentlyContinue) {
    if (Test-Path §CancelFile) { exit 3 }
    Start-Sleep -Milliseconds 500
  }
  if (Test-Path §CancelFile) { exit 3 }
  §installer = Start-Process msiexec.exe -ArgumentList @('/i',§PackageFile,'/passive','/norestart') -Wait -PassThru
  exit §installer.ExitCode
} catch {
  §_.Exception.Message | Out-File -FilePath §ErrorFile -Encoding utf8
  exit 1
}
""".replace('§', '$')

    private fun macHelper(): String = """#!/bin/sh
set -eu
dmg=§1
launcher=§2
pid=§3
ready_file=§4
error_file=§5
cancel_file=§6
app_path=§(printf '%s' "§launcher" | sed 's#\(.app\)/Contents/MacOS/.*#\1#')
if [ "§app_path" = "§launcher" ]; then
  printf '%s\n' 'Could not locate the installed macOS app bundle.' > "§error_file"
  exit 1
fi
: > "§ready_file"
while kill -0 "§pid" >/dev/null 2>&1; do
  if [ -f "§cancel_file" ]; then exit 3; fi
  sleep 1
done
if [ -f "§cancel_file" ]; then exit 3; fi
mount_dir=§(mktemp -d)
cleanup() { hdiutil detach "§mount_dir" -quiet >/dev/null 2>&1 || true; rm -rf "§mount_dir"; }
trap cleanup EXIT
hdiutil attach "§dmg" -nobrowse -readonly -mountpoint "§mount_dir" -quiet
source_app=§(find "§mount_dir" -maxdepth 2 -type d -name '*.app' | head -n 1)
if [ -z "§source_app" ]; then printf '%s\n' 'The update DMG contains no app bundle.' > "§error_file"; exit 1; fi
if [ -w "§(dirname "§app_path")" ]; then
  rm -rf "§app_path.previous"
  mv "§app_path" "§app_path.previous"
  if ! ditto "§source_app" "§app_path"; then mv "§app_path.previous" "§app_path"; exit 1; fi
  rm -rf "§app_path.previous"
else
  command_text="rm -rf '§app_path.previous'; mv '§app_path' '§app_path.previous'; ditto '§source_app' '§app_path' && rm -rf '§app_path.previous'"
  osascript -e "do shell script quoted form of \"§command_text\" with administrator privileges"
fi
open "§app_path"
""".replace('§', '$')
}
