package com.kardinal.vpncontrol

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

internal class AndroidUpdateActionsService(
    private val context: Context,
    private val stateProvider: () -> MainUiState,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
    private val launch: (suspend () -> Unit) -> Job,
    private val client: OkHttpClient = defaultClient(),
    private val currentBuildNumber: Int = BuildConfig.VERSION_CODE,
    private val currentVersion: String = BuildConfig.VERSION_NAME,
    private val manifestUrl: String = AppUpdateLogic.LATEST_MANIFEST_URL,
    private val trustUrl: (String) -> Boolean = AppUpdateLogic::isTrustedGithubUrl,
) {
    private var activeJob: Job? = null
    private var preparedFile: File? = null

    fun checkAndDownload() {
        if (activeJob?.isActive == true) return
        preparedFile = null
        updateState {
            it.copy(
                appUpdate = AppUpdateState(
                    showDialog = true,
                    phase = AppUpdatePhase.CHECKING,
                    currentVersion = currentVersion,
                ),
            )
        }
        lateinit var job: Job
        job = launch {
            try {
                val manifest = AppUpdateLogic.parseManifest(fetchText(manifestUrl), trustUrl)
                if (!AppUpdateLogic.isUpdateAvailable(currentBuildNumber, manifest)) {
                    updateAppState {
                        it.copy(
                            phase = AppUpdatePhase.UP_TO_DATE,
                            releaseNotesUrl = manifest.releaseNotesUrl,
                        )
                    }
                    return@launch
                }
                val asset = AppUpdateLogic.selectAsset(
                    manifest = manifest,
                    platform = UpdatePlatform.ANDROID,
                    architectureAliases = Build.SUPPORTED_ABIS.toSet(),
                    preferredPackageTypes = listOf(UpdatePackageType.APK),
                )
                if (asset == null) {
                    updateAppState {
                        it.copy(
                            phase = AppUpdatePhase.UNSUPPORTED,
                            releaseNotesUrl = manifest.releaseNotesUrl,
                        )
                    }
                    return@launch
                }
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.DOWNLOADING,
                        availableVersion = asset.displayVersion,
                        releaseNotesUrl = manifest.releaseNotesUrl,
                        totalBytes = asset.sizeBytes,
                    )
                }
                val file = downloadAsset(asset)
                updateAppState { it.copy(phase = AppUpdatePhase.VERIFYING) }
                verifyApk(file, asset, manifest.buildNumber)
                preparedFile = file
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
            } catch (error: Throwable) {
                cleanupPartialDownloads()
                updateAppState {
                    it.copy(
                        phase = AppUpdatePhase.FAILED,
                        message = error.message.orEmpty(),
                        preparedAsset = null,
                    )
                }
            } finally {
                if (activeJob === job) activeJob = null
            }
        }
        activeJob = job
    }

    fun dismissOrCancel() {
        activeJob?.cancel(CancellationException("Update canceled by user"))
        activeJob = null
        cleanupPartialDownloads()
        updateState {
            it.copy(
                appUpdate = AppUpdateState(
                    currentVersion = currentVersion,
                ),
            )
        }
    }

    fun buildInstallIntent(): Intent? {
        val file = preparedFile?.takeIf(File::isFile) ?: return null
        if (!context.packageManager.canRequestPackageInstalls()) {
            updateAppState {
                it.copy(message = "Allow VPN Control to install apps, then tap Install update again.")
            }
            return Intent(
                Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                Uri.parse("package:${context.packageName}"),
            )
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        updateAppState { it.copy(phase = AppUpdatePhase.INSTALLING, message = "") }
        return Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
            data = uri
            flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK
            putExtra(Intent.EXTRA_NOT_UNKNOWN_SOURCE, true)
            putExtra(Intent.EXTRA_RETURN_RESULT, false)
        }
    }

    private suspend fun fetchText(url: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .header("Accept", "application/json")
            .header("User-Agent", "VPNControlAndroid/$currentVersion")
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("GitHub update check failed: HTTP ${response.code}")
            response.body?.string()?.takeIf(String::isNotBlank)
                ?: throw IOException("The update source returned an empty manifest")
        }
    }

    private suspend fun downloadAsset(asset: UpdateAsset): File = withContext(Dispatchers.IO) {
        val updateDirectory = File(context.cacheDir, UPDATE_DIRECTORY).apply { mkdirs() }
        val partial = File(updateDirectory, "${asset.fileName}.part")
        val completed = File(updateDirectory, asset.fileName)
        partial.delete()
        completed.delete()
        val request = Request.Builder()
            .url(asset.downloadUrl)
            .header("Accept", "application/octet-stream")
            .header("User-Agent", "VPNControlAndroid/$currentVersion")
            .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Update download failed: HTTP ${response.code}")
            val body = response.body ?: throw IOException("GitHub returned an empty update package")
            val expectedTotal = asset.sizeBytes
            var copied = 0L
            body.byteStream().use { input ->
                partial.outputStream().buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        ensureActive()
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        copied += read
                        updateAppState {
                            it.copy(downloadedBytes = copied, totalBytes = expectedTotal)
                        }
                    }
                }
            }
        }
        require(partial.length() == asset.sizeBytes) {
            "Downloaded update size does not match the release manifest"
        }
        if (!partial.renameTo(completed)) {
            partial.copyTo(completed, overwrite = true)
            partial.delete()
        }
        completed
    }

    private fun verifyApk(file: File, asset: UpdateAsset, manifestBuildNumber: Int) {
        require(file.sha256() == asset.sha256) { "Downloaded update checksum does not match" }
        val archive = packageArchiveInfo(file)
            ?: error("Downloaded file is not a valid APK")
        require(archive.packageName == context.packageName) { "Downloaded APK has the wrong application ID" }
        require(archive.longVersionCode == manifestBuildNumber.toLong()) {
            "Downloaded APK version does not match the release manifest"
        }
        require(archive.longVersionCode > currentBuildNumber.toLong()) { "Downloaded APK is not newer" }
        val installed = installedPackageInfo()
        val installedSigners = installed.signingInfo?.apkContentsSigners.orEmpty().map { it.toByteArray().sha256() }.toSet()
        val archiveSigners = archive.signingInfo?.apkContentsSigners.orEmpty().map { it.toByteArray().sha256() }.toSet()
        require(installedSigners.isNotEmpty() && installedSigners == archiveSigners) {
            "Downloaded APK is not signed with the installed app key"
        }
    }

    @Suppress("DEPRECATION")
    private fun packageArchiveInfo(file: File) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        context.packageManager.getPackageArchiveInfo(
            file.absolutePath,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
        )
    } else {
        context.packageManager.getPackageArchiveInfo(file.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
    }

    @Suppress("DEPRECATION")
    private fun installedPackageInfo() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
        )
    } else {
        context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
    }

    private fun cleanupPartialDownloads() {
        File(context.cacheDir, UPDATE_DIRECTORY).listFiles { file -> file.name.endsWith(".part") }
            ?.forEach(File::delete)
    }

    private fun updateAppState(transform: (AppUpdateState) -> AppUpdateState) {
        updateState { state -> state.copy(appUpdate = transform(state.appUpdate)) }
    }

    private fun File.sha256(): String = inputStream().buffered().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
        digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun ByteArray.sha256(): String {
        return MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { byte -> "%02x".format(byte) }
    }

    companion object {
        private const val UPDATE_DIRECTORY = "updates"

        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(20, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.MINUTES)
            .callTimeout(10, TimeUnit.MINUTES)
            .followRedirects(true)
            .build()
    }
}
