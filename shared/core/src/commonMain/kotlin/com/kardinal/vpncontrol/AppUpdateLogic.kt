package com.kardinal.vpncontrol

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

enum class UpdatePlatform(val wireName: String) {
    ANDROID("android"),
    WINDOWS("windows"),
    LINUX("linux"),
    MACOS("macos"),
}

enum class UpdatePackageType(val wireName: String) {
    APK("apk"),
    MSI("msi"),
    DEB("deb"),
    RPM("rpm"),
    ARCH_BUNDLE("arch-bundle"),
    DMG("dmg"),
}

data class UpdateAsset(
    val platform: UpdatePlatform,
    val architecture: String,
    val packageType: UpdatePackageType,
    val displayVersion: String,
    val fileName: String,
    val downloadUrl: String,
    val sha256: String,
    val sizeBytes: Long,
)

data class UpdateManifest(
    val schemaVersion: Int,
    val buildNumber: Int,
    val releaseTag: String,
    val releaseNotesUrl: String,
    val assets: List<UpdateAsset>,
)

enum class AppUpdatePhase {
    IDLE,
    CHECKING,
    DOWNLOADING,
    VERIFYING,
    READY,
    UP_TO_DATE,
    INSTALLING,
    UNSUPPORTED,
    FAILED,
}

data class AppUpdateState(
    val showDialog: Boolean = false,
    val phase: AppUpdatePhase = AppUpdatePhase.IDLE,
    val currentVersion: String = "",
    val availableVersion: String = "",
    val releaseNotesUrl: String = "",
    val downloadedBytes: Long = 0L,
    val totalBytes: Long = 0L,
    val message: String = "",
    val preparedAsset: UpdateAsset? = null,
) {
    val progress: Float?
        get() = totalBytes.takeIf { it > 0L }?.let { total ->
            (downloadedBytes.toDouble() / total.toDouble()).coerceIn(0.0, 1.0).toFloat()
        }
}

object AppUpdateLogic {
    const val SUPPORTED_SCHEMA_VERSION = 1
    const val LATEST_MANIFEST_URL =
        "https://github.com/Karapsin/vpn_control/releases/latest/download/update-manifest.json"

    private val json = Json { ignoreUnknownKeys = true }
    private val sha256Regex = Regex("[0-9a-f]{64}")

    fun parseManifest(
        raw: String,
        trustUrl: (String) -> Boolean = ::isTrustedGithubUrl,
    ): UpdateManifest {
        val root = json.parseToJsonElement(raw).jsonObject
        val schemaVersion = root.requiredInt("schemaVersion")
        require(schemaVersion == SUPPORTED_SCHEMA_VERSION) {
            "Unsupported update manifest schema: $schemaVersion"
        }
        val buildNumber = root.requiredInt("buildNumber")
        require(buildNumber > 0) { "Update build number must be positive" }
        val releaseTag = root.requiredString("releaseTag")
        val releaseNotesUrl = root.requiredString("releaseNotesUrl")
        require(trustUrl(releaseNotesUrl)) { "Untrusted update release-notes URL" }
        val assets = root["assets"]?.jsonArray?.map { element ->
            parseAsset(element.jsonObject, trustUrl)
        }.orEmpty()
        require(assets.isNotEmpty()) { "Update manifest contains no assets" }
        return UpdateManifest(
            schemaVersion = schemaVersion,
            buildNumber = buildNumber,
            releaseTag = releaseTag,
            releaseNotesUrl = releaseNotesUrl,
            assets = assets,
        )
    }

    fun isUpdateAvailable(currentBuildNumber: Int, manifest: UpdateManifest): Boolean {
        return manifest.buildNumber > currentBuildNumber
    }

    fun selectAsset(
        manifest: UpdateManifest,
        platform: UpdatePlatform,
        architectureAliases: Set<String>,
        preferredPackageTypes: List<UpdatePackageType>,
    ): UpdateAsset? {
        val normalizedArchitectures = architectureAliases.map(::normalizeArchitecture).toSet()
        val candidates = manifest.assets.filter { asset ->
            asset.platform == platform && normalizeArchitecture(asset.architecture) in normalizedArchitectures
        }
        return preferredPackageTypes.firstNotNullOfOrNull { packageType ->
            candidates.firstOrNull { it.packageType == packageType }
        }
    }

    fun normalizeArchitecture(raw: String): String = when (raw.trim().lowercase()) {
        "amd64", "x64", "x86-64", "x86_64" -> "x86_64"
        "aarch64", "arm64", "arm64-v8a" -> "arm64"
        else -> raw.trim().lowercase()
    }

    private fun parseAsset(root: JsonObject, trustUrl: (String) -> Boolean): UpdateAsset {
        val platformWireName = root.requiredString("platform")
        val packageTypeWireName = root.requiredString("packageType")
        val sha256 = root.requiredString("sha256").lowercase()
        val downloadUrl = root.requiredString("downloadUrl")
        val sizeBytes = root.requiredLong("sizeBytes")
        require(sha256Regex.matches(sha256)) { "Invalid update asset SHA-256" }
        require(trustUrl(downloadUrl)) { "Untrusted update download URL" }
        require(sizeBytes > 0L) { "Update asset size must be positive" }
        return UpdateAsset(
            platform = requireNotNull(UpdatePlatform.entries.firstOrNull { it.wireName == platformWireName }) {
                "Unknown update platform: $platformWireName"
            },
            architecture = root.requiredString("architecture"),
            packageType = requireNotNull(UpdatePackageType.entries.firstOrNull { it.wireName == packageTypeWireName }) {
                "Unknown update package type: $packageTypeWireName"
            },
            displayVersion = root.requiredString("displayVersion"),
            fileName = root.requiredString("fileName").also { fileName ->
                require('/' !in fileName && '\\' !in fileName && fileName !in setOf(".", "..")) {
                    "Invalid update asset file name"
                }
            },
            downloadUrl = downloadUrl,
            sha256 = sha256,
            sizeBytes = sizeBytes,
        )
    }

    fun isTrustedGithubUrl(raw: String): Boolean {
        return raw.startsWith("https://github.com/Karapsin/vpn_control/", ignoreCase = true)
    }

    private fun JsonObject.requiredString(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull?.trim()?.takeIf(String::isNotEmpty)
            ?: error("Update manifest is missing $key")
    }

    private fun JsonObject.requiredInt(key: String): Int {
        return this[key]?.jsonPrimitive?.intOrNull ?: error("Update manifest is missing $key")
    }

    private fun JsonObject.requiredLong(key: String): Long {
        return this[key]?.jsonPrimitive?.longOrNull ?: error("Update manifest is missing $key")
    }
}
