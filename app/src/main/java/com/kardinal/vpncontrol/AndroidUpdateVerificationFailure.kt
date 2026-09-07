package com.kardinal.vpncontrol

/** Public diagnostics are identifiers, never exception messages, paths or certificate data. */
internal enum class AndroidUpdateVerificationReason {
    ARTIFACT_READ_FAILED,
    CHECKSUM_MISMATCH,
    ARCHIVE_READ_FAILED,
    ARCHIVE_METADATA_UNAVAILABLE,
    PACKAGE_ID_MISMATCH,
    MANIFEST_VERSION_MISMATCH,
    VERSION_NOT_NEWER,
    INSTALLED_METADATA_UNAVAILABLE,
    INSTALLED_SIGNERS_UNAVAILABLE,
    ARCHIVE_SIGNERS_UNAVAILABLE,
    SIGNER_MISMATCH,
}

internal class AndroidUpdateVerificationFailure(val reason: AndroidUpdateVerificationReason) :
    IllegalArgumentException(reason.name)

internal fun requireAndroidUpdateVerification(condition: Boolean, reason: AndroidUpdateVerificationReason) {
    if (!condition) throw AndroidUpdateVerificationFailure(reason)
}

/** Values come from PackageManager's verified APK metadata, before a session is created. */
internal fun verifyAndroidUpdatePackageIdentity(
    archivePackage: String?, archiveBuild: Long, archiveVersion: String?,
    expectedPackage: String, expectedBuild: Int, expectedVersion: String, currentBuild: Int,
) {
    requireAndroidUpdateVerification(archivePackage == expectedPackage, AndroidUpdateVerificationReason.PACKAGE_ID_MISMATCH)
    requireAndroidUpdateVerification(archiveBuild == expectedBuild.toLong() && archiveVersion == expectedVersion,
        AndroidUpdateVerificationReason.MANIFEST_VERSION_MISMATCH)
    requireAndroidUpdateVerification(archiveBuild > currentBuild.toLong(), AndroidUpdateVerificationReason.VERSION_NOT_NEWER)
}

internal inline fun <T> androidUpdateVerificationRead(reason: AndroidUpdateVerificationReason, block: () -> T): T =
    try { block() }
    catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
    catch (_: Exception) { throw AndroidUpdateVerificationFailure(reason) }
