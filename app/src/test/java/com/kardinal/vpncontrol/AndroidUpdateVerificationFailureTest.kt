package com.kardinal.vpncontrol

import org.junit.Assert.*
import org.junit.Test

class AndroidUpdateVerificationFailureTest {
    @Test fun publicVersionAndInternalBuildMustBothMatchVerifiedArchiveMetadata() {
        verifyAndroidUpdatePackageIdentity("com.kardinal.vpncontrol", 16480, "2.1.4",
            "com.kardinal.vpncontrol", 16480, "2.1.4", 16460)
        for (archiveVersion in listOf(null, "2.1.3", "2.1.5", "2.1.4 ")) {
            val error = assertThrows(AndroidUpdateVerificationFailure::class.java) {
                verifyAndroidUpdatePackageIdentity("com.kardinal.vpncontrol", 16480, archiveVersion,
                    "com.kardinal.vpncontrol", 16480, "2.1.4", 16460)
            }
            assertEquals(AndroidUpdateVerificationReason.MANIFEST_VERSION_MISMATCH, error.reason)
        }
    }

    @Test fun packageAndBuildFailuresRemainDistinctAndNoSameVersionReplacementIsAdmitted() {
        data class Case(val packageName: String, val build: Int, val current: Int, val reason: AndroidUpdateVerificationReason)
        for ((archivePackage, build, current, reason) in listOf(
            Case("other.package", 16480, 16460, AndroidUpdateVerificationReason.PACKAGE_ID_MISMATCH),
            Case("com.kardinal.vpncontrol", 16460, 16460, AndroidUpdateVerificationReason.MANIFEST_VERSION_MISMATCH),
            Case("com.kardinal.vpncontrol", 16480, 16480, AndroidUpdateVerificationReason.VERSION_NOT_NEWER),
        )) {
            val error = assertThrows(AndroidUpdateVerificationFailure::class.java) {
                verifyAndroidUpdatePackageIdentity(archivePackage, build.toLong(), "2.1.4",
                    "com.kardinal.vpncontrol", 16480, "2.1.4", current)
            }
            assertEquals(reason, error.reason)
        }
    }
    @Test fun failureReasonsAreAllowlistedAndNeverExposeUnderlyingMetadata() {
        AndroidUpdateVerificationReason.entries.forEach { reason ->
            val error = assertThrows(AndroidUpdateVerificationFailure::class.java) {
                requireAndroidUpdateVerification(false, reason)
            }
            assertEquals(reason.name, error.message)
            assertNull(error.cause)
        }
        val error = assertThrows(AndroidUpdateVerificationFailure::class.java) {
            androidUpdateVerificationRead(AndroidUpdateVerificationReason.ARCHIVE_READ_FAILED) {
                throw java.io.IOException("PRIVATE_PATH_PRIVATE_SIGNER")
            }
        }
        assertEquals("ARCHIVE_READ_FAILED", error.message)
        assertNull(error.cause)
    }

    @Test fun ResourceFailureAndCancellationAreNotRelabeledAsArtifactValidation() {
        val failure = OutOfMemoryError("synthetic")
        val caught = assertThrows(OutOfMemoryError::class.java) {
            androidUpdateVerificationRead(AndroidUpdateVerificationReason.ARCHIVE_READ_FAILED) { throw failure }
        }
        assertSame(failure, caught)
        assertThrows(kotlinx.coroutines.CancellationException::class.java) {
            androidUpdateVerificationRead(AndroidUpdateVerificationReason.ARCHIVE_READ_FAILED) {
                throw kotlinx.coroutines.CancellationException()
            }
        }
    }
}
