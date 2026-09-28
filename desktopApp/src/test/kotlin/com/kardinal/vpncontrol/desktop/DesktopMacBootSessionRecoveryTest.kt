package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopMacBootSessionRecoveryTest {
    private val job = "d98286a2-1094-4459-8e8d-bc6a2d91a851"
    private val correlation = DesktopInstallCorrelation("previous-owner", "request", "operation")
    private val binding = DesktopInstallCorrelationRecord(correlation, job, "a".repeat(64),
        DesktopInstallReceiptAuthority.MACHINE)

    @Test fun priorBootAndAbsentProtectedReceiptTerminatesOnlyTheExactUnknownJob() {
        val marked = mutableListOf<Pair<DesktopInstallCorrelation, String>>()
        reconcileMacPreauthorizationProcessLoss(
            recovered = listOf(DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN)),
            previousBoot = { it == job },
            markNotStarted = { identity, receipt -> marked += identity to receipt },
        )

        assertEquals(listOf(correlation to job), marked)
    }

    @Test fun userLocalPriorBootTerminatesOnlyWhenItsProtectedReceiptIsAbsent() {
        val userLocal = binding.copy(receiptAuthority = DesktopInstallReceiptAuthority.MACOS_USER_LOCAL)
        val receipt = DesktopInstallJobReceipt(job, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
        val marked = mutableListOf<Pair<DesktopInstallCorrelation, String>>()

        reconcileMacPreauthorizationProcessLoss(
            recovered = listOf(
                DesktopInstallCorrelationRecovery(userLocal, null, ControlCode.OUTCOME_UNKNOWN),
                DesktopInstallCorrelationRecovery(userLocal, receipt, ControlCode.ACCEPTED),
            ),
            previousBoot = { it == job },
            markNotStarted = { identity, receiptId -> marked += identity to receiptId },
        )

        assertEquals(listOf(correlation to job), marked)
    }

    @Test fun userLocalCancellationRechecksOnlyItsBoundReceiptAuthority() {
        fun verify(receipt: DesktopInstallJobReceipt?, expectedSuccess: Boolean) {
            val workspace = Files.createTempDirectory("vpn-mac-user-local-authority")
            try {
                DesktopInstallCorrelationJournal(workspace).record(correlation, job,
                    DesktopInstallReceiptAuthority.MACOS_USER_LOCAL)
                val routed = mutableListOf<DesktopInstallReceiptAuthority>()
                val reopened = DesktopInstallCorrelationJournal(workspace, readBoundReceipt = { record ->
                    routed += record.receiptAuthority
                    receipt ?: throw NoSuchFileException(record.jobId)
                }, readProtectedReceipt = { error("Machine receipt fallback is forbidden") })

                val result = runCatching { reopened.markNotStarted(correlation, job) }

                assertEquals(expectedSuccess, result.isSuccess)
                assertEquals(listOf(DesktopInstallReceiptAuthority.MACOS_USER_LOCAL), routed)
            } finally { workspace.toFile().deleteRecursively() }
        }

        verify(receipt = null, expectedSuccess = true)
        verify(DesktopInstallJobReceipt(job, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK),
            expectedSuccess = false)
    }

    @Test fun currentOrUnrecordedBootAndProtectedReceiptRemainUntouched() {
        val receipt = DesktopInstallJobReceipt(job, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
        val candidates = listOf(
            DesktopInstallCorrelationRecovery(binding, null, ControlCode.OUTCOME_UNKNOWN),
            DesktopInstallCorrelationRecovery(binding.copy(jobId = "00000000-0000-0000-0000-000000000052"),
                null, ControlCode.OUTCOME_UNKNOWN),
            DesktopInstallCorrelationRecovery(binding, receipt, ControlCode.ACCEPTED),
            DesktopInstallCorrelationRecovery(binding, null, ControlCode.CANCELLED, notStarted = true),
        )
        val marked = mutableListOf<String>()

        reconcileMacPreauthorizationProcessLoss(candidates, previousBoot = { false }) { _, receiptId -> marked += receiptId }

        assertEquals(emptyList(), marked)
    }

    @Test fun bootTokenIsExactAndLegacyAbsenceStaysUnknown() {
        val input = privateInput("vpn-mac-boot-token")
        try {
            assertFalse(DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" })
            DesktopMacBootSessionRecord.publish(input, job, "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")
            assertFalse(DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" })
            assertTrue(DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" })
        } finally { input.parent.toFile().deleteRecursively() }
    }

    @Test fun malformedOrInsecureBootTokenCannotTerminalizeAJob() {
        val input = privateInput("vpn-mac-invalid-boot-token")
        val token = input.resolve(DesktopMacBootSessionRecord.FILE_NAME)
        try {
            Files.writeString(token, "VPN_CONTROL_MAC_BOOT_SESSION_V1\n$job\nnot-a-uuid\n")
            Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"))
            assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" } }
            if ("posix" in token.fileSystem.supportedFileAttributeViews()) {
                Files.writeString(token, "VPN_CONTROL_MAC_BOOT_SESSION_V1\n$job\naaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n")
                Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-r--r--"))
                assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" } }
            }
        } finally { input.parent.toFile().deleteRecursively() }
    }

    @Test fun macAclGrantOnBootTokenCannotTerminalizeAJob() {
        org.junit.Assume.assumeTrue("Darwin ACL behavior", Platform.isMac())
        val input = privateInput("vpn-mac-acl-boot-token")
        val token = input.resolve(DesktopMacBootSessionRecord.FILE_NAME)
        try {
            DesktopMacBootSessionRecord.publish(input, job, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            val chmod = ProcessBuilder("/bin/chmod", "+a", "everyone allow write", token.toString()).start()
            assertTrue(chmod.waitFor(10, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(0, chmod.exitValue())
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(token))
            assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(input, job) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" } }
        } finally { input.parent.toFile().deleteRecursively() }
    }

    @Test fun linkedInputCannotSupplyPriorBootProof() {
        org.junit.Assume.assumeTrue("Darwin symbolic links", Platform.isMac())
        val root = Files.createTempDirectory("vpn-mac-linked-boot-token").toRealPath()
        val original = Files.createDirectory(root.resolve("original")).resolve(job)
        Files.createDirectory(original, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            DesktopMacBootSessionRecord.publish(original, job, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            val alias = Files.createSymbolicLink(root.resolve("alias"), original.parent).resolve(job)
            assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(alias, job) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" } }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test fun decodedTokenMustMatchExactJobAndValidBootBeforeRecovery() {
        val launch = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        fun bytes(jobId: String = job, boot: String = launch) =
            "VPN_CONTROL_MAC_BOOT_SESSION_V1\n$jobId\n$boot\n".encodeToByteArray()
        assertFalse(DesktopMacBootSessionRecord.belongsToPreviousBoot(job, null) { error("Legacy absence has no proof") })
        assertFalse(DesktopMacBootSessionRecord.belongsToPreviousBoot(job, bytes()) { launch })
        assertTrue(DesktopMacBootSessionRecord.belongsToPreviousBoot(job, bytes()) { "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" })
        assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(job, bytes(boot = "invalid")) { launch } }
        assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(job, bytes(jobId = "00000000-0000-0000-0000-000000000052")) { launch } }
        assertFails { DesktopMacBootSessionRecord.belongsToPreviousBoot(job, bytes()) { "invalid" } }
    }

    @Test fun descriptorTrustRejectsUnsafeTokenBeforeReadingAndClosesEveryHandle() {
        val input = desktopMacTestPath("/Users/test/Library/Application Support/vpn-control-install-inputs").resolve(job)
        val token = input.resolve(DesktopMacBootSessionRecord.FILE_NAME)
        val bytes = "VPN_CONTROL_MAC_BOOT_SESSION_V1\n$job\naaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n".encodeToByteArray()
        val secure = MacAdmissionInfo(501, 0x8180, 1, bytes.size.toLong(), 1, 1)
        for (metadata in listOf(secure, secure.copy(uid = 502), secure.copy(mode = 0x81a4),
            secure.copy(mode = 0x4180), secure.copy(links = 2), secure.copy(size = 257),
            secure.copy(acl = MacAdmissionAcl.DENY_ONLY))) {
            val native = DesktopMacInstallAdmissionTest.Fake().apply {
                this.metadata[input.toString()] = secure.copy(mode = 0x41c0, size = 0)
                this.metadata[token.toString()] = metadata
            }
            var reads = 0
            val result = runCatching { DesktopMacBootSessionRecord.readPrivateToken(input, job, native) { reads++; bytes } }
            assertEquals(metadata == secure, result.isSuccess)
            assertEquals(if (metadata == secure) 1 else 0, reads)
            assertEquals(native.paths.size, native.closed.size)
        }
    }

    private fun privateInput(prefix: String): java.nio.file.Path {
        org.junit.Assume.assumeTrue("Darwin descriptor-backed token storage", Platform.isMac())
        val input = Files.createTempDirectory(prefix).toRealPath().resolve(job)
        return Files.createDirectory(input, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    }

    @Test fun nativeBootSessionUuidNormalizationRejectsNoncanonicalValues() {
        assertEquals("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            DesktopMacBootSession.canonical("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"))
        for (value in listOf("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa", "{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}",
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa\n")) assertFails { DesktopMacBootSession.canonical(value) }
    }

    @Test fun nativeKernelBootSessionIdentityIsStableAndCanonicalOnMac() {
        org.junit.Assume.assumeTrue("Darwin kern.bootsessionuuid", Platform.isMac())
        val first = DesktopMacBootSession.current()
        assertEquals(first, DesktopMacBootSession.canonical(first))
        assertEquals(first, DesktopMacBootSession.current())
    }
}
