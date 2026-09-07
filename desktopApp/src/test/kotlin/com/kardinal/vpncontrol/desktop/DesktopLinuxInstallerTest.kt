package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.PosixFilePermissions
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.channels.Channels
import kotlin.test.*

class DesktopLinuxInstallerTest {
    @Test fun unavailableAuthorizationUsesCanonicalInteractionRequiredCode() {
        for ((uid, available) in listOf(0L to true, 1000L to false)) {
            val failure = assertFails { requireLinuxInstallAuthorization(uid, available) }
            assertEquals(ControlCode.INTERACTION_REQUIRED.name, failure.message)
        }
        requireLinuxInstallAuthorization(1000, true)
    }
    @Test fun privatePipeFramesCountUtf8BytesAndBoundPackageBytes() {
        val request = "東京\n".encodeToByteArray()
        val payload = byteArrayOf(0, 10, 13, 127, -1)
        val output = ByteArrayOutputStream()
        linuxInstallWritePayload(output, request, Channels.newChannel(ByteArrayInputStream(payload)), payload.size.toLong())
        assertContentEquals("000007\n".encodeToByteArray() + request + payload, output.toByteArray())
        for (count in listOf(payload.size - 1, payload.size + 1)) {
            assertFails { linuxInstallWritePayload(ByteArrayOutputStream(), request,
                Channels.newChannel(ByteArrayInputStream(payload)), count.toLong()) }
        }
    }
    @Test fun nativeProcessStatHandlesSpacesAndClosingParenthesesInCommandName() {
        val fields = listOf("S") + List(18) { "0" } + "1234567" + List(4) { "0" }
        assertEquals(1234567L, parseLinuxInstallProcessStart("123 (vpn ) spaced) " + fields.joinToString(" ")))
        assertFails { parseLinuxInstallProcessStart(fields.joinToString(" ")) }
    }

    @Test fun linuxInitialReceiptAbsenceIsRetriedBeforeReadiness() = runBlocking {
        val job = "00000000-0000-0000-0000-000000000001"
        var reads = 0
        val prepared = DesktopReceiptPreparedInstall(job, {
            if (++reads == 1) throw NoSuchFileException("status.json")
            DesktopInstallJobReceipt(job, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK)
        }, {}, {}, {})
        assertTrue(prepared.awaitAuthorization().isSuccess)
        assertEquals(2, reads)
        prepared.close()
    }

    @Test fun privateCommandRecordIsCompleteAndNeverOverwritesPriorCommit() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val directory = Files.createTempDirectory("vpn-linux-install-record-")
        try {
            val target = directory.resolve("commit")
            val value = "00000000-0000-0000-0000-000000000001\n".encodeToByteArray()
            linuxInstallPublishRecord(target, value)
            assertContentEquals(value, Files.readAllBytes(target))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target))
            assertEquals(1, (Files.getAttribute(target, "unix:nlink") as Number).toInt())
            assertFails { linuxInstallPublishRecord(target, "replacement".encodeToByteArray()) }
            assertContentEquals(value, Files.readAllBytes(target))
            assertEquals(listOf(target), Files.list(directory).use { it.toList() })
        } finally {
            Files.deleteIfExists(directory.resolve("commit"))
            Files.delete(directory)
        }
    }
}
