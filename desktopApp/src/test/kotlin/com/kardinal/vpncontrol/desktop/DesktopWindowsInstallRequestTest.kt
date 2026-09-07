package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlValue
import kotlin.test.*

class DesktopWindowsInstallRequestTest {
    @Test fun ancestryPinsRequestDataReadSoWindowsActuallyEnforcesSharingDenials() {
        val pin = windowsInstallOpenOptions(WindowsInstallNative.INSPECT, false, false)
        assertEquals(1, pin.rights and 1, "Metadata-only handles do not enforce deny-delete sharing")
        assertEquals(1, pin.share)
    }

    @Test fun immutableInputPinsNeverPermitConcurrentWritesOrDeletion() {
        val options = windowsInstallOpenOptions(4, shareDelete = false, create = false)
        assertEquals(0x00120081, options.rights)
        assertEquals(1, options.share)
        assertEquals(3, options.creation)
        assertFails { windowsInstallOpenOptions(4, shareDelete = true, create = false) }
        assertFails { windowsInstallOpenOptions(4, shareDelete = false, create = true) }
        // Existing cancellation readers deliberately remain write-sharing.
        assertEquals(3, windowsInstallOpenOptions(WindowsInstallNative.READ, false, false).share)
    }

    private fun request() = DesktopWindowsInstallRequest(
        jobId = "00000000-0000-0000-0000-000000000001",
        principalSid = "S-1-5-21-10-20-30-1001",
        ownerPid = 123, ownerStartedAtEpochMillis = 456,
        launcher = "C:\\Users\\Test\\VPN Control\\vpn-control.exe",
        packageFile = "C:\\Users\\Test\\update.msi",
        packageSha256 = "a".repeat(64), packageSize = 1234,
        stateDirectory = "C:\\Users\\Test\\VPN workspace",
    )

    @Test fun boundedPrivateRequestRoundTripsWithoutExposingPathsInStringRepresentation() {
        val input = request().copy(launcher = "C:\\Users\\Тест\\VPN Control\\vpn-control.exe")
        assertEquals(input, DesktopWindowsInstallRequest.decode(input.encode()))
        assertFalse(input.toString().contains("Users"))
        assertFalse(input.toString().contains("Тест"))
    }

    @Test fun privateRequestRetainsTheOriginatingUnicodeWorkspaceThroughWorkerDecode() {
        val stateDirectory = ControlValue.Text("D:\\Работа 空間\\VPN ' & $ % workspace")
        val values = ControlProtocolCodec.decodeValues(request().encode().decodeToString()) +
            ("stateDirectory" to stateDirectory)
        val input = DesktopWindowsInstallRequest.decode(ControlProtocolCodec.encodeValues(values).encodeToByteArray())
        assertEquals(stateDirectory, ControlProtocolCodec.decodeValues(input.encode().decodeToString())["stateDirectory"])
        assertFalse(input.toString().contains("workspace"))
    }

    @Test fun rejectsUnknownDuplicateAndOversizedRequestFields() {
        val encoded = request().encode().decodeToString()
        assertFails { DesktopWindowsInstallRequest.decode(encoded.replaceFirst("{", "{\"extra\":1,").encodeToByteArray()) }
        assertFails { DesktopWindowsInstallRequest.decode(encoded.replaceFirst("{", "{\"jobId\":\"x\",").encodeToByteArray()) }
        assertFails { DesktopWindowsInstallRequest.decode(ByteArray(65537)) }
    }

    @Test fun neverAcceptsNetworkPathsAlternateDataStreamsOrRelativeTargets() {
        listOf("\\\\server\\share\\update.msi", "C:\\update.msi:stream", "..\\update.msi", "C:\\a\\..\\update.msi").forEach {
            assertFails { request().copy(packageFile = it) }
            assertFails { request().copy(stateDirectory = it) }
        }
        listOf("C:\\workspace\\", "C:\\workspace\" serve", "C:\\workspace\nserve").forEach {
            assertFails { request().copy(stateDirectory = it) }
        }
        assertFails { request().copy(launcher = "C:\\Windows\\powershell.exe") }
        assertFails { request().copy(principalSid = "S-1-5-21';whoami") }
        assertFails { request().copy(packageSha256 = "x".repeat(64)) }
        assertFails { request().copy(ownerPid = 0) }
    }
}
