package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopFrontendSshKeyImportTest {
    private val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-PRIVATE-INPUT\n-----END OPENSSH PRIVATE KEY-----\n"

    @Test
    fun retriesRecoverCommitAndStalePickerActionsNeverWriteCredentials() = runTest {
        val directory = Files.createTempDirectory("vpn-control-key-picker")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        val path = directory.resolve("credentials/home-ssh-private-key")
        try {
            val action = DesktopSshKeyImportAction(owner.controllerId, service.configurationRevision, key)
            assertEquals(ControlCode.CONFLICT, submitFrontendSshKeyImport(action.copy(controllerId = "old-owner"), owner,
                service::importControlSshKey).code)
            assertFalse(Files.exists(path))
            service.applyControlSettings(mapOf("language" to ControlValue.Text("en"))).getOrThrow()
            assertEquals(ControlCode.CONFLICT, submitFrontendSshKeyImport(action, owner, service::importControlSshKey).code)
            assertFalse(Files.exists(path))
            val reopened = DesktopSshKeyImportAction(owner.controllerId, service.configurationRevision, key)
            val committed = submitFrontendSshKeyImport(reopened, owner, service::importControlSshKey)
            assertEquals(ControlCode.OK, committed.code)
            assertEquals(committed, submitFrontendSshKeyImport(reopened, owner, service::importControlSshKey))
            assertEquals(committed.configurationRevision, service.configurationRevision)
            assertEquals(1L, service.state.homeSshRouteSettings.credentialVersion)
            assertNotEquals(reopened.request().requestId, reopened.copy(content = key + "changed").request().requestId)
            assertNotEquals(reopened.request().requestId,
                DesktopSshKeyImportAction(owner.controllerId, service.configurationRevision, key).request().requestId)
            assertFalse(reopened.toString().contains("SYNTHETIC"))
            assertFalse(Files.readString(directory.resolve("workspace.json")).contains("SYNTHETIC"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun keyImportReturnsCommitMetadataInsteadOfPollingSnapshot() = runTest {
        val directory = Files.createTempDirectory("vpn-control-key-picker-result")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val action = DesktopSshKeyImportAction(owner.controllerId, 0, key)
            val remote = object : ControlSession by owner {
                override suspend fun submit(request: ControlRequest) = ControlResult(owner.controllerId,
                    request.requestId, ControlCode.OK, 7, restartRequired = true)
            }
            assertFalse(remote.snapshots.value.restartRequired)
            assertTrue(submitFrontendSshKeyImport(action, remote) { _, _ -> error("No local write") }.restartRequired)
            val preview = submitFrontendSshKeyImport(action, null) { _, _ ->
                DesktopControlWriteResponse(DesktopCliResponse.success("Imported"), DesktopControlMetadata(9, true))
            }
            assertEquals(9L, preview.configurationRevision)
            assertTrue(preview.restartRequired)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
