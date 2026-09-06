package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopFrontendLocationDraftTest {
    @Test
    fun guardedOpaqueEditorNeverRetargetsAndRetainsOriginalResult() = runTest {
        val directory = Files.createTempDirectory("vpn-control-location-draft")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            suspend fun open(id: String?) = DesktopLocationDraft.from(owner.submit(ControlRequest(
                java.util.UUID.randomUUID().toString(), if (id == null) ControlCommand(ControlOperationId.STATUS)
                else ControlCommand(ControlOperationId.LOCATIONS_SHOW, mapOf("id" to ControlValue.Text(id))),
                controllerId = owner.controllerId)), id)
            val add = open(null).copy(content = "socks://127.0.0.1:1080#2")
            assertEquals(ControlCode.CONFLICT, owner.submit(add.copy(controllerId = "stale-owner").request()).code)
            assertTrue(service.visibleDesktopLocations().isEmpty())
            val added = owner.submit(add.request())
            assertEquals(ControlCode.OK, added.code)
            assertEquals(added, owner.submit(add.request()))
            val firstId = (added.data.getValue("id") as ControlValue.Text).value
            val second = owner.submit(open(null).copy(content = "socks://127.0.0.2:1080#Target").request())
            val secondId = (second.data.getValue("id") as ControlValue.Text).value
            val draft = open(secondId).copy(content = "socks://127.0.0.3:1080#Edited")
            val other = open(secondId).copy(content = "socks://127.0.0.4:1080#Other")
            service.deleteLocation(service.resolveControlLocation(firstId).getOrThrow().index).getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(draft.request()).code)
            assertEquals("Target", service.visibleDesktopLocations().single().name)
            val reopened = open(secondId).copy(content = draft.content)
            val saved = owner.submit(reopened.request())
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(saved, owner.submit(reopened.request()))
            assertEquals("Edited", service.visibleDesktopLocations().single().name)
            assertEquals(ControlCode.CONFLICT, owner.submit(other.request().copy(ifRevision = null)).code)
            val newId = (saved.data.getValue("id") as ControlValue.Text).value
            assertNotEquals(secondId, newId)
            val noop = owner.submit(open(newId).request())
            assertEquals(ControlCode.OK, noop.code)
            assertEquals(saved.configurationRevision, noop.configurationRevision)
            assertEquals(ControlValue.Text(newId), noop.data["id"])
            assertEquals(setOf("id"), saved.data.keys)
            assertFalse(reopened.toString().contains("127.0.0.3"))
            val command = DesktopCliCommand.LocationSave(reopened.content, configurationId = secondId)
            assertEquals(command, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(command)).getOrThrow())
            assertFalse(ControlProtocolCodec.encodeResult(saved).contains("socks://"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun failedLocationPersistenceKeepsOriginalIdentityRevisionAndContent() = runTest {
        val directory = Files.createTempDirectory("vpn-control-location-draft-failure")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            val row = service.saveLocation("socks://127.0.0.1:1080#Original").getOrThrow()
            val id = requireNotNull(service.controlLocationId(row))
            val read = owner.submit(ControlRequest("read", ControlCommand(ControlOperationId.LOCATIONS_SHOW,
                mapOf("id" to ControlValue.Text(id))), controllerId = owner.controllerId))
            val draft = DesktopLocationDraft.from(read, id).copy(content = "socks://127.0.0.2:1080#Changed")
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val failed = owner.submit(draft.request())
            assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code)
            assertEquals(read.configurationRevision, failed.configurationRevision)
            assertEquals(row.rawLink, service.visibleDesktopLocations().single().rawLink)
            assertEquals(id, service.controlLocationId(service.visibleDesktopLocations().single()))
            assertEquals(failed, owner.submit(draft.request()))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
