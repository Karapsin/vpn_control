package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import kotlin.test.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest

class DesktopFrontendSubscriptionDraftTest {
    @Test
    fun actualOwnerGuardsStableSubscriptionEditsAndRetainsSavedIdentityOnRetry() = runTest {
        val directory = Files.createTempDirectory("vpn-control-subscription-editor")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            suspend fun open(id: String?) = DesktopSubscriptionDraft.from(owner.submit(ControlRequest(
                java.util.UUID.randomUUID().toString(), if (id == null) ControlCommand(ControlOperationId.SETTINGS_SHOW)
                else ControlCommand(ControlOperationId.SUBSCRIPTIONS_SHOW, mapOf("id" to ControlValue.Text(id))),
                controllerId = owner.controllerId)), id)
            val add = open(null).copy(source = "https://fixture.example/source", name = "First")
            assertTrue(service.state.subscriptions.isEmpty())
            val added = owner.submit(add.request())
            assertEquals(ControlCode.OK, added.code)
            val id = (added.data.getValue("id") as ControlValue.Text).value
            assertEquals(service.state.subscriptions.single().id, id)
            assertEquals(added, owner.submit(add.copy(failure = ControlCode.TIMEOUT).request()))
            assertEquals(1, service.state.subscriptions.size)
            val first = open(id).editName("First edit")
            val second = open(id).editName("Second edit")
            assertEquals("First", service.state.subscriptions.single().customName)
            val changed = owner.submit(first.request())
            assertEquals(ControlCode.OK, changed.code)
            assertEquals(ControlValue.Text(id), changed.data["id"])
            assertEquals(ControlCode.CONFLICT, owner.submit(second.request()).code)
            assertEquals("Second edit", second.name)
            assertEquals("First edit", service.state.subscriptions.single().customName)
            assertEquals(changed, owner.submit(first.request()))
            assertEquals(changed.configurationRevision, service.configurationRevision)
            assertEquals(ControlCode.CONFLICT, owner.submit(open(id).copy(controllerId = "previous-owner").request()).code)
            assertFalse(service.state.showAddSubscriptionEditor)
            assertFalse(service.state.showProfileHistoryRenameDialog)
            assertEquals("", service.state.profileTitleDraft)
            assertEquals(setOf("id"), changed.data.keys)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun stableIdExplicitReadCreatesIsolatedGuardedRetryableEditor() {
        val read = ControlResult("owner", "show", ControlCode.OK, 7, data = mapOf(
            "id" to ControlValue.Text("source-id"), "source" to ControlValue.Text("https://private.example/token"),
            "name" to ControlValue.Text("Original")))
        val first = DesktopSubscriptionDraft.from(read, "source-id")
        val second = DesktopSubscriptionDraft.from(read, "source-id").editName("Second")
        val request = first.request()
        assertEquals(ControlOperationId.SUBSCRIPTIONS_UPDATE, request.command.operation)
        assertEquals(ControlValue.Text("source-id"), request.command.arguments["id"])
        assertEquals("owner", request.controllerId)
        assertEquals(7L, request.ifRevision)
        assertEquals(request, first.copy(failure = ControlCode.TIMEOUT).request())
        assertNotEquals(request.requestId, first.editName("Changed").request().requestId)
        assertNotEquals(request.requestId, second.request().requestId)
        assertEquals("Original", first.name)
        assertEquals(80, first.editName("x".repeat(100)).name.length)
        assertFalse(first.toString().contains("private.example"))
        assertFailsWith<IllegalArgumentException> { DesktopSubscriptionDraft.from(read, "different-id") }
    }

    @Test
    fun addNeverBorrowsAnotherFrontendOrReadPayloadDraft() {
        val read = ControlResult("owner", "show", ControlCode.OK, 8,
            data = mapOf("source" to ControlValue.Text("ignored"), "name" to ControlValue.Text("ignored")))
        val draft = DesktopSubscriptionDraft.from(read, null)
        assertEquals("", draft.source)
        assertEquals("", draft.name)
        assertEquals(ControlOperationId.SUBSCRIPTIONS_ADD, draft.request().command.operation)
        assertFalse("id" in draft.request().command.arguments)
    }
}
