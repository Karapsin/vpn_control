package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopGuardedSubscriptionActionsTest {
    @Test
    fun deletingPendingSubscriptionPreservesActiveAndConflictRestoresRuntimeWithoutLosingNewSettings() = runTest {
        val directory = Files.createTempDirectory("vpn-control-subscription-runtime")
        val active = SubscriptionSource("active", "https://example.test/active", "Active",
            cachedLocations = listOf("socks://127.0.0.1:1080#Active"))
        val pending = SubscriptionSource("pending", "https://example.test/pending", "Pending",
            cachedLocations = listOf("socks://127.0.0.2:1080#Pending"))
        val rows = active.cachedLocations.toDesktopLocationRecords(0).map { it.copy(sourceUrl = active.url) } +
            pending.cachedLocations.toDesktopLocationRecords(1).map { it.copy(sourceUrl = pending.url) }
        val runtime = SubscriptionActionRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), DesktopWorkspace(
            PersistedState(subscriptions = listOf(active, pending), activeSubscriptionId = active.id,
                profileUrl = active.url, profileSourceMode = ProfileSourceMode.SUBSCRIPTION, appMode = AppMode.PROXY_ONLY), rows),
            runtimeController = runtime, controlPlatform = ControlPlatform.LINUX)
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.applyLocationSelection(service.visibleDesktopLocations().single().index).getOrThrow()
            assertTrue(owner.session.execute(DesktopCliCommand.On).success)
            fun request(id: String, operation: ControlOperationId) = desktopGuiSourceAction("frontend", owner.controllerId,
                service.configurationRevision, ControlCommand(operation, if (operation == ControlOperationId.SOURCE_SET)
                    mapOf("source" to ControlValue.Text("subscription"), "subscription-id" to ControlValue.Text(id))
                else mapOf("id" to ControlValue.Text(id))))
            assertEquals(ControlCode.OK, owner.submit(request(pending.id, ControlOperationId.SOURCE_SET)).code)
            service.applyLocationSelection(service.visibleDesktopLocations().single().index).getOrThrow()
            val deletePending = request(pending.id, ControlOperationId.SUBSCRIPTIONS_DELETE)
            assertEquals(ControlCode.OK, owner.submit(deletePending).code)
            assertEquals(0, runtime.stops)
            assertEquals(active.url, service.activeDesktopLocation()?.sourceUrl)
            val deleteActive = request(active.id, ControlOperationId.SUBSCRIPTIONS_DELETE)
            runtime.onStop = { service.setAppLanguage(AppLanguage.ENGLISH); service.setSubscriptionHwid("new-value") }
            val conflicted = owner.submit(deleteActive)
            assertEquals(ControlCode.CONFLICT, conflicted.code)
            assertEquals(AppLanguage.ENGLISH, service.state.appLanguage)
            assertEquals("new-value", service.state.subscriptionHwid)
            assertEquals(active.id, service.state.subscriptions.single().id)
            assertTrue(service.state.isVpnRunning)
            assertEquals(runtime.started.first(), runtime.started.last())
            assertEquals(active.url, service.activeDesktopLocation()?.sourceUrl)
            assertEquals(conflicted, owner.submit(deleteActive))
            assertEquals(1, runtime.stops)
            runtime.onStop = {}
            val removed = owner.submit(request(active.id, ControlOperationId.SUBSCRIPTIONS_DELETE))
            assertEquals(ControlCode.OK, removed.code)
            assertEquals(service.configurationRevision, removed.configurationRevision)
            assertFalse(service.state.isVpnRunning)
            assertTrue(service.state.subscriptions.isEmpty())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun guardedSourceAndDeletionRejectStaleStateAndRetainRetryResult() = runTest {
        val directory = Files.createTempDirectory("vpn-control-guarded-source")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val id = service.saveControlSubscription("https://example.test/a", "First", null).getOrThrow()
            val revision = service.configurationRevision
            fun source(name: String, rev: Long = revision) = ControlRequest(name,
                ControlCommand(ControlOperationId.SOURCE_SET, mapOf("source" to ControlValue.Text("subscription"),
                    "subscription-id" to ControlValue.Text(id))), controllerId = owner.controllerId, ifRevision = rev)
            assertEquals(ControlCode.CONFLICT, owner.submit(source("wrong-owner").copy(controllerId = "old")).code)
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(source("stale")).code)
            val select = source("select", service.configurationRevision)
            val selected = owner.submit(select)
            assertEquals(ControlCode.OK, selected.code)
            assertEquals(ControlValue.Text(id), selected.data["id"])
            assertEquals(selected, owner.submit(select))
            val noop = owner.submit(select.copy(requestId = "noop", ifRevision = selected.configurationRevision))
            assertEquals(ControlCode.OK, noop.code)
            assertEquals(selected.configurationRevision, noop.configurationRevision)
            val delete = ControlRequest("delete", ControlCommand(ControlOperationId.SUBSCRIPTIONS_DELETE,
                mapOf("id" to ControlValue.Text(id))), controllerId = owner.controllerId, ifRevision = service.configurationRevision)
            val deleted = owner.submit(delete)
            assertEquals(ControlCode.OK, deleted.code)
            assertEquals(ControlValue.Text(id), deleted.data["id"])
            assertEquals(deleted, owner.submit(delete))
            assertTrue(service.state.subscriptions.isEmpty())
            assertEquals(ControlCode.NOT_FOUND, owner.submit(source("gone", service.configurationRevision)).code)
            service.saveControlSubscription("https://example.test/another", "Another", null).getOrThrow()
            service.saveControlSubscription("https://example.test/third", "Third", null).getOrThrow()
            val all = desktopGuiSourceAction("frontend", owner.controllerId, service.configurationRevision,
                ControlCommand(ControlOperationId.SOURCE_SET, mapOf("source" to ControlValue.Text("all"))))
            assertEquals(ControlCode.OK, owner.submit(all).code)
            assertEquals(ALL_SUBSCRIPTIONS_ID, service.state.activeSubscriptionId)
            val mode = desktopGuiSourceAction("frontend", owner.controllerId, service.configurationRevision,
                ControlCommand(ControlOperationId.SOURCE_SET, mapOf("mode" to ControlValue.Text("current-locations"))))
            assertEquals(mode, desktopGuiSourceAction("frontend", owner.controllerId, service.configurationRevision, mode.command))
            assertEquals(ControlCode.OK, owner.submit(mode).code)
            assertEquals(ProfileSourceMode.CURRENT_LOCATIONS, service.state.profileSourceMode)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun failedPersistenceDoesNotDeleteOrSelectAndRetriesDoNotClaimSuccess() = runTest {
        val directory = Files.createTempDirectory("vpn-control-subscription-persistence")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val id = service.saveControlSubscription("https://example.test/private", "Name", null).getOrThrow()
            val revision = service.configurationRevision
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            for (command in listOf(ControlCommand(ControlOperationId.SOURCE_SET,
                mapOf("source" to ControlValue.Text("current-locations"))),
                ControlCommand(ControlOperationId.SUBSCRIPTIONS_DELETE, mapOf("id" to ControlValue.Text(id))))) {
                val request = desktopGuiSourceAction("frontend", owner.controllerId, revision, command)
                val result = owner.submit(request)
                assertEquals(ControlCode.PERSISTENCE_FAILED, result.code)
                assertEquals(revision, result.configurationRevision)
                assertTrue(result.data.isEmpty())
                assertEquals(result, owner.submit(request))
                assertEquals(id, service.state.subscriptions.single().id)
                assertEquals(ProfileSourceMode.SUBSCRIPTION, service.state.profileSourceMode)
            }
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}

private class SubscriptionActionRuntime : DesktopRuntimeController {
    var onStop: () -> Unit = {}
    var stops = 0
    val started = mutableListOf<ProxyProfile>()
    private var mode: AppMode? = null
    override suspend fun start(profile: ProxyProfile, routingRules: RoutingRules, dnsSettings: DnsSettings,
        appMode: AppMode, activeVerificationPort: Int?, homeSshRouteSettings: HomeSshRouteSettings): Result<DesktopRuntimeSession> {
        started += profile; mode = appMode
        return Result.success(DesktopRuntimeSession(appMode, 1080, null, null, "{}", java.nio.file.Path.of("synthetic.log"), 1L))
    }
    override suspend fun stop(): Result<Unit> { stops++; onStop(); mode = null; return Result.success(Unit) }
    override fun isRunning() = mode != null
    override fun currentMode() = mode
    override fun currentPort(): Int? = if (mode == null) null else 1080
}
