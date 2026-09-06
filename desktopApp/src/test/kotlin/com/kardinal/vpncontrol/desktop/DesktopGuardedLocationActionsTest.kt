package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopGuardedLocationActionsTest {
    @Test
    fun pendingDeletionDoesNotStopActiveAndConflictRollbackPreservesNewConfiguration() = runTest {
        val directory = Files.createTempDirectory("vpn-control-guarded-delete")
        val runtime = GuardedDeleteRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime,
            controlPlatform = ControlPlatform.LINUX)
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.applyControlSettings(mapOf("mode" to ControlValue.Text("proxy-only"))).getOrThrow()
            val active = service.saveLocation("socks://127.0.0.1:1080#Active").getOrThrow()
            val pending = service.saveLocation("socks://127.0.0.2:1080#Pending").getOrThrow()
            fun action(row: DesktopLocationRecord, operation: ControlOperationId) = desktopGuiLocationAction("frontend",
                owner.controllerId, service.configurationRevision, requireNotNull(service.controlLocationId(row)), operation)
            assertEquals(ControlCode.OK, owner.submit(action(active, ControlOperationId.LOCATIONS_SELECT)).code)
            assertTrue(owner.session.execute(DesktopCliCommand.On).success)
            val selectPending = action(pending, ControlOperationId.LOCATIONS_SELECT)
            val selected = owner.submit(selectPending)
            assertEquals(ControlCode.OK, selected.code)
            assertTrue(selected.restartRequired)
            assertEquals(0, runtime.stops)
            assertEquals(selected, owner.submit(selectPending))
            val deletePending = action(pending, ControlOperationId.LOCATIONS_DELETE)
            val removed = owner.submit(deletePending)
            assertEquals(ControlCode.OK, removed.code)
            assertEquals(0, runtime.stops)
            assertEquals(removed, owner.submit(deletePending))
            assertEquals(active.rawLink, service.activeDesktopLocation()?.rawLink)
            val stale = action(active, ControlOperationId.LOCATIONS_DELETE)
            service.saveLocation("socks://127.0.0.3:1080#New").getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(stale).code)
            assertEquals(0, runtime.stops)
            val deleteActive = action(active, ControlOperationId.LOCATIONS_DELETE)
            runtime.onStop = {
                service.setAppLanguage(AppLanguage.ENGLISH)
                service.setSubscriptionHwid("new-during-stop")
            }
            val conflicted = owner.submit(deleteActive)
            assertEquals(ControlCode.CONFLICT, conflicted.code)
            assertTrue(service.state.isVpnRunning)
            assertEquals(AppLanguage.ENGLISH, service.state.appLanguage)
            assertEquals("new-during-stop", service.state.subscriptionHwid)
            assertEquals(active.rawLink, service.activeDesktopLocation()?.rawLink)
            assertEquals(conflicted, owner.submit(deleteActive))
            assertEquals(1, runtime.stops)
            assertEquals(2, runtime.starts)
            assertEquals(runtime.startedProfiles.first(), runtime.startedProfiles.last())
            runtime.onStop = {}
            val successfulDelete = owner.submit(action(active, ControlOperationId.LOCATIONS_DELETE))
            assertEquals(ControlCode.OK, successfulDelete.code)
            assertFalse(service.state.isVpnRunning)
            assertEquals(2, runtime.stops)
            assertFalse(service.visibleDesktopLocations().any { it.rawLink == active.rawLink })
            assertEquals(setOf("id"), successfulDelete.data.keys)
            assertEquals(service.configurationRevision, successfulDelete.configurationRevision)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun stopAndPersistenceFailuresKeepLocationAndAreDeduplicated() = runTest {
        val directory = Files.createTempDirectory("vpn-control-delete-failure")
        val runtime = GuardedDeleteRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime,
            controlPlatform = ControlPlatform.LINUX)
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.applyControlSettings(mapOf("mode" to ControlValue.Text("proxy-only"))).getOrThrow()
            val row = service.saveLocation("socks://127.0.0.1:1080#Target").getOrThrow()
            val id = requireNotNull(service.controlLocationId(row))
            fun action(opening: String) = desktopGuiLocationAction(opening, owner.controllerId,
                service.configurationRevision, id, ControlOperationId.LOCATIONS_DELETE)
            service.applyLocationSelection(row.index).getOrThrow()
            assertTrue(owner.session.execute(DesktopCliCommand.On).success)
            val revision = service.configurationRevision
            runtime.failStop = true
            val stopRequest = action("stop-failure")
            val stopped = owner.submit(stopRequest)
            assertEquals(ControlCode.RUNTIME_FAILED, stopped.code)
            assertTrue(stopped.data.isEmpty())
            assertEquals(revision, stopped.configurationRevision)
            assertEquals(stopped, owner.submit(stopRequest))
            assertEquals(1, runtime.stops)
            assertTrue(runtime.isRunning())
            assertEquals(id, service.controlLocationId(service.visibleDesktopLocations().single()))
            runtime.failStop = false
            val persistRequest = action("persistence-failure")
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val direct = service.mutateControlLocation(persistRequest.command, persistRequest.ifRevision)
            assertFalse(direct.response.success)
            assertEquals("ROLLBACK_FAILED", direct.response.message)
            assertEquals(revision, direct.metadata.configurationRevision)
            val persisted = owner.submit(persistRequest)
            // Native runtime is restored, but durable rollback cannot be claimed while storage is unavailable.
            assertEquals(ControlCode.RUNTIME_FAILED, persisted.code)
            assertEquals(revision, persisted.configurationRevision)
            assertTrue(persisted.data.isEmpty())
            assertTrue(runtime.isRunning())
            assertTrue(service.state.isVpnRunning)
            assertEquals(row.rawLink, service.activeDesktopLocation()?.rawLink)
            assertEquals(id, service.controlLocationId(service.visibleDesktopLocations().single()))
            assertEquals(persisted, owner.submit(persistRequest))
            assertEquals(3, runtime.stops)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun opaqueSelectionRejectsReplacedAndWrongOwnerWithoutRetargetingNumericName() = runTest {
        val directory = Files.createTempDirectory("vpn-control-guarded-select")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.saveLocation("socks://127.0.0.1:1080#2").getOrThrow()
            val target = service.saveLocation("socks://127.0.0.2:1080#Target").getOrThrow()
            val request = desktopGuiLocationAction("frontend", owner.controllerId, service.configurationRevision,
                requireNotNull(service.controlLocationId(target)), ControlOperationId.LOCATIONS_SELECT)
            assertEquals(ControlCode.CONFLICT, owner.submit(request.copy(controllerId = "old")).code)
            assertEquals(ControlCode.OK, owner.submit(request).code)
            assertEquals(target.rawLink, service.state.selectedProfileRawLink)
            val beforeReorder = request.copy(requestId = "before-reorder")
            service.deleteLocation(service.visibleDesktopLocations().first().index).getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(beforeReorder).code)
            val reordered = owner.submit(request.copy(requestId = "stable-after-reorder", ifRevision = null))
            assertEquals(ControlCode.OK, reordered.code)
            assertEquals(request.command.arguments["id"], reordered.data["id"])
            assertEquals(target.rawLink, service.state.selectedProfileRawLink)
            service.saveLocation("socks://127.0.0.3:1080#Replacement", service.visibleDesktopLocations().single().index, target.rawLink).getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(request.copy(requestId = "replaced", ifRevision = null)).code)
            assertEquals("Replacement", service.state.selectedProfileName)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}

private class GuardedDeleteRuntime : DesktopRuntimeController {
    var onStop: () -> Unit = {}
    var starts = 0
    var stops = 0
    var failStop = false
    val startedProfiles = mutableListOf<ProxyProfile>()
    private var mode: AppMode? = null
    override suspend fun start(profile: ProxyProfile, routingRules: RoutingRules, dnsSettings: DnsSettings,
        appMode: AppMode, activeVerificationPort: Int?, homeSshRouteSettings: HomeSshRouteSettings): Result<DesktopRuntimeSession> {
        starts++; mode = appMode; startedProfiles += profile
        return Result.success(DesktopRuntimeSession(appMode, 1080, null, null, "{}", Path.of("synthetic.log"), 1L))
    }
    override suspend fun stop(): Result<Unit> {
        stops++
        if (failStop) return Result.failure(IllegalStateException("synthetic private runtime failure"))
        onStop(); mode = null; return Result.success(Unit)
    }
    override fun isRunning() = mode != null
    override fun currentMode() = mode
    override fun currentPort(): Int? = if (mode == null) null else 1080
}
