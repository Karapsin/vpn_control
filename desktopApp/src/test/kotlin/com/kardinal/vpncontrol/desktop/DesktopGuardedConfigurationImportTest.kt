package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopGuardedConfigurationImportTest {
    @Test fun activeImportConflictRestoresRuntimeWithoutOverwritingConcurrentSettings() = runTest {
        val directory = Files.createTempDirectory("guarded-active-import")
        val runtime = ImportRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            runtimeController = runtime, controlPlatform = ControlPlatform.LINUX)
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.applyControlSettings(mapOf("mode" to ControlValue.Text("proxy-only"))).getOrThrow()
            val active = service.saveLocation("socks://127.0.0.1:1080#Active").getOrThrow()
            service.applyLocationSelection(active.index).getOrThrow()
            assertTrue(owner.session.execute(DesktopCliCommand.On).success)
            val input = LocationConfigs.export(listOf("socks://127.0.0.2:1080#Replacement")).content
            val request = ControlRequest("active-import", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text(input))), controllerId = owner.controllerId,
                ifRevision = service.configurationRevision)
            runtime.onStop = {
                service.setAppLanguage(AppLanguage.ENGLISH)
                service.setSubscriptionHwid("changed-during-import")
            }
            val conflicted = owner.submit(request)
            assertEquals(ControlCode.CONFLICT, conflicted.code)
            assertTrue(runtime.isRunning())
            assertEquals(active.rawLink, service.activeDesktopLocation()?.rawLink)
            assertEquals("Active", service.visibleDesktopLocations().single().name)
            assertEquals("changed-during-import", service.state.subscriptionHwid)
            assertEquals(AppLanguage.ENGLISH, service.state.appLanguage)
            assertEquals(conflicted, owner.submit(request))
            assertEquals(1, runtime.stops)
            runtime.onStop = {}
            val saved = owner.submit(request.copy(requestId = "fresh-import", ifRevision = service.configurationRevision))
            assertEquals(ControlCode.OK, saved.code)
            assertFalse(runtime.isRunning())
            assertEquals("Replacement", service.visibleDesktopLocations().single().name)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun routingGuardsRetainOpeningRevisionAndDeduplicateDurableSave() = runTest {
        val directory = Files.createTempDirectory("guarded-routing")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val request = ControlRequest("routing", ControlCommand(ControlOperationId.ROUTING_SET,
                mapOf("key" to ControlValue.Text("direct-domains"), "value" to ControlValue.Text("example.test"))),
                controllerId = owner.controllerId, ifRevision = service.configurationRevision)
            assertEquals(ControlCode.CONFLICT, owner.submit(request.copy(controllerId = "old-owner")).code)
            val saved = owner.submit(request)
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(setOf("example.test"), service.state.routingRules.directDomainSuffixes.toSet())
            assertEquals(mapOf("direct-domains" to ControlValue.ArrayValue(listOf(ControlValue.Text("example.test")))), saved.data)
            assertEquals(service.configurationRevision, saved.configurationRevision)
            assertEquals(saved, owner.submit(request))
            val stale = owner.submit(request.copy(requestId = "stale", command = request.command.copy(arguments =
                request.command.arguments + ("value" to ControlValue.Text("new.test")))))
            assertEquals(ControlCode.CONFLICT, stale.code)
            assertEquals(setOf("example.test"), service.state.routingRules.directDomainSuffixes.toSet())
            val before = service.configurationRevision
            val invalid = owner.submit(ControlRequest("invalid", ControlCommand(ControlOperationId.ROUTING_IMPORT,
                mapOf("input" to ControlValue.Text("PRIVATE_INVALID_INPUT"))), controllerId = owner.controllerId,
                ifRevision = before))
            assertEquals(ControlCode.INVALID_ARGUMENT, invalid.code)
            assertEquals(before, service.configurationRevision)
            assertTrue(invalid.data.isEmpty())
            assertFalse(invalid.toString().contains("PRIVATE_INVALID_INPUT"))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun bulkImportConflictsWithoutReplacingNewerLocationsAndRetainsRetryResult() = runTest {
        val directory = Files.createTempDirectory("guarded-location-import")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            val input = LocationConfigs.export(listOf("socks://127.0.0.1:1080#Imported")).content
            val request = ControlRequest("import", ControlCommand(ControlOperationId.LOCATIONS_IMPORT,
                mapOf("input" to ControlValue.Text(input))), controllerId = owner.controllerId,
                ifRevision = service.configurationRevision)
            service.saveLocation("socks://127.0.0.2:1080#Newer").getOrThrow()
            assertEquals(ControlCode.CONFLICT, owner.submit(request).code)
            assertEquals("Newer", service.visibleDesktopLocations().single().name)
            val fresh = request.copy(requestId = "fresh", ifRevision = service.configurationRevision)
            val imported = owner.submit(fresh)
            assertEquals(ControlCode.OK, imported.code)
            assertEquals(ControlValue.IntegerValue(1), imported.data["importedLocations"])
            assertFalse(imported.data.toString().contains("socks://"))
            assertEquals("Imported", service.visibleDesktopLocations().single().name)
            assertEquals(service.configurationRevision, imported.configurationRevision)
            assertEquals(imported, owner.submit(fresh))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun routingPersistenceFailureKeepsConfigurationAndNeverBecomesSuccess() = runTest {
        val directory = Files.createTempDirectory("guarded-routing-failure")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setControlRouting("direct-domains", "original.test").getOrThrow()
            val before = service.configurationRevision
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val request = ControlRequest("failure", ControlCommand(ControlOperationId.ROUTING_SET,
                mapOf("key" to ControlValue.Text("direct-domains"), "value" to ControlValue.Text("lost.test"))),
                controllerId = owner.controllerId, ifRevision = before)
            val failed = owner.submit(request)
            assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code)
            assertEquals(before, failed.configurationRevision)
            assertEquals(setOf("original.test"), service.state.routingRules.directDomainSuffixes.toSet())
            assertEquals(failed, owner.submit(request))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}

private class ImportRuntime : DesktopRuntimeController {
    var onStop: () -> Unit = {}
    var stops = 0
    private var mode: AppMode? = null
    override suspend fun start(profile: ProxyProfile, routingRules: RoutingRules, dnsSettings: DnsSettings,
        appMode: AppMode, activeVerificationPort: Int?, homeSshRouteSettings: HomeSshRouteSettings): Result<DesktopRuntimeSession> {
        mode = appMode
        return Result.success(DesktopRuntimeSession(appMode, 1080, null, null, "{}", java.nio.file.Path.of("fake.log"), 1))
    }
    override suspend fun stop(): Result<Unit> { stops++; onStop(); mode = null; return Result.success(Unit) }
    override fun isRunning() = mode != null
    override fun currentMode() = mode
    override fun currentPort(): Int? = if (mode == null) null else 1080
}
