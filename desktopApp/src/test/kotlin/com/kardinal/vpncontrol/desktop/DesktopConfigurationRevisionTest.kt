package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopConfigurationRevisionTest {
    @Test
    fun competingSettingsSavesAtSameRevisionCannotOverwriteEachOther() {
        val directory = Files.createTempDirectory("vpn-control-revision-race")
        val executor = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
            val start = java.util.concurrent.CyclicBarrier(2)
            val attempts = listOf(17L, 18L).map { value ->
                executor.submit<Pair<Long, Result<Map<String, ControlValue>>>> {
                    start.await(5, java.util.concurrent.TimeUnit.SECONDS)
                    value to service.applyControlSettings(
                        mapOf("validation.batch-size" to ControlValue.IntegerValue(value)), expectedRevision = 0)
                }
            }.map { it.get(10, java.util.concurrent.TimeUnit.SECONDS) }
            val winner = attempts.single { it.second.isSuccess }
            assertEquals("CONFLICT", attempts.single { it.second.isFailure }.second.exceptionOrNull()?.message)
            assertEquals(1L, service.configurationRevision)
            assertEquals(winner.first.toInt(), service.state.validationSettings.batchSize)
            val bytes = Files.readAllBytes(directory.resolve("workspace.json"))
            // Even a stale no-op is a conflict, not an implicit revision rebase.
            assertEquals("CONFLICT", service.applyControlSettings(
                mapOf("validation.batch-size" to ControlValue.IntegerValue(winner.first)),
                expectedRevision = 0).exceptionOrNull()?.message)
            kotlin.test.assertContentEquals(bytes, Files.readAllBytes(directory.resolve("workspace.json")))
            assertTrue(service.applyControlSettings(
                mapOf("validation.batch-size" to ControlValue.IntegerValue(winner.first)), expectedRevision = 1).isSuccess)
            assertEquals(1L, service.configurationRevision)
        } finally {
            executor.shutdownNow()
            executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun revisionAdvancesOnlyForDurableConfigurationChanges() {
        val directory = Files.createTempDirectory("vpn-control-revision")
        try {
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
            assertEquals(0, service.configurationRevision)
            val patch = mapOf("validation.batch-size" to ControlValue.IntegerValue(17))
            assertTrue(service.applyControlSettings(patch).isSuccess)
            assertEquals(1, service.configurationRevision)
            assertTrue(service.applyControlSettings(patch).isSuccess)
            assertEquals(1, service.configurationRevision)
            service.openScreen(AppScreen.MAIN)
            service.setCustomDnsDraft("https://pending.example/dns-query")
            service.postStatus("status-only test update")
            service.forceRunningStateForTesting(true)
            assertEquals(1, service.configurationRevision)
            // Both primary and recovery destinations are unavailable; preserve committed state.
            Files.delete(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            assertTrue(service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(18))).isFailure)
            assertEquals(1, service.configurationRevision)
            assertEquals(17, service.state.validationSettings.batchSize)
        } finally { directory.toFile().deleteRecursively() }
    }
}
