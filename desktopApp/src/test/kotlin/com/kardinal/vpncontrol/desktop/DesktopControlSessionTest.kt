package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlSession
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopControlSessionTest {
    @Test
    fun observesDirectLegacyRunningAndTerminalWithoutInspectionCalls() = runTest {
        val directory = Files.createTempDirectory("vpn-control-session-legacy-flow")
        val release = CompletableDeferred<Unit>()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            locationBenchmarker = { profile, _, _, _ ->
                release.await()
                Result.success(ProfileBenchmark(profile, "ok", "ok", 1.0, 1.0, 1.0, "test=ok"))
            })
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            service.saveLocation("socks://127.0.0.1:1080#Fixture").getOrThrow()
            val client = launch { owner.session.execute(DesktopCliCommand.LocationBenchmark("Fixture")) }
            runCurrent()
            val running = owner.snapshots.value.operations.single()
            assertEquals(ControlOperationPhase.RUNNING, running.phase)
            assertNull(running.result)
            // Disconnecting a synchronous observer must not stop the owner's operation.
            client.cancel()
            runCurrent()
            assertEquals(ControlOperationPhase.RUNNING, owner.snapshots.value.operations.single().phase)
            release.complete(Unit)
            runCurrent()
            val terminal = owner.snapshots.value.operations.single()
            assertEquals(running.id, terminal.id)
            assertEquals(ControlOperationPhase.SUCCEEDED, terminal.phase)
            assertEquals(ControlCode.OK, terminal.result?.code)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun observesAsyncCompletionAndOwnerActionCancellationWithoutInspectionCalls() = runTest {
        for (cancel in listOf(false, true)) {
            val directory = Files.createTempDirectory("vpn-control-session-async-flow")
            val release = CompletableDeferred<Unit>()
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
                locationBenchmarker = { profile, _, _, _ ->
                    release.await()
                    if (cancel) throw CancellationException("private action detail")
                    Result.success(ProfileBenchmark(profile, "ok", "ok", 1.0, 1.0, 1.0, "test=ok"))
                })
            val owner = DesktopControllerOwner(service, scope = CoroutineScope(backgroundScope.coroutineContext +
                SupervisorJob(backgroundScope.coroutineContext[Job])))
            try {
                service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
                service.saveLocation("socks://127.0.0.1:1080#Fixture").getOrThrow()
                val accepted = owner.submit(ControlRequest("async", ControlCommand(ControlOperationId.LOCATIONS_BENCHMARK,
                    mapOf("selector" to ControlValue.Text("Fixture"))), controllerId = owner.controllerId, asynchronous = true))
                assertTrue(accepted.ok)
                assertFalse(accepted.final)
                runCurrent()
                assertEquals(ControlOperationPhase.RUNNING, owner.snapshots.value.operations.single().phase)
                release.complete(Unit)
                runCurrent()
                val terminal = owner.snapshots.value.operations.single()
                assertEquals(accepted.operationId, terminal.id)
                assertEquals(if (cancel) ControlOperationPhase.CANCELLED else ControlOperationPhase.SUCCEEDED, terminal.phase)
                assertEquals(if (cancel) ControlCode.CANCELLED else ControlCode.OK, terminal.result?.code)
                assertFalse(owner.snapshots.value.toString().contains("private action detail"))
            } finally { owner.close(); directory.toFile().deleteRecursively() }
        }
    }

    @Test
    fun observesLegacyServiceCommitsAndTypedOperationResultsWithoutCompose() = runTest {
        val directory = Files.createTempDirectory("vpn-control-session-flow")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(), emptyList()))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        val session: ControlSession = owner
        try {
            runCurrent()
            assertEquals(0L, session.snapshots.value.configurationRevision)
            assertFalse(session.snapshots.value.runtimeRunning)
            service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(7))).getOrThrow()
            runCurrent()
            assertEquals(1L, session.snapshots.value.configurationRevision)
            val result = session.submit(ControlRequest("settings", ControlCommand(ControlOperationId.SETTINGS_SET,
                mapOf("key" to ControlValue.Text("validation.batch-size"), "value" to ControlValue.Text("8"))),
                controllerId = owner.controllerId))
            assertEquals(ControlCode.OK, result.code)
            assertEquals(2L, session.snapshots.value.configurationRevision)
            val operation = assertNotNull(session.operation(requireNotNull(result.operationId)))
            assertEquals(ControlOperationPhase.SUCCEEDED, operation.phase)
            assertEquals(result, operation.result)
            assertEquals(ControlCode.NOT_FOUND, session.cancelOperation("missing").code)
            val beforeDraft = session.snapshots.value
            service.toggleDnsDialog()
            service.setCustomDnsDraft("https://unsaved.example/dns-query")
            runCurrent()
            assertEquals(beforeDraft, session.snapshots.value)
            assertFalse(session.snapshots.value.toString().contains("unsaved.example"))
        } finally {
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
