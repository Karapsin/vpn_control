package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.*
import com.kardinal.vpncontrol.model.ControlCode
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopMacUpdateServiceTest {
    private val identity = DesktopInstallCorrelation("owner", "request", "operation")
    private val job = "00000000-0000-0000-0000-000000000041"
    private inner class Adapter : DesktopMacInstallAdapter {
        var prepares = 0
        var recoveries = 0
        var released = 0
        val maintainedOwners = mutableListOf<String>()
        var lateResult: Result<Unit> = Result.success(Unit)
        var confirmLate = false
        var received: DesktopInstallCorrelation? = null
        var attached: DesktopFrontendProcessIdentity? = null
        var cancelled: (() -> Unit)? = null
        val prepared = object : DesktopPreparedInstall {
            override val jobId = job
            override suspend fun commit() = Result.success(Unit)
            override fun cancel() = Result.success(Unit).also { cancelled?.invoke() }
            override fun close() {}
        }
        var outcome: Result<DesktopPreparedInstall> = Result.success(prepared)
        override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
            frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> {
            prepares++; received = correlation; attached = frontend; cancelled = onCancellationConfirmed
            assertTrue(Files.isRegularFile(packageFile)); assertEquals(UpdatePlatform.MACOS, asset.platform)
            assertEquals(UpdatePackageType.DMG, asset.packageType)
            return outcome
        }
        override fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> {
            recoveries++; return Result.success(emptyList())
        }
        override fun reconcileLateAuthorization(ownerId: String): Result<Unit> {
            maintainedOwners += ownerId
            if (confirmLate && lateResult.isSuccess) cancelled?.invoke()
            return lateResult
        }
        override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> {
            released++; assertEquals(identity, correlation); assertEquals(job, receipt.jobId); return Result.success(Unit)
        }
    }

    @Test fun verifiedDmgUsesExactIdentityAndNativeAdapterBeforeStoppingRuntime() = runBlocking { fixture { service, state, adapter, _ ->
        val frontend = DesktopFrontendProcessIdentity("00000000-0000-0000-0000-000000000042", 123, 456)
        assertSame(adapter.prepared, service.prepareVerifiedInstaller(identity, frontend).getOrThrow())
        assertEquals(identity, adapter.received); assertEquals(frontend, adapter.attached)
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        assertTrue(state().isVpnRunning)
        adapter.prepared.cancel().getOrThrow()
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
    } }

    @Test fun unknownWorkerStaysInstallingAndRecoverySettlementUseSelectedAdapter() = runBlocking { fixture { service, state, adapter, _ ->
        assertTrue(service.recoverInstallCorrelations().isSuccess); assertEquals(1, adapter.recoveries)
        adapter.outcome = Result.failure(DesktopInstallPreparationFailure(adapter.prepared, IllegalStateException("OUTCOME_UNKNOWN")))
        assertIs<DesktopInstallPreparationFailure>(service.prepareVerifiedInstaller(identity).exceptionOrNull())
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        assertTrue(state().isVpnRunning)
        service.settleVerifiedInstall(identity, DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)).getOrThrow()
        assertEquals(1, adapter.released); assertNull(state().appUpdate.preparedAsset)
    } }

    @Test fun lateAuthorizationRunsOnlyInOwnerMaintenanceAndPreservesLiveRuntime() = runBlocking { fixture { service, state, adapter, _ ->
        adapter.outcome = Result.failure(DesktopInstallPreparationFailure(adapter.prepared, IllegalStateException("OUTCOME_UNKNOWN")))
        assertIs<DesktopInstallPreparationFailure>(service.prepareVerifiedInstaller(identity).exceptionOrNull())
        adapter.confirmLate = true
        service.recoverInstallCorrelations().getOrThrow()
        assertTrue(adapter.maintainedOwners.isEmpty())
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        adapter.lateResult = Result.failure(IllegalStateException("PERSISTENCE_FAILED"))
        assertEquals("PERSISTENCE_FAILED", service.reconcileTerminalInstallInputs("owner").exceptionOrNull()?.message)
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        adapter.lateResult = Result.success(Unit)
        service.reconcileTerminalInstallInputs("owner").getOrThrow()
        assertEquals(listOf("owner", "owner"), adapter.maintainedOwners)
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
        assertTrue(state().isVpnRunning)
    } }

    @Test fun changedDmgNeverLaunchesAdapter() = runBlocking { fixture { service, state, adapter, directory ->
        Files.writeString(directory.resolve(requireNotNull(state().appUpdate.preparedAsset).fileName), "changed")
        assertEquals("INVALID_ARGUMENT", service.prepareVerifiedInstaller(identity).exceptionOrNull()?.message)
        assertEquals(0, adapter.prepares)
    } }

    private suspend fun fixture(block: suspend (DesktopUpdateService, () -> MainUiState, Adapter, Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-mac-update-service-").toRealPath()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"
        val bytes = "synthetic dmg, never mounted".encodeToByteArray()
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        server.createContext("/manifest") { exchange ->
            val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2","releaseNotesUrl":"$base/notes","assets":[{"platform":"macos","architecture":"arm64","packageType":"dmg","displayVersion":"1.0.2","fileName":"test.dmg","downloadUrl":"$base/package","sha256":"$hash","sizeBytes":${bytes.size}}]}""".encodeToByteArray()
            exchange.sendResponseHeaders(200, manifest.size.toLong()); exchange.responseBody.use { it.write(manifest) }
        }
        server.createContext("/package") { exchange ->
            exchange.sendResponseHeaders(200, bytes.size.toLong()); exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        var state = MainUiState(isVpnRunning = true)
        val adapter = Adapter()
        val workspace = directory.resolve("workspace")
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory, DesktopBuildInfo(1, "1.0.1"),
            osName = "Mac OS X", osArchitecture = "arm64", currentCommand = null,
            manifestUrl = "$base/manifest", trustUrl = { it.startsWith("$base/") }, workspaceDirectory = workspace,
            macInstallerFactory = { assertEquals(workspace, it); adapter })
        try { service.check().getOrThrow(); service.downloadChecked().getOrThrow(); block(service, { state }, adapter, directory) }
        finally { server.stop(0); Files.list(directory).use { it.toList() }.forEach(Files::delete); Files.delete(directory) }
    }
}
