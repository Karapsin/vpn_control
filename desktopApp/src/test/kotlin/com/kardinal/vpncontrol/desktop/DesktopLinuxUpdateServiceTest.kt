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

class DesktopLinuxUpdateServiceTest {
    private val identity = DesktopInstallCorrelation("owner", "request", "operation")
    private val job = "00000000-0000-0000-0000-000000000041"
    private inner class Adapter : DesktopLinuxInstallAdapter {
        var prepares = 0
        var recovered = 0
        var released = 0
        var correlation: DesktopInstallCorrelation? = null
        var frontend: DesktopFrontendProcessIdentity? = null
        var cancellation: (() -> Unit)? = null
        var packageType: UpdatePackageType? = null
        val prepared = object : DesktopPreparedInstall {
            override val jobId = job
            override suspend fun commit() = Result.success(Unit)
            override fun cancel() = Result.success(Unit).also { cancellation?.invoke() }
            override fun close() = Unit
        }
        var outcome: Result<DesktopPreparedInstall> = Result.success(prepared)
        var releaseOutcome = Result.success(Unit)
        override suspend fun prepare(packageFile: Path, asset: UpdateAsset, correlation: DesktopInstallCorrelation,
            frontend: DesktopFrontendProcessIdentity?, onCancellationConfirmed: () -> Unit): Result<DesktopPreparedInstall> {
            prepares++; this.correlation = correlation; this.frontend = frontend; cancellation = onCancellationConfirmed
            assertTrue(Files.isRegularFile(packageFile))
            assertEquals(UpdatePlatform.LINUX, asset.platform)
            packageType = asset.packageType
            assertTrue(asset.packageType in setOf(UpdatePackageType.DEB, UpdatePackageType.RPM, UpdatePackageType.ARCH_BUNDLE))
            return outcome
        }
        override fun recoverCorrelations(): Result<List<DesktopInstallCorrelationRecovery>> {
            recovered++; return Result.success(emptyList())
        }
        override fun releaseCompleted(correlation: DesktopInstallCorrelation, receipt: DesktopInstallJobReceipt): Result<Unit> {
            released++; assertEquals(identity, correlation); return releaseOutcome
        }
    }

    @Test fun verifiedLinuxAssetDispatchesExactIdentityAndKeepsRuntimeUntilOwnerHandoff() = runBlocking { fixture { service, state, adapter, _ ->
        val frontend = DesktopFrontendProcessIdentity("00000000-0000-0000-0000-000000000042", 123, 456)
        val prepared = service.prepareVerifiedInstaller(identity, frontend).getOrThrow()
        assertSame(adapter.prepared, prepared)
        assertEquals(identity, adapter.correlation)
        assertEquals(frontend, adapter.frontend)
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        assertTrue(state().isVpnRunning)
        assertEquals("BUSY", service.dismiss().exceptionOrNull()?.message)
        assertTrue(prepared.cancel().isSuccess)
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
    } }

    @Test fun uncertainWorkerRetainsInstallingStateWhileOrdinaryFailureRestoresReady() = runBlocking { fixture { service, state, adapter, _ ->
        adapter.outcome = Result.failure(IllegalStateException("INTERACTION_REQUIRED"))
        assertTrue(service.prepareVerifiedInstaller(identity).isFailure)
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
        adapter.outcome = Result.failure(DesktopInstallPreparationFailure(adapter.prepared, IllegalStateException("OUTCOME_UNKNOWN")))
        assertIs<DesktopInstallPreparationFailure>(service.prepareVerifiedInstaller(identity).exceptionOrNull())
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        assertEquals("BUSY", service.prepareVerifiedInstaller(identity).exceptionOrNull()?.message)
        assertTrue(state().isVpnRunning)
    } }

    @Test fun verifiedArchBundleUsesReceiptAdapterWithoutStoppingRuntimeOrReportingInstalled() = runBlocking {
        fixture(preparedPackageType = UpdatePackageType.ARCH_BUNDLE) { service, state, adapter, _ ->
            val prepared = service.prepareVerifiedInstaller(identity).getOrThrow()
            assertSame(adapter.prepared, prepared)
            assertEquals(UpdatePackageType.ARCH_BUNDLE, adapter.packageType)
            assertEquals(identity, adapter.correlation)
            assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
            assertNotNull(state().appUpdate.preparedAsset)
            assertTrue(state().isVpnRunning)
            assertTrue(prepared.cancel().isSuccess)
            assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
        }
    }

    @Test fun changedVerifiedPackageNeverReachesNativeAdapter() = runBlocking { fixture { service, state, adapter, directory ->
        val fileName = requireNotNull(state().appUpdate.preparedAsset).fileName
        Files.writeString(directory.resolve(fileName), "changed")
        assertEquals("INVALID_ARGUMENT", service.prepareVerifiedInstaller(identity).exceptionOrNull()?.message)
        assertEquals(0, adapter.prepares)
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
    } }

    @Test fun recoveryAndSettlementUseAdapterProofBeforeChangingUpdateState() = runBlocking { fixture { service, state, adapter, _ ->
        assertTrue(service.recoverInstallCorrelations().isSuccess)
        assertEquals(1, adapter.recovered); assertEquals(0, adapter.prepares)
        service.prepareVerifiedInstaller(identity).getOrThrow()
        val failed = DesktopInstallJobReceipt(job, 5, DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED)
        adapter.releaseOutcome = Result.failure(IllegalStateException("OUTCOME_UNKNOWN"))
        assertTrue(service.settleVerifiedInstall(identity, failed).isFailure)
        assertEquals(AppUpdatePhase.INSTALLING, state().appUpdate.phase)
        adapter.releaseOutcome = Result.success(Unit)
        assertTrue(service.settleVerifiedInstall(identity, failed).isSuccess)
        assertEquals(AppUpdatePhase.READY, state().appUpdate.phase)
        assertEquals(ControlCode.RUNTIME_FAILED.wireName, state().appUpdate.message)
        assertNotNull(state().appUpdate.preparedAsset)
        val succeeded = DesktopInstallJobReceipt(job, 6, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)
        assertTrue(service.settleVerifiedInstall(identity, succeeded).isSuccess)
        assertNull(state().appUpdate.preparedAsset)
        assertNull(service.checkedStatus())
        assertTrue(state().isVpnRunning)
    } }

    private suspend fun fixture(preparedPackageType: UpdatePackageType? = null,
        block: suspend (DesktopUpdateService, () -> MainUiState, Adapter, Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-linux-update-service-").toRealPath()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"
        val bytes = "synthetic package, never executed".encodeToByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        server.createContext("/manifest") { exchange ->
            val assets = listOf("deb", "rpm").joinToString(",") { type ->
                """{"platform":"linux","architecture":"arm64","packageType":"$type","displayVersion":"1.0.2","fileName":"test.$type","downloadUrl":"$base/package","sha256":"$digest","sizeBytes":${bytes.size}}"""
            }
            val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2","releaseNotesUrl":"$base/notes","assets":[$assets]}""".encodeToByteArray()
            exchange.sendResponseHeaders(200, manifest.size.toLong()); exchange.responseBody.use { it.write(manifest) }
        }
        server.createContext("/package") { exchange ->
            exchange.sendResponseHeaders(200, bytes.size.toLong()); exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        var state = MainUiState(isVpnRunning = true)
        val adapter = Adapter()
        val workspace = directory.resolve("workspace")
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            DesktopBuildInfo(1, "1.0.1"), osName = "Linux", osArchitecture = "arm64", currentCommand = null,
            manifestUrl = "$base/manifest", trustUrl = { it.startsWith("$base/") }, workspaceDirectory = workspace,
            linuxInstallerFactory = { assertEquals(workspace, it); adapter })
        try {
            service.check().getOrThrow(); service.downloadChecked().getOrThrow()
            // Exercise dispatch independently of the test host's distribution/package preference.
            if (preparedPackageType != null) state = state.copy(appUpdate = state.appUpdate.copy(
                preparedAsset = requireNotNull(state.appUpdate.preparedAsset).copy(packageType = preparedPackageType)))
            block(service, { state }, adapter, directory)
        } finally {
            server.stop(0)
            Files.list(directory).use { it.toList() }.forEach(Files::delete)
            Files.delete(directory)
        }
    }
}
