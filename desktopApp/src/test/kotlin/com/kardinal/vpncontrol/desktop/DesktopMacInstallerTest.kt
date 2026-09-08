package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.UpdateAsset
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopMacInstallerTest {
    @Test fun unsupportedPlatformAndPackageCannotStageOrLaunchNativeWorker() = runBlocking {
        val asset = UpdateAsset(UpdatePlatform.MACOS, "arm64", UpdatePackageType.DMG, "1.0.0", "update.dmg",
            "https://example.invalid/update.dmg", "a".repeat(64), 1)
        val correlation = DesktopInstallCorrelation("controller", "request", "operation")
        val absent = Path.of("/does-not-exist/vpn-control-test-package.dmg")
        val workspace = Path.of(System.getProperty("java.io.tmpdir")).resolve("vpn-mac-unsupported-${java.util.UUID.randomUUID()}")
        assertEquals("UNSUPPORTED", DesktopMacInstaller(workspace, isMac = { false })
            .prepare(absent, asset, correlation).exceptionOrNull()?.message)
        assertEquals("UNSUPPORTED", DesktopMacInstaller(workspace, isMac = { true })
            .prepare(absent, asset.copy(packageType = UpdatePackageType.DEB), correlation).exceptionOrNull()?.message)
        assertFalse(java.nio.file.Files.exists(workspace))
    }

    @Test fun provenUnstartedCancellationIsIdempotentButUnconfirmedExternalWorkerStaysUnknown() = runBlocking {
        var recorded = 0
        var confirmed = 0
        var delegated = 0
        val delegate = object : DesktopPreparedInstall {
            override val jobId = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel(): Result<Unit> { delegated++; return Result.failure(IllegalStateException("OUTCOME_UNKNOWN")) }
            override fun close() {}
        }
        val unstarted = DesktopMacUnstartedCancellation(delegate, { true }, { recorded++ }, { confirmed++ })
        unstarted.cancel().getOrThrow(); unstarted.cancel().getOrThrow()
        assertEquals(1, recorded); assertEquals(1, confirmed); assertEquals(0, delegated)
        assertEquals("CANCELLED", unstarted.commit().exceptionOrNull()?.message)
        val external = DesktopMacUnstartedCancellation(delegate, { false }, { error("No local proof") }, { error("Unconfirmed") })
        assertEquals("OUTCOME_UNKNOWN", external.cancel().exceptionOrNull()?.message)
        assertEquals("OUTCOME_UNKNOWN", external.cancel().exceptionOrNull()?.message)
        assertEquals(2, delegated)
    }

    @Test fun closeFailureLeavesPreparedCancellationRetryable() {
        var closes = 0
        val delegate = object : DesktopPreparedInstall {
            override val jobId = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"
            override suspend fun commit() = Result.success(Unit)
            override fun cancel() = Result.success(Unit)
            override fun close() {
                closes++
                if (closes == 1) error("close failed")
            }
        }
        val prepared = DesktopMacUnstartedCancellation(delegate, { true }, {}, {})

        assertFails { prepared.close() }
        prepared.close()
        assertEquals(2, closes)
    }
}
