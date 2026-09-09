package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class DesktopRuntimeRestoreLeaseTest {
    @Test
    fun closeWhileRestoreWaitsKeepsRetainedAInputUntilRestoreTerminates() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-runtime-restore-lease-")
        val native = BlockingRestoreNative()
        val credentials = DesktopHomeSshCredentialStore(directory)
        val manager = DesktopProxyRuntimeManager(LeaseRuntimeConfigStore(), directory.resolve("runtime"), native)
        try {
            credentials.importPrivateKey(LEASE_KEY_A)
            assertTrue(manager.start(profile("127.0.0.1"), RoutingRules(), DnsSettings(), AppMode.PROXY_ONLY,
                null, SSH_SETTINGS).isSuccess)
            val lease = assertNotNull(manager.captureRuntimeRestoreLease())
            credentials.importPrivateKey(LEASE_KEY_B)
            assertTrue(manager.start(profile("127.0.0.2"), RoutingRules(), DnsSettings(), AppMode.PROXY_ONLY,
                null, SSH_SETTINGS).isSuccess)

            val replacement = async {
                manager.start(profile("127.0.0.3"), RoutingRules(), DnsSettings(), AppMode.PROXY_ONLY,
                    null, SSH_SETTINGS)
            }
            withTimeout(5_000) { native.restoreReadinessEntered.await() }
            val restore = async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { lease.restore() }
            lease.close()
            assertTrue(Files.exists(native.keyPaths.first()), "close must not retire A while restore waits on transition")

            native.allowRestoreReadiness.complete(Unit)
            assertTrue(withTimeout(5_000) { replacement.await() }.isSuccess)
            assertTrue(withTimeout(5_000) { restore.await() }.isSuccess)
            assertTrue(manager.isRunning())
        } finally {
            native.allowRestoreReadiness.complete(Unit)
            manager.stop()
            directory.toFile().deleteRecursively()
        }
    }
}

private class BlockingRestoreNative : DesktopRuntimeManagerNative {
    val keyPaths = mutableListOf<Path>()
    val restoreReadinessEntered = CompletableDeferred<Unit>()
    val allowRestoreReadiness = CompletableDeferred<Unit>()
    private var prepares = 0
    private var nextPid = 80_000L

    override fun preflight(launch: DesktopRuntimeLaunch) = DesktopPreflightReport(
        launch.appMode, listOf(DesktopPreflightCheck("fixture", DesktopPreflightStatus.PASS, "ready")),
    )

    override fun prepare(launch: DesktopRuntimeLaunch): DesktopPreparedRuntimeProcess {
        prepares++
        keyPaths.add(requireNotNull(launch.privateKeyPath))
        return object : DesktopPreparedRuntimeProcess {
            private var consumed = false
            override fun commit(): DesktopRuntimeProcess {
                check(!consumed)
                consumed = true
                return object : DesktopRuntimeProcess {
                    override var isAlive = true
                    override fun pid(): Long = nextPid++
                    override fun destroy() { isAlive = false }
                    override fun destroyForcibly() { isAlive = false }
                    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = !isAlive
                }
            }
            override fun close() { consumed = true }
        }
    }

    override suspend fun awaitReady(process: DesktopRuntimeProcess, launch: DesktopRuntimeLaunch): Boolean {
        if (prepares == 3) {
            restoreReadinessEntered.complete(Unit)
            allowRestoreReadiness.await()
        }
        return true
    }
}

private fun profile(host: String) = LocationConfigs.decodeStoredLocation("socks://$host:1080#Fixture")

private class LeaseRuntimeConfigStore : RuntimeConfigStore {
    private var value: String? = null
    override suspend fun readRuntimeConfig(): String? = value
    override suspend fun writeRuntimeConfig(configJson: String) { value = configJson }
    override suspend fun clearRuntimeConfig() { value = null }
}

private val SSH_SETTINGS = HomeSshRouteSettings(
    enabled = true,
    host = "ssh.example.test",
    user = "fixture",
    hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"),
)
private const val LEASE_KEY_A = "-----BEGIN PRIVATE KEY-----\nfixture-A\n-----END PRIVATE KEY-----\n"
private const val LEASE_KEY_B = "-----BEGIN PRIVATE KEY-----\nfixture-B\n-----END PRIVATE KEY-----\n"
