package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class DesktopRuntimeRestoreCredentialTest {
    @Test
    fun retainedManagerLeaseRestoresAAfterSuccessfulBAndReleasesIdempotently() = runTest {
        restoreCredentialFixture { fixture ->
            assertTrue(fixture.startManager(fixture.a).isSuccess)
            val lease = assertNotNull(fixture.manager.captureRuntimeRestoreLease())

            fixture.credentials.importPrivateKey(KEY_B)
            assertTrue(fixture.startManager(fixture.b).isSuccess)
            assertTrue(Files.exists(fixture.native.keyPaths.first()), "leased A input must survive committed B")
            assertTrue(lease.restore().isSuccess)
            lease.close()
            lease.close()

            assertEquals(listOf(KEY_A, KEY_B, KEY_A), fixture.native.preparedKeys)
            assertEquals(KEY_B, Files.readString(Path.of(requireNotNull(fixture.credentials.privateKeyPathOrNull()))))
            assertTrue(fixture.manager.isRunning())
        }
    }

    @Test
    fun capturedLifecycleRestoreUsesActualAKeyAfterCommittedB() = runTest {
        restoreCredentialFixture { fixture ->
            val state = fixture.state
            assertTrue(fixture.start(state, fixture.a).isSuccess)
            val originalRuntime = requireNotNull(fixture.lifecycle.activeConnection).runtimeId
            val restore = fixture.lifecycle.captureRuntimeRestore()

            fixture.credentials.importPrivateKey(KEY_B)
            assertTrue(fixture.start(state, fixture.b).isSuccess)
            try {
                assertTrue(restore().isSuccess)
            } finally {
                releaseDesktopRuntimeRestore(restore)
            }

            assertEquals(listOf(KEY_A, KEY_B, KEY_A), fixture.native.preparedKeys)
            assertEquals(fixture.a.rawLink, fixture.lifecycle.activeLocation?.rawLink)
            assertNotEquals(originalRuntime, requireNotNull(fixture.lifecycle.activeConnection).runtimeId)
            assertEquals(KEY_B, Files.readString(Path.of(requireNotNull(fixture.credentials.privateKeyPathOrNull()))))
        }
    }

    @Test
    fun failedPostStartCommitRestoresActualAKeyAfterCommittedB() = runTest {
        restoreCredentialFixture { fixture ->
            val state = fixture.state
            assertTrue(fixture.start(state, fixture.a).isSuccess)
            val originalRuntime = requireNotNull(fixture.lifecycle.activeConnection).runtimeId
            fixture.credentials.importPrivateKey(KEY_B)
            fixture.failFinalCommit = true

            val result = fixture.start(state, fixture.b)

            assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
            assertEquals(listOf(KEY_A, KEY_B, KEY_A), fixture.native.preparedKeys)
            assertEquals(fixture.a.rawLink, fixture.lifecycle.activeLocation?.rawLink)
            assertNotEquals(originalRuntime, requireNotNull(fixture.lifecycle.activeConnection).runtimeId)
            assertEquals(KEY_B, Files.readString(Path.of(requireNotNull(fixture.credentials.privateKeyPathOrNull()))))
        }
    }
}

private suspend fun restoreCredentialFixture(action: suspend (RestoreCredentialFixture) -> Unit) {
    val directory = Files.createTempDirectory("vpn-control-restore-credential-")
    val fixture = RestoreCredentialFixture(directory)
    try {
        action(fixture)
    } finally {
        fixture.manager.stop()
        assertTrue(fixture.native.keyPaths.none(Files::exists), "runtime key captures must retire after the fixture")
        directory.toFile().deleteRecursively()
    }
}

private class RestoreCredentialFixture(directory: Path) {
    val state = MainUiState(appMode = AppMode.PROXY_ONLY, homeSshRouteSettings = HomeSshRouteSettings(
        enabled = true, host = "ssh.example.test", user = "fixture",
        hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"),
    ))
    val credentials = DesktopHomeSshCredentialStore(directory)
    val native = RestoreCredentialNative()
    val manager = DesktopProxyRuntimeManager(RestoreCredentialRuntimeConfigStore(), directory.resolve("runtime"), native)
    val lifecycle = DesktopConnectionLifecycleService(manager)
    val a = location(0, "127.0.0.1", "A")
    val b = location(1, "127.0.0.2", "B")
    var failFinalCommit = false

    init {
        credentials.importPrivateKey(KEY_A)
    }

    suspend fun start(state: MainUiState, location: DesktopLocationRecord): Result<Unit> = lifecycle.startConnection(
        state = state,
        locations = listOf(a, b),
        location = location,
        benchmarkSummary = null,
        currentState = { state },
        setResumeConnectionOnLaunch = {},
        commitState = { _, next ->
            if (failFinalCommit && !next.isBusy) Result.failure(DesktopPersistenceException()) else Result.success(Unit)
        },
        updateState = {},
    )

    suspend fun startManager(location: DesktopLocationRecord): Result<DesktopRuntimeSession> = manager.start(
        profile = com.kardinal.vpncontrol.data.LocationConfigs.decodeStoredLocation(location.rawLink),
        routingRules = state.routingRules,
        dnsSettings = state.dnsSettings,
        appMode = state.appMode,
        activeVerificationPort = null,
        homeSshRouteSettings = state.homeSshRouteSettings,
    )
}

private class RestoreCredentialNative : DesktopRuntimeManagerNative {
    val preparedKeys = mutableListOf<String>()
    val keyPaths = mutableListOf<Path>()
    private var nextPid = 70_000L

    override fun preflight(launch: DesktopRuntimeLaunch): DesktopPreflightReport = DesktopPreflightReport(
        launch.appMode,
        listOf(DesktopPreflightCheck("fixture", DesktopPreflightStatus.PASS, "ready")),
    )

    override fun prepare(launch: DesktopRuntimeLaunch): DesktopPreparedRuntimeProcess {
        val keyPath = requireNotNull(launch.privateKeyPath)
        keyPaths.add(keyPath)
        preparedKeys += Files.readString(keyPath)
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

    override suspend fun awaitReady(process: DesktopRuntimeProcess, launch: DesktopRuntimeLaunch): Boolean = true
}

private fun location(index: Int, host: String, name: String): DesktopLocationRecord =
    listOf("socks://$host:1080#$name").toDesktopLocationRecords(index).single()

private class RestoreCredentialRuntimeConfigStore : RuntimeConfigStore {
    private var value: String? = null
    override suspend fun readRuntimeConfig(): String? = value
    override suspend fun writeRuntimeConfig(configJson: String) { value = configJson }
    override suspend fun clearRuntimeConfig() { value = null }
}

private const val KEY_A = "-----BEGIN PRIVATE KEY-----\nfixture-A\n-----END PRIVATE KEY-----\n"
private const val KEY_B = "-----BEGIN PRIVATE KEY-----\nfixture-B\n-----END PRIVATE KEY-----\n"
