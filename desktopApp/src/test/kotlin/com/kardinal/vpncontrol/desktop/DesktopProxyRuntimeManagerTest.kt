package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import java.util.concurrent.TimeUnit

class DesktopProxyRuntimeManagerTest {
    @Test fun failedCandidateRecoversActualSshKeyAfterPendingKeyImport() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val credentials = DesktopHomeSshCredentialStore(fixture.directory)
            val keyA = "-----BEGIN PRIVATE KEY-----\nfixture-A\n-----END PRIVATE KEY-----\n"
            val keyB = "-----BEGIN PRIVATE KEY-----\nfixture-B\n-----END PRIVATE KEY-----\n"
            val settings = HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture",
                hostKeys = listOf("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"))
            val observedKeys = mutableListOf<String>()
            fixture.native.onPrepare = { launch ->
                observedKeys += Files.readString(assertNotNull(launch.privateKeyPath))
            }
            credentials.importPrivateKey(keyA)
            val actual = fixture.start("127.0.0.1", settings).getOrThrow()
            credentials.importPrivateKey(keyB)
            fixture.native.rejectCandidateReadiness = true
            val failure = fixture.start("127.0.0.2", settings).exceptionOrNull() as DesktopRuntimeTransitionFailure
            assertNotNull(failure.recoveredSession)
            assertFalse(failure.recoveryFailed)
            assertEquals(listOf(keyA, keyB, keyA), observedKeys)
            assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
            fixture.manager.stop().getOrThrow()
            assertTrue(fixture.native.launches.mapNotNull { it.privateKeyPath }.none(Files::exists))
            assertEquals(keyB, Files.readString(Path.of(assertNotNull(credentials.privateKeyPathOrNull()))))
        }
    }

    @Test fun invalidSshPreparationRemovesOnlyCandidateKeyAndKeepsCommittedCredential() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val credentials = DesktopHomeSshCredentialStore(fixture.directory)
            val key = "-----BEGIN PRIVATE KEY-----\nfixture-A\n-----END PRIVATE KEY-----\n"
            val source = Path.of(credentials.importPrivateKey(key))
            val result = fixture.start("127.0.0.1",
                HomeSshRouteSettings(enabled = true, host = "ssh.example.test", user = "fixture"))
            assertTrue(result.isFailure) // Missing pinned host key fails after the credential capture.
            assertTrue(fixture.native.started.isEmpty())
            assertEquals(key, Files.readString(source))
            Files.list(fixture.directory.resolve("runtime")).use { assertEquals(0L, it.count()) }
        }
    }

    @Test fun failedAdmissionStaysPendingAndPreservesActualAUntilPinsClose() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            var allowClose = false
            var closeCalls = 0
            val pins = AutoCloseable { closeCalls++; if (!allowClose) throw WindowsInstallNativeFailure(32) }
            fixture.native.prepareFailure = DesktopWindowsRuntimeFailure("PERMISSION_DENIED", retainedAdmission = pins)
            val pending = CompletableDeferred<ControlCode>()
            val operation = async(DesktopOperationProgress { if (it != null) pending.complete(it) }) {
                fixture.start("127.0.0.2")
            }
            try {
                val observed = withTimeout(5000) {
                    kotlinx.coroutines.selects.select<ControlCode> {
                        pending.onAwait { it }
                        operation.onAwait { result ->
                            kotlin.test.fail("Preparation completed before native pin closure: " +
                                "code=${result.exceptionOrNull()?.message}, closeCalls=$closeCalls")
                        }
                    }
                }
                assertEquals(ControlCode.OUTCOME_UNKNOWN, observed)
                assertTrue(operation.isActive)
                assertEquals(actual.processId, fixture.manager.currentProcessId())
                assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
                allowClose = true
                assertEquals("PERMISSION_DENIED", withTimeout(5000) { operation.await() }.exceptionOrNull()?.message)
                assertTrue(closeCalls >= 2)
                assertEquals(actual.processId, fixture.manager.currentProcessId())
            } finally { allowClose = true; operation.cancelAndJoin() }
        }
    }

    @Test fun transientNativeReaderCleanupRetainsOwnershipUntilTheExactHandleCloses() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val child = fixture.native.started.single()
            child.closeFailure = WindowsInstallNativeFailure(32)
            val pending = CompletableDeferred<ControlCode>()
            val confirmed = java.util.concurrent.atomic.AtomicBoolean(false)
            val operation = async(DesktopOperationProgress { code ->
                if (code == null) confirmed.set(true) else pending.complete(code)
            }) { fixture.manager.stop() }
            assertEquals(ControlCode.OUTCOME_UNKNOWN, withTimeout(5000) { pending.await() })
            assertTrue(operation.isActive)
            assertFalse(child.isAlive)
            assertFalse(confirmed.get())
            assertEquals(actual.configJson, fixture.store.readRuntimeConfig(),
                "A transient reader discarded the retained launch before native disposal completed")
            withTimeout(5000) { operation.await() }.getOrThrow()
            assertEquals(2, child.closeCalls)
            assertTrue(confirmed.get())
            assertEquals(null, fixture.store.readRuntimeConfig())
            assertEquals(1, fixture.native.started.size)
            assertFalse(fixture.manager.isRunning())
        }
    }

    @Test fun committedRuntimeCarriesResourceWarningWithoutRollingBackKnownB() = runBlocking {
        runtimeTransitionFixture { fixture ->
            fixture.start("127.0.0.1").getOrThrow()
            val warning = DesktopRuntimeResourceWarning(ControlCode.PERSISTENCE_FAILED,
                "00000000-0000-0000-0000-000000000041", DesktopRuntimeResourceDisposition.COMMITTED_CLEANUP_PENDING)
            fixture.native.nextResourceWarnings = listOf(warning)
            val next = fixture.start("127.0.0.2").getOrThrow()
            assertEquals(listOf(warning), next.resourceWarnings)
            assertEquals(next.processId, fixture.manager.currentProcessId())
            assertEquals(next.configJson, fixture.store.readRuntimeConfig())
            assertTrue(fixture.manager.isRunning())
            assertEquals(2, fixture.native.started.size)
            assertFalse(fixture.native.started.first().isAlive)
        }
    }

    @Test fun confirmedStopPublicationFailureDoesNotBecomeUnknownLiveChild() = runBlocking {
        runtimeTransitionFixture { fixture ->
            fixture.start("127.0.0.1").getOrThrow()
            val warning = DesktopRuntimeResourceWarning(ControlCode.PERMISSION_DENIED,
                "00000000-0000-0000-0000-000000000041", DesktopRuntimeResourceDisposition.PENDING_PUBLICATION)
            fixture.native.started.single().closeFailure = DesktopRuntimeResourcePublicationFailure(listOf(warning))
            var unknownReported = false
            val result = kotlinx.coroutines.withContext(DesktopOperationProgress { if (it != null) unknownReported = true }) {
                fixture.manager.stop()
            }
            val failure = assertNotNull(result.exceptionOrNull() as? DesktopRuntimeResourcePublicationFailure)
            assertTrue(failure.runtimeStopped)
            assertEquals(listOf(warning), failure.warnings)
            assertFalse(unknownReported, "Known child exit was turned into a pending native operation")
            assertFalse(fixture.manager.isRunning())
            assertEquals(null, fixture.store.readRuntimeConfig())
        }
    }

    @Test fun uncertainPreparedChildStaysPendingUntilItsExactExitIsConfirmed() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val uncertain = FakeManagerRuntimeProcess(9001).also { it.refuseStop = true }
            fixture.native.prepareFailure = DesktopWindowsRuntimeFailure("OUTCOME_UNKNOWN", uncertain)
            val pending = CompletableDeferred<ControlCode>()
            val confirmed = java.util.concurrent.atomic.AtomicBoolean(false)
            val operation = async(DesktopOperationProgress { code ->
                if (code == null) confirmed.set(true) else pending.complete(code)
            }) { fixture.start("127.0.0.2") }
            try {
                assertEquals(ControlCode.OUTCOME_UNKNOWN, withTimeout(5000) { pending.await() })
                assertTrue(operation.isActive)
                assertFalse(confirmed.get())
                assertEquals(actual.processId, fixture.manager.currentProcessId())
                uncertain.refuseStop = false
                val result = withTimeout(5000) { operation.await() }
                assertEquals("RUNTIME_FAILED", result.exceptionOrNull()?.message,
                    "A confirmed abort must not leave a terminal unknown outcome")
                val ledger = com.kardinal.vpncontrol.control.ControlOperationLedger("fixture-owner")
                ledger.admit("fixture-operation", "fixture-request",
                    com.kardinal.vpncontrol.model.ControlOperationId.ON,
                    "fixture-fingerprint", true, true, 0)
                val terminal = ledger.complete("fixture-operation",
                    com.kardinal.vpncontrol.model.ControlResult("fixture-owner", "fixture-request",
                        ControlCode.valueOf(result.exceptionOrNull()!!.message!!), 0,
                        operationId = "fixture-operation"), 1)
                assertTrue(terminal.phase.terminal, "Confirmed native failure did not release the public ledger")
                assertTrue(confirmed.get())
                assertFalse(uncertain.isAlive)
                assertEquals(actual.processId, fixture.manager.currentProcessId())
            } finally {
                uncertain.refuseStop = false
                operation.cancelAndJoin()
            }
        }
    }

    @Test fun cancellationAfterPreparationPreservesActualAAndReturnsEstablishedMetadata() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val observed = java.util.concurrent.atomic.AtomicReference<Result<DesktopRuntimeSession>?>(null)
            val caller = launch {
                val originalJob = currentCoroutineContext()[Job]!!
                fixture.native.onPrepare = { originalJob.cancel() }
                observed.set(fixture.start("127.0.0.2"))
            }
            withTimeout(5000) { caller.join() }
            assertEquals("CANCELLED", assertNotNull(observed.get()).exceptionOrNull()?.message)
            assertEquals(actual.processId, fixture.manager.currentProcessId())
            assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
            assertEquals(1, fixture.native.cancelledPreparations)
            assertEquals(1, fixture.native.started.size)
        }
    }

    @Test fun cancellationDuringCandidateReadinessRecoversAAndReturnsItsNewIdentity() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val entered = CompletableDeferred<Unit>()
            fixture.native.onReadiness = { launch ->
                if (launch.configJson.contains("127.0.0.2")) {
                    entered.complete(Unit)
                    awaitCancellation()
                }
            }
            val observed = java.util.concurrent.atomic.AtomicReference<Result<DesktopRuntimeSession>?>(null)
            val caller = launch { observed.set(fixture.start("127.0.0.2")) }
            try {
                withTimeout(5000) { entered.await() }
                caller.cancelAndJoin()
                val failure = assertNotNull(observed.get()).exceptionOrNull() as? DesktopRuntimeTransitionFailure
                assertNotNull(failure)
                assertEquals(ControlCode.CANCELLED, failure.originalCode)
                val recovered = assertNotNull(failure.recoveredSession)
                assertNotEquals(actual.processId, recovered.processId)
                assertEquals(recovered.processId, fixture.manager.currentProcessId())
                assertEquals(actual.configJson, recovered.configJson)
                assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
                assertTrue(fixture.native.started.single { it.pid() == recovered.processId }.isAlive)
                assertTrue(fixture.native.started.filter { it.pid() != recovered.processId }.none { it.isAlive })
            } finally { caller.cancelAndJoin() }
        }
    }

    @Test fun deniedCandidatePreservesActualChildConfigurationAndLog() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val original = fixture.native.started.single()
            val configuration = fixture.store.readRuntimeConfig()
            Files.writeString(actual.logFile, "original active log")
            fixture.native.prepareFailure = DesktopWindowsRuntimeFailure("CANCELLED")
            val result = fixture.start("127.0.0.2")
            assertTrue(original.isAlive, "Preparing B stopped actual A")
            assertEquals(actual.processId, fixture.manager.currentProcessId())
            assertEquals(configuration, fixture.store.readRuntimeConfig())
            assertEquals(configuration, Files.readString(fixture.native.launches.first().configPath))
            assertEquals("original active log", Files.readString(actual.logFile))
            assertEquals("CANCELLED", result.exceptionOrNull()?.message)
        }
    }

    @Test fun invalidCandidatePreservesActualChildAndPublishedInputs() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            val configuration = fixture.store.readRuntimeConfig()
            Files.writeString(actual.logFile, "original validation log")
            fixture.native.preflightFailure = true
            assertTrue(fixture.start("127.0.0.2").isFailure)
            assertTrue(fixture.manager.isRunning())
            assertEquals(actual.processId, fixture.manager.currentProcessId())
            assertEquals(configuration, fixture.store.readRuntimeConfig())
            assertEquals("original validation log", Files.readString(actual.logFile))
            assertEquals(1, fixture.native.prepares)
        }
    }

    @Test fun failedCommittedCandidateRecoversExactActualInputsWithNewRuntimeIdentity() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            Files.writeString(actual.logFile, "actual A log")
            fixture.native.rejectCandidateReadiness = true
            val result = fixture.start("127.0.0.2")
            assertTrue(fixture.manager.isRunning(), "Failed B did not recover actual A")
            val failure = result.exceptionOrNull() as? DesktopRuntimeTransitionFailure
            assertNotNull(failure)
            val recovered = assertNotNull(failure.recoveredSession)
            assertFalse(failure.recoveryFailed)
            assertNotEquals(actual.processId, recovered.processId)
            assertEquals(recovered.processId, fixture.manager.currentProcessId())
            assertEquals(actual.configJson, recovered.configJson)
            assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
            assertEquals(actual.managementProxyPort, recovered.managementProxyPort)
            assertEquals("actual A log", Files.readString(recovered.logFile))
            assertEquals(3, fixture.native.prepares)
            assertFalse(fixture.native.started[1].isAlive)
        }
    }

    @Test fun candidateReadinessResourceFailureKeepsOwnershipAndRecoversActualA() = runBlocking {
        runtimeTransitionFixture { fixture ->
            val actual = fixture.start("127.0.0.1").getOrThrow()
            fixture.native.onReadiness = { launch ->
                if (launch.configJson.contains("127.0.0.2")) throw OutOfMemoryError("readiness fixture")
            }
            val invocation = runCatching { fixture.start("127.0.0.2") }
            assertTrue(invocation.isSuccess, "Resource failure escaped with owned candidate still alive: " +
                "failure=${invocation.exceptionOrNull()?.javaClass?.simpleName}, " +
                "livePids=${fixture.native.started.filter { it.isAlive }.map { it.pid() }}")
            val failure = assertNotNull(invocation.getOrThrow().exceptionOrNull() as? DesktopRuntimeTransitionFailure)
            assertEquals(ControlCode.RUNTIME_FAILED, failure.originalCode)
            assertFalse(failure.recoveryFailed)
            val recovered = assertNotNull(failure.recoveredSession)
            assertNotEquals(actual.processId, recovered.processId)
            assertEquals(actual.configJson, recovered.configJson)
            assertEquals(actual.configJson, fixture.store.readRuntimeConfig())
            assertEquals(recovered.processId, fixture.manager.currentProcessId())
            assertEquals(listOf(recovered.processId), fixture.native.started.filter { it.isAlive }.map { it.pid() })
        }
    }

    @Test fun failedRecoveryIsExplicitAndLeavesNoClaimedRunningCandidate() = runBlocking {
        runtimeTransitionFixture { fixture ->
            fixture.start("127.0.0.1").getOrThrow()
            fixture.native.rejectCandidateReadiness = true
            fixture.native.rejectRecovery = true
            val result = fixture.start("127.0.0.2")
            val failure = result.exceptionOrNull() as? DesktopRuntimeTransitionFailure
            assertNotNull(failure)
            assertTrue(failure.recoveryFailed)
            assertEquals("ROLLBACK_FAILED", failure.message)
            assertEquals(ControlCode.RUNTIME_FAILED, failure.originalCode)
            assertFalse(fixture.manager.isRunning())
            assertTrue(fixture.native.started.none { it.isAlive })
        }
    }

    @Test
    fun windowsRouteDnsToolingAllowsForColdPowerShellStartup() {
        val observedTimeouts = mutableListOf<Long>()

        val check = windowsRouteDnsToolingCheck { _, timeoutSeconds ->
            observedTimeouts += timeoutSeconds
            DesktopCommandResult(
                exitCode = if (timeoutSeconds >= 15L) 0 else -1,
                output = "",
            )
        }

        assertEquals(DesktopPreflightStatus.PASS, check.status)
        assertEquals(listOf(15L, 15L), observedTimeouts)
    }

    @Test
    fun windowsVpnCapabilityRequiresAdministratorPrivileges() {
        val tempDir = Files.createTempDirectory("vpn-control-windows-vpn-not-admin")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Windows 11",
                windowsAdministratorOverride = false,
            )

            assertContains(
                manager.desktopVpnCapabilityStatus(),
                "Windows VPN mode needs Administrator privileges",
            )
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windowsVpnCapabilityPassesWhenAdministratorPrivilegesAreAvailable() {
        val tempDir = Files.createTempDirectory("vpn-control-windows-vpn-admin")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Windows 11",
                windowsAdministratorOverride = true,
            )

            assertEquals(
                RuntimeStatusMessages.desktopVpnCapabilityReady(),
                manager.desktopVpnCapabilityStatus(),
            )
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun macosVpnCapabilityExplainsProxyOnlyFallback() {
        val tempDir = Files.createTempDirectory("vpn-control-macos-vpn")
        try {
            val manager = DesktopProxyRuntimeManager(
                runtimeConfigStore = InMemoryRuntimeConfigStore(),
                baseDir = tempDir,
                runtimeOsNameOverride = "Mac OS X",
            )

            val status = manager.desktopVpnCapabilityStatus()
            assertContains(status, "macOS VPN mode needs a privileged Network Extension helper")
            assertContains(status, "Proxy-only mode")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linuxVpnCapabilityFailureNamesResolvedSingBoxBinary() {
        val binaryPath = Path.of("opt", "vpn-control", "bin", "sing-box")
        val resolvedPath = binaryPath.toAbsolutePath().normalize().toString()
        val detail = linuxNetworkPrivilegesMissingDetail(
            DesktopSingBoxExecutable(
                path = binaryPath,
                source = "VPN_CONTROL_SING_BOX",
            ),
        )

        assertContains(detail, resolvedPath)
        assertContains(detail, "VPN_CONTROL_SING_BOX")
        assertContains(detail, "sudo setcap cap_net_admin,cap_net_raw+ep")
        assertContains(detail, "'$resolvedPath'")
        assertFalse(detail.contains("command -v sing-box"))
    }

    @Test
    fun linuxVpnCapabilityRequiresBothInstalledCapabilities() {
        assertFalse(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_admin=ep"))
        assertFalse(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_raw=ep"))
        assertTrue(linuxNetworkCapabilitiesAvailable("/opt/vpn-control/bin/sing-box cap_net_admin,cap_net_raw=ep"))
    }

    @Test
    fun linuxTunMissingDetailExplainsKernelModuleMismatch() {
        val modulesRoot = Files.createTempDirectory("vpn-control-modules-root")
        try {
            Files.createDirectories(modulesRoot.resolve("7.0.3-arch1-2"))

            val detail = linuxTunBackendMissingDetail(
                currentKernel = "6.19.14-arch1-1",
                modulesRoot = modulesRoot,
            )

            assertContains(detail, "/dev/net/tun")
            assertContains(detail, "6.19.14-arch1-1")
            assertContains(detail, "7.0.3-arch1-2")
            assertContains(detail, "Reboot into an installed kernel")
            assertContains(detail, "sudo modprobe tun")
        } finally {
            modulesRoot.toFile().deleteRecursively()
        }
    }

    @Test
    fun linuxTunMissingDetailKeepsSimpleModprobeGuidanceWhenModulesExist() {
        val modulesRoot = Files.createTempDirectory("vpn-control-modules-root")
        try {
            Files.createDirectories(modulesRoot.resolve("6.19.14-arch1-1"))

            val detail = linuxTunBackendMissingDetail(
                currentKernel = "6.19.14-arch1-1",
                modulesRoot = modulesRoot,
            )

            assertContains(detail, "/dev/net/tun")
            assertContains(detail, "sudo modprobe tun")
            assertFalse(detail.contains("Reboot into an installed kernel"))
        } finally {
            modulesRoot.toFile().deleteRecursively()
        }
    }
}

private class RuntimeTransitionFixture(val directory: Path) {
    val store = InMemoryRuntimeConfigStore()
    val native = FakeRuntimeManagerNative()
    val manager = DesktopProxyRuntimeManager(store, directory.resolve("runtime"), native)
    suspend fun start(server: String, ssh: HomeSshRouteSettings = HomeSshRouteSettings()) = manager.start(
        com.kardinal.vpncontrol.data.LocationConfigs.decodeStoredLocation("socks://$server:1080#Fixture"),
        RoutingRules(), DnsSettings(), AppMode.PROXY_ONLY, null, ssh,
    )
}

private suspend fun runtimeTransitionFixture(action: suspend (RuntimeTransitionFixture) -> Unit) {
    val directory = Files.createTempDirectory("vpn-control-runtime-transition-")
    val fixture = RuntimeTransitionFixture(directory)
    try { action(fixture) }
    finally { fixture.manager.stop(); directory.toFile().deleteRecursively() }
}

private class FakeRuntimeManagerNative : DesktopRuntimeManagerNative {
    var prepareFailure: Exception? = null
    var preflightFailure = false
    var rejectCandidateReadiness = false
    var rejectRecovery = false
    var prepares = 0
    var cancelledPreparations = 0
    var onPrepare: ((DesktopRuntimeLaunch) -> Unit)? = null
    var onReadiness: (suspend (DesktopRuntimeLaunch) -> Unit)? = null
    var nextResourceWarnings: List<DesktopRuntimeResourceWarning> = emptyList()
    val launches = mutableListOf<DesktopRuntimeLaunch>()
    val started = mutableListOf<FakeManagerRuntimeProcess>()
    override fun preflight(launch: DesktopRuntimeLaunch) = DesktopPreflightReport(launch.appMode,
        listOf(DesktopPreflightCheck("fixture validation",
            if (preflightFailure) DesktopPreflightStatus.FAIL else DesktopPreflightStatus.PASS, "fixture")))
    override fun prepare(launch: DesktopRuntimeLaunch): DesktopPreparedRuntimeProcess {
        prepares++
        onPrepare?.invoke(launch)
        prepareFailure?.let { throw it }
        if (rejectRecovery && prepares == 3) throw DesktopWindowsRuntimeFailure("PERMISSION_DENIED")
        launches += launch
        return object : DesktopPreparedRuntimeProcess {
            private var closed = false
            override fun commit(): DesktopRuntimeProcess {
                check(!closed); closed = true
                return FakeManagerRuntimeProcess(1000L + prepares).also {
                    it.resourceWarnings = nextResourceWarnings
                    started += it
                }
            }
            override fun close() {
                if (!closed) cancelledPreparations++
                closed = true
            }
        }
    }
    override suspend fun awaitReady(process: DesktopRuntimeProcess, launch: DesktopRuntimeLaunch): Boolean {
        onReadiness?.invoke(launch)
        return !rejectCandidateReadiness || !launch.configJson.contains("127.0.0.2")
    }
}

private class FakeManagerRuntimeProcess(private val identity: Long) : DesktopRuntimeProcess {
    @Volatile override var isAlive = true
    @Volatile var refuseStop = false
    override var resourceWarnings: List<DesktopRuntimeResourceWarning> = emptyList()
    var closeFailure: Exception? = null
    var closeCalls = 0
    override fun pid() = identity
    override fun destroy() { if (!refuseStop) isAlive = false }
    override fun destroyForcibly() { if (!refuseStop) isAlive = false }
    override fun waitFor(timeout: Long, unit: TimeUnit) = !isAlive
    override fun close() { closeCalls++; closeFailure?.let { closeFailure = null; throw it } }
}

private class InMemoryRuntimeConfigStore : com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore {
    private var config: String? = null

    override suspend fun readRuntimeConfig(): String? = config

    override suspend fun writeRuntimeConfig(configJson: String) {
        config = configJson
    }

    override suspend fun clearRuntimeConfig() {
        config = null
    }
}
