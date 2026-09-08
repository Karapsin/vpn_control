package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlRuntimeConfiguration
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.data.AndroidDirectDomainRuleSetStore
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidRuntimeObserverTest {
    @Test fun restorepointLeaseProtectsStoppedRuntimeAssetUntilRecoveryReleasesIt() = temporaryRuleSetStore { store ->
        val observer = AndroidRuntimeObserver()
        val a = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))))
        val configuration = ControlRuntimeConfiguration.committed(MainUiState(appMode = AppMode.VPN))
        observer.started(Any(), AppMode.VPN, "runtime-a", configuration, a)
        val point = requireNotNull(observer.captureRuntime())

        observer.resetCompleted(true)
        val b = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("b.test"))))
        observer.started(Any(), AppMode.VPN, "runtime-b", ruleSetLease = b)
        observer.resetCompleted(true)
        store.prune(emptySet())
        assertTrue(File(a.path).isFile)
        assertFalse(File(b.path).exists())

        point.close()
        point.close()
        store.prune(emptySet())
        assertFalse(File(a.path).exists())
    }

    @Test fun failedCleanupAndDuplicateStartKeepOnlyTheAdoptedRuleSetLease() = temporaryRuleSetStore { store ->
        val observer = AndroidRuntimeObserver()
        val active = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("active.test"))))
        val handle = Any()
        observer.started(handle, AppMode.VPN, "runtime", ruleSetLease = active)
        val duplicate = store.acquire(active.path)
        observer.started(handle, AppMode.VPN, "runtime", ruleSetLease = duplicate)
        val uncertain = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("uncertain.test"))))
        observer.started(Any(), AppMode.VPN, "runtime-uncertain", ruleSetLease = uncertain)
        store.prune(emptySet())
        assertFalse("A duplicate observation must close its unadopted lease", File(active.path).exists())
        assertTrue(File(uncertain.path).isFile)

        observer.resetCompleted(false)
        assertEquals(AndroidRuntimeKnowledge.UNKNOWN, observer.state.value.knowledge)
        val failedStart = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("failed-start.test"))))
        observer.retainUncertainRuleSet(failedStart)
        val rejected = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("rejected.test"))))
        observer.started(Any(), AppMode.VPN, "runtime-rejected", ruleSetLease = rejected)
        store.prune(emptySet())
        assertTrue("Unknown native cleanup must retain its staged asset", File(uncertain.path).isFile)
        assertTrue("A failed start must retain its staged asset after unknown cleanup", File(failedStart.path).isFile)
        assertFalse("The observer must close a lease it cannot adopt", File(rejected.path).exists())
    }

    @Test fun processStartsUnknownAndSuccessfulNativeStartPublishesImmutableIdentity() {
        var now = 1000L
        var sequence = 0
        val observer = AndroidRuntimeObserver({ now }, { "runtime-${++sequence}" })
        assertEquals(AndroidRuntimeKnowledge.UNKNOWN, observer.state.value.knowledge)
        observer.resetCompleted(true)
        assertEquals(AndroidRuntimeKnowledge.STOPPED, observer.state.value.knowledge)
        val handle = Any()
        observer.started(handle, AppMode.PROXY_ONLY, "private-config")
        val first = observer.state.value
        assertEquals("runtime-1", first.runtimeId)
        assertEquals(1000L, first.startedAtEpochMillis)
        assertEquals(AppMode.PROXY_ONLY, first.activeMode)
        assertFalse(first.toString().contains("private-config"))
        now = 2000
        observer.started(handle, AppMode.PROXY_ONLY, "private-config")
        assertSame(first, observer.state.value)
        observer.resetCompleted(true)
        observer.started(Any(), AppMode.PROXY_ONLY, "private-config")
        assertNotEquals(first.runtimeId, observer.state.value.runtimeId)
        assertEquals(first.configurationId, observer.state.value.configurationId)
        val otherProcess = AndroidRuntimeObserver()
        otherProcess.started(Any(), AppMode.PROXY_ONLY, "private-config")
        assertNotEquals(first.configurationId, otherProcess.state.value.configurationId)
    }

    @Test fun stopRevokeAndFailedStartCleanupClearActiveIdentityAndAreIdempotent() {
        for (event in listOf("stop", "revoke", "failed-start")) {
            val observer = AndroidRuntimeObserver()
            observer.started(Any(), AppMode.VPN, event)
            observer.resetCompleted(true)
            val stopped = observer.state.value
            assertEquals(AndroidRuntimeKnowledge.STOPPED, stopped.knowledge)
            assertNull(stopped.runtimeId)
            assertNull(stopped.activeMode)
            assertNull(stopped.configurationId)
            observer.resetCompleted(true)
            assertSame(stopped, observer.state.value)
        }
    }

    @Test fun failedNativeCloseNeverFabricatesAnOffOrKnownSingleRuntime() {
        val observer = AndroidRuntimeObserver()
        observer.started(Any(), AppMode.VPN, "config")
        observer.resetCompleted(false)
        assertEquals(AndroidRuntimeKnowledge.UNKNOWN, observer.state.value.knowledge)
        observer.resetCompleted(true)
        observer.started(Any(), AppMode.VPN, "replacement")
        assertEquals(AndroidRuntimeKnowledge.UNKNOWN, observer.state.value.knowledge)
    }

    @Test fun providerUsesLiveObservationRatherThanStalePersistedFlagAndMode() = runTest {
        val observer = AndroidRuntimeObserver({ 1000 })
        val reader = AndroidControlReader("owner", { PersistedState(isVpnRunning = false, appMode = AppMode.VPN,
            sessionStartedAtEpochMillis = 100, sessionStoppedAtEpochMillis = 200) },
            clockMillis = { 5000 }, runtimeObservation = { observer.state.value })
        val request = ControlRequest("stats", ControlCommand(ControlOperationId.STATS))
        assertEquals(ControlValue.Null, reader.read(request).data["running"])
        observer.started(Any(), AppMode.PROXY_ONLY, "config")
        val stats = reader.read(request).data
        assertEquals(ControlValue.BooleanValue(true), stats["running"])
        assertEquals(ControlValue.IntegerValue(4000), stats["elapsedMillis"])
        assertEquals(ControlValue.Text("proxy-only"), stats["activeMode"])
        assertEquals(ControlValue.IntegerValue(100), stats["startedAtEpochMillis"])
        assertEquals(ControlValue.IntegerValue(200), stats["stoppedAtEpochMillis"])
        assertEquals(ControlValue.IntegerValue(1000), stats["runtimeStartedAtEpochMillis"])
        val firstFrontend = observer.state.value.applyKnownState(MainUiState(isVpnRunning = false))
        val replacementFrontend = observer.state.value.applyKnownState(MainUiState(isVpnRunning = false))
        assertTrue(firstFrontend.isVpnRunning)
        assertEquals(firstFrontend.sessionStartedAtEpochMillis, replacementFrontend.sessionStartedAtEpochMillis)
        observer.resetCompleted(true)
        assertEquals(ControlValue.BooleanValue(false), reader.read(request).data["running"])
        assertEquals(ControlValue.Null, reader.read(request).data["runtimeId"])
        assertEquals(ControlValue.Null, reader.read(request).data["runtimeStartedAtEpochMillis"])
        assertEquals(ControlValue.IntegerValue(100), reader.read(request).data["startedAtEpochMillis"])
    }

    private fun temporaryRuleSetStore(block: (AndroidDirectDomainRuleSetStore) -> Unit) {
        val directory = Files.createTempDirectory("observer-rule-set-").toFile()
        try {
            block(AndroidDirectDomainRuleSetStore(directory))
        } finally {
            directory.deleteRecursively()
        }
    }

}
