package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import org.junit.Test

class AndroidSettingsActionsServiceTest {
    @Test fun staleSshSaveKeepsVisibleTypedFailureWithUnsavedInput() {
        val controller = MainController()
        val statuses = mutableListOf<String>()
        val requests = mutableListOf<com.kardinal.vpncontrol.model.ControlRequest>()
        val draft = AndroidSshDraftControl({ com.kardinal.vpncontrol.control.ControlCommitted("owner", 4,
            com.kardinal.vpncontrol.model.PersistedState(homeSshRouteSettings =
                com.kardinal.vpncontrol.model.HomeSshRouteSettings(host = "committed-host"))) }, { request ->
            requests += request
            com.kardinal.vpncontrol.model.ControlResult(controllerId = "owner", requestId = request.requestId,
                code = com.kardinal.vpncontrol.model.ControlCode.CONFLICT, configurationRevision = 5)
        })
        val service = service(controller, sshDraft = draft, updateStatus = { statuses += it })
        service.toggleHomeSshRouteDialog()
        service.updateHomeSshDraft { it.copy(homeSshHostDraft = "unsaved.invalid") }
        service.saveHomeSshRoute()
        val failure = SettingsStatusMessages.homeSshSettingsInvalid("CONFLICT")
        assertEquals(failure, controller.currentState().homeSshDraftFailure)
        assertEquals(listOf(failure), statuses)
        assertEquals("unsaved.invalid", controller.currentState().homeSshHostDraft)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        assertEquals(4L, requests.single().ifRevision)
    }

    @Test fun editingAndReopeningSshDraftClearPriorFeedback() {
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true,
            homeSshDraftFailure = SettingsStatusMessages.homeSshSettingsInvalid("CONFLICT")))
        val service = service(controller)
        service.updateHomeSshDraft { it.copy(homeSshHostDraft = "new-input") }
        org.junit.Assert.assertNull(controller.currentState().homeSshDraftFailure)
        controller.update { it.copy(homeSshDraftFailure = SettingsStatusMessages.homeSshSettingsInvalid("CONFLICT")) }
        service.toggleHomeSshRouteDialog()
        service.toggleHomeSshRouteDialog()
        org.junit.Assert.assertNull(controller.currentState().homeSshDraftFailure)
    }

    @Test fun sshImportResponseFailureNeverCopiesPrivateExceptionTextIntoStatus() {
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true, homeSshHostDraft = "unsaved-host"))
        val statuses = mutableListOf<String>()
        service(controller, updateStatus = { statuses += it }, importKey = { privateInput ->
            throw java.io.IOException("Private input: $privateInput")
        }).importHomeSshPrivateKey("PRIVATE_TEST_KEY_MATERIAL")
        assertEquals(listOf(SettingsStatusMessages.homeSshPrivateKeyImportFailed("OUTCOME_UNKNOWN")), statuses)
        assertEquals(statuses.single(), controller.currentState().homeSshDraftFailure)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        assertEquals("unsaved-host", controller.currentState().homeSshHostDraft)
    }
    @Test fun unchangedSshSaveCannotClearImportedKeyRestartWarning() {
        val settings = com.kardinal.vpncontrol.model.HomeSshRouteSettings(credentialVersion = 1)
        val controller = MainController(MainUiState(isVpnRunning = true, homeSshRouteSettings = settings,
            homeSshRestartPending = true, showHomeSshRouteDialog = true))
        var writtenVersion: Long? = null
        service(controller, updateHomeSshRouteSettings = { writtenVersion = it.credentialVersion },
            homeSshPendingRestart = { assertEquals(1L, writtenVersion); true }).saveHomeSshRoute()
        assertEquals(1L, writtenVersion)
        assertTrue(controller.currentState().homeSshRestartPending)
        assertTrue(controller.currentState().showHomeSshRestartDialog)
    }
    @Test fun actualRevertClearsWarningButUnknownRuntimeCannotClearIt() {
        for (knownPending in listOf(false, true, null)) {
            val controller = MainController(MainUiState(isVpnRunning = true, homeSshRestartPending = true,
                showHomeSshRouteDialog = true, showHomeSshRestartDialog = true,
                homeSshRouteSettings = com.kardinal.vpncontrol.model.HomeSshRouteSettings(credentialVersion = 4)))
            var saved = false
            service(controller, updateHomeSshRouteSettings = { saved = true; assertEquals(4, it.credentialVersion) },
                homeSshPendingRestart = { assertTrue(saved); knownPending }).saveHomeSshRoute()
            assertEquals(knownPending ?: true, controller.currentState().homeSshRestartPending)
            assertEquals(knownPending ?: true, controller.currentState().showHomeSshRestartDialog)
            assertEquals(4, controller.currentState().homeSshRouteSettings.credentialVersion)
            org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
        }
    }
    @Test fun failedPostSaveObservationIsConservativeWithoutUndoingCommittedSave() {
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true))
        var writes = 0
        service(controller, updateHomeSshRouteSettings = { writes++ },
            homeSshPendingRestart = { throw java.io.IOException("PRIVATE_FAILURE") }).saveHomeSshRoute()
        assertEquals(1, writes)
        assertTrue(controller.currentState().homeSshRestartPending)
        assertTrue(controller.currentState().showHomeSshRestartDialog)
        org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun sshSaveKeepsDraftOnBusyAndOwnsLeaseUntilPersistenceCompletes() = kotlinx.coroutines.test.runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        val controller = MainController(MainUiState(showHomeSshRouteDialog = true))
        var writes = 0
        val service = service(controller, launchMutation = { jobs.launchMutation(it) },
            updateHomeSshRouteSettings = { writes++; gate.await() })
        val lease = requireNotNull(jobs.tryAcquireMutation())
        service.saveHomeSshRoute()
        service.importHomeSshPrivateKey("not-a-real-key")
        runCurrent()
        assertEquals(0, writes)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        jobs.releaseMutation(lease)
        service.saveHomeSshRoute()
        runCurrent()
        assertEquals(1, writes)
        assertTrue(controller.currentState().showHomeSshRouteDialog)
        jobs.cancelActive()
        org.junit.Assert.assertNull(jobs.tryAcquireMutation())
        gate.complete(Unit)
        runCurrent()
        org.junit.Assert.assertFalse(controller.currentState().showHomeSshRouteDialog)
        org.junit.Assert.assertFalse(jobs.busy.value)
    }
    @Test
    fun setSessionStatsEnabledPersistsAndReportsStatus() {
        val controller = MainController()
        val statuses = mutableListOf<String>()
        var persisted: Boolean? = null
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            updateSessionStatsEnabled = { persisted = it },
        )

        service.setSessionStatsEnabled(true)

        assertTrue(controller.currentState().sessionStatsEnabled)
        assertEquals(true, persisted)
        assertEquals(
            listOf(SettingsStatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true)),
            statuses,
        )
    }

    @Test fun stoppedModePersistsThroughTypedOwner() = ModeFixture(running = false).use { f ->
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals(0, f.stopCalls)
        assertEquals(1, f.writes)
        assertEquals(1L, f.result!!.configurationRevision)
        assertFalse(f.result!!.restartRequired)
        assertEquals(AppMode.PROXY_ONLY, f.controller.currentState().appMode)
        assertEquals(ControlOperationId.SETTINGS_SET, f.requests.single().command.operation)
        assertEquals("owner", f.requests.single().controllerId)
        assertEquals(0L, f.requests.single().ifRevision)
    }

    @Test fun liveModeSaveKeepsRuntimeAndCommitsPendingConfiguration() = ModeFixture().use { f ->
        val live = f.observer.state.value
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals("GUI save must not stop A", 0, f.stopCalls)
        assertTrue(f.controller.currentState().isVpnRunning)
        assertEquals(live, f.observer.state.value)
        assertEquals(AppMode.VPN, f.observer.state.value.activeMode)
        assertEquals(AppMode.PROXY_ONLY, f.committed.value.appMode)
        assertEquals(AppMode.PROXY_ONLY, f.controller.currentState().appMode)
        assertFalse(f.controller.currentState().showAppModeDialog)
        assertEquals(ControlCode.OK, f.result!!.code)
        assertEquals(1L, f.result!!.configurationRevision)
        assertTrue(f.result!!.restartRequired)
        assertEquals(0, f.schedules)
    }

    @Test fun failedModePersistenceKeepsLiveRuntimeAndCommittedMode() = ModeFixture().use { f ->
        val live = f.observer.state.value
        f.failPersistence = true
        // The preserved legacy effect path throws directly; observe its state as well as the owner result.
        runCatching { f.service.setAppMode(AppMode.PROXY_ONLY) }
        assertEquals("Failed save must not first stop A", 0, f.stopCalls)
        assertEquals(live, f.observer.state.value)
        assertTrue(f.controller.currentState().isVpnRunning)
        assertTrue(f.controller.currentState().showAppModeDialog)
        assertEquals(AppMode.VPN, f.controller.currentState().appMode)
        assertEquals(AppMode.VPN, f.committed.value.appMode)
        assertEquals(0, f.writes)
        assertEquals(ControlCode.PERSISTENCE_FAILED, f.result!!.code)
        assertEquals(0L, f.result!!.configurationRevision)
        assertEquals(listOf("PERSISTENCE_FAILED"), f.statuses)
    }

    @Test fun busyModeSaveDoesNotEnterPersistenceOrChangeUi() = ModeFixture().use { f ->
        f.busy = true
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals(ControlCode.BUSY, f.result!!.code)
        assertEquals(0, f.writes)
        assertEquals(0, f.stopCalls)
        assertEquals(AppMode.VPN, f.controller.currentState().appMode)
        assertTrue(f.controller.currentState().showAppModeDialog)
        assertEquals(listOf("BUSY"), f.statuses)
    }

    @Test fun capturedModeRevisionCannotOverwriteAConcurrentCommit() = ModeFixture().use { f ->
        f.beforeExecute = { f.committed = f.committed.copy(revision = 1) }
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals(0L, f.requests.single().ifRevision)
        assertEquals(ControlCode.CONFLICT, f.result!!.code)
        assertEquals(1L, f.result!!.configurationRevision)
        assertEquals(AppMode.VPN, f.committed.value.appMode)
        assertEquals(AppMode.VPN, f.controller.currentState().appMode)
        assertEquals(0, f.stopCalls)
        assertEquals(0, f.writes)
    }

    @Test fun unknownRuntimeCannotCommitModeOrClaimStopped() = ModeFixture().use { f ->
        f.observer.resetCompleted(cleanupSucceeded = false)
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals(ControlCode.UNAVAILABLE, f.result!!.code)
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in f.result!!.warnings)
        assertEquals(0, f.writes)
        assertEquals(0, f.stopCalls)
        assertTrue(f.controller.currentState().isVpnRunning)
        assertEquals(AppMode.VPN, f.controller.currentState().appMode)
        assertEquals(AndroidRuntimeKnowledge.UNKNOWN, f.observer.state.value.knowledge)
    }

    @Test fun modeRevertClearsPendingWithoutReplacingLiveRuntime() = ModeFixture().use { f ->
        val live = f.observer.state.value
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertTrue(f.result!!.restartRequired)
        f.service.setAppMode(AppMode.VPN)
        assertFalse(f.result!!.restartRequired)
        assertEquals(2L, f.result!!.configurationRevision)
        f.service.setAppMode(AppMode.VPN)
        assertEquals(2, f.writes)
        assertEquals(2L, f.result!!.configurationRevision)
        assertEquals(live, f.observer.state.value)
        assertEquals(0, f.stopCalls)
        assertEquals(0, f.schedules)
    }

    @Test fun confirmedCommitWithUnknownPendingKeepsCommittedModeAndTruthfulFailure() = ModeFixture().use { f ->
        f.pendingUnknownAfterCommit = true
        val live = f.observer.state.value
        f.service.setAppMode(AppMode.PROXY_ONLY)
        assertEquals(ControlCode.RUNTIME_FAILED, f.result!!.code)
        assertEquals(ControlValue.BooleanValue(true), f.result!!.data["configurationCommitted"])
        assertEquals(1L, f.result!!.configurationRevision)
        assertTrue("PENDING_RESTART_STATE_UNAVAILABLE" in f.result!!.warnings)
        assertEquals(AppMode.PROXY_ONLY, f.controller.currentState().appMode)
        assertTrue(f.controller.currentState().showAppModeDialog)
        assertEquals(live, f.observer.state.value)
        assertEquals(0, f.stopCalls)
        assertEquals(listOf("RUNTIME_FAILED"), f.statuses)
    }

    @Test fun staleDnsSaveCannotOverwriteExternalCliCommitAndKeepsDraftVisible() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        assertEquals(ControlCode.OK, f.cliDns("https://cli.example.test/dns-query").code)
        f.project()
        assertEquals("https://draft.example.test/dns-query", f.controller.currentState().customDnsEndpointDraft)
        f.service.saveDns()
        assertEquals("https://cli.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
        assertEquals(1L, f.snapshot().revision)
        assertTrue(f.controller.currentState().showDnsDialog)
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertEquals("owner", f.guiRequests.single().controllerId)
        assertEquals(0L, f.guiRequests.single().ifRevision)
    }

    @Test fun staleDnsEpochCannotOverwriteRecreatedOwnerEvenWhenRevisionIsZero() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        f.cliDns("https://cli.example.test/dns-query")
        f.replaceOwner("replacement-owner")
        f.project()
        assertEquals(0L, f.snapshot().revision)
        f.service.saveDns()
        assertEquals("https://cli.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
        assertEquals(0L, f.snapshot().revision)
        assertTrue(f.controller.currentState().showDnsDialog)
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertEquals("owner", f.guiRequests.single().controllerId)
    }

    @Test fun dnsRevisionIsCheckedInsideActualStorageTransactionBeforeWrite() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        f.beforeCommit = {
            f.configuration.edit { prefs ->
                prefs[f.modeKey] = DnsMode.CUSTOM_DOH.name
                prefs[f.endpointKey] = "https://racing.example.test/dns-query"
            }
        }
        f.service.saveDns()
        assertEquals("https://racing.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
        assertEquals(1L, f.snapshot().revision)
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertTrue(f.controller.currentState().showDnsDialog)
    }

    @Test fun dnsSaveNormalizesThroughTypedOwnerAndLeavesLiveRuntimeUntouched() = DnsFixture().use { f ->
        val live = f.observer.state.value
        f.service.toggleDnsDialog()
        f.draft(" https://dns.example.test ")
        f.service.saveDns()
        assertEquals("https://dns.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
        assertEquals(1L, f.snapshot().revision)
        assertEquals(ControlOperationId.SETTINGS_APPLY, f.guiRequests.single().command.operation)
        assertEquals(1, f.ownerTransactions)
        assertEquals(0, f.legacyWrites)
        assertEquals(0, f.stopCalls)
        assertEquals(live, f.observer.state.value)
        assertTrue(f.results.single().restartRequired)
        assertFalse(f.controller.currentState().showDnsDialog)
        assertEquals(listOf(SettingsStatusMessages.dnsSettingsSaved(DnsMode.CUSTOM_DOH)), f.statuses)
    }

    @Test fun dnsBusySaveRetainsOpeningGuardAndCanRetryAfterLeaseRelease() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        val lease = requireNotNull(f.jobs.tryAcquireMutation())
        f.service.saveDns()
        assertEquals(listOf("BUSY"), f.statuses)
        assertEquals(0L, f.snapshot().revision)
        assertTrue(f.controller.currentState().showDnsDialog)
        f.jobs.releaseMutation(lease)
        f.service.saveDns()
        assertEquals(f.guiRequests[0], f.guiRequests[1])
        assertEquals(1L, f.snapshot().revision)
        assertFalse(f.controller.currentState().showDnsDialog)
    }

    @Test fun dnsPersistenceFailureRetainsDraftAndExactRequestWithoutRebasing() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        f.failPersistence = true
        f.service.saveDns()
        assertEquals(listOf("PERSISTENCE_FAILED"), f.statuses)
        assertEquals(0L, f.snapshot().revision)
        assertEquals(DnsSettings(), f.snapshot().value.dnsSettings)
        assertTrue(f.controller.currentState().showDnsDialog)
        f.failPersistence = false
        f.service.saveDns()
        assertEquals(f.guiRequests[0], f.guiRequests[1])
        assertEquals(listOf("PERSISTENCE_FAILED", "PERSISTENCE_FAILED"), f.statuses)
        assertEquals(0L, f.snapshot().revision)
        // A user closes and reopens a fresh draft before making a new attempt.
        f.service.toggleDnsDialog()
        f.service.toggleDnsDialog()
        f.draft("https://fresh.example.test/dns-query")
        f.service.saveDns()
        assertEquals(1L, f.snapshot().revision)
        assertFalse(f.controller.currentState().showDnsDialog)
        assertTrue(f.guiRequests[2].requestId != f.guiRequests[1].requestId)
    }

    @Test fun dnsLostResponseRetryRecoversSameOwnerResultWithoutSecondCommit() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        f.loseNextResponse = true
        f.service.saveDns()
        assertEquals(listOf("OUTCOME_UNKNOWN"), f.statuses)
        assertEquals(1L, f.snapshot().revision)
        assertTrue(f.controller.currentState().showDnsDialog)
        f.project()
        f.service.saveDns()
        assertEquals(f.guiRequests[0], f.guiRequests[1])
        assertEquals(f.results[0], f.results[1])
        assertEquals(1, f.ownerTransactions)
        assertEquals(1L, f.snapshot().revision)
        assertFalse(f.controller.currentState().showDnsDialog)
        assertFalse(f.statuses.any { it.contains("PRIVATE") })
    }

    @Test fun dnsCommittedButUnknownPendingStateKeepsTruthfulFailureAndOpenDraft() = DnsFixture().use { f ->
        f.service.toggleDnsDialog()
        f.draft("https://draft.example.test/dns-query")
        f.unknownPendingAfterCommit = true
        f.service.saveDns()
        assertEquals(1L, f.snapshot().revision)
        assertEquals(ControlCode.RUNTIME_FAILED, f.results.single().code)
        assertEquals(ControlValue.BooleanValue(true), f.results.single().data["configurationCommitted"])
        assertEquals(listOf("RUNTIME_FAILED"), f.statuses)
        assertTrue(f.controller.currentState().showDnsDialog)
        assertEquals(0, f.stopCalls)
    }

    @Test fun dnsInvalidInputAndMissingOpeningGuardNeverReachPersistence() = DnsFixture().use { f ->
        f.draft("https://draft.example.test/dns-query")
        f.service.saveDns()
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertTrue(f.guiRequests.isEmpty())
        f.service.toggleDnsDialog()
        f.draft("https://PRIVATE@dns.example.test/dns-query")
        f.service.saveDns()
        assertEquals(SettingsStatusMessages.customDnsEndpointInvalid(), f.statuses.last())
        assertEquals(0L, f.snapshot().revision)
        assertTrue(f.controller.currentState().showDnsDialog)
        assertFalse(f.statuses.any { it.contains("PRIVATE") })
    }

    @Test fun dnsSnapshotFailureDoesNotOpenOrCreateAnUnguardedDraft() = DnsFixture().use { f ->
        f.failSnapshot = true
        f.service.toggleDnsDialog()
        assertFalse(f.controller.currentState().showDnsDialog)
        assertEquals(listOf("UNAVAILABLE"), f.statuses)
        f.failSnapshot = false
        f.draft("https://draft.example.test/dns-query")
        f.service.saveDns()
        assertEquals("CONFLICT", f.statuses.last())
        assertEquals(0L, f.snapshot().revision)
        assertTrue(f.guiRequests.isEmpty())
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun acceptedDnsSaveCompletionCannotCloseReplacementDialog() = kotlinx.coroutines.test.runTest {
        DnsFixture(frontendLaunch = { block -> launch { block() } }).use { f ->
            f.service.toggleDnsDialog()
            f.frontendCompletions.last().await()
            f.draft("https://accepted.example.test/dns-query")
            val admitted = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeCommit = { admitted.complete(Unit); release.await() }
            f.service.saveDns()
            val originalCompletion = f.frontendCompletions.last()
            admitted.await()
            f.service.toggleDnsDialog()
            f.service.toggleDnsDialog()
            f.frontendCompletions.last().await()
            f.draft("https://replacement.example.test/dns-query")
            release.complete(Unit)
            originalCompletion.await()
            assertEquals("https://accepted.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
            assertEquals(1L, f.snapshot().revision)
            assertTrue(f.controller.currentState().showDnsDialog)
            assertEquals("https://replacement.example.test/dns-query", f.controller.currentState().customDnsEndpointDraft)
            assertTrue(f.statuses.isEmpty())
            assertEquals(ControlCode.OK, f.operationStatus(f.guiRequests.single().requestId).code)
            assertEquals(1, f.ownerTransactions)
            // The replacement draft keeps its own earlier opening revision; it is never silently rebased.
            f.service.saveDns()
            f.frontendCompletions.last().await()
            assertEquals("CONFLICT", f.statuses.single())
            assertTrue(f.controller.currentState().showDnsDialog)
            assertEquals(1, f.ownerTransactions)
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun acceptedDnsSaveCompletionCannotDiscardEditsMadeWhileOwnerWaits() = kotlinx.coroutines.test.runTest {
        DnsFixture(frontendLaunch = { block -> launch { block() } }).use { f ->
            f.service.toggleDnsDialog()
            f.frontendCompletions.last().await()
            f.draft("https://accepted.example.test/dns-query")
            val admitted = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeCommit = { admitted.complete(Unit); release.await() }
            f.service.saveDns()
            val originalCompletion = f.frontendCompletions.last()
            admitted.await()
            f.service.onDnsDraftChanged("https://edited.example.test/dns-query")
            release.complete(Unit)
            originalCompletion.await()
            assertEquals("https://accepted.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
            assertTrue(f.controller.currentState().showDnsDialog)
            assertEquals("https://edited.example.test/dns-query", f.controller.currentState().customDnsEndpointDraft)
            assertTrue(f.statuses.isEmpty())
            assertEquals(ControlCode.OK, f.operationStatus(f.guiRequests.single().requestId).code)
            assertEquals(1, f.ownerTransactions)
            f.service.saveDns()
            f.frontendCompletions.last().await()
            assertEquals("CONFLICT", f.statuses.single())
            assertEquals(1, f.ownerTransactions)
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun dnsEditsUndoneDuringSaveStillRequireExplicitCompletionRetry() = kotlinx.coroutines.test.runTest {
        DnsFixture(frontendLaunch = { block -> launch { block() } }).use { f ->
            f.service.toggleDnsDialog()
            f.frontendCompletions.last().await()
            f.draft("https://accepted.example.test/dns-query")
            val admitted = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeCommit = { admitted.complete(Unit); release.await() }
            f.service.saveDns()
            val originalCompletion = f.frontendCompletions.last()
            admitted.await()
            f.service.onDnsDraftChanged("https://edited.example.test/dns-query")
            f.service.onDnsDraftChanged("https://accepted.example.test/dns-query")
            release.complete(Unit)
            originalCompletion.await()
            assertTrue(f.controller.currentState().showDnsDialog)
            assertTrue(f.statuses.isEmpty())
            assertEquals(1, f.ownerTransactions)
            f.service.saveDns()
            f.frontendCompletions.last().await()
            assertEquals(f.guiRequests[0], f.guiRequests[1])
            assertEquals(1, f.ownerTransactions)
            assertFalse(f.controller.currentState().showDnsDialog)
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun delayedDnsOpeningCannotReopenCancelledDialog() = kotlinx.coroutines.test.runTest {
        DnsFixture(frontendLaunch = { block -> launch { block() } }).use { f ->
            val captured = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeSnapshotResult = { captured.complete(Unit); release.await() }
            f.service.toggleDnsDialog()
            val originalCompletion = f.frontendCompletions.last()
            captured.await()
            f.service.toggleDnsDialog()
            // The authentic old caller creates a second task instead of cancelling its pending opening.
            f.frontendCompletions.filter { it !== originalCompletion }.forEach { it.await() }
            release.complete(Unit)
            originalCompletion.await()
            assertFalse(f.controller.currentState().showDnsDialog)
            assertEquals(0L, f.snapshot().revision)
            assertTrue(f.guiRequests.isEmpty())
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun delayedDnsOpeningCannotRebaseNewerOpeningOrItsEditedDraft() = kotlinx.coroutines.test.runTest {
        DnsFixture(frontendLaunch = { block -> launch { block() } }).use { f ->
            val captured = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeSnapshotResult = { captured.complete(Unit); release.await() }
            f.service.toggleDnsDialog()
            val originalCompletion = f.frontendCompletions.last()
            captured.await()
            f.service.toggleDnsDialog()
            assertEquals(ControlCode.OK, f.cliDns("https://cli.example.test/dns-query").code)
            f.service.toggleDnsDialog()
            f.frontendCompletions.filter { it !== originalCompletion }.forEach { it.await() }
            f.draft("https://replacement.example.test/dns-query")
            release.complete(Unit)
            originalCompletion.await()
            assertTrue(f.controller.currentState().showDnsDialog)
            assertEquals("https://replacement.example.test/dns-query", f.controller.currentState().customDnsEndpointDraft)
            f.service.saveDns()
            f.frontendCompletions.last().await()
            assertEquals(1L, f.guiRequests.single().ifRevision)
            assertEquals("https://replacement.example.test/dns-query", f.snapshot().value.dnsSettings.endpoint)
            assertEquals(2L, f.snapshot().revision)
            assertFalse(f.controller.currentState().showDnsDialog)
            assertEquals(2, f.ownerTransactions)
        }
    }

    @Test fun queuedRefreshSaveClosedBeforeExecutionNeverSubmitsOldDraft() = queuedPolicySave(PolicyGroup.REFRESH, true)
    @Test fun queuedRefreshSaveEditedBeforeExecutionNeverSubmitsOldDraft() = queuedPolicySave(PolicyGroup.REFRESH, false)
    @Test fun queuedValidationSaveClosedBeforeExecutionNeverSubmitsOldDraft() = queuedPolicySave(PolicyGroup.VALIDATION, true)
    @Test fun queuedValidationSaveEditedBeforeExecutionNeverSubmitsOldDraft() = queuedPolicySave(PolicyGroup.VALIDATION, false)
    private fun queuedPolicySave(group: PolicyGroup, close: Boolean) {
        val queued = java.util.ArrayDeque<suspend () -> Unit>()
        PolicyFixture(group, { queued.addLast(it) }).use { f ->
            f.toggle(); runBlocking { queued.removeFirst().invoke() }; f.draft("draft")
            val before = f.snapshot()
            f.save()
            if (close) f.toggle() else f.draft("edited")
            runBlocking { queued.removeFirst().invoke() }
            println("QUEUED_POLICY group=$group close=$close submissions=${f.requests.size} revision=${f.snapshot().revision} transactions=${f.transactions}")
            assertTrue("A queued invalidated draft must not enter the owner", f.requests.isEmpty())
            assertEquals(before, f.snapshot()); assertEquals(0, f.transactions)
            assertTrue(f.statuses.isEmpty())
            assertEquals(!close, f.visible())
        }
    }

    @Test fun queuedDnsSaveClosedBeforeExecutionNeverSubmitsOldDraft() = queuedDnsSave(true)
    @Test fun queuedDnsSaveEditedBeforeExecutionNeverSubmitsOldDraft() = queuedDnsSave(false)
    private fun queuedDnsSave(close: Boolean) {
        val queued = java.util.ArrayDeque<suspend () -> Unit>()
        DnsFixture(frontendLaunch = { queued.addLast(it) }).use { f ->
            f.service.toggleDnsDialog(); runBlocking { queued.removeFirst().invoke() }
            f.draft("https://queued.example.test/dns-query"); val before = f.snapshot()
            f.service.saveDns()
            if (close) f.service.toggleDnsDialog() else f.service.onDnsDraftChanged("https://edited.example.test/dns-query")
            runBlocking { queued.removeFirst().invoke() }
            println("QUEUED_DNS close=$close submissions=${f.guiRequests.size} revision=${f.snapshot().revision} transactions=${f.ownerTransactions}")
            assertTrue("A queued invalidated DNS draft must not enter the owner", f.guiRequests.isEmpty())
            assertEquals(before, f.snapshot()); assertEquals(0, f.ownerTransactions)
            assertTrue(f.statuses.isEmpty())
            assertEquals(!close, f.controller.currentState().showDnsDialog)
        }
    }

    @Test fun changedRefreshInputAfterLostResponseDoesNotReplaceOriginalRequest() = changedPolicyAfterLostResponse(PolicyGroup.REFRESH)
    @Test fun changedValidationInputAfterLostResponseDoesNotReplaceOriginalRequest() = changedPolicyAfterLostResponse(PolicyGroup.VALIDATION)
    private fun changedPolicyAfterLostResponse(group: PolicyGroup) = PolicyFixture(group).use { f ->
        f.toggle(); f.draft("draft"); f.loseResponse = true; f.save()
        val originalRequest = f.requests.single(); val originalResult = f.results.single()
        val committed = f.snapshot()
        assertEquals(ControlCode.OK, f.operationStatus(originalRequest.requestId).code)
        f.draft("edited"); f.save()
        println("UNKNOWN_POLICY group=$group submissions=${f.requests.size} revision=${f.snapshot().revision} transactions=${f.transactions} codes=${f.results.map { it.code }} sameRequest=${f.requests.all { it == originalRequest }}")
        assertEquals("Changed input cannot replace an unresolved request", listOf(originalRequest), f.requests)
        assertEquals(committed, f.snapshot()); assertTrue(f.visible())
        assertEquals(listOf("OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN"), f.statuses)
        f.draft("draft"); f.save()
        assertEquals(listOf(originalRequest, originalRequest), f.requests)
        assertEquals(listOf(originalResult, originalResult), f.results)
        assertEquals(committed, f.snapshot()); assertEquals(1, f.transactions)
        assertFalse(f.visible())
    }

    @Test fun changedDnsInputAfterLostResponseDoesNotReplaceOriginalRequest() = DnsFixture().use { f ->
        f.service.toggleDnsDialog(); f.draft("https://accepted.example.test/dns-query")
        f.loseNextResponse = true; f.service.saveDns()
        val originalRequest = f.guiRequests.single(); val originalResult = f.results.single(); val committed = f.snapshot()
        assertEquals(ControlCode.OK, f.operationStatus(originalRequest.requestId).code)
        f.service.onDnsDraftChanged("https://edited.example.test/dns-query"); f.service.saveDns()
        println("UNKNOWN_DNS submissions=${f.guiRequests.size} revision=${f.snapshot().revision} transactions=${f.ownerTransactions} codes=${f.results.map { it.code }} sameRequest=${f.guiRequests.all { it == originalRequest }}")
        assertEquals("Changed DNS input cannot replace an unresolved request", listOf(originalRequest), f.guiRequests)
        assertEquals(committed, f.snapshot()); assertTrue(f.controller.currentState().showDnsDialog)
        assertEquals(listOf("OUTCOME_UNKNOWN", "OUTCOME_UNKNOWN"), f.statuses)
        f.service.onDnsDraftChanged("https://accepted.example.test/dns-query"); f.service.saveDns()
        assertEquals(listOf(originalRequest, originalRequest), f.guiRequests)
        assertEquals(listOf(originalResult, originalResult), f.results)
        assertEquals(committed, f.snapshot()); assertEquals(1, f.ownerTransactions)
        assertFalse(f.controller.currentState().showDnsDialog)
    }

    private enum class PolicyGroup { REFRESH, VALIDATION }

    @Test fun staleRefreshDraftCannotOverwriteCliCommit() = policyStaleRevision(PolicyGroup.REFRESH)
    @Test fun staleValidationDraftCannotOverwriteCliCommit() = policyStaleRevision(PolicyGroup.VALIDATION)
    private fun policyStaleRevision(group: PolicyGroup) = PolicyFixture(group).use { f ->
        f.toggle(); f.draft("draft")
        assertEquals(ControlCode.OK, f.cli("cli").code)
        f.controller.mergePersistedState(f.snapshot().value)
        f.save()
        assertEquals("A stale GUI draft must not overwrite the CLI commit", f.expected("cli"), f.current())
        assertTrue(f.visible())
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertEquals(1L, f.snapshot().revision)
        assertEquals(1, f.transactions)
        assertEquals(0, f.legacyWrites)
        assertEquals(0L, f.requests.single().ifRevision)
    }

    @Test fun staleRefreshEpochCannotSaveAtRecreatedRevisionZero() = policyStaleEpoch(PolicyGroup.REFRESH)
    @Test fun staleValidationEpochCannotSaveAtRecreatedRevisionZero() = policyStaleEpoch(PolicyGroup.VALIDATION)
    private fun policyStaleEpoch(group: PolicyGroup) = PolicyFixture(group).use { f ->
        f.toggle(); f.draft("draft")
        f.replaceOwner("replacement")
        val before = f.snapshot()
        f.save()
        assertEquals("A replaced controller must reject the original opening", before, f.snapshot())
        assertEquals(listOf("CONFLICT"), f.statuses)
        assertTrue(f.visible())
        assertEquals("owner", f.requests.single().controllerId)
        assertEquals(0L, f.requests.single().ifRevision)
        assertEquals(0, f.transactions)
    }

    @Test fun failedRefreshPersistenceKeepsDraftAndLiveRuntime() = policyFailedPersistence(PolicyGroup.REFRESH)
    @Test fun failedValidationPersistenceKeepsDraftAndLiveRuntime() = policyFailedPersistence(PolicyGroup.VALIDATION)
    private fun policyFailedPersistence(group: PolicyGroup) = PolicyFixture(group).use { f ->
        f.toggle(); f.draft("draft")
        val before = f.snapshot(); val runtime = f.observer.state.value
        f.failPersistence = true
        f.save()
        assertTrue("Persistence failure must not close the dialog", f.visible())
        assertEquals(before, f.snapshot())
        assertEquals(runtime, f.observer.state.value)
        assertEquals(listOf("PERSISTENCE_FAILED"), f.statuses)
        assertEquals(0, f.schedules)
        assertEquals(0, f.transactions)
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun acceptedRefreshCompletionCannotCloseOrReportIntoReplacementDraft() = kotlinx.coroutines.test.runTest {
        policyReplacement(PolicyGroup.REFRESH) { block -> launch { block() } }
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun acceptedValidationCompletionCannotCloseOrReportIntoReplacementDraft() = kotlinx.coroutines.test.runTest {
        policyReplacement(PolicyGroup.VALIDATION) { block -> launch { block() } }
    }
    private suspend fun policyReplacement(group: PolicyGroup, launch: (suspend () -> Unit) -> Unit) {
        PolicyFixture(group, launch).use { f ->
            f.openAwaited(); f.draft("draft")
            val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeCommit = { entered.complete(Unit); release.await() }
            f.save(); val oldCompletion = f.completions.last(); entered.await()
            if (f.visible()) f.toggle()
            f.openAwaited(); f.draft("replacement")
            release.complete(Unit); oldCompletion.await()
            assertTrue(f.visible())
            assertEquals(f.expected("replacement"), f.draftValue())
            assertTrue("Old completion must not report success into the replacement frontend", f.statuses.isEmpty())
            assertEquals(f.expected("draft"), f.current())
            assertEquals(1, f.transactions)
            assertEquals(ControlCode.OK, f.operationStatus(f.requests.single().requestId).code)
            f.save(); f.completions.last().await()
            assertEquals("CONFLICT", f.statuses.single())
            assertEquals(1, f.transactions)
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun refreshEditsUndoneDuringSaveStillRetainAcceptedRequest() = kotlinx.coroutines.test.runTest {
        policyEdited(PolicyGroup.REFRESH) { block -> launch { block() } }
    }
    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun validationEditsUndoneDuringSaveStillRetainAcceptedRequest() = kotlinx.coroutines.test.runTest {
        policyEdited(PolicyGroup.VALIDATION) { block -> launch { block() } }
    }
    private suspend fun policyEdited(group: PolicyGroup, launch: (suspend () -> Unit) -> Unit) {
        PolicyFixture(group, launch).use { f ->
            f.openAwaited(); f.draft("draft")
            val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeCommit = { entered.complete(Unit); release.await() }
            f.save(); val completion = f.completions.last(); entered.await()
            f.draft("edited"); f.draft("draft")
            release.complete(Unit); completion.await()
            assertTrue("Edits invalidate the old completion even when undone", f.visible())
            assertTrue(f.statuses.isEmpty())
            assertEquals(1, f.transactions)
            f.save(); f.completions.last().await()
            assertEquals(f.requests[0], f.requests[1])
            assertEquals(1, f.transactions)
            assertFalse(f.visible())
        }
    }

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
    @Test fun delayedPolicySnapshotsCannotReopenOrRebaseReplacementDrafts() = kotlinx.coroutines.test.runTest {
        for (group in PolicyGroup.entries) PolicyFixture(group, { block -> launch { block() } }).use { f ->
            val entered = kotlinx.coroutines.CompletableDeferred<Unit>()
            val release = kotlinx.coroutines.CompletableDeferred<Unit>()
            f.beforeSnapshot = { entered.complete(Unit); release.await() }
            f.toggle(); val oldCompletion = f.completions.last(); entered.await()
            f.toggle() // cancel pending opening
            assertEquals(ControlCode.OK, f.cli("cli").code)
            f.openAwaited(); f.draft("replacement")
            release.complete(Unit); oldCompletion.await()
            assertTrue(f.visible())
            assertEquals(f.expected("replacement"), f.draftValue())
            f.save(); f.completions.last().await()
            assertEquals(1L, f.requests.single().ifRevision)
            assertEquals(f.expected("replacement"), f.current())
            assertFalse(f.visible())
        }
    }

    @Test fun policyBusySnapshotAndUnknownRuntimeFailuresKeepDrafts() {
        for (group in PolicyGroup.entries) PolicyFixture(group).use { f ->
            f.failSnapshot = true; f.toggle()
            assertFalse(f.visible()); assertEquals(listOf("UNAVAILABLE"), f.statuses)
            f.failSnapshot = false; f.statuses.clear(); f.toggle(); f.draft("draft")
            val lease = requireNotNull(f.jobs.tryAcquireMutation())
            f.save(); f.jobs.releaseMutation(lease)
            assertEquals(listOf("BUSY"), f.statuses); assertTrue(f.visible())
            f.statuses.clear(); f.observer.resetCompleted(false); f.save()
            assertEquals(listOf("UNAVAILABLE"), f.statuses); assertTrue(f.visible())
            assertEquals(0, f.transactions)
        }
    }

    @Test fun lostPolicyResponseRetainsRequestAndRecoversWithoutSecondCommit() {
        for (group in PolicyGroup.entries) PolicyFixture(group).use { f ->
            f.toggle(); f.draft("draft"); f.loseResponse = true; f.save()
            assertEquals(listOf("OUTCOME_UNKNOWN"), f.statuses); assertTrue(f.visible())
            assertEquals(ControlCode.OK, f.operationStatus(f.requests.single().requestId).code)
            f.save()
            assertEquals(f.requests[0], f.requests[1])
            assertEquals(1, f.transactions); assertFalse(f.visible())
            assertEquals(if (group == PolicyGroup.REFRESH) 1 else 0, f.schedules)
        }
    }

    @Test fun refreshSchedulerFailureIsCommittedAndKeepsDraftWithoutFalseSuccess() = PolicyFixture(PolicyGroup.REFRESH).use { f ->
        f.toggle(); f.draft("draft"); f.failSchedule = true; f.save()
        assertEquals(f.expected("draft"), f.current())
        assertEquals(1L, f.snapshot().revision)
        assertEquals(ControlCode.RUNTIME_FAILED, f.results.single().code)
        assertEquals(ControlValue.BooleanValue(true), f.results.single().data["configurationCommitted"])
        assertEquals(listOf("RUNTIME_FAILED"), f.statuses)
        assertTrue(f.visible())
        f.save()
        assertEquals(f.requests[0], f.requests[1]); assertEquals(1, f.schedules)
        assertEquals(1, f.transactions)
    }

    @Test fun policyGroupNormalizationPreservesUnrelatedSettingsAndLiveRuntime() {
        PolicyFixture(PolicyGroup.REFRESH).use { f ->
            val runtime = f.observer.state.value; f.toggle()
            f.service.onSubscriptionRefreshPolicyDraftChanged(SubscriptionRefreshPolicy.CUSTOM)
            f.service.onSubscriptionRefreshCustomHoursDraftChanged("0.001"); f.save()
            assertEquals(0, f.transactions); assertTrue(f.visible()); assertTrue(f.requests.isEmpty())
            f.statuses.clear(); f.service.onSubscriptionRefreshCustomHoursDraftChanged("1,5")
            f.service.onFindBestAfterSubscriptionRefreshDraftChanged(true); f.save()
            assertEquals(1.5, f.snapshot().value.subscriptionRefreshCustomHours, 0.0)
            assertTrue(f.snapshot().value.findBestAfterSubscriptionRefresh)
            assertEquals(BenchmarkValidationSettings(), f.snapshot().value.validationSettings)
            assertEquals(runtime, f.observer.state.value); assertEquals(1, f.schedules)
            assertEquals(setOf("refresh.policy", "refresh.custom-hours", "refresh.find-best-after-refresh"), f.patch().keys)
            f.toggle(); f.save(); assertEquals(1, f.schedules) // unchanged save has no scheduler effect
        }
        PolicyFixture(PolicyGroup.VALIDATION).use { f ->
            val runtime = f.observer.state.value; f.toggle()
            f.service.onValidationTestUrlDraftChanged("example.test")
            f.service.onValidationBatchSizeDraftChanged("nonnumeric")
            f.service.onValidationSubscriptionRefreshConcurrencyDraftChanged("99")
            f.service.onValidationRetryCountDraftChanged("-3")
            f.service.onValidationActiveVerificationWindowSizeDraftChanged("0")
            val expected = MainDraftLogic.resolveValidationSettingsSave(f.controller.currentState()).settings
            f.save()
            assertEquals(expected, f.snapshot().value.validationSettings)
            assertEquals(SubscriptionRefreshPolicy.OFF, f.snapshot().value.subscriptionRefreshPolicy)
            assertEquals(runtime, f.observer.state.value); assertEquals(0, f.schedules)
            assertEquals(setOf("validation.test-url", "validation.batch-size", "validation.subscription-refresh-concurrency",
                "validation.retry-count", "validation.active-verification-window-size"), f.patch().keys)
        }
    }

    private class PolicyFixture(
        val group: PolicyGroup,
        private val frontendLaunch: (suspend () -> Unit) -> Unit = { runBlocking { it() } },
    ) : java.io.Closeable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        private val directory = java.nio.file.Files.createTempDirectory("policy-draft-test-").toFile()
        private val underlying = androidx.datastore.preferences.core.PreferenceDataStoreFactory.create(scope = scope) {
            java.io.File(directory, "configuration.preferences_pb")
        }
        var failPersistence = false
        private val store = object : androidx.datastore.core.DataStore<androidx.datastore.preferences.core.Preferences> {
            override val data = underlying.data
            override suspend fun updateData(transform: suspend (androidx.datastore.preferences.core.Preferences) -> androidx.datastore.preferences.core.Preferences): androidx.datastore.preferences.core.Preferences {
                if (failPersistence) throw java.io.IOException("inert storage refusal")
                return underlying.updateData(transform)
            }
        }
        private val policy = androidx.datastore.preferences.core.stringPreferencesKey("subscription_refresh_policy")
        private val hours = androidx.datastore.preferences.core.doublePreferencesKey("subscription_refresh_custom_hours_v2")
        private val findBest = androidx.datastore.preferences.core.booleanPreferencesKey("find_best_after_subscription_refresh")
        private val url = androidx.datastore.preferences.core.stringPreferencesKey("validation_test_url")
        private val batch = androidx.datastore.preferences.core.intPreferencesKey("validation_batch_size")
        private val concurrency = androidx.datastore.preferences.core.intPreferencesKey("validation_subscription_refresh_concurrency")
        private val retry = androidx.datastore.preferences.core.intPreferencesKey("validation_retry_count")
        private val window = androidx.datastore.preferences.core.intPreferencesKey("validation_active_verification_window_size")
        private fun configuration(epoch: String) = com.kardinal.vpncontrol.data.AndroidConfigurationStore(store, { prefs ->
            PersistedState(subscriptionRefreshPolicy = prefs[policy]?.let(SubscriptionRefreshPolicy::valueOf) ?: SubscriptionRefreshPolicy.OFF,
                subscriptionRefreshCustomHours = prefs[hours] ?: 24.0, findBestAfterSubscriptionRefresh = prefs[findBest] ?: false,
                validationSettings = BenchmarkValidationSettings(testUrl = prefs[url] ?: BenchmarkValidationSettings.DEFAULT_TEST_URL,
                    batchSize = prefs[batch] ?: BenchmarkValidationSettings.DEFAULT_BATCH_SIZE,
                    subscriptionRefreshConcurrency = prefs[concurrency] ?: BenchmarkValidationSettings.DEFAULT_SUBSCRIPTION_REFRESH_CONCURRENCY,
                    retryCount = prefs[retry] ?: BenchmarkValidationSettings.DEFAULT_RETRY_COUNT,
                    activeVerificationWindowSize = prefs[window] ?: BenchmarkValidationSettings.DEFAULT_ACTIVE_VERIFICATION_WINDOW_SIZE))
        }, epoch)
        private var configuration = configuration("owner")
        val observer = AndroidRuntimeObserver()
        val jobs = AndroidCommandJobs(scope)
        val controller = MainController(MainUiState(isVpnRunning = true))
        val statuses = mutableListOf<String>()
        val requests = mutableListOf<ControlRequest>()
        val results = mutableListOf<ControlResult>()
        val completions = mutableListOf<kotlinx.coroutines.CompletableDeferred<Unit>>()
        val frontendFailures = mutableListOf<Throwable>()
        var transactions = 0; var legacyWrites = 0; var schedules = 0
        var failSnapshot = false; var failSchedule = false; var loseResponse = false
        var beforeCommit: suspend () -> Unit = {}
        var beforeSnapshot: suspend () -> Unit = {}
        init { observer.started(Any(), AppMode.VPN, "inert-live-A", ControlRuntimeConfiguration.committed(MainUiState())) }
        private suspend fun write(prefs: androidx.datastore.preferences.core.MutablePreferences, next: PersistedState) {
            prefs[policy] = next.subscriptionRefreshPolicy.name; prefs[hours] = next.subscriptionRefreshCustomHours
            prefs[findBest] = next.findBestAfterSubscriptionRefresh
            prefs[url] = next.validationSettings.testUrl; prefs[batch] = next.validationSettings.batchSize
            prefs[concurrency] = next.validationSettings.subscriptionRefreshConcurrency; prefs[retry] = next.validationSettings.retryCount
            prefs[window] = next.validationSettings.activeVerificationWindowSize
        }
        private fun owner() = AndroidSettingsControl(configuration.controllerId, scope, snapshot = { configuration.snapshot() },
            commit = { patch, epoch, revision ->
                val before = beforeCommit; beforeCommit = {}; before()
                var scheduling = false
                val committed = configuration.editProjected(epoch, revision) { prefs, previous ->
                    check(observer.hasAuthoritativeConfiguration()) { "RUNTIME_STATE_UNKNOWN" }
                    val next = (ControlSettingsLogic.plan(previous, patch, ControlPlatform.ANDROID, false) as ControlSettingsPlan.Configuration).state
                    scheduling = previous.subscriptionRefreshPolicy != next.subscriptionRefreshPolicy || previous.subscriptionRefreshCustomHours != next.subscriptionRefreshCustomHours
                    write(prefs, next); transactions++
                }
                AndroidSettingsCommit(committed, scheduling)
            }, schedule = { schedules++; if (failSchedule) throw java.io.IOException("inert scheduler refusal") },
            pendingRestart = observer::pendingRestart, mutationJobs = jobs)
        private var control = owner()
        private fun draftPort() = AndroidSettingsDraftControl({
            if (failSnapshot) throw java.io.IOException("inert snapshot refusal")
            val captured = configuration.snapshot(); val before = beforeSnapshot; beforeSnapshot = {}; before(); captured
        }, { request -> requests += request; control.execute(request).also { result ->
            results += result
            if (loseResponse) { loseResponse = false; throw java.io.IOException("inert response lost after actual owner completion") }
        } })
        val service = AndroidSettingsActionsService(controller, object : AndroidControllerEffectSink {
            override fun handle(effects: List<MainControllerEffect>) = runBlocking { handleWithinMutation(effects) }
            override suspend fun handleWithinMutation(effects: List<MainControllerEffect>) {
                for (effect in effects) {
                    val before = beforeCommit; beforeCommit = {}; before()
                    when (effect) {
                        is MainControllerEffect.SaveSubscriptionRefreshPolicy -> {
                            configuration.editProjected(null, null) { prefs, previous -> write(prefs, previous.copy(
                                subscriptionRefreshPolicy = effect.policy, subscriptionRefreshCustomHours = effect.customHours,
                                findBestAfterSubscriptionRefresh = effect.findBestAfterRefresh)) }
                            legacyWrites++; schedules++; statuses += effect.statusMessage
                        }
                        is MainControllerEffect.SaveValidationSettings -> {
                            configuration.editProjected(null, null) { prefs, previous -> write(prefs, previous.copy(validationSettings = effect.settings)) }
                            legacyWrites++; statuses += effect.statusMessage
                        }
                        is MainControllerEffect.UpdateStatus -> statuses += effect.message
                        else -> error("Unexpected policy effect")
                    }
                }
            }
        }, launch = { block ->
            val completion = kotlinx.coroutines.CompletableDeferred<Unit>(); completions += completion
            frontendLaunch { try { block() } catch (error: Exception) { frontendFailures += error } finally { completion.complete(Unit) } }
        }, stopConnection = { error("Policy save must not stop runtime") }, commitAppMode = { error("Not a mode fixture") },
            dnsDraft = AndroidDnsDraftControl({ error("Not a DNS fixture") }, { error("Not a DNS fixture") }),
            refreshDraft = draftPort(), validationDraft = draftPort(), updateStatus = { statuses += it },
            updateSessionStatsEnabled = {}, updateLiveTrafficStatsEnabled = {}, updateProfileTotalsEnabled = {},
            updateLatencyHistoryEnabled = {}, updateConnectionLogEnabled = {}, updateConnectionTestToolsEnabled = {})
        suspend fun openAwaited() {
            val before = completions.size
            toggle()
            // The preserved original opening is synchronous and owns no launch handle.
            completions.drop(before).forEach { it.await() }
        }
        fun toggle() { if (group == PolicyGroup.REFRESH) service.toggleRefreshPolicyDialog() else service.toggleValidationSettingsDialog() }
        fun save() { if (group == PolicyGroup.REFRESH) service.saveSubscriptionRefreshPolicy() else service.saveValidationSettings() }
        fun visible() = if (group == PolicyGroup.REFRESH) controller.currentState().showRefreshPolicyDialog else controller.currentState().showValidationSettingsDialog
        fun expected(label: String) = if (group == PolicyGroup.REFRESH) when(label) { "draft" -> "2.5"; "cli" -> "3.5"; "edited" -> "4.5"; else -> "5.5" } else "https://$label.example.test/probe"
        fun draft(label: String) { if (group == PolicyGroup.REFRESH) {
            service.onSubscriptionRefreshPolicyDraftChanged(SubscriptionRefreshPolicy.CUSTOM)
            service.onSubscriptionRefreshCustomHoursDraftChanged(expected(label))
        } else service.onValidationTestUrlDraftChanged(expected(label)) }
        fun draftValue() = if (group == PolicyGroup.REFRESH) controller.currentState().subscriptionRefreshCustomHoursDraft else controller.currentState().validationTestUrlDraft
        fun current() = if (group == PolicyGroup.REFRESH) snapshot().value.subscriptionRefreshCustomHours.toString() else snapshot().value.validationSettings.testUrl
        fun snapshot(): ControlCommitted<PersistedState> = runBlocking { configuration.snapshot() }
        fun replaceOwner(epoch: String) { configuration = configuration(epoch); control = owner() }
        fun cli(label: String) = runBlocking {
            val opening = configuration.snapshot()
            val patch = if (group == PolicyGroup.REFRESH) mapOf("refresh.policy" to ControlValue.Text("custom"),
                "refresh.custom-hours" to ControlValue.DecimalValue(expected(label).toDouble()))
                else mapOf("validation.test-url" to ControlValue.Text(expected(label)))
            control.execute(ControlRequest(java.util.UUID.randomUUID().toString(), ControlCommand(ControlOperationId.SETTINGS_APPLY,
                mapOf("input" to ControlValue.Text(ControlDocumentCodec.encodeValues(patch)))), controllerId = opening.controllerId, ifRevision = opening.revision))
        }
        fun patch() = ControlDocumentCodec.decodeValues((requests.last().command.arguments["input"] as ControlValue.Text).value)
        fun operationStatus(request: String) = runBlocking {
            control.execute(ControlRequest("observe-"+request, ControlCommand(ControlOperationId.OPERATIONS_STATUS,
                mapOf("id" to ControlValue.Text(requireNotNull(control.operationIdForRequest(request))))), controllerId = configuration.controllerId))
        }
        override fun close() { runBlocking { requireNotNull(scope.coroutineContext[kotlinx.coroutines.Job]).cancelAndJoin() }; check(directory.deleteRecursively()) }
    }

    private class DnsFixture(
        private val frontendLaunch: (suspend () -> Unit) -> Unit = { runBlocking { it() } },
    ) : java.io.Closeable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        private val directory = java.nio.file.Files.createTempDirectory("dns-draft-test-").toFile()
        private val underlying = androidx.datastore.preferences.core.PreferenceDataStoreFactory.create(scope = scope) {
            java.io.File(directory, "configuration.preferences_pb")
        }
        var failPersistence = false
        private val store = object : androidx.datastore.core.DataStore<androidx.datastore.preferences.core.Preferences> {
            override val data = underlying.data
            override suspend fun updateData(
                transform: suspend (androidx.datastore.preferences.core.Preferences) -> androidx.datastore.preferences.core.Preferences,
            ): androidx.datastore.preferences.core.Preferences {
                if (failPersistence) throw java.io.IOException("PRIVATE inert storage refusal")
                return underlying.updateData(transform)
            }
        }
        val modeKey = androidx.datastore.preferences.core.stringPreferencesKey("dns_mode")
        val endpointKey = androidx.datastore.preferences.core.stringPreferencesKey("custom_dns_endpoint")
        private val legacyKey = androidx.datastore.preferences.core.stringPreferencesKey("legacy_custom_dns_address")
        var configuration = configuration("owner")
            private set
        val observer = AndroidRuntimeObserver()
        val jobs = AndroidCommandJobs(scope)
        val controller = MainController(MainUiState(isVpnRunning = true))
        val statuses = mutableListOf<String>()
        val guiRequests = mutableListOf<ControlRequest>()
        val results = mutableListOf<ControlResult>()
        var ownerTransactions = 0
        var legacyWrites = 0
        var stopCalls = 0
        var failSnapshot = false
        var loseNextResponse = false
        var unknownPendingAfterCommit = false
        var beforeCommit: suspend () -> Unit = {}
        var beforeSnapshotResult: suspend () -> Unit = {}
        val frontendCompletions = mutableListOf<kotlinx.coroutines.CompletableDeferred<Unit>>()
        init { observer.started(Any(), AppMode.VPN, "inert-live-A",
            ControlRuntimeConfiguration.committed(MainUiState())) }

        private fun configuration(epoch: String) = com.kardinal.vpncontrol.data.AndroidConfigurationStore(
            store, { prefs -> PersistedState(
                dnsSettings = DnsSettings(
                    mode = prefs[modeKey]?.let(DnsMode::valueOf) ?: DnsMode.AUTOMATIC,
                    endpoint = prefs[endpointKey].orEmpty(), legacyRawAddress = prefs[legacyKey].orEmpty()),
                subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF,
            ) }, epoch)

        private fun owner() = AndroidSettingsControl(configuration.controllerId, scope,
            snapshot = { configuration.snapshot() },
            commit = { patch, epoch, revision ->
                val before = beforeCommit
                beforeCommit = {}
                before()
                val committed = configuration.editProjected(epoch, revision) { prefs, previous ->
                    check(observer.hasAuthoritativeConfiguration()) { "RUNTIME_STATE_UNKNOWN" }
                    val plan = ControlSettingsLogic.plan(previous, patch, ControlPlatform.ANDROID, false)
                    val proposed = (plan as? ControlSettingsPlan.Configuration)?.state ?: error("INVALID_ARGUMENT")
                    // Android Context and the unrelated repository fields are omitted;
                    // production owner decisions and the actual DataStore guard/transaction execute.
                    prefs[modeKey] = proposed.dnsSettings.mode.name
                    prefs[endpointKey] = proposed.dnsSettings.endpoint
                    prefs[legacyKey] = proposed.dnsSettings.legacyRawAddress
                    ownerTransactions++
                }
                AndroidSettingsCommit(committed, false)
            }, schedule = { error("DNS must not reschedule subscription refresh") },
            pendingRestart = {
                if (unknownPendingAfterCommit && ownerTransactions > 0) null else observer.pendingRestart(it)
            }, mutationJobs = jobs)
        private var control = owner()
        private val dnsDraft = AndroidDnsDraftControl({
            if (failSnapshot) throw java.io.IOException("PRIVATE inert snapshot refusal")
            val captured = configuration.snapshot()
            val before = beforeSnapshotResult
            beforeSnapshotResult = {}
            before()
            captured
        }, { request ->
            guiRequests += request
            control.execute(request).also {
                results += it
                if (loseNextResponse) {
                    loseNextResponse = false
                    throw java.io.IOException("PRIVATE lost response after actual commit")
                }
            }
        })
        val service = AndroidSettingsActionsService(controller,
            effectSink = object : AndroidControllerEffectSink {
                override fun handle(effects: List<MainControllerEffect>) = runBlocking { handleWithinMutation(effects) }
                override suspend fun handleWithinMutation(effects: List<MainControllerEffect>) {
                    effects.forEach { effect -> when (effect) {
                        is MainControllerEffect.SaveDns -> {
                            // The preserved GUI's actual legacy updateDns storage boundary:
                            // no expected epoch/revision is supplied to AndroidConfigurationStore.edit.
                            configuration.edit { prefs ->
                                prefs[modeKey] = effect.settings.mode.name
                                prefs[endpointKey] = effect.settings.endpoint
                                prefs[legacyKey] = effect.settings.legacyRawAddress
                            }
                            legacyWrites++
                            statuses += effect.statusMessage
                        }
                        is MainControllerEffect.UpdateStatus -> statuses += effect.message
                        else -> error("Unexpected DNS effect")
                    } }
                }
            }, launch = { block ->
                val completion = kotlinx.coroutines.CompletableDeferred<Unit>()
                frontendCompletions += completion
                frontendLaunch { try { block() } finally { completion.complete(Unit) } }
            },
            stopConnection = { stopCalls++; observer.resetCompleted(true); Result.success(Unit) },
            refreshDraft = AndroidSettingsDraftControl({ error("Not a refresh fixture") }, { error("Not a refresh fixture") }),
            validationDraft = AndroidSettingsDraftControl({ error("Not a validation fixture") }, { error("Not a validation fixture") }),
            commitAppMode = { error("Not a mode fixture") }, dnsDraft = dnsDraft,
            updateStatus = { statuses += it }, updateSessionStatsEnabled = {},
            updateLiveTrafficStatsEnabled = {}, updateProfileTotalsEnabled = {}, updateLatencyHistoryEnabled = {},
            updateConnectionLogEnabled = {}, updateConnectionTestToolsEnabled = {})

        fun draft(endpoint: String) {
            service.onDnsModeChanged(DnsMode.CUSTOM_DOH)
            service.onDnsDraftChanged(endpoint)
        }
        fun snapshot(): ControlCommitted<PersistedState> = runBlocking { configuration.snapshot() }
        fun project() { controller.mergePersistedState(snapshot().value) }
        fun replaceOwner(epoch: String) { configuration = configuration(epoch); control = owner() }
        fun cliDns(endpoint: String): ControlResult = runBlocking {
            val captured = configuration.snapshot()
            control.execute(ControlRequest(java.util.UUID.randomUUID().toString(),
                ControlCommand(ControlOperationId.SETTINGS_APPLY, mapOf("input" to ControlValue.Text(
                    ControlDocumentCodec.encodeValues(mapOf("dns.mode" to ControlValue.Text("custom-doh"),
                        "dns.endpoint" to ControlValue.Text(endpoint)))))),
                controllerId = captured.controllerId, ifRevision = captured.revision))
        }
        fun operationStatus(requestId: String): ControlResult = runBlocking {
            val id = requireNotNull(control.operationIdForRequest(requestId))
            control.execute(ControlRequest("observe-" + requestId,
                ControlCommand(ControlOperationId.OPERATIONS_STATUS, mapOf("id" to ControlValue.Text(id))),
                controllerId = configuration.controllerId))
        }
        override fun close() {
            runBlocking { requireNotNull(scope.coroutineContext[kotlinx.coroutines.Job]).cancelAndJoin() }
            check(directory.deleteRecursively())
        }
    }

    private class ModeFixture(running: Boolean = true) : java.io.Closeable {
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val observer = AndroidRuntimeObserver(initiallyStopped = !running)
        var committed = ControlCommitted("owner", 0L, PersistedState(appMode = AppMode.VPN,
            subscriptionRefreshPolicy = SubscriptionRefreshPolicy.OFF))
        val controller = MainController(MainUiState(isVpnRunning = running, appMode = AppMode.VPN,
            showAppModeDialog = true))
        var stopCalls = 0
        var writes = 0
        var schedules = 0
        var busy = false
        var failPersistence = false
        var pendingUnknownAfterCommit = false
        var beforeExecute: () -> Unit = {}
        val statuses = mutableListOf<String>()
        val requests = mutableListOf<ControlRequest>()
        var result: ControlResult? = null
        init { if (running) observer.started(Any(), AppMode.VPN, "inert-runtime-A",
            ControlRuntimeConfiguration.committed(MainUiState())) }
        // Only persistence/native handles are modeled; the owner, settings decisions and runtime observer are production classes.
        private val owner = AndroidSettingsControl("owner", scope, snapshot = { committed },
            commit = { patch, epoch, revision ->
                check(epoch == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                check(observer.hasAuthoritativeConfiguration()) { "RUNTIME_STATE_UNKNOWN" }
                val previous = committed.value
                val plan = ControlSettingsLogic.plan(previous, patch, ControlPlatform.ANDROID, false)
                val next = (plan as? ControlSettingsPlan.Configuration)?.state ?: error("INVALID_ARGUMENT")
                if (failPersistence) throw java.io.IOException("inert persistence refusal")
                if (ControlConfigurationIdentity.of(previous) != ControlConfigurationIdentity.of(next)) {
                    committed = committed.copy(revision = committed.revision + 1, value = next)
                    writes++
                }
                AndroidSettingsCommit(committed, previous.subscriptionRefreshPolicy != next.subscriptionRefreshPolicy ||
                    previous.subscriptionRefreshCustomHours != next.subscriptionRefreshCustomHours)
            }, schedule = { schedules++ }, pendingRestart = {
                if (pendingUnknownAfterCommit && writes > 0) null else observer.pendingRestart(it)
            }, busy = { busy })
        val service = AndroidSettingsActionsService(controller,
            effectSink = AndroidControllerEffectSink { effects ->
                // This is the preserved legacy adapter's real UpdateAppMode persistence boundary for RED.
                effects.forEach { if (it is MainControllerEffect.UpdateAppMode) {
                    if (failPersistence) throw java.io.IOException("inert persistence refusal")
                    committed = committed.copy(revision = committed.revision + 1,
                        value = committed.value.copy(appMode = it.mode)); writes++
                } }
            }, launch = { runBlocking { it() } },
            stopConnection = { stopCalls++; observer.resetCompleted(true); Result.success(Unit) },
            refreshDraft = AndroidSettingsDraftControl({ error("Not a refresh fixture") }, { error("Not a refresh fixture") }),
            validationDraft = AndroidSettingsDraftControl({ error("Not a validation fixture") }, { error("Not a validation fixture") }),
            dnsDraft = AndroidDnsDraftControl({ error("Not a DNS fixture") }, { error("Not a DNS fixture") }),
            commitAppMode = { mode ->
                val captured = committed
                val request = ControlRequest(java.util.UUID.randomUUID().toString(),
                    ControlCommand(ControlOperationId.SETTINGS_SET, mapOf("key" to ControlValue.Text("mode"),
                        "value" to ControlValue.Text(if (mode == AppMode.VPN) "vpn" else "proxy-only"))),
                    controllerId = captured.controllerId, ifRevision = captured.revision)
                requests += request
                beforeExecute()
                owner.execute(request).also { result = it }
            }, updateStatus = { statuses += it }, updateSessionStatsEnabled = {},
            updateLiveTrafficStatsEnabled = {}, updateProfileTotalsEnabled = {}, updateLatencyHistoryEnabled = {},
            updateConnectionLogEnabled = {}, updateConnectionTestToolsEnabled = {})
        override fun close() { scope.cancel() }
    }

    private fun service(
        controller: MainController,
        effectSink: AndroidControllerEffectSink = AndroidControllerEffectSink {},
        stopConnection: suspend () -> Result<Unit> = { Result.success(Unit) },
        updateStatus: suspend (String) -> Unit = {},
        updateSessionStatsEnabled: suspend (Boolean) -> Unit = {},
        launchMutation: (suspend () -> Unit) -> Unit = { block -> runBlocking { block() } },
        updateHomeSshRouteSettings: suspend (com.kardinal.vpncontrol.model.HomeSshRouteSettings) -> Unit = {},
        homeSshPendingRestart: suspend () -> Boolean? = { null },
        importKey: (suspend (String) -> com.kardinal.vpncontrol.model.ControlResult)? = null,
        sshDraft: AndroidSshDraftControl? = null,
    ): AndroidSettingsActionsService {
        return AndroidSettingsActionsService(
            controller = controller,
            effectSink = effectSink,
            launch = { block -> runBlocking { block() } },
            stopConnection = stopConnection,
            commitAppMode = { error("Mode owner must be configured explicitly in this test") },
            refreshDraft = AndroidSettingsDraftControl({ error("Not a refresh fixture") }, { error("Not a refresh fixture") }),
            validationDraft = AndroidSettingsDraftControl({ error("Not a validation fixture") }, { error("Not a validation fixture") }),
            dnsDraft = AndroidDnsDraftControl({ error("DNS owner must be configured explicitly in this test") },
                { error("DNS owner must be configured explicitly in this test") }),
            updateStatus = updateStatus,
            updateSessionStatsEnabled = updateSessionStatsEnabled,
            updateLiveTrafficStatsEnabled = {},
            updateProfileTotalsEnabled = {},
            updateLatencyHistoryEnabled = {},
            updateConnectionLogEnabled = {},
            updateConnectionTestToolsEnabled = {},
            launchMutation = launchMutation,
            updateHomeSshRouteSettings = updateHomeSshRouteSettings,
            homeSshPendingRestart = homeSshPendingRestart,
            importKey = importKey,
            sshDraft = sshDraft,
        )
    }
}
