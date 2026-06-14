package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.PreflightResult
import com.kardinal.vpncontrol.data.ProfileSelectionAttempt
import com.kardinal.vpncontrol.data.ProfileSelectionAttemptPlan
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ConnectionStatusMessages
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidFindBestActionsServiceTest {
    @Test
    fun refreshWithoutLocationsPostsPreconditionError() = runBlocking {
        var state = MainUiState(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        val statuses = mutableListOf<String>()
        var refreshCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfileAttemptPlan = {
                refreshCalls += 1
                Result.success(attemptPlan("Should not run"))
            },
        )

        service.refresh()

        assertEquals(0, refreshCalls)
        assertEquals(listOf(SubscriptionStatusMessages.addSavedLocationFirst()), statuses)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshSuccessStartsWinnerAndRecordsLatency() = runBlocking {
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
        )
        val statuses = mutableListOf<String>()
        val latencies = mutableListOf<LatencyHistoryEntry>()
        val events = mutableListOf<String>()
        var startCalls = 0
        var persistCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfileAttemptPlan = { Result.success(attemptPlan("Germany")) },
            verifySelectionCandidate = { attempt, _ ->
                events += "precheck ${attempt.selection.profile.remarks}"
                Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
            },
            startSelection = { selection, _ ->
                events += "start ${selection.profile.remarks}"
                startCalls += 1
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
            verifyActiveSelection = { attempt ->
                events += "active ${attempt.selection.profile.remarks}"
                Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
            },
            persistSelection = { persistCalls += 1 },
            appendLatencyHistory = { latencies += it },
        )

        service.refresh()

        assertEquals(1, startCalls)
        assertEquals(1, persistCalls)
        assertEquals(
            ConnectionStatusMessages.findBestStart(ProfileSourceMode.CURRENT_LOCATIONS),
            statuses.first(),
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Germany"),
            statuses.last(),
        )
        assertEquals(listOf("precheck Germany", "start Germany", "active Germany"), events)
        assertEquals("fixed-id", latencies.single().id)
        assertEquals("Germany", latencies.single().profileName)
        assertEquals(1234L, latencies.single().createdAtEpochMillis)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshRestoresSnapshotWhenStartFailsBeforeApply() = runBlocking {
        val previous = PersistedState(selectedProfileName = "Previous")
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
        )
        val statuses = mutableListOf<String>()
        var restored = false
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            snapshot = { previous },
            restoreSnapshot = {
                restored = true
                state = state.copy(selectedProfileName = it.selectedProfileName)
            },
            refreshBestProfileAttemptPlan = { Result.success(attemptPlan("Candidate")) },
            startSelection = { _, _ ->
                SelectionCommitResult(
                    stage = SelectionCommitStage.APPLY_FAILED,
                    error = IllegalStateException("start failed"),
                )
            },
        )

        service.refresh()

        assertTrue(restored)
        assertEquals("Previous", state.selectedProfileName)
        assertEquals("start failed", statuses.last())
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun refreshRetriesSearchBeforeSuccess() = runBlocking {
        var state = MainUiState(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
            validationSettings = BenchmarkValidationSettings(retryCount = 1),
        )
        val statuses = mutableListOf<String>()
        var refreshCalls = 0
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            refreshBestProfileAttemptPlan = {
                refreshCalls += 1
                if (refreshCalls == 1) {
                    Result.failure(IllegalStateException("first failed"))
                } else {
                    Result.success(attemptPlan("Retry Winner"))
                }
            },
            startSelection = { _, _ ->
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
        )

        service.refresh()

        assertEquals(2, refreshCalls)
        assertTrue(
            statuses.any {
                it == BenchmarkStatusMessages.retryingBestLocationSearch(attempt = 2, total = 2)
            },
        )
        assertEquals(
            ConnectionStatusMessages.connectionStartedOnTarget(AppMode.VPN, "Retry Winner"),
            statuses.last(),
        )
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun failingFastestCandidateIsNeverStarted() = runBlocking {
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
        )
        val first = attempt("First")
        val second = attempt("Second")
        val starts = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        val activeVerifications = mutableListOf<String>()
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            refreshBestProfileAttemptPlan = {
                Result.success(
                    ProfileSelectionAttemptPlan(
                        attempts = listOf(first, second),
                        locationBenchmarkDetails = emptyMap(),
                        failureMessage = null,
                    ),
                )
            },
            verifySelectionCandidate = { attempt, _ ->
                prechecks += attempt.selection.profile.remarks
                if (attempt.selection.profile.remarks == "First") {
                    Result.success(blockedBenchmark(attempt.selection.profile.remarks))
                } else {
                    Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
                }
            },
            startSelection = { selection, _ ->
                starts += selection.profile.remarks
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
            verifyActiveSelection = { attempt ->
                activeVerifications += attempt.selection.profile.remarks
                Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
            },
        )

        service.refresh()

        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(listOf("Second"), starts)
        assertEquals(listOf("Second"), activeVerifications)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun verificationFailureStopsAndTriesNextVerifiedCandidateInSameWindow() = runBlocking {
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
            validationSettings = BenchmarkValidationSettings(activeVerificationWindowSize = 2),
        )
        val first = attempt("First")
        val second = attempt("Second")
        val starts = mutableListOf<String>()
        val activeVerifications = mutableListOf<String>()
        val prechecks = mutableListOf<String>()
        var stops = 0
        val latencies = mutableListOf<LatencyHistoryEntry>()
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            refreshBestProfileAttemptPlan = {
                Result.success(
                    ProfileSelectionAttemptPlan(
                        attempts = listOf(first, second),
                        locationBenchmarkDetails = emptyMap(),
                        failureMessage = null,
                    ),
                )
            },
            startSelection = { selection, _ ->
                starts += selection.profile.remarks
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
            stopConnection = {
                stops += 1
                Result.success(Unit)
            },
            verifyActiveSelection = { attempt ->
                activeVerifications += attempt.selection.profile.remarks
                if (attempt.selection.profile.remarks == "First") {
                    Result.success(blockedBenchmark("First"))
                } else {
                    Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
                }
            },
            verifySelectionCandidate = { attempt, _ ->
                prechecks += attempt.selection.profile.remarks
                Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
            },
            appendLatencyHistory = { latencies += it },
        )

        service.refresh()

        assertEquals(listOf("First", "Second"), starts)
        assertEquals(listOf("First", "Second"), activeVerifications)
        assertEquals(listOf("First", "Second"), prechecks)
        assertEquals(1, stops)
        assertEquals("Second", latencies.single().profileName)
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun allActiveVerificationFailuresRestorePreviousRunningConnectionStatus() = runBlocking {
        val previous = PersistedState(isVpnRunning = true, selectedProfileName = "Previous")
        var state = MainUiState(
            appMode = AppMode.VPN,
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf("stored"),
            isVpnRunning = true,
        )
        val statuses = mutableListOf<String>()
        var stops = 0
        var rollbackReason = ""
        val service = service(
            stateProvider = { state },
            setBusy = { busy -> state = state.copy(isBusy = busy) },
            setRefreshing = { refreshing -> state = state.copy(isRefreshing = refreshing) },
            updateStatus = { statuses += it },
            snapshot = { previous },
            refreshBestProfileAttemptPlan = { Result.success(attemptPlan("Candidate")) },
            startSelection = { _, _ ->
                SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
            },
            verifySelectionCandidate = { attempt, _ ->
                Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
            },
            verifyActiveSelection = { attempt ->
                Result.success(blockedBenchmark(attempt.selection.profile.remarks))
            },
            stopConnection = {
                stops += 1
                Result.success(Unit)
            },
            rollbackSelectionChange = { _, reason ->
                rollbackReason = reason
                "previous restored after: $reason"
            },
        )

        service.refresh()

        assertEquals(1, stops)
        assertTrue(rollbackReason.contains("Candidate"))
        assertEquals("previous restored after: $rollbackReason", statuses.last())
        assertFalse(state.isBusy)
        assertFalse(state.isRefreshing)
    }

    private fun service(
        stateProvider: () -> MainUiState,
        setBusy: (Boolean) -> Unit,
        setRefreshing: (Boolean) -> Unit,
        updateStatus: suspend (String) -> Unit = {},
        snapshot: suspend () -> PersistedState = { PersistedState() },
        restoreSnapshot: suspend (PersistedState) -> Unit = {},
        refreshBestProfileAttemptPlan: suspend () -> Result<ProfileSelectionAttemptPlan> = {
            Result.success(attemptPlan("Winner"))
        },
        startSelection: suspend (ProfileSelection, String) -> SelectionCommitResult = { _, _ ->
            SelectionCommitResult(stage = SelectionCommitStage.SUCCESS)
        },
        persistSelection: suspend (ProfileSelection) -> Unit = {},
        verifyActiveSelection: suspend (ProfileSelectionAttempt) -> Result<ProfileBenchmark> = { attempt ->
            Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
        },
        verifySelectionCandidate: suspend (ProfileSelectionAttempt, Int) -> Result<ProfileBenchmark> = { attempt, _ ->
            Result.success(verifiedBenchmark(attempt.selection.profile.remarks))
        },
        rollbackSelectionChange: suspend (PersistedState, String) -> String = { _, message -> message },
        stopConnection: suspend () -> Result<Unit> = { Result.success(Unit) },
        updateLocationBenchmarkDetails: suspend (Map<String, String>) -> Unit = {},
        appendLatencyHistory: suspend (LatencyHistoryEntry) -> Unit = {},
    ): AndroidFindBestActionsService {
        return AndroidFindBestActionsService(
            stateProvider = stateProvider,
            launchTrackedBusyOperation = { block -> runBlocking { block() } },
            setBusy = setBusy,
            setRefreshing = setRefreshing,
            updateStatus = updateStatus,
            snapshot = snapshot,
            restoreSnapshot = restoreSnapshot,
            refreshBestProfileAttemptPlan = refreshBestProfileAttemptPlan,
            startSelection = startSelection,
            persistSelection = persistSelection,
            verifyActiveSelection = verifyActiveSelection,
            verifySelectionCandidate = verifySelectionCandidate,
            rollbackSelectionChange = rollbackSelectionChange,
            stopConnection = stopConnection,
            updateLocationBenchmarkDetails = updateLocationBenchmarkDetails,
            appendLatencyHistory = appendLatencyHistory,
            idGenerator = { "fixed-id" },
            clockMillis = { 1234L },
        )
    }
}

private fun attemptPlan(name: String): ProfileSelectionAttemptPlan {
    val attempt = attempt(name)
    return ProfileSelectionAttemptPlan(
        attempts = listOf(attempt),
        locationBenchmarkDetails = mapOf(attempt.selection.profile.rawLink to attempt.preflight.detail),
        failureMessage = null,
    )
}

private fun attempt(name: String): ProfileSelectionAttempt {
    val selection = profileSelection(name)
    val preflight = PreflightResult(
        profile = selection.profile,
        connectMillis = 50.0,
        detail = "$name: tcp=50.0ms country=DE",
        candidateCountryCode = "DE",
    )
    return ProfileSelectionAttempt(
        selection = selection,
        preflight = preflight,
        activeVerificationPort = 24080,
    )
}

private fun profileSelection(name: String): ProfileSelection {
    val profile = ProxyProfile(
        protocol = ProxyProtocol.VLESS,
        remarks = name,
        server = "test.example.net",
        serverPort = 443,
        uuid = "11111111-1111-4111-8111-111111111111",
        network = "tcp",
        flow = "",
        security = "tls",
        sni = "test.example.net",
        fingerprint = "",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "",
        rawLink = "vless://test#$name",
    )
    return ProfileSelection(
        profile = profile,
        benchmark = ProfileBenchmark(
            profile = profile,
            primaryStatus = "manual",
            secondaryStatus = "manual",
            primaryTotal = null,
            secondaryTotal = null,
            score = 50.0,
            detail = "$name: tcp=50.0ms country=DE",
        ),
        runtimeConfigJson = "{}",
    )
}

private fun verifiedBenchmark(name: String): ProfileBenchmark {
    val selection = profileSelection(name)
    return ProfileBenchmark(
        profile = selection.profile,
        primaryStatus = "manual",
        secondaryStatus = "ok",
        primaryTotal = null,
        secondaryTotal = 60.0,
        score = 110.0,
        detail = "$name: tcp=50.0ms country=DE test=ok test_codes=200 score=110.0",
    )
}

private fun blockedBenchmark(name: String): ProfileBenchmark {
    val selection = profileSelection(name)
    return ProfileBenchmark(
        profile = selection.profile,
        primaryStatus = "manual",
        secondaryStatus = "blocked",
        primaryTotal = null,
        secondaryTotal = null,
        score = Double.POSITIVE_INFINITY,
        detail = "$name: tcp=50.0ms country=DE test=blocked active_verification_failed",
    )
}
