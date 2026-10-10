package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.data.*
import android.content.Context
import android.content.ContextWrapper
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import java.io.File
import kotlinx.coroutines.*
import org.junit.Assert.*
import com.kardinal.vpncontrol.shared.storageapi.RefreshScheduler
import com.kardinal.vpncontrol.model.SubscriptionStatusMessages
import com.kardinal.vpncontrol.data.ImportPreference
import com.kardinal.vpncontrol.model.ProfileSourceMode
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AndroidProfileActionsServiceTest {
    @Test
    fun saveProfileEmitsPersistableProfileSourceEffect() {
        val controller = MainController(
            MainUiState(
                profileDraft = " https://example.com/sub.txt ",
                profileTitleDraft = "Example",
                profileSourceMode = ProfileSourceMode.SUBSCRIPTION,
                showAddSubscriptionEditor = true,
            ),
        )
        val capturedEffects = mutableListOf<MainControllerEffect>()
        val service = service(
            controller = controller,
            effectSink = AndroidControllerEffectSink { effects -> capturedEffects += effects },
        )

        service.saveProfile()

        assertEquals("https://example.com/sub.txt", controller.currentState().profileDraft)
        assertFalse(controller.currentState().showAddSubscriptionEditor)
        assertEquals(
            listOf(
                MainControllerEffect.SaveProfileSource(
                    value = "https://example.com/sub.txt",
                    mode = ProfileSourceMode.SUBSCRIPTION,
                    normalizedName = "Example",
                    statusMessage = SubscriptionStatusMessages.subscriptionSaved(),
                ),
            ),
            capturedEffects,
        )
    }

    @Test
    fun showRenameDialogPrefersSavedNameOverPreview() {
        val controller = MainController(
            MainUiState(
                profileHistoryNames = mapOf("https://example.com/sub.txt" to "Saved Name"),
                subscriptions = listOf(SubscriptionSource("saved", "https://example.com/sub.txt", "Saved Name")),
            ),
        )
        val service = service(
            controller = controller,
            sourcePreviewTitle = { "Preview Name" },
        )

        service.showProfileHistoryRenameDialog(" https://example.com/sub.txt ")

        assertEquals(true, controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("https://example.com/sub.txt", controller.currentState().profileHistoryRenameSource)
        assertEquals("https://example.com/sub.txt", controller.currentState().profileHistoryRenameUrlDraft)
        assertEquals("Saved Name", controller.currentState().profileHistoryRenameDraft)
    }

    @Test
    @OptIn(ExperimentalCoroutinesApi::class)
    fun incomingImportFailureUpdatesStatus() = runTest {
        val controller = MainController()
        val statuses = mutableListOf<String>()
        val service = service(
            controller = controller,
            launch = { block -> launch { block() } },
            updateStatus = { statuses += it },
            resolveIncomingImport = { _, _, _ ->
                Result.failure(IllegalArgumentException("bad import"))
            },
        )

        service.handleIncomingImportText("not a subscription", ImportPreference.AUTO)
        advanceUntilIdle()

        assertEquals(listOf("bad import"), statuses)
    }

    @Test fun staleRenameCannotOverwriteCliNameCommittedAtSameUrl() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("GUI draft")
        f.cli(ControlOperationId.SUBSCRIPTIONS_UPDATE, "id" to f.id, "name" to "CLI winner")
        f.service.saveProfileHistoryRename()
        assertEquals("CLI winner", f.saved().subscriptions.single().customName)
        assertEquals(2L, f.storage.configurationSnapshot().revision)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("GUI draft", f.controller.currentState().profileHistoryRenameDraft)
        assertEquals(ControlCode.CONFLICT, f.results.last().code)
    }

    @Test fun deletedThenRecreatedUrlNeverRetargetsCapturedSubscriptionId() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("old draft")
        f.cli(ControlOperationId.SUBSCRIPTIONS_DELETE, "id" to f.id)
        f.cli(ControlOperationId.SUBSCRIPTIONS_ADD, "source" to f.url, "name" to "replacement")
        val replacement = f.saved().subscriptions.single().id
        assertNotEquals(f.id, replacement)
        f.service.saveProfileHistoryRename()
        assertEquals(replacement, f.saved().subscriptions.single().id)
        assertEquals("replacement", f.saved().subscriptions.single().customName)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
    }

    @Test fun removedTargetRetainsDraftAndCommittedDeletion() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("preserved")
        f.cli(ControlOperationId.SUBSCRIPTIONS_DELETE, "id" to f.id)
        f.service.saveProfileHistoryRename()
        assertTrue(f.saved().subscriptions.isEmpty())
        assertEquals("preserved", f.controller.currentState().profileHistoryRenameDraft)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
    }

    @Test fun ownerReplacementRejectsOpeningEpochWithoutRebase() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("preserved")
        f.replaceOwner()
        f.service.saveProfileHistoryRename()
        assertEquals(ControlCode.CONFLICT, f.results.last().code)
        assertEquals("Original", f.saved().subscriptions.single().customName)
        assertEquals(f.ownerId, f.requests.last().controllerId)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
    }

    @Test fun busySaveNeverChangesConfigurationOrClosesDraft() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("preserved")
        val lease = requireNotNull(f.jobs.tryAcquireMutation())
        try {
            f.service.saveProfileHistoryRename()
            assertEquals(ControlCode.BUSY, f.results.last().code)
            assertEquals("Original", f.saved().subscriptions.single().customName)
            assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        } finally { f.jobs.releaseMutation(lease) }
    }

    @Test fun unknownRuntimeAndPersistenceFailureKeepDraftAndOriginalBytes() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("preserved")
        val bytes = f.preferencesFile.readBytes()
        f.runtimeKnown = false
        f.service.saveProfileHistoryRename()
        assertEquals(ControlCode.RUNTIME_FAILED, f.results.last().code)
        assertArrayEquals(bytes, f.preferencesFile.readBytes())
        f.runtimeKnown = true
        f.failPersistence = true
        runCatching { f.service.saveProfileHistoryRename() }
        assertEquals(ControlCode.PERSISTENCE_FAILED, f.results.last().code)
        assertArrayEquals(bytes, f.preferencesFile.readBytes())
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("preserved", f.controller.currentState().profileHistoryRenameDraft)
    }

    @Test fun responseLossExplicitRetryUsesExactAcceptedRequestAndLedgerResult() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("Committed once")
        f.loseNextResponse = true
        f.service.saveProfileHistoryRename()
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("Committed once", f.saved().subscriptions.single().customName)
        assertEquals(2L, f.storage.configurationSnapshot().revision)
        val request = f.requests.single()
        f.service.saveProfileHistoryRename()
        assertEquals(listOf(request, request), f.requests)
        assertEquals(2L, f.storage.configurationSnapshot().revision)
        assertFalse(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals(2, f.schedules) // initial add plus one rename; retry has no effect.
    }

    @Test fun editedUnknownRequestCannotReplayOrRebase() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("accepted")
        f.loseNextResponse = true
        f.service.saveProfileHistoryRename()
        f.service.onProfileHistoryRenameDraftChanged("different")
        f.service.saveProfileHistoryRename()
        assertEquals(1, f.requests.size)
        assertEquals("accepted", f.saved().subscriptions.single().customName)
        assertEquals("different", f.controller.currentState().profileHistoryRenameDraft)
        assertEquals(ControlCode.OUTCOME_UNKNOWN.wireName, f.statuses.last())
    }

    @Test fun responseLossRetryAgainstReplacementOwnerNeverStartsNewMutation() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("accepted")
        f.loseNextResponse = true
        f.service.saveProfileHistoryRename()
        val request = f.requests.single()
        f.replaceOwner()
        f.service.saveProfileHistoryRename()
        assertEquals(listOf(request, request), f.requests)
        assertEquals(ControlCode.CONFLICT, f.results.last().code)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("accepted", f.saved().subscriptions.single().customName)
    }

    @Test fun successfulTypedSaveNormalizesInputsAndPreservesStableId() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameUrlDraftChanged(" https://new.example.test/sub ")
        f.service.onProfileHistoryRenameDraftChanged(" Renamed ")
        f.service.saveProfileHistoryRename()
        val row = f.saved().subscriptions.single()
        assertEquals(f.id, row.id)
        assertEquals("https://new.example.test/sub", row.url)
        assertEquals("Renamed", row.customName)
        assertEquals(ControlOperationId.SUBSCRIPTIONS_UPDATE, f.requests.single().command.operation)
        assertEquals(1L, f.requests.single().ifRevision)
        assertEquals(f.ownerId, f.requests.single().controllerId)
        assertFalse(f.controller.currentState().showProfileHistoryRenameDialog)
    }

    @Test fun saveWithoutOpeningCannotWriteOrDismissExistingInput() = fixture { f ->
        f.controller.showProfileHistoryRenameDialog(f.url, "unbound draft")
        f.service.saveProfileHistoryRename()
        assertEquals("Original", f.saved().subscriptions.single().customName)
        assertTrue(f.requests.isEmpty())
        assertEquals(ControlCode.CONFLICT.wireName, f.statuses.last())
        assertEquals("unbound draft", f.controller.currentState().profileHistoryRenameDraft)
    }

    @Test fun lateOpeningAfterCloseCannotReopenDialog() = fixture { f ->
        f.queueFrontend = true
        f.service.showProfileHistoryRenameDialog(f.url)
        f.service.closeProfileHistoryRenameDialog()
        f.runNext()
        assertFalse(f.controller.currentState().showProfileHistoryRenameDialog)
    }

    @Test fun lateOpeningAfterReopenCannotReplaceNewOpening() = fixture { f ->
        val otherUrl = "https://second.example.test/sub"
        f.cli(ControlOperationId.SUBSCRIPTIONS_ADD, "source" to otherUrl, "name" to "Second")
        f.controller.mergePersistedState(f.saved())
        f.queueFrontend = true
        f.service.showProfileHistoryRenameDialog(f.url)
        f.service.showProfileHistoryRenameDialog(otherUrl)
        f.runNext()
        assertFalse(f.controller.currentState().showProfileHistoryRenameDialog)
        f.runNext()
        assertEquals(otherUrl, f.controller.currentState().profileHistoryRenameSource)
        assertEquals("Second", f.controller.currentState().profileHistoryRenameDraft)
    }

    @Test fun closedOrEditedQueuedSaveCannotSubmitCapturedOldInput() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("old input")
        f.queueFrontend = true
        f.service.saveProfileHistoryRename()
        f.service.onProfileHistoryRenameDraftChanged("new input")
        f.runNext()
        assertTrue(f.requests.isEmpty())
        assertEquals("Original", f.saved().subscriptions.single().customName)
        f.service.saveProfileHistoryRename()
        f.service.closeProfileHistoryRenameDialog()
        f.runNext()
        assertTrue(f.requests.isEmpty())
        assertEquals("Original", f.saved().subscriptions.single().customName)
    }

    @Test fun inFlightSuccessCannotEraseEditedDraftOrCloseReopenedDialog() = fixture { f ->
        for (reopen in listOf(false, true)) {
            f.open()
            f.service.onProfileHistoryRenameDraftChanged("submitted-$reopen")
            f.queueFrontend = true
            val reached = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            f.afterExecute = { reached.complete(Unit); release.await() }
            f.service.saveProfileHistoryRename()
            coroutineScope {
                val waiting = async { f.runNext() }
                reached.await()
                if (reopen) {
                    f.service.closeProfileHistoryRenameDialog()
                    f.queueFrontend = false
                    f.service.showProfileHistoryRenameDialog(f.url)
                }
                f.service.onProfileHistoryRenameDraftChanged("new input-$reopen")
                release.complete(Unit)
                waiting.await()
            }
            assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
            assertEquals("new input-$reopen", f.controller.currentState().profileHistoryRenameDraft)
            f.afterExecute = {}
            f.queueFrontend = false
            f.service.closeProfileHistoryRenameDialog()
        }
    }

    @Test fun invalidUrlAndDuplicateSourceRetainUserInputWithoutMutation() = fixture { f ->
        val otherUrl = "https://other.example.test/sub"
        f.cli(ControlOperationId.SUBSCRIPTIONS_ADD, "source" to otherUrl)
        for (url in listOf("invalid source", otherUrl)) {
            f.controller.mergePersistedState(f.saved())
            f.open()
            f.service.onProfileHistoryRenameUrlDraftChanged(url)
            val before = f.storage.configurationSnapshot()
            f.service.saveProfileHistoryRename()
            assertEquals(ControlCode.INVALID_ARGUMENT, f.results.last().code)
            assertEquals(before, f.storage.configurationSnapshot())
            assertEquals(url, f.controller.currentState().profileHistoryRenameUrlDraft)
            assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
            f.service.closeProfileHistoryRenameDialog()
        }
    }

    @Test fun pendingOpeningCannotOverwriteDraftEditedBeforeSnapshotReturns() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("prior visible draft")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        f.beforeOpeningSnapshot = { entered.complete(Unit); release.await() }
        f.queueFrontend = true
        f.service.showProfileHistoryRenameDialog(f.url)
        coroutineScope {
            val waiting = async { f.runNext() }
            entered.await()
            f.service.onProfileHistoryRenameDraftChanged("edit during opening")
            release.complete(Unit)
            waiting.await()
        }
        assertEquals("edit during opening", f.controller.currentState().profileHistoryRenameDraft)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertTrue(f.requests.isEmpty())
    }

    @Test fun pendingOpeningFailureCannotPublishAfterDraftEdit() = fixture { f ->
        f.open()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        f.beforeOpeningSnapshot = { entered.complete(Unit); release.await(); throw java.io.IOException("PRIVATE_OPEN_FAILURE") }
        f.queueFrontend = true
        f.service.showProfileHistoryRenameDialog(f.url)
        coroutineScope {
            val waiting = async { f.runNext() }
            entered.await()
            f.service.onProfileHistoryRenameDraftChanged("newer visible input")
            release.complete(Unit)
            waiting.await()
        }
        assertTrue("Superseded opening failure must not publish status", f.statuses.isEmpty())
        assertEquals("newer visible input", f.controller.currentState().profileHistoryRenameDraft)
    }

    @Test fun queuedMissingOpeningErrorCannotPublishAfterReopen() = fixture { f ->
        f.controller.showProfileHistoryRenameDialog(f.url, "unbound")
        f.queueFrontend = true
        f.service.saveProfileHistoryRename()
        f.service.closeProfileHistoryRenameDialog()
        f.queueFrontend = false
        f.open()
        f.runNext()
        assertTrue("Old validation must not publish into reopened dialog", f.statuses.isEmpty())
        assertEquals("Original", f.controller.currentState().profileHistoryRenameDraft)
        assertTrue(f.requests.isEmpty())
    }

    @Test fun queuedUnknownInputErrorCannotPublishAfterReopen() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("accepted")
        f.loseNextResponse = true
        f.service.saveProfileHistoryRename()
        f.statuses.clear()
        f.service.onProfileHistoryRenameDraftChanged("different input")
        f.queueFrontend = true
        f.service.saveProfileHistoryRename()
        f.service.closeProfileHistoryRenameDialog()
        f.queueFrontend = false
        f.open()
        f.runNext()
        assertTrue("Old uncertain-input validation must not publish after reopening", f.statuses.isEmpty())
        assertEquals("accepted", f.controller.currentState().profileHistoryRenameDraft)
        assertEquals(1, f.requests.size)
    }

    @Test fun acceptedSaveCannotPublishSuccessIntoNewerEditedDraft() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("accepted")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        f.afterExecute = { entered.complete(Unit); release.await() }
        f.queueFrontend = true
        f.service.saveProfileHistoryRename()
        coroutineScope {
            val waiting = async { f.runNext() }
            entered.await()
            assertEquals("accepted", f.saved().subscriptions.single().customName)
            f.service.onProfileHistoryRenameDraftChanged("newer unsaved input")
            release.complete(Unit)
            waiting.await()
        }
        assertTrue("Accepted older save must not publish stale success", f.statuses.isEmpty())
        assertEquals("newer unsaved input", f.controller.currentState().profileHistoryRenameDraft)
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        assertEquals(ControlCode.OK, f.results.single().code)
    }

    @Test fun acceptedFailureCannotPublishIntoNewerEditedDraft() = fixture { f ->
        f.open()
        f.service.onProfileHistoryRenameDraftChanged("attempted")
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        f.afterExecute = { entered.complete(Unit); release.await() }
        val lease = requireNotNull(f.jobs.tryAcquireMutation())
        try {
            f.queueFrontend = true
            f.service.saveProfileHistoryRename()
            coroutineScope {
                val waiting = async { f.runNext() }
                entered.await()
                f.service.onProfileHistoryRenameDraftChanged("newer unsaved input")
                release.complete(Unit)
                waiting.await()
            }
            assertTrue("Older rejected save must not publish stale failure", f.statuses.isEmpty())
            assertEquals("newer unsaved input", f.controller.currentState().profileHistoryRenameDraft)
            assertEquals(ControlCode.BUSY, f.results.single().code)
            assertEquals("Original", f.saved().subscriptions.single().customName)
        } finally { f.jobs.releaseMutation(lease) }
    }

    @Test fun queuedMissingOpeningErrorCannotPublishAfterPendingOpenCompletes() = fixture { f ->
        f.queueFrontend = true
        f.service.showProfileHistoryRenameDialog(f.url)
        f.service.saveProfileHistoryRename()
        f.runNext() // The actual committed snapshot establishes an opening in this same generation.
        assertTrue(f.controller.currentState().showProfileHistoryRenameDialog)
        f.runNext()
        assertTrue("Missing-opening validation must not publish after an opening becomes available", f.statuses.isEmpty())
        assertEquals("Original", f.controller.currentState().profileHistoryRenameDraft)
        assertTrue(f.requests.isEmpty())
    }

    private fun fixture(block: suspend (RenameFixture) -> Unit) = runBlocking {
        RenameFixture().use { fixture -> block(fixture) }
    }

    /** Only Context directories, known native stopped state and unused scheduling are external seams. */
    private class RenameFixture : AutoCloseable {
        val root = java.nio.file.Files.createTempDirectory("android-subscription-rename-").toFile()
        private val context = object : ContextWrapper(null) {
            private val files = File(root, "files").also { check(it.mkdirs()) }
            private val cache = File(root, "cache").also { check(it.mkdirs()) }
            override fun getApplicationContext(): Context = this
            override fun getFilesDir(): File = files
            override fun getCacheDir(): File = cache
            override fun getPackageName(): String = "com.kardinal.vpncontrol.rename.fixture"
        }
        val preferencesFile = File(root, "rename.preferences_pb")
        private val storeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val ownerScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        var runtimeKnown = true
        var failPersistence = false
        private val realStore = androidx.datastore.core.DataStoreFactory.create(
            serializer = AndroidPreferencesSerializer(context.cacheDir.toPath()), scope = storeScope) { preferencesFile }
        private val store = object : DataStore<Preferences> {
            override val data = realStore.data
            override suspend fun updateData(transform: suspend (Preferences) -> Preferences): Preferences {
                if (failPersistence) throw java.io.IOException("PRIVATE_PERSISTENCE_FAILURE")
                return realStore.updateData(transform)
            }
        }
        // ProfileStorage owns the normal application singleton. Swap only its DataStore transport
        // for an owned real instance; preserve its decoder, atomic edit and exact production writes.
        private val singleton = Class.forName("com.kardinal.vpncontrol.data.AndroidPreferencesStore")
        private val singletonObject = singleton.getDeclaredField("INSTANCE").also { it.isAccessible = true }.get(null)
        private val singletonStore = singleton.getDeclaredField("instance").also { it.isAccessible = true }
        private val previousStore = singletonStore.get(singletonObject)
        init { singletonStore.set(singletonObject, store) }
        val storage = ProfileStorage(context, runtimeRunning = { if (runtimeKnown) false else null })
        val ownerId = AndroidConfigurationEpoch.id
        val jobs = AndroidCommandJobs(ownerScope)
        var schedules = 0
        private fun owner(id: String) = AndroidSettingsControl(id, ownerScope, storage::configurationSnapshot,
            { _, _, _ -> error("unused settings path") }, { schedules++ }, { false }, mutationJobs = jobs,
            subscription = storage::commitControlSubscription)
        private var control = owner(ownerId)
        val controller = MainController()
        val statuses = mutableListOf<String>()
        val requests = mutableListOf<ControlRequest>()
        val results = mutableListOf<ControlResult>()
        val url = "https://original.example.test/sub"
        val id: String
        var loseNextResponse = false
        var afterExecute: suspend () -> Unit = {}
        var beforeOpeningSnapshot: suspend () -> Unit = {}
        var queueFrontend = false
        private val queued = ArrayDeque<suspend () -> Unit>()
        private val launchFrontend: (suspend () -> Unit) -> Unit = { work ->
            if (queueFrontend) queued.addLast(work) else runBlocking { work() }
        }
        private val scheduler = object : RefreshScheduler {
            override suspend fun sync(state: PersistedState) { schedules++ }
            override suspend fun scheduleNext(state: PersistedState) { error("unused schedule") }
            override fun cancel() { error("unused cancellation") }
        }
        private val repository = AppRepository(storage, BenchmarkOrchestrator(context, storage), scheduler, { false })
        private val effects = AndroidControllerEffectHandler(repository, launchFrontend, {}, {}, launchFrontend)
        val service = AndroidProfileActionsService(
            renameDraft = AndroidSubscriptionRenameDraftControl(controller, controller::currentState, launchFrontend,
                { beforeOpeningSnapshot(); storage.configurationSnapshot() }, { request ->
                    requests += request
                    val result = control.execute(request).also { results += it }
                    afterExecute()
                    if (loseNextResponse) { loseNextResponse = false; throw java.io.IOException("PRIVATE_RESPONSE_LOSS") }
                    result
                }, { statuses += it }),
            controller = controller, stateProvider = controller::currentState, effectSink = effects,
            launch = launchFrontend, updateStatus = { statuses += it }, launchMutation = launchFrontend,
        )
        init {
            val result = runBlocking { cli(ControlOperationId.SUBSCRIPTIONS_ADD, "source" to url, "name" to "Original") }
            id = (result.data.getValue("id") as ControlValue.Text).value
            runBlocking { controller.mergePersistedState(saved()) }
        }
        fun open() { service.showProfileHistoryRenameDialog(url) }
        suspend fun saved() = storage.configurationSnapshot().value
        suspend fun cli(operation: ControlOperationId, vararg values: Pair<String, String>): ControlResult {
            val snapshot = storage.configurationSnapshot()
            return control.execute(ControlRequest(java.util.UUID.randomUUID().toString(), ControlCommand(operation,
                values.associate { it.first to ControlValue.Text(it.second) }), controllerId = snapshot.controllerId,
                ifRevision = snapshot.revision)).also { check(it.code == ControlCode.OK) }
        }
        fun replaceOwner() { control = owner("replacement-owner") }
        suspend fun runNext() { queued.removeFirst()() }
        override fun close() {
            queued.clear()
            runBlocking {
                ownerScope.coroutineContext[Job]!!.cancelAndJoin()
                storeScope.coroutineContext[Job]!!.cancelAndJoin()
            }
            singletonStore.set(singletonObject, previousStore)
            check(root.deleteRecursively())
        }
    }

    private fun service(
        controller: MainController,
        effectSink: AndroidControllerEffectSink = AndroidControllerEffectSink {},
        launch: (suspend () -> Unit) -> Unit = { block ->
            kotlinx.coroutines.runBlocking { block() }
        },
        updateStatus: suspend (String) -> Unit = {},
        sourcePreviewTitle: (String) -> String? = { null },
        validateProfileSource: (String) -> Result<Unit> = { Result.success(Unit) },
        resolveIncomingImport: suspend (
            raw: String,
            preference: ImportPreference,
            validateSubscription: (String) -> Result<Unit>,
        ) -> Result<com.kardinal.vpncontrol.data.IncomingImportPayload> = { _, _, _ ->
            Result.failure(IllegalStateException("not configured"))
        },
    ): AndroidProfileActionsService {
        return AndroidProfileActionsService(
            renameDraft = AndroidSubscriptionRenameDraftControl(controller, controller::currentState, launch,
                { ControlCommitted("test-owner", 0, PersistedState(subscriptions = controller.currentState().subscriptions)) },
                { error("not configured") }, updateStatus, sourcePreviewTitle),
            controller = controller,
            stateProvider = controller::currentState,
            effectSink = effectSink,
            launch = launch,
            updateStatus = updateStatus,
            sourcePreviewTitle = sourcePreviewTitle,
            validateProfileSource = validateProfileSource,
            resolveIncomingImport = resolveIncomingImport,
        )
    }
}
