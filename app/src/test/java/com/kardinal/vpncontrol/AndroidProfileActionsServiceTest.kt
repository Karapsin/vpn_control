package com.kardinal.vpncontrol

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
            ),
        )
        val service = service(
            controller = controller,
            sourcePreviewTitle = { "Preview Name" },
        )

        service.showProfileHistoryRenameDialog(" https://example.com/sub.txt ")

        assertEquals(true, controller.currentState().showProfileHistoryRenameDialog)
        assertEquals("https://example.com/sub.txt", controller.currentState().profileHistoryRenameSource)
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
