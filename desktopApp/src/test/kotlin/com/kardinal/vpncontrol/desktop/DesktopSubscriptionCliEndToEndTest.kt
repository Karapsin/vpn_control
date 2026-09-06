package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopSubscriptionCliEndToEndTest {
    @Test
    fun terminalAndGuiShareSubscriptionPlansWithoutOverwritingOpenDrafts() {
        val directory = Files.createTempDirectory("vpn-control-subscriptions-東京")
        val empty = DesktopWorkspace(PersistedState(), emptyList())
        val fetched = mutableListOf<String>()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), empty,
            subscriptionContentFetcher = object : com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher {
                override suspend fun fetch(url: String, subscriptionHwid: String): com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent {
                    fetched += url
                    if (url.contains("failed.test")) error("https://failed.test/SECRET")
                    return com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent(
                        body = "socks://127.0.0.1:1080#Refreshed", contentType = "text/plain")
                }
            })
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { service.executeCliCommand(it) } }, portFile = endpoint,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            service.toggleAddSubscriptionEditor()
            service.setProfileDraft("https://draft.example.test/unfinished")
            service.setProfileTitleDraft("Unsaved GUI draft")
            val input = directory.resolve("subscription source 東京.txt")
            val source = "https://example.test/sub?token=synthetic-secret"
            Files.writeString(input, "$source\n")
            assertEquals(0, invoke("subscriptions", "add", "--input", input.toString(), "--name", "Terminal").first)
            val id = service.state.subscriptions.single().id
            assertEquals(source, service.state.subscriptions.single().url)
            assertTrue(service.state.showAddSubscriptionEditor)
            assertEquals("Unsaved GUI draft", service.state.profileTitleDraft)
            assertEquals("https://draft.example.test/unfinished", service.state.profileDraft)
            assertFalse(invoke("subscriptions", "list").second.contains("synthetic-secret"))
            assertTrue(invoke("subscriptions", "show", id).second.contains(source))
            service.showSubscriptionRenameDialog(id)
            service.setSubscriptionRenameDraft("GUI name")
            service.saveSubscriptionRename()
            assertTrue(invoke("subscriptions", "list").second.contains("GUI name"))
            assertEquals(0, invoke("subscriptions", "update", id, "--name", "").first)
            assertEquals("", service.state.subscriptions.single().customName)
            val before = service.state
            Files.writeString(input, "not a supported subscription")
            assertEquals(1, invoke("subscriptions", "update", id, "--input", input.toString()).first)
            assertEquals(before, service.state)
            assertEquals(1, invoke("subscriptions", "update", "missing", "--name", "Name").first)
            Files.writeString(input, source)
            assertEquals(0, invoke("subscriptions", "add", "--input", input.toString(), "--name", "Same source").first)
            assertEquals(id, service.state.subscriptions.single().id)
            assertEquals(0, invoke("subscriptions", "refresh", id).first)
            assertEquals(listOf(source), fetched)
            assertEquals(1, service.state.subscriptions.single().cachedLocations.size)
            assertEquals(1, invoke("subscriptions", "refresh", "missing").first)
            assertEquals(1, fetched.size)
            Files.writeString(input, "https://failed.test/subscription")
            assertEquals(0, invoke("subscriptions", "add", "--input", input.toString()).first)
            val failedId = service.state.subscriptions.first { it.id != id }.id
            val partial = invoke("subscriptions", "refresh", "all")
            assertEquals(1, partial.first)
            assertTrue(partial.second.contains("PARTIAL_FAILURE"))
            assertTrue(partial.second.contains(id))
            assertTrue(partial.second.contains(failedId))
            assertFalse(partial.second.contains("failed.test"))
            assertFalse(partial.second.contains("SECRET"))
            assertFalse(service.state.isBusy)
            assertFalse(service.state.isRefreshing)
            assertEquals(0, invoke("subscriptions", "delete", failedId).first)
            val reloaded = DesktopStateStore(directory).loadWorkspace(empty)
            assertEquals(service.state.subscriptions, reloaded.persistedState.subscriptions)
            assertEquals(0, invoke("subscriptions", "delete", id).first)
            assertEquals(1, invoke("subscriptions", "delete", id).first)
            assertTrue(DesktopStateStore(directory).loadWorkspace(empty).persistedState.subscriptions.isEmpty())
            assertFalse(service.state.isVpnRunning)
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }
}
