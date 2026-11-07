package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import kotlin.test.*

/** Exercise the public argv adapter, not just the parser-to-owner shortcut. */
class DesktopCliSourceModeParityTest {
    @Test
    fun modeOnlySelectionMatchesGuiAndPersistsEmptyAndRememberedSelections() = runBlocking {
        for (json in listOf(false, true)) for (remember in listOf(false, true)) {
            fixture {
                val remembered = if (remember) service.saveControlSubscription(
                    "https://example.test/remembered", "Remembered", null).getOrThrow() else null
                if (remembered != null) service.activateSelection(remembered).getOrThrow()
                suspend fun gui(mode: String) = owner.submit(desktopGuiSourceAction("frontend", owner.controllerId,
                    service.configurationRevision, ControlCommand(ControlOperationId.SOURCE_SET,
                        mapOf("mode" to ControlValue.Text(mode)))))
                assertEquals(ControlCode.OK, gui("current-locations").code)
                val beforeGui = service.configurationRevision
                assertEquals(ControlCode.OK, gui("subscription").code)
                val guiRevisionChange = service.configurationRevision - beforeGui
                val guiState = service.state.profileSourceMode to service.state.activeSubscriptionId
                assertEquals(ControlCode.OK, gui("current-locations").code)

                val beforeCli = service.configurationRevision
                invoke(this, json, "--controller-id", owner.controllerId, "--if-revision", beforeCli.toString(),
                    "source", "set", "subscription")
                assertEquals(ProfileSourceMode.SUBSCRIPTION to remembered.orEmpty(), guiState)
                assertEquals(guiState, service.state.profileSourceMode to service.state.activeSubscriptionId)
                assertEquals(guiRevisionChange, service.configurationRevision - beforeCli)
                val persisted = store.loadWorkspace(DesktopWorkspace(PersistedState(), emptyList())).persistedState
                assertEquals(guiState, persisted.profileSourceMode to persisted.activeSubscriptionId)

                // A repeated mode selection is a durable no-op, as with the GUI toggle.
                val revision = service.configurationRevision
                invoke(this, json, "source", "set", "subscription")
                assertEquals(revision, service.configurationRevision)
            }
        }
    }

    @Test
    fun explicitSubscriptionIdsStillSelectAndMissingIdsDoNotMutate() = runBlocking {
        for (json in listOf(false, true)) fixture {
            val first = service.saveControlSubscription("https://example.test/first", "First", null).getOrThrow()
            val second = service.saveControlSubscription("https://example.test/second", "Second", null).getOrThrow()
            invoke(this, json, "source", "set", "current-locations")
            invoke(this, json, "source", "set", "subscription", first)
            assertEquals(first, service.state.activeSubscriptionId)
            invoke(this, json, "source", "set", "subscription", second)
            assertEquals(ProfileSourceMode.SUBSCRIPTION, service.state.profileSourceMode)
            assertEquals(second, service.state.activeSubscriptionId)
            assertEquals(second, store.loadWorkspace(DesktopWorkspace(PersistedState(), emptyList())).persistedState.activeSubscriptionId)
            val revision = service.configurationRevision
            invoke(this, json, "source", "set", "subscription", "missing", expected = ControlCode.NOT_FOUND)
            assertEquals(second, service.state.activeSubscriptionId)
            assertEquals(revision, service.configurationRevision)
        }
    }

    @Test
    fun sourceSelectionRejectsInvalidArgumentsBeforeContactingOwner() {
        for (json in listOf(false, true)) for (args in listOf(
            arrayOf("source", "set"),
            arrayOf("source", "set", "unknown"),
            arrayOf("source", "set", "current-locations", "extra"),
            arrayOf("source", "set", "all", "extra"),
            arrayOf("source", "set", "subscription", "id", "extra"),
            arrayOf("source", "set", "subscription", "--unknown"),
            arrayOf("--if-revision", "0", "source", "set", "subscription"),
            arrayOf("--controller-id", "owner", "--if-revision", "-1", "source", "set", "subscription"),
        )) {
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            assertEquals(1, DesktopCli.handleArgs(arrayOf(*(if (json) arrayOf("--json") else emptyArray()), *args),
                printLine = stdout::add, printProgress = stderr::add,
                requestCommand = { error("Invalid argv must not contact an owner: ${args.toList()}") },
                startHeadlessController = { error("Invalid argv must not start an owner") }))
            assertOutput(json, ControlCode.INVALID_ARGUMENT, stdout, stderr)
        }
    }

    @Test
    fun modeOnlyAndExplicitSelectionRetainEpochAndRevisionGuards() = runBlocking {
        for (json in listOf(false, true)) fixture {
            val id = service.saveControlSubscription("https://example.test/first", "First", null).getOrThrow()
            service.setSourceMode(ProfileSourceMode.CURRENT_LOCATIONS).getOrThrow()
            for (selection in listOf(arrayOf("subscription"), arrayOf("subscription", id))) {
                val revision = service.configurationRevision
                for ((epoch, expectedRevision) in listOf("old-owner" to revision, owner.controllerId to revision - 1)) {
                    invoke(this, json, "--controller-id", epoch, "--if-revision", expectedRevision.toString(),
                        "source", "set", *selection, expected = ControlCode.CONFLICT)
                    assertEquals(ProfileSourceMode.CURRENT_LOCATIONS, service.state.profileSourceMode)
                    assertEquals(id, service.state.activeSubscriptionId)
                    assertEquals(revision, service.configurationRevision)
                }
            }
        }
    }

    @Test
    fun pinnedModeOnlyRequestDoesNotBootstrapMissingOwner() {
        for (json in listOf(false, true)) {
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            var requests = 0
            val exit = DesktopCli.handleArgs(arrayOf(*(if (json) arrayOf("--json") else emptyArray()),
                "--controller-id", "missing-owner", "--if-revision", "0", "source", "set", "subscription"),
                printLine = stdout::add, printProgress = stderr::add,
                requestCommand = {
                    val request = assertIs<DesktopCliCommand.ControlSubmit>(it).request
                    assertEquals("missing-owner", request.controllerId)
                    assertEquals(0L, request.ifRevision)
                    requests++
                    DesktopCliResponse.notRunning()
                }, startHeadlessController = { error("Pinned request must not bootstrap a replacement owner") })
            assertEquals(2, exit)
            assertEquals(1, requests)
            assertOutput(json, ControlCode.UNAVAILABLE, stdout, stderr)
        }
    }

    private data class Fixture(val service: DesktopAppService, val store: DesktopStateStore,
        val owner: DesktopControllerOwner, val endpoint: Path)

    private suspend fun fixture(block: suspend Fixture.() -> Unit) {
        val directory = Files.createTempDirectory("public-source-mode-東京 ")
        val store = DesktopStateStore(directory)
        val service = DesktopAppServiceFactory.createForTesting(store, DesktopWorkspace(PersistedState(), emptyList()))
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } }, portFile = endpoint,
            controllerId = owner.controllerId))
        try { Fixture(service, store, owner, endpoint).block() }
        finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    private fun invoke(fixture: Fixture, json: Boolean, vararg args: String,
        expected: ControlCode = ControlCode.OK) {
        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        var requests = 0
        val exit = DesktopCli.handleArgs(arrayOf(*(if (json) arrayOf("--json") else emptyArray()), *args),
            printLine = stdout::add, printProgress = stderr::add,
            requestCommand = {
                requests++
                DesktopActivationServer.requestCliCommand(it, fixture.endpoint)
            }, startHeadlessController = { error("Fixture already owns controller") })
        assertEquals(expected.exitCode, exit, "argv=${args.toList()}, stdout=$stdout, stderr=$stderr")
        assertEquals(1, requests)
        assertOutput(json, expected, stdout, stderr)
    }

    private fun assertOutput(json: Boolean, code: ControlCode, stdout: List<String>, stderr: List<String>) {
        if (json) {
            assertTrue(stderr.isEmpty(), stderr.toString())
            val result = ControlDocumentCodec.decodeResult(stdout.single())
            assertEquals(code, result.code)
            assertTrue(result.final)
        } else if (code == ControlCode.OK) {
            assertTrue(stderr.isEmpty(), stderr.toString())
            assertTrue(stdout.single().isNotBlank())
        } else {
            assertTrue(stdout.isEmpty(), stdout.toString())
            assertTrue(stderr.single().startsWith(code.wireName), stderr.toString())
        }
    }
}
