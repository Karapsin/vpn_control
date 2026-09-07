package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.PersistedState
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopSshCliTest {
    @Test
    fun importTransfersContentPrivatelyAndRollsBackWhenMetadataCannotBeSaved() {
        val directory = Files.createTempDirectory("vpn-control-ssh-cli-東京")
        val store = DesktopStateStore(directory)
        val service = DesktopAppServiceFactory.createForTesting(store, DesktopWorkspace(PersistedState(), emptyList()))
        val credentials = DesktopHomeSshCredentialStore(directory)
        val endpoint = directory.resolve("activation.port")
        val owner = DesktopControllerOwner(service)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add, printProgress = lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            assertTrue(invoke("ssh", "key", "status").second.contains("present: false"))
            assertTrue(invoke("settings", "languages").second.contains("system"))
            val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-PRIVATE-INPUT\n-----END OPENSSH PRIVATE KEY-----\n"
            val input = directory.resolve("test key 東京.txt")
            Files.writeString(input, key)
            val response = invoke("ssh", "key", "import", "--input", input.toString())
            assertEquals(0, response.first)
            assertFalse(response.second.contains("SYNTHETIC-PRIVATE-INPUT"))
            assertTrue(invoke("ssh", "key", "status").second.contains("present: true"))
            assertEquals(1L, service.state.homeSshRouteSettings.credentialVersion)
            assertEquals(1L, service.configurationRevision)
            assertEquals(0, invoke("ssh", "key", "import", "--input", input.toString()).first)
            assertEquals(1L, service.state.homeSshRouteSettings.credentialVersion)
            assertEquals(1L, service.configurationRevision)
            assertFalse(Files.readString(directory.resolve("workspace.json")).contains("SYNTHETIC-PRIVATE-INPUT"))
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous-workspace.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            Files.writeString(input, key.replace("SYNTHETIC-PRIVATE-INPUT", "SYNTHETIC-REPLACEMENT"))
            val failed = invoke("ssh", "key", "import", "--input", input.toString())
            assertEquals(1, failed.first)
            assertTrue(failed.second.startsWith("PERSISTENCE_FAILED\n"))
            assertEquals(key, Files.readString(Path.of(credentials.privateKeyPathOrNull()!!)))
            assertEquals(1L, service.state.homeSshRouteSettings.credentialVersion)
            assertEquals(1L, service.configurationRevision)
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
