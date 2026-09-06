package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.*
import kotlin.test.*

class DesktopGuardedSshKeyTest {
    @Test fun guardedImportRejectsStaleProposalsAndDeduplicatesWithoutRetainingKeyData() = runBlocking {
        val directory = Files.createTempDirectory("guarded-key")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId))
        val credentials = DesktopHomeSshCredentialStore(directory)
        val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-GUARDED-KEY\n-----END OPENSSH PRIVATE KEY-----\n"
        fun request(id: String, revision: Long, input: String = key) = ControlRequest(id,
            ControlCommand(ControlOperationId.SSH_KEY_IMPORT, mapOf("input" to ControlValue.Text(input))),
            controllerId = owner.controllerId, ifRevision = revision)
        suspend fun send(request: ControlRequest) = withContext(Dispatchers.IO) {
            ControlProtocolCodec.decodeResult(DesktopActivationServer.requestCliCommand(
                DesktopCliCommand.ControlSubmit(request), endpoint).message)
        }
        try {
            assertEquals(ControlCode.CONFLICT, send(request("stale", 1)).code)
            assertNull(credentials.privateKeyPathOrNull())
            assertEquals(ControlCode.CONFLICT, send(request("epoch", 0).copy(controllerId = "old-owner")).code)
            assertNull(credentials.privateKeyPathOrNull())
            val original = request("import", 0)
            val saved = send(original)
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(1L, saved.configurationRevision)
            assertTrue(saved.data.isEmpty())
            assertEquals(saved, send(original)) // Response-loss retry, not another credential write.
            assertEquals(ControlCode.CONFLICT, send(original.copy(command = original.command.copy(
                arguments = mapOf("input" to ControlValue.Text(key.replace("GUARDED", "CHANGED")))))).code)
            assertEquals(ControlCode.OK, send(request("unchanged", 1)).code)
            assertEquals(1L, service.configurationRevision)
            assertEquals(1L, service.state.homeSshRouteSettings.credentialVersion)
            assertEquals(key, Files.readString(Path.of(assertNotNull(credentials.privateKeyPathOrNull()))))
            assertFalse(Files.readString(directory.resolve("workspace.json")).contains("SYNTHETIC-GUARDED-KEY"))
            assertFalse(owner.session.operationSnapshot().toString().contains("SYNTHETIC-GUARDED-KEY"))
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous-workspace.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val failed = send(request("rollback", 1, key.replace("GUARDED", "REPLACEMENT")))
            assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code)
            assertEquals(1L, failed.configurationRevision)
            assertEquals(key, Files.readString(Path.of(assertNotNull(credentials.privateKeyPathOrNull()))))
            assertEquals(failed, send(request("rollback", 1, key.replace("GUARDED", "REPLACEMENT"))))
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun credentialVersionOverflowRestoresKeyAndDoesNotChangeConfiguration() {
        val directory = Files.createTempDirectory("key-version-overflow")
        try {
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), DesktopWorkspace(
                PersistedState(homeSshRouteSettings = HomeSshRouteSettings(credentialVersion = Long.MAX_VALUE)), emptyList()))
            val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC-OVERFLOW\n-----END OPENSSH PRIVATE KEY-----\n"
            val response = service.importControlSshKey(key, 0)
            assertFalse(response.response.success)
            assertEquals(0L, service.configurationRevision)
            assertEquals(Long.MAX_VALUE, service.state.homeSshRouteSettings.credentialVersion)
            assertNull(DesktopHomeSshCredentialStore(directory).privateKeyPathOrNull())
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun resultMetadataBelongsToKeyCommitNotLaterSettingsWrite() = runBlocking {
        val directory = Files.createTempDirectory("key-result-metadata")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val session = DesktopHeadlessSession(scope, { service.state }, service::executeCliCommand, {},
            metadataProvider = service::controlMetadata, importSshKey = { content, revision ->
                service.importControlSshKey(content, revision).also {
                    service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(7))).getOrThrow()
                }
            })
        try {
            val request = ControlRequest("key", ControlCommand(ControlOperationId.SSH_KEY_IMPORT,
                mapOf("input" to ControlValue.Text("-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTHETIC\n-----END OPENSSH PRIVATE KEY-----\n"))),
                controllerId = session.controllerId, ifRevision = 0)
            val result = ControlProtocolCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message)
            assertEquals(ControlCode.OK, result.code)
            assertEquals(1L, result.configurationRevision)
            assertEquals(2L, service.configurationRevision)
        } finally { session.close(); scope.cancel(); directory.toFile().deleteRecursively() }
    }
}
