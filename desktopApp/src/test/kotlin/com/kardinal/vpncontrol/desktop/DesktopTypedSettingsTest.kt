package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DesktopTypedSettingsTest {
    @Test
    fun settingsReplyRetainsItsCommitRevisionWhenAnotherWriterCommitsBeforeLedgerCompletion() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-settings-result-revision")
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val session = DesktopHeadlessSession(scope, { service.state }, service::executeCliCommand, {},
            metadataProvider = service::controlMetadata, applySettings = { patch, revision ->
                val committed = service.applyControlSettingsResponse(patch, revision)
                // Deterministically interleave an existing GUI/service writer after the commit
                // monitor is released, but before operation completion captures the reply.
                service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(9))).getOrThrow()
                committed
            })
        try {
            val request = ControlRequest("captured", ControlCommand(ControlOperationId.SETTINGS_SET,
                mapOf("key" to ControlValue.Text("validation.batch-size"), "value" to ControlValue.Text("8"))),
                controllerId = session.controllerId)
            val result = ControlProtocolCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message)
            assertEquals(ControlCode.OK, result.code)
            assertEquals(1L, result.configurationRevision)
            assertEquals(mapOf("validation.batch-size" to ControlValue.IntegerValue(8)), result.data)
            assertEquals(2L, service.configurationRevision)
            assertEquals(9, service.state.validationSettings.batchSize)
            assertEquals(result, ControlProtocolCodec.decodeResult(session.execute(DesktopCliCommand.ControlSubmit(request)).message))
        } finally { session.close(); scope.cancel(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun authenticatedSettingsBindEpochRevisionAndRetryIdentity() {
        val directory = Files.createTempDirectory("vpn-control-typed-settings")
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val session = DesktopHeadlessSession(scope, { service.state }, service::executeCliCommand, {},
            metadataProvider = service::controlMetadata, applySettings = service::applyControlSettingsResponse)
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint,
            controllerId = session.controllerId))
        try {
            fun request(id: String, value: String, revision: Long) = ControlRequest(id,
                ControlCommand(ControlOperationId.SETTINGS_SET, mapOf(
                    "key" to ControlValue.Text("validation.batch-size"), "value" to ControlValue.Text(value))),
                controllerId = session.controllerId, ifRevision = revision)
            fun send(request: ControlRequest) = DesktopActivationServer.requestCliCommand(
                DesktopCliCommand.ControlSubmit(request), endpoint)
            val original = request("first", "17", 0)
            val saved = ControlProtocolCodec.decodeResult(send(original).message)
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(1L, saved.configurationRevision)
            assertEquals(session.controllerId, saved.controllerId)
            assertEquals(17, service.state.validationSettings.batchSize)
            assertEquals(mapOf("validation.batch-size" to ControlValue.IntegerValue(17)), saved.data)
            // Retrying the accepted request does not run a stale proposal again.
            assertEquals(saved, ControlProtocolCodec.decodeResult(send(original).message))
            assertEquals(1L, service.configurationRevision)
            assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(send(original.copy(ifRevision = 1)).message).code)
            val wrongOwner = ControlProtocolCodec.decodeResult(send(original.copy(controllerId = "different-owner")).message)
            assertEquals(ControlCode.CONFLICT, wrongOwner.code)
            assertEquals(session.controllerId, wrongOwner.controllerId)
            assertEquals(original.requestId, wrongOwner.requestId)
            assertEquals(1L, wrongOwner.configurationRevision)
            val stale = ControlProtocolCodec.decodeResult(send(request("stale", "18", 0)).message)
            assertEquals(ControlCode.CONFLICT, stale.code)
            assertEquals(1L, stale.configurationRevision)
            assertEquals(17, service.state.validationSettings.batchSize)
            val next = ControlProtocolCodec.decodeResult(send(request("next", "18", 1)).message)
            assertEquals(ControlCode.OK, next.code)
            assertEquals(2L, next.configurationRevision)
            assertEquals(saved, ControlProtocolCodec.decodeResult(send(original).message))
            assertEquals(18, DesktopStateStore(directory).loadWorkspace(DesktopWorkspace(
                com.kardinal.vpncontrol.model.PersistedState(), emptyList())).persistedState.validationSettings.batchSize)
            val batch = ControlRequest("batch", ControlCommand(ControlOperationId.SETTINGS_APPLY,
                mapOf("input" to ControlValue.Text("{\"validation.batch-size\":19,\"validation.retry-count\":2}"))),
                controllerId = session.controllerId, ifRevision = 2)
            val applied = ControlProtocolCodec.decodeResult(send(batch).message)
            assertEquals(ControlCode.OK, applied.code)
            assertEquals(3L, applied.configurationRevision)
            assertEquals(19, service.state.validationSettings.batchSize)
            assertEquals(mapOf("validation.batch-size" to ControlValue.IntegerValue(19),
                "validation.retry-count" to ControlValue.IntegerValue(2)), applied.data)
            assertEquals(applied, ControlProtocolCodec.decodeResult(send(batch).message))
            val invalid = batch.copy(requestId = "invalid", ifRevision = 3, command = ControlCommand(
                ControlOperationId.SETTINGS_APPLY, mapOf("input" to ControlValue.Text(
                    "{\"validation.batch-size\":10,\"unknown\":true}"))))
            assertEquals(ControlCode.INVALID_ARGUMENT, ControlProtocolCodec.decodeResult(send(invalid).message).code)
            assertEquals(3L, service.configurationRevision)
            assertEquals(19, service.state.validationSettings.batchSize)
            val normalizedRequest = request("normalized", "0", 3)
            val normalized = ControlProtocolCodec.decodeResult(send(normalizedRequest).message)
            assertEquals(ControlCode.OK, normalized.code)
            assertEquals(mapOf("validation.batch-size" to ControlValue.IntegerValue(1)), normalized.data)
            assertEquals(1, service.state.validationSettings.batchSize)
            assertEquals(4L, normalized.configurationRevision)
            assertEquals(normalized, ControlProtocolCodec.decodeResult(send(normalizedRequest).message))
            assertEquals(saved, ControlProtocolCodec.decodeResult(send(original).message))
            assertEquals(emptyMap(), stale.data)
        } finally {
            server.close()
            session.close()
            scope.cancel()
            directory.toFile().deleteRecursively()
        }
    }
}
