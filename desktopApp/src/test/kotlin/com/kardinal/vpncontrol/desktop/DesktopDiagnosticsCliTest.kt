package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.SettingsStatusMessages
import java.nio.file.Files
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.cancel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopDiagnosticsCliTest {
    @Test
    fun timedOutOrNonExportOperationWaitNeverWritesAndRetainsItsOperationIdentity() {
        fun response(code: ControlCode, final: Boolean, data: Map<String, com.kardinal.vpncontrol.model.ControlValue> = emptyMap()): DesktopCliResponse {
            val result = ControlResult("owner", "request", code, 0, final = final,
                operationId = "operation-identity", data = data)
            return DesktopCliResponse(result.ok, com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result), result.exitCode)
        }
        fun invoke(output: String, response: DesktopCliResponse): Triple<Int?, List<String>, ByteArray> {
            val lines = mutableListOf<String>()
            val errors = mutableListOf<String>()
            val bytes = java.io.ByteArrayOutputStream()
            val arguments = if (output == "-") arrayOf("operations", "wait", "operation-identity", "--output", output)
                else arrayOf("--json", "operations", "wait", "operation-identity", "--output", output)
            val code = DesktopCli.handleArgs(arguments, lines::add,
                requestCommand = { command ->
                    val request = (command as DesktopCliCommand.ControlSubmit).request
                    val result = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(response.message)
                    response.copy(message = com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(
                        result.copy(requestId = request.requestId)))
                }, startHeadlessController = { error("Must not replace owner") },
                writeOutput = { _, _ -> error("Timed-out/non-export result must not write a file") },
                writeBinaryOutput = { _, chunk -> bytes.write(chunk); Result.success(Unit) }, printProgress = errors::add)
            return Triple(code, lines + errors, bytes.toByteArray())
        }
        val fileTimeout = invoke("report.txt", response(ControlCode.TIMEOUT, final = false))
        assertEquals(2, fileTimeout.first)
        val timeoutResult = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(fileTimeout.second.single())
        assertEquals(ControlCode.TIMEOUT, timeoutResult.code)
        assertEquals("operation-identity", timeoutResult.operationId)
        val rawTimeout = invoke("-", response(ControlCode.TIMEOUT, final = false))
        assertEquals(2, rawTimeout.first)
        assertTrue(rawTimeout.second.single().contains("operationId=operation-identity"))
        assertTrue(rawTimeout.third.isEmpty())
        val nonExport = invoke("report.txt", response(ControlCode.OK, final = true))
        assertEquals(1, nonExport.first)
        assertEquals(ControlCode.INVALID_ARGUMENT, com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
            nonExport.second.single()).code)
    }

    @Test
    fun publicAsyncDiagnosticsUsesWaitForExactClientSideExportAndDoesNotReplay() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-async-diagnostics-cli")
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var reports = 0
        val report = "VPN Control Desktop Diagnostics\nretained report\n"
        val session = DesktopHeadlessSession(scope, { com.kardinal.vpncontrol.MainUiState() }, executeCommand = {
            assertEquals(DesktopCliCommand.DiagnosticsExport, it)
            reports++
            started.complete(Unit)
            finish.await()
            DesktopCliResponse.success(report)
        }, refresh = {})
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { session.execute(it) } }, portFile = endpoint, controllerId = session.controllerId))
        try {
            val acceptedOutput = mutableListOf<String>()
            lateinit var submission: DesktopCliCommand.ControlSubmit
            assertEquals(0, DesktopCli.handleArgs(arrayOf("--json", "--async", "diagnostics", "export"), acceptedOutput::add,
                requestCommand = { command ->
                    submission = command as DesktopCliCommand.ControlSubmit
                    DesktopActivationServer.requestCliCommand(command, endpoint)
                }, startHeadlessController = { error("Must reuse owner") }))
            val accepted = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(acceptedOutput.single())
            assertEquals(ControlCode.ACCEPTED, accepted.code)
            assertFalse(accepted.final)
            val operationId = assertNotNull(accepted.operationId)
            started.await()
            assertEquals(1, reports)
            assertEquals(ControlCode.ACCEPTED, com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
                DesktopActivationServer.requestCliCommand(submission.copy(request = submission.request.copy(
                    controllerId = session.controllerId)), endpoint).message).code)
            assertEquals(1, reports)
            assertEquals(1, DesktopCli.handleArgs(arrayOf("--json", "--async", "diagnostics", "export", "--output", "ignored.txt"), {},
                requestCommand = { error("Invalid async output dispatched") }, startHeadlessController = { error("Invalid async output started owner") }))
            finish.complete(Unit)
            val destination = directory.resolve("diagnostics.txt")
            val completedOutput = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs(arrayOf("--json", "operations", "wait", operationId, "--output", destination.toString()),
                completedOutput::add, requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                startHeadlessController = { error("Must not replace operation owner") }))
            assertEquals(report, Files.readString(destination))
            val completed = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(completedOutput.single())
            assertEquals(ControlCode.OK, completed.code)
            assertEquals(report.toByteArray().size.toLong(),
                (completed.data.getValue("bytes") as com.kardinal.vpncontrol.model.ControlValue.IntegerValue).value)
            assertFalse(completed.data.containsKey("content"))
        } finally {
            server.close()
            session.close()
            scope.cancel()
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun asyncDiagnosticsExportRetainsExactReportForOperationWait() = runBlocking {
        val report = "VPN Control Desktop Diagnostics\nredacted report\n"
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Unconfined)
        val session = DesktopHeadlessSession(scope, { com.kardinal.vpncontrol.MainUiState() }, executeCommand = {
            assertEquals(DesktopCliCommand.DiagnosticsExport, it)
            DesktopCliResponse.success(report)
        }, refresh = {})
        try {
            val request = ControlRequest("diagnostics-request", ControlCommand(ControlOperationId.DIAGNOSTICS_EXPORT),
                controllerId = session.controllerId, asynchronous = true)
            val accepted = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
                session.execute(DesktopCliCommand.ControlSubmit(request)).message)

            // Immediate completion may publish the terminal report before async admission returns.
            assertEquals(ControlCode.OK, accepted.code)
            assertTrue(accepted.final)
            assertNotNull(accepted.operationId)
            assertEquals(report, (accepted.data.getValue("content") as com.kardinal.vpncontrol.model.ControlValue.Text).value)

            val completed = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
                session.execute(DesktopCliCommand.ControlSubmit(ControlRequest("wait-request",
                    ControlCommand(ControlOperationId.OPERATIONS_WAIT, mapOf("id" to
                        com.kardinal.vpncontrol.model.ControlValue.Text(accepted.operationId!!))),
                    controllerId = session.controllerId))).message)
            assertEquals(ControlCode.OK, completed.code)
            assertTrue(completed.final)
            assertEquals(accepted.operationId, completed.operationId)
            assertEquals(report, (completed.data.getValue("content") as com.kardinal.vpncontrol.model.ControlValue.Text).value)
        } finally {
            session.close()
            scope.cancel()
        }
    }

    @Test
    fun logsAndReportsRedactStructuredSecretsAndStatsUseRealCounters() {
        val directory = Files.createTempDirectory("vpn-control-diagnostics-cli")
        val secretStatus = SettingsStatusMessages.homeSshPrivateKeyImportFailed("https://example.test/private/SECRET-TOKEN")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory),
            DesktopWorkspace(PersistedState(successfulStarts = 3, successfulStops = 2,
                statusMessage = secretStatus,
                connectionLog = listOf(ConnectionLogEntry("id", secretStatus, 100))), emptyList()))
        val endpoint = directory.resolve("activation.port")
        val owner = DesktopControllerOwner(service)
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { runBlocking { owner.session.execute(it) } }, portFile = endpoint, controllerId = owner.controllerId,
        ))
        try {
            fun invoke(vararg args: String): Pair<Int?, String> {
                val lines = mutableListOf<String>()
                return DesktopCli.handleArgs(arrayOf(*args), lines::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Reuse owner") }) to lines.joinToString("\n")
            }
            val stats = invoke("stats")
            assertEquals(0, stats.first)
            assertTrue(stats.second.contains("successfulStarts: 3"))
            assertTrue(stats.second.contains("elapsedMillis: unknown"))
            assertFalse(stats.second.contains("rxBytes"))
            val logs = invoke("logs", "--limit", "1")
            assertEquals(0, logs.first)
            assertFalse(logs.second.contains("SECRET-TOKEN"))
            assertTrue(invoke("logs", "--limit", "0").second.contains("entries: []"))
            fun json(vararg args: String): com.kardinal.vpncontrol.model.ControlResult {
                val result = invoke("--json", *args)
                assertEquals(0, result.first, result.second)
                return com.kardinal.vpncontrol.control.ControlProtocolCodec.decodeResult(result.second).also {
                    assertEquals(owner.controllerId, it.controllerId)
                    assertTrue(it.final)
                }
            }
            val jsonStats = json("stats")
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.IntegerValue(3), jsonStats.data["successfulStarts"])
            assertEquals(com.kardinal.vpncontrol.model.ControlValue.Null, jsonStats.data["elapsedMillis"])
            val jsonLogs = json("logs", "--limit", "1")
            assertFalse(jsonLogs.toString().contains("SECRET-TOKEN"))
            assertEquals(1, (jsonLogs.data.getValue("entries") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(0, (json("logs", "--limit", "0").data.getValue("entries") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(1, invoke("--json", "logs", "--limit", "-1").first)
            val followed = mutableListOf<String>()
            var following = true
            assertEquals(130, DesktopCli.handleArgs(arrayOf("--json", "logs", "--follow"), printLine = followed::add,
                requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                streamPause = { following = false }, streamActive = { following }))
            assertFalse(followed.joinToString("\n").contains("SECRET-TOKEN"))
            assertEquals(2, followed.size)
            assertTrue(json("source", "show").data.containsKey("mode"))
            assertEquals(com.kardinal.vpncontrol.model.AppLanguage.entries.size,
                (json("settings", "languages").data.getValue("languages") as com.kardinal.vpncontrol.model.ControlValue.ArrayValue).values.size)
            assertEquals(jsonStats.configurationRevision, jsonLogs.configurationRevision)
            assertTrue(owner.session.operationSnapshot().isEmpty())
            val output = directory.resolve("diagnostic report.txt")
            val before = service.state
            assertEquals(0, invoke("diagnostics", "export", "--output", output.toString()).first)
            val report = Files.readString(output)
            assertTrue(report.contains("VPN Control Desktop Diagnostics"))
            assertFalse(report.contains("SECRET-TOKEN"))
            assertEquals(before, service.state)
        } finally { server.close(); owner.close(); directory.toFile().deleteRecursively() }
    }
}
