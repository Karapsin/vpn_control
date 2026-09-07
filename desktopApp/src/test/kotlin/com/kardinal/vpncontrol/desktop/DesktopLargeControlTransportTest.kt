package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class DesktopLargeControlTransportTest {
    @Test fun repeatedPublicationRetainsOriginalBytesAndAcknowledgesOnlyOnce() {
        val owner = java.util.UUID.randomUUID().toString()
        val context = java.util.UUID.randomUUID().toString()
        DesktopControlDocuments(owner).use { documents ->
            var acknowledgements = 0
            val original = documents.publish("original", "response", context) { acknowledgements++ }
            assertEquals(original, documents.publish("original", "response", context) { acknowledgements += 100 })
            assertFails { documents.publish("changed", "response", context) { error("Conflicting reply") } }
            assertFails { documents.publish("original", "snapshot", context) { error("Conflicting kind") } }
            var ackFrame: String? = null
            assertEquals("original", DesktopControlDocuments.download(owner, original, "response", context) { frame ->
                val result = requireNotNull(documents.handle(frame))
                if (result == "ACKNOWLEDGED") {
                    ackFrame = frame
                    documents.responseFlushed(frame)
                    documents.responseFlushed(frame)
                }
                result
            })
            assertEquals(1, acknowledgements)
            assertEquals("ACKNOWLEDGED", documents.handle(requireNotNull(ackFrame)))
            documents.responseFlushed(requireNotNull(ackFrame))
            assertEquals(1, acknowledgements)
            assertFalse(documents.hasWork())
        }
    }

    @Test fun legacyOwnerKeepsSmallCommandsButRejectsLargeInputBeforeAdmission() {
        val directory = Files.createTempDirectory("control-legacy-owner")
        val endpoint = directory.resolve("activation.port")
        val calls = AtomicInteger()
        try {
            assertNotNull(DesktopActivationServer.start({ DesktopActivationShowResult.HEADLESS },
                { calls.incrementAndGet(); DesktopCliResponse.success("small") }, endpoint)).use {
                val current = DesktopControlEndpoint.read(endpoint)
                assertTrue(current.documentTransfers)
                DesktopControlEndpoint(current.port, current.controllerId, current.token).publish(endpoint)
                assertFalse(DesktopControlEndpoint.read(endpoint).documentTransfers)
                assertTrue(DesktopActivationServer.requestCliCommand(DesktopCliCommand.Select("one"), endpoint).success)
                val large = DesktopActivationServer.requestCliCommand(DesktopCliCommand.LocationsImport("x".repeat(2_000_000)), endpoint)
                assertEquals(2, large.exitCode)
                assertEquals("INCOMPATIBLE_PROTOCOL", large.message)
                assertEquals(1, calls.get())
            }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun uploadReferencesAndRepliesAreBoundToRequestContextAndKind() {
        val owner = java.util.UUID.randomUUID().toString()
        val context = java.util.UUID.randomUUID().toString()
        val other = java.util.UUID.randomUUID().toString()
        DesktopControlDocuments(owner).use { documents ->
            val upload = DesktopControlDocuments.upload(owner, "input", context) { requireNotNull(documents.handle(it)) }
            try {
                assertFails { documents.consume(upload.first, other) }
                assertEquals("input", documents.consume(upload.first, context))
            } finally { upload.second() }
            var acknowledged = false
            val reply = documents.publish("response", "response", context) { acknowledged = true }
            assertFails { DesktopControlDocuments.download(owner, reply, "response", other) { error("No IO before identity checks") } }
            assertFails { DesktopControlDocuments.download(owner, reply, "snapshot", context) { error("No IO before kind checks") } }
            assertFalse(acknowledged)
            assertEquals("response", DesktopControlDocuments.download(owner, reply, "response", context) { frame ->
                val response = requireNotNull(documents.handle(frame))
                if (response == "ACKNOWLEDGED") assertFalse(acknowledged)
                documents.responseFlushed(frame)
                response
            })
            assertTrue(acknowledged)
            assertFalse(documents.hasWork())
        }
    }

    @Test fun cliRoutingImportAndGuiSnapshotKeepLargeCommittedResults() = kotlinx.coroutines.runBlocking {
        val directory = Files.createTempDirectory("control-large-cli-gui")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service)
        try {
            val endpoint = directory.resolve("activation.port")
            val server = assertNotNull(DesktopActivationServer.start(
                onShowWindow = { DesktopActivationShowResult.HEADLESS }, portFile = endpoint,
                controllerId = owner.controllerId,
                onCliCommand = { kotlinx.coroutines.runBlocking { owner.execute(it) } }))
            server.use {
                val gui = DesktopRemoteControlSession.connect(this,
                    request = { DesktopActivationServer.requestCliCommand(it, endpoint) }, pollMillis = 60_000).getOrThrow()
                try {
                val domains = (0 until 70_000).map { "domain-$it.example.test" }
                val document = com.kardinal.vpncontrol.data.RoutingRulesTransfer.export(RoutingRules(directDomainSuffixes = domains)).content
                val output = mutableListOf<String>()
                val exit = DesktopCli.handleArgs(arrayOf("--json", "routing", "import", "--input", "-"),
                    printLine = output::add, requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Existing owner must be used") }, readInput = { Result.success(document) })
                assertEquals(0, exit)
                val result = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(output.single())
                assertEquals(ControlCode.OK, result.code)
                assertEquals(domains, service.state.routingRules.directDomainSuffixes)
                val snapshot = DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSnapshotRead(owner.controllerId), endpoint)
                val decoded = com.kardinal.vpncontrol.control.ControlSnapshotCodec.decodeDocument(snapshot.message)
                assertTrue(decoded.operations.any { it.result?.data == result.data })
                assertEquals(1L, decoded.configurationRevision)
                assertEquals(decoded, gui.refresh().getOrThrow())
                val freshGui = DesktopRemoteControlSession.connect(this,
                    request = { DesktopActivationServer.requestCliCommand(it, endpoint) }, pollMillis = 60_000).getOrThrow()
                freshGui.use { assertEquals(decoded, it.snapshots.value) }
                val changed = owner.execute(DesktopCliCommand.ControlSubmit(ControlRequest("later-write", ControlCommand(
                    ControlOperationId.SETTINGS_SET, mapOf("key" to ControlValue.Text("validation.batch-size"),
                        "value" to ControlValue.Text("7"))), controllerId = owner.controllerId)))
                assertTrue(changed.success)
                for (operation in listOf(ControlOperationId.OPERATIONS_WAIT, ControlOperationId.OPERATIONS_STATUS)) {
                    val query = ControlRequest("inspect-${operation.wireName}", ControlCommand(operation,
                        mapOf("id" to ControlValue.Text(requireNotNull(result.operationId)))), controllerId = owner.controllerId)
                    val retained = com.kardinal.vpncontrol.control.ControlDocumentCodec.decodeResult(
                        DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(query), endpoint).message)
                    assertEquals(result.copy(requestId = query.requestId), retained)
                }
                } finally { gui.close() }
            }
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun largeTypedCommandAndResponseCrossAuthenticatedBoundedFrames() {
        val directory = Files.createTempDirectory("control-large-wire")
        val payload = "東\\\"\n".repeat(1_600_000)
        val calls = AtomicInteger()
        val command = DesktopCliCommand.ControlSubmit(ControlRequest("large-request", ControlCommand(
            ControlOperationId.LOCATIONS_IMPORT, mapOf("input" to ControlValue.Text(payload)))))
        try {
            val endpoint = directory.resolve("activation.port")
            val server = assertNotNull(DesktopActivationServer.start(
                onShowWindow = { DesktopActivationShowResult.HEADLESS }, portFile = endpoint,
                onCliCommand = { received ->
                    val request = assertIs<DesktopCliCommand.ControlSubmit>(received).request
                    assertEquals(payload, (request.command.arguments.getValue("input") as ControlValue.Text).value)
                    assertNotNull(request.controllerId)
                    calls.incrementAndGet()
                    DesktopCliResponse.success(payload)
                }))
            server.use {
                val response = DesktopActivationServer.requestCliCommand(command, endpoint)
                assertTrue(response.success, response.message.take(100))
                assertEquals(payload, response.message)
                assertEquals(1, calls.get())
            }
        } finally { directory.toFile().deleteRecursively() }
    }
}
