package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlTransferCodec
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.ControlTransferChunk
import com.kardinal.vpncontrol.model.ControlTransferCommand
import com.kardinal.vpncontrol.model.RoutingRules
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.net.SocketTimeoutException
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The owner may parse a String; the independently constrained public client must still publish by chunks. */
class DesktopLargeExportCliProcessTest {
    @Test fun constrainedPublicClientStreamsLargeRoutingExportToPrivateFile() {
        val root = Files.createTempDirectory("large-export-public-client")
        val workspace = root.resolve("workspace")
        val input = root.resolve("routing-input.json")
        val output = root.resolve("routing-output.json")
        val canonical = root.resolve("routing-canonical.json")
        val ownerLog = root.resolve("owner.log")
        val importLog = root.resolve("import.log")
        val exportOut = root.resolve("export.out")
        val exportErr = root.resolve("export.err")
        var complete = false
        val java = Path.of(System.getProperty("java.home"), "bin", if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java").toString()
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        fun command(memory: String? = null, args: List<String>) = buildList {
            add(java); add("-Djava.awt.headless=true"); if (memory != null) add("-Xmx$memory")
            add("-cp"); add(classpath); add(DesktopJvmCliTestBootstrap::class.java.name)
            addAll(DesktopJvmCliTestBootstrap.encode(listOf("--state-dir", workspace.toString()) + args))
        }
        fun invoke(memory: String = "512m", args: List<String>, log: Path): Process = ProcessBuilder(command(memory, args))
            .redirectErrorStream(true).redirectOutput(log.toFile()).start()
        val owner = invoke(args = listOf("serve"), log = ownerLog)
        try {
            val endpoint = workspace.resolve("activation.port")
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
            while (!Files.exists(endpoint) && owner.isAlive && System.nanoTime() < deadline) Thread.sleep(25)
            assertTrue(owner.isAlive && Files.exists(endpoint), Files.readString(ownerLog))
            val domains = (0 until 500_000).map { "domain-$it.example.test" }
            val source = RoutingRulesTransfer.export(RoutingRules(directDomainSuffixes = domains)).content
            Files.writeString(input, source)
            assertTrue(source.toByteArray().size > 10 * 1024 * 1024)
            val imported = invoke(args = listOf("routing", "import", "--input", input.toString()), log = importLog)
            assertTrue(imported.waitFor(120, TimeUnit.SECONDS), "routing import timed out")
            assertEquals(0, imported.exitValue(), Files.readString(importLog))
            val stopped = invoke(args = listOf("quit"), log = root.resolve("quit-before-export.log"))
            assertTrue(stopped.waitFor(30, TimeUnit.SECONDS), "owner quit timed out")
            assertEquals(0, stopped.exitValue(), Files.readString(root.resolve("quit-before-export.log")))
            assertTrue(owner.waitFor(30, TimeUnit.SECONDS), "persistent owner did not stop")
            val exported = ProcessBuilder(command("64m", listOf("--json", "routing", "export", "--output", output.toString())))
                .redirectOutput(exportOut.toFile()).redirectError(exportErr.toFile()).start()
            assertTrue(exported.waitFor(120, TimeUnit.SECONDS), "routing export timed out")
            assertEquals(0, exported.exitValue(), Files.readString(exportErr))
            val canonicalExport = ProcessBuilder(command("512m", listOf("routing", "export", "--output", "-")))
                .redirectOutput(canonical.toFile()).redirectError(root.resolve("canonical.err").toFile()).start()
            assertTrue(canonicalExport.waitFor(120, TimeUnit.SECONDS), "canonical routing export timed out")
            assertEquals(0, canonicalExport.exitValue(), Files.readString(root.resolve("canonical.err")))
            val result = ControlProtocolCodec.decodeResult(Files.readString(exportOut).trim())
            assertEquals(ControlCode.OK, result.code)
            assertEquals(Files.size(output), (result.data["bytes"] as com.kardinal.vpncontrol.model.ControlValue.IntegerValue).value)
            assertEquals(canonicalRoutingExport(Files.readString(canonical)), canonicalRoutingExport(Files.readString(output)))
            assertEquals(domains, RoutingRulesTransfer.import(Files.readString(output)).directDomainSuffixes)
            assertTrue("content" !in result.data)
            val existing = Files.readAllBytes(output)
            val repeated = ProcessBuilder(command("64m", listOf("--json", "routing", "export", "--output", output.toString())))
                .redirectOutput(exportOut.toFile()).redirectError(exportErr.toFile()).start()
            assertTrue(repeated.waitFor(120, TimeUnit.SECONDS), "repeated routing export timed out")
            assertEquals(ControlCode.PERSISTENCE_FAILED, ControlProtocolCodec.decodeResult(Files.readString(exportOut).trim()).code)
            assertEquals(1, repeated.exitValue())
            assertEquals(sha256(existing), sha256(Files.readAllBytes(output)))
            complete = true
        } finally {
            if (owner.isAlive) {
                val quit = invoke(args = listOf("quit"), log = root.resolve("quit.log"))
                quit.waitFor(10, TimeUnit.SECONDS)
                if (owner.isAlive) { owner.destroy(); if (!owner.waitFor(10, TimeUnit.SECONDS)) owner.destroyForcibly() }
            }
            if (complete) root.toFile().deleteRecursively()
        }
    }

    @Test fun manifestMismatchErasesThePrivatePartialBeforePublication() {
        val root = Files.createTempDirectory("large-export-manifest-mismatch")
        val owner = java.util.UUID.randomUUID().toString()
        val context = java.util.UUID.randomUUID().toString()
        val output = root.resolve("output.json")
        DesktopControlDocuments(owner).use { documents ->
            val reference = documents.publish("payload-東京".repeat(20_000), "export", context) { }
            val result = DesktopControlDocuments.downloadExport(owner, reference, context, output.toString()) { frame ->
                val response = requireNotNull(documents.handle(frame))
                val fields = ControlProtocolCodec.decodeValues(frame.removePrefix(DesktopControlDocuments.TRANSFER))
                val command = ControlTransferCodec.decode((fields.getValue("command") as com.kardinal.vpncontrol.model.ControlValue.Text).value)
                if (command is ControlTransferCommand.Read) {
                    val chunk = ControlTransferCodec.decodeChunk(response)
                    ControlTransferCodec.encodeChunk(ControlTransferChunk(chunk.id, chunk.offset,
                        chunk.bytes.copyOf().also { if (it.isNotEmpty()) it[0] = (it[0].toInt() xor 1).toByte() }))
                } else response
            }
            assertTrue(result.isFailure)
            assertTrue(!Files.exists(output))
            assertEquals(0L, Files.list(root).use { it.count() })
        }
        root.toFile().deleteRecursively()
    }

    @Test fun manifestCountMismatchErasesThePrivatePartialBeforePublication() {
        val root = Files.createTempDirectory("large-export-count-mismatch")
        val owner = java.util.UUID.randomUUID().toString()
        val context = java.util.UUID.randomUUID().toString()
        val output = root.resolve("output.json")
        DesktopControlDocuments(owner).use { documents ->
            val reference = documents.publish("payload-東京".repeat(20_000), "export", context) { }
            val result = DesktopControlDocuments.downloadExport(owner, reference, context, output.toString()) { frame ->
                val response = requireNotNull(documents.handle(frame))
                val fields = ControlProtocolCodec.decodeValues(frame.removePrefix(DesktopControlDocuments.TRANSFER))
                val command = ControlTransferCodec.decode((fields.getValue("command") as com.kardinal.vpncontrol.model.ControlValue.Text).value)
                if (command is ControlTransferCommand.Read) {
                    val chunk = ControlTransferCodec.decodeChunk(response)
                    ControlTransferCodec.encodeChunk(ControlTransferChunk(chunk.id, chunk.offset, chunk.bytes.copyOf(chunk.bytes.size - 1)))
                } else response
            }
            assertTrue(result.isFailure)
            assertTrue(!Files.exists(output))
            assertEquals(0L, Files.list(root).use { it.count() })
        }
        root.toFile().deleteRecursively()
    }

    @Test fun lostAcknowledgementAfterPublicationKeepsTheCommittedExport() {
        val root = Files.createTempDirectory("large-export-ack-loss")
        val owner = java.util.UUID.randomUUID().toString()
        val context = java.util.UUID.randomUUID().toString()
        val output = root.resolve("output.json")
        DesktopControlDocuments(owner).use { documents ->
            val content = "payload-東京".repeat(20_000)
            val reference = documents.publish(content, "export", context) { }
            val result = DesktopControlDocuments.downloadExport(owner, reference, context, output.toString()) { frame ->
                val response = requireNotNull(documents.handle(frame))
                if (response == "ACKNOWLEDGED") throw SocketTimeoutException("response lost after owner acknowledgement")
                response
            }
            assertTrue(result.isSuccess)
            assertTrue(!result.getOrThrow().acknowledged)
            assertEquals(content, Files.readString(output))
        }
        root.toFile().deleteRecursively()
    }

    @Test fun exportTransportKeepsResultMetadataAndClassifiesFailures() {
        val original = ControlResult("owner", "request", ControlCode.OK, 7, restartRequired = true,
            operationId = "operation", warnings = listOf("OWNER_WARNING"), data = mapOf(
                "content" to ControlValue.Text("payload"), "retained" to ControlValue.Text("metadata")))
        DesktopControlDocuments("owner").use { documents ->
            val frame = requireNotNull(documents.publishExport(DesktopCliResponse.success(
                ControlProtocolCodec.encodeResult(original)), java.util.UUID.randomUUID().toString()) { })
            val published = ControlProtocolCodec.decodeResult(DesktopCliProtocol.decodeResponse(frame).message)
            assertEquals(ControlValue.Text("metadata"), published.data["retained"])
            assertTrue("content" !in published.data)
            val completed = DesktopActivationServer.completeExportDownload(published,
                Result.success(DesktopExportDownload(7, acknowledged = false)))
            assertEquals("owner", completed.controllerId)
            assertEquals("request", completed.requestId)
            assertEquals("operation", completed.operationId)
            assertEquals(7, completed.configurationRevision)
            assertTrue(completed.restartRequired)
            assertEquals(ControlValue.Text("metadata"), completed.data["retained"])
            assertEquals(7, (completed.data["exportBytes"] as ControlValue.IntegerValue).value)
            assertTrue("exportReference" !in completed.data)
            assertEquals(listOf("OWNER_WARNING", "EXPORT_ACK_UNCONFIRMED"), completed.warnings)
            val final = ControlProtocolCodec.decodeResult(DesktopControlExports.completeStreamed(
                DesktopCliResponse(completed.ok, ControlProtocolCodec.encodeResult(completed), completed.exitCode), "json",
                ControlCode.INCOMPATIBLE_PROTOCOL).message)
            assertEquals(ControlValue.Text("metadata"), final.data["retained"])
            assertEquals(ControlValue.Text("json"), final.data["format"])
            assertEquals(7, (final.data["bytes"] as ControlValue.IntegerValue).value)
            assertTrue("exportBytes" !in final.data)
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL,
                DesktopActivationServer.completeExportDownload(published, Result.failure(DesktopControlProtocolException())).code)
            val root = Files.createTempDirectory("large-export-timeout")
            try {
                val reference = (published.data.getValue("exportReference") as ControlValue.Text).value
                val timedDownload = DesktopControlDocuments.downloadExport("owner", reference,
                    java.util.UUID.fromString(referenceContext(reference)).toString(), root.resolve("output.json").toString()) {
                    throw SocketTimeoutException("read timed out")
                }
                assertTrue(timedDownload.isFailure)
                assertTrue(!Files.exists(root.resolve("output.json")))
                val timed = DesktopActivationServer.completeExportDownload(published, timedDownload)
                assertEquals(ControlCode.TIMEOUT, timed.code)
                assertEquals("request", timed.requestId)
                assertEquals("operation", timed.operationId)
                assertTrue(!timed.final)
                assertEquals(ControlValue.Text("metadata"), timed.data["retained"])
            } finally { root.toFile().deleteRecursively() }
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** The owner creates an export timestamp for each request; every other serialized byte must match. */
    private fun canonicalRoutingExport(content: String) = content.replace(
        Regex("\\\"exported_at\\\": \\\"[^\\\"]+\\\""), "\"exported_at\": \"<generated>\"")

    private fun referenceContext(reference: String): String =
        (ControlProtocolCodec.decodeValues(reference.removePrefix(DesktopControlDocuments.REFERENCE)).getValue("context") as ControlValue.Text).value
}
