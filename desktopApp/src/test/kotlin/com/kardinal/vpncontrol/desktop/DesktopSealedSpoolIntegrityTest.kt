package com.kardinal.vpncontrol.desktop

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * Native `windows-document-acceptance` (ade9c4da, 2.2.18): after the seal, the harness rewrote the held
 * spool with a same-length command naming another controller and sent the honest reference. The owner
 * read the changed bytes, ran them and answered `cli-response\terror\t1\tCONFLICT` (37 frame bytes,
 * sha256 cc0f2ba7...). Sealed content is immutable (cli.md, transport step 3): bytes that no longer match
 * the sealed digest never reach the command parser, and the owner closes without a reply.
 */
class DesktopSealedSpoolIntegrityTest {
    private fun encoded(value: String) = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())

    private fun exchange(endpoint: DesktopControlEndpoint, vararg frames: String): String? =
        Socket(InetAddress.getLoopbackAddress(), endpoint.port).use { socket ->
            socket.soTimeout = 10_000
            val output = DataOutputStream(socket.getOutputStream())
            val input = DataInputStream(socket.getInputStream())
            DesktopControlFrames.write(output, endpoint.token)
            assertEquals("AUTHENTICATED", DesktopControlFrames.read(input))
            frames.forEach { DesktopControlFrames.write(output, it) }
            try { DesktopControlFrames.read(input) } catch (_: EOFException) { null }
        }

    private fun withSpoolParent(block: (Path) -> Unit) {
        val parent = Files.createTempDirectory("sealed-spool-integrity")
        val previous = System.getProperty("java.io.tmpdir")
        System.setProperty("java.io.tmpdir", parent.toString())
        try { block(parent) } finally {
            System.setProperty("java.io.tmpdir", previous)
            parent.toFile().deleteRecursively()
        }
    }

    private fun run(mutate: Boolean): Pair<String?, Int> {
        var outcome: Pair<String?, Int>? = null
        withSpoolParent { parent ->
            val portFile = parent.resolve("activation.port")
            val calls = AtomicInteger()
            val owner = UUID.randomUUID().toString()
            // The headless session's own check of a snapshot request (DesktopHeadlessSession).
            val server = assertNotNull(DesktopActivationServer.start({ DesktopActivationShowResult.HEADLESS }, { command ->
                calls.incrementAndGet()
                if (command is DesktopCliCommand.ControlSnapshotRead && command.controllerId != owner)
                    DesktopCliResponse.failure("CONFLICT") else DesktopCliResponse.success("snapshot")
            }, portFile, controllerId = owner))
            server.use {
                val endpoint = DesktopControlEndpoint.read(portFile)
                val context = UUID.randomUUID().toString()
                val original = "cli\tcontrol-snapshot\t" + encoded(owner)
                val replacement = "cli\tcontrol-snapshot\t" + encoded(UUID.randomUUID().toString())
                assertEquals(original.length, replacement.length)
                val (reference, discard) = DesktopControlDocuments.upload(owner, original, context) {
                    requireNotNull(exchange(endpoint, it))
                }
                val payloads = Files.walk(parent).use { paths -> paths.filter { it.fileName.toString() == "payload" }.toList() }
                assertEquals(1, payloads.size, "one sealed spool")
                assertContentEquals(original.toByteArray(), Files.readAllBytes(payloads.single()))
                if (mutate) FileChannel.open(payloads.single(), StandardOpenOption.WRITE).use { channel ->
                    assertEquals(replacement.length, channel.write(ByteBuffer.wrap(replacement.toByteArray()), 0))
                }
                outcome = exchange(endpoint, DesktopControlDocuments.context(owner, context, "snapshot"), reference) to calls.get()
                discard()
            }
        }
        return requireNotNull(outcome)
    }

    @Test fun aSealedSpoolChangedAfterItsSealIsNeverRunAndGetsNoReply() {
        val (reply, calls) = run(mutate = true)
        assertNull(reply, "the owner answered changed sealed bytes: $reply")
        assertEquals(0, calls, "changed sealed bytes reached the command handler")
    }

    @Test fun theUnchangedSealedSpoolStillRuns() {
        val (reply, calls) = run(mutate = false)
        assertEquals(1, calls)
        assertEquals("cli-response\tok\t0\t" + encoded("snapshot"), reply)
    }
}
