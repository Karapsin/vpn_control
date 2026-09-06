package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.Socket
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DesktopControlTransportTest {
    @Test
    fun transientOwnerCanCloseOnCompletionWithoutTruncatingReply() {
        val directory = Files.createTempDirectory("vpn-control-reply-before-close")
        val endpointFile = directory.resolve("activation.port")
        val closed = CountDownLatch(1)
        val message = "result-東京".repeat(20_000)
        lateinit var server: DesktopActivationServer
        server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { DesktopCliResponse.success(message) },
            portFile = endpointFile,
            onCliCommandFinished = { server.close(); closed.countDown() },
        ))
        try {
            assertEquals(DesktopActivationShowResult.HEADLESS, DesktopActivationServer.requestShow(endpointFile))
            assertEquals(1L, closed.count)
            val response = DesktopActivationServer.requestCliCommand(DesktopCliCommand.SourceShow, endpointFile)
            assertTrue(response.success)
            assertEquals(message, response.message)
            assertTrue(closed.await(2, TimeUnit.SECONDS))
            assertFalse(Files.exists(endpointFile))
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun unauthenticatedAndMalformedClientsNeverExecuteAnActionOrKillListener() {
        val directory = Files.createTempDirectory("vpn-control-auth")
        val calls = AtomicInteger()
        val endpointFile = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { calls.incrementAndGet(); DesktopActivationShowResult.SHOWN },
            onCliCommand = { calls.incrementAndGet(); DesktopCliResponse.success("ready") }, portFile = endpointFile,
        ))
        try {
            val endpoint = DesktopControlEndpoint.read(endpointFile)
            Socket(InetAddress.getLoopbackAddress(), endpoint.port).use { socket ->
                socket.soTimeout = 1000
                DesktopControlFrames.write(DataOutputStream(socket.getOutputStream()), "incorrect-token")
                assertEquals("PERMISSION_DENIED", DesktopControlFrames.read(DataInputStream(socket.getInputStream())))
            }
            Socket(InetAddress.getLoopbackAddress(), endpoint.port).use { socket ->
                DataOutputStream(socket.getOutputStream()).apply { writeInt(Int.MAX_VALUE); flush() }
            }
            assertEquals(0, calls.get())
            assertTrue(DesktopActivationServer.requestCliCommand(DesktopCliCommand.Status, endpointFile).success)
            assertEquals(1, calls.get())
            if (Files.getFileStore(endpointFile).supportsFileAttributeView("posix")) {
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(endpointFile))
            }
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun statusIsResponsiveWhileMutationRunsAndAnotherMutationIsRejected() {
        val directory = Files.createTempDirectory("vpn-control-concurrent-control")
        val endpointFile = directory.resolve("activation.port")
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS },
            onCliCommand = { command ->
                if (command == DesktopCliCommand.On) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) }
                DesktopCliResponse.success("ready")
            }, portFile = endpointFile,
        ))
        try {
            val slow = executor.submit<DesktopCliResponse> { DesktopActivationServer.requestCliCommand(DesktopCliCommand.On, endpointFile) }
            assertTrue(entered.await(2, TimeUnit.SECONDS))
            assertTrue(DesktopActivationServer.requestCliCommand(DesktopCliCommand.Status, endpointFile).success)
            assertFalse(DesktopActivationServer.requestCliCommand(DesktopCliCommand.Off, endpointFile).success)
            release.countDown()
            assertTrue(slow.get(2, TimeUnit.SECONDS).success)
        } finally { release.countDown(); server.close(); executor.shutdownNow(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun incompatibleDescriptorCannotTriggerMissingControllerFallback() {
        val directory = Files.createTempDirectory("vpn-control-old-control")
        try {
            val file = directory.resolve("activation.port")
            Files.writeString(file, "12345")
            val result = DesktopActivationServer.requestCliCommand(DesktopCliCommand.On, file)
            assertFalse(result.isDesktopAppNotRunning)
            assertEquals("INCOMPATIBLE_PROTOCOL", result.message)
            assertEquals(2, result.exitCode)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test
    fun oldOwnerCloseCannotDeleteReplacementDescriptor() {
        val directory = Files.createTempDirectory("vpn-control-owner-epoch")
        val file = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start({ DesktopActivationShowResult.SHOWN }, portFile = file))
        try {
            val replacement = DesktopControlEndpoint.create(12345)
            replacement.publish(file)
            server.close()
            assertEquals(replacement.controllerId, DesktopControlEndpoint.read(file).controllerId)
        } finally { server.close(); directory.toFile().deleteRecursively() }
    }

    @Test
    fun framesPreserveUnicodeAndRejectOversizedMalformedAndTruncatedInput() {
        val bytes = ByteArrayOutputStream()
        DesktopControlFrames.write(DataOutputStream(bytes), "東京 \"office\"\nрусский")
        assertEquals("東京 \"office\"\nрусский", DesktopControlFrames.read(DataInputStream(ByteArrayInputStream(bytes.toByteArray()))))
        for (size in listOf(-1, 0, Int.MAX_VALUE)) {
            val invalid = ByteArrayOutputStream()
            DataOutputStream(invalid).writeInt(size)
            assertFailsWith<DesktopControlProtocolException> {
                DesktopControlFrames.read(DataInputStream(ByteArrayInputStream(invalid.toByteArray())))
            }
        }
        assertFailsWith<java.io.EOFException> {
            DesktopControlFrames.read(DataInputStream(ByteArrayInputStream(bytes.toByteArray().dropLast(1).toByteArray())))
        }
    }
}
