package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.concurrent.atomic.AtomicInteger
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopFrontendInstanceTest {
    @Test fun publicQuitCanCloseOnlyItsCapturedFrontendGeneration() = runBlocking {
        val directory = Files.createTempDirectory("frontend-public-quit")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        val ownerEndpoint = directory.resolve("owner.port")
        val ownerServer = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.HEADLESS }, controllerId = owner.controllerId,
            portFile = ownerEndpoint, onCliCommand = { runBlocking { owner.execute(it) } },
            onCliResponseFlushed = owner::responseFlushed))
        val presentation = visibility().apply { ownerId = owner.controllerId }
        val exited = java.util.concurrent.CountDownLatch(1)
        val quitExit = DesktopFrontendQuitExit({ owner.controllerId }, { it() }).apply {
            install { exited.countDown() }
        }
        val frontend = assertNotNull(DesktopFrontendInstance.start(directory, presentation, quitExit))
        try {
            assertTrue(owner.execute(DesktopCliCommand.ControlFrontendLease(java.util.UUID.randomUUID().toString(),
                owner.controllerId, frontend.identity, DesktopFrontendLeaseAction.ATTACH)).success)
            val identity = DesktopFrontendProcessIdentity.read(directory, frontend.identity).getOrThrow()
            val publicRequestId = "public quit request with spaces"
            val publicResponse = DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(ControlRequest(
                publicRequestId, ControlCommand(ControlOperationId.QUIT), controllerId = owner.controllerId)), ownerEndpoint)
            assertTrue(publicResponse.success)
            assertTrue(exited.await(3, java.util.concurrent.TimeUnit.SECONDS),
                "A flushed public QUIT must close only its captured frontend")
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3)
            while (!owner.exitRequested && System.nanoTime() < deadline) Thread.sleep(5)
            assertTrue(owner.exitRequested, "Owner must release only after the frontend's exact acknowledgement")
            assertEquals(frontend.identity, identity.registrationId)
        } finally {
            frontend.close(); ownerServer.close(); owner.close(); directory.toFile().deleteRecursively()
        }
    }

    @Test fun authenticatedInstallExitReachesTheCapturedFrontendEndpoint() {
        val directory = Files.createTempDirectory("frontend-install-exit")
        val owner = java.util.UUID.randomUUID().toString()
        val presentation = visibility().apply { ownerId = owner }
        val exited = java.util.concurrent.CountDownLatch(1)
        presentation.installExit.install { exited.countDown() }
        val frontend = assertNotNull(DesktopFrontendInstance.start(directory, presentation))
        try {
            val identity = DesktopFrontendProcessIdentity.current(frontend.identity)
            val requestId = java.util.UUID.randomUUID().toString()
            val request = ControlRequest(requestId, ControlCommand(ControlOperationId.QUIT, mapOf(
                "owner" to ControlValue.Text(owner),
                "installOperation" to ControlValue.Text(java.util.UUID.randomUUID().toString()),
                "jobId" to ControlValue.Text(java.util.UUID.randomUUID().toString()),
                "pid" to ControlValue.IntegerValue(identity.pid),
                "startedAtEpochMillis" to ControlValue.IntegerValue(identity.startedAtEpochMillis),
            )), controllerId = frontend.identity)
            val response = DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(request),
                DesktopFrontendInstance.endpoint(directory))
            assertTrue(response.success, "Captured frontend must accept its authenticated installation exit: ${response.message}")
            val result = ControlProtocolCodec.decodeResult(response.message)
            assertEquals(frontend.identity, result.controllerId)
            assertEquals(requestId, result.requestId)
            assertEquals(ControlCode.OK, result.code)
            assertTrue(result.final)
            assertTrue(exited.await(3, java.util.concurrent.TimeUnit.SECONDS))
        } finally { frontend.close(); directory.toFile().deleteRecursively() }
    }

    private fun visibility(onShow: () -> Unit = {}, onHide: () -> Unit = {}) = DesktopFrontendVisibility({ it() }).apply {
        ownerId = "test-owner"
        available = { true }
        install { shown -> if (shown) onShow() else onHide(); com.kardinal.vpncontrol.model.ControlCode.OK }
    }
    @Test fun frontendRegistrationActivationAndDetachDoNotOwnControllerLifetime() {
        val directory = Files.createTempDirectory("frontend-registration")
        val ownerLock = assertNotNull(DesktopSingleInstanceLock.acquire(directory.resolve("vpn-control.lock")))
        val ownerEndpoint = directory.resolve("activation.port")
        val owner = assertNotNull(DesktopActivationServer.start({ DesktopActivationShowResult.HEADLESS },
            onCliCommand = { DesktopCliResponse.success("OWNER_ALIVE") }, portFile = ownerEndpoint))
        val before = Files.readAllBytes(ownerEndpoint)
        val shows = AtomicInteger()
        val hides = AtomicInteger()
        val first = assertNotNull(DesktopFrontendInstance.start(directory, visibility({ shows.incrementAndGet() }, { hides.incrementAndGet() })))
        try {
            assertNull(DesktopFrontendInstance.start(directory, visibility()))
            assertEquals(DesktopActivationShowResult.SHOWN, DesktopFrontendInstance.show(directory))
            assertEquals(1, shows.get())
            assertTrue(DesktopFrontendInstance.hide(directory, "test-owner").success)
            assertEquals(1, hides.get())
            assertFalse(DesktopActivationServer.requestCliCommand(DesktopCliCommand.On,
                DesktopFrontendInstance.endpoint(directory)).success)
            first.close()
            assertFalse(Files.exists(DesktopFrontendInstance.endpoint(directory)))
            assertContentEquals(before, Files.readAllBytes(ownerEndpoint))
            assertEquals("OWNER_ALIVE", DesktopActivationServer.requestCliCommand(DesktopCliCommand.Status, ownerEndpoint).message)
            assertNull(DesktopSingleInstanceLock.acquire(directory.resolve("vpn-control.lock")))
            val replacement = assertNotNull(DesktopFrontendInstance.start(directory, visibility({ shows.incrementAndGet() })))
            try {
                first.close() // Late duplicate cleanup cannot remove the replacement's endpoint/lock.
                assertEquals(DesktopActivationShowResult.SHOWN, DesktopFrontendInstance.show(directory))
                assertEquals(2, shows.get())
            } finally { replacement.close() }
        } finally {
            first.close(); owner.close(); ownerLock.close(); directory.toFile().deleteRecursively()
        }
    }

    @Test fun frontendRegistrationIsIsolatedByWorkspace() {
        val directory = Files.createTempDirectory("frontend-isolation")
        val firstDirectory = directory.resolve("東京 one")
        val secondDirectory = directory.resolve("two")
        val firstShows = AtomicInteger()
        val secondShows = AtomicInteger()
        val first = assertNotNull(DesktopFrontendInstance.start(firstDirectory, visibility({ firstShows.incrementAndGet() })))
        val second = assertNotNull(DesktopFrontendInstance.start(secondDirectory, visibility({ secondShows.incrementAndGet() })))
        try {
            assertEquals(DesktopActivationShowResult.SHOWN, DesktopFrontendInstance.show(firstDirectory))
            assertEquals(1, firstShows.get())
            assertEquals(0, secondShows.get())
            assertEquals(DesktopActivationShowResult.SHOWN, DesktopFrontendInstance.show(secondDirectory))
            assertEquals(1, secondShows.get())
            assertFalse(Files.exists(firstDirectory.resolve("workspace.json")))
            assertFalse(Files.exists(secondDirectory.resolve("activation.port")))
        } finally { first.close(); second.close(); directory.toFile().deleteRecursively() }
    }
}
