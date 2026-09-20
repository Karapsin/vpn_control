package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.test.runTest
import kotlin.test.*

class DesktopQuitControlTest {
    @Test fun quit_releases_only_a_captured_dead_frontend_generation() = runTest {
        val directory = Files.createTempDirectory("owner-quit-dead-frontend")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        val frontend = java.util.UUID.randomUUID().toString()
        try {
            val javaCommand = Path.of(System.getProperty("java.home"), "bin",
                if (System.getProperty("os.name").startsWith("Windows", true)) "java.exe" else "java").toString()
            val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
            val exited = ProcessBuilder(javaCommand, "-cp", classpath, DesktopQuitProcessProbe::class.java.name).start()
            val started = try {
                val identity = exited.toHandle().info().startInstant().orElseThrow().toEpochMilli()
                exited.outputStream.close()
                assertTrue(exited.waitFor(10, TimeUnit.SECONDS), "Owned identity probe must exit on stdin EOF")
                assertEquals(0, exited.exitValue())
                identity
            } finally {
                exited.outputStream.close()
                if (exited.isAlive) {
                    exited.destroyForcibly()
                    exited.waitFor(5, TimeUnit.SECONDS)
                }
            }
            val exitedIdentity = DesktopFrontendProcessIdentity(frontend, exited.pid(), started)
            assertTrue(exitedIdentity.isDefinitelyGone())
            assertEquals(ControlCode.OK, ControlProtocolCodec.decodeResult(owner.frontends.execute(
                DesktopCliCommand.ControlFrontendLease(java.util.UUID.randomUUID().toString(), owner.controllerId,
                    frontend, DesktopFrontendLeaseAction.ATTACH)).message).code)
            assertTrue(owner.frontends.captureProcessIdentity(frontend,
                exitedIdentity))
            val result = owner.submit(ControlRequest("quit-dead-frontend", ControlCommand(ControlOperationId.QUIT),
                controllerId = owner.controllerId))
            assertEquals(ControlCode.OK, result.code)
            assertNull(owner.frontends.registration())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun quitUsesOwnerAdmissionAndOnlyExitsAfterItsTerminalResponseIsFlushed() = runTest {
        val directory = Files.createTempDirectory("owner-quit-control")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val request = ControlRequest("quit", ControlCommand(ControlOperationId.QUIT), controllerId = owner.controllerId,
                ifRevision = service.configurationRevision)
            assertEquals(ControlCode.CONFLICT, owner.submit(request.copy(controllerId = "old-owner")).code)
            assertFalse(owner.exitRequested)
            val result = owner.submit(request)
            assertEquals(ControlCode.OK, result.code)
            assertFalse(owner.exitRequested)
            assertEquals(result, owner.submit(request))
            val response = DesktopCliResponse.success(ControlProtocolCodec.encodeResult(result))
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request.copy(requestId = "other")), response)
            assertFalse(owner.exitRequested)
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request), response)
            assertTrue(owner.exitRequested)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun quitPersistenceFailureCannotReleaseOwnerExitGate() = runTest {
        val directory = Files.createTempDirectory("owner-quit-failure")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            service.applyControlSettings(mapOf("validation.batch-size" to ControlValue.IntegerValue(7))).getOrThrow()
            Files.move(directory.resolve("workspace.json"), directory.resolve("previous.json"))
            Files.createDirectory(directory.resolve("workspace.json"))
            Files.createDirectory(directory.resolve("workspace-recovery.json"))
            val request = ControlRequest("failed-quit", ControlCommand(ControlOperationId.QUIT), controllerId = owner.controllerId)
            val result = owner.submit(request)
            assertFalse(result.ok)
            owner.responseFlushed(DesktopCliCommand.ControlSubmit(request),
                DesktopCliResponse(result.ok, ControlProtocolCodec.encodeResult(result), result.exitCode))
            assertFalse(owner.exitRequested)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}

/** Keeps the exact test-owned process alive until its start identity has been captured. */
object DesktopQuitProcessProbe {
    @JvmStatic fun main(arguments: Array<String>) { System.`in`.read() }
}
