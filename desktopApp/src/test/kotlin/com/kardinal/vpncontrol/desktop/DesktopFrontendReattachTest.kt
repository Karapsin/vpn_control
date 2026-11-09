package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.test.runTest
import kotlin.test.*

/**
 * A GUI started after another one crashed or exited attaches at once. Native operation 90dd6d45: a GUI reopened
 * seconds after a crash got BUSY for its ATTACH while the dead frontend's lease ran out, so main printed
 * "UNAVAILABLE: could not attach graphical frontend." and the app exited 0 with no window.
 * These run against the owner's real ATTACH path and the default process observation.
 */
class DesktopFrontendReattachTest {
    private suspend fun attach(owner: DesktopControllerOwner, frontend: String): ControlCode =
        ControlProtocolCodec.decodeResult(owner.execute(DesktopCliCommand.ControlFrontendLease(UUID.randomUUID().toString(),
            owner.controllerId, frontend, DesktopFrontendLeaseAction.ATTACH)).message).code

    /** The identity of one test-owned JVM that has exited, as an owner captured it at that frontend's attach. */
    private fun exitedIdentity(frontend: String): DesktopFrontendProcessIdentity {
        val javaCommand = Path.of(System.getProperty("java.home"), "bin",
            if (System.getProperty("os.name").startsWith("Windows", true)) "java.exe" else "java").toString()
        val classpath = DesktopJvmCliTestBootstrap.classpath(requireNotNull(System.getProperty("vpnControl.test.mainClasspath")))
        val process = ProcessBuilder(javaCommand, "-cp", classpath, DesktopQuitProcessProbe::class.java.name).start()
        try {
            val started = process.toHandle().info().startInstant().orElseThrow().toEpochMilli()
            process.outputStream.close()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "Owned identity probe must exit on stdin EOF")
            assertEquals(0, process.exitValue())
            return DesktopFrontendProcessIdentity(frontend, process.pid(), started)
        } finally {
            process.outputStream.close()
            if (process.isAlive) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
        }
    }

    @Test fun a_new_frontend_attaches_once_the_crashed_frontends_captured_process_is_gone() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-gone")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)), scope = backgroundScope)
        val crashed = UUID.randomUUID().toString()
        val reopened = UUID.randomUUID().toString()
        try {
            val gone = exitedIdentity(crashed)
            assertTrue(gone.isDefinitelyGone())
            assertEquals(ControlCode.OK, attach(owner, crashed))
            assertTrue(owner.frontends.captureProcessIdentity(crashed, gone))
            assertEquals(ControlCode.OK, attach(owner, reopened), "The crashed frontend's lease must not refuse the reopened GUI")
            assertEquals(reopened, owner.frontends.registration())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun a_live_captured_frontend_keeps_its_lease() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-live")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)), scope = backgroundScope)
        val live = UUID.randomUUID().toString()
        try {
            assertEquals(ControlCode.OK, attach(owner, live))
            // This test JVM stands for a frontend that still runs: the default observation reads it as SAME.
            assertTrue(owner.frontends.captureProcessIdentity(live, DesktopFrontendProcessIdentity.current(live)))
            assertEquals(ControlCode.BUSY, attach(owner, UUID.randomUUID().toString()))
            assertEquals(live, owner.frontends.registration())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun an_uncaptured_frontend_keeps_its_lease() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-uncaptured")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)), scope = backgroundScope)
        val attached = UUID.randomUUID().toString()
        try {
            // No frontend endpoint answers here, so the owner captured no identity at this attach.
            assertEquals(ControlCode.OK, attach(owner, attached))
            assertEquals(ControlCode.BUSY, attach(owner, UUID.randomUUID().toString()))
            assertEquals(attached, owner.frontends.registration())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun the_same_registration_attaches_again() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-same")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)), scope = backgroundScope)
        val frontend = UUID.randomUUID().toString()
        try {
            assertEquals(ControlCode.OK, attach(owner, frontend))
            val identity = DesktopFrontendProcessIdentity.current(frontend)
            assertTrue(owner.frontends.captureProcessIdentity(frontend, identity))
            assertEquals(ControlCode.OK, attach(owner, frontend))
            assertEquals(frontend, owner.frontends.registration())
            // Its pinned generation is unchanged: another one still cannot replace it.
            assertFalse(owner.frontends.captureProcessIdentity(frontend, identity.copy(pid = identity.pid + 1)))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
