package com.kardinal.vpncontrol.desktop

import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import java.util.concurrent.TimeUnit
import java.util.concurrent.CompletableFuture
import kotlin.test.*

/**
 * Explicitly opt in inside the owned disposable Linux VM, as its standard user under a controlling
 * PTY (e.g. util-linux script). No password is supplied by the test or transported through Java.
 * This runs only fixed /usr/bin/true with privilege, never an installer or VPN process.
 */
class DesktopLinuxTerminalAuthorizationNativeTest {
    @Test fun explicitTerminalPromptAuthorizesFixedHarmlessCommand() = runBlocking {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        assumeTrue(System.getenv("VPN_CONTROL_NATIVE_TERMINAL_AUTH") in setOf("success", "diagnostic"))
        assertEquals(0, runPrompt())
    }

    @Test fun explicitTerminalPromptCancellationDoesNotAuthorizeCommand() = runBlocking {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        assumeTrue(System.getenv("VPN_CONTROL_NATIVE_TERMINAL_AUTH") == "cancel")
        assertTrue(runPrompt() in setOf(126, 127))
    }

    private suspend fun runPrompt(): Int {
        val owner = requireNotNull(currentLinuxAuthorizationOwner())
        val diagnostic = System.getenv("VPN_CONTROL_NATIVE_TERMINAL_AUTH") == "diagnostic"
        DesktopLinuxTerminalAuthorization.start(owner).use {
            val process = ProcessBuilder("/usr/bin/pkexec", "--disable-internal-agent", "/usr/bin/true")
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(if (diagnostic) ProcessBuilder.Redirect.PIPE else ProcessBuilder.Redirect.DISCARD).start()
            process.outputStream.close()
            // Opt-in disposable-VM diagnostic of fixed harmless argv only. Authentication still
            // uses /dev/tty, never this pipe; cap messages and close excess diagnostic output.
            val stderr = if (diagnostic) CompletableFuture.supplyAsync {
                process.errorStream.use { stream -> stream.readNBytes(4097) }
            } else null
            try {
                assertTrue(process.waitFor(120, TimeUnit.SECONDS), "Terminal authorization fixture timed out")
                stderr?.get(2, TimeUnit.SECONDS)?.let { bytes ->
                    System.err.println("PKEXEC_DIAGNOSTIC exit=${process.exitValue()} ownerPid=${owner.pid} startTicks=${owner.startTicks} uid=${owner.uid}")
                    System.err.println(bytes.take(4096).toByteArray().decodeToString())
                    if (bytes.size > 4096) System.err.println("PKEXEC_DIAGNOSTIC truncated")
                }
                return process.exitValue()
            } finally {
                // Fixed harmless test command only; never used to stop a package manager.
                if (process.isAlive) { process.destroy(); if (!process.waitFor(2, TimeUnit.SECONDS)) process.destroyForcibly() }
            }
        }
    }
}
