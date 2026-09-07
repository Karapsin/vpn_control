package com.kardinal.vpncontrol.desktop

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.*

class DesktopLinuxTerminalAuthorizationTest {
    private val owner = DesktopLinuxAuthorizationOwner(123, 456, 1000)
    private class Agent(var alive: Boolean = true, var ready: Boolean = false) : DesktopLinuxTerminalAgentProcess {
        var closes = 0
        override fun isAlive() = alive
        override fun registrationReady() = ready
        override fun close() { closes++ }
    }

    @Test fun commandPinsStartTicksAndKeepsTerminalTrafficOffControlStreams() {
        val args = linuxTerminalAgentArguments(owner)
        assertEquals(listOf("/bin/sh", "-c"), args.take(2))
        assertEquals("123,456", args.last())
        assertTrue(args[2].contains("exec 3>&1"))
        assertTrue(args[2].contains("exec </dev/tty >/dev/tty 2>/dev/tty"))
        assertTrue(args[2].contains("--notify-fd 3"))
        assertTrue(args[2].contains("--process \"${'$'}1\""))
        assertFails { DesktopLinuxAuthorizationOwner(123, 0, 1000) }
        assertFails { DesktopLinuxAuthorizationOwner(123, 456, 0) }
    }

    @Test fun explicitTerminalAgentTargetsPkexecParentWithoutSessionDependentFallback() {
        // pkexec authorizes its parent, not its own PID or the terminal client PID.
        val authenticatedOwner = DesktopLinuxAuthorizationOwner(987, 654321, 1000)
        val arguments = linuxTerminalAgentArguments(authenticatedOwner)
        assertEquals("987,654321", arguments.last())
        // polkit discards a process fallback when the subject has no logind session.
        // An explicit terminal invocation must therefore register a process-specific agent.
        assertFalse(arguments[2].contains("--fallback"))
        assertFalse(arguments[2].contains("--system-bus-name"))
    }

    @Test fun registrationMustBeAcknowledgedBeforeReturningLease() = runBlocking {
        val agent = Agent(ready = true)
        val lease = DesktopLinuxTerminalAuthorization.start(owner, { true }, { agent })
        assertEquals(0, agent.closes)
        lease.close()
        assertEquals(1, agent.closes)
    }

    @Test fun changedOwnerNeverStartsAgentAndReuseDuringWaitClosesIt() = runBlocking {
        var launches = 0
        assertFails { DesktopLinuxTerminalAuthorization.start(owner, { false }, { launches++; Agent() }) }
        assertEquals(0, launches)
        val agent = Agent()
        var checks = 0
        assertFails { DesktopLinuxTerminalAuthorization.start(owner, { ++checks < 3 }, { agent }) }
        assertEquals(1, agent.closes)
    }

    @Test fun missingTerminalOrFailedRegistrationDoesNotBecomeReadiness() = runBlocking {
        val agent = Agent(alive = false, ready = true)
        val failure = assertFails { DesktopLinuxTerminalAuthorization.start(owner, { true }, { agent }) }
        assertEquals("INTERACTION_REQUIRED", failure.message)
        assertEquals(1, agent.closes)
    }

    @Test fun timeoutAndCallerCancellationCloseOnlyOwnedAgent() = runBlocking {
        val timedOut = Agent()
        assertFails { DesktopLinuxTerminalAuthorization.start(owner, { true }, { timedOut }, timeoutMillis = 1) }
        assertEquals(1, timedOut.closes)
        val cancelled = Agent()
        assertFails { withTimeout(30) { DesktopLinuxTerminalAuthorization.start(owner, { true }, { cancelled }) } }
        assertEquals(1, cancelled.closes)
    }
}
