package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*

class DesktopWindowsScopedRuntimeProcessTest {
    private class Channel : DesktopWindowsPreparedRuntimeChannel {
        override val childPid = 41L
        var alive = true
        var lost = false
        var childDead = false
        var closed = false
        var commits = 0
        var aborts = 0
        var failCommit = false
        var failClose = false
        var abortConfirmed = true
        val stops = mutableListOf<Boolean>()
        override fun status(): DesktopWindowsRuntimeStatus {
            check(!lost) { "OUTCOME_UNKNOWN" }
            return DesktopWindowsRuntimeStatus(alive)
        }
        override fun stop(force: Boolean) { stops += force; check(!lost) { "OUTCOME_UNKNOWN" } }
        override fun childExited() = childDead
        override fun close() { check(!failClose) { "OUTCOME_UNKNOWN" }; closed = true }
        override fun commit() { commits++; check(!failCommit) { "RUNTIME_START_FAILED" } }
        override fun abort(): Boolean { aborts++; return abortConfirmed }
    }
    @Test fun preparationDoesNotRunChildAndCloseDisposesOnlyUncommittedCandidate() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel()
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            assertEquals(0, channel.commits)
            prepared.close()
            prepared.close()
            assertEquals(1, channel.aborts)
            assertTrue(channel.closed)
            assertFailsWith<IllegalStateException> { prepared.commit() }
        } finally { Files.delete(log) }
    }
    @Test fun preparedCommitTransfersLifetimeExactlyOnce() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel()
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val runtime = prepared.commit()
            prepared.close()
            assertEquals(1, channel.commits)
            assertEquals(0, channel.aborts)
            assertFalse(channel.closed)
            assertTrue(runtime.isAlive)
            assertFailsWith<IllegalStateException> { prepared.commit() }
            channel.alive = false
            runtime.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun lostCommitAcknowledgmentConfirmsCandidateExitBeforeReturningFailure() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel().also { it.failCommit = true }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            assertFailsWith<IllegalStateException> { prepared.commit() }
            assertEquals(1, channel.aborts)
            assertTrue(channel.closed)
            assertFailsWith<IllegalStateException> { prepared.commit() }
        } finally { Files.delete(log) }
    }
    @Test fun unconfirmedCleanupTransfersRetainedRuntimeOwnershipThroughTypedFailure() {
        val log = Files.createTempFile("vpn-prepared-handle-", ".log")
        try {
            val channel = Channel().also { it.failCommit = true; it.abortConfirmed = false; it.lost = true }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.commit() }
            assertEquals("OUTCOME_UNKNOWN", failure.code)
            val retained = assertNotNull(failure.unresolvedRuntime)
            assertTrue(retained.isAlive)
            assertFalse(channel.closed)
            channel.childDead = true
            retained.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun confirmedAbortStillRetainsOwnershipWhenHandleClosureFails() {
        val log = Files.createTempFile("vpn-prepared-close-failure-", ".log")
        try {
            val channel = Channel().also {
                it.failClose = true
                it.lost = true
                it.childDead = true
            }
            val prepared = DesktopPreparedWindowsRuntimeProcess(channel, log)
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> { prepared.close() }
            assertEquals("OUTCOME_UNKNOWN", failure.code)
            val retained = assertNotNull(failure.unresolvedRuntime)
            assertFalse(retained.isAlive, "Known child exit must survive a separate cleanup failure")
            assertFalse(channel.closed)
            prepared.close() // Ownership has transferred to the failure, never discarded or duplicated.
            assertEquals(1, channel.aborts)
            channel.failClose = false
            retained.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun exactChannelStopDoesNotPretendAcceptanceMeansExited() {
        val log = Files.createTempFile("vpn-runtime-handle-", ".log")
        try {
            val channel = Channel()
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            process.destroy()
            assertEquals(listOf(false), channel.stops)
            assertTrue(process.isAlive)
            assertFalse(process.waitFor(0, TimeUnit.MILLISECONDS))
            assertFailsWith<IllegalStateException> { process.close() }
            process.destroyForcibly()
            assertEquals(listOf(false, true), channel.stops)
            channel.alive = false
            assertTrue(process.waitFor(0, TimeUnit.MILLISECONDS))
            process.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
    @Test fun lostStatusRetainsRuntimeUntilRetainedChildHandleSignalsExit() {
        val log = Files.createTempFile("vpn-runtime-handle-", ".log")
        try {
            val channel = Channel().also { it.lost = true }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            assertTrue(process.isAlive)
            assertEquals(41L, process.pid())
            channel.childDead = true
            assertFalse(process.isAlive)
        } finally { Files.delete(log) }
    }
    @Test fun lostStopUsesOwnedNativeAbortAndRetainsUnconfirmedOutcome() {
        val log = Files.createTempFile("vpn-runtime-lost-stop-", ".log")
        try {
            val channel = Channel().also { it.lost = true; it.abortConfirmed = false }
            val process = DesktopWindowsScopedRuntimeProcess(channel, log)
            assertFailsWith<IllegalStateException> { process.destroyForcibly() }
            assertEquals(1, channel.aborts)
            assertTrue(process.isAlive)
            assertFalse(channel.closed)
            channel.abortConfirmed = true
            process.destroyForcibly()
            assertEquals(2, channel.aborts)
            assertFalse(process.isAlive)
            process.close()
            assertTrue(channel.closed)
        } finally { Files.delete(log) }
    }
}
