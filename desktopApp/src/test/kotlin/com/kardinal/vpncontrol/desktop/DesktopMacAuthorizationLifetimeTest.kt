package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import kotlinx.coroutines.runBlocking
import kotlin.test.*

class DesktopMacAuthorizationLifetimeTest {
    private val job = "05dc777a-9bb2-4a73-8d20-b42f45f64a32"

    @Test fun lateExactCancellationIsObservedAfterInitialAuthorizationTimeout() = runBlocking {
        val process = FakeProcess(alive = true, reply = "VPN_CONTROL_AUTH_V1\n$job\n-128\n".encodeToByteArray())
        val collector = DesktopMacAuthorizationCollector(job, process)
        val lifetime = DesktopMacAuthorizationLifetime(
            awaitAuthorization = { Result.failure(IllegalStateException(ControlCode.OUTCOME_UNKNOWN.name)) },
            collector = collector)

        assertEquals(ControlCode.OUTCOME_UNKNOWN.name, lifetime.awaitInitial().exceptionOrNull()?.message)
        process.alive = false
        assertEquals(ControlCode.CANCELLED, lifetime.lateAuthorization())
    }

    @Test fun collectorCachesKnownReplyForImmediateAndLateObservation() {
        val process = FakeProcess(alive = false, reply = "VPN_CONTROL_AUTH_V1\n$job\n-128\n".encodeToByteArray())
        val collector = DesktopMacAuthorizationCollector(job, process)

        assertEquals(ControlCode.CANCELLED, collector.poll())
        assertEquals(ControlCode.CANCELLED, collector.poll())
    }

    @Test fun malformedAndOversizeRepliesRemainUnknown() {
        val malformed = DesktopMacAuthorizationCollector(job,
            FakeProcess(false, "VPN_CONTROL_AUTH_V1\n$job\n0\n".encodeToByteArray()))
        val oversize = DesktopMacAuthorizationCollector(job,
            FakeProcess(false, ("x".repeat(257)).encodeToByteArray()))

        assertEquals(null, malformed.poll())
        assertEquals(null, malformed.poll())
        assertEquals(null, oversize.poll())
    }

    @Test fun receiptConflictLeavesWatcherAndPreparedStateUntouched() {
        var watcherStops = 0
        var closes = 0
        var marks = 0
        val observer = observer(
            requireReceiptAbsent = { error("Protected receipt exists") },
            stopWatcher = { watcherStops++; true },
            closePrepared = { closes++ },
            markNotStarted = { marks++ },
        )

        assertTrue(observer.reconcile("owner").isFailure)
        assertFalse(observer.isCompleted())
        assertEquals(0, watcherStops)
        assertEquals(0, closes)
        assertEquals(0, marks)
    }

    @Test fun watcherAndCloseFailuresDoNotPublishOrConfirmAndCloseCanRetry() {
        var watcherStops = 0
        var closeAttempts = 0
        var marks = 0
        var confirmations = 0
        val observer = observer(
            stopWatcher = { ++watcherStops > 1 },
            closePrepared = {
                closeAttempts++
                if (closeAttempts == 1) error("close failed")
            },
            markNotStarted = { marks++ },
            onCancellationConfirmed = { confirmations++ },
        )

        assertTrue(observer.reconcile("owner").isFailure)
        assertFalse(observer.isCompleted())
        assertEquals(0, closeAttempts)
        assertEquals(0, marks)
        assertTrue(observer.reconcile("owner").isFailure)
        assertEquals(1, closeAttempts)
        assertEquals(0, marks)
        assertTrue(observer.reconcile("owner").isSuccess)
        assertTrue(observer.isCompleted())
        assertEquals(2, closeAttempts)
        assertEquals(1, marks)
        assertEquals(1, confirmations)
        assertTrue(observer.reconcile("owner").isSuccess)
        assertEquals(1, marks)
        assertEquals(1, confirmations)
    }

    @Test fun foreignOwnerCannotConsumeOrPublishLateReply() {
        var stops = 0
        var marks = 0
        val observer = observer(stopWatcher = { stops++; true }, markNotStarted = { marks++ })

        assertTrue(observer.reconcile("foreign").isSuccess)
        assertEquals(0, stops)
        assertEquals(0, marks)
    }

    private fun observer(
        requireReceiptAbsent: () -> Unit = {},
        stopWatcher: () -> Boolean = { true },
        closePrepared: () -> Unit = {},
        markNotStarted: (ControlCode) -> Unit = {},
        onCancellationConfirmed: () -> Unit = {},
    ): DesktopMacLateAuthorization {
        val process = FakeProcess(false, "VPN_CONTROL_AUTH_V1\n$job\n-128\n".encodeToByteArray())
        return DesktopMacLateAuthorization(
            ownerId = "owner",
            lifetime = DesktopMacAuthorizationLifetime({ Result.success(Unit) }, DesktopMacAuthorizationCollector(job, process)),
            requireReceiptAbsent = requireReceiptAbsent,
            stopWatcher = stopWatcher,
            closePrepared = closePrepared,
            markNotStarted = markNotStarted,
            onCancellationConfirmed = onCancellationConfirmed,
        )
    }

    private class FakeProcess(var alive: Boolean, private val reply: ByteArray) : Process() {
        override fun isAlive(): Boolean = alive
        override fun exitValue(): Int { check(!alive); return 0 }
        override fun getInputStream(): InputStream = ByteArrayInputStream(reply)
        override fun getErrorStream(): InputStream = ByteArrayInputStream(byteArrayOf())
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun waitFor(): Int { alive = false; return 0 }
        override fun waitFor(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean { alive = false; return true }
        override fun destroy() { alive = false }
        override fun destroyForcibly(): Process { alive = false; return this }
    }
}
