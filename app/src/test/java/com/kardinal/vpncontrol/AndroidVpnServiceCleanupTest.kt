package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.vpn.AndroidVpnServiceCleanup
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.sync.Mutex
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidVpnServiceCleanupTest {
    @Test fun destructionOfAcknowledgedStoppedInstanceDoesNotResetRestoredRuntime() = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val observer = AndroidRuntimeObserver(initiallyStopped = true)
        val lifecycle = AndroidVpnServiceCleanup(scope, Mutex()) { observer.resetCompleted(true) }
        observer.started(Any(), com.kardinal.vpncontrol.model.AppMode.VPN, "original")
        observer.resetCompleted(true)
        lifecycle.stopped()
        observer.started(Any(), com.kardinal.vpncontrol.model.AppMode.VPN, "restored")
        val restored = observer.state.value
        lifecycle.finish(null)
        runCurrent()
        assertEquals(restored, observer.state.value)
        assertFalse(scope.isActive)
    }

    @Test fun newRuntimeWorkInSameInstanceRequiresCleanupAgain() = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        var stops = 0
        val lifecycle = AndroidVpnServiceCleanup(scope, Mutex()) { stops++ }
        lifecycle.stopped()
        lifecycle.runtimeWorkStarted()
        lifecycle.finish(null)
        runCurrent()
        assertEquals(1, stops)
    }

    @Test fun revokeThenDestroyQueuesOneCleanupAfterCommandAndCancelsOnlyAfterDurableStop() = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val mutex = Mutex(locked = true) // An admitted command is still completing.
        val telemetry = CompletableDeferred<Unit>()
        val statuses = mutableListOf<String?>()
        val lifecycle = AndroidVpnServiceCleanup(scope, mutex) {
            statuses += it
            telemetry.await()
        }
        lifecycle.finish("revoked")
        lifecycle.finish(null)
        runCurrent()
        assertTrue(lifecycle.finishing)
        assertTrue(statuses.isEmpty())
        assertTrue(scope.isActive)
        mutex.unlock()
        runCurrent()
        assertEquals(listOf("revoked"), statuses)
        assertTrue(scope.isActive)
        telemetry.complete(Unit)
        runCurrent()
        assertFalse(scope.isActive)
    }

    @Test fun cancelledServiceScopeCannotAbandonQueuedNativeCleanup() = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val mutex = Mutex(locked = true)
        var cleaned = false
        val lifecycle = AndroidVpnServiceCleanup(scope, mutex) { cleaned = true }
        lifecycle.finish(null)
        scope.cancel()
        runCurrent()
        assertFalse(cleaned)
        mutex.unlock()
        runCurrent()
        assertTrue(cleaned)
    }
    @Test fun destructionReturnsToMainWhileStorageWaitsForMainThreadCommit() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val storeCommit = CompletableDeferred<Unit>()
        val cleanupEntered = CountDownLatch(1)
        val callbackReturned = CountDownLatch(1)
        val cleanupDone = CountDownLatch(1)
        val lifecycle = AndroidVpnServiceCleanup(scope, Mutex()) {
            cleanupEntered.countDown()
            storeCommit.await() // DataStore is processing another caller's main-dispatched transform.
            cleanupDone.countDown()
        }
        val main = Thread {
            lifecycle.finish(null)
            callbackReturned.countDown()
        }
        main.start()
        try {
            assertTrue(cleanupEntered.await(2, TimeUnit.SECONDS))
            assertTrue("onDestroy must return so the main-dispatched storage transaction can finish",
                callbackReturned.await(300, TimeUnit.MILLISECONDS))
        } finally {
            storeCommit.complete(Unit)
            main.join(2000)
        }
        assertTrue(cleanupDone.await(2, TimeUnit.SECONDS))
    }
}
