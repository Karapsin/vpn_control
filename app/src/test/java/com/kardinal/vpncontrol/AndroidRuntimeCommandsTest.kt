package com.kardinal.vpncontrol

import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.TimeoutCancellationException
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidRuntimeCommandsTest {
    @Test fun nativeValidationFailurePrecedesRuntimeReset() {
        val commands = AndroidRuntimeCommands()
        val ticket = commands.register(AndroidRuntimeAction.START, "invalid")
        var reset = false
        val result = runCatching {
            commands.prepareStart(ticket.id, "invalid", null, AndroidPreparedConnections()) { error("invalid config") }
            reset = true
        }
        assertTrue(result.isFailure)
        assertFalse(reset)
    }
    @Test fun cancelledClaimedWaiterCanObserveActualCompletionLater() = runTest {
        val commands = AndroidRuntimeCommands()
        val ticket = commands.register(AndroidRuntimeAction.STOP)
        assertTrue(commands.claim(ticket.id, AndroidRuntimeAction.STOP))
        val waiter = async { commands.await(ticket, 1000) }
        runCurrent()
        waiter.cancel()
        runCurrent()
        commands.complete(ticket.id, Result.success(Unit))
        assertTrue(commands.await(ticket, 1000).isSuccess)
    }

    @Test fun expiredClaimedReceiptIsUnknownAndLateSuccessCannotOverwriteIt() = runTest {
        var now = 0L
        val commands = AndroidRuntimeCommands(clockMillis = { now }, retentionMillis = 100)
        val ticket = commands.register(AndroidRuntimeAction.STOP)
        assertTrue(commands.claim(ticket.id, AndroidRuntimeAction.STOP))
        now = 101
        commands.complete(ticket.id, Result.success(Unit))
        assertTrue(commands.await(ticket, 1000).exceptionOrNull() is AndroidRuntimeOutcomeUnknownException)
    }
    @Test fun stalePreparedTokenFailsPreflightBeforeReplacingExistingRuntime() {
        val commands = AndroidRuntimeCommands()
        val ticket = commands.register(AndroidRuntimeAction.START, "exact")
        val observer = AndroidRuntimeObserver()
        observer.started(Any(), com.kardinal.vpncontrol.model.AppMode.VPN, "existing")
        val before = observer.state.value
        val failed = runCatching {
            commands.prepareStart(ticket.id, "exact", "expired-token", AndroidPreparedConnections())
            observer.resetCompleted(true) // Same ordering as service: reset only after preflight.
        }
        assertEquals("RUNTIME_PREPARATION_STALE", failed.exceptionOrNull()?.message)
        assertEquals(before, observer.state.value)
    }

    @Test fun delayedAcknowledgmentNeverCompletesAnotherCommand() = runTest {
        val commands = AndroidRuntimeCommands()
        val first = commands.register(AndroidRuntimeAction.START, "first")
        val second = commands.register(AndroidRuntimeAction.STOP)
        assertTrue(commands.claim(first.id, AndroidRuntimeAction.START, "first"))
        assertTrue(commands.claim(second.id, AndroidRuntimeAction.STOP))
        val waiting = async { commands.await(second, 1000) }
        commands.complete(first.id, Result.success(Unit))
        runCurrent()
        assertFalse(waiting.isCompleted)
        commands.complete(second.id, Result.failure(IllegalStateException("RUNTIME_OUTCOME_UNKNOWN")))
        assertEquals("RUNTIME_OUTCOME_UNKNOWN", waiting.await().exceptionOrNull()?.message)
        assertTrue(commands.await(first, 1000).isSuccess)
    }

    @Test fun invalidConfigActionOrExpiredCommandCannotAuthorizeEffects() = runTest {
        val commands = AndroidRuntimeCommands()
        val ticket = commands.register(AndroidRuntimeAction.START, "exact")
        assertFalse(commands.claim(ticket.id, AndroidRuntimeAction.START, "changed"))
        assertFalse(commands.claim(ticket.id, AndroidRuntimeAction.STOP))
        assertTrue(commands.claim(ticket.id, AndroidRuntimeAction.START, "exact"))
        assertFalse(commands.claim(ticket.id, AndroidRuntimeAction.START, "exact"))
        commands.discard(ticket)
        assertFalse(commands.claim(ticket.id, AndroidRuntimeAction.START, "exact"))
    }

    @Test fun dispatchRejectionDiscardsReceiptAndTimeoutDoesNotInventSuccess() = runTest {
        val commands = AndroidRuntimeCommands()
        val rejected = commands.register(AndroidRuntimeAction.STOP)
        commands.discard(rejected) // Adapter's startService exception path.
        assertFalse(commands.claim(rejected.id, AndroidRuntimeAction.STOP))
        val dispatched = commands.register(AndroidRuntimeAction.START, "config")
        assertTrue(commands.claim(dispatched.id, AndroidRuntimeAction.START, "config"))
        val outcome = runCatching { commands.await(dispatched, 10) }
        assertTrue(outcome.exceptionOrNull() is TimeoutCancellationException)
        commands.complete(dispatched.id, Result.success(Unit)) // Late service completion is not another receipt.
        assertTrue(commands.await(dispatched, 1000).isSuccess)
        assertTrue(com.kardinal.vpncontrol.data.VpnCommandException("wait expired",
            outcome.exceptionOrNull(), commandDispatched = true).outcomeUnknown)
        val next = commands.register(AndroidRuntimeAction.START, "config")
        assertFalse(next.completion.isCompleted)
    }
}
