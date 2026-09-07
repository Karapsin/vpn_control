package com.kardinal.vpncontrol

import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

class AndroidRetainedRuntimeServiceTest {
    @Test fun staleOrRevokedRetentionCannotDispatchOrReleaseAnotherSession() {
        val gate = AndroidRuntimeRetentionGate()
        val active = AndroidRuntimeObservation(AndroidRuntimeKnowledge.RUNNING)
        assertNull(gate.acquire(active, AndroidRuntimeObservation(), true))
        val first = requireNotNull(gate.acquire(active, active, true))
        assertNull(gate.acquire(active, active, true))
        gate.release(first)
        val second = requireNotNull(gate.acquire(active, active, true))
        assertTrue(runCatching { gate.checkCurrent(first) }.isFailure)
        assertTrue(runCatching { gate.release(first) }.isFailure)
        assertTrue(runCatching { gate.checkCurrent(second, false) }.isFailure)
        gate.checkCurrent(second)
        gate.release(second); assertFalse(gate.occupied)
    }
    @Test fun onlyExistingHostCanBeRetainedAndOldDestroyCannotUnregisterReplacement() = runTest {
        val access = AndroidRetainedRuntimeServices()
        val observation = AndroidRuntimeObservation(AndroidRuntimeKnowledge.RUNNING)
        assertNull(access.acquire(observation))
        var acquired = 0
        val session = object : AndroidRetainedRuntimeSession {
            override suspend fun dispatch(action: AndroidRuntimeAction, commandId: String, preparedId: String?) {}
            override suspend fun release() = Result.success(Unit)
        }
        fun host() = object : AndroidRetainedRuntimeServices.Host {
            override suspend fun acquire(expected: AndroidRuntimeObservation): AndroidRetainedRuntimeSession { acquired++; return session }
        }
        val old = host(); val fresh = host()
        access.register(old); access.register(fresh); access.unregister(old)
        assertSame(session, access.acquire(observation)); assertEquals(1, acquired)
        assertNull(access.acquire(AndroidRuntimeObservation(AndroidRuntimeKnowledge.STOPPED)))
        access.unregister(fresh); assertNull(access.acquire(observation))
    }
}
