package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.PersistedState
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class VpnStartWaiterTest {
    @Test
    fun returnsWhenRuntimeStartSequenceAdvancesDespiteStatusOverwrite() = runTest {
        var snapshotsRead = 0
        val snapshots = listOf(
            PersistedState(
                isVpnRunning = true,
                runtimeStartSequence = 5L,
                statusMessage = BenchmarkStatusMessages.downloadingRemoteSource(),
            ),
            PersistedState(
                isVpnRunning = true,
                runtimeStartSequence = 6L,
                statusMessage = BenchmarkStatusMessages.downloadingRemoteSource(),
            ),
        )

        VpnStartWaiter.waitForStart(
            snapshot = {
                snapshots.getOrElse(snapshotsRead++) { snapshots.last() }
            },
            initialStatus = "starting",
            initialRuntimeStartSequence = 5L,
            timeoutMillis = 1_000L,
            pollIntervalMillis = 1L,
            delayFn = {},
        )

        assertEquals(2, snapshotsRead)
    }

    @Test
    fun throwsWhenConnectionStopsWithNewFailureStatusBeforeStartSequenceAdvances() = runTest {
        try {
            VpnStartWaiter.waitForStart(
                snapshot = {
                    PersistedState(
                        isVpnRunning = false,
                        runtimeStartSequence = 5L,
                        statusMessage = "start failed",
                    )
                },
                initialStatus = "starting",
                initialRuntimeStartSequence = 5L,
                timeoutMillis = 1_000L,
                pollIntervalMillis = 1L,
                delayFn = {},
            )
            fail("Expected start wait to fail")
        } catch (error: IllegalStateException) {
            assertEquals("start failed", error.message)
        }
    }
}
