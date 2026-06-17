package com.kardinal.vpncontrol.data

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackgroundRefreshLeaseLogicTest {
    @Test
    fun emptyLeaseCanBeAcquiredByNonBlankOwner() {
        assertTrue(
            BackgroundRefreshLeaseLogic.canAcquire(
                currentOwner = "",
                currentStartedAtMillis = 0L,
                requestedOwner = "run-1",
                nowMillis = 1_000L,
                staleAfterMillis = 10_000L,
            ),
        )
        assertFalse(
            BackgroundRefreshLeaseLogic.canAcquire(
                currentOwner = "",
                currentStartedAtMillis = 0L,
                requestedOwner = "",
                nowMillis = 1_000L,
                staleAfterMillis = 10_000L,
            ),
        )
    }

    @Test
    fun activeLeaseBlocksDifferentOwnerUntilStale() {
        assertFalse(
            BackgroundRefreshLeaseLogic.canAcquire(
                currentOwner = "run-1",
                currentStartedAtMillis = 1_000L,
                requestedOwner = "run-2",
                nowMillis = 5_000L,
                staleAfterMillis = 10_000L,
            ),
        )
        assertTrue(
            BackgroundRefreshLeaseLogic.canAcquire(
                currentOwner = "run-1",
                currentStartedAtMillis = 1_000L,
                requestedOwner = "run-2",
                nowMillis = 11_000L,
                staleAfterMillis = 10_000L,
            ),
        )
    }

    @Test
    fun sameOwnerCanRenewLease() {
        assertTrue(
            BackgroundRefreshLeaseLogic.canAcquire(
                currentOwner = "run-1",
                currentStartedAtMillis = 1_000L,
                requestedOwner = "run-1",
                nowMillis = 2_000L,
                staleAfterMillis = 10_000L,
            ),
        )
    }
}
