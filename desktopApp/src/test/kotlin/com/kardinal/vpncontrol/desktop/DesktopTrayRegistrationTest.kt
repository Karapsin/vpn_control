package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopTrayRegistrationTest {
    @Test
    fun retryableFailuresScheduleRetriesUntilIconInstalls() {
        val target = FakeTrayRegistrationTarget(
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.Installed("tray-icon"),
        )
        val scheduler = FakeTrayRetryScheduler()
        val installed = mutableListOf<String>()
        var unavailableCalls = 0
        val registration = RetryingTrayRegistration(
            target = target,
            scheduler = scheduler,
            retryPolicy = TrayRegistrationRetryPolicy(maxAttempts = 5, retryDelayMillis = 250),
            onInstalled = installed::add,
            onUnavailable = { unavailableCalls += 1 },
        )

        registration.start()
        scheduler.runNext()
        scheduler.runNext()

        assertEquals(3, target.installCalls)
        assertEquals(listOf(250, 250), scheduler.scheduledDelays)
        assertEquals("tray-icon", registration.installedIcon)
        assertEquals(listOf("tray-icon"), installed)
        assertEquals(0, unavailableCalls)
        assertEquals(0, scheduler.pendingCount)

        registration.dispose()

        assertNull(registration.installedIcon)
        assertEquals(listOf("tray-icon"), target.removedIcons)
    }

    @Test
    fun unsupportedTrayDoesNotScheduleRetry() {
        val target = FakeTrayRegistrationTarget(TrayInstallResult.Unsupported)
        val scheduler = FakeTrayRetryScheduler()
        var unavailableCalls = 0
        val registration = RetryingTrayRegistration(
            target = target,
            scheduler = scheduler,
            onUnavailable = { unavailableCalls += 1 },
        )

        registration.start()

        assertEquals(1, target.installCalls)
        assertTrue(scheduler.scheduledDelays.isEmpty())
        assertNull(registration.installedIcon)
        assertEquals(1, unavailableCalls)
    }

    @Test
    fun retryLoopStopsAtConfiguredAttemptLimit() {
        val target = FakeTrayRegistrationTarget(
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.Installed("too-late"),
        )
        val scheduler = FakeTrayRetryScheduler()
        var unavailableCalls = 0
        val registration = RetryingTrayRegistration(
            target = target,
            scheduler = scheduler,
            retryPolicy = TrayRegistrationRetryPolicy(maxAttempts = 3, retryDelayMillis = 10),
            onUnavailable = { unavailableCalls += 1 },
        )

        registration.start()
        scheduler.runNext()
        scheduler.runNext()

        assertEquals(3, target.installCalls)
        assertEquals(listOf(10, 10), scheduler.scheduledDelays)
        assertEquals(0, scheduler.pendingCount)
        assertNull(registration.installedIcon)
        assertEquals(1, unavailableCalls)
    }

    @Test
    fun disposeCancelsPendingRetryWithoutRemovingFailedIcon() {
        val target = FakeTrayRegistrationTarget(
            TrayInstallResult.RetryableFailure,
            TrayInstallResult.Installed("late-icon"),
        )
        val scheduler = FakeTrayRetryScheduler()
        var unavailableCalls = 0
        val registration = RetryingTrayRegistration(
            target = target,
            scheduler = scheduler,
            retryPolicy = TrayRegistrationRetryPolicy(maxAttempts = 3, retryDelayMillis = 10),
            onUnavailable = { unavailableCalls += 1 },
        )

        registration.start()
        registration.dispose()
        scheduler.runNext()

        assertEquals(1, target.installCalls)
        assertEquals(0, scheduler.pendingCount)
        assertTrue(scheduler.scheduledRetries.single().cancelled)
        assertTrue(target.removedIcons.isEmpty())
        assertNull(registration.installedIcon)
        assertEquals(0, unavailableCalls)
    }

    @Test
    fun installExceptionIsRetried() {
        val target = FakeTrayRegistrationTarget(
            null,
            TrayInstallResult.Installed("tray-icon"),
        )
        val scheduler = FakeTrayRetryScheduler()
        val registration = RetryingTrayRegistration(
            target = target,
            scheduler = scheduler,
            retryPolicy = TrayRegistrationRetryPolicy(maxAttempts = 2, retryDelayMillis = 50),
        )

        registration.start()
        scheduler.runNext()

        assertEquals(2, target.installCalls)
        assertEquals(listOf(50), scheduler.scheduledDelays)
        assertEquals("tray-icon", registration.installedIcon)
    }
}

private class FakeTrayRegistrationTarget(
    vararg results: TrayInstallResult<String>?,
) : TrayRegistrationTarget<String> {
    private val results = results.toMutableList()

    var installCalls = 0
        private set
    val removedIcons = mutableListOf<String>()

    override fun install(): TrayInstallResult<String> {
        installCalls += 1
        val result = results.removeFirstOrNull()
        if (result == null) {
            error("simulated install failure")
        }
        return result
    }

    override fun remove(icon: String) {
        removedIcons += icon
    }
}

private class FakeTrayRetryScheduler : TrayRetryScheduler {
    val scheduledDelays = mutableListOf<Int>()
    val scheduledRetries = mutableListOf<ScheduledRetry>()

    val pendingCount: Int
        get() = scheduledRetries.count { !it.cancelled && !it.ran }

    override fun schedule(delayMillis: Int, action: () -> Unit): TrayRetryHandle {
        val retry = ScheduledRetry(action)
        scheduledDelays += delayMillis
        scheduledRetries += retry
        return retry
    }

    fun runNext() {
        scheduledRetries
            .firstOrNull { !it.ran }
            ?.run()
    }
}

private class ScheduledRetry(
    private val action: () -> Unit,
) : TrayRetryHandle {
    var cancelled = false
        private set
    var ran = false
        private set

    override fun cancel() {
        cancelled = true
    }

    fun run() {
        if (cancelled) {
            ran = true
            return
        }
        ran = true
        action()
    }
}
