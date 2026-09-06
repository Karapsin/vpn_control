package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidEffectBatchRunnerTest {
    @Test fun mutationBatchIsExcludedBothDirectionsAndRetainsLeaseUntilLastEffect() = runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        val gate = CompletableDeferred<Unit>()
        var writes = 0
        val runner = AndroidEffectBatchRunner({ jobs.launch(it) }, { jobs.launchMutation(it) }) { effects ->
            effects.forEach { writes++; gate.await() }
        }
        val effects = listOf(MainControllerEffect.UpdateAppMode(AppMode.PROXY_ONLY), MainControllerEffect.UpdateStatus("done"))
        val settingsLease = requireNotNull(jobs.tryAcquireMutation())
        runner.handle(effects)
        runCurrent()
        assertEquals(0, writes)
        jobs.releaseMutation(settingsLease)
        runner.handle(effects)
        runCurrent()
        assertEquals(1, writes)
        assertNull(jobs.tryAcquireMutation())
        jobs.cancelActive()
        gate.complete(Unit)
        runCurrent()
        assertEquals(2, writes)
        assertFalse(jobs.busy.value)
    }

    @Test fun alreadyAdmittedStopThenEffectsDoNotReacquireAndHandledFailureReleasesLease() = runTest {
        val jobs = AndroidCommandJobs(backgroundScope)
        var stopped = false
        var failed = false
        val runner = AndroidEffectBatchRunner({ jobs.launch(it) }, { fail("nested acquisition") }) {
            assertTrue(stopped)
            error("persistence failure")
        }
        jobs.launchMutation {
            stopped = true
            failed = runCatching { runner.handleWithinMutation(listOf(MainControllerEffect.UpdateAppMode(AppMode.PROXY_ONLY))) }.isFailure
        }
        runCurrent()
        assertTrue(failed)
        assertFalse(jobs.busy.value)
    }
}
