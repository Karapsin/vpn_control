package com.kardinal.vpncontrol.desktop

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class DesktopRuntimeMutationTransactionTest {
    @Test
    fun cancellationDuringStopStillCompletesFailedSaveAndRollback() = runTest {
        val stopped = CompletableDeferred<Unit>()
        val continueStop = CompletableDeferred<Unit>()
        val events = mutableListOf<String>()
        val job = launch {
            commitDesktopRuntimeMutation(true,
                captureRestore = { events += "capture"; suspend { events += "restore"; Result.success(Unit) } },
                stop = { events += "stop"; stopped.complete(Unit); continueStop.await(); Result.success(Unit) },
                commit = { events += "save"; Result.failure(DesktopPersistenceException()) })
        }
        stopped.await()
        job.cancel()
        continueStop.complete(Unit)
        job.join()
        assertEquals(listOf("capture", "stop", "save", "restore"), events)
    }
}
