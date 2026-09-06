package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.*

@OptIn(ExperimentalCoroutinesApi::class)
class DesktopUpdateCancelCommandTest {
    @Test fun cancelWaitsForCleanupAndRetryCannotCancelANewerDownload() = runTest {
        val cleanup = CompletableDeferred<Unit>()
        val cleaning = CompletableDeferred<Unit>()
        var downloads = 0
        var dismissals = 0
        val session = DesktopHeadlessSession(backgroundScope, { MainUiState() }, { command ->
            when (command) {
                DesktopCliCommand.UpdatesDownload -> {
                    downloads++
                    try { awaitCancellation() } finally {
                        cleaning.complete(Unit)
                        withContext(NonCancellable) { cleanup.await() }
                    }
                }
                DesktopCliCommand.UpdatesDismiss -> { dismissals++; DesktopCliResponse.success("") }
                else -> error("unexpected command")
            }
        }, {}, controllerId = "owner")
        fun request(id: String, operation: ControlOperationId, async: Boolean = false) = DesktopCliCommand.ControlSubmit(
            ControlRequest(id, ControlCommand(operation), controllerId = "owner", asynchronous = async))
        try {
            session.execute(request("download", ControlOperationId.UPDATES_DOWNLOAD, true))
            runCurrent()
            assertEquals(1, downloads)
            val cancellation = request("cancel", ControlOperationId.UPDATES_CANCEL)
            val waiting = async { session.execute(cancellation) }
            runCurrent()
            cleaning.await()
            assertFalse(waiting.isCompleted)
            assertEquals(0, dismissals)
            cleanup.complete(Unit)
            val result = waiting.await()
            assertEquals(ControlCode.OK, ControlProtocolCodec.decodeResult(result.message).code)
            assertEquals(1, dismissals)
            session.execute(request("new-download", ControlOperationId.UPDATES_DOWNLOAD, true))
            runCurrent()
            assertEquals(2, downloads)
            assertEquals(result, session.execute(cancellation))
            assertEquals(1, dismissals)
            assertFalse(session.operationSnapshot().single { it.requestId == "new-download" }.phase.terminal)
        } finally { cleanup.complete(Unit); session.close() }
    }
}
