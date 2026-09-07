package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.AndroidSettingsCommit
import com.kardinal.vpncontrol.model.*
import java.lang.ref.WeakReference
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidRoutingAdmissionTest {
    @Test fun externalInputRetryAndDisconnectedWaiterKeepOneOwnerAndCloseEverySpool() = runTest {
        val owner = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val release = CompletableDeferred<Unit>()
        var closes = 0
        var commits = 0
        fun input(failClose: Boolean = false): AndroidControlInputSpool = AndroidControlInputSpool(object : ControlTransferSpool {
            val bytes = java.io.ByteArrayOutputStream()
            override fun append(bytes: ByteArray) { this.bytes.write(bytes) }
            override fun read(offset: Long, length: Int) = bytes.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length)
            override fun sha256() = error("unused")
            override fun erase() { closes++; if (failClose) throw java.io.IOException("private synthetic close failure") }
        }).also { it.append("{\"direct_domain_suffixes\":[\"example.test\"]}"); it.seal() }
        val request = ControlRequest("external", ControlCommand(ControlOperationId.ROUTING_IMPORT), controllerId = "owner")
        val jobs = AndroidCommandJobs(owner)
        val control = AndroidSettingsControl("owner", owner, { ControlCommitted("owner", 0, PersistedState()) },
            { _, _, _ -> error("not settings") }, {}, { false }, mutationJobs = jobs, routingImport = { _, _, _ ->
                commits++; release.await(); AndroidSettingsCommit(ControlCommitted("owner", 1, PersistedState()), false)
            })
        try {
            val first = control.admitRoutingDocument(request, input())
            val waiter = launch { first.await() }
            runCurrent()
            assertEquals(1, closes) // Parsed input is gone before suspended durable work.
            waiter.cancelAndJoin()
            assertFalse(first.isCompleted)
            assertSame(first, control.admitRoutingDocument(request, input()))
            assertEquals(2, closes)
            release.complete(Unit)
            assertEquals(ControlCode.OK, first.await().code)
            assertEquals(first.await(), control.admitRoutingDocument(request, input()).await())
            assertEquals(3, closes)
            assertEquals(1, commits)
            owner.cancel()
            assertEquals(ControlCode.CANCELLED, control.admitRoutingDocument(request.copy(requestId = "closed"), input()).await().code)
            assertEquals(4, closes)
            val failedCleanup = withTimeout(1000) {
                control.admitRoutingDocument(request.copy(requestId = "close-failure"), input(failClose = true)).await()
            }
            assertEquals(ControlCode.CANCELLED, failedCleanup.code)
            assertTrue("PRIVATE_INPUT_CLEANUP_UNAVAILABLE" in failedCleanup.warnings)
            assertFalse(jobs.busy.value)
            assertEquals(5, closes)
        } finally { release.complete(Unit); owner.cancel() }
    }

    private fun document(): ByteArray = ControlDocumentCodec.encodeRequest(ControlRequest("large", ControlCommand(
        ControlOperationId.ROUTING_IMPORT, mapOf("input" to ControlValue.Text(
            """{"direct_domain_suffixes":["example.test"],"ignore_rules":false}""" + " ".repeat(1_000_000)))),
        controllerId = "owner")).toByteArray()

    @Test fun realReaderAndOwnerReleaseRawDocumentBeforeCommitAndRetainSyncResult() = runTest {
        val owner = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val release = CompletableDeferred<Unit>()
        var raw: WeakReference<String>? = null
        var entered = false
        try {
            val control = AndroidSettingsControl("owner", owner, { ControlCommitted("owner", 0, PersistedState()) },
                { _, _, _ -> error("not settings") }, {}, { false }, routingImport = { rules, epoch, revision ->
                    entered = true
                    release.await()
                    assertEquals("owner", epoch)
                    assertNull(revision)
                    AndroidSettingsCommit(ControlCommitted("owner", 1, PersistedState(routingRules = RoutingRules(
                        directDomainSuffixes = rules.consume().directDomainSuffixes.lines()))), false)
                })
            val reader = AndroidControlReader("owner", { PersistedState() }, routingAdmission = { request ->
                raw = WeakReference((request.command.arguments.getValue("input") as ControlValue.Text).value)
                control.admitRoutingImport(request)
            }, operationIdForRequest = control::operationIdForRequest)
            val result = async { reader.executeDocument(document(), "transport") }
            runCurrent()
            assertTrue(entered)
            assertFalse(result.isCompleted)
            repeat(40) { if (raw!!.get() != null) {
                val pressure = Array(8) { ByteArray(128 * 1024) }
                System.gc()
                assertEquals(8, pressure.size)
            } }
            assertNull("Decoded document remains reachable across Reader/owner commit suspension", raw!!.get())
            release.complete(Unit)
            val completed = ControlDocumentCodec.decodeResult(result.await().toString(Charsets.UTF_8))
            assertEquals(ControlCode.OK, completed.code)
            assertEquals("large", completed.requestId)
            assertEquals(1L, completed.configurationRevision)
        } finally { release.complete(Unit); owner.cancel() }
    }

    @Test fun preparedAdmissionRejectsStaleGuardsAndRetainsRetryWhileBusy() = runTest {
        val owner = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val release = CompletableDeferred<Unit>()
        var calls = 0
        try {
            val jobs = AndroidCommandJobs(owner)
            val control = AndroidSettingsControl("owner", owner, { ControlCommitted("owner", 4, PersistedState()) },
                { _, _, _ -> error("not settings") }, {}, { false }, mutationJobs = jobs,
                routingImport = { rules, _, _ -> calls++; release.await()
                    AndroidSettingsCommit(ControlCommitted("owner", 5, PersistedState(routingRules = RoutingRules(
                        directDomainSuffixes = rules.consume().directDomainSuffixes.lines()))), false) })
            val request = ControlDocumentCodec.decodeRequest(document().toString(Charsets.UTF_8)).copy(ifRevision = 4)
            assertEquals(ControlCode.CONFLICT, control.admitRoutingImport(request.copy(controllerId = "old")).await().code)
            assertEquals(ControlCode.CONFLICT, control.admitRoutingImport(request.copy(ifRevision = 3)).await().code)
            assertEquals(0, calls)
            val first = control.admitRoutingImport(request)
            runCurrent()
            val retry = control.admitRoutingImport(request)
            assertSame(first, retry)
            assertEquals(ControlCode.BUSY, control.admitRoutingImport(request.copy(requestId = "other")).await().code)
            release.complete(Unit)
            assertEquals(ControlCode.OK, first.await().code)
            assertEquals(first.await(), control.admitRoutingImport(request).await())
            assertEquals(1, calls)
            assertFalse(jobs.busy.value)
        } finally { release.complete(Unit); owner.cancel() }
    }
}
