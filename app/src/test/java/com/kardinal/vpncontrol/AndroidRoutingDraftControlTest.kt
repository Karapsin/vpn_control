package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import java.io.Reader
import java.io.StringReader
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidRoutingDraftControlTest {
    private val input = "{\"direct_domain_suffixes\":[\" *.Example.COM. \",\"example.com\"]}"

    @Test fun resourceFailureWithUnknownCommitWarningKeepsTheOriginalAttempt() = runTest {
        Fixture(testScheduler).use { fixture ->
            var first = true
            val draft = fixture.draft { request, spool ->
                if (first) {
                    first = false
                    spool.close()
                    CompletableDeferred(ControlResult("owner", request.requestId, ControlCode.RUNTIME_FAILED, 0,
                        operationId = "original-operation", warnings = listOf("RESOURCE_EXHAUSTED", "CONFIGURATION_OUTCOME_UNKNOWN")))
                } else fixture.control.admitRoutingDocument(request, spool)
            }
            draft.observe(fixture.committed); draft.openEditor()
            val original = draft.save(RoutingRules(directDomainSuffixes = listOf("example.com")))
            val changed = draft.save(RoutingRules(directDomainSuffixes = listOf("changed.test")))
            assertEquals(ControlCode.CONFLICT, changed.result.code)
            assertEquals(listOf("PREVIOUS_REQUEST_OUTCOME_UNKNOWN"), changed.result.warnings)
            val recovered = draft.save(RoutingRules(directDomainSuffixes = listOf("example.com")))
            assertEquals(ControlCode.OK, recovered.result.code)
            assertEquals(original.result.requestId, recovered.result.requestId)
            assertEquals(2, fixture.requests.size)
            assertEquals(fixture.requests.first(), fixture.requests.last())
        }
    }

    @Test fun pickerCompletionKeepsTheOpeningEpochAndRevisionAfterAnotherPublication() = runTest {
        Fixture(testScheduler).use { fixture ->
            val draft = fixture.draft()
            draft.observe(fixture.committed)
            assertTrue(draft.beginImport())
            fixture.committed = fixture.committed.copy(revision = 1, value = PersistedState(
                routingRules = RoutingRules(directDomainSuffixes = listOf("other.test"))))
            draft.observe(fixture.committed)
            val result = draft.importDocument { StringReader(input) }
            assertEquals(ControlCode.CONFLICT, result.result.code)
            assertFalse(result.applyToDraft)
            assertEquals(0, fixture.commits)
            assertEquals(0L, fixture.requests.single().ifRevision)
            assertEquals(listOf("other.test"), fixture.committed.value.routingRules.directDomainSuffixes)
            assertEquals(1, fixture.closedInputs)
        }
    }

    @Test fun responseLossRetryRecoversTheOriginalResultAndRejectsChangedInput() = runTest {
        Fixture(testScheduler).use { fixture ->
            var lost = true
            val draft = fixture.draft { request, spool ->
                val completion = fixture.control.admitRoutingDocument(request, spool)
                if (lost) { lost = false; completion.await(); throw java.io.IOException("synthetic response loss") }
                completion
            }
            draft.observe(fixture.committed); draft.beginImport()
            val unknown = draft.importDocument { StringReader(input) }.result
            assertEquals(ControlCode.OUTCOME_UNKNOWN, unknown.code)
            assertFalse(unknown.final)
            assertNotNull(unknown.operationId)
            draft.observe(fixture.committed)
            assertTrue(draft.beginImport())
            assertEquals(ControlCode.CONFLICT, draft.importDocument {
                StringReader("{\"direct_domain_suffixes\":[\"changed.test\"]}")
            }.result.code)
            val recovered = draft.importDocument { StringReader(input) }
            assertEquals(ControlCode.OK, recovered.result.code)
            assertEquals(unknown.requestId, recovered.result.requestId)
            assertEquals(unknown.operationId, recovered.result.operationId)
            assertTrue(recovered.applyToDraft)
            assertEquals(1, fixture.commits)
            assertEquals(3, fixture.closedInputs)
        }
    }

    @Test fun explicitRetryAfterKnownPersistenceFailureUsesANewRequestWithoutRebasing() = runTest {
        Fixture(testScheduler).use { fixture ->
            fixture.persistenceFailure = true
            val draft = fixture.draft()
            draft.observe(fixture.committed); draft.beginImport()
            val first = draft.importDocument { StringReader(input) }
            assertEquals(ControlCode.PERSISTENCE_FAILED, first.result.code)
            assertFalse(first.applyToDraft)
            assertEquals(0L, fixture.committed.revision)
            fixture.persistenceFailure = false
            assertTrue(draft.beginImport())
            val second = draft.importDocument { StringReader(input) }
            assertEquals(ControlCode.OK, second.result.code)
            assertNotEquals(first.result.requestId, second.result.requestId)
            assertEquals(listOf(0L, 0L), fixture.requests.map { it.ifRevision })
            assertEquals(2, fixture.commits)
            assertEquals(listOf("example.com"), fixture.committed.value.routingRules.directDomainSuffixes)
        }
    }

    @Test fun editorAdvancesOnlyAfterItsOwnCommitAndUsesTheStreamingNormalization() = runTest {
        Fixture(testScheduler).use { fixture ->
            val draft = fixture.draft()
            draft.observe(fixture.committed); assertTrue(draft.openEditor())
            val first = draft.save(RoutingRules(directDomainSuffixes = listOf(" *.Example.COM. ", "example.com")))
            assertTrue(first.applyToDraft)
            assertEquals(listOf("example.com"), fixture.committed.value.routingRules.directDomainSuffixes)
            val second = draft.save(RoutingRules(directDomainSuffixes = listOf("new.test")))
            assertTrue(second.applyToDraft)
            assertEquals(listOf(0L, 1L), fixture.requests.map { it.ifRevision })
            fixture.committed = fixture.committed.copy(revision = 3)
            draft.observe(fixture.committed)
            assertEquals(ControlCode.CONFLICT, draft.save(RoutingRules()).result.code)
            assertEquals(2L, fixture.requests.last().ifRevision)
            assertEquals(2, fixture.commits)
        }
    }

    @Test fun closingPickerDuringInputPreparationDisposesBytesWithoutAdmission() = runTest {
        Fixture(testScheduler).use { fixture ->
            val draft = fixture.draft()
            draft.observe(fixture.committed); draft.beginImport()
            var readerClosed = false
            val result = draft.importDocument {
                object : StringReader(input) {
                    override fun read(buffer: CharArray, offset: Int, count: Int): Int {
                        draft.cancelImport()
                        return super.read(buffer, offset, count)
                    }
                    override fun close() { readerClosed = true; super.close() }
                }
            }
            assertEquals(ControlCode.CANCELLED, result.result.code)
            assertTrue(readerClosed)
            assertTrue(fixture.requests.isEmpty())
            assertEquals(1, fixture.closedInputs)
        }
    }

    @Test fun interruptedWaitDoesNotCancelOwnerAndExplicitRetryKeepsIdentity() = runTest {
        Fixture(testScheduler).use { fixture ->
            val gate = CompletableDeferred<Unit>()
            fixture.commitGate = gate
            val draft = fixture.draft()
            draft.observe(fixture.committed); draft.beginImport()
            val waiter = launch { draft.importDocument { StringReader(input) } }
            runCurrent()
            assertEquals(1, fixture.commits)
            val request = fixture.requests.single()
            waiter.cancelAndJoin()
            assertTrue(fixture.jobs.busy.value)
            val retry = async { draft.importDocument { StringReader(input) } }
            runCurrent()
            assertEquals(request, fixture.requests.last())
            gate.complete(Unit)
            assertEquals(ControlCode.OK, retry.await().result.code)
            assertEquals(1, fixture.commits)
            assertFalse(fixture.jobs.busy.value)
        }
    }

    @Test fun inputFailureIsTypedAndCannotReachPersistenceOrLeakItsDetails() = runTest {
        Fixture(testScheduler).use { fixture ->
            val draft = fixture.draft()
            draft.observe(fixture.committed); draft.beginImport()
            for ((failure, expected) in listOf(
                java.io.IOException("UNTRUSTED_SECRET_PAYLOAD") to ControlCode.UNAVAILABLE,
                OutOfMemoryError("UNTRUSTED_SECRET_PAYLOAD") to ControlCode.RUNTIME_FAILED,
                java.nio.charset.MalformedInputException(1) to ControlCode.INVALID_ARGUMENT,
            )) {
                val result = draft.importDocument {
                    object : Reader() {
                        override fun read(buffer: CharArray, offset: Int, count: Int): Int = throw failure
                        override fun close() {}
                    }
                }.result
                assertEquals(expected, result.code)
                assertTrue(result.final)
                assertFalse(result.toString().contains("UNTRUSTED_SECRET_PAYLOAD"))
            }
            assertEquals(0, fixture.commits)
            assertEquals(3, fixture.closedInputs)
            assertTrue(fixture.requests.isEmpty())
        }
    }

    @Test fun replacementOwnerCannotReceiveAnAutomaticReplayOfTheOldPicker() = runTest {
        Fixture(testScheduler).use { fixture ->
            var replacement = false
            val draft = fixture.draft { request, spool ->
                if (replacement) {
                    spool.close()
                    CompletableDeferred(ControlResult("replacement", request.requestId, ControlCode.CONFLICT, 0))
                } else fixture.control.admitRoutingDocument(request, spool)
            }
            draft.observe(fixture.committed); draft.beginImport()
            replacement = true
            draft.observe(ControlCommitted("replacement", 0, PersistedState()))
            val result = draft.importDocument { StringReader(input) }.result
            assertEquals(ControlCode.OUTCOME_UNKNOWN, result.code)
            assertEquals("owner", result.controllerId)
            assertEquals("owner", fixture.requests.single().controllerId)
            assertEquals(0, fixture.commits)
        }
    }

    private class Fixture(scheduler: TestCoroutineScheduler) : AutoCloseable {
        val dispatcher = StandardTestDispatcher(scheduler)
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val jobs = AndroidCommandJobs(scope)
        var committed = ControlCommitted("owner", 0, PersistedState())
        var commits = 0
        var closedInputs = 0
        var persistenceFailure = false
        var commitGate: CompletableDeferred<Unit>? = null
        val requests = mutableListOf<ControlRequest>()
        val control = AndroidSettingsControl("owner", scope, { committed },
            { _, _, _ -> error("not settings") }, {}, { false }, mutationJobs = jobs,
            routingImport = { prepared, epoch, revision ->
                commits++
                commitGate?.await()
                if (persistenceFailure) throw java.io.IOException("private persistence failure")
                check(epoch == committed.controllerId && revision == committed.revision) { "CONFLICT" }
                val domains = AndroidPersistedDomainSuffixes.decode(prepared.consume().directDomainSuffixes)
                committed = committed.copy(revision = committed.revision + 1,
                    value = PersistedState(routingRules = RoutingRules(directDomainSuffixes = domains)))
                AndroidSettingsCommit(committed, false)
            })
        fun draft(admit: suspend (ControlRequest, AndroidControlInputSpool) -> Deferred<ControlResult> = control::admitRoutingDocument) =
            AndroidRoutingDraftControl({
                AndroidControlInputSpool(object : ControlTransferSpool {
                    val output = java.io.ByteArrayOutputStream()
                    override fun append(bytes: ByteArray) { check(bytes.size <= 65536); output.write(bytes) }
                    override fun read(offset: Long, length: Int) = output.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length)
                    override fun sha256() = error("unused")
                    override fun erase() { closedInputs++; output.reset() }
                })
            }, { request, spool -> requests += request; admit(request, spool) }, control::operationIdForRequest, dispatcher)
        override fun close() { commitGate?.complete(Unit); scope.cancel() }
    }
}
