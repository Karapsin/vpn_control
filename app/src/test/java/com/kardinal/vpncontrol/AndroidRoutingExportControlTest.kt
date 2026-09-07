package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*
import java.io.StringWriter
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidRoutingExportControlTest {
    @Test fun preparedExportPinsExactOwnerBytesAndCanBeReusedAcrossPickerRecreation() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        val prepared = export.prepare()
        assertEquals(ControlCode.OK, prepared.result.code)
        assertTrue(prepared.fileName!!.endsWith(".json"))
        fixture.rules = RoutingRules(directDomainSuffixes = listOf("later.test"))
        assertEquals(prepared, export.prepare())
        assertEquals(1, fixture.reads)
        val writer = StringWriter()
        val result = export.write({ writer }, { error("successful output must not be deleted") })
        assertEquals(prepared.result, result)
        assertEquals(listOf("original.test"), RoutingRulesTransfer.import(writer.toString()).directDomainSuffixes)
        assertEquals(1, fixture.closed)
        assertEquals(ControlCode.CONFLICT, export.write({ error("must not reopen output") }, { false }).code)
        export.close()
        assertEquals(1, fixture.closed)
    }

    @Test fun readFailuresAndForeignOwnersCannotPublishSuccessfulExportContent() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control { request ->
            AndroidControlDocumentResponse(ControlResult("owner", request.requestId, ControlCode.UNAVAILABLE, 7)) {
                error("failed response content must not be written")
            }
        }
        val result = export.prepare()
        assertEquals(ControlCode.UNAVAILABLE, result.result.code)
        assertEquals(7L, result.result.configurationRevision)
        assertNull(result.fileName)
        assertEquals(0, fixture.opened)
        val foreign = fixture.control { request ->
            AndroidControlDocumentResponse(ControlResult("replacement", request.requestId, ControlCode.OK, 0)) { it.append("unsafe") }
        }.prepare()
        assertEquals(ControlCode.OUTCOME_UNKNOWN, foreign.result.code)
        assertEquals("owner", foreign.result.controllerId)
        assertNull(foreign.fileName)
        assertEquals(0, fixture.opened)
    }

    @Test fun pickerCancellationDisposesPrivateInputWithoutOpeningAnyDestination() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        export.prepare()
        export.close()
        assertEquals(1, fixture.closed)
        assertEquals(ControlCode.CONFLICT, export.write({ error("cancelled picker") }, { false }).code)
    }

    @Test fun recoveredFreshDocumentWithoutPrivateInputIsDisposedWithoutReadingNewOwnerState() = runTest {
        val fixture = Fixture(testScheduler)
        val recreated = fixture.control { error("A lost export must not be recreated from current settings") }
        var discarded = 0
        val result = recreated.write({ error("No input authorizes opening this document") }, { discarded++; true })
        assertEquals(ControlCode.CONFLICT, result.code)
        assertEquals(1, discarded)
        assertEquals(0, fixture.reads)
        assertEquals(0, fixture.opened)
        assertEquals(ControlCode.CONFLICT, recreated.write({ error("No replay") }, { error("No repeated disposal") }).code)
        val unremovable = fixture.control().write({ error("No input") }, { false })
        assertTrue("EXPORT_OUTPUT_CLEANUP_UNAVAILABLE" in unremovable.warnings)
    }

    @Test fun duplicateCallbackNeverDisposesPreviouslyCompletedOutput() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        export.prepare()
        val output = StringWriter()
        assertEquals(ControlCode.OK, export.write({ output }, { error("Completed output") }).code)
        assertEquals(ControlCode.CONFLICT, export.write({ error("No replay") }, { error("Completed output must survive") }).code)
        assertTrue(output.toString().isNotEmpty())
    }

    @Test fun outputFailureDeletesOnlyTheCreatedDestinationAndKeepsCorrelatedFailure() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        val prepared = export.prepare()
        var discarded = 0
        val result = export.write({ object : java.io.Writer() {
            override fun write(buffer: CharArray, offset: Int, count: Int) { throw java.io.IOException("SECRET_OUTPUT_DETAILS") }
            override fun flush() {}
            override fun close() {}
        } }, { discarded++; true })
        assertEquals(ControlCode.PERSISTENCE_FAILED, result.code)
        assertEquals(prepared.result.requestId, result.requestId)
        assertEquals(prepared.result.configurationRevision, result.configurationRevision)
        assertFalse(result.toString().contains("SECRET_OUTPUT_DETAILS"))
        assertEquals(1, discarded)
        assertEquals(1, fixture.closed)
        assertEquals(ControlCode.CONFLICT, export.write({ error("cannot replay external output") }, { false }).code)
    }

    @Test fun cancelledOutputDisposesItsCreatedDestinationAndNeverReplaysIt() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        export.prepare()
        var discarded = 0
        try {
            export.write({ object : java.io.Writer() {
                override fun write(buffer: CharArray, offset: Int, count: Int) { throw CancellationException("cancelled output") }
                override fun flush() {}
                override fun close() {}
            } }, { discarded++; true })
            fail("Cancellation must propagate after cleanup")
        } catch (_: CancellationException) { }
        assertEquals(1, discarded)
        assertEquals(1, fixture.closed)
        assertEquals(ControlCode.CONFLICT, export.write({ error("cancelled output must not reopen") }, { false }).code)
    }

    @Test fun cancellationAfterWriterClosePreservesKnownCompleteOutput() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        export.prepare()
        var completed = false
        var discarded = 0
        val job = launch {
            val current = currentCoroutineContext()[Job]!!
            export.write({ object : StringWriter() {
                override fun close() { completed = true; current.cancel() }
            } }, { discarded++; true })
        }
        job.join()
        assertTrue(completed)
        assertEquals(0, discarded)
        assertEquals(1, fixture.closed)
    }

    @Test fun failedExternalCleanupAndPrivateCleanupAreReportedWithoutErasingKnownSuccess() = runTest {
        val fixture = Fixture(testScheduler)
        val export = fixture.control()
        export.prepare()
        val failed = export.write({ throw java.io.IOException() }, { false })
        assertEquals(ControlCode.PERSISTENCE_FAILED, failed.code)
        assertTrue("EXPORT_OUTPUT_CLEANUP_UNAVAILABLE" in failed.warnings)
        export.prepare()
        fixture.closeFailure = true
        val successful = export.write({ StringWriter() }, { false })
        assertEquals(ControlCode.OK, successful.code)
        assertTrue("PRIVATE_INPUT_CLEANUP_UNAVAILABLE" in successful.warnings)
    }

    @Test fun closingWhilePreparationIsSuspendedCannotReopenTheFilePicker() = runTest {
        val fixture = Fixture(testScheduler)
        val gate = CompletableDeferred<Unit>()
        val export = fixture.control { request -> gate.await(); fixture.response(request) }
        val preparing = async { export.prepare() }
        runCurrent()
        export.close()
        gate.complete(Unit)
        val result = preparing.await()
        assertEquals(ControlCode.CANCELLED, result.result.code)
        assertNull(result.fileName)
        assertEquals(1, fixture.closed)
    }

    private class Fixture(scheduler: TestCoroutineScheduler) {
        val dispatcher = StandardTestDispatcher(scheduler)
        var rules = RoutingRules(directDomainSuffixes = listOf("original.test"))
        var reads = 0
        var opened = 0
        var closed = 0
        var closeFailure = false
        fun response(request: ControlRequest): AndroidControlDocumentResponse {
            assertEquals(ControlOperationId.ROUTING_EXPORT, request.command.operation)
            assertEquals("owner", request.controllerId)
            val captured = rules
            return AndroidControlDocumentResponse(ControlResult("owner", request.requestId, ControlCode.OK, 7)) {
                RoutingRulesTransfer.writeExport(captured, "2026-09-07T00:00:00Z", it)
            }
        }
        fun control(read: suspend (ControlRequest) -> AndroidControlDocumentResponse = ::response) = AndroidRoutingExportControl(
            "owner", { request -> reads++; read(request) }, {
                opened++
                AndroidControlInputSpool(object : ControlTransferSpool {
                    val bytes = java.io.ByteArrayOutputStream()
                    override fun append(bytes: ByteArray) { check(bytes.size <= 65536); this.bytes.write(bytes) }
                    override fun read(offset: Long, length: Int) = bytes.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length)
                    override fun sha256() = error("unused")
                    override fun erase() { closed++; if (closeFailure) throw java.io.IOException("cleanup") }
                })
            }, dispatcher)
    }
}
