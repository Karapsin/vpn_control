package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.control.ControlOperationLedger
import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.kardinal.vpncontrol.model.*
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.file.Files
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test

class AndroidRetainedControlResultsTest {
    @Test fun diskSnapshotPreservesEveryValueAndResultIdentityAfterOriginalListChanges() {
        val spool = Spool()
        val source = values().toMutableList()
        val original = result(source)
        AndroidRetainedControlResults { spool }.use { store ->
            val retained = store.retain(original)
            assertNotSame(original.data["direct-domains"], retained.data["direct-domains"])
            assertEquals(original, retained)
            val expected = (source.last() as ControlValue.Text).value
            source[0] = ControlValue.Text("changed")
            source[source.lastIndex] = ControlValue.Text("changed")
            assertEquals(text(0), (domains(retained).first() as ControlValue.Text).value)
            assertEquals(expected, (domains(retained).last() as ControlValue.Text).value)
            assertSame(retained, store.retain(retained))
            val encoded = buildString { ControlDocumentCodec.writeResult(retained, this) }
            val decoded = ControlDocumentCodec.decodeResult(encoded)
            assertEquals(retained, decoded)
            assertEquals("original-operation", decoded.operationId)
            assertEquals("original-request", decoded.requestId)
            assertEquals(7L, decoded.configurationRevision)
        }
        assertEquals(1, spool.erases)
    }

    @Test fun failedSpoolingKeepsKnownSuccessExactDataAndSmallFailureMetadata() {
        for (failure in listOf(IOException("synthetic private storage failure"), OutOfMemoryError("synthetic pressure"))) {
            val spool = Spool(appendFailure = failure)
            val original = result(values())
            AndroidRetainedControlResults { spool }.use { store ->
                val retained = store.retain(original)
                assertEquals(ControlCode.OK, retained.code)
                assertSame(original.data, retained.data)
                assertEquals(original.configurationRevision, retained.configurationRevision)
                assertEquals(original.operationId, retained.operationId)
                assertEquals(original.requestId, retained.requestId)
                assertTrue("RETAINED_RESULT_STORAGE_UNAVAILABLE" in retained.warnings)
                assertEquals(failure is OutOfMemoryError, "RESOURCE_EXHAUSTED" in retained.warnings)
                assertEquals(1, spool.erases)
            }
        }
    }

    @Test fun corruptedIndexValueHashAndReadFailureNeverReturnFabricatedResultValues() {
        // Index location, UTF16 count, digest and body are independently checked.
        for (position in listOf(0, 8, 12, 44 * 400)) {
            val spool = Spool()
            AndroidRetainedControlResults { spool }.use { store ->
                val retained = store.retain(result(values()))
                spool.corrupt(position)
                assertTrue(runCatching { domains(retained)[0] }.exceptionOrNull() is IOException)
                assertEquals(ControlCode.OK, retained.code)
                assertEquals(7L, retained.configurationRevision)
            }
        }
        val spool = Spool()
        AndroidRetainedControlResults { spool }.use { store ->
            val retained = store.retain(result(values()))
            val failure = IOException("synthetic retained read failure")
            spool.readFailure = failure
            assertSame(failure, runCatching { domains(retained)[0] }.exceptionOrNull())
            assertEquals("original-operation", retained.operationId)
        }
    }

    @Test fun ledgerExpiryDoesNotInvalidateAnOutstandingReader() {
        val spool = Spool()
        AndroidRetainedControlResults { spool }.use { store ->
            val retained = store.retain(result(values()))
            val ledger = ControlOperationLedger("owner", completedCapacity = 1, retentionMillis = 10)
            ledger.admit("original-operation", "original-request", ControlOperationId.ROUTING_IMPORT,
                "fingerprint", mutates = true, cancellable = false, now = 0)
            ledger.complete("original-operation", retained, 0)
            val reader = requireNotNull(ledger.get("original-operation", 0)?.result)
            assertNull(ledger.get("original-operation", 10))
            store.reap()
            assertEquals(0, spool.erases)
            assertEquals(text(0), (domains(reader).first() as ControlValue.Text).value)
            assertEquals(text(399), (domains(reader).last() as ControlValue.Text).value)
        }
        assertEquals(1, spool.erases)
    }

    @Test fun ownerShutdownClosesBackingOnceAndExplicitlyInvalidatesRemainingReaders() {
        val directory = Files.createTempDirectory("retained-result-lifetime-")
        try {
            val store = AndroidRetainedControlResults { AndroidControlTransferSpool.create(directory) }
            val retained = store.retain(result(values()))
            assertEquals(0L, Files.list(directory).use { it.count() })
            assertEquals(text(0), (domains(retained)[0] as ControlValue.Text).value)
            store.close(); store.close()
            assertTrue(runCatching { domains(retained)[0] }.exceptionOrNull() is IOException)
            val later = store.retain(result(values()))
            assertEquals(ControlCode.OK, later.code)
            assertTrue("RETAINED_RESULT_STORAGE_UNAVAILABLE" in later.warnings)
            assertEquals(0L, Files.list(directory).use { it.count() })
        } finally { Files.delete(directory) }
    }

    @Test fun applicationScopeShutdownClosesResultsAfterOwnedWorkCompletes() = runBlocking {
        val job = SupervisorJob()
        val scope = CoroutineScope(job + Dispatchers.Default)
        val spool = Spool()
        val retainedStore = AndroidRetainedControlResults { spool }
        val retained = retainedStore.retain(result(values()))
        AndroidSettingsControl("owner", scope, { com.kardinal.vpncontrol.control.ControlCommitted("owner", 0, PersistedState()) },
            { _, _, _ -> error("not a mutation") }, {}, { false }, retainedResults = retainedStore)
        job.cancelAndJoin()
        assertEquals(1, spool.erases)
        assertTrue(runCatching { domains(retained)[0] }.exceptionOrNull() is IOException)
    }

    @Test fun smallResultsKeepTheirOriginalRepresentation() {
        AndroidRetainedControlResults { error("Small results must not open a spool") }.use { store ->
            val original = result(listOf(ControlValue.Text("small.test")))
            assertSame(original, store.retain(original))
            val empty = original.copy(data = emptyMap())
            assertSame(empty, store.retain(empty))
        }
    }

    @Test fun changingCaptureInputCannotPublishAnUnverifiableHistoricalResult() {
        val source = values().toMutableList()
        var changed = false
        val spool = Spool(beforeAppend = {
            if (!changed) { source[source.lastIndex] = ControlValue.Text("z".repeat(text(399).length)); changed = true }
        })
        AndroidRetainedControlResults { spool }.use { store ->
            val retained = store.retain(result(source))
            assertEquals(ControlCode.OK, retained.code)
            assertTrue("RETAINED_RESULT_STORAGE_UNAVAILABLE" in retained.warnings)
            assertEquals(1, spool.erases)
        }
    }

    @Test fun failedPartialSpoolCleanupRemainsOwnedForShutdownRetry() {
        var closes = 0
        val spool = object : ControlTransferSpool {
            override fun append(bytes: ByteArray): Unit = throw IOException("synthetic write failure")
            override fun read(offset: Long, length: Int): ByteArray = error("not readable")
            override fun sha256(): String = error("not readable")
            override fun erase() { if (closes++ == 0) throw IOException("synthetic close failure") }
        }
        val store = AndroidRetainedControlResults { spool }
        assertTrue("RETAINED_RESULT_STORAGE_UNAVAILABLE" in store.retain(result(values())).warnings)
        assertEquals(1, closes)
        store.close()
        assertEquals(2, closes)
    }

    private class Spool(private val appendFailure: Throwable? = null,
        private val beforeAppend: () -> Unit = {}) : ControlTransferSpool {
        private val bytes = ByteArrayOutputStream()
        var erases = 0
        var readFailure: Throwable? = null
        private var corruption: Int? = null
        fun corrupt(index: Int) { corruption = index }
        override fun append(bytes: ByteArray) {
            appendFailure?.let { throw it }
            beforeAppend()
            this.bytes.write(bytes)
        }
        override fun read(offset: Long, length: Int): ByteArray {
            readFailure?.let { throw it }
            check(erases == 0)
            return bytes.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length).also { output ->
                corruption?.let { if (it >= offset && it < offset + length) output[(it - offset).toInt()] =
                    (output[(it - offset).toInt()].toInt() xor 128).toByte() }
            }
        }
        override fun sha256(): String = error("Retained values use indexed record verification")
        override fun erase() { erases++; bytes.reset() }
    }

    companion object {
        private fun text(index: Int) = "$index-" + "a".repeat(90) + "\u0000\uD800x\uDC00\n"
        private fun values() = List(400) { ControlValue.Text(text(it)) }
        private fun domains(result: ControlResult) = (result.data.getValue("direct-domains") as ControlValue.ArrayValue).values
        private fun result(values: List<ControlValue>) = ControlResult("owner", "original-request", ControlCode.OK,
            7, operationId = "original-operation", restartRequired = true,
            data = mapOf("direct-domains" to ControlValue.ArrayValue(values), "ignore-rules" to ControlValue.BooleanValue(false)),
            warnings = listOf("existing-warning"))
    }
}
