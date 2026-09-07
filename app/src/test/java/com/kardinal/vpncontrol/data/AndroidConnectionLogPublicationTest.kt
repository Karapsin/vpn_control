package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import java.io.IOException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidConnectionLogPublicationTest {
    private fun entry(id: String) = ConnectionLogEntry(id, "duplicate message", 1L)

    @Test fun everyDurableAppendIsDeliveredDespiteMultipleHistoryRolloversWithoutReads() = runTest {
        val publication = AndroidConnectionLogPublication()
        val delivered = mutableListOf<String>()
        publication.observe { delivered += it.last().id }
        var persisted = emptyList<ConnectionLogEntry>()
        repeat(601) { index -> publication.commit {
            (persisted + entry(index.toString())).takeLast(200).also { persisted = it }
        } }
        assertEquals((0..600).map(Int::toString), delivered)
        assertEquals(200, persisted.size)
    }

    @Test fun cancellationAfterDurableWriteCannotLosePublicationOrLetNextWritePass() = runTest {
        val publication = AndroidConnectionLogPublication()
        val durable = CompletableDeferred<Unit>()
        val response = CompletableDeferred<Unit>()
        val events = mutableListOf<String>()
        publication.observe { events += "publish-${it.single().id}" }
        val first = launch { publication.commit {
            events += "commit-a"
            durable.complete(Unit)
            response.await()
            listOf(entry("a"))
        } }
        durable.await()
        first.cancel()
        val second = async { publication.commit { events += "commit-b"; listOf(entry("b")) } }
        runCurrent()
        assertFalse(second.isCompleted)
        assertEquals(listOf("commit-a"), events)
        response.complete(Unit)
        first.join(); second.await()
        assertEquals(listOf("commit-a", "publish-a", "commit-b", "publish-b"), events)
    }

    @Test fun failedPersistenceNeverPublishesAndReleasesWriteSlot() = runTest {
        val publication = AndroidConnectionLogPublication()
        val delivered = mutableListOf<String>()
        publication.observe { delivered += it.single().id }
        assertTrue(runCatching { publication.commit { throw IOException("write rejected") } }.isFailure)
        publication.commit { listOf(entry("committed")) }
        assertEquals(listOf("committed"), delivered)
    }

    @Test fun writesStillCommitBeforeAnObserverIsAttached() = runTest {
        val publication = AndroidConnectionLogPublication()
        var writes = 0
        publication.commit { writes++; listOf(entry("early")) }
        assertEquals(1, writes)
    }
}
