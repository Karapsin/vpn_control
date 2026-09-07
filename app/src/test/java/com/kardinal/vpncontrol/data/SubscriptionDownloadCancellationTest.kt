package com.kardinal.vpncontrol.data

import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import okhttp3.*
import okio.Timeout
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SubscriptionDownloadCancellationTest {
    @Test fun cancellingFetchCancelsExactCallWithoutStartingFallbackOrNetwork() = runTest {
        var count = 0
        lateinit var call: FakeCall
        val client = SubscriptionDownloadClient("test", callFactory = { _, request -> count++; FakeCall(request).also { call = it } })
        val fetch = launch { client.fetch("https://fixture.invalid/subscription", "") }
        runCurrent()
        assertEquals(1, count)
        fetch.cancelAndJoin()
        assertTrue(call.cancelled)
        assertEquals(1, count)
    }
    private class FakeCall(private val original: Request) : Call {
        var cancelled = false
        override fun request() = original
        override fun execute(): Response = error("No synchronous network")
        override fun enqueue(responseCallback: Callback) {}
        override fun cancel() { cancelled = true }
        override fun isExecuted() = true
        override fun isCanceled() = cancelled
        override fun timeout() = Timeout.NONE
        override fun clone(): Call = FakeCall(original)
    }
}
