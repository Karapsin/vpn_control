package com.kardinal.vpncontrol.data

import kotlinx.coroutines.test.runTest
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SubscriptionDownloadDiagnosticsTest {
    @Test fun unsuccessfulResponseUsesMessageFreeTypedStatusForSafeDiagnostics() = runTest {
        val diagnostics = mutableListOf<String>()
        val client = SubscriptionDownloadClient(
            userAgent = "test",
            callFactory = { _, request -> StatusCall(request, 503, "private upstream hostname") },
            diagnosticsLogger = diagnostics::add,
        )

        val failure = runCatching { client.fetch("https://fixture.example.test/subscription", "") }.exceptionOrNull()

        assertTrue(failure is SubscriptionHttpStatusException)
        assertEquals(503, (failure as SubscriptionHttpStatusException).statusCode)
        assertNull(failure?.message)
        assertEquals(1, diagnostics.size)
        assertTrue(diagnostics.single().contains("http_status=503"))
        assertFalse(diagnostics.single().contains("private upstream hostname"))
    }

    @Test fun directFailureEmitsOnlyCategoricalRouteAndRedactedFailureTrace() = runTest {
        val privateUrl = "https://user:password@private.example.test/subscription?token=secret"
        val diagnostics = mutableListOf<String>()
        val client = SubscriptionDownloadClient(
            userAgent = "test",
            callFactory = { _, request -> FailedCall(request, java.net.UnknownHostException(privateUrl)) },
            diagnosticsLogger = diagnostics::add,
        )

        runCatching { client.fetch(privateUrl, "") }

        assertEquals(1, diagnostics.size)
        val diagnostic = diagnostics.single()
        assertTrue(diagnostic.contains("route=direct"))
        assertTrue(diagnostic.contains("proxy_mode=system-default"))
        assertTrue(diagnostic.contains("stage=subscription-refresh.download"))
        assertTrue(diagnostic.contains(java.net.UnknownHostException::class.java.name))
        listOf(privateUrl, "user", "password", "private.example.test", "token=secret").forEach {
            assertFalse(diagnostic.contains(it))
        }
    }

    @Test fun diagnosticsWriteFailureDoesNotReplaceTheTransportFailure() = runTest {
        val client = SubscriptionDownloadClient(
            userAgent = "test",
            callFactory = { _, request -> FailedCall(request, java.net.UnknownHostException("private.example.test")) },
            diagnosticsLogger = { error("diagnostics storage unavailable") },
        )

        val failure = runCatching { client.fetch("https://fixture.example.test/subscription", "") }.exceptionOrNull()

        assertTrue(failure is java.net.UnknownHostException)
    }

    @Test fun cyclicFailureCauseDoesNotBlockDiagnosticsOrReplaceTransportFailure() = runTest {
        val first = java.io.IOException("private-first")
        val second = java.io.IOException("private-second")
        first.initCause(second)
        second.initCause(first)
        val diagnostics = mutableListOf<String>()
        val client = SubscriptionDownloadClient(
            userAgent = "test",
            callFactory = { _, request -> FailedCall(request, first) },
            diagnosticsLogger = diagnostics::add,
        )

        val failure = runCatching { client.fetch("https://fixture.example.test/subscription", "") }.exceptionOrNull()

        assertEquals(java.io.IOException::class.java, failure?.javaClass)
        assertEquals(1, diagnostics.size)
        assertTrue(diagnostics.single().contains("cause_cycle"))
        assertFalse(diagnostics.single().contains("private-first"))
        assertFalse(diagnostics.single().contains("private-second"))
    }

    private class StatusCall(
        private val original: Request,
        private val code: Int,
        private val message: String,
    ) : Call {
        override fun request(): Request = original
        override fun execute(): Response = error("No synchronous network")
        override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(
            this,
            Response.Builder()
                .request(original)
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message(message)
                .build(),
        )
        override fun cancel() = Unit
        override fun isExecuted(): Boolean = true
        override fun isCanceled(): Boolean = false
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = StatusCall(original, code, message)
    }

    private class FailedCall(
        private val original: Request,
        private val failure: java.io.IOException,
    ) : Call {
        override fun request(): Request = original
        override fun execute(): Response = error("No synchronous network")
        override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, failure)
        override fun cancel() = Unit
        override fun isExecuted(): Boolean = true
        override fun isCanceled(): Boolean = false
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = FailedCall(original, failure)
    }
}
