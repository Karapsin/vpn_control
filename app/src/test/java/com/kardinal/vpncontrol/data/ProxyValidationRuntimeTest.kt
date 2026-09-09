package com.kardinal.vpncontrol.data

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import android.content.Context
import android.content.ContextWrapper
import java.net.SocketTimeoutException
import java.net.ConnectException
import java.io.IOException
import java.io.InterruptedIOException
import javax.net.ssl.SSLException
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class ProxyValidationRuntimeTest {
    @Test fun requestFailureStillCollapsesWithoutSafeDiagnosticStage() {
        val stages = mutableListOf<String>()
        val runtime = ProxyValidationRuntime(
            context = object : ContextWrapper(null) { override fun getApplicationContext(): Context = this },
            browserUserAgent = "fixture",
            genericSecondaryBlockedMarkers = emptyList(),
            chatGptBlockedMarkers = emptyList(),
            reportStage = stages::add,
        )
        val result = runtime.runProxyRuns(24080, "https://private.invalid/", 1, ValidationRuntimeSettings()) {
                _, _, _ -> throw SocketTimeoutException("private target")
        }
        assertEquals(listOf("000"), result.codes)
        assertEquals(listOf("request_timeout"), stages)
    }

    @Test fun deadChildIsNotReportedAsGenericNotReady() {
        assertEquals("proxy_early_exit", validationReadinessStage(DeadProcess()))
    }

    @Test fun requestStagesAreFixedAndCancellationPropagates() {
        assertEquals("request_tls", validationRequestFailureStage(SSLException("private")))
        assertEquals("request_connect", validationRequestFailureStage(ConnectException("private")))
        assertEquals("request_timeout", validationRequestFailureStage(SocketTimeoutException("private")))
        assertEquals("request_interrupted", validationRequestFailureStage(InterruptedIOException("private")))
        assertEquals("request_io", validationRequestFailureStage(IOException("private")))
        assertEquals("request_error", validationRequestFailureStage(IllegalStateException("private")))
        assertEquals("http_non_success", validationHttpOutcomeStage("451"))
        assertEquals(null, validationHttpOutcomeStage("204"))

        val runtime = ProxyValidationRuntime(
            context = object : ContextWrapper(null) { override fun getApplicationContext(): Context = this },
            browserUserAgent = "fixture",
            genericSecondaryBlockedMarkers = emptyList(),
            chatGptBlockedMarkers = emptyList(),
            reportStage = { error("diagnostic must not receive cancellation") },
        )
        val result = runCatching {
            runtime.runProxyRuns(24080, "https://private.invalid/", 1, ValidationRuntimeSettings()) {
                    _, _, _ -> throw CancellationException("private")
            }
        }
        assertTrue(result.exceptionOrNull() is CancellationException)
    }

    private class DeadProcess : Process() {
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun getInputStream(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))
        override fun waitFor(): Int = 1
        override fun exitValue(): Int = 1
        override fun destroy() = Unit
        override fun isAlive(): Boolean = false
    }
}
