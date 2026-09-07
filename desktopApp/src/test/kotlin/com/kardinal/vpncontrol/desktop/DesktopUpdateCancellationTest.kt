package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.MainUiState
import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.util.Optional
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopUpdateCancellationTest {
    @Test
    fun cancellationClosesManifestBodyBeforeWaitingForItsReader() = runBlocking {
        val reading = CountDownLatch(1)
        val closed = CountDownLatch(1)
        val input = object : InputStream() {
            override fun read(): Int {
                reading.countDown()
                while (closed.count != 0L) {
                    try { closed.await() } catch (_: InterruptedException) { /* Close owns release. */ }
                }
                return -1
            }
            override fun close() { closed.countDown() }
        }
        val response = object : HttpResponse<InputStream> {
            override fun statusCode() = 200
            override fun request(): HttpRequest = HttpRequest.newBuilder(URI.create("http://127.0.0.1/manifest")).GET().build()
            override fun previousResponse(): Optional<HttpResponse<InputStream>> = Optional.empty()
            override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
            override fun body(): InputStream = input
            override fun sslSession() = Optional.empty<javax.net.ssl.SSLSession>()
            override fun uri(): URI = URI.create("http://127.0.0.1/manifest")
            override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1
        }
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val action = owner.launch { readDesktopUpdateManifest(CompletableFuture.completedFuture(response)) }
        try {
            assertTrue(reading.await(5, TimeUnit.SECONDS), "Manifest body reader never started")
            action.cancel()
            assertTrue(withTimeoutOrNull(2_000) { action.join(); true } ?: false,
                "Cancellation must close the body before waiting for an interruption-resistant reader")
            assertEquals(0L, closed.count)
        } finally {
            input.close()
            action.join()
            owner.cancel()
        }
    }

    @Test
    fun completedResponseWithoutGetHandoffIsClosedDuringCancellation() {
        class TrackingInput : ByteArrayInputStream(byteArrayOf('{'.code.toByte())) {
            var closed = false
            override fun close() { closed = true; super.close() }
        }
        val input = TrackingInput()
        val response = object : HttpResponse<InputStream> {
            override fun statusCode() = 200
            override fun request(): HttpRequest = HttpRequest.newBuilder(URI.create("http://127.0.0.1/manifest")).GET().build()
            override fun previousResponse(): Optional<HttpResponse<InputStream>> = Optional.empty()
            override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
            override fun body(): InputStream = input
            override fun sslSession() = Optional.empty<javax.net.ssl.SSLSession>()
            override fun uri(): URI = URI.create("http://127.0.0.1/manifest")
            override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1
        }
        val future = CompletableFuture<HttpResponse<InputStream>>()
        val lease = DesktopUpdateResponseLease(future)
        future.complete(response)
        lease.close()
        assertTrue(input.closed)
    }

    @Test
    fun responseLeaseCancelsFutureWhenBodyCloseFails() {
        class ClosingFailureInput : InputStream() {
            override fun read() = -1
            override fun close() { throw IOException("synthetic close failure") }
        }
        class TrackingFuture<T> : CompletableFuture<T>() {
            var cancellationCalls = 0
            override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
                cancellationCalls++
                return super.cancel(mayInterruptIfRunning)
            }
        }
        val input = ClosingFailureInput()
        val response = object : HttpResponse<InputStream> {
            override fun statusCode() = 200
            override fun request(): HttpRequest = HttpRequest.newBuilder(URI.create("http://127.0.0.1/manifest")).GET().build()
            override fun previousResponse(): Optional<HttpResponse<InputStream>> = Optional.empty()
            override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
            override fun body(): InputStream = input
            override fun sslSession() = Optional.empty<javax.net.ssl.SSLSession>()
            override fun uri(): URI = URI.create("http://127.0.0.1/manifest")
            override fun version(): HttpClient.Version = HttpClient.Version.HTTP_1_1
        }
        val future = TrackingFuture<HttpResponse<InputStream>>()
        val lease = DesktopUpdateResponseLease(future)
        future.complete(response)
        assertFailsWith<IOException> { lease.close() }
        assertEquals(1, future.cancellationCalls)
    }

    @Test
    fun manifestHttpFailureCompletesWithoutLeavingUpdateStateActive() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-update-http-error")
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/manifest") { exchange ->
            exchange.sendResponseHeaders(503, -1)
            exchange.close()
        }
        server.start()
        var state = MainUiState(isVpnRunning = true)
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            manifestUrl = "http://127.0.0.1:${server.address.port}/manifest", trustUrl = { true })
        try {
            assertTrue(service.check().isFailure)
            assertEquals(AppUpdatePhase.FAILED, state.appUpdate.phase)
            assertTrue(state.isVpnRunning)
        } finally {
            server.stop(0)
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun stalledPackageCancellationClosesAndRemovesPartialBeforeCompleting() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-download-cancel")
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        server.createContext("/manifest") { exchange ->
            val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2",
                "releaseNotesUrl":"$base/notes","assets":[{"platform":"macos","architecture":"arm64",
                "packageType":"dmg","displayVersion":"1.0.2","fileName":"test.dmg",
                "downloadUrl":"$base/package","sha256":"${"0".repeat(64)}","sizeBytes":10000}]}""".toByteArray()
            exchange.sendResponseHeaders(200, manifest.size.toLong())
            exchange.responseBody.use { it.write(manifest) }
        }
        server.createContext("/package") { exchange ->
            try {
                exchange.sendResponseHeaders(200, 10_000)
                exchange.responseBody.write(1)
                exchange.responseBody.flush()
                started.countDown()
                release.await(15, TimeUnit.SECONDS)
            } finally { exchange.close() }
        }
        server.start()
        val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        var state = MainUiState(isVpnRunning = true)
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            buildInfo = DesktopBuildInfo(1, "1.0.1"), osName = "macOS", osArchitecture = "arm64",
            manifestUrl = "$base/manifest", trustUrl = { it.startsWith("$base/") })
        try {
            assertTrue(service.check().getOrThrow().updateAvailable)
            val action = owner.launch { service.downloadChecked() }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            action.cancel()
            assertTrue(withTimeoutOrNull(2_000) { action.join(); true } ?: false)
            assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase)
            assertEquals(null, state.appUpdate.preparedAsset)
            assertFalse(Files.exists(directory.resolve("test.dmg.part")))
            assertFalse(Files.exists(directory.resolve("test.dmg")))
            assertTrue(state.isVpnRunning)
            assertTrue(service.dismiss().isSuccess)
        } finally {
            release.countDown()
            server.stop(0)
            owner.cancel()
            owner.coroutineContext[kotlinx.coroutines.Job]?.join()
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun cancelledManifestCheckStopsWhileHeadersOrBodyAreStalled() = runBlocking {
        for (sendHeaders in listOf(false, true)) {
            val directory = Files.createTempDirectory("vpn-control-update-cancel")
            val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
            val started = CountDownLatch(1)
            val release = CountDownLatch(1)
            server.createContext("/manifest") { exchange ->
                try {
                    if (sendHeaders) {
                        exchange.sendResponseHeaders(200, 10_000)
                        exchange.responseBody.write('{'.code)
                        exchange.responseBody.flush()
                    }
                    started.countDown()
                    release.await(15, TimeUnit.SECONDS)
                } finally { exchange.close() }
            }
            server.start()
            val owner = CoroutineScope(SupervisorJob() + Dispatchers.Default)
            var state = MainUiState(isVpnRunning = true)
            val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
                manifestUrl = "http://127.0.0.1:${server.address.port}/manifest", trustUrl = { true })
            val action = owner.launch { service.check() }
            var stoppedPromptly = false
            try {
                assertTrue(started.await(5, TimeUnit.SECONDS),
                    "Manifest request did not reach the stalled ${if (sendHeaders) "body" else "headers"}; " +
                        "actionCompleted=${action.isCompleted}, updatePhase=${state.appUpdate.phase}")
                action.cancel()
                stoppedPromptly = withTimeoutOrNull(2_000) { action.join(); true } ?: false
            } finally {
                release.countDown()
                server.stop(0)
                action.join()
                owner.cancel()
                directory.toFile().deleteRecursively()
            }
            assertTrue(stoppedPromptly, "Cancellation waited for stalled HTTP ${if (sendHeaders) "body" else "headers"}")
            assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase)
            assertTrue(state.isVpnRunning)
        }
    }
}
