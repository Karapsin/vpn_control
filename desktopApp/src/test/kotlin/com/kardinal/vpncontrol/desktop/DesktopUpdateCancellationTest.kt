package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.MainUiState
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.file.Files
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
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopUpdateCancellationTest {
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
                assertTrue(started.await(5, TimeUnit.SECONDS))
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
