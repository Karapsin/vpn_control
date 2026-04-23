package com.kardinal.vpncontrol.data

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class LocalProtocolSmokeInstrumentedTest {
    private val appContext = InstrumentationRegistry.getInstrumentation().targetContext
    private val storage = ProfileStorage(appContext)
    private val orchestrator = BenchmarkOrchestrator(appContext, storage)

    @Before
    fun prepareValidationSettings() = runBlocking {
        storage.updateValidationSettings(
            BenchmarkValidationSettings(
                primaryUrl = "https://www.google.com/generate_204",
                secondaryUrl = "https://example.com/",
                batchSize = 1,
                retryCount = 0,
            ),
        )
    }

    @Test
    fun benchmarksLocalSocksServer() = runSmoke(
        link = "socks://alice:secretpass@10.0.2.2:18081#SOCKS%20Local",
        port = 18081,
    )

    @Test
    fun benchmarksLocalShadowsocksServer() = runSmoke(
        link = "ss://YWVzLTEyOC1nY206c3Mtc2VjcmV0LTEyMw==@10.0.2.2:18082#Shadowsocks%20Local",
        port = 18082,
    )

    @Test
    fun benchmarksLocalTrojanServer() {
        assumeTrue(
            "Local Trojan smoke requires a trusted TLS fixture; enable explicitly when one is configured",
            InstrumentationRegistry.getArguments().getString("vpncontrol.trojan.smoke") == "1",
        )
        runSmoke(
            link = "trojan://trojan-secret-123@10.0.2.2:18084#Trojan%20Local",
            port = 18084,
        )
    }

    @Test
    fun benchmarksLocalVmessServer() = runSmoke(
        link = "vmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MgTG9jYWwiLCJhZGQiOiIxMC4wLjIuMiIsInBvcnQiOiIxODA4MyIsImlkIjoiYjgzMTM4MWQtNjMyNC00ZDUzLWFkNGYtOGNkYTQ4YjMwODExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0=",
        port = 18083,
    )

    private fun runSmoke(link: String, port: Int) = runBlocking {
        assumeTrue(
            "Live protocol smoke requires a bundled sing-box binary for this ABI",
            hasBundledSingBoxBinary(),
        )
        assumeTrue(
            "Local smoke fixture on 10.0.2.2:$port is not running",
            isServerReachable(port),
        )

        val benchmark = orchestrator.benchmarkLocation(link).getOrThrow()

        assertEquals("ok", benchmark.primaryStatus)
        assertEquals("ok", benchmark.secondaryStatus)
    }

    private fun isServerReachable(port: Int): Boolean {
        return runCatching {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("10.0.2.2", port), 3_000)
            }
        }.isSuccess
    }

    private fun hasBundledSingBoxBinary(): Boolean {
        return appContext.applicationInfo.nativeLibraryDir
            ?.let { java.io.File(it, "libsing-box.so") }
            ?.exists()
            ?: false
    }
}
