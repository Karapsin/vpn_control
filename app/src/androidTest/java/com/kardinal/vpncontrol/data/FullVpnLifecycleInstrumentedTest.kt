package com.kardinal.vpncontrol.data

import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FullVpnLifecycleInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val appContext = instrumentation.targetContext

    @Test
    fun routesTcpTrafficThroughVpnAndStopsCleanly() = runBlocking {
        assumeTrue(
            "Full VPN integration is intentionally limited to a disposable emulator",
            InstrumentationRegistry.getArguments().getString("vpncontrol.fullVpn") == "1",
        )
        assertNull(
            "The disposable emulator must grant ACTIVATE_VPN before this test",
            VpnService.prepare(appContext),
        )
        val fixture = AndroidSocksHttpFixture(EXPECTED_BODY)
        fixture.start()
        try {
            val storage = ProfileStorage(appContext)
            val manager = VpnManager(appContext, storage)
            val profile = socksProfile(fixture.port)
            val config = SingBoxConfigFactory.buildTunConfig(
                profile = profile,
                dns = DnsSettings(),
                routingRules = RoutingRules(ignoreRules = true),
            )
            val selection = ProfileSelection(
                profile = profile,
                benchmark = ProfileBenchmark(
                    profile = profile,
                    primaryStatus = "manual",
                    secondaryStatus = "manual",
                    primaryTotal = null,
                    secondaryTotal = null,
                    score = Double.MAX_VALUE,
                    detail = "Disposable Android full-VPN fixture",
                ),
                runtimeConfigJson = config,
            )

            var started = false
            try {
                storage.updateAppMode(AppMode.VPN)
                manager.start(selection).getOrThrow()
                started = true

                val probeUid = executeShellCommand("id -u").trim().toInt()
                assertTrue(
                    "The TCP probe must run outside the VPN owner's excluded UID",
                    probeUid != Process.myUid(),
                )
                executeShellCommand(SHELL_TCP_PROBE)
                assertTrue(
                    "The shell TCP probe did not reach the disposable SOCKS fixture through the VPN",
                    fixture.awaitDestination(EXPECTED_DESTINATION, 5, TimeUnit.SECONDS),
                )
            } finally {
                if (started || storage.snapshot().isVpnRunning) {
                    manager.stop().getOrThrow()
                }
            }
            assertEquals(false, storage.snapshot().isVpnRunning)
        } finally {
            fixture.close()
        }
    }

    private fun executeShellCommand(command: String): String {
        val descriptor = instrumentation.uiAutomation.executeShellCommand(command)
        return ParcelFileDescriptor.AutoCloseInputStream(descriptor)
            .bufferedReader()
            .use { it.readText() }
    }

    private fun socksProfile(port: Int): ProxyProfile = ProxyProfile(
        protocol = ProxyProtocol.SOCKS,
        remarks = "Disposable Android integration fixture",
        server = "127.0.0.1",
        serverPort = port,
        network = "tcp",
        flow = "",
        security = "",
        sni = "",
        fingerprint = "",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "",
        rawLink = "socks://127.0.0.1:$port#DisposableAndroidIntegrationFixture",
    )

    private companion object {
        const val EXPECTED_BODY = "vpn-control-full-vpn-ok"
        const val EXPECTED_DESTINATION = "203.0.113.1:80"
        const val SHELL_TCP_PROBE = "toybox nc -4 -n -w 5 -z 203.0.113.1 80"
    }
}
