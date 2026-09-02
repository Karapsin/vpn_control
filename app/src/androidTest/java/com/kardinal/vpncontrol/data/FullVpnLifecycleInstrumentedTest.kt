package com.kardinal.vpncontrol.data

import android.net.VpnService
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import java.net.HttpURLConnection
import java.net.URI
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FullVpnLifecycleInstrumentedTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val appContext = instrumentation.targetContext

    @Test
    fun routesHttpTrafficThroughVpnAndStopsCleanly() = runBlocking {
        assumeTrue(
            "Full VPN integration is intentionally limited to a disposable emulator",
            InstrumentationRegistry.getArguments().getString("vpncontrol.fullVpn") == "1",
        )
        assertNull(
            "The disposable emulator must grant ACTIVATE_VPN before this test",
            VpnService.prepare(appContext),
        )
        val storage = ProfileStorage(appContext)
        val manager = VpnManager(appContext, storage)
        val profile = socksProfile()
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

            val connection = URI(TARGET_URL).toURL().openConnection() as HttpURLConnection
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            assertEquals(200, connection.responseCode)
            assertEquals(EXPECTED_BODY, connection.inputStream.bufferedReader().use { it.readText() })
        } finally {
            if (started || storage.snapshot().isVpnRunning) {
                manager.stop().getOrThrow()
            }
        }
        assertEquals(false, storage.snapshot().isVpnRunning)
    }

    private fun socksProfile(): ProxyProfile = ProxyProfile(
        protocol = ProxyProtocol.SOCKS,
        remarks = "Disposable Android integration fixture",
        server = "10.0.2.2",
        serverPort = FIXTURE_PORT,
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
        rawLink = "socks://10.0.2.2:$FIXTURE_PORT#DisposableAndroidIntegrationFixture",
    )

    private companion object {
        const val FIXTURE_PORT = 18081
        const val TARGET_URL = "http://198.18.0.1/probe"
        const val EXPECTED_BODY = "vpn-control-full-vpn-ok"
    }
}
