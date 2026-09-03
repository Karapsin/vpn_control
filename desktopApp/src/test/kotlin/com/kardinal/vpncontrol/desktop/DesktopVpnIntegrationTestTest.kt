package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class DesktopVpnIntegrationTestTest {
    private val validArgs = arrayOf(
        DesktopVpnIntegrationTest.ARG,
        "--integration-socks-port", "18081",
        "--integration-target-url", "http://198.18.0.1/probe",
        "--integration-expected-body", "vpn-control-token",
        "--integration-state-dir", "/tmp/vpn-control-integration-test",
    )

    @Test
    fun probeRefusesToAlterRoutesWithoutExplicitDisposableRunnerOptIn() {
        val output = mutableListOf<String>()
        var executed = false

        val exit = DesktopVpnIntegrationTest.handleArgs(
            args = validArgs,
            getenv = { null },
            execute = {
                executed = true
                Result.success("unexpected")
            },
            printLine = output::add,
        )

        assertEquals(2, exit)
        assertEquals(false, executed)
        assertTrue(output.single().contains(DesktopVpnIntegrationTest.ALLOW_ENV))
    }

    @Test
    fun optedInProbePassesValidatedRequestToRuntime() {
        var captured: DesktopVpnIntegrationRequest? = null

        val exit = DesktopVpnIntegrationTest.handleArgs(
            args = validArgs,
            getenv = { "1" },
            execute = { request ->
                captured = request
                Result.success("passed")
            },
            printLine = {},
        )

        assertEquals(0, exit)
        val request = assertNotNull(captured)
        assertEquals(18081, request.socksPort)
        assertEquals("http://198.18.0.1/probe", request.targetUrl)
        assertEquals("vpn-control-token", request.expectedBody)
    }

    @Test
    fun malformedProbeArgumentsFailBeforeRuntimeStarts() {
        val exit = DesktopVpnIntegrationTest.handleArgs(
            args = arrayOf(DesktopVpnIntegrationTest.ARG, "--integration-socks-port", "0"),
            getenv = { "1" },
            execute = { error("must not execute") },
            printLine = {},
        )

        assertEquals(2, exit)
    }

    @Test
    fun disposableTunProbeExcludesItsLocalSocksFixtureFromTheTunRoute() {
        val config = DesktopProxyConfigFactory.buildVpnConfig(
            profile = testSocksProfile(),
            dns = com.kardinal.vpncontrol.model.DnsSettings(),
            routingRules = com.kardinal.vpncontrol.model.RoutingRules(ignoreRules = true),
        )
        val tunInbound = Json.parseToJsonElement(config).jsonObject
            .getValue("inbounds").jsonArray
            .first().jsonObject
        assertEquals(
            listOf(
                "127.0.0.0/8",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "1.1.1.1/32",
            ),
            tunInbound.getValue("route_exclude_address").jsonArray.map { it.jsonPrimitive.content },
        )
    }

    private fun testSocksProfile() = com.kardinal.vpncontrol.model.ProxyProfile(
        protocol = com.kardinal.vpncontrol.model.ProxyProtocol.SOCKS,
        remarks = "integration",
        server = "127.0.0.1",
        serverPort = 1080,
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
        rawLink = "socks://127.0.0.1:1080",
    )
}
