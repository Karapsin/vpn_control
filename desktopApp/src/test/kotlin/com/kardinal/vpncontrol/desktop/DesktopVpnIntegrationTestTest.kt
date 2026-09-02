package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

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
}
