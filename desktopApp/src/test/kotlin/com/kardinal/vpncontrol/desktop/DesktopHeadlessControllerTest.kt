package com.kardinal.vpncontrol.desktop

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopHeadlessControllerTest {
    @Test
    fun publicServeCommandSelectsLongLivedServiceMode() {
        assertEquals(
            HeadlessControllerMode.SERVICE,
            DesktopHeadlessController.modeForArgs(arrayOf("serve")),
        )
        assertEquals(
            HeadlessControllerMode.TRANSIENT,
            DesktopHeadlessController.modeForArgs(arrayOf("--headless-controller")),
        )
        assertEquals(null, DesktopHeadlessController.modeForArgs(arrayOf("serve", "extra")))
    }

    @Test
    fun nonLinuxHeadlessStartIsRejected() {
        val response = DesktopHeadlessController.startForCliCommand(
            command = DesktopCliCommand.On,
            osName = "Windows 11",
            currentCommand = "C:\\vpn-control.exe",
            requestCommand = { error("request should not be sent") },
            startProcess = { _, _ -> error("process should not start") },
        )

        assertEquals(false, response.success)
        assertEquals(DesktopCliResponse.UNAVAILABLE_EXIT_CODE, response.exitCode)
        assertTrue(response.message.contains("Linux only"))
    }

    @Test
    fun linuxHeadlessStartSpawnsControllerAndRetriesCommand() {
        var starts = 0
        var requests = 0
        var sleepCalls = 0

        val response = DesktopHeadlessController.startForCliCommand(
            command = DesktopCliCommand.On,
            osName = "Linux",
            currentCommand = "/opt/vpn-control/bin/vpn-control",
            requestCommand = {
                requests += 1
                if (requests == 1) {
                    DesktopCliResponse.notRunning()
                } else {
                    DesktopCliResponse.success("VPN started.")
                }
            },
            startProcess = { command, _: Path ->
                starts += 1
                assertEquals("/opt/vpn-control/bin/vpn-control", command)
                Result.success(FakeHeadlessProcess())
            },
            clockMillis = { requests * 100L },
            sleepMillis = { sleepCalls += 1 },
        )

        assertEquals(1, starts)
        assertEquals(2, requests)
        assertEquals(1, sleepCalls)
        assertEquals(DesktopCliResponse.success("VPN started."), response)
    }
}

private class FakeHeadlessProcess : Process() {
    override fun getOutputStream(): OutputStream = ByteArrayOutputStream()

    override fun getInputStream(): InputStream = ByteArrayInputStream(ByteArray(0))

    override fun getErrorStream(): InputStream = ByteArrayInputStream(ByteArray(0))

    override fun waitFor(): Int = 0

    override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = true

    override fun exitValue(): Int = 0

    override fun destroy() = Unit

    override fun isAlive(): Boolean = true
}
