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
    fun unknownPlatformHeadlessStartIsRejected() {
        val response = DesktopHeadlessController.startForCliCommand(
            command = DesktopCliCommand.On,
            osName = "Unknown OS",
            currentCommand = "C:\\vpn-control.exe",
            requestCommand = { error("request should not be sent") },
            startProcess = { _, _ -> error("process should not start") },
        )

        assertEquals(false, response.success)
        assertEquals(DesktopCliResponse.UNAVAILABLE_EXIT_CODE, response.exitCode)
        assertEquals("UNSUPPORTED", response.message)
    }

    @Test
    fun linuxHeadlessStartSpawnsControllerAndRetriesCommand() {
        var starts = 0
        var requests = 0
        var sleepCalls = 0

        val response = DesktopHeadlessController.startForCliCommand(
            command = DesktopCliCommand.On,
            workspaceDirectory = Path.of("東京 workspace"),
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
            startProcess = { command, log: Path ->
                starts += 1
                assertEquals(listOf("/opt/vpn-control/bin/vpn-control", "--headless-controller", "--state-dir", "東京 workspace"), command)
                assertEquals(Path.of("東京 workspace", "headless.log"), log)
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

    @Test
    fun windowsAndMacHeadlessStartupUseArgumentSafeLaunchers() {
        for ((os, launcher) in listOf(
            "Windows 11" to "C:\\Program Files\\VPN 東京\\vpn-control-cli.exe",
            "Mac OS X" to "/Applications/VPN 東京.app/Contents/MacOS/vpn-control",
            "Darwin" to "/Applications/VPN Control.app/Contents/MacOS/vpn-control",
        )) {
            val result = DesktopHeadlessController.startForCliCommand(
                command = DesktopCliCommand.SourceShow, osName = os,
                currentCommand = launcher, packagedLauncher = null,
                requestCommand = { DesktopCliResponse.success("ready") },
                startProcess = { command, _ ->
                    val ownerLauncher = if (os == "Windows 11") "C:\\Program Files\\VPN 東京\\vpn-control.exe" else launcher
                    assertEquals(listOf(ownerLauncher, DesktopHeadlessController.ARG), command)
                    Result.success(FakeHeadlessProcess())
                },
            )
            assertTrue(result.success)
        }
    }

    @Test
    fun developmentJavaLaunchIncludesClasspathAndMainClass() {
        assertEquals(listOf("C:\\Apps 東京\\vpn-control.exe", DesktopHeadlessController.ARG),
            DesktopHeadlessController.launchCommand(null, "C:\\Apps 東京\\vpn-control-cli.exe", ""))
        assertEquals(listOf("/JDK 東京/bin/java", "-Djava.awt.headless=true", "-cp", "classes:lib/a b.jar",
            "com.kardinal.vpncontrol.desktop.MainKt", DesktopHeadlessController.ARG),
            DesktopHeadlessController.launchCommand("/JDK 東京/bin/java", null, "classes:lib/a b.jar"))
        assertEquals(listOf("/App bundle/launcher", DesktopHeadlessController.ARG),
            DesktopHeadlessController.launchCommand("/jdk/bin/java", "/App bundle/launcher", ""))
        assertEquals(null, DesktopHeadlessController.launchCommand("java.exe", null, ""))
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
