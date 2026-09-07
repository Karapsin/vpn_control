package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopAppChildProcessTest {
    @Test fun packagedOwnerAndFrontendLaunchDoNotInheritJpackageReentryMarker() {
        for (launcher in listOf("/opt/東京 space/bin/vpn-control", "C:\\Apps\\vpn-control.exe", "C:\\Apps\\vpn-control-cli.exe")) {
            for (arguments in listOf(listOf("--headless-controller"), listOf("--frontend-owner", "owner"))) {
                val command = listOf(launcher) + arguments
                val builder = desktopAppChildProcess(command,
                    mapOf("_JPACKAGE_LAUNCHER" to "0", "PATH" to "literal-path", "CUSTOM" to "literal value"))
                assertEquals(command, builder.command())
                assertEquals(mapOf("PATH" to "literal-path", "CUSTOM" to "literal value"), builder.environment())
            }
        }
    }
    @Test fun explicitJavaInvocationPreservesItsEnvironmentAndExactArguments() {
        val environment = mapOf("_JPACKAGE_LAUNCHER" to "0", "JAVA_TOOL_OPTIONS" to "literal options")
        for (java in listOf("/jdk/bin/java", "C:\\JDK\\java.exe", "C:\\JDK\\javaw.exe")) {
            val command = listOf(java, "-cp", "literal --headless-controller path", "Main", "--headless-controller")
            val builder = desktopAppChildProcess(command, environment)
            assertEquals(environment, builder.environment())
            assertEquals(command, builder.command())
        }
    }
}
