package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopDirectProbeRoutingTest {
    @Test
    fun forValidationDirectoryAddsStableProbeProcessPath() {
        val validationDir = Files.createTempDirectory("vpn-control-probe-routing")
        try {
            val currentCommand = validationDir.resolve("vpn-control").toString()
            val routing = DesktopDirectProbeRouting.forValidationDirectory(
                validationDirectory = validationDir,
                currentProcessCommand = currentCommand,
                osName = "Linux",
            )

            assertTrue(routing.processNames.contains("vpn-control-probe-sing-box"))
            assertTrue(
                routing.processPaths.contains(
                    validationDir.resolve("vpn-control-probe-sing-box")
                        .toAbsolutePath()
                        .normalize()
                        .toString(),
                ),
            )
            assertEquals(1, routing.processPaths.size)
        } finally {
            validationDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun prepareDirectProbeSingBoxExecutableCopiesToUniqueProbeName() {
        val validationDir = Files.createTempDirectory("vpn-control-probe-copy")
        try {
            val source = Files.createTempFile(validationDir, "sing-box-source", "")
            Files.writeString(source, "test binary")

            val probe = prepareDirectProbeSingBoxExecutable(
                source = source,
                validationDirectory = validationDir,
                osName = "Linux",
            )

            assertEquals("vpn-control-probe-sing-box", probe.fileName.toString())
            assertEquals("test binary", Files.readString(probe))
            assertTrue(Files.isExecutable(probe))
        } finally {
            validationDir.toFile().deleteRecursively()
        }
    }
}
