package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopAdbProcessTest {
    @Test fun outputFloodAndBlockedStdinAreBoundedAndOnlyOwnedChildrenAreStopped() {
        val root = Files.createTempDirectory("adb-process-bounds")
        val executable = Path.of(System.getProperty("java.home"), "bin",
            if (System.getProperty("os.name").lowercase().contains("windows")) "java.exe" else "java")
        val classes = Path.of(FakeAdbMain::class.java.protectionDomain.codeSource.location.toURI())
        val classpath = classes.toString() + java.io.File.pathSeparator + requireNotNull(System.getProperty("vpnControl.test.mainClasspath"))
        try {
            for (mode in listOf("flood", "stall")) {
                Files.deleteIfExists(root.resolve("pid"))
                val runner = DesktopAdbProcess(listOf(executable.toString(), "-cp", classpath,
                    FakeAdbMain::class.java.name, root.toString(), mode))
                val started = System.nanoTime()
                assertFails { runner.execute(listOf("devices"), ByteArray(1_048_576), 2000) }
                assertTrue((System.nanoTime() - started) / 1_000_000 < 6000)
                if (Files.exists(root.resolve("pid"))) {
                    assertFalse(ProcessHandle.of(Files.readString(root.resolve("pid")).toLong()).map { it.isAlive }.orElse(false))
                }
            }
        } finally { root.toFile().deleteRecursively() }
    }
}
