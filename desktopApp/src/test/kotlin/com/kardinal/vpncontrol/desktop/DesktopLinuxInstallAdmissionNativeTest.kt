package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Unprivileged disposable files only; no production gate, VPN, or package manager. */
class DesktopLinuxInstallAdmissionNativeTest {
    @Test fun nativeSharedFlockMatchesWorkerUtilityAndDoesNotLeakAcrossExec() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val directory = Files.createTempDirectory("vpn-linux-admission-")
        val gate = directory.resolve("gate")
        Files.write(gate, ByteArray(17))
        val native = JnaLinuxInstallAdmission()
        val fds = mutableListOf<Int>()
        var child: Process? = null
        try {
            var parent = native.openRoot().also { fds += it }
            for (part in directory) parent = native.openDirectory(parent, part.toString()).also { fds += it }
            val fd = requireNotNull(native.openOptionalGate(parent, "gate")).also { fds += it }
            assertTrue(native.lockSharedNonBlocking(fd))
            assertContentEquals(ByteArray(17), native.readGate(fd))
            assertEquals(1, exclusive(gate.toString()))
            child = ProcessBuilder("/bin/sleep", "10").start()
            native.close(fd); fds.remove(fd)
            assertTrue(child.isAlive)
            assertEquals(0, exclusive(gate.toString()))
        } finally {
            child?.destroy(); child?.waitFor(2, TimeUnit.SECONDS)
            fds.asReversed().forEach(native::close)
            Files.deleteIfExists(gate); Files.delete(directory)
        }
    }

    @Test fun nativeNoFollowNonBlockingOpenRejectsSymlinkAndDoesNotWaitForFifoWriter() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val directory = Files.createTempDirectory("vpn-linux-admission-fifo-")
        val fifo = directory.resolve("fifo")
        val link = directory.resolve("link")
        val native = JnaLinuxInstallAdmission()
        val fds = mutableListOf<Int>()
        try {
            val mkfifo = ProcessBuilder("/usr/bin/mkfifo", fifo.toString()).start()
            assertTrue(mkfifo.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, mkfifo.exitValue())
            Files.createSymbolicLink(link, fifo.fileName)
            var parent = native.openRoot().also { fds += it }
            for (part in directory) parent = native.openDirectory(parent, part.toString()).also { fds += it }
            assertFails { native.openOptionalGate(parent, "link") }
            val start = System.nanoTime()
            val fd = requireNotNull(native.openOptionalGate(parent, "fifo")).also { fds += it }
            assertTrue(System.nanoTime() - start < 1_000_000_000)
            assertEquals(0x1000, native.inspect(fd).mode and 0xf000)
        } finally {
            fds.asReversed().forEach(native::close)
            Files.deleteIfExists(link); Files.deleteIfExists(fifo); Files.delete(directory)
        }
    }

    private fun exclusive(path: String): Int {
        val process = ProcessBuilder("/usr/bin/flock", "-n", "-x", path, "/usr/bin/true").start()
        assertTrue(process.waitFor(5, TimeUnit.SECONDS))
        return process.exitValue()
    }
}
