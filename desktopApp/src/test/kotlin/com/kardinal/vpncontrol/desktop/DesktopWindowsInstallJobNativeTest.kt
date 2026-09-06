package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Real Win32 IO with the inherited token (standard or elevated CI); never requests elevation.
 * The test-only policy trusts ONLY explicitly current-SID-owned temporary objects. Elevated
 * execution is not evidence for standard-user access; both environments run these same assertions.
 */
class DesktopWindowsInstallJobNativeTest {
    @Test fun currentUserUnicodeHandlesReplaceBoundedReadAndCancellation() = fixture { native, policy, temp ->
        assertTrue(native.programData().matches(Regex("^[A-Za-z]:\\\\.+"))) // actual SHGetKnownFolderPath marshaling
        val backend = DesktopWindowsInstallJobBackend(policy)
        assertFailsWith<IllegalArgumentException> { DesktopWindowsInstallJobBackend(native).openRoot(backend.defaultRoot(), false) }
        val root = backend.openRoot(backend.defaultRoot(), true)
        val jobId = UUID.randomUUID().toString()
        val job = root.createJob(jobId)
        val jobPath = backend.defaultRoot().resolve(jobId)
        try {
            val tempName = "status-${UUID.randomUUID()}.tmp"
            job.createFile(tempName, DesktopInstallJobBackend.Purpose.STATUS_TEMP).use { it.writeExact("{\"unicode\":\"東京\"}".toByteArray()) }
            job.replaceFile(tempName, "status.json")
            job.openFile("status.json").use { file ->
                assertTrue(file.readBounded(1024).toString(Charsets.UTF_8).contains("東京"))
                assertFailsWith<IllegalArgumentException> { file.readBounded(1) }
            }
            val second = "status-${UUID.randomUUID()}.tmp"
            job.createFile(second, DesktopInstallJobBackend.Purpose.STATUS_TEMP).use { it.writeExact("{}".toByteArray()) }
            job.replaceFile(second, "status.json")
            job.openFile("status.json").use { assertContentEquals("{}".toByteArray(), it.readBounded(2)) }
            val cancel = job.createFile("cancel", DesktopInstallJobBackend.Purpose.CANCEL)
            try {
                cancel.writeExact(byteArrayOf(0))
                job.openFile("cancel", true).use { it.writeExact(byteArrayOf(1)) }
                assertContentEquals(byteArrayOf(1), cancel.readBounded(1))
                assertFails { Files.move(jobPath, temp.resolve("renamed")) }
                assertFails { Files.delete(jobPath.resolve("cancel")) }
                root.close(); job.close()
                assertFails { Files.move(jobPath, temp.resolve("renamed")) }
                assertContentEquals(byteArrayOf(1), cancel.readBounded(1))
            } finally { cancel.close() }
            // The raw user-owned descriptor remains unacceptable to the production trust policy.
            val handle = native.open(jobPath.resolve("cancel").toString(), WindowsInstallNative.READ, false)
            try {
                val actual = native.inspect(handle)
                assertEquals(policy.sid, actual.owner, "Fixture must be explicitly user-owned, including on elevated CI")
                assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(actual, WindowsInstallTrust.Kind.CANCEL) }
            }
            finally { native.close(handle) }
        } finally { job.close(); root.close() }
    }

    @Test fun actualJunctionIsRejectedWithoutFollowingItsTarget() = fixture { _, policy, temp ->
        val backend = DesktopWindowsInstallJobBackend(policy)
        backend.openRoot(backend.defaultRoot(), true).use { root ->
            val target = Files.createDirectory(temp.resolve("junction-target"))
            val id = UUID.randomUUID().toString()
            val link = backend.defaultRoot().resolve(id)
            val process = ProcessBuilder("cmd.exe", "/d", "/c", "mklink", "/J", link.toString(), target.toString()).redirectErrorStream(true).start()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "junction command timed out")
            assertEquals(0, process.exitValue(), process.inputStream.bufferedReader().readText())
            try { assertFailsWith<IllegalArgumentException> { root.openJob(id) } }
            finally { Files.delete(link) } // delete the junction itself, never recursively follow it
            assertTrue(Files.isDirectory(target))
        }
    }

    private fun fixture(action: (JnaWindowsInstallNative, UserOwnedTestPolicy, Path) -> Unit) {
        assumeTrue("Windows native execution only", Platform.isWindows())
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        val sid = try {
            val elevation = WinNT.TOKEN_ELEVATION()
            check(Advapi32.INSTANCE.GetTokenInformation(token.value, 20, elevation, elevation.size(), IntByReference()))
            check(elevation.TokenIsElevated in 0..1) { "Invalid token elevation information" }
            Advapi32Util.getTokenAccount(token.value).sidString
        } finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        val temp = Files.createTempDirectory("vpn-control-native-東京 space-")
        val native = JnaWindowsInstallNative()
        try { action(native, UserOwnedTestPolicy(native, sid, temp), temp) }
        finally { Files.walk(temp).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    /** Only tests replace the SYSTEM/Admin policy; native APIs, sharing and reparse metadata remain genuine. */
    private class UserOwnedTestPolicy(val delegate: JnaWindowsInstallNative, val sid: String, val temp: Path) : WindowsInstallNative by delegate {
        override fun programData() = temp.toString()
        private fun scoped(path: String) { require(Path.of(path).normalize().startsWith(temp)) }
        private fun sddl() = "O:${sid}G:${sid}D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) {
            scoped(path); delegate.createDirectory(path, sddl(), allowExisting)
        }
        override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?): WindowsInstallNative.Handle {
            if (access != WindowsInstallNative.INSPECT) scoped(path)
            return delegate.open(path, access, shareDelete, createSddl?.let { sddl() })
        }
        override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
            val actual = delegate.inspect(handle)
            // The production default is unchanged and independently asserted to reject these objects.
            return actual.copy(owner = if (actual.owner == sid) "S-1-5-32-544" else actual.owner,
                dacl = actual.dacl?.map { if (it.sid == sid) it.copy(sid = "S-1-5-32-544") else it })
        }
    }
}
