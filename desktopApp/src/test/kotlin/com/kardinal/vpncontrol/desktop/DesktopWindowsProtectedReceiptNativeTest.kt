package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import org.junit.Assume.assumeTrue
import java.util.UUID
import kotlin.test.*

/** Opt-in only: root sets up this protected fixture in an owned disposable Windows VM. */
class DesktopWindowsProtectedReceiptNativeTest {
    @Test fun productionDefaultRootReadsProtectedReceiptWithRetainedAncestors() {
        val (jobId, elevated) = fixture()
        val backend = DesktopWindowsInstallJobBackend()
        val root = backend.openRoot(backend.defaultRoot(), false)
        val job = try { root.openJob(jobId) } catch (failure: Throwable) { root.close(); throw failure }
        try {
            if (!elevated) {
                assertFails { job.openFile("status.json", write = true) }
                assertFails { job.createFile("status-${UUID.randomUUID()}.tmp", DesktopInstallJobBackend.Purpose.STATUS_TEMP) }
            }
            job.openFile("status.json").use { receipt ->
                root.close(); job.close()
                assertTrue(receipt.readBounded(128).toString(Charsets.UTF_8) in RECEIPTS)
            }
        } finally { job.close(); root.close() }
    }

    @Test fun elevatedProtectedReceiptReplacementKeepsOldReaderAndStrictParentPins() {
        val (jobId, elevated) = fixture()
        assumeTrue("Protected receipt mutation requires the separately supplied elevated token", elevated)
        val backend = DesktopWindowsInstallJobBackend()
        backend.openRoot(backend.defaultRoot(), false).use { root ->
            root.openJob(jobId).use { job ->
                job.openFile("status.json").use { previous ->
                    val old = previous.readBounded(128)
                    for (version in listOf(2, 1)) {
                        val temp = "status-${UUID.randomUUID()}.tmp"
                        try {
                            job.createFile(temp, DesktopInstallJobBackend.Purpose.STATUS_TEMP).use {
                                it.writeExact(RECEIPTS[version - 1].toByteArray(Charsets.UTF_8))
                            }
                            job.replaceFile(temp, "status.json")
                            job.openFile("status.json").use {
                                assertEquals(RECEIPTS[version - 1], it.readBounded(128).toString(Charsets.UTF_8))
                            }
                            assertContentEquals(old, previous.readBounded(128))
                        } finally {
                            try { job.deleteFile(temp) }
                            catch (missing: WindowsInstallNativeFailure) { if (missing.code != 2) throw missing }
                        }
                    }
                }
            }
        }
    }

    private fun fixture(): Pair<String, Boolean> {
        assumeTrue("Windows native execution only", Platform.isWindows())
        val job = System.getProperty("vpn.control.native.protectedJob")
        assumeTrue("Requires explicit disposable-VM protected receipt fixture", !job.isNullOrBlank())
        require(DesktopInstallJobNames.validJob(requireNotNull(job)))
        val expected = requireNotNull(System.getProperty("vpn.control.native.expectedElevation")).toInt()
        require(expected in 0..1)
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        val elevated = try {
            val info = WinNT.TOKEN_ELEVATION()
            check(Advapi32.INSTANCE.GetTokenInformation(token.value, 20, info, info.size(), IntByReference()))
            assertEquals(expected, info.TokenIsElevated, "Native receipt evidence must use the requested token")
            info.TokenIsElevated == 1
        } finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        return job to elevated
    }

    companion object {
        private val RECEIPTS = listOf("{\"nativeReceipt\":1}", "{\"nativeReceipt\":2}")
    }
}
