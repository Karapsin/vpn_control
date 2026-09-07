package com.kardinal.vpncontrol.desktop

import java.nio.file.NoSuchFileException
import kotlin.test.*

class DesktopMacInstallNativeResultTest {
    @Test fun onlyNativeAbsentObjectCanBecomePositiveMissingReceiptEvidence() {
        assertEquals(12, macInstallNativeResult(12, 2))
        assertFailsWith<NoSuchFileException> { macInstallNativeResult(-1, 2) }
        for (nativeError in listOf(0, 1, 5, 9, 13, 20, 22, 40))
            assertFalse(assertFails { macInstallNativeResult(-1, nativeError) } is NoSuchFileException)
    }
}
