package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopLinuxAdmissionFlagsTest {
    @Test fun arm64UsesItsOwnLinuxUapiDirectoryAndNoFollowFlags() {
        assertEquals(0x4000, linuxAdmissionOpenFlags("aarch64").directory)
        assertEquals(0x8000, linuxAdmissionOpenFlags("arm64").noFollow)
        assertEquals(0x800, linuxAdmissionOpenFlags("aarch64").nonBlocking)
        assertEquals(0x80000, linuxAdmissionOpenFlags("aarch64").closeOnExec)
    }
    @Test fun x64UsesGenericLinuxFlagsAndUnknownAbiFailsClosed() {
        assertEquals(0x10000, linuxAdmissionOpenFlags("amd64").directory)
        assertEquals(0x20000, linuxAdmissionOpenFlags("x86_64").noFollow)
        for (architecture in listOf("arm", "i386", "riscv64", "unknown")) {
            assertFails { linuxAdmissionOpenFlags(architecture) }
        }
    }
}
