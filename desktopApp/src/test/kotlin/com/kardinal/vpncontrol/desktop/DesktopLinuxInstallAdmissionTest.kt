package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopLinuxInstallAdmissionTest {
    @Test fun boundedControlObservesOnlyValidatedPendingWhileRetainingSharedLease() {
        for (pending in listOf(false, true)) {
            val native = Fake().also { if (pending) it.bytes[8] = 1 }
            var observed = false
            DesktopLinuxInstallAdmission.enter(native, allowPendingControl = true,
                onPendingControl = { observed = true }).use {
                assertEquals(pending, observed)
                assertEquals(5, native.open.size)
            }
            assertTrue(native.open.isEmpty())
        }
        var observed = false
        DesktopLinuxInstallAdmission.enter(Fake().also { it.missing = "gate-linux" },
            allowPendingControl = true, onPendingControl = { observed = true }).close()
        assertFalse(observed)
        for (native in listOf(Fake().also { it.shared = false }, Fake().also { it.bytes[8] = 2 })) {
            assertFails { DesktopLinuxInstallAdmission.enter(native, allowPendingControl = true,
                onPendingControl = { observed = true }) }
            assertFalse(observed)
            assertTrue(native.open.isEmpty())
        }
    }

    private class Fake : LinuxInstallAdmissionNative {
        val open = mutableSetOf<Int>()
        var missing: String? = null
        var shared = true
        var bytes = ByteArray(17)
        var gate = LinuxAdmissionInfo(0, 0x8124, 1, 17, 1, 5)
        var directory = LinuxAdmissionInfo(0, 0x41ed, 2, 4096, 1, 1)
        var reads = 0
        var afterRead: (() -> Unit)? = null
        private fun handle() = (open.size + 1).also { open += it }
        override fun openRoot() = handle()
        override fun openDirectory(parent: Int, name: String) = handle()
        override fun openOptionalDirectory(parent: Int, name: String) = if (missing == name) null else handle()
        override fun openOptionalGate(parent: Int, name: String) = if (missing == name) null else handle()
        override fun inspect(fd: Int) = if (fd == 5) gate else directory
        override fun lockSharedNonBlocking(fd: Int) = shared
        override fun readGate(fd: Int): ByteArray { reads++; afterRead?.invoke(); return bytes }
        override fun close(fd: Int) { check(open.remove(fd)) }
    }

    @Test fun sharedLeaseRetainsAncestorsAndGateUntilIdempotentClose() {
        val native = Fake()
        val lease = DesktopLinuxInstallAdmission.enter(native)
        assertEquals(5, native.open.size)
        lease.close(); lease.close()
        assertTrue(native.open.isEmpty())
    }

    @Test fun missingPreUpdaterRootOrGateReleasesAllDescriptors() {
        for (missing in listOf("vpn-control-install-jobs", "gate-linux")) {
            val native = Fake().also { it.missing = missing }
            DesktopLinuxInstallAdmission.enter(native).close()
            assertTrue(native.open.isEmpty())
        }
    }

    @Test fun exclusiveInstallerOrPendingMarkerRejectsStartupAsBusy() {
        for (exclusive in listOf(true, false)) {
            val native = Fake().also { if (exclusive) it.shared = false else it.bytes[8] = 1 }
            assertEquals("BUSY", assertFails { DesktopLinuxInstallAdmission.enter(native) }.message)
            assertTrue(native.open.isEmpty())
            if (exclusive) assertEquals(0, native.reads)
        }
    }

    @Test fun unsafeOwnerPermissionsTypesLinksAndSizeFailClosed() {
        val base = Fake().gate
        for (bad in listOf(base.copy(uid = 1000), base.copy(mode = 0x81b6), base.copy(mode = 0x1124),
            base.copy(links = 0), base.copy(links = 2), base.copy(size = 18))) {
            val native = Fake().also { it.gate = bad }
            assertFails { DesktopLinuxInstallAdmission.enter(native) }
            assertTrue(native.open.isEmpty())
        }
        val native = Fake().also { it.directory = it.directory.copy(mode = 0x41ff) }
        assertFails { DesktopLinuxInstallAdmission.enter(native) }
        assertTrue(native.open.isEmpty())
    }

    @Test fun corruptGateAndRetainedInodeMutationFailClosed() {
        for (bytes in listOf(ByteArray(16), ByteArray(18), ByteArray(17).also { it[0] = 1 }, ByteArray(17).also { it[8] = 2 })) {
            val native = Fake().also { it.bytes = bytes }
            assertFails { DesktopLinuxInstallAdmission.enter(native) }
            assertTrue(native.open.isEmpty())
        }
        val native = Fake()
        native.afterRead = { native.gate = native.gate.copy(inode = 7) }
        assertFails { DesktopLinuxInstallAdmission.enter(native) }
        assertTrue(native.open.isEmpty())
    }
}
