package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopWindowsTransferPinsTest {
    @Test fun exactWindowsServicingPrincipalIsTrustedOnlyForTransferAncestors() {
        val installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        val info = directory(installer)
        DesktopWindowsTransferPins.verify(info, SID)
        assertFails { DesktopWindowsTransferPins.verify(info, SID, private = true) }
        assertFails { WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.ANCESTOR) }
        assertFails { DesktopWindowsTransferPins.verify(directory("$installer-1"), SID) }
        assertFails { DesktopWindowsTransferPins.verify(directory(SID).copy(
            dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, "$installer-1"))), SID) }
        assertFails { DesktopWindowsTransferPins.verify(directory(SID).copy(
            dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, installer))), SID, private = true) }
    }

    @Test fun mutableAncestorRetainsLinkedChildAndActualParentUntilTransferCloses() {
        val native = Fake().also { it.hostile = directory(SID).copy(
            dacl = listOf(WindowsInstallAce(0, 0, 0x116, "S-1-1-0"))) }
        val pins = DesktopWindowsTransferPins.open("C:\\Users\\東京\\Temp", SID, native, witnessPaths())
        val witness = native.opened.single { it.path.endsWith("\\witness") }
        assertFalse(witness.shareDelete)
        assertFalse(witness.closed)
        assertEquals("C:\\Users\\東京\\Temp", (pins.parentHandle as Fake.Pin).path)
        assertFails { native.replace(witness.path) }
        pins.createDirectory()
        pins.deleteDirectory()
        assertFalse(witness.closed)
        pins.close()
        assertTrue(native.opened.all { it.closed })
        val rights = windowsInstallOpenOptions(WindowsInstallNative.INSPECT, false, false)
        assertEquals(1, rights.share)
        assertNotEquals(0, rights.rights and 1)
    }

    @Test fun missingUnlinkedReparseAndRacedChildrenNeverProveMutableAncestorSafe() {
        for (mode in listOf("missing", "unlinked", "reparse", "parent-race", "acl-race")) {
            val native = Fake().also { it.hostile = directory(SID).copy(
                dacl = listOf(WindowsInstallAce(0, 0, 0x116, "S-1-1-0"))) }
            if (mode == "reparse") native.witness = directory(SID).copy(reparseTag = 42)
            val ancestry = witnessPaths(if (mode == "missing") emptyList() else listOf("witness")) { path ->
                if (path.endsWith("\\witness")) {
                    if (mode == "parent-race") native.hostile = directory(SID).copy(reparseTag = 42)
                    if (mode == "acl-race") native.hostile = directory(SID).copy(
                        dacl = listOf(WindowsInstallAce(0, 0, 0x40, "S-1-1-0")))
                }
                if (mode == "unlinked" && path.endsWith("\\witness")) "C:\\elsewhere\\witness" else path
            }
            assertFails { DesktopWindowsTransferPins.open("C:\\Users\\東京\\Temp", SID, native, ancestry) }
            assertEquals(0, native.creates)
            assertTrue(native.opened.all { it.closed })
        }
    }

    private fun witnessPaths(names: List<String> = listOf("witness"), transform: (String) -> String = { it }) =
        object : WindowsAdmissionNative by JnaWindowsInstallAdmission() {
            override fun children(path: String) = names
            override fun canonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + transform((handle as Fake.Pin).path)
        }

    @Test fun pinsEveryAncestorAndPrivateDirectoryUntilExactHandleDeletion() {
        val native = Fake()
        val pins = DesktopWindowsTransferPins.open("C:\\Users\\東京\\Temp", SID, native)
        val child = pins.createDirectory()
        assertEquals(listOf("C:\\", "C:\\Users", "C:\\Users\\東京", "C:\\Users\\東京\\Temp", child), native.opened.map { it.path })
        assertTrue(native.opened.all { !it.shareDelete && !it.closed })
        assertEquals(WindowsInstallNative.DELETE, native.opened.last().access)
        assertFails { native.replace("C:\\Users") }
        pins.deleteDirectory()
        assertEquals(listOf(child), native.deleted)
        pins.close()
        assertTrue(native.opened.all { it.closed })
    }

    @Test fun hostileOwnerAclAndReparseParentsFailBeforeCreationAndReleaseAllPins() {
        for (info in listOf(
            directory("S-1-5-21-9-8-7-6"), directory(SID).copy(dacl = null),
            directory(SID).copy(reparseTag = 42), directory(SID).copy(attributes = 0x400),
            directory(SID).copy(directory = false), directory(SID).copy(disk = false),
            directory(SID).copy(dacl = listOf(WindowsInstallAce(0, 0, 0x40, "S-1-1-0"))),
            directory(SID).copy(dacl = listOf(WindowsInstallAce(9, 0, 0, SID))),
        )) {
            val native = Fake().also { it.hostile = info }
            assertFails { DesktopWindowsTransferPins.open("C:\\Users\\東京\\Temp", SID, native) }
            assertEquals(0, native.creates)
            assertTrue(native.opened.all { it.closed })
        }
    }

    @Test fun currentTokenSidIsTrustedWithoutRelaxingInstallerOrPrivatePayloadPolicy() {
        DesktopWindowsTransferPins.verify(directory(SID), SID)
        assertFails { WindowsInstallTrust.verify(directory(SID), WindowsInstallTrust.Kind.ANCESTOR) }
        val publicRead = directory(SID).copy(dacl = listOf(WindowsInstallAce(0, 0, 0x120089, "S-1-1-0")))
        DesktopWindowsTransferPins.verify(publicRead, SID)
        assertFails { DesktopWindowsTransferPins.verify(publicRead, SID, private = true) }
        assertFails { DesktopWindowsTransferPins.verify(directory("S-1-5-32-544"), SID, private = true) }
        assertFails { DesktopWindowsTransferPins.open("\\\\server\\share\\tmp", SID, Fake()) }
    }

    private class Fake : WindowsInstallNative {
        class Pin(val path: String, val access: Int, val shareDelete: Boolean) : WindowsInstallNative.Handle { var closed = false }
        val opened = mutableListOf<Pin>()
        val deleted = mutableListOf<String>()
        var creates = 0
        var hostile: WindowsInstallInfo? = null
        var witness: WindowsInstallInfo? = null
        override fun programData() = error("Not an installer store")
        override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?) = Pin(path, access, shareDelete).also { opened += it }
        override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
            val path = (handle as Pin).path
            return if (path.endsWith("\\witness")) witness ?: directory(SID)
                else if (path == "C:\\Users\\東京") hostile ?: directory(SID)
                else directory(if (path == "C:\\" || path == "C:\\Users") "S-1-5-18" else SID)
        }
        override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) {
            assertFalse(allowExisting)
            assertEquals("O:${SID}G:${SID}D:P(A;;FA;;;$SID)", sddl)
            creates++
        }
        fun replace(path: String) { check(opened.none { it.path == path && !it.shareDelete && !it.closed }) }
        override fun delete(handle: WindowsInstallNative.Handle) { deleted += (handle as Pin).path }
        override fun close(handle: WindowsInstallNative.Handle) { (handle as Pin).closed = true }
        override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray = error("unused")
        override fun writeAndSync(handle: WindowsInstallNative.Handle, bytes: ByteArray) = error("unused")
        override fun rename(handle: WindowsInstallNative.Handle, directory: WindowsInstallNative.Handle, name: String) = error("unused")
    }
    companion object {
        private const val SID = "S-1-5-21-1-2-3-1001"
        private fun directory(owner: String) = WindowsInstallInfo(true, owner = owner,
            dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, owner)))
    }
}
