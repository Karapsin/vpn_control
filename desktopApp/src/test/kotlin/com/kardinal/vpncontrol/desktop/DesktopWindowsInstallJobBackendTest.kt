package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopWindowsInstallJobBackendTest {
    @Test fun renamePacketUsesAbsoluteVolumePathAndByteLengthOnBothNativeLayouts() {
        val directory = "\\\\?\\Volume{12345678-1234-1234-1234-123456789abc}\\Users\\東京 😀\\job"
        val expected = (directory + "\\" + DesktopInstallJobNames.STATUS).toByteArray(Charsets.UTF_16LE)
        for (width in listOf(4, 8)) {
            windowsInstallRenameInfo(directory, width).use { packet ->
                val root = if (width == 8) 8L else 4L
                assertEquals(1, packet.getByte(0).toInt())
                assertContentEquals(ByteArray(width), packet.getByteArray(root, width))
                assertEquals(expected.size, packet.getInt(root + width))
                assertContentEquals(expected, packet.getByteArray(root + width + 4, expected.size))
            }
        }
        for (invalid in listOf("C:\\job", "job", directory + '\u0000', "\\\\server\\share\\job")) {
            assertFailsWith<IllegalArgumentException> { windowsInstallRenameInfo(invalid, 8) }
        }
    }
    @Test fun exactTrustedInstallerOwnerIsAcceptedOnlyForStandardAncestorsWithoutRelaxingAcl() {
        val installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        val info = directory().copy(owner = installer)
        WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.ANCESTOR)
        for (kind in listOf(WindowsInstallTrust.Kind.DIRECTORY, WindowsInstallTrust.Kind.STATUS, WindowsInstallTrust.Kind.CANCEL)) {
            assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(info.copy(directory = kind == WindowsInstallTrust.Kind.DIRECTORY), kind) }
        }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(info.copy(owner = "$installer-1"), WindowsInstallTrust.Kind.ANCESTOR) }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(info.copy(dacl = listOf(allow(CLIENT, 0x40000))), WindowsInstallTrust.Kind.ANCESTOR) }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(info.copy(dacl = listOf(allow(installer, 0x40000))), WindowsInstallTrust.Kind.ANCESTOR) }
    }
    @Test fun nativeOpenFlagsNeverFollowReparsePointsAndRestrictedWritesFlushWithoutBroadeningAcl() {
        val client = windowsInstallOpenOptions(WindowsInstallNative.READ_WRITE, false, false)
        assertEquals(0, client.rights and 0x40000000)
        assertEquals(0, client.rights and (0xD0154)) // no append/EA/attributes/delete/DACL/owner
        assertEquals(0, client.share and 4)
        assertEquals(0x02200000, client.flags and 0x02200000)
        assertNotEquals(0, client.flags and 0x80000000.toInt())
        assertEquals(3, client.creation) // OPEN_EXISTING, no accidental creation/truncation
        val created = windowsInstallOpenOptions(WindowsInstallNative.READ_WRITE, false, true)
        assertNotEquals(0, created.rights and 0x40000000)
        assertEquals(1, created.creation) // CREATE_NEW
        val ancestor = windowsInstallOpenOptions(WindowsInstallNative.INSPECT, false, false)
        assertEquals(1, ancestor.share) // deny write and delete handles throughout retained ancestry
    }
    @Test fun protectedAncestorsRemainPinnedUntilLastChildFileCloses() {
        val native = FakeNative()
        val backend = DesktopWindowsInstallJobBackend(native)
        val root = backend.openRoot(backend.defaultRoot(), true)
        val job = root.createJob(JOB)
        val cancel = job.createFile("cancel", DesktopInstallJobBackend.Purpose.CANCEL, CLIENT)
        cancel.writeExact(byteArrayOf(0))
        val client = job.openFile("cancel", write = true)
        client.writeExact(byteArrayOf(1))
        assertContentEquals(byteArrayOf(1), cancel.readBounded(1))
        assertFailsWith<IllegalArgumentException> { client.writeExact(byteArrayOf(0)) }
        assertFailsWith<IllegalArgumentException> { client.writeExact(byteArrayOf(1, 1)) }
        root.close(); job.close(); client.close()
        assertTrue(native.handles.filterNot { it.closed }.all { !it.shareDelete })
        assertEquals(5, native.handles.count { !it.closed }) // drive, ProgramData, root, job, retained cancel
        cancel.close()
        assertTrue(native.handles.all { it.closed })
        assertEquals(2, native.syncs)
    }

    @Test fun allReparseTagsAndUntrustedAncestorsFailWithoutCreatingAnything() {
        for (info in listOf(
            directory().copy(attributes = 0x400, reparseTag = 0x80000003.toInt()),
            directory().copy(attributes = 0x400, reparseTag = 0x8000001B.toInt()),
            directory().copy(reparseTag = 123),
            directory().copy(owner = CLIENT),
            directory().copy(dacl = null),
            directory().copy(dacl = listOf(allow(CLIENT, 0x40))),
            directory().copy(dacl = listOf(allow(CLIENT, 0x40000))),
        )) {
            val native = FakeNative()
            native.nodes.getValue("C:\\ProgramData").info = info
            val backend = DesktopWindowsInstallJobBackend(native)
            assertFailsWith<IllegalArgumentException> { backend.openRoot(backend.defaultRoot(), true) }
            assertEquals(0, native.creates)
            assertTrue(native.handles.all { it.closed })
        }
    }

    @Test fun unrelatedAncestorChildCreationIsAllowedButProductDirectoryMutationIsNot() {
        WindowsInstallTrust.verify(directory().copy(dacl = listOf(allow(CLIENT, 6))), WindowsInstallTrust.Kind.ANCESTOR)
        for (mask in listOf(2, 4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x02000000, 0x01000000)) {
            assertFailsWith<IllegalArgumentException> {
                WindowsInstallTrust.verify(directory().copy(dacl = listOf(allow(CLIENT, mask))), WindowsInstallTrust.Kind.DIRECTORY)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            WindowsInstallTrust.verify(directory().copy(dacl = listOf(WindowsInstallAce(9, 0, 0, CLIENT))), WindowsInstallTrust.Kind.DIRECTORY)
        }
        // Conservative even if a deny ACE precedes an unsafe allow; no partial effective-ACL inference.
        assertFailsWith<IllegalArgumentException> {
            WindowsInstallTrust.verify(directory().copy(dacl = listOf(WindowsInstallAce(1, 0, 2, CLIENT), allow(CLIENT, 2))), WindowsInstallTrust.Kind.DIRECTORY)
        }
    }

    @Test fun cancellationAllowsOneNamedUserOnlyAndRejectsHardlinksOrExtraRights() {
        val base = WindowsInstallInfo(false, owner = ADMIN, dacl = listOf(allow(CLIENT, 0x120083)), size = 1)
        WindowsInstallTrust.verify(base, WindowsInstallTrust.Kind.CANCEL, CLIENT)
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(base, WindowsInstallTrust.Kind.STATUS) }
        for (mask in listOf(0x120087, 0x120093, 0x130083, 0x160083, 0x1A0083)) {
            assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(base.copy(dacl = listOf(allow(CLIENT, mask))), WindowsInstallTrust.Kind.CANCEL) }
        }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(base.copy(links = 2), WindowsInstallTrust.Kind.CANCEL) }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(base.copy(dacl = listOf(allow("S-1-1-0", 2))), WindowsInstallTrust.Kind.CANCEL) }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.verify(base, WindowsInstallTrust.Kind.CANCEL, "$CLIENT-other") }
        assertFailsWith<IllegalArgumentException> { WindowsInstallTrust.cancelSddl("$CLIENT)(A;;FA;;;WD)") }
    }

    @Test fun nativeHandlesOwnStatusReplacementAndBoundedReadsDetectGrowth() {
        val native = FakeNative()
        val backend = DesktopWindowsInstallJobBackend(native)
        backend.openRoot(backend.defaultRoot(), true).use { root -> root.createJob(JOB).use { job ->
            val temp = "status-$JOB.tmp"
            job.createFile(temp, DesktopInstallJobBackend.Purpose.STATUS_TEMP).use { it.writeExact("{}".toByteArray()) }
            job.replaceFile(temp, "status.json")
            assertEquals(1, native.renames)
            job.openFile("status.json").use {
                assertContentEquals("{}".toByteArray(), it.readBounded(2))
                assertFailsWith<IllegalArgumentException> { it.readBounded(1) }
                native.growDuringRead = true
                assertFailsWith<IllegalArgumentException> { it.readBounded(2) }
            }
            assertFailsWith<IllegalArgumentException> { job.openFile("status.json", true) }
            assertFailsWith<IllegalArgumentException> { job.openFile("../cancel") }
            assertFailsWith<IllegalArgumentException> { job.replaceFile(temp, "cancel") }
        } }
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun noncanonicalRootsAndSubstitutedNewJobsFailClosed() {
        val native = FakeNative()
        val backend = DesktopWindowsInstallJobBackend(native)
        for (path in listOf("\\\\server\\share", "C:\\ProgramData\\..\\vpn-control-install-jobs", "C:\\ProgramData\\vpn-control-install-jobs:stream", "C:\\other\\vpn-control-install-jobs")) {
            assertFailsWith<IllegalArgumentException> { backend.openRoot(Path.of(path), true) }
        }
        backend.openRoot(backend.defaultRoot(), true).use { root ->
            native.substituteNewDirectory = true
            assertFailsWith<IllegalArgumentException> { root.createJob(JOB) }
        }
        assertTrue(native.handles.all { it.closed })
    }

    private class FakeNative : WindowsInstallNative {
        class Node(var info: WindowsInstallInfo, var data: ByteArray = byteArrayOf())
        class Open(val path: String, val node: Node, val shareDelete: Boolean) : WindowsInstallNative.Handle { var closed = false }
        val nodes = mutableMapOf("C:\\" to Node(directory()), "C:\\ProgramData" to Node(directory().copy(dacl = listOf(allow(CLIENT, 6)))))
        val handles = mutableListOf<Open>()
        var creates = 0
        var syncs = 0
        var renames = 0
        var growDuringRead = false
        var substituteNewDirectory = false
        override fun programData() = "C:\\ProgramData"
        override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?): WindowsInstallNative.Handle {
            if (createSddl != null) {
                if (path in nodes) throw WindowsInstallNativeFailure(80)
                nodes[path] = Node(WindowsInstallInfo(false, owner = ADMIN, dacl =
                    if (path.endsWith("\\cancel")) listOf(allow(CLIENT, 0x120083)) else emptyList()))
            }
            val node = nodes[path] ?: throw WindowsInstallNativeFailure(2)
            return Open(path, node, shareDelete).also(handles::add)
        }
        override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) {
            if (path in nodes && !allowExisting) throw WindowsInstallNativeFailure(183)
            creates++
            nodes.putIfAbsent(path, Node(if (substituteNewDirectory) directory().copy(attributes = 0x400) else directory()))
        }
        override fun inspect(handle: WindowsInstallNative.Handle) = (handle as Open).let { check(!it.closed); it.node.info.copy(size = it.node.data.size.toLong()) }
        override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray {
            val node = (handle as Open).node
            if (growDuringRead) node.data += byteArrayOf(0)
            return node.data.take(limit).toByteArray()
        }
        override fun writeAndSync(handle: WindowsInstallNative.Handle, bytes: ByteArray) { (handle as Open).node.data = bytes.copyOf(); syncs++ }
        override fun rename(handle: WindowsInstallNative.Handle, directory: WindowsInstallNative.Handle, name: String) {
            val source = handle as Open
            val parent = directory as Open
            check(!source.closed && !parent.closed && !parent.shareDelete)
            nodes[parent.path + "\\" + name] = nodes.remove(source.path)!!
            renames++
        }
        override fun delete(handle: WindowsInstallNative.Handle) { nodes.remove((handle as Open).path) }
        override fun close(handle: WindowsInstallNative.Handle) { (handle as Open).let { check(!it.closed); it.closed = true } }
    }

    companion object {
        private const val ADMIN = "S-1-5-32-544"
        private const val CLIENT = "S-1-5-21-1-2-3-1001"
        private const val JOB = "11111111-2222-3333-4444-555555555555"
        private fun allow(sid: String, mask: Int) = WindowsInstallAce(0, 0, mask, sid)
        private fun directory() = WindowsInstallInfo(true, owner = ADMIN, dacl = emptyList())
    }
}
