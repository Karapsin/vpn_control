package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.DROP
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.FILE_ADD_FILE
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.HIDEOUT
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.MALLORY
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.MALLORY_GROUPS
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SID
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SYSTEM
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.TEMP
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.WINDOWS_TEMP
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.directory
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.dropVolume
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.lastFolderRefusal
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.mountAs
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.ownFile
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.privateTo
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.systemTempVolume
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.transferVolume
import java.nio.ByteBuffer
import kotlin.test.*

/**
 * Exports (the GUI's save dialog, `vpn-control-cli ... --output`, and the product's own records) pin the export
 * folder's chain sharing writes, then create their private partial by path in that folder and publish it by a
 * leaf rename relative to the partial's actual parent. Review of the folder-pin fix: if the folder lets another
 * local user add files (a drop box) and is empty, that user may turn it into a junction between the pins and the
 * creation, and the export would be published in their folder. Nothing an export creates may stay outside the
 * folder the user chose, and an export that succeeds is published there. Such a folder is used only beside an entry
 * the user can open; otherwise the export is refused with a message that says what helps. Judged by [SharingVolume],
 * which applies each object's DACL to the export's own opens as Windows does.
 */
class DesktopWindowsExportPinSharingTest {
    @Test fun anotherUserCannotRedirectAnExportOutOfAnEmptyDropBoxThroughAJunction() {
        val volume = dropVolume()
        val raced = mutableListOf<Int>()
        volume.beforeCreate = { path -> if (volume.isChild(path, DROP)) raced += volume.mountAs(MALLORY_GROUPS, DROP, HIDEOUT, FILE_ADD_FILE) }
        val exports = ExportVolume(volume)
        val outcome = runCatching { export(exports, DROP, "routing.json", "secret") }
        assertEquals(emptyList(), volume.nodes.keys.filter { volume.isChild(it, HIDEOUT) },
            "The export was created in another user's folder (junction set with FILE_ADD_FILE: $raced, outcome $outcome)")
        outcome.onSuccess { assertEquals("secret", exports.content("$DROP\\routing.json")) }
        assertTrue(volume.live().isEmpty(), volume.live().toString())
    }

    /**
     * Review of the hardening: a drop box usually holds other users' files, private to them, which the export cannot
     * open and so cannot retain. A drop box holding only such files, the empty drop box and an emptied C:\Windows\Temp
     * (the CLI as SYSTEM) are all refused before anything is created, with a message that says what helps.
     */
    @Test fun anExportIntoAFolderOthersMayWriteIsRefusedWithAClearMessageWhenItHoldsNothingTheUserCanOpen() {
        val held = dropVolume().apply { addEntry(DROP, "dropped.txt", privateTo(MALLORY)) }
        for ((owner, volume, folder) in listOf(Triple(SID, held, DROP), Triple(SID, dropVolume(), DROP),
                Triple(SYSTEM, systemTempVolume(), WINDOWS_TEMP))) {
            val exports = ExportVolume(volume)
            val refused = assertFailsWith<IllegalStateException> { export(exports, folder, "routing.json", "secret", owner) }
            assertEquals(lastFolderRefusal(folder), refused.message)
            assertEquals(emptyList(), volume.created)
            assertEquals(emptyList(), exports.written)
            assertTrue(volume.live().isEmpty(), volume.live().toString())
        }
    }

    @Test fun anExportIntoADropBoxHoldingAFileOfTheUsersStaysInThePinnedFolder() {
        // Another user's private file comes first and cannot be opened; the user's own file is retained as the witness.
        val volume = dropVolume().apply {
            addEntry(DROP, "dropped.txt", privateTo(MALLORY))
            addEntry(DROP, "mine.txt", ownFile(SID))
        }
        val raced = mutableListOf<Int>()
        volume.beforeCreate = { path -> if (volume.isChild(path, DROP)) raced += volume.mountAs(MALLORY_GROUPS, DROP, HIDEOUT, FILE_ADD_FILE) }
        val exports = ExportVolume(volume)
        val file = DesktopWindowsExportFile.create(DROP, exports, volume.ancestry(), SID)
        try {
            assertEquals(listOf(145), raced) // ERROR_DIR_NOT_EMPTY: the retained entry keeps the folder from becoming a junction
            volume.assertOthersMayAddEntries(listOf(DROP))
            volume.assertPinnedAgainstRenameAndDeletion(listOf(DROP, "$DROP\\mine.txt"))
            // The witness is the user's file; the other user's stays unheld (beside them only the export's partial).
            assertEquals(listOf("$DROP\\mine.txt"), volume.live().map { it.path }.filter { it.endsWith(".txt") })
            file.channel.write(ByteBuffer.wrap("secret".toByteArray()))
            file.force()
            file.publish("routing.json")
        } finally { file.erase() }
        assertEquals("secret", exports.content("$DROP\\routing.json"))
        assertEquals(emptyList(), volume.nodes.keys.filter { volume.isChild(it, HIDEOUT) })
        assertTrue(volume.live().isEmpty(), volume.live().toString())
    }

    /** The creation's half, independent of the trust policy: a partial found behind a junction is deleted unwritten. */
    @Test fun anExportPartialCreatedBehindAJunctionIsDeletedBeforeAByteIsWritten() {
        val volume = transferVolume().apply {
            nodes["C:\\Users\\mallory"] = directory(MALLORY)
            nodes[HIDEOUT] = directory(MALLORY)
        }
        volume.beforeCreate = { path -> if (volume.isChild(path, TEMP)) volume.redirect(TEMP, HIDEOUT) }
        val exports = ExportVolume(volume)
        assertFails { export(exports, TEMP, "routing.json", "secret") }
        val strays = volume.created.filter { volume.isChild(it, HIDEOUT) }
        assertEquals(1, strays.size, "The model must have redirected the creation: ${volume.created}")
        assertEquals(strays, volume.deleted, "The export must delete the partial it created behind the junction")
        assertEquals(emptyList(), exports.written, "No byte may reach a partial outside the pinned folder")
        assertEquals(emptyList(), volume.nodes.keys.filter { volume.isChild(it, HIDEOUT) })
        assertTrue(volume.live().isEmpty(), volume.live().toString())
    }

    private fun export(exports: ExportVolume, folder: String, leaf: String, text: String, owner: String = SID) {
        val file = DesktopWindowsExportFile.create(folder, exports, exports.volume.ancestry(), owner)
        try {
            file.channel.write(ByteBuffer.wrap(text.toByteArray()))
            file.force()
            file.publish(leaf)
        } finally { file.erase() }
    }
}

/**
 * [SharingVolume] with an export's native calls as JnaWindowsInstallNative makes them: the partial is created by path
 * (CREATE_NEW, read sharing only, private to its owner) wherever the path resolves, and published by a leaf rename in
 * its actual parent.
 */
internal class ExportVolume(val volume: SharingVolume) : WindowsExportNative, WindowsInstallNative by volume {
    private val bytes = mutableMapOf<String, ByteArray>()
    /** Every path a byte was written to. */
    val written = mutableListOf<String>()
    fun content(path: String) = bytes[path]?.decodeToString()

    override fun retainedExportDirectory(directory: WindowsInstallNative.Handle) = "\\\\?\\" + (directory as SharingVolume.Open).path
    override fun createExportPartial(path: String, owner: String): WindowsInstallNative.Handle {
        val requested = path.removePrefix("\\\\?\\")
        volume.beforeCreate(requested)
        val actual = volume.resolve(requested)
        if (actual in volume.nodes) throw WindowsInstallNativeFailure(80)
        check(actual.substringBeforeLast('\\') in volume.nodes) { "No parent for $actual" }
        volume.nodes[actual] = WindowsInstallInfo(false, owner = owner, dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, owner)))
        volume.created += actual
        bytes[actual] = ByteArray(0)
        return SharingVolume.Open(actual, -1, SharingVolume.fileRights(0x40130083), 1).also { volume.opens += it }
    }
    override fun requirePrivateExport(handle: WindowsInstallNative.Handle, owner: String) =
        requireWindowsPrivateExport(8, volume.inspect(handle), owner)
    override fun readExportChunk(value: WindowsInstallNative.Handle, offset: Long, bytes: ByteArray, count: Int): Int {
        val content = this.bytes.getValue(path(value))
        val available = maxOf(0, minOf(count.toLong(), content.size - offset).toInt())
        content.copyInto(bytes, 0, offset.toInt(), offset.toInt() + available)
        return available
    }
    override fun writeExportChunk(value: WindowsInstallNative.Handle, offset: Long, bytes: ByteArray, count: Int): Int {
        val path = path(value)
        written += path
        val content = this.bytes.getValue(path)
        val grown = content.copyOf(maxOf(content.size, offset.toInt() + count))
        bytes.copyInto(grown, offset.toInt(), 0, count)
        this.bytes[path] = grown
        volume.nodes[path] = volume.nodes.getValue(path).copy(size = grown.size.toLong())
        return count
    }
    override fun syncExport(value: WindowsInstallNative.Handle) { path(value) }
    override fun publishExportNoReplace(value: WindowsInstallNative.Handle, leaf: String) {
        val source = path(value)
        val target = source.substringBeforeLast('\\') + "\\" + leaf
        if (target in volume.nodes) throw WindowsInstallNativeFailure(183)
        volume.nodes[target] = volume.nodes.remove(source)!!
        bytes[target] = bytes.remove(source)!!
    }
    private fun path(value: WindowsInstallNative.Handle) = (value as SharingVolume.Open).also { check(!it.closed) }.path
}
