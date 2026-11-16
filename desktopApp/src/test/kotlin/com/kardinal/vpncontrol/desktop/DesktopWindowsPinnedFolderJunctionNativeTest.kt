package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinDef
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assume.assumeTrue
import kotlin.test.*

/**
 * Windows only. Review of the folder-pin fix: a folder pin that shares writes admits a FILE_WRITE_DATA (FILE_ADD_FILE)
 * handle on the folder, and FSCTL_SET_REPARSE_POINT accepts it ([MS-FSA] 2.1.5.10.37), so an empty pinned folder can
 * become a junction; the pin before the fix (read sharing only) refused that open. What the product then creates by path
 * in the pinned folder must be proven its child, or be deleted. DesktopWindowsPinSharingTest and
 * DesktopWindowsExportPinSharingTest model the same on every platform, with another user's DACL rights and the access
 * check of the product's own opens.
 */
class DesktopWindowsPinnedFolderJunctionNativeTest {
    private fun fixture(block: (Path, Path) -> Unit) {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("pinned-junction-東京")
        val pinned = Files.createDirectory(root.resolve("pinned"))
        val hideout = Files.createDirectory(root.resolve("hideout"))
        removingTree(root) { block(pinned, hideout) }
    }

    /**
     * Runs [block], then deletes [root]. A deletion the file system refuses is retried with a bounded backoff (a scanner
     * may hold a file just closed), and one that still fails never hides [block]'s own failure: it is suppressed into
     * it, and thrown only when [block] passed.
     */
    private fun <T> removingTree(root: Path, block: () -> T): T {
        var failure: Throwable? = null
        try {
            return block()
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            val leftover = runCatching {
                Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).toList() }.forEach { path ->
                    var attempt = 0
                    while (true) {
                        try { Files.deleteIfExists(path); break }
                        catch (refused: FileSystemException) {
                            if (++attempt == 8) throw refused
                            Thread.sleep(25L shl (attempt - 1))
                        }
                    }
                }
            }.exceptionOrNull()
            if (leftover != null) failure?.addSuppressed(leftover) ?: throw leftover
        }
    }

    @Test fun nativeFileWriteDataTurnsAnEmptyFolderPinnedSharingWritesIntoAJunction() = fixture { pinned, hideout ->
        val native = JnaWindowsInstallNative()
        val pin = native.open(pinned.toString(), WindowsInstallNative.PINNED_DIRECTORY, shareDelete = false)
        try {
            val writer = Junction.writeData(pinned)
            try {
                assertEquals(0, Junction.mount(writer, hideout), "FSCTL_SET_REPARSE_POINT with FILE_WRITE_DATA on an empty pinned folder")
                assertEquals(0, Junction.unmount(writer))
                Files.writeString(pinned.resolve("entry.txt"), "entry") // creating by path opens no folder
                assertEquals(145, Junction.mount(writer, hideout), "A non-empty folder takes no reparse point")
                Files.delete(pinned.resolve("entry.txt"))
            } finally { assertTrue(Kernel32.INSTANCE.CloseHandle(writer)) }
        } finally { native.close(pin) }
        // The folder pin before the fix (INSPECT, read sharing only) refused that FILE_WRITE_DATA open.
        val strict = native.open(pinned.toString(), WindowsInstallNative.INSPECT, shareDelete = false)
        try { assertEquals(32, assertFailsWith<WindowsInstallNativeFailure> { Junction.writeData(pinned) }.code) }
        finally { native.close(strict) }
    }

    @Test fun nativeTransferFolderCreatedBehindAJunctionIsDeletedAndRefused() = fixture { pinned, hideout ->
        val pins = DesktopWindowsTransferPins.open(pinned.toAbsolutePath().toString(),
            JnaWindowsInstallAdmission().currentSid(), JnaWindowsInstallNative())
        try {
            // The other side wins the race: the empty pinned folder becomes a junction before the private folder exists.
            val writer = Junction.writeData(pinned)
            try {
                assertEquals(0, Junction.mount(writer, hideout))
                try {
                    assertFails { pins.createDirectory() }
                    assertEquals(emptyList(), Files.list(hideout).use { it.toList() }, "The product left its folder behind the junction")
                } finally { assertEquals(0, Junction.unmount(writer)) }
            } finally { assertTrue(Kernel32.INSTANCE.CloseHandle(writer)) }
        } finally { pins.close() }
        assertEquals(emptyList(), Files.list(pinned).use { it.toList() })
    }

    @Test fun nativeExportPartialCreatedBehindAJunctionIsDeletedUnwritten() = fixture { pinned, hideout ->
        val files = JnaWindowsInstallNative()
        val ancestry = JnaWindowsInstallAdmission()
        var writer: WinNT.HANDLE? = null
        val racing = object : WindowsExportNative by files {
            override fun createExportPartial(path: String, owner: String): WindowsInstallNative.Handle {
                // The other side wins the race: the export folder becomes a junction just before the partial exists.
                writer = Junction.writeData(pinned).also { assertEquals(0, Junction.mount(it, hideout)) }
                return files.createExportPartial(path, owner)
            }
        }
        try {
            assertFails { DesktopWindowsExportFile.create(pinned.toAbsolutePath().toString(), racing, ancestry, ancestry.currentSid()) }
            assertNotNull(writer, "The export never created its partial")
            assertEquals(emptyList(), Files.list(hideout).use { it.toList() }, "The export left its partial behind the junction")
        } finally {
            writer?.let { assertEquals(0, Junction.unmount(it)); assertTrue(Kernel32.INSTANCE.CloseHandle(it)) }
        }
        assertEquals(emptyList(), Files.list(pinned).use { it.toList() })
    }

    /**
     * The witness is opened as the product opens anything, with no privilege enabled: an entry its token cannot read
     * (another account's private file; here one only an unrelated SID may read, owned by this user, who keeps
     * READ_CONTROL and DELETE but neither FILE_READ_DATA nor SYNCHRONIZE) refuses the open with 5, and a folder Users
     * may add files to that holds only such entries is refused with the clear message. A file of the user's own is
     * retained: it cannot be deleted while the pins live, and the transfer folder is created in place.
     *
     * Every pin opens with FILE_FLAG_BACKUP_SEMANTICS, so a token with SeBackupPrivilege enabled reads any file whatever
     * its DACL. The test therefore runs on a thread impersonating this process with backup and restore disabled, as an
     * interactive user's process runs. An open that succeeds anyway is closed before the test fails, so no handle of
     * the test keeps the private file from its deletion. Windows Desktop Package run 43877068415 lost such a failure:
     * the fixture's deletion of dropped.txt was refused with 32 ("being used by another process") and replaced it.
     */
    @Test fun nativeFolderOthersMayWriteIsUsedOnlyBesideAnEntryTheUserCanOpen() {
        assumeTrue(Platform.isWindows())
        val ancestry = JnaWindowsInstallAdmission()
        val sid = ancestry.currentSid()
        val native = JnaWindowsInstallNative()
        val root = Files.createTempDirectory("pinned-witness-東京")
        removingTree(root) { withoutBackupPrivileges { disabled ->
            val drop = root.resolve("drop")
            native.createDirectory(drop.toString(), "O:${sid}G:${sid}D:P(A;OICI;FA;;;$sid)(A;;0x1200af;;;BU)", allowExisting = false)
            val dropped = drop.resolve("dropped.txt")
            native.close(native.open(dropped.toString(), WindowsInstallNative.READ_WRITE, shareDelete = true,
                createSddl = "O:${sid}G:${sid}D:P(A;;FA;;;S-1-5-21-1-2-3-1002)(A;;SD;;;$sid)"))
            val unreadable = runCatching { native.open(dropped.toString(), WindowsInstallNative.PINNED_DIRECTORY, shareDelete = false) }
            unreadable.getOrNull()?.let(native::close)
            assertEquals(5, (unreadable.exceptionOrNull() as? WindowsInstallNativeFailure)?.code,
                "another account's private file was opened as a pin ($unreadable; privileges this thread disabled: $disabled)")
            val refused = runCatching { DesktopWindowsTransferPins.open(drop.toString(), sid, native, ancestry) }
            refused.getOrNull()?.close()
            assertEquals("Cannot use $drop: other accounts can write to it and it holds nothing you can open. " +
                "Add a file of your own to it, or choose a folder only you can change.",
                (refused.exceptionOrNull() as? IllegalStateException)?.message,
                "$refused (privileges this thread disabled: $disabled)")
            val mine = Files.writeString(drop.resolve("mine.txt"), "mine")
            DesktopWindowsTransferPins.open(drop.toString(), sid, native, ancestry).use { pins ->
                assertFails { Files.delete(mine) } // the retained witness shares no deletion
                val private = Path.of(pins.createDirectory())
                assertTrue(Files.isDirectory(drop.resolve(private.fileName)), "$private")
                pins.deleteDirectory()
            }
            assertEquals(listOf(dropped, mine), Files.list(drop).use { it.sorted().toList() })
        } }
    }

    /**
     * Runs [block] on this thread impersonating this process with SeBackupPrivilege and SeRestorePrivilege disabled, and
     * hands it the names of those that were enabled. CreateFile checks access against the thread's token.
     */
    private fun <T> withoutBackupPrivileges(block: (List<String>) -> T): T {
        val advapi = Advapi32.INSTANCE
        check(advapi.ImpersonateSelf(2)) { "ImpersonateSelf: ${Native.getLastError()}" } // SecurityImpersonation
        try {
            val token = WinNT.HANDLEByReference()
            // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, checked against this process's own token (OpenAsSelf).
            check(advapi.OpenThreadToken(Kernel32.INSTANCE.GetCurrentThread(), 0x20 or 0x8, true, token)) {
                "OpenThreadToken: ${Native.getLastError()}" }
            try {
                val disabled = mutableListOf<String>()
                for (name in listOf("SeBackupPrivilege", "SeRestorePrivilege")) {
                    val luid = WinNT.LUID()
                    check(advapi.LookupPrivilegeValue(null, name, luid)) { "LookupPrivilegeValue($name): ${Native.getLastError()}" }
                    val wanted = WinNT.TOKEN_PRIVILEGES(1).apply { Privileges[0] = WinNT.LUID_AND_ATTRIBUTES(luid, WinDef.DWORD(0)) }
                    val previous = WinNT.TOKEN_PRIVILEGES(1)
                    check(advapi.AdjustTokenPrivileges(token.value, false, wanted, previous.size(), previous, IntByReference())) {
                        "AdjustTokenPrivileges($name): ${Native.getLastError()}" }
                    // The previous state lists the privilege only when this call changed it: it was enabled.
                    if (previous.PrivilegeCount.toInt() == 1 && previous.Privileges[0].Attributes.toInt() and 0x2 != 0) disabled += name
                }
                return block(disabled)
            } finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        } finally { check(advapi.RevertToSelf()) { "RevertToSelf: ${Native.getLastError()}" } }
    }

    /** Another program's view of a folder: FILE_WRITE_DATA only, and the mount point it may set ([MS-FSCC] 2.1.2.5). */
    private object Junction {
        private const val MOUNT_POINT = 0xA0000003.toInt()

        /** CreateFile with FILE_WRITE_DATA (it adds SYNCHRONIZE and FILE_READ_ATTRIBUTES), sharing all, on the folder itself. */
        fun writeData(folder: Path): WinNT.HANDLE {
            val handle = Kernel32.INSTANCE.CreateFile(folder.toString(), 0x2, 7, null, 3, 0x02200000, null)
            if (handle == WinBase.INVALID_HANDLE_VALUE || handle.pointer == WinBase.INVALID_HANDLE_VALUE.pointer)
                throw WindowsInstallNativeFailure(Native.getLastError())
            return handle
        }

        /** FSCTL_SET_REPARSE_POINT with a mount point of [target]: 0, or the Win32 error. */
        fun mount(handle: WinNT.HANDLE, target: Path): Int {
            val print = target.toAbsolutePath().toString()
            val substitute = ("\\??\\" + print).toByteArray(Charsets.UTF_16LE)
            val printed = print.toByteArray(Charsets.UTF_16LE)
            val data = ByteBuffer.allocate(16 + substitute.size + 2 + printed.size + 2).order(ByteOrder.LITTLE_ENDIAN)
            data.putInt(MOUNT_POINT).putShort((8 + substitute.size + 2 + printed.size + 2).toShort()).putShort(0)
            data.putShort(0).putShort(substitute.size.toShort()).putShort((substitute.size + 2).toShort()).putShort(printed.size.toShort())
            data.put(substitute).putShort(0).put(printed).putShort(0)
            return control(handle, 0x000900A4, data.array())
        }

        /** FSCTL_DELETE_REPARSE_POINT of the mount point: 0, or the Win32 error. */
        fun unmount(handle: WinNT.HANDLE): Int =
            control(handle, 0x000900AC, ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putInt(MOUNT_POINT).array())

        private fun control(handle: WinNT.HANDLE, code: Int, bytes: ByteArray): Int = Memory(bytes.size.toLong()).use { input ->
            input.write(0, bytes, 0, bytes.size)
            if (Kernel32.INSTANCE.DeviceIoControl(handle, code, input, bytes.size, null, 0, IntByReference(), null)) 0
            else Native.getLastError()
        }
    }
}
