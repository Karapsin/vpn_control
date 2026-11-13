package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.ptr.IntByReference
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import org.junit.Assume.assumeTrue
import kotlin.test.*

/**
 * Windows only. Review of the folder-pin fix: a folder pin that shares writes admits a FILE_WRITE_DATA (FILE_ADD_FILE)
 * handle on the folder, and FSCTL_SET_REPARSE_POINT accepts it ([MS-FSA] 2.1.5.10.37), so an empty pinned folder can
 * become a junction; the pin before the fix (read sharing only) refused that open. What the product then creates by path
 * in the pinned folder must be proven its child, or be deleted. DesktopWindowsPinSharingTest and
 * DesktopWindowsExportPinSharingTest model the same on every platform, with another user's DACL rights.
 */
class DesktopWindowsPinnedFolderJunctionNativeTest {
    private fun fixture(block: (Path, Path) -> Unit) {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("pinned-junction-東京")
        val pinned = Files.createDirectory(root.resolve("pinned"))
        val hideout = Files.createDirectory(root.resolve("hideout"))
        try { block(pinned, hideout) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
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
