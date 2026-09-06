package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions

/** Export secrets are private from the first byte; never overwrite an existing leaf. */
internal object DesktopPrivateExportWriter {
    fun write(path: String, bytes: ByteArray): Result<Unit> = runCatching {
        val destination = Path.of(path).toAbsolutePath()
        if (Platform.isWindows()) {
            val token = WinNT.HANDLEByReference()
            check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
            val sid = try { Advapi32Util.getTokenAccount(token.value).sidString }
            finally { Kernel32.INSTANCE.CloseHandle(token.value) }
            // D:P suppresses inherited grants AT CREATE_NEW; do not tighten after writing.
            val native = JnaWindowsInstallNative()
            val handle = native.open(destination.toString(), WindowsInstallNative.READ_WRITE, true,
                "O:${sid}G:${sid}D:P(A;;FA;;;$sid)")
            try {
                native.requirePrivateExport(handle, sid)
                native.writeAndSync(handle, bytes)
            } finally { native.close(handle) }
        } else if (Platform.isMac()) {
            val native = Native.load("System", MacApi::class.java)
            val fd = native.open(destination.toString(), 1 or 0x200 or 0x800 or 0x100, 384) // WRONLY|CREAT|EXCL|NOFOLLOW,0600
            check(fd >= 0)
            try {
                // Verify this exact newly-created descriptor before payload IO. BSD0600
                // alone does not limit inherited Darwin allow ACEs.
                DesktopMacInstallJobAcl.requireAbsent(fd)
                var offset = 0
                while (offset < bytes.size) {
                    val chunk = bytes.copyOfRange(offset, minOf(offset + 8192, bytes.size))
                    val count = native.write(fd, chunk, chunk.size.toLong())
                    check(count in 1..chunk.size.toLong())
                    offset += count.toInt()
                }
                check(native.fsync(fd) == 0)
            } finally { check(native.close(fd) == 0) }
        } else {
            // Unsupported permission models fail before creation; there is no public fallback.
            FileChannel.open(destination, setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) check(channel.write(buffer) > 0)
                channel.force(true)
            }
        }
    }
    private interface MacApi : Library {
        fun open(path: String, flags: Int, vararg mode: Any): Int
        fun write(fd: Int, bytes: ByteArray, size: Long): Long
        fun fsync(fd: Int): Int
        fun close(fd: Int): Int
    }
}
