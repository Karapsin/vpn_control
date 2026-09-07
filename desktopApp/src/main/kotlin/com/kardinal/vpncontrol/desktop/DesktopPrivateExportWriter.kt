package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import java.nio.ByteBuffer
import java.nio.file.Path
import java.security.MessageDigest

/** Export secrets are private from the first byte; never overwrite an existing leaf. */
internal object DesktopPrivateExportWriter {
    fun write(path: String, bytes: ByteArray): Result<Unit> = writeChunks(path) { emit ->
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset.toLong() + DesktopExportUtf8.CHUNK_BYTES, bytes.size.toLong()).toInt()
            val chunk = bytes.copyOfRange(offset, end)
            emit(chunk, chunk.size)
            offset = end
        }
    }

    fun writeText(path: String, text: String): Result<Unit> = writeChunks(path) { emit ->
        DesktopExportUtf8.encode(text, emit)
    }

    internal fun writeChunks(path: String,
                             backend: (Path) -> DesktopControlTransferFile = { DesktopControlTransferParent.create(it, export = true) },
                             produce: ((ByteArray, Int) -> Unit) -> Unit): Result<Unit> = runCatching {
        val destination = Path.of(path).toAbsolutePath().normalize()
        val parent = requireNotNull(destination.parent)
        val leaf = requireNotNull(destination.fileName).toString()
        val partial = backend(parent)
        try {
            var count = 0L
            val expectedHash = MessageDigest.getInstance("SHA-256")
            produce { bytes, size ->
                require(size in 1..DesktopExportUtf8.CHUNK_BYTES && size <= bytes.size)
                val buffer = ByteBuffer.wrap(bytes, 0, size)
                while (buffer.hasRemaining()) check(partial.channel.write(buffer) > 0)
                count = Math.addExact(count, size.toLong())
                expectedHash.update(bytes, 0, size)
            }
            partial.force()
            require(partial.channel.size() == count) { "Export size mismatch" }
            partial.channel.position(0)
            val actualHash = MessageDigest.getInstance("SHA-256")
            val buffer = ByteBuffer.allocate(DesktopExportUtf8.CHUNK_BYTES)
            var received = 0L
            while (true) {
                buffer.clear()
                val size = partial.channel.read(buffer)
                if (size == -1) break
                check(size > 0)
                received = Math.addExact(received, size.toLong())
                require(received <= count) { "Export size mismatch" }
                actualHash.update(buffer.array(), 0, size)
            }
            require(received == count && MessageDigest.isEqual(expectedHash.digest(), actualHash.digest())) { "Export verification failed" }
            partial.publish(leaf)
        } finally {
            try { partial.channel.close() } finally { partial.erase() }
        }
    }

    /** Private Windows spool initialization only; never recursively invokes export publication. */
    internal fun createPrivateEmpty(path: String): Result<Unit> = runCatching {
            check(Platform.isWindows())
            val destination = Path.of(path).toAbsolutePath()
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
                native.writeStreamAndSync(handle) { }
            } finally { native.close(handle) }
    }
}
