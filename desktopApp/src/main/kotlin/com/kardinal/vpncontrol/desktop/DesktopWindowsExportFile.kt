package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.channels.SeekableByteChannel
import java.nio.file.Path

/** Export publication retains the verified file handle through the no-replace native rename. */
internal object DesktopWindowsExportFile {
    fun create(parent: Path): DesktopControlTransferFile {
        val native = JnaWindowsInstallNative()
        val owner = JnaWindowsInstallAdmission().currentSid()
        val pins = DesktopWindowsTransferPins.open(parent.toAbsolutePath().toString(), owner, native)
        var handle: WindowsInstallNative.Handle? = null
        try {
            val directory = native.retainedExportDirectory(pins.parentHandle)
            // Keep the native volume-GUID namespace intact; java.nio rejects this form.
            handle = native.createExportPartial(directory.trimEnd('\\') + "\\.vpn-export-${java.util.UUID.randomUUID()}.partial", owner)
            native.requirePrivateExport(handle, owner)
            val file = handle
            val channel = object : SeekableByteChannel {
                private var open = true
                private var offset = 0L
                override fun isOpen() = open
                override fun close() { open = false } // File owner retains native handle until cleanup.
                override fun position() = offset
                override fun position(newPosition: Long): SeekableByteChannel { check(open); require(newPosition >= 0); offset = newPosition; return this }
                override fun size(): Long { check(open); return native.inspect(file).size }
                override fun truncate(size: Long): SeekableByteChannel = throw UnsupportedOperationException()
                override fun read(dst: ByteBuffer): Int {
                    check(open)
                    if (!dst.hasRemaining()) return 0
                    val bytes = ByteArray(minOf(8192, dst.remaining()))
                    val count = native.readExportChunk(file, offset, bytes, bytes.size)
                    if (count == 0) return -1
                    dst.put(bytes, 0, count); offset += count
                    return count
                }
                override fun write(src: ByteBuffer): Int {
                    check(open)
                    if (!src.hasRemaining()) return 0
                    val bytes = ByteArray(minOf(8192, src.remaining()))
                    src.duplicate().get(bytes)
                    val count = native.writeExportChunk(file, offset, bytes, bytes.size)
                    src.position(src.position() + count); offset += count
                    return count
                }
            }
            return object : DesktopControlTransferFile {
                override val channel: SeekableByteChannel = channel
                private var published = false
                private var erased = false
                override fun force() = native.syncExport(file)
                override fun publish(leaf: String) {
                    require(!published && !erased && leaf.isNotBlank() && leaf !in setOf(".", "..") && leaf.none { it in "\\/:\u0000" })
                    native.requirePrivateExport(file, owner)
                    native.publishExportNoReplace(file, leaf)
                    published = true
                }
                override fun erase() {
                    if (erased) return
                    erased = true
                    try { if (!published) native.delete(file) }
                    finally {
                        try { native.close(file) }
                        finally { pins.close() }
                    }
                }
            }
        } catch (failure: Throwable) {
            handle?.let { runCatching { native.delete(it) }; runCatching { native.close(it) } }
            pins.close()
            throw failure
        }
    }
}
