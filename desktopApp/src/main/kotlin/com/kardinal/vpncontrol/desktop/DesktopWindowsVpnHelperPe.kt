package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Reads only retained bytes; addresses are file offsets, never process pointers. */
internal object DesktopWindowsVpnHelperPe {
    internal data class Header(val machine: Int, val clrHeader: Boolean, val dependentLoadFlags: Int)

    fun machine(size: Long, read: (Long, Int) -> ByteArray): Int {
        val dos = exact(size, 0, 64, read)
        require(dos[0] == 0x4d.toByte() && dos[1] == 0x5a.toByte()) { "UNSUPPORTED" }
        val offset = unsigned(dos, 0x3c)
        require(offset >= 64) { "UNSUPPORTED" }
        val pe = exact(size, offset, 24, read)
        require(unsigned(pe, 0) == 0x4550L) { "UNSUPPORTED" }
        return short(pe, 4)
    }

    fun inspect(size: Long, maximum: Long, read: (Long, Int) -> ByteArray): DesktopWindowsPinnedExecutable {
        require(size in 64..maximum) { "RESOURCE_EXHAUSTED" }
        val dos = exact(size, 0, 64, read)
        require(dos[0] == 0x4d.toByte() && dos[1] == 0x5a.toByte()) { "UNSUPPORTED" }
        val offset = unsigned(dos, 0x3c)
        require(offset >= 64) { "UNSUPPORTED" }
        val pe = exact(size, offset, 24, read)
        require(unsigned(pe, 0) == 0x4550L) { "UNSUPPORTED" }
        val machine = short(pe, 4)
        require(machine == 0x8664) { "UNSUPPORTED" }
        val sections = short(pe, 6)
        val optionalSize = short(pe, 20)
        require(sections in 1..96 && optionalSize in 240..4096) { "UNSUPPORTED" }
        val optional = exact(size, offset + 24, optionalSize, read)
        require(short(optional, 0) == 0x20b) { "UNSUPPORTED" }
        val count = unsigned(optional, 108)
        require(count >= 15 && 112 + count * 8 <= optionalSize) { "UNSUPPORTED" }
        val sectionTable = exact(size, offset + 24 + optionalSize, sections * 40, read)
        fun address(rva: Long, length: Long): Long {
            require(rva > 0 && length > 0 && length <= size) { "UNSUPPORTED" }
            val matches = (0 until sections).mapNotNull { section ->
                val start = section * 40
                val virtual = unsigned(sectionTable, start + 12)
                val rawSize = unsigned(sectionTable, start + 16)
                val raw = unsigned(sectionTable, start + 20)
                val delta = rva - virtual
                if (delta >= 0 && delta + length <= rawSize && raw + delta + length <= size) raw + delta else null
            }
            require(matches.size == 1) { "UNSUPPORTED" }
            return matches.single()
        }
        val clr = unsigned(optional, 112 + 14 * 8) != 0L || unsigned(optional, 116 + 14 * 8) != 0L
        val loadRva = unsigned(optional, 112 + 10 * 8)
        val loadSize = unsigned(optional, 116 + 10 * 8)
        require(loadSize >= 80) { "UNSUPPORTED" }
        val load = exact(size, address(loadRva, loadSize), 80, read)
        require(unsigned(load, 0) in 80..loadSize) { "UNSUPPORTED" }
        val dependentFlags = short(load, 78)
        val digest = MessageDigest.getInstance("SHA-256")
        var position = 0L
        while (position < size) {
            val bytes = exact(size, position, minOf(8192L, size - position).toInt(), read)
            digest.update(bytes)
            position += bytes.size
        }
        return DesktopWindowsPinnedExecutable(digest.digest().joinToString("") { "%02x".format(it) },
            size, machine, clr, dependentFlags)
    }

    private fun exact(size: Long, offset: Long, count: Int, read: (Long, Int) -> ByteArray): ByteArray {
        require(offset >= 0 && count in 1..8192 && offset <= size && count <= size - offset) { "UNSUPPORTED" }
        return read(offset, count).also { require(it.size == count) { "CONFLICT" } }
    }
    private fun short(bytes: ByteArray, offset: Int) =
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getShort(offset).toInt() and 0xffff
    private fun unsigned(bytes: ByteArray, offset: Int) =
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt(offset).toLong() and 0xffffffffL
}
