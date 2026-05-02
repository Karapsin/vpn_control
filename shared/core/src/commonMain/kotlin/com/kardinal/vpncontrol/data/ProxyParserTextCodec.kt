package com.kardinal.vpncontrol.data

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
internal fun decodeLooseBase64(data: ByteArray): String {
    val compact = data.decodeToString().replace("\\s+".toRegex(), "")
    return decodeBase64(compact).decodeToString()
}

@OptIn(ExperimentalEncodingApi::class)
internal fun decodeMaybeBase64(raw: String): String {
    val compact = raw.trim()
    return runCatching { decodeBase64(compact).decodeToString() }
        .getOrElse { compact.decodeUrlComponent() }
}

@OptIn(ExperimentalEncodingApi::class)
private fun decodeBase64(raw: String): ByteArray {
    val normalized = raw.replace("\\s+".toRegex(), "")
    val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
    return runCatching {
        Base64.Default.decode(padded)
    }.recoverCatching {
        Base64.UrlSafe.decode(padded)
    }.getOrThrow()
}

internal fun removeScheme(value: String, scheme: String): String {
    return value.substring(scheme.length)
}

internal fun splitOnce(value: String, delimiter: Char): Pair<String, String?> {
    val index = value.indexOf(delimiter)
    return if (index == -1) {
        value to null
    } else {
        value.substring(0, index) to value.substring(index + 1)
    }
}

internal fun String.decodeUrlComponent(): String {
    if ('%' !in this && '+' !in this) return this
    val output = StringBuilder(length)
    val bytes = mutableListOf<Byte>()

    fun flushBytes() {
        if (bytes.isEmpty()) return
        output.append(bytes.toByteArray().decodeToString())
        bytes.clear()
    }

    var index = 0
    while (index < length) {
        val char = this[index]
        when {
            char == '%' && index + 2 < length -> {
                val byte = hexByteOrNull(this[index + 1], this[index + 2])
                if (byte != null) {
                    bytes += byte
                    index += 3
                    continue
                }
                flushBytes()
                output.append(char)
                index += 1
            }
            char == '+' -> {
                flushBytes()
                output.append(' ')
                index += 1
            }
            else -> {
                flushBytes()
                output.append(char)
                index += 1
            }
        }
    }
    flushBytes()
    return output.toString()
}

internal fun String.encodeUrlComponent(): String {
    val output = StringBuilder(length)
    encodeToByteArray().forEach { byte ->
        val value = byte.toInt() and 0xFF
        if (isUnreservedUrlByte(value)) {
            output.append(value.toChar())
        } else {
            output.append('%')
            output.append(HEX_DIGITS[value ushr 4])
            output.append(HEX_DIGITS[value and 0x0F])
        }
    }
    return output.toString()
}

private fun isUnreservedUrlByte(value: Int): Boolean {
    return value in 'a'.code..'z'.code ||
        value in 'A'.code..'Z'.code ||
        value in '0'.code..'9'.code ||
        value == '-'.code ||
        value == '_'.code ||
        value == '.'.code ||
        value == '~'.code
}

private fun hexByteOrNull(first: Char, second: Char): Byte? {
    val high = first.digitToIntOrNull(16) ?: return null
    val low = second.digitToIntOrNull(16) ?: return null
    return ((high shl 4) or low).toByte()
}

private val HEX_DIGITS = "0123456789ABCDEF"
