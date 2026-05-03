package com.kardinal.vpncontrol.model

internal object StatusMessageCodec {
    private const val PREFIX = "vpn-control-status:v1:"

    fun encode(
        key: StatusMessageKey,
        vararg args: String,
    ): String = buildString {
        append(PREFIX)
        append(key.name)
        if (args.isNotEmpty()) {
            append(':')
            append(args.joinToString(separator = "|", transform = ::escapeArg))
        }
    }

    fun decode(raw: String): StructuredStatusMessage? {
        if (!raw.startsWith(PREFIX)) return null
        val payload = raw.removePrefix(PREFIX)
        val keyName = payload.substringBefore(':')
        val key = StatusMessageKey.entries.firstOrNull { it.name == keyName } ?: return null
        val encodedArgs = payload.substringAfter(':', missingDelimiterValue = "")
        val args = if (encodedArgs.isBlank()) {
            emptyList()
        } else {
            encodedArgs.split('|').map(::unescapeArg)
        }
        return StructuredStatusMessage(key, args)
    }

    private fun escapeArg(value: String): String = buildString {
        value.forEach { char ->
            when (char) {
                '%' -> append("%25")
                '|' -> append("%7C")
                ':' -> append("%3A")
                '\n' -> append("%0A")
                '\r' -> append("%0D")
                else -> append(char)
            }
        }
    }

    private fun unescapeArg(value: String): String {
        val builder = StringBuilder()
        var index = 0
        while (index < value.length) {
            if (value[index] == '%' && index + 2 < value.length) {
                when (value.substring(index + 1, index + 3)) {
                    "25" -> {
                        builder.append('%')
                        index += 3
                        continue
                    }
                    "7C" -> {
                        builder.append('|')
                        index += 3
                        continue
                    }
                    "3A" -> {
                        builder.append(':')
                        index += 3
                        continue
                    }
                    "0A" -> {
                        builder.append('\n')
                        index += 3
                        continue
                    }
                    "0D" -> {
                        builder.append('\r')
                        index += 3
                        continue
                    }
                }
            }
            builder.append(value[index])
            index += 1
        }
        return builder.toString()
    }
}
