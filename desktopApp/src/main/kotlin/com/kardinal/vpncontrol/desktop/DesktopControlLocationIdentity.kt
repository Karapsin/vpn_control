package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom

/** Owner-local opaque configuration identities, not exposed profile links or persistent row IDs. */
internal class DesktopControlLocationIdentity {
    private val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }

    fun id(source: String, content: String): String? {
        if (content.isBlank()) return null
        val sourceBytes = source.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        digest.update(ByteBuffer.allocate(4).putInt(sourceBytes.size).array())
        digest.update(sourceBytes)
        return digest.digest(content.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) }
    }
}
