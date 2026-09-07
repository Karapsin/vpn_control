package com.kardinal.vpncontrol.data

import java.util.Base64
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Validate with the bundled SSH implementation before publishing any credential bytes. */
internal object AndroidSshPrivateKeyValidation {
    fun normalize(content: String): String {
        val normalized = content.trim()
        require(normalized.isNotEmpty() && normalized.length <= 128 * 1024)
        val lines = normalized.lines()
        val header = lines.first()
        require(header in headers && lines.size >= 3)
        require(lines.last() == header.replace("BEGIN", "END"))
        val body = buildString {
            for (line in lines.subList(1, lines.lastIndex)) for (character in line) {
                if (character != ' ' && character != '\t') append(character)
            }
        }
        require(body.isNotEmpty())
        // PEM's Base64 layer is checked even in storage-only tests. Algorithm,
        // encryption and complete key structure remain the bundled runtime's job.
        val decoded = Base64.getDecoder().decode(body)
        try { require(decoded.isNotEmpty()) } finally { decoded.fill(0) }
        return "$normalized\n"
    }

    fun validateRuntime(content: String, checkConfig: (String) -> Unit = io.nekohasekai.libbox.Libbox::checkConfig) {
        val configuration = JsonObject(mapOf(
            "log" to JsonObject(mapOf("disabled" to JsonPrimitive(true))),
            "outbounds" to JsonArray(listOf(JsonObject(mapOf(
                "type" to JsonPrimitive("ssh"), "tag" to JsonPrimitive("credential-validation"),
                "server" to JsonPrimitive("127.0.0.1"), "server_port" to JsonPrimitive(9),
                "user" to JsonPrimitive("credential-validation"),
                "private_key" to JsonArray(listOf(JsonPrimitive(content))),
            )))),
        )).toString()
        // checkConfig constructs and closes an unstarted service. It parses the
        // key without contacting the placeholder server or changing live traffic.
        try { checkConfig(configuration) }
        catch (_: Exception) { throw IllegalArgumentException("Invalid SSH private key") }
    }

    private val headers = setOf("-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----")
}
