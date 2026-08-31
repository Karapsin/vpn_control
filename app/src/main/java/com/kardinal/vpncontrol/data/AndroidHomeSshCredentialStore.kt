package com.kardinal.vpncontrol.data

import android.content.Context
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING

class AndroidHomeSshCredentialStore(
    context: Context,
) {
    private val credentialFile = File(context.filesDir, "credentials/home-ssh-private-key")

    fun importPrivateKey(content: String): String {
        val normalized = content.trim().takeIf(String::isNotBlank)
            ?: error("SSH private key is empty")
        require(normalized.length <= MAX_PRIVATE_KEY_CHARS) { "SSH private key is too large" }
        val header = normalized.lineSequence().firstOrNull().orEmpty()
        require(header in SUPPORTED_PRIVATE_KEY_HEADERS) {
            "The selected file does not look like an SSH private key"
        }
        require(header != "-----BEGIN ENCRYPTED PRIVATE KEY-----" && "Proc-Type: 4,ENCRYPTED" !in normalized) {
            "Encrypted SSH private keys are not supported"
        }
        credentialFile.parentFile?.mkdirs()
        val temporary = File.createTempFile("home-ssh-key-", ".tmp", credentialFile.parentFile)
        try {
            temporary.writeText("$normalized\n")
            restrictToOwner(temporary)
            runCatching {
                Files.move(temporary.toPath(), credentialFile.toPath(), REPLACE_EXISTING, ATOMIC_MOVE)
            }.recoverCatching {
                Files.move(temporary.toPath(), credentialFile.toPath(), REPLACE_EXISTING)
            }.getOrThrow()
            restrictToOwner(credentialFile)
        } finally {
            temporary.delete()
        }
        return credentialFile.absolutePath
    }

    fun privateKeyPathOrNull(): String? {
        return credentialFile.takeIf { it.isFile && it.length() > 0L }?.absolutePath
    }

    fun hasPrivateKey(): Boolean = privateKeyPathOrNull() != null

    private fun restrictToOwner(file: File) {
        file.setReadable(false, false)
        file.setWritable(false, false)
        file.setExecutable(false, false)
        require(file.setReadable(true, true) && file.setWritable(true, true)) {
            "Could not restrict the SSH private key to the app"
        }
    }

    private companion object {
        const val MAX_PRIVATE_KEY_CHARS = 128 * 1024
        val SUPPORTED_PRIVATE_KEY_HEADERS = setOf(
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
        )
    }
}
