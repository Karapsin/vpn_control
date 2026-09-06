package com.kardinal.vpncontrol.desktop

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.TRUNCATE_EXISTING
import java.nio.file.StandardOpenOption.WRITE

class DesktopHomeSshCredentialStore(
    baseDir: Path,
) {
    private val credentialFile = baseDir.resolve("credentials/home-ssh-private-key")

    fun importPrivateKey(content: String): String {
        val normalized = content.trim()
        require(normalized.isNotBlank()) { "SSH private key is empty" }
        require(normalized.length <= MAX_PRIVATE_KEY_CHARS) { "SSH private key is too large" }
        val header = normalized.lineSequence().firstOrNull().orEmpty()
        require(header in SUPPORTED_PRIVATE_KEY_HEADERS) {
            "The selected file does not look like an SSH private key"
        }
        require(header != "-----BEGIN ENCRYPTED PRIVATE KEY-----" && "Proc-Type: 4,ENCRYPTED" !in normalized) {
            "Encrypted SSH private keys are not supported"
        }
        Files.createDirectories(credentialFile.parent)
        val temporary = Files.createTempFile(credentialFile.parent, "home-ssh-key-", ".tmp")
        try {
            restrictToCurrentUser(temporary)
            Files.writeString(
                temporary,
                "$normalized\n",
                StandardCharsets.UTF_8,
                CREATE,
                TRUNCATE_EXISTING,
                WRITE,
            )
            java.nio.channels.FileChannel.open(temporary, WRITE).use { it.force(true) }
            try {
                Files.move(temporary, credentialFile, REPLACE_EXISTING, ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(temporary, credentialFile, REPLACE_EXISTING)
            }
        } finally {
            Files.deleteIfExists(temporary)
        }
        return credentialFile.toAbsolutePath().normalize().toString()
    }

    fun privateKeyPathOrNull(): String? {
        return credentialFile
            .takeIf(Files::isRegularFile)
            ?.takeIf { runCatching { Files.size(it) > 0L }.getOrDefault(false) }
            ?.toAbsolutePath()
            ?.normalize()
            ?.toString()
    }

    fun hasPrivateKey(): Boolean = privateKeyPathOrNull() != null

    /** Keep key material out of persisted state and restore it if its metadata commit fails. */
    internal fun importAndCommit(content: String, commit: (changed: Boolean) -> Result<Unit>): Result<Unit> {
        val previous = runCatching {
            require(!Files.isSymbolicLink(credentialFile))
            if (Files.exists(credentialFile)) {
                require(Files.size(credentialFile) <= MAX_PRIVATE_KEY_CHARS * 4L + 1)
                Files.readString(credentialFile)
            } else null
        }.getOrElse { return Result.failure(IllegalStateException("PERSISTENCE_FAILED")) }
        try {
            importPrivateKey(content)
        } catch (_: IllegalArgumentException) {
            return Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
        } catch (_: Exception) {
            return Result.failure(IllegalStateException("PERSISTENCE_FAILED"))
        }
        val result = runCatching { commit(previous?.trim() != content.trim()).getOrThrow() }
        if (result.isSuccess) return Result.success(Unit)
        val restored = runCatching {
            if (previous == null) Files.deleteIfExists(credentialFile) else importPrivateKey(previous)
        }
        return Result.failure(IllegalStateException(if (restored.isSuccess) "PERSISTENCE_FAILED" else "ROLLBACK_FAILED"))
    }

    private fun restrictToCurrentUser(path: Path) {
        runCatching {
            Files.setPosixFilePermissions(
                path,
                PosixFilePermissions.fromString("rw-------"),
            )
        }.recoverCatching {
            val view = Files.getFileAttributeView(path, AclFileAttributeView::class.java)
                ?: error("The platform does not expose file ACLs")
            val owner = Files.getOwner(path)
            view.acl = listOf(
                AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(owner)
                    .setPermissions(AclEntryPermission.values().toSet())
                    .build(),
            )
        }.recoverCatching {
            val file = path.toFile()
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            require(file.setReadable(true, true) && file.setWritable(true, true)) {
                "Could not restrict the SSH private key to the current user"
            }
        }.getOrThrow()
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
