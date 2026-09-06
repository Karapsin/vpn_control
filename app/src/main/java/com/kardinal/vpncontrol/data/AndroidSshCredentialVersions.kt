package com.kardinal.vpncontrol.data

import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.StandardOpenOption.READ

/**
 * Immutable credential payloads. Staging never changes the committed version.
 * Call stage from the serialized configuration transaction and persist its returned
 * version in that same transaction. Failed commits leave harmless, unreferenced
 * versions; they are never overwritten or reused by a subsequent import.
 */
internal class AndroidSshCredentialVersions(
    private val credentials: File,
    private val syncDirectory: (File) -> Unit = { directory ->
        FileChannel.open(directory.toPath(), READ).use { it.force(true) }
    },
) {
    private val legacy = File(credentials, "home-ssh-private-key")
    private val versions = File(credentials, "home-ssh-key-versions")
    private val enabled = File(versions, "versioned")

    fun path(version: Long): String? = synchronized(lock) {
        require(version >= 0)
        val selected = if (enabled.isFile) File(versions, "$version.key") else legacy
        selected.takeIf { !Files.isSymbolicLink(it.toPath()) && it.isFile && it.length() in 1..MAX_BYTES }
            ?.absolutePath
    }

    fun stage(content: String, committedVersion: Long): Long = synchronized(lock) {
        require(committedVersion >= 0 && committedVersion < Long.MAX_VALUE)
        val normalized = normalize(content)
        path(committedVersion)?.let { current ->
            if (File(current).readText().trim() == normalized.trim()) return@synchronized committedVersion
        }
        check(!Files.isSymbolicLink(credentials.toPath()) && !Files.isSymbolicLink(versions.toPath()))
        check(versions.mkdirs() || versions.isDirectory)
        syncDirectory(credentials)
        credentials.parentFile?.let(syncDirectory)
        if (!enabled.exists()) {
            // Pin the pre-migration key before any configuration can select a new
            // version. Do not touch the legacy file while older readers use it.
            if (legacy.exists()) {
                check(!Files.isSymbolicLink(legacy.toPath()) && legacy.isFile && legacy.length() in 1..MAX_BYTES)
                val old = legacy.readBytes()
                val archived = File(versions, "$committedVersion.key")
                if (archived.exists()) check(archived.readBytes().contentEquals(old))
                else publish(archived, old)
            }
        }
        var candidate = committedVersion + 1
        while (File(versions, "$candidate.key").exists()) {
            check(candidate < Long.MAX_VALUE)
            candidate++
        }
        publish(File(versions, "$candidate.key"), normalized.toByteArray(Charsets.UTF_8))
        if (!enabled.exists()) publish(enabled, byteArrayOf(1))
        candidate
    }

    private fun publish(destination: File, bytes: ByteArray) {
        check(!destination.exists() && !Files.isSymbolicLink(destination.toPath()))
        val temporary = File.createTempFile("key-stage-", ".tmp", versions)
        try {
            check(temporary.setReadable(false, false) && temporary.setWritable(false, false))
            check(temporary.setReadable(true, true) && temporary.setWritable(true, true))
            temporary.writeBytes(bytes)
            FileChannel.open(temporary.toPath(), WRITE).use { it.force(true) }
            // Fail closed if this filesystem cannot publish atomically. Payloads
            // remain private and no committed metadata has changed at this point.
            Files.move(temporary.toPath(), destination.toPath(), ATOMIC_MOVE)
            syncDirectory(versions)
        } finally {
            temporary.delete()
        }
    }

    private fun normalize(content: String): String {
        val normalized = content.trim()
        require(normalized.isNotEmpty() && normalized.length <= 128 * 1024)
        require(normalized.lineSequence().first() in headers)
        require("Proc-Type: 4,ENCRYPTED" !in normalized)
        return "$normalized\n"
    }

    private companion object {
        val lock = Any()
        const val MAX_BYTES = 128 * 1024 * 4L + 1
        val headers = setOf("-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN DSA PRIVATE KEY-----")
    }
}
