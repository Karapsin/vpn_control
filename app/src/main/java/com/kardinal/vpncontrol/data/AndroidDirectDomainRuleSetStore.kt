package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.BasicFileAttributes
import java.security.DigestOutputStream
import java.security.MessageDigest

/**
 * App-private, content-addressed sing-box source rule sets for generated direct
 * domains. A lease never deletes its file: deletion is an explicit, stopped-only
 * reconciliation step so an uncertain native runtime keeps all of its inputs.
 */
internal class AndroidDirectDomainRuleSetStore(
    directory: File,
    private val openOutput: (File) -> OutputStream = ::FileOutputStream,
) {
    private val directory = prepareDirectory(directory)
    private val directoryIdentity = directoryKey(this.directory.toPath())
    private val leases = mutableMapOf<String, Int>()

    internal class Lease internal constructor(
        private val store: AndroidDirectDomainRuleSetStore,
        val path: String,
    ) : AutoCloseable {
        private var closed = false

        @Synchronized fun retain(): Lease {
            check(!closed) { "Rule-set lease is closed" }
            return store.retain(path)
        }

        @Synchronized override fun close() {
            if (closed) return
            closed = true
            store.release(path)
        }
    }

    /** Returns null when generated direct-domain routing is intentionally absent. */
    @Synchronized fun stage(routing: RoutingRules): Lease? {
        assertDirectoryIdentity()
        if (routing.ignoreRules || routing.directDomainSuffixes.isEmpty()) return null
        val temporary = File.createTempFile("direct-domains-", ".tmp", directory)
        try {
            makePrivate(temporary, executable = false)
            val digest = MessageDigest.getInstance("SHA-256")
            var empty = true
            DigestOutputStream(BufferedOutputStream(openOutput(temporary)), digest).writer(Charsets.UTF_8).use { writer ->
                writer.write("{\"version\":1,\"rules\":[{\"domain_suffix\":[")
                canonicalDomains(routing).forEach { domain ->
                    if (!empty) writer.write(','.code) else empty = false
                    writeJsonString(writer, domain)
                }
                writer.write("]}]}")
            }
            if (empty) { Files.delete(temporary.toPath()); return null }
            FileChannel.open(temporary.toPath(), WRITE).use { it.force(true) }
            val target = File(directory, digest.digest().joinToString("") { "%02x".format(it) } + ".json")
            if (target.exists()) {
                verifyOwned(target)
                Files.deleteIfExists(temporary.toPath())
            } else {
                if (!publishNew(temporary, target)) {
                    verifyOwned(target)
                    Files.deleteIfExists(temporary.toPath())
                }
                verifyOwned(target)
            }
            return retain(target.canonicalPath)
        } catch (failure: Throwable) {
            runCatching { Files.deleteIfExists(temporary.toPath()) }
            throw failure
        }
    }

    /** Only the reserved generated definition can carry a private runtime asset. */
    fun pathFromConfig(config: String): String? {
        if (!config.contains(SingBoxRouteDnsBuilder.LOCAL_DIRECT_DOMAINS_TAG)) return null
        val definitions = org.json.JSONObject(config).optJSONObject("route")?.optJSONArray("rule_set") ?: return null
        var result: String? = null
        for (index in 0 until definitions.length()) {
            val definition = definitions.getJSONObject(index)
            if (definition.optString("tag") != SingBoxRouteDnsBuilder.LOCAL_DIRECT_DOMAINS_TAG) continue
            // A user CUSTOM config may independently use this tag. Only a local
            // reference into our private store identifies one of our generated assets.
            if (definition.optString("type") != "local") continue
            val candidate = File(definition.optString("path"))
            if (!candidate.toPath().isAbsolute || candidate.toPath().parent != directory.toPath()) continue
            require(result == null && definition.getString("format") == "source") {
                "Invalid generated direct rule-set definition"
            }
            result = ownedPath(candidate)
        }
        return result
    }

    fun acquireFromConfig(config: String): Lease? = pathFromConfig(config)?.let(::acquire)

    /** Acquires only a complete immutable file published by this directory. */
    @Synchronized fun acquire(path: String): Lease {
        assertDirectoryIdentity()
        return retain(verifyOwned(File(path)).canonicalPath)
    }

    /** Call only after authoritative STOPPED; foreign and malformed children are untouched. */
    @Synchronized fun prune(protectedPaths: Set<String>) {
        assertDirectoryIdentity()
        val protected = protectedPaths.mapNotNull { path ->
            runCatching { ownedPath(File(path)) }.getOrNull()
        }.toSet()
        directory.listFiles()?.forEach { candidate ->
            val canonical = runCatching { ownedPath(candidate) }.getOrNull() ?: return@forEach
            if (canonical !in protected && (leases[canonical] ?: 0) == 0) {
                // A hash-shaped name alone does not establish ownership of a
                // directory or damaged/foreign file. Preserve that evidence.
                if (runCatching { verifyOwned(candidate) }.isFailure) return@forEach
                Files.deleteIfExists(candidate.toPath())
            }
        }
    }

    @Synchronized private fun retain(path: String): Lease {
        leases[path] = (leases[path] ?: 0) + 1
        return Lease(this, path)
    }

    @Synchronized private fun release(path: String) {
        val current = requireNotNull(leases[path]) { "Unknown rule-set lease" }
        if (current == 1) leases.remove(path) else leases[path] = current - 1
    }

    private fun verifyOwned(candidate: File): File {
        val path = ownedPath(candidate)
        require(candidate.isFile && !Files.isSymbolicLink(candidate.toPath())) { "Invalid direct rule-set file" }
        requirePrivateFile(candidate.toPath())
        val expected = candidate.name.removeSuffix(".json")
        val digest = MessageDigest.getInstance("SHA-256")
        candidate.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        require(actual == expected) { "Direct rule-set digest mismatch" }
        return File(path)
    }

    private fun requirePrivateFile(path: Path) {
        val permissions = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS)
        require(permissions == setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)) {
            "Direct rule-set file is not private"
        }
    }

    private fun ownedPath(candidate: File): String {
        assertDirectoryIdentity()
        val path = candidate.toPath()
        require(path.isAbsolute && path.parent == directory.toPath()) { "Foreign direct rule-set path" }
        require(FILE_NAME.matches(candidate.name)) { "Invalid direct rule-set name" }
        require(!Files.isSymbolicLink(path)) { "Symlinked direct rule-set file" }
        return path.toString()
    }

    private fun assertDirectoryIdentity() {
        val path = directory.toPath()
        require(Files.isDirectory(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            directoryKey(path) == directoryIdentity) { "Direct rule-set directory changed" }
    }

    private fun publishNew(temporary: File, target: File): Boolean {
        assertDirectoryIdentity()
        // Android app policy may deny hard links. Exclusive native rename keeps
        // publication atomic without permitting replacement of a raced target.
        return AndroidNativePublication.publishNew(temporary, target)
    }

    private fun canonicalDomains(routing: RoutingRules): Iterable<String> {
        val values = routing.directDomainSuffixes
        if (values is AndroidPersistedDomainSuffixes) {
            // The persisted view is already normalized and distinct without retaining tokens.
            return Iterable {
                object : Iterator<String> {
                    private var index = 0
                    override fun hasNext(): Boolean = index < values.size
                    override fun next(): String = requireNotNull(toDomainSuffix(values[index++]))
                }
            }
        }
        val seen = LinkedHashSet<String>()
        values.forEach { value -> toDomainSuffix(value)?.let(seen::add) }
        return seen
    }

    private fun toDomainSuffix(value: String): String? {
        val normalized = value.removePrefix("*.").trimStart('.').trimEnd('.').lowercase()
        return normalized.takeIf { it.isNotBlank() }?.let { ".$it" }
    }

    private fun writeJsonString(writer: java.io.Writer, value: String) {
        writer.write('"'.code)
        value.forEach { character ->
            when (character) {
                '"' -> writer.write("\\\"")
                '\\' -> writer.write("\\\\")
                '\b' -> writer.write("\\b")
                '\u000c' -> writer.write("\\f")
                '\n' -> writer.write("\\n")
                '\r' -> writer.write("\\r")
                '\t' -> writer.write("\\t")
                else -> if (character.code < 0x20 || character.isSurrogate()) writer.write("\\u%04x".format(character.code))
                else writer.write(character.code)
            }
        }
        writer.write('"'.code)
    }

    companion object {
        private val FILE_NAME = Regex("[0-9a-f]{64}\\.json")

        private fun directoryKey(path: Path): Any = requireNotNull(
            Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey(),
        ) { "Direct rule-set directory has no stable identity" }

        private fun prepareDirectory(value: File): File {
            val path = value.toPath().toAbsolutePath()
            if (!Files.exists(path, NOFOLLOW_LINKS)) {
                Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            require(Files.isDirectory(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path)) { "Invalid direct rule-set directory" }
            val permissions = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS)
            require(permissions == setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE)) { "Direct rule-set directory is not private" }
            return path.toFile().canonicalFile
        }

        private fun makePrivate(file: File, executable: Boolean) {
            require(file.setReadable(false, false) && file.setWritable(false, false) && file.setExecutable(false, false)) {
                "Cannot clear direct rule-set permissions"
            }
            require(file.setReadable(true, true) && file.setWritable(true, true) &&
                (!executable || file.setExecutable(true, true))) { "Cannot make direct rule-set private" }
        }
    }
}
