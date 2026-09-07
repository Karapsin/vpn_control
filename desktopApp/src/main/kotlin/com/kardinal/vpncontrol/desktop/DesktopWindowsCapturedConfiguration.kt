package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.util.UUID

/** Private immutable input captured using the ordinary owner's filesystem authority. */
internal class DesktopWindowsCapturedConfiguration internal constructor(
    private var configuration: String,
    private val capturedResources: List<DesktopWindowsCapturedResource>,
    mutableResources: List<DesktopWindowsRuntimeResource> = emptyList(),
) : AutoCloseable {
    internal val mutableResources = mutableResources.toList()
    private var closed = false
    private var readers = 0
    private var erased = false

    internal fun <T> withSnapshot(action: (String, List<DesktopWindowsCapturedResource>) -> T): T {
        val snapshot = synchronized(this) {
            check(!closed) { "Captured configuration is closed" }
            readers++
            configuration
        }
        try { return action(snapshot, capturedResources) }
        finally { synchronized(this) { readers--; eraseWhenUnused() } }
    }

    internal fun <T> consumeSnapshot(action: (String, List<DesktopWindowsCapturedResource>) -> T): T {
        val snapshot = synchronized(this) {
            check(!closed && readers == 0) { "CONFLICT" }
            closed = true
            readers++
            configuration
        }
        try { return action(snapshot, capturedResources) }
        finally { synchronized(this) { readers--; eraseWhenUnused() } }
    }

    @Synchronized override fun close() { closed = true; eraseWhenUnused() }

    private fun eraseWhenUnused() {
        if (!closed || readers != 0 || erased) return
        var failure: Exception? = null
        capturedResources.forEach { resource ->
            try { resource.close() } catch (error: Exception) { failure = failure ?: error }
        }
        configuration = ""
        if (failure == null) erased = true
        failure?.let { throw it }
    }

    override fun toString() = "DesktopWindowsCapturedConfiguration(<redacted>)"
}

/** Only opaque identifiers and bounded reads cross into the privileged broker. */
internal class DesktopWindowsCapturedResource internal constructor(
    val id: String,
    val extension: String,
    val byteCount: Long,
    val sha256: String,
    private val spool: com.kardinal.vpncontrol.control.ControlTransferSpool,
) : AutoCloseable {
    val reference get() = "vpn-control-resource:$id"
    fun read(offset: Long, length: Int): ByteArray = spool.read(offset, length)
    override fun close() = spool.erase()
    override fun toString() = "DesktopWindowsCapturedResource(<redacted>)"

    companion object {
        fun capture(path: Path, spoolParent: Path): DesktopWindowsCapturedResource {
            // Resolve aliases while still ordinary. The privileged helper never receives this path.
            val source = path.toRealPath()
            val before = Files.readAttributes(source, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            require(before.isRegularFile) { "UNSUPPORTED" }
            val spool = DesktopControlTransferSpool.create(spoolParent)
            try {
                var count = 0L
                Files.newByteChannel(source, setOf(StandardOpenOption.READ, NOFOLLOW_LINKS)).use { input ->
                    val buffer = ByteBuffer.allocate(65536)
                    while (true) {
                        buffer.clear()
                        val received = input.read(buffer)
                        if (received == -1) break
                        check(received > 0) { "UNAVAILABLE" }
                        spool.append(buffer.array().copyOf(received))
                        count = Math.addExact(count, received.toLong())
                    }
                }
                val after = Files.readAttributes(source, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                check(before.fileKey() == after.fileKey() && before.size() == count && after.size() == count &&
                    before.lastModifiedTime() == after.lastModifiedTime()) { "CONFLICT" }
                // Local rule-set format inference depends on these suffixes. Other supported readers
                // consume bytes independently of the original filename; no caller filename crosses.
                val extension = source.fileName.toString().let { when {
                    it.endsWith(".srs") -> ".srs"
                    it.endsWith(".json") -> ".json"
                    else -> ".bin"
                } }
                return DesktopWindowsCapturedResource(UUID.randomUUID().toString(), extension,
                    count, spool.sha256(), spool)
            } catch (failure: Throwable) {
                try { spool.erase() } catch (cleanup: Exception) { failure.addSuppressed(cleanup) }
                throw failure
            }
        }
    }
}
