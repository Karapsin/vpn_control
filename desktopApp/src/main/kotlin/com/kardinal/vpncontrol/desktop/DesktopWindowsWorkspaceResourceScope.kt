package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.util.UUID

/** Lazy workspace identity; binding an ordinary controller performs no filesystem work. */
internal class DesktopWindowsWorkspaceResourceScope(
    workspace: Path,
    private val controllerId: String,
    private val read: (Path) -> ByteArray = ::readScopeRecord,
    private val publish: (Path, ByteArray) -> Result<Unit> = { path, bytes -> DesktopPrivateExportWriter.write(path.toString(), bytes) },
    private val admit: (Path, String) -> DesktopWindowsResourceScopeRecord = DesktopWindowsResourceAdmission::captureScopeRecord,
    private val newScopeId: () -> String = { UUID.randomUUID().toString() },
) : DesktopWindowsRuntimeResourceScopeProvider {
    private val path = workspace.toAbsolutePath().normalize().resolve("runtime-resource-scope.json")
    private var established: DesktopWindowsRuntimeResourceScope? = null
    private val registry by lazy { DesktopWindowsWorkspaceResourceJournalRegistry(path.parent, ::current) }
    override fun journals(): DesktopWindowsRuntimeResourceJournalRegistry = registry

    init { require(UUID.fromString(controllerId).toString() == controllerId) }

    @Synchronized override fun current(): DesktopWindowsRuntimeResourceScope {
        val existing = established
        val scopeId = existing?.scopeId ?: decode(loadOrCreate())
        val proof = admit(path, scopeId)
        if (existing != null) {
            val original = existing.record
            check(proof.path == original.path && proof.parentIdentity == original.parentIdentity &&
                proof.fileIdentity == original.fileIdentity && proof.byteCount == original.byteCount &&
                proof.sha256 == original.sha256) { "CONFLICT" }
            return existing
        }
        return DesktopWindowsRuntimeResourceScope(scopeId, controllerId, proof).also { established = it }
    }

    private fun loadOrCreate(): ByteArray = try {
        read(path)
    } catch (_: NoSuchFileException) {
        val bytes = DesktopWindowsRuntimeResourceScope.recordBytes(newScopeId())
        val failure = publish(path, bytes).exceptionOrNull()
        if (failure != null && failure !is FileAlreadyExistsException &&
            !(failure is WindowsInstallNativeFailure && failure.code in setOf(80, 183))) throw failure
        // A racing creator may win, but a private scope is never overwritten or repaired.
        read(path)
    }

    private fun decode(bytes: ByteArray): String {
        require(bytes.size <= 128) { "CONFLICT" }
        val match = Regex("\\{\"schemaVersion\":1,\"scopeId\":\"([a-f0-9-]{36})\"}").matchEntire(bytes.toString(Charsets.UTF_8))
            ?: error("CONFLICT")
        val id = match.groupValues[1]
        check(bytes.contentEquals(DesktopWindowsRuntimeResourceScope.recordBytes(id))) { "CONFLICT" }
        return id
    }
}

private fun readScopeRecord(path: Path): ByteArray = Files.newByteChannel(path,
    setOf(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)).use { channel ->
    val bytes = ByteBuffer.allocate(129)
    while (bytes.hasRemaining()) {
        val count = channel.read(bytes)
        if (count < 0) break
        check(count > 0) { "UNAVAILABLE" }
    }
    check(bytes.position() <= 128) { "CONFLICT" }
    bytes.array().copyOf(bytes.position())
}
