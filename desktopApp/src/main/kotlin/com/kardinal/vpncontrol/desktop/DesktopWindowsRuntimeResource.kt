package com.kardinal.vpncontrol.desktop

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.WString
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.win32.StdCallLibrary
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID

internal enum class DesktopWindowsRuntimeResourceKind { CACHE, OUTPUT }

/** Bound lazily by the authoritative controller after private workspace admission. */
internal fun interface DesktopWindowsRuntimeResourceScopeProvider {
    fun current(): DesktopWindowsRuntimeResourceScope?
    fun journals(): DesktopWindowsRuntimeResourceJournalRegistry? = null
}

/** Correlation and retained-resource evidence only. Reading these records never executes work. */
internal interface DesktopWindowsRuntimeResourceJournalRegistry {
    /** Write through before native preparation; an exact repeat is harmless. Unresolved records are never evicted. */
    fun retain(job: DesktopWindowsRuntimeResourceJob)
    fun pending(scope: DesktopWindowsRuntimeResourceScope): List<DesktopWindowsRuntimeResourceJob>
    /** Called only after authoritative native reconciliation, never from an ordinary caller's phase flag. */
    fun reconcile(job: DesktopWindowsRuntimeResourceJob, disposition: DesktopWindowsRuntimeResourceJobDisposition)
}

internal enum class DesktopWindowsRuntimeResourceJobDisposition {
    NO_MUTABLE_HANDOFF,
    PUBLICATION_AND_CLEANUP_CONFIRMED,
}

internal class DesktopWindowsRuntimeResourceEntry(val resourceId: String, val kind: DesktopWindowsRuntimeResourceKind) {
    init { require(UUID.fromString(resourceId).toString() == resourceId) }
    override fun toString() = "DesktopWindowsRuntimeResourceEntry(<redacted>)"
}

internal class DesktopWindowsRuntimeResourceNativeOwner(
    val processId: Long,
    val creationFileTime: Long,
    val sid: String,
) {
    init {
        require(processId in 1..0xffffffffL && creationFileTime > 0)
        val fields = sid.split('-')
        require(fields.size in 4..18 && fields[0] == "S" && fields[1] == "1")
        require(fields.drop(2).all { it.isNotEmpty() && it.all { digit -> digit in '0'..'9' } && (it == "0" || it[0] != '0') })
        require(fields[2].toLongOrNull()?.let { it in 0..0xffffffffffffL } == true)
        require(fields.drop(3).all { it.toLongOrNull()?.let { n -> n in 0..0xffffffffL } == true })
    }
    override fun toString() = "DesktopWindowsRuntimeResourceNativeOwner(<redacted>)"
}

internal class DesktopWindowsRuntimeResourceJob(
    val jobId: String,
    val scope: DesktopWindowsRuntimeResourceScope,
    entries: List<DesktopWindowsRuntimeResourceEntry>,
    val nativeOwner: DesktopWindowsRuntimeResourceNativeOwner,
) {
    val resources = entries.toList()
    init {
        require(UUID.fromString(jobId).toString() == jobId)
        require(resources.isNotEmpty() && resources.map { it.resourceId }.distinct().size == resources.size)
    }
    override fun toString() = "DesktopWindowsRuntimeResourceJob(<redacted>)"
}

internal class DesktopWindowsRuntimeResourceScope(
    val scopeId: String,
    val controllerId: String,
    internal val record: DesktopWindowsResourceScopeRecord,
) {
    init { require(UUID.fromString(scopeId).toString() == scopeId && UUID.fromString(controllerId).toString() == controllerId) }
    override fun toString() = "DesktopWindowsRuntimeResourceScope(<redacted>)"

    companion object {
        fun recordBytes(scopeId: String): ByteArray {
            require(UUID.fromString(scopeId).toString() == scopeId)
            return "{\"schemaVersion\":1,\"scopeId\":\"$scopeId\"}".toByteArray(Charsets.UTF_8)
        }
    }
}

internal class DesktopWindowsResourceScopeRecord internal constructor(
    internal val path: String,
    internal val parentIdentity: String,
    internal val fileIdentity: String,
    internal val byteCount: Long,
    internal val sha256: String,
) {
    init {
        require(path.isNotEmpty() && path.length <= 32767 && '\u0000' !in path)
        require(parentIdentity.matches(Regex("[a-f0-9]{24}")) && fileIdentity.matches(Regex("[a-f0-9]{24}")))
        require(byteCount > 0 && sha256.matches(Regex("[a-f0-9]{64}")))
    }
    override fun toString() = "DesktopWindowsResourceScopeRecord(<redacted>)"
}

/** The ordinary owner authorizes one destination parent before requesting elevation. */
internal class DesktopWindowsResourceDestination internal constructor(
    internal val path: String,
    internal val parentIdentity: String,
) {
    init {
        require(path.isNotEmpty() && '\u0000' !in path && path.length <= 32767)
        require(parentIdentity.matches(Regex("[a-f0-9]{24}")))
    }
    override fun toString() = "DesktopWindowsResourceDestination(<redacted>)"
}

/** No caller-selected path remains in the configuration sent to the privileged runtime. */
internal class DesktopWindowsRuntimeResource(
    val id: String,
    val kind: DesktopWindowsRuntimeResourceKind,
    internal val destination: DesktopWindowsResourceDestination,
) {
    init { require(UUID.fromString(id).toString() == id) }
    val reference get() = "vpn-control-mutable:$id"
    override fun toString() = "DesktopWindowsRuntimeResource(<redacted>)"

    companion object {
        fun admit(path: Path, kind: DesktopWindowsRuntimeResourceKind) = DesktopWindowsRuntimeResource(
            UUID.randomUUID().toString(), kind, DesktopWindowsResourceAdmission.capture(path),
        )
    }
}

/** Direct original-token filesystem inspection; no shell, helper, key bytes or cache read. */
internal object DesktopWindowsResourceAdmission {
    fun capture(requested: Path): DesktopWindowsResourceDestination = withParent(requested) { _, destination -> destination }

    fun captureScopeRecord(requested: Path, scopeId: String): DesktopWindowsResourceScopeRecord = withParent(requested) { api, destination ->
        val files = JnaWindowsInstallNative()
        val handle = files.open(destination.path, WindowsInstallNative.READ, shareDelete = false)
        try {
            files.requirePrivateExport(handle, JnaWindowsInstallAdmission().currentSid())
            val expected = DesktopWindowsRuntimeResourceScope.recordBytes(scopeId)
            val bytes = files.read(handle, expected.size + 1)
            check(bytes.contentEquals(expected)) { "CONFLICT" }
            val identity = Memory(52).use { info ->
                check(api.GetFileInformationByHandle(files.retainedHandle(handle), info)) { "UNAVAILABLE" }
                nativeIdentity(info)
            }
            DesktopWindowsResourceScopeRecord(destination.path, destination.parentIdentity, identity, bytes.size.toLong(),
                MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
        } finally { files.close(handle) }
    }

    private fun <T> withParent(requested: Path, action: (Api, DesktopWindowsResourceDestination) -> T): T {
        check(System.getProperty("os.name").startsWith("Windows", true))
        val native = Native.load("kernel32", Api::class.java)
        val path = requested.toAbsolutePath().normalize()
        val leaf = requireNotNull(path.fileName) { "INVALID_ARGUMENT" }.toString()
        require(leaf.isNotEmpty() && leaf !in setOf(".", "..") && leaf.none { it in "\\/:\u0000" })
        // Resolve ordinary-user aliases before admission. Every native recheck thereafter binds
        // to this exact directory identity, including a cache captured later at commit.
        val parent = requireNotNull(path.parent).toRealPath()
        val handles = mutableListOf<WinNT.HANDLE>()
        try {
            var identity: String? = null
            for (directory in generateSequence(parent) { it.parent }.toList().asReversed()) {
                val handle = native.CreateFileW(WString(directory.toString()), 0x81, 1, null, 3, 0x02200000, null)
                if (handle == WinBase.INVALID_HANDLE_VALUE || handle.pointer == WinBase.INVALID_HANDLE_VALUE.pointer)
                    throw WindowsInstallNativeFailure(Kernel32.INSTANCE.GetLastError())
                handles += handle
                Memory(52).use { info ->
                    check(native.GetFileType(handle) == 1 && native.GetFileInformationByHandle(handle, info)) { "UNAVAILABLE" }
                    check(info.getInt(0) and 0x410 == 0x10) { "CONFLICT" }
                    Memory(65536).use { value ->
                        val length = native.GetFinalPathNameByHandleW(handle, value, 32768, 0)
                        check(length in 1 until 32768) { "UNAVAILABLE" }
                        val final = String(CharArray(length) { value.getShort(it.toLong() * 2).toInt().toChar() })
                            .let { if (it.startsWith("\\\\?\\UNC\\", true)) "\\\\" + it.drop(8) else it.removePrefix("\\\\?\\") }
                        check(final.trimEnd('\\').equals(directory.toString().trimEnd('\\'), true)) { "CONFLICT" }
                    }
                    identity = nativeIdentity(info)
                }
            }
            return action(native, DesktopWindowsResourceDestination(parent.resolve(leaf).toString(), requireNotNull(identity)))
        } finally { handles.asReversed().forEach { Kernel32.INSTANCE.CloseHandle(it) } }
    }

    private fun nativeIdentity(info: Pointer) = listOf(28L, 44L, 48L).joinToString("") { offset ->
        (info.getInt(offset).toLong() and 0xffffffffL).toString(16).padStart(8, '0')
    }

    private interface Api : StdCallLibrary {
        fun CreateFileW(path: WString, access: Int, share: Int, security: Pointer?, creation: Int,
                        flags: Int, template: WinNT.HANDLE?): WinNT.HANDLE
        fun GetFileType(handle: WinNT.HANDLE): Int
        fun GetFileInformationByHandle(handle: WinNT.HANDLE, info: Pointer): Boolean
        fun GetFinalPathNameByHandleW(handle: WinNT.HANDLE, path: Pointer, size: Int, flags: Int): Int
    }
}
