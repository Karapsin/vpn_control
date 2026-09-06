package com.kardinal.vpncontrol.desktop

import java.io.IOException
import java.nio.file.Path

/** Native handles, not Java symbolic-link classification, define this trust boundary. */
internal class DesktopWindowsInstallJobBackend(
    private val native: WindowsInstallNative = JnaWindowsInstallNative(),
) : DesktopInstallJobBackend {
    fun defaultRoot(): Path = Path.of(canonical(native.programData()) + "\\vpn-control-install-jobs")

    override fun openRoot(root: Path, create: Boolean): DesktopInstallJobBackend.Directory {
        val expected = canonical(defaultRoot().toString())
        val requested = canonical(root.toString())
        require(requested.equals(expected, ignoreCase = true)) { "Untrusted installer root" }
        val pins = mutableListOf<Pin>()
        try {
            val components = requested.substring(3).split('\\')
            var path = requested.substring(0, 3)
            pins += openDirectory(path, strict = false)
            components.forEachIndexed { index, component ->
                path = path.trimEnd('\\') + "\\" + component
                val final = index == components.lastIndex
                val pin = try { openDirectory(path, strict = final) } catch (error: WindowsInstallNativeFailure) {
                    if (!create || !final || error.code != 2) throw error
                    native.createDirectory(path, WindowsInstallTrust.directorySddl, allowExisting = true)
                    openDirectory(path, strict = true)
                }
                pins += pin
            }
            return Directory(requested, pins)
        } catch (error: Throwable) {
            pins.asReversed().forEach(Pin::close)
            throw error
        }
    }

    private fun openDirectory(path: String, strict: Boolean): Pin {
        val handle = native.open(path, WindowsInstallNative.INSPECT, shareDelete = false)
        try {
            WindowsInstallTrust.verify(native.inspect(handle), if (strict) WindowsInstallTrust.Kind.DIRECTORY else WindowsInstallTrust.Kind.ANCESTOR)
            return Pin(handle)
        } catch (error: Throwable) { native.close(handle); throw error }
    }

    private inner class Pin(val handle: WindowsInstallNative.Handle) {
        private var references = 1
        @Synchronized fun retain(): Pin { check(references > 0); references++; return this }
        @Synchronized fun close() { check(references > 0); if (--references == 0) native.close(handle) }
    }

    private inner class Directory(val path: String, val pins: List<Pin>) : DesktopInstallJobBackend.Directory {
        private var closed = false
        private fun ready() { check(!closed) }
        private fun child(name: String) = "$path\\$name"
        private fun retain() = pins.map(Pin::retain)
        @Synchronized override fun createJob(jobId: String): DesktopInstallJobBackend.Directory {
            ready(); require(DesktopInstallJobNames.validJob(jobId))
            native.createDirectory(child(jobId), WindowsInstallTrust.directorySddl, allowExisting = false)
            return openJob(jobId)
        }
        @Synchronized override fun openJob(jobId: String): DesktopInstallJobBackend.Directory {
            ready(); require(DesktopInstallJobNames.validJob(jobId))
            val pin = openDirectory(child(jobId), strict = true)
            return Directory(child(jobId), retain() + pin)
        }
        @Synchronized override fun createFile(name: String, purpose: DesktopInstallJobBackend.Purpose, clientPrincipal: String?): DesktopInstallJobBackend.File {
            ready(); DesktopInstallJobNames.requireCreate(name, purpose)
            require(clientPrincipal == null || purpose == DesktopInstallJobBackend.Purpose.CANCEL)
            val cancel = purpose == DesktopInstallJobBackend.Purpose.CANCEL
            val sddl = if (cancel) WindowsInstallTrust.cancelSddl(clientPrincipal) else WindowsInstallTrust.statusSddl
            return file(name, WindowsInstallNative.READ_WRITE, create = true, sddl = sddl,
                cancel = cancel, clientPrincipal = clientPrincipal, cancelWrite = if (cancel) 0 else null)
        }
        @Synchronized override fun openFile(name: String, write: Boolean): DesktopInstallJobBackend.File {
            ready(); DesktopInstallJobNames.requireReadable(name)
            require(!write || name == DesktopInstallJobNames.CANCEL)
            return file(name, if (write) WindowsInstallNative.READ_WRITE else WindowsInstallNative.READ,
                cancel = name == DesktopInstallJobNames.CANCEL, cancelWrite = if (write) 1 else null)
        }
        private fun file(name: String, access: Int, create: Boolean = false, sddl: String? = null,
            cancel: Boolean, clientPrincipal: String? = null, cancelWrite: Int? = null): File {
            val handle = native.open(child(name), access, shareDelete = !cancel, createSddl = if (create) requireNotNull(sddl) else null)
            try {
                val info = native.inspect(handle)
                WindowsInstallTrust.verify(info, if (cancel) WindowsInstallTrust.Kind.CANCEL else WindowsInstallTrust.Kind.STATUS, clientPrincipal)
                if (cancel && !create) require(info.size == 1L) { "Invalid cancellation file" }
                return File(handle, retain(), cancel, access == WindowsInstallNative.READ_WRITE, cancelWrite)
            } catch (error: Throwable) { native.close(handle); throw error }
        }
        @Synchronized override fun replaceFile(tempName: String, targetName: String) {
            ready(); require(DesktopInstallJobNames.validTemp(tempName) && targetName == DesktopInstallJobNames.STATUS)
            // Validate an existing destination too; the pinned strict directory excludes user substitution.
            try { openFile(targetName).close() } catch (error: WindowsInstallNativeFailure) { if (error.code != 2) throw error }
            val source = native.open(child(tempName), WindowsInstallNative.DELETE, shareDelete = true)
            try {
                WindowsInstallTrust.verify(native.inspect(source), WindowsInstallTrust.Kind.STATUS)
                native.rename(source, pins.last().handle, targetName)
            } finally { native.close(source) }
        }
        @Synchronized override fun deleteFile(name: String) {
            ready(); require(name == DesktopInstallJobNames.STATUS || name == DesktopInstallJobNames.CANCEL || DesktopInstallJobNames.validTemp(name))
            val handle = native.open(child(name), WindowsInstallNative.DELETE, shareDelete = true)
            try {
                WindowsInstallTrust.verify(native.inspect(handle), if (name == DesktopInstallJobNames.CANCEL) WindowsInstallTrust.Kind.CANCEL else WindowsInstallTrust.Kind.STATUS)
                native.delete(handle)
            } finally { native.close(handle) }
        }
        @Synchronized override fun close() { if (!closed) { closed = true; pins.asReversed().forEach(Pin::close) } }
    }

    private inner class File(val handle: WindowsInstallNative.Handle, val pins: List<Pin>,
        val cancel: Boolean, val writable: Boolean, val cancelWrite: Int?) : DesktopInstallJobBackend.File {
        private var closed = false
        @Synchronized override fun readBounded(maxBytes: Int): ByteArray {
            check(!closed); require(maxBytes in 0..1_048_576)
            val info = native.inspect(handle)
            WindowsInstallTrust.verify(info, if (cancel) WindowsInstallTrust.Kind.CANCEL else WindowsInstallTrust.Kind.STATUS)
            require(info.size <= maxBytes && (!cancel || info.size == 1L)) { "Installer file exceeds bound" }
            val bytes = native.read(handle, maxBytes + 1)
            require(bytes.size <= maxBytes && native.inspect(handle).size <= maxBytes) { "Installer file grew beyond bound" }
            return bytes
        }
        @Synchronized override fun writeExact(bytes: ByteArray) {
            check(!closed && writable); require(bytes.size <= 1_048_576)
            if (cancel) require(bytes.size == 1 && bytes[0].toInt() == cancelWrite) { "Invalid cancellation write" }
            WindowsInstallTrust.verify(native.inspect(handle), if (cancel) WindowsInstallTrust.Kind.CANCEL else WindowsInstallTrust.Kind.STATUS)
            native.writeAndSync(handle, bytes)
        }
        @Synchronized override fun close() {
            if (!closed) { closed = true; try { native.close(handle) } finally { pins.asReversed().forEach(Pin::close) } }
        }
    }

    companion object {
        internal fun canonical(path: String): String {
            val value = path.replace('/', '\\')
            require(Regex("^[A-Za-z]:\\\\[^:]*$").matches(value)) { "Only local absolute DOS paths are supported" }
            require(value.length <= 240 && !value.any { it.code < 32 })
            val components = value.substring(3).split('\\')
            require(components.all { it.isNotBlank() && it != "." && it != ".." && !it.endsWith('.') && !it.endsWith(' ') })
            require(components.none { Regex("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\..*)?").matches(it) })
            return value
        }
    }
}

internal data class WindowsInstallAce(val type: Int, val flags: Int, val mask: Int, val sid: String)
internal data class WindowsInstallInfo(val directory: Boolean, val attributes: Int = 0, val reparseTag: Int = 0,
    val owner: String, val dacl: List<WindowsInstallAce>?, val size: Long = 0, val links: Int = 1, val disk: Boolean = true)

internal object WindowsInstallTrust {
    enum class Kind { ANCESTOR, DIRECTORY, STATUS, CANCEL }
    private val trusted = setOf("S-1-5-18", "S-1-5-32-544")
    // Windows may own the volume root through this exact service identity. This
    // exception grants neither product-object ownership nor additional ACE rights.
    private const val TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    private const val WRITE_DATA = 0x2
    private const val CHILD_CREATION = 0x6
    private const val MUTATION = 0x500D0156 // GENERIC_WRITE/ALL, DELETE, WRITE_DAC/OWNER, write/append/EA/attributes/delete-child
    private const val INHERIT_ONLY = 0x8
    private const val CLIENT_MASK = 0x00120083 // Read/write data, read attributes/control, synchronize; nothing else.
    private val READ_MASK = 0xA01200A9.toInt() // Generic read/execute plus their concrete file rights.
    val directorySddl = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
    val statusSddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)"
    fun cancelSddl(principal: String?): String {
        require(principal == null || validClientSid(principal))
        return "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" +
            if (principal == null) "" else "(A;;0x00120083;;;$principal)"
    }
    private fun validClientSid(sid: String) = Regex("S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+").matches(sid)

    fun verify(info: WindowsInstallInfo, kind: Kind, expectedClient: String? = null) {
        require(info.disk && info.attributes and 0x400 == 0 && info.reparseTag == 0) { "Reparse/device path rejected" }
        require(info.owner in trusted || kind == Kind.ANCESTOR && info.owner == TRUSTED_INSTALLER) { "Untrusted installer owner" }
        require(info.directory == (kind == Kind.ANCESTOR || kind == Kind.DIRECTORY)) { "Unexpected installer object type" }
        require(info.directory || info.links == 1) { "Hard-linked installer file rejected" }
        val acl = requireNotNull(info.dacl) { "Unrestricted installer DACL" }
        val writers = mutableSetOf<String>()
        for (ace in acl) {
            require(ace.type == 0 || ace.type == 1) { "Unsupported installer ACE" }
            if (ace.flags and INHERIT_ONLY != 0 || ace.type == 1 || ace.sid in trusted) continue
            val allowed = READ_MASK or when (kind) { Kind.ANCESTOR -> CHILD_CREATION; Kind.CANCEL -> WRITE_DATA; else -> 0 }
            require(ace.mask and allowed.inv() == 0) { "Unsupported installer access mask" }
            val dangerous = ace.mask and MUTATION
            if (kind == Kind.ANCESTOR && dangerous and CHILD_CREATION.inv() == 0) continue
            if (kind == Kind.CANCEL && dangerous == WRITE_DATA && ace.mask and CLIENT_MASK.inv() == 0 && validClientSid(ace.sid)) {
                writers += ace.sid
                continue
            }
            require(dangerous == 0) { "Untrusted installer mutation rights" }
        }
        require(writers.size <= 1 && (expectedClient == null || writers == setOf(expectedClient))) { "Unexpected cancellation principal" }
    }
}

internal class WindowsInstallNativeFailure(val code: Int) : IOException("Windows installer IPC failed ($code)")

/** Injectable boundary lets deterministic tests verify flags, native metadata rejection and handle lifetime. */
internal interface WindowsInstallNative {
    interface Handle
    fun programData(): String
    fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String? = null): Handle
    fun createDirectory(path: String, sddl: String, allowExisting: Boolean)
    fun inspect(handle: Handle): WindowsInstallInfo
    fun read(handle: Handle, limit: Int): ByteArray
    fun writeAndSync(handle: Handle, bytes: ByteArray)
    fun rename(handle: Handle, directory: Handle, name: String)
    fun delete(handle: Handle)
    fun close(handle: Handle)
    companion object { const val INSPECT = 0; const val READ = 1; const val READ_WRITE = 2; const val DELETE = 3 }
}
