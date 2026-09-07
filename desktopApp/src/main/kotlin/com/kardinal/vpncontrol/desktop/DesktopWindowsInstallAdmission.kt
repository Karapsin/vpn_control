package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/** Normal-process read-only participation in a pre-existing protected installer gate. */
internal object DesktopWindowsInstallAdmission {
    fun enter(launcher: Path, native: WindowsAdmissionNative = JnaWindowsInstallAdmission(),
        allowPendingControl: Boolean = false, onPendingControl: () -> Unit = {}): AutoCloseable {
        val executable = DesktopWindowsInstallJobBackend.canonical(launcher.toString())
        require(executable.substringAfterLast('\\').lowercase(java.util.Locale.ROOT) in
            setOf("vpn-control.exe", "vpn-control-cli.exe")) { "Unapproved launcher" }
        val parent = executable.substringBeforeLast('\\').let { if (it.length == 2) "$it\\" else it }
        val sid = native.currentSid()
        val handles = mutableListOf<WindowsInstallNative.Handle>()
        var gate: WindowsInstallNative.Handle? = null
        var locked = false
        fun release() {
            var failure: Throwable? = null
            if (locked) {
                runCatching { native.unlockShared(requireNotNull(gate)) }.onFailure { failure = it }
                locked = false
            }
            handles.asReversed().forEach { handle -> runCatching { native.close(handle) }.onFailure { failure = failure ?: it } }
            handles.clear()
            failure?.let { throw it }
        }
        fun missing(): AutoCloseable { release(); return AutoCloseable { } }
        fun pinNonEmptyWitness(path: String, parent: WindowsInstallNative.Handle) {
            val canonicalParent = native.canonicalPath(parent).trimEnd('\\')
            for (name in native.children(path)) {
                if (name.isBlank() || name == "." || name == ".." || name.any { it in "\\/:\u0000" }) continue
                val child = runCatching { native.openDirectory(path.trimEnd('\\') + "\\" + name) }.getOrNull() ?: continue
                var retained = false
                try {
                    val info = native.inspect(child)
                    require(info.disk && info.attributes and 0x400 == 0 && info.reparseTag == 0)
                    val canonicalChild = native.canonicalPath(child)
                    require(canonicalChild.substringBeforeLast('\\') == canonicalParent) { "Unlinked ancestor witness" }
                    val currentParent = native.inspect(parent)
                    require(currentParent.disk && currentParent.directory && currentParent.attributes and 0x400 == 0 && currentParent.reparseTag == 0)
                    require(native.canonicalPath(parent).trimEnd('\\') == canonicalParent)
                    // No DELETE sharing on this retained child prevents the ancestor becoming empty;
                    // Windows rejects SET_REPARSE_POINT for a nonempty directory.
                    handles += child
                    retained = true
                    return
                } catch (_: IllegalArgumentException) {
                    // A raced/unsuitable entry proves nothing. Try another, otherwise fail closed.
                } finally { if (!retained) native.close(child) }
            }
            error("Unpinned mutable ancestor")
        }
        fun pin(path: String, application: Boolean, finalProductRoot: Boolean = false): WindowsInstallNative.Handle {
            val handle = native.openDirectory(path)
            handles += handle
            require(native.persistentAcl(handle)) { "Untrusted installation volume" }
            val info = native.inspect(handle)
            val trustedCurrent = "S-1-5-32-544"
            val policyInfo = if (application) info.copy(owner = if (info.owner == sid) trustedCurrent else info.owner,
                dacl = info.dacl?.map { if (it.sid == sid) it.copy(sid = trustedCurrent) else it }) else info
            val kind = if (finalProductRoot) WindowsInstallTrust.Kind.DIRECTORY else WindowsInstallTrust.Kind.ANCESTOR
            try { WindowsInstallTrust.verify(policyInfo, kind) }
            catch (rejection: IllegalArgumentException) {
                if (finalProductRoot) throw rejection
                // First reject every unsafe permission other than the specific attribute/EA rights.
                WindowsInstallTrust.verify(policyInfo, kind, ancestorPinnedNonEmpty = true)
                pinNonEmptyWitness(path, handle)
                val current = native.inspect(handle)
                val currentPolicy = if (application) current.copy(owner = if (current.owner == sid) trustedCurrent else current.owner,
                    dacl = current.dacl?.map { if (it.sid == sid) it.copy(sid = trustedCurrent) else it }) else current
                WindowsInstallTrust.verify(currentPolicy, kind, ancestorPinnedNonEmpty = true)
            }
            return handle
        }
        fun ancestry(path: String, application: Boolean): WindowsInstallNative.Handle {
            var prefix = path.substring(0, 3)
            var last = pin(prefix, application)
            if (path.length > 3) for (component in path.substring(3).split('\\')) {
                prefix = prefix.trimEnd('\\') + "\\" + component
                last = pin(prefix, application)
            }
            return last
        }
        try {
            val application = ancestry(parent, true)
            val id = installationId(native.invariantUppercase(native.canonicalPath(application)))
            val programData = DesktopWindowsInstallJobBackend.canonical(native.programData())
            ancestry(programData, false)
            val product = "$programData\\vpn-control-install-jobs"
            try { pin(product, false, finalProductRoot = true) }
            catch (error: WindowsInstallNativeFailure) { if (error.code == 2) return missing(); throw error }
            gate = try { native.openGate("$product\\gate-$id") }
            catch (error: WindowsInstallNativeFailure) { if (error.code == 2) return missing(); throw error }
            val retainedGate = requireNotNull(gate)
            handles += retainedGate
            require(native.persistentAcl(retainedGate)) { "Untrusted installation volume" }
            WindowsInstallTrust.verify(native.inspect(retainedGate), WindowsInstallTrust.Kind.STATUS)
            check(native.lockShared(retainedGate)) { "BUSY" }
            locked = true
            val info = native.inspect(retainedGate)
            WindowsInstallTrust.verify(info, WindowsInstallTrust.Kind.STATUS)
            require(info.size == 17L) { "Malformed installation gate" }
            val bytes = try { native.readGate(retainedGate) }
            catch (error: WindowsInstallNativeFailure) { if (error.code == 33) error("BUSY"); throw error }
            require(bytes.size == 17 && bytes.indices.all { if (it == 8) bytes[it] in 0..1 else bytes[it] == 0.toByte() }) { "Malformed installation gate" }
            // Control-only clients retain the same shared lock and all strict witnesses.
            // They cannot enter once the installer holds the exclusive replacement lock.
            check(bytes[8] == 0.toByte() || allowPendingControl) { "BUSY" }
            if (bytes[8] == 1.toByte()) onPendingControl()
            return object : AutoCloseable {
                private var closed = false
                @Synchronized override fun close() { if (!closed) { closed = true; release() } }
            }
        } catch (error: Throwable) { runCatching { release() }; throw error }
    }

    /** Input is Windows-native invariant uppercase, including the canonical extended-path prefix. */
    internal fun installationId(normalized: String): String {
        require(normalized.startsWith("\\\\?\\") && '\u0000' !in normalized)
        val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(normalized))
        val bytes = ByteArray(encoded.remaining()).also { encoded.get(it) }
        val hex = MessageDigest.getInstance("SHA-256").digest(bytes).take(16).joinToString("") { "%02x".format(it) }
        return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20, 32)}"
    }
}

internal interface WindowsAdmissionNative {
    fun currentSid(): String
    fun programData(): String
    fun openDirectory(path: String): WindowsInstallNative.Handle
    fun openGate(path: String): WindowsInstallNative.Handle
    fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo
    fun persistentAcl(handle: WindowsInstallNative.Handle): Boolean
    fun canonicalPath(handle: WindowsInstallNative.Handle): String
    fun invariantUppercase(value: String): String
    fun children(path: String): List<String>
    fun lockShared(handle: WindowsInstallNative.Handle): Boolean
    fun readGate(handle: WindowsInstallNative.Handle): ByteArray
    fun unlockShared(handle: WindowsInstallNative.Handle)
    fun close(handle: WindowsInstallNative.Handle)
}
