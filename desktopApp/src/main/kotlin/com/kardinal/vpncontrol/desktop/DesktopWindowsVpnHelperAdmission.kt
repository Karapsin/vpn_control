package com.kardinal.vpncontrol.desktop

import com.sun.jna.platform.win32.WinNT
import java.nio.file.Path
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.*

/** No path, principal or machine setting supplied by a controller can choose privileged code. */
internal object DesktopWindowsVpnHelperAdmission {
    const val HELPER = "vpn-control-vpn-broker.exe"
    internal const val MAX_HELPER_BYTES = 64L * 1024 * 1024
    internal const val MAX_MANIFEST_BYTES = 65536
    private const val CURRENT_OWNER = "S-1-5-32-544"

    fun retain(runtimeSha256: String, runtimeSize: Long,
               native: WindowsVpnHelperNative = JnaWindowsVpnHelperNative()): DesktopWindowsVpnHelperLease {
        require(runtimeSha256.matches(Regex("[a-f0-9]{64}")) && runtimeSize in 64..201326592)
        val handles = mutableListOf<WindowsInstallNative.Handle>()
        var originalImage: WindowsInstallNative.Handle? = null
        var application: AutoCloseable? = null
        // Track all opens performed inside existing admission as well. Its failed-entry
        // cleanup can throw after opening a witness; the outer component must still own it.
        val applicationHandles = mutableListOf<WindowsInstallNative.Handle>()
        val applicationNative = object : WindowsAdmissionNative by native {
            override fun openDirectory(path: String) = native.openDirectory(path).also { applicationHandles += it }
            override fun openGate(path: String) = native.openGate(path).also { applicationHandles += it }
            override fun close(handle: WindowsInstallNative.Handle) {
                native.close(handle)
                applicationHandles.remove(handle)
            }
        }
        var ready = false
        var closed = false
        fun release() {
            var failed: Throwable? = null
            for (index in handles.indices.reversed()) {
                if (handles[index] === originalImage) continue
                try { native.close(handles[index]); handles.removeAt(index) }
                catch (failure: Throwable) { failed = failed ?: failure }
            }
            if (handles.all { it === originalImage }) {
                try { application?.close(); application = null }
                catch (failure: Throwable) { failed = failed ?: failure }
            }
            // On enter failure no returned lease owns these entries. After a successful
            // lease closes, this list is already empty. Never double-close a successful one.
            if (handles.all { it === originalImage } && application == null) for (index in applicationHandles.indices.reversed()) {
                try { applicationNative.close(applicationHandles[index]) }
                catch (failure: Throwable) { failed = failed ?: failure }
            }
            if (handles.all { it === originalImage } && application == null && applicationHandles.isEmpty()) {
                try {
                    native.close()
                    // This is the final physical fence, even if another dependent close failed
                    // earlier. Do not discard the queried object while cleanup remains pending.
                    originalImage?.let { native.close(it); handles.remove(it); originalImage = null }
                } catch (failure: Throwable) { failed = failed ?: failure }
            }
            failed?.let { throw it }
            closed = true
        }
        val pending = object : AutoCloseable {
            @Synchronized override fun close() { if (!closed) release() }
        }
        try {
            val process = native.currentProcess()
            val owner = process.owner
            require(native.currentSid() == owner.sid) { "PERMISSION_DENIED" }
            fun physical(handle: WindowsInstallNative.Handle, directory: Boolean): WindowsInstallInfo {
                require(native.persistentAcl(handle)) { "PERMISSION_DENIED" }
                val info = native.inspect(handle)
                require(info.disk && info.directory == directory && info.attributes and 0x400 == 0 && info.reparseTag == 0 &&
                    (directory || info.links == 1)) { "PERMISSION_DENIED" }
                return info
            }
            fun trusted(handle: WindowsInstallNative.Handle, directory: Boolean, witnessed: Boolean) {
                val info = physical(handle, directory)
                val policy = info.copy(owner = if (info.owner == owner.sid) CURRENT_OWNER else info.owner,
                    dacl = info.dacl?.map { if (it.sid == owner.sid) it.copy(sid = CURRENT_OWNER) else it })
                WindowsInstallTrust.verify(policy,
                    if (directory) WindowsInstallTrust.Kind.ANCESTOR else WindowsInstallTrust.Kind.STATUS,
                    ancestorPinnedNonEmpty = witnessed)
            }
            // Native process queries may return a short leaf spelling. Pin that exact query
            // before resolving its canonical name; a string expansion cannot prove identity.
            val queried = native.openDirectory(DesktopWindowsInstallJobBackend.canonical(process.image))
            handles += queried
            originalImage = queried
            trusted(queried, false, false)
            val originalIdentity = native.identity(queried)
            val originalCanonical = native.canonicalPath(queried)
            require(originalCanonical.startsWith("\\\\?\\")) { "UNSUPPORTED" }
            val executable = DesktopWindowsInstallJobBackend.canonical(originalCanonical.removePrefix("\\\\?\\"))
            require(executable.substringAfterLast('\\').lowercase(java.util.Locale.ROOT) in
                setOf("vpn-control.exe", "vpn-control-cli.exe")) { "UNAVAILABLE" }
            // Existing admission preserves the first-gate physical fence and rejects pending gates.
            application = DesktopWindowsInstallAdmission.enter(Path.of(executable), applicationNative)
            val paths = mutableListOf(executable.substring(0, 3))
            var path = paths.single()
            for (part in executable.substring(3).split('\\')) {
                path = path.trimEnd('\\') + "\\" + part
                paths += path
            }
            fun pin(path: String, directory: Boolean, parent: WindowsInstallNative.Handle? = null): WindowsInstallNative.Handle {
                val file = native.openDirectory(path)
                handles += file // Ownership precedes every inspection and rejected-parent cleanup.
                physical(file, directory)
                if (parent != null) {
                    require(native.canonicalPath(file).substringBeforeLast('\\') == native.canonicalPath(parent).trimEnd('\\')) {
                        "PERMISSION_DENIED"
                    }
                    trusted(parent, directory = true, witnessed = true)
                }
                return file
            }
            var previous: WindowsInstallNative.Handle? = null
            var appRoot: WindowsInstallNative.Handle? = null
            var nativeImage: WindowsInstallNative.Handle? = null
            for ((index, current) in paths.withIndex()) {
                val file = pin(current, directory = index != paths.lastIndex, parent = previous)
                if (index == paths.lastIndex - 1) appRoot = file
                if (index == paths.lastIndex) { nativeImage = file; trusted(file, false, false) }
                previous = file
            }
            require(native.identity(requireNotNull(nativeImage)) == originalIdentity &&
                native.canonicalPath(nativeImage) == originalCanonical &&
                native.canonicalPath(queried) == originalCanonical) { "CONFLICT" }
            require(native.machine(requireNotNull(nativeImage)) == 0x8664) { "UNSUPPORTED" }
            val rootPath = executable.substringBeforeLast('\\')
            var parent = requireNotNull(appRoot)
            path = rootPath
            for (component in listOf("app", "native", "windows-amd64")) {
                path += "\\" + component
                parent = pin(path, directory = true, parent = parent)
            }
            val helperPath = "$path\\$HELPER"
            val helper = pin(helperPath, false, parent)
            trusted(helper, false, false)
            val manifest = pin("$path\\native-helpers.json", false, parent)
            trusted(manifest, false, false)
            val record = manifest(native.read(manifest, MAX_MANIFEST_BYTES), runtimeSha256, runtimeSize)
            val actual = native.executable(helper, MAX_HELPER_BYTES)
            require(actual.size == record.size && actual.sha256 == record.sha256 && actual.machine == 0x8664 &&
                !actual.clrHeader && actual.dependentLoadFlags == 0x800) { "PERMISSION_DENIED" }
            val expectedIdentity = native.identity(helper)
            val expectedCanonical = native.canonicalPath(helper)
            // Recheck the native image path/generation after admission, before constructing argv.
            val current = native.currentProcess()
            require(current.image == process.image && current.owner.processId == owner.processId &&
                current.owner.creationFileTime == owner.creationFileTime && current.owner.sid == owner.sid) { "PERMISSION_DENIED" }
            ready = true
            return object : DesktopWindowsVpnHelperLease {
                override val executable = helperPath
                override val owner = process.owner
                override fun parameters(pipeName: String): String {
                    check(ready && !closed)
                    val arguments = arguments(pipeName, owner, runtimeSha256)
                    if (windowsInstallArgument(executable).length.toLong() + arguments.length + 2 > 32767)
                        throw DesktopWindowsRuntimeFailure("RESOURCE_EXHAUSTED")
                    return arguments
                }
                @Synchronized override fun verifyStartedProcess(process: WinNT.HANDLE) {
                    check(ready && !closed)
                    // This path comes from the retained ShellExecute process, not a PID lookup.
                    val peer = native.openDirectory(native.processImage(process))
                    handles += peer
                    trusted(peer, false, false)
                    require(native.identity(peer) == expectedIdentity && native.canonicalPath(peer) == expectedCanonical) {
                        "PERMISSION_DENIED"
                    }
                }
                @Synchronized override fun close() { pending.close() }
                override fun toString() = "Packaged Windows VPN helper (<redacted>)"
            }
        } catch (failure: Throwable) {
            try { pending.close() }
            catch (_: Throwable) { throw DesktopWindowsAdmissionCleanupFailure(failure, pending) }
            throw failure
        }
    }

    internal fun arguments(pipe: String, owner: DesktopWindowsRuntimeResourceNativeOwner, digest: String): String {
        val prefix = "vpn-control-vpn-"
        require(pipe.startsWith(prefix) && java.util.UUID.fromString(pipe.removePrefix(prefix)).toString() == pipe.removePrefix(prefix))
        require(digest.matches(Regex("[a-f0-9]{64}")))
        return listOf(pipe, owner.processId.toString(), owner.creationFileTime.toString(), owner.sid, digest)
            .joinToString(" ", transform = ::windowsInstallArgument)
    }

    private data class Artifact(val sha256: String, val size: Long)
    private fun manifest(bytes: ByteArray, digest: String, size: Long): Artifact {
        require(bytes.isNotEmpty() && bytes.size <= MAX_MANIFEST_BYTES) { "UNAVAILABLE" }
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        val parsed = Json.parseToJsonElement(text)
        // The producer emits ordinary JSON. Reject duplicate members and alternate escaped keys,
        // rather than accepting the parser's last-member-wins interpretation of a security record.
        val compact = StringBuilder(text.length)
        var quoted = false; var escaped = false
        for (character in text) {
            if (quoted) {
                compact.append(character)
                if (escaped) escaped = false else if (character == '\\') escaped = true else if (character == '"') quoted = false
            } else {
                if (character == '"') quoted = true
                if (character !in " \t\r\n") compact.append(character)
            }
        }
        require(parsed.toString() == compact.toString()) { "UNAVAILABLE" }
        val root = parsed.jsonObject
        fun JsonObject.number(name: String): Long = getValue(name).jsonPrimitive.let {
            require(!it.isString); requireNotNull(it.longOrNull)
        }
        fun JsonObject.boolean(name: String): Boolean = getValue(name).jsonPrimitive.let {
            require(!it.isString); requireNotNull(it.booleanOrNull)
        }
        require(root.keys == setOf("schemaVersion", "policySha256", "artifacts", "runtimeAuthority") &&
            root.number("schemaVersion") == 1L)
        fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.let {
            require(it.isString); it.content
        }
        require(root.string("policySha256").matches(Regex("[a-f0-9]{64}")))
        val authority = root.getValue("runtimeAuthority").jsonObject
        require(authority.keys == setOf("runtimeSha256", "runtimeSizeBytes", "authoritySourceSha256"))
        require(authority.string("runtimeSha256") == digest && authority.number("runtimeSizeBytes") == size) {
            "PERMISSION_DENIED"
        }
        // The producer checks this provenance against its exact generated source. It is not
        // proof of compiled code; the native entry point enforces its compiled runtime hash.
        require(authority.string("authoritySourceSha256").matches(Regex("[a-f0-9]{64}")))
        val records = root.getValue("artifacts").jsonArray
        require(records.size == 2)
        val artifacts = records.map { it.jsonObject }
        require(artifacts.map { it.string("name") }.toSet() == setOf(HELPER, "vpn-control-install-helper.exe"))
        val broker = artifacts.single { it.string("name") == HELPER }
        require(broker.string("machine") == "AMD64" && !broker.boolean("clrHeader") &&
            broker.number("dependentLoadFlags") == 0x800L &&
            broker["operations"]?.jsonArray?.map { it.jsonPrimitive.let { value -> require(value.isString); value.content } } == listOf("authenticated-runtime-channel"))
        val helperSize = broker.number("sizeBytes")
        require(helperSize in 64..MAX_HELPER_BYTES) { "RESOURCE_EXHAUSTED" }
        val helperDigest = broker.string("sha256")
        require(helperDigest.matches(Regex("[a-f0-9]{64}")))
        return Artifact(helperDigest, helperSize)
    }
}

internal data class DesktopWindowsNativeOwnerImage(val image: String, val owner: DesktopWindowsRuntimeResourceNativeOwner) {
    override fun toString() = "Native owner image (<redacted>)"
}
internal data class DesktopWindowsPinnedExecutable(val sha256: String, val size: Long, val machine: Int,
    val clrHeader: Boolean, val dependentLoadFlags: Int)
internal interface DesktopWindowsVpnHelperLease : AutoCloseable {
    val executable: String
    val owner: DesktopWindowsRuntimeResourceNativeOwner
    fun parameters(pipeName: String): String
    fun verifyStartedProcess(process: WinNT.HANDLE)
}
internal interface WindowsVpnHelperNative : WindowsAdmissionNative, AutoCloseable {
    override fun close() {}
    fun currentProcess(): DesktopWindowsNativeOwnerImage
    fun processImage(process: WinNT.HANDLE): String
    fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray
    fun machine(handle: WindowsInstallNative.Handle): Int
    fun identity(handle: WindowsInstallNative.Handle): String
    fun executable(handle: WindowsInstallNative.Handle, maximum: Long): DesktopWindowsPinnedExecutable
}
