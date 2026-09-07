package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import java.security.MessageDigest

internal data class MacAdmissionRoot(val path: Path, val uid: Long)
internal enum class MacAdmissionAcl { EMPTY, DENY_ONLY }
internal data class MacAdmissionInfo(val uid: Long, val mode: Int, val links: Long, val size: Long, val device: Long, val inode: Long,
    val gid: Long = 0, val acl: MacAdmissionAcl = MacAdmissionAcl.EMPTY)

internal interface MacInstallAdmissionNative {
    fun currentUid(): Long
    fun currentExecutable(): String
    fun homeDirectory(): Path
    fun adminGroupId(): Long? = null
    fun openRoot(): Int
    fun openChild(parent: Int, name: String, directory: Boolean, optional: Boolean = false): Int?
    /** Descriptor-derived metadata; must reject invalid ACLs and any permission-granting ACL entry. */
    fun inspect(fd: Int): MacAdmissionInfo
    fun canonicalPath(fd: Int): Path
    fun lockShared(fd: Int): Boolean
    fun readGate(fd: Int): ByteArray
    fun close(fd: Int)
}

/** Unbound Darwin admission: no creation, writable descriptors, process launch or permission requests. */
internal object DesktopMacInstallAdmission {
    fun enter(launcher: Path, native: MacInstallAdmissionNative = JnaMacInstallAdmission(),
        roots: List<MacAdmissionRoot> = listOf(
            MacAdmissionRoot(Path.of("/Library/Application Support/vpn-control-install-jobs"), 0),
            MacAdmissionRoot(native.homeDirectory().resolve("Library/Application Support/vpn-control-install-jobs"), native.currentUid())),
        allowPendingControl: Boolean = false, onPendingControl: () -> Unit = {}): AutoCloseable {
        require(launcher.isAbsolute && launcher == launcher.normalize())
        require(launcher.fileName.toString() == "vpn-control" && launcher.parent?.fileName.toString() == "MacOS" &&
            launcher.parent?.parent?.fileName.toString() == "Contents" && launcher.parent?.parent?.parent?.fileName.toString().endsWith(".app"))
        require(launcher.toString() == native.currentExecutable()) { "Process executable identity changed" }
        val uid = native.currentUid()
        val adminGroup by lazy { native.adminGroupId() }
        val handles = mutableListOf<Int>()
        var closed = false
        fun release() {
            if (closed) return
            closed = true
            var failure: Throwable? = null
            handles.asReversed().forEach { runCatching { native.close(it) }.onFailure { error -> failure = failure ?: error } }
            handles.clear()
            failure?.let { throw it }
        }
        fun pin(fd: Int, directory: Boolean, owner: Long, ancestry: Boolean, rootOwnedAllowed: Boolean = ancestry): Int {
            handles += fd
            val info = native.inspect(fd)
            require(info.mode and 0xf000 == if (directory) 0x4000 else 0x8000) { "Wrong admission object type" }
            require(info.uid == owner || rootOwnedAllowed && info.uid == 0L) { "Untrusted admission owner" }
            val ancestorDirectory = directory && ancestry
            require(info.acl == MacAdmissionAcl.EMPTY || ancestorDirectory && info.acl == MacAdmissionAcl.DENY_ONLY) {
                "Untrusted admission ACL"
            }
            // Native admin-group members already have machine-install authority. This exception is
            // only for root-owned ancestor directories, never the private authority root or a file.
            val adminWritable = ancestorDirectory && info.uid == 0L && info.mode and 0x2 == 0 &&
                info.gid == adminGroup
            require(info.mode and 0x12 == 0 || adminWritable ||
                ancestorDirectory && info.uid == 0L && info.mode and 0x200 != 0) {
                "Untrusted admission permissions"
            }
            require(directory || info.links == 1L) { "Hard-linked admission file" }
            return fd
        }
        fun directory(path: Path, owner: Long, optional: Boolean, application: Boolean = false): Int? {
            require(path.isAbsolute && path == path.normalize())
            var fd = pin(native.openRoot(), true, owner, true)
            for ((index, part) in path.withIndex()) {
                val child = native.openChild(fd, part.toString(), true, optional) ?: return null
                fd = pin(child, true, owner, ancestry = application || index < path.nameCount - 1,
                    rootOwnedAllowed = application || index < path.nameCount - 1)
            }
            require(native.canonicalPath(fd) == path) { "Admission directory identity changed" }
            return fd
        }
        try {
            val executableParent = requireNotNull(directory(launcher.parent, uid, false, application = true))
            val executable = pin(requireNotNull(native.openChild(executableParent, "vpn-control", false)), false, uid,
                ancestry = false, rootOwnedAllowed = true)
            require(native.canonicalPath(executable) == launcher)
            val executableInfo = native.inspect(executable)
            require(executableInfo.mode and 0x49 != 0 && executableInfo.mode and 0xc00 == 0)
            // A first installer can create its gate after another workspace has already started.
            // Lock the exact executable inode even when no authority gate exists yet.
            check(native.lockShared(executable)) { "BUSY" }
            val bundle = launcher.parent.parent.parent
            val name = "gate-" + installationId(bundle)
            var pending = false
            for (root in roots.distinct()) {
                require(root.uid == 0L || root.uid == uid) { "Unrelated admission authority" }
                val parent = directory(root.path, root.uid, true) ?: continue
                val gate = native.openChild(parent, name, false, true) ?: continue
                pin(gate, false, root.uid, false)
                check(native.lockShared(gate)) { "BUSY" }
                val before = native.inspect(gate)
                require(before.size == 17L)
                val bytes = native.readGate(gate)
                require(native.inspect(gate) == before) { "Unstable admission gate" }
                require(bytes.size == 17 && bytes.indices.all { if (it == 8) bytes[it] in 0..1 else bytes[it] == 0.toByte() }) {
                    "Malformed admission gate"
                }
                pending = pending || bytes[8] == 1.toByte()
            }
            check(!pending || allowPendingControl) { "BUSY" }
            if (pending) onPendingControl() // Once, only after all gates and locks were verified.
            return object : AutoCloseable { @Synchronized override fun close() = release() }
        } catch (failure: Throwable) { runCatching { release() }; throw failure }
    }

    internal fun installationId(canonicalBundle: Path): String {
        require(canonicalBundle.isAbsolute && canonicalBundle == canonicalBundle.normalize())
        return MessageDigest.getInstance("SHA-256").digest(canonicalBundle.toString().toByteArray(Charsets.UTF_8))
            .take(16).joinToString("") { "%02x".format(it) }
    }
}
