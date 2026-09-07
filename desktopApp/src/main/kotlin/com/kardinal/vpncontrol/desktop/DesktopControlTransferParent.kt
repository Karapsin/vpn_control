package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import java.nio.channels.FileChannel
import java.nio.channels.SeekableByteChannel
import java.nio.file.*
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID

internal fun desktopLinuxExportOpenFlags(architecture: String, directory: Boolean): Int {
    val (directoryFlag, noFollowFlag) = when (architecture) {
        "aarch64", "arm", "arm64" -> 0x4000 to 0x8000
        "x86", "x86-64", "amd64", "x86_64", "i386" -> 0x10000 to 0x20000
        else -> error("Unsupported native export architecture")
    }
    return 0x80000 or noFollowFlag or if (directory) directoryFlag else 2
}

/** Retains the namespace as well as the payload; cleanup never resolves a replaced parent. */
internal interface DesktopControlTransferFile {
    val channel: SeekableByteChannel
    fun force() { (channel as FileChannel).force(false) }
    fun publish(leaf: String) { error("Publication unavailable") }
    fun erase()
}

internal object DesktopControlTransferParent {
    fun create(parent: Path, export: Boolean = false): DesktopControlTransferFile =
        if (Platform.isWindows()) {
            if (export) DesktopWindowsExportFile.create(parent) else windows(parent)
        } else if (Platform.isMac()) DesktopMacTransferFile.create(parent) else posix(parent, export)

    private interface UnixIdentity : Library {
        fun geteuid(): Int
        fun open(path: String, flags: Int): Int
        fun openat(parent: Int, name: String, flags: Int): Int
        fun close(fd: Int): Int
        fun fsync(fd: Int): Int
        fun linkat(source: Int, sourceName: String, target: Int, targetName: String, flags: Int): Int
    }
    private fun posix(parent: Path, export: Boolean): DesktopControlTransferFile {
        val unix = Native.load("c", UnixIdentity::class.java)
        val uid = unix.geteuid()
        val principal = parent.fileSystem.userPrincipalLookupService.lookupPrincipalByName(uid.toString())
        val rootOwner = parent.fileSystem.userPrincipalLookupService.lookupPrincipalByName("0")
        fun trustedOwner(path: Path) = Files.getOwner(path, NOFOLLOW_LINKS).let { it == principal || it == rootOwner }
        // Only immutable OS-owned aliases (e.g. macOS /var and /tmp) may be resolved.
        // User aliases are not an alternative way around the ancestor policy.
        var prefix = parent.toAbsolutePath().normalize().root
        for (name in parent.toAbsolutePath().normalize()) {
            prefix = prefix.resolve(name)
            if (Files.isSymbolicLink(prefix)) {
                require(Platform.isMac() && prefix in setOf(Path.of("/var"), Path.of("/tmp"))) { "Transfer link rejected" }
                require(Files.getOwner(prefix, NOFOLLOW_LINKS) == rootOwner) { "Untrusted transfer link" }
                require(trustedOwner(prefix.parent)) { "Untrusted transfer link parent" }
                val mode = Files.getAttribute(prefix.parent, "unix:mode", NOFOLLOW_LINKS) as Int
                require(mode and 0x12 == 0) { "Mutable transfer link parent" }
            }
        }
        val resolved = parent.toRealPath()
        val retained = mutableListOf<SecureDirectoryStream<Path>>()
        var directory: SecureDirectoryStream<Path>? = null
        var container: SecureDirectoryStream<Path>? = null
        var leaf: Path? = null
        var channel: FileChannel? = null
        val nativePins = mutableListOf<Int>()
        fun secure(stream: DirectoryStream<Path>): SecureDirectoryStream<Path> {
            if (stream is SecureDirectoryStream<Path>) return stream
            stream.close()
            error("Pinned transfer directories unavailable")
        }
        fun inspect(stream: SecureDirectoryStream<Path>, path: Path, private: Boolean = false) {
            val attrs = requireNotNull(stream.getFileAttributeView(PosixFileAttributeView::class.java)).readAttributes()
            require(attrs.isDirectory && !attrs.isSymbolicLink && (attrs.owner() == principal || !private && attrs.owner() == rootOwner))
            val mode = Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Int
            require(if (private) mode and 0x1ff == 0x1c0 else mode and 0x12 == 0 || mode and 0x200 != 0) { "Untrusted transfer permissions" }
            if (Platform.isMac()) DesktopMacInstallJobAcl.requireAbsent(path)
            require(attrs.fileKey() == Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey()) { "Transfer parent replaced" }
        }
        try {
            var path = resolved.root
            var current = secure(Files.newDirectoryStream(path)).also { retained += it }
            inspect(current, path)
            for (name in resolved) {
                current = current.newDirectoryStream(name, NOFOLLOW_LINKS).also { retained += it }
                path = path.resolve(name)
                inspect(current, path)
            }
            container = current
            leaf = Path.of("vpn-control-transfer-${UUID.randomUUID()}")
            val target = resolved.resolve(leaf)
            Files.createDirectory(target, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            directory = current.newDirectoryStream(leaf, NOFOLLOW_LINKS).also { retained += it }
            inspect(directory, target, private = true)
            val opened = directory.newByteChannel(Path.of("payload"), setOf(StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            if (opened !is FileChannel) { opened.close(); error("Retained transfer file unavailable") }
            var pinnedChannel: FileChannel = opened
            channel = opened
            if (Platform.isMac()) DesktopMacInstallJobAcl.requireAbsent(target.resolve("payload"))
            val pinnedDirectory = directory
            val pinnedParent = current
            val name = leaf
            val sourceKey = requireNotNull(directory.getFileAttributeView(Path.of("payload"), BasicFileAttributeView::class.java,
                NOFOLLOW_LINKS)).readAttributes().fileKey()
            val parentKey = requireNotNull(current.getFileAttributeView(BasicFileAttributeView::class.java)).readAttributes().fileKey()
            var publishParent = -1
            var publishSource = -1
            if (export) {
                fun pinNative(path: Path, expected: Any?): Int {
                    val fd = unix.open(path.toString(), desktopLinuxExportOpenFlags(Platform.ARCH, directory = true))
                    check(fd >= 0)
                    nativePins += fd
                    val actual = Files.readAttributes(Path.of("/proc/self/fd/$fd"), BasicFileAttributes::class.java)
                    require(actual.isDirectory && actual.fileKey() == expected) { "Export parent replaced" }
                    return fd
                }
                publishParent = pinNative(resolved, parentKey)
                val privateKey = requireNotNull(directory.getFileAttributeView(BasicFileAttributeView::class.java)).readAttributes().fileKey()
                val privateFd = pinNative(target, privateKey)
                publishSource = unix.openat(privateFd, "payload", desktopLinuxExportOpenFlags(Platform.ARCH, directory = false))
                check(publishSource >= 0)
                nativePins += publishSource
                val sourcePath = Path.of("/proc/self/fd/$publishSource")
                val actual = Files.readAttributes(sourcePath, BasicFileAttributes::class.java)
                require(actual.isRegularFile && actual.fileKey() == sourceKey) { "Export partial replaced" }
                pinnedChannel = FileChannel.open(sourcePath, StandardOpenOption.READ, StandardOpenOption.WRITE)
                channel = pinnedChannel
                opened.close()
            }
            val finalChannel = pinnedChannel
            val finalParent = publishParent
            val finalSource = publishSource
            return object : DesktopControlTransferFile {
                override val channel: FileChannel = finalChannel
                override fun publish(leaf: String) {
                    require(export && leaf.isNotBlank() && leaf !in setOf(".", "..") && '/' !in leaf && '\u0000' !in leaf)
                    require(Files.readAttributes(resolved, BasicFileAttributes::class.java, NOFOLLOW_LINKS).fileKey() == parentKey) { "Export parent replaced" }
                    require(Files.readAttributes(Path.of("/proc/self/fd/$finalSource"), BasicFileAttributes::class.java).fileKey() == sourceKey)
                    check(unix.linkat(-100, "/proc/self/fd/$finalSource", finalParent, leaf, 0x400) == 0) { "Export publication failed" }
                    check(unix.fsync(finalParent) == 0) { "Export publication synchronization failed" }
                }
                private var erased = false
                override fun erase() {
                    if (erased) return
                    erased = true
                    try {
                      try {
                        val actual = requireNotNull(pinnedDirectory.getFileAttributeView(Path.of("payload"), BasicFileAttributeView::class.java, NOFOLLOW_LINKS)).readAttributes().fileKey()
                        if (actual != sourceKey) return // Never remove a replacement entry.
                        pinnedDirectory.deleteFile(Path.of("payload"))
                      } catch (_: NoSuchFileException) { }
                    try {
                        val expected = requireNotNull(pinnedDirectory.getFileAttributeView(BasicFileAttributeView::class.java)).readAttributes().fileKey()
                        val current = requireNotNull(pinnedParent.getFileAttributeView(name, BasicFileAttributeView::class.java, NOFOLLOW_LINKS)).readAttributes().fileKey()
                        require(expected == current) { "Transfer directory replaced" }
                        pinnedParent.deleteDirectory(name)
                    } catch (_: NoSuchFileException) { }
                    } finally {
                        retained.asReversed().forEach { runCatching { it.close() } }
                        nativePins.asReversed().forEach { runCatching { unix.close(it) } }
                    }
                }
            }
        } catch (error: Throwable) {
            runCatching { channel?.close() }
            runCatching { directory?.deleteFile(Path.of("payload")) }
            if (directory != null) runCatching { container?.deleteDirectory(requireNotNull(leaf)) }
            retained.asReversed().forEach { runCatching { it.close() } }
            nativePins.asReversed().forEach { runCatching { unix.close(it) } }
            throw error
        }
    }

    private fun windows(parent: Path): DesktopControlTransferFile {
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        val sid = try { Advapi32Util.getTokenAccount(token.value).sidString }
        finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        val native = JnaWindowsInstallNative()
        val pins = DesktopWindowsTransferPins.open(parent.toAbsolutePath().toString(), sid, native)
        var channel: FileChannel? = null
        var createdPayload: Path? = null
        try {
            val directory = pins.createDirectory()
            val payload = Path.of(directory).resolve("payload")
            createdPayload = payload
            DesktopPrivateExportWriter.createPrivateEmpty(payload.toString()).getOrThrow()
            val opened = FileChannel.open(payload, StandardOpenOption.READ, StandardOpenOption.WRITE, NOFOLLOW_LINKS)
            channel = opened
            return object : DesktopControlTransferFile {
                override val channel: FileChannel = opened
                private var erased = false
                override fun erase() {
                    if (erased) return
                    Files.deleteIfExists(payload) // Every ancestor, including the private directory, remains pinned.
                    pins.deleteDirectory()
                    erased = true
                    pins.close()
                }
            }
        } catch (error: Throwable) {
            runCatching { channel?.close() }
            runCatching { createdPayload?.let(Files::deleteIfExists) }
            runCatching { pins.deleteDirectory() }
            pins.close()
            throw error
        }
    }
}

/** Spool-specific current-token trust; installer trust itself remains strictly administrator-owned. */
internal class DesktopWindowsTransferPins private constructor(
    private val path: String, private val sid: String, private val native: WindowsInstallNative,
    private val handles: MutableList<WindowsInstallNative.Handle>,
    internal val parentHandle: WindowsInstallNative.Handle,
) : AutoCloseable {
    private var directory: WindowsInstallNative.Handle? = null
    fun createDirectory(parentPath: String = path): String {
        check(directory == null)
        val target = parentPath.trimEnd('\\') + "\\vpn-control-transfer-${UUID.randomUUID()}"
        native.createDirectory(target, "O:${sid}G:${sid}D:P(A;;FA;;;$sid)", false)
        val handle = native.open(target, WindowsInstallNative.DELETE, shareDelete = false)
        try { verify(native.inspect(handle), sid, private = true) }
        catch (error: Throwable) { native.close(handle); throw error }
        directory = handle
        handles += handle
        return target
    }
    fun deleteDirectory() { directory?.let { native.delete(it) } }
    override fun close() { handles.asReversed().forEach(native::close); handles.clear() }

    companion object {
        fun open(parent: String, sid: String, native: WindowsInstallNative,
                 ancestry: WindowsAdmissionNative = JnaWindowsInstallAdmission()): DesktopWindowsTransferPins {
            require(Regex("S-1-[0-9]+(?:-[0-9]+)+").matches(sid))
            val path = DesktopWindowsInstallJobBackend.canonical(parent)
            val handles = mutableListOf<WindowsInstallNative.Handle>()
            try {
                var prefix = path.substring(0, 3)
                fun witness(parentPath: String, parentHandle: WindowsInstallNative.Handle): WindowsInstallNative.Handle {
                    val canonicalParent = ancestry.canonicalPath(parentHandle).trimEnd('\\')
                    for (name in ancestry.children(parentPath).take(4096)) {
                        if (name.isBlank() || name in setOf(".", "..") || name.any { it in "\\/:\u0000" }) continue
                        val child = runCatching {
                            native.open(parentPath.trimEnd('\\') + "\\" + name, WindowsInstallNative.INSPECT, shareDelete = false)
                        }.getOrNull() ?: continue
                        var retained = false
                        try {
                            val info = native.inspect(child)
                            require(info.disk && info.attributes and 0x400 == 0 && info.reparseTag == 0)
                            require(ancestry.canonicalPath(child).substringBeforeLast('\\') == canonicalParent) { "Unlinked transfer witness" }
                            // The child was opened with FILE_READ_DATA/LIST_DIRECTORY and without
                            // write/delete sharing. Recheck the linked parent after it cannot empty.
                            verify(native.inspect(parentHandle), sid, ancestorPinnedNonEmpty = true)
                            require(ancestry.canonicalPath(parentHandle).trimEnd('\\') == canonicalParent)
                            retained = true
                            return child
                        } catch (_: IllegalArgumentException) {
                            // A raced or unsuitable child proves nothing.
                        } finally { if (!retained) native.close(child) }
                    }
                    error("Unpinned mutable transfer ancestor")
                }
                fun pin(): WindowsInstallNative.Handle {
                    val handle = native.open(prefix, WindowsInstallNative.INSPECT, shareDelete = false)
                    handles += handle
                    val info = native.inspect(handle)
                    try { verify(info, sid) }
                    catch (rejection: IllegalArgumentException) {
                        // This second policy check allows only the established attribute/EA
                        // exception. Unknown masks, mutation rights and principals still fail.
                        verify(info, sid, ancestorPinnedNonEmpty = true)
                        handles += witness(prefix, handle)
                    }
                    return handle
                }
                var parentHandle = pin()
                for (name in path.substring(3).split('\\')) {
                    prefix = prefix.trimEnd('\\') + "\\" + name
                    parentHandle = pin()
                }
                return DesktopWindowsTransferPins(path, sid, native, handles, parentHandle)
            } catch (error: Throwable) { handles.asReversed().forEach(native::close); throw error }
        }
        internal fun verify(info: WindowsInstallInfo, sid: String, private: Boolean = false,
                            ancestorPinnedNonEmpty: Boolean = false) {
            require(!private || !ancestorPinnedNonEmpty)
            if (private) {
                require(info.owner == sid)
                requireNotNull(info.dacl).forEach { ace ->
                    require(ace.type == 0 || ace.type == 1)
                    require(ace.type != 0 || ace.flags and 8 != 0 || ace.sid == sid || ace.mask == 0) { "Public transfer directory" }
                }
            }
            val trustedCurrent = "S-1-5-32-544"
            // Windows servicing owns C:\Windows and has full access there. Its one exact
            // native service identity is trusted only for spool ancestors; installer policy
            // and private current-user payload admission remain unchanged.
            val installer = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            // OWNER RIGHTS is the retained object's current owner, not another user.
            // Python-created private workspace parents use this ACE. Elevated tokens
            // may default their object owner to Administrators. Resolve it only to
            // the retained ancestor's current user or already trusted BA/SY owner;
            // private payloads still require the explicit current-user ACE.
            fun trusted(principal: String) = principal == sid || !private && (
                principal == installer || principal == "S-1-3-4" &&
                    info.owner in setOf(sid, trustedCurrent, "S-1-5-18"))
            WindowsInstallTrust.verify(info.copy(owner = if (trusted(info.owner)) trustedCurrent else info.owner,
                dacl = info.dacl?.map { if (trusted(it.sid)) it.copy(sid = trustedCurrent) else it }),
                if (private) WindowsInstallTrust.Kind.DIRECTORY else WindowsInstallTrust.Kind.ANCESTOR,
                ancestorPinnedNonEmpty = ancestorPinnedNonEmpty)
        }
    }
}
