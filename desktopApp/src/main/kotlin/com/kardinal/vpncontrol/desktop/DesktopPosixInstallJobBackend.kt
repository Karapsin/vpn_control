package com.kardinal.vpncontrol.desktop

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.SeekableByteChannel
import java.nio.file.*
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/**
 * Root-owned POSIX implementation. SecureDirectoryStream is mandatory, never emulated with path IO.
 * The injected policy is exclusively for isolated fixtures; production uses root ownership, no group/
 * other write, and native macOS extended-ACL rejection. Only the final root child may be provisioned.
 */
internal class DesktopPosixInstallJobBackend(
    private val verifyTrust: (Path, PosixFileAttributes) -> Unit = ::verifyProductionTrust,
    private val verifyExtendedAcl: (Path) -> Unit = { path ->
        if (System.getProperty("os.name").startsWith("Mac", ignoreCase = true)) DesktopMacInstallJobAcl.requireAbsent(path)
    },
) : DesktopInstallJobBackend {
    override fun openRoot(root: Path, create: Boolean): DesktopInstallJobBackend.Directory {
        require(root.isAbsolute && root == root.normalize() && root.nameCount > 0)
        val retained = mutableListOf<SecureDirectoryStream<Path>>()
        try {
            var absolute = root.root
            var stream = secure(Files.newDirectoryStream(absolute)).also { retained += it }
            inspectDirectory(stream, absolute)
            root.forEachIndexed { index, name ->
                absolute = absolute.resolve(name)
                var created = false
                if (create && index == root.nameCount - 1) {
                    try { Files.createDirectory(absolute, PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS)); created = true }
                    catch (_: FileAlreadyExistsException) { /* Existing root is inspected, never repaired. */ }
                }
                val next = stream.newDirectoryStream(name, LinkOption.NOFOLLOW_LINKS)
                retained += next
                if (created) requireNotNull(next.getFileAttributeView(PosixFileAttributeView::class.java)).setPermissions(DIRECTORY_PERMISSIONS)
                inspectDirectory(next, absolute)
                stream = next
            }
            return Directory(absolute, stream, retained)
        } catch (failure: Exception) {
            retained.asReversed().forEach { runCatching { it.close() } }
            throw failure
        }
    }

    private fun secure(stream: DirectoryStream<Path>): SecureDirectoryStream<Path> {
        if (stream is SecureDirectoryStream<Path>) return stream
        stream.close()
        throw UnsupportedOperationException("Secure installer directory handles unavailable")
    }

    private fun inspectDirectory(stream: SecureDirectoryStream<Path>, path: Path) {
        val attributes = requireNotNull(stream.getFileAttributeView(PosixFileAttributeView::class.java)).readAttributes()
        require(attributes.isDirectory && !attributes.isSymbolicLink)
        verifyTrust(path, attributes)
        verifyExtendedAcl(path)
    }

    private inner class Directory(private val path: Path, private val stream: SecureDirectoryStream<Path>,
        private val retained: List<SecureDirectoryStream<Path>> = listOf(stream),
    ) : DesktopInstallJobBackend.Directory {
        private var closed = false
        private fun checkOpen() = check(!closed)
        override fun createJob(jobId: String): DesktopInstallJobBackend.Directory {
            checkOpen(); require(DesktopInstallJobNames.validJob(jobId))
            // All path ancestors are already proved immutable to unprivileged users and retained.
            Files.createDirectory(path.resolve(jobId), PosixFilePermissions.asFileAttribute(DIRECTORY_PERMISSIONS))
            stream.newDirectoryStream(Path.of(jobId), LinkOption.NOFOLLOW_LINKS).use {
                requireNotNull(it.getFileAttributeView(PosixFileAttributeView::class.java)).setPermissions(DIRECTORY_PERMISSIONS)
            }
            return openJob(jobId)
        }
        override fun openJob(jobId: String): DesktopInstallJobBackend.Directory {
            checkOpen(); require(DesktopInstallJobNames.validJob(jobId))
            val child = stream.newDirectoryStream(Path.of(jobId), LinkOption.NOFOLLOW_LINKS)
            try { inspectDirectory(child, path.resolve(jobId)); return Directory(path.resolve(jobId), child) }
            catch (failure: Exception) { child.close(); throw failure }
        }
        override fun createFile(name: String, purpose: DesktopInstallJobBackend.Purpose,
            clientPrincipal: String?,
        ): DesktopInstallJobBackend.File {
            checkOpen(); DesktopInstallJobNames.requireCreate(name, purpose)
            require((purpose == DesktopInstallJobBackend.Purpose.CANCEL) == (clientPrincipal != null))
            val permissions = if (purpose == DesktopInstallJobBackend.Purpose.CANCEL) CANCEL_PERMISSIONS else STATUS_PERMISSIONS
            val channel = stream.newByteChannel(Path.of(name), setOf(StandardOpenOption.CREATE_NEW,
                StandardOpenOption.READ, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(permissions))
            try {
                require(channel is FileChannel)
                view(name).setPermissions(permissions)
                if (clientPrincipal != null) {
                    require(clientPrincipal.isNotBlank() && clientPrincipal.length <= 256 && '\u0000' !in clientPrincipal)
                    val owner = path.fileSystem.userPrincipalLookupService.lookupPrincipalByName(clientPrincipal)
                    view(name).setOwner(owner)
                }
                inspectFile(name, cancellation = purpose == DesktopInstallJobBackend.Purpose.CANCEL)
                return File(channel, writable = true, cancellationOnly = false)
            } catch (failure: Exception) { channel.close(); throw failure }
        }
        private fun view(name: String) = requireNotNull(stream.getFileAttributeView(Path.of(name),
            PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS))
        private fun inspectFile(name: String, cancellation: Boolean) {
            val attributes = view(name).readAttributes()
            require(attributes.isRegularFile && !attributes.isSymbolicLink)
            if (!cancellation) { verifyTrust(path.resolve(name), attributes); verifyExtendedAcl(path.resolve(name)) }
            // Cancellation contents are untrusted by design, but no other user may mutate this leaf.
            require(PosixFilePermission.GROUP_WRITE !in attributes.permissions() &&
                PosixFilePermission.OTHERS_WRITE !in attributes.permissions())
        }
        override fun openFile(name: String, write: Boolean): DesktopInstallJobBackend.File {
            checkOpen(); DesktopInstallJobNames.requireReadable(name)
            require(!write || name == DesktopInstallJobNames.CANCEL)
            inspectFile(name, cancellation = name == DesktopInstallJobNames.CANCEL)
            val options = mutableSetOf<OpenOption>(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)
            if (write) options += StandardOpenOption.WRITE
            val channel = stream.newByteChannel(Path.of(name), options)
            if (channel !is FileChannel) { channel.close(); error("Durable installer file handles unavailable") }
            return File(channel, writable = write, cancellationOnly = write)
        }
        override fun replaceFile(tempName: String, targetName: String) {
            checkOpen(); require(DesktopInstallJobNames.validTemp(tempName) && targetName == DesktopInstallJobNames.STATUS)
            inspectFile(tempName, cancellation = false)
            try { inspectFile(targetName, cancellation = false) } catch (_: NoSuchFileException) { }
            stream.move(Path.of(tempName), stream, Path.of(targetName))
            FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        }
        override fun deleteFile(name: String) {
            checkOpen(); require(DesktopInstallJobNames.validTemp(name))
            stream.deleteFile(Path.of(name))
        }
        override fun close() {
            if (closed) return
            closed = true
            retained.asReversed().forEach { it.close() }
        }
    }

    private class File(private val channel: SeekableByteChannel, private val writable: Boolean,
        private val cancellationOnly: Boolean,
    ) : DesktopInstallJobBackend.File {
        @Synchronized override fun readBounded(maxBytes: Int): ByteArray {
            require(maxBytes in 1..DesktopInstallJobReceipt.MAX_BYTES)
            channel.position(0)
            val buffer = ByteBuffer.allocate(maxBytes + 1)
            while (buffer.hasRemaining()) { if (channel.read(buffer) < 0) break }
            require(buffer.position() <= maxBytes && channel.size() <= maxBytes)
            return buffer.array().copyOf(buffer.position())
        }
        @Synchronized override fun writeExact(bytes: ByteArray) {
            check(writable); require(bytes.size in 1..DesktopInstallJobReceipt.MAX_BYTES)
            require(!cancellationOnly || bytes.contentEquals(byteArrayOf(1)))
            channel.position(0)
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            channel.truncate(bytes.size.toLong())
            (channel as FileChannel).force(true)
        }
        override fun close() = channel.close()
    }

    companion object {
        private val DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwxr-xr-x")
        private val STATUS_PERMISSIONS = PosixFilePermissions.fromString("rw-r--r--")
        private val CANCEL_PERMISSIONS = PosixFilePermissions.fromString("rw-------")
        fun defaultRoot(): Path = when {
            System.getProperty("os.name").startsWith("Linux", true) -> Path.of("/var/lib/vpn-control-install-jobs")
            System.getProperty("os.name").startsWith("Mac", true) -> Path.of("/Library/Application Support/vpn-control-install-jobs")
            else -> throw UnsupportedOperationException("POSIX installer root unavailable")
        }
        private fun verifyProductionTrust(path: Path, attributes: PosixFileAttributes) {
            require(attributes.owner() == path.fileSystem.userPrincipalLookupService.lookupPrincipalByName("root"))
            require(PosixFilePermission.GROUP_WRITE !in attributes.permissions() &&
                PosixFilePermission.OTHERS_WRITE !in attributes.permissions())
        }
    }
}
