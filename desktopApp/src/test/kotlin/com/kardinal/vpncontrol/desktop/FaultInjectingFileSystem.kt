package com.kardinal.vpncontrol.desktop

import java.io.File
import java.io.IOException
import java.net.URI
import java.nio.channels.FileChannel
import java.nio.channels.SeekableByteChannel
import java.nio.file.AccessMode
import java.nio.file.CopyOption
import java.nio.file.DirectoryStream
import java.nio.file.FileStore
import java.nio.file.FileSystem
import java.nio.file.FileSystems
import java.nio.file.LinkOption
import java.nio.file.OpenOption
import java.nio.file.Path
import java.nio.file.PathMatcher
import java.nio.file.ProviderMismatchException
import java.nio.file.StandardOpenOption
import java.nio.file.WatchEvent
import java.nio.file.WatchKey
import java.nio.file.WatchService
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.FileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.UserPrincipalLookupService
import java.nio.file.spi.FileSystemProvider

/** File operations a test can make fail. Each is matched by the real path it acts on (a move by its source). */
internal enum class FileFault { ATTRIBUTES, READ, CREATE, MOVE }

/**
 * Test-only view of the default file system. An operation fails when [fault] returns an exception for it, as a
 * sharing lock, a full disk or a flaky network mount would; every other operation reaches the real files.
 * [path] maps a real folder into this view, so production code runs unchanged on top of it.
 */
internal class FaultInjectingFileSystem(private val fault: (FileFault, Path) -> IOException?) {
    private val delegate: FileSystem = FileSystems.getDefault()
    // Not named provider/fileSystem: inside the inner Path those names would bind to its own getFileSystem().
    private val faultProvider = FaultProvider()
    private val faultFileSystem = FaultFileSystem()

    private val creations = mutableMapOf<String, Set<PosixFilePermission>?>()

    fun path(real: Path): Path = wrap(real)

    /**
     * The POSIX permissions requested when the file [name] was created through this view, or null when it was
     * created without them, which leaves them to the process umask.
     */
    @Synchronized fun permissionsRequestedAtCreation(name: String): Set<PosixFilePermission>? = creations[name]

    private fun wrap(real: Path): Path = FaultPath(real)

    private fun unwrap(path: Path): Path = (path as? FaultPath)?.real ?: throw ProviderMismatchException()

    private fun fail(kind: FileFault, real: Path) {
        fault(kind, real)?.let { throw it }
    }

    private fun beforeOpen(real: Path, options: Set<OpenOption>, attrs: Array<out FileAttribute<*>>) {
        if (StandardOpenOption.CREATE in options || StandardOpenOption.CREATE_NEW in options) fail(FileFault.CREATE, real)
        if (StandardOpenOption.WRITE !in options && StandardOpenOption.APPEND !in options) fail(FileFault.READ, real)
        if (StandardOpenOption.CREATE_NEW in options) {
            @Suppress("UNCHECKED_CAST")
            val permissions = attrs.firstOrNull { it.name() == "posix:permissions" }?.value() as Set<PosixFilePermission>?
            synchronized(this) { creations.putIfAbsent(real.fileName.toString(), permissions?.toSet()) }
        }
    }

    private inner class FaultProvider : FileSystemProvider() {
        private val real: FileSystemProvider get() = delegate.provider()

        override fun getScheme(): String = "fault-injecting"
        override fun newFileSystem(uri: URI, env: Map<String, *>): FileSystem = throw UnsupportedOperationException()
        override fun getFileSystem(uri: URI): FileSystem = throw UnsupportedOperationException()
        override fun getPath(uri: URI): Path = throw UnsupportedOperationException()

        override fun newByteChannel(
            path: Path,
            options: MutableSet<out OpenOption>,
            vararg attrs: FileAttribute<*>,
        ): SeekableByteChannel {
            val target = unwrap(path)
            beforeOpen(target, options, attrs)
            return real.newByteChannel(target, options, *attrs)
        }

        override fun newFileChannel(
            path: Path,
            options: MutableSet<out OpenOption>,
            vararg attrs: FileAttribute<*>,
        ): FileChannel {
            val target = unwrap(path)
            beforeOpen(target, options, attrs)
            return real.newFileChannel(target, options, *attrs)
        }

        override fun newDirectoryStream(dir: Path, filter: DirectoryStream.Filter<in Path>): DirectoryStream<Path> {
            val stream = real.newDirectoryStream(unwrap(dir)) { entry -> filter.accept(wrap(entry)) }
            return object : DirectoryStream<Path> {
                override fun iterator(): MutableIterator<Path> {
                    val entries = stream.iterator()
                    return object : MutableIterator<Path> {
                        override fun hasNext(): Boolean = entries.hasNext()
                        override fun next(): Path = wrap(entries.next())
                        override fun remove() = entries.remove()
                    }
                }

                override fun close() = stream.close()
            }
        }

        override fun createDirectory(dir: Path, vararg attrs: FileAttribute<*>) = real.createDirectory(unwrap(dir), *attrs)
        override fun delete(path: Path) = real.delete(unwrap(path))
        override fun copy(source: Path, target: Path, vararg options: CopyOption) =
            real.copy(unwrap(source), unwrap(target), *options)

        override fun move(source: Path, target: Path, vararg options: CopyOption) {
            val from = unwrap(source)
            fail(FileFault.MOVE, from)
            real.move(from, unwrap(target), *options)
        }

        override fun isSameFile(path: Path, path2: Path): Boolean = real.isSameFile(unwrap(path), unwrap(path2))
        override fun isHidden(path: Path): Boolean = real.isHidden(unwrap(path))
        override fun getFileStore(path: Path): FileStore = real.getFileStore(unwrap(path))

        override fun checkAccess(path: Path, vararg modes: AccessMode) {
            val target = unwrap(path)
            fail(FileFault.ATTRIBUTES, target)
            real.checkAccess(target, *modes)
        }

        override fun <V : FileAttributeView> getFileAttributeView(path: Path, type: Class<V>, vararg options: LinkOption): V? =
            real.getFileAttributeView(unwrap(path), type, *options)

        override fun <A : BasicFileAttributes> readAttributes(path: Path, type: Class<A>, vararg options: LinkOption): A {
            val target = unwrap(path)
            fail(FileFault.ATTRIBUTES, target)
            return real.readAttributes(target, type, *options)
        }

        override fun readAttributes(path: Path, attributes: String, vararg options: LinkOption): MutableMap<String, Any> {
            val target = unwrap(path)
            fail(FileFault.ATTRIBUTES, target)
            return real.readAttributes(target, attributes, *options)
        }

        override fun setAttribute(path: Path, attribute: String, value: Any?, vararg options: LinkOption) =
            real.setAttribute(unwrap(path), attribute, value, *options)
    }

    private inner class FaultFileSystem : FileSystem() {
        override fun provider(): FileSystemProvider = faultProvider
        override fun close() = throw UnsupportedOperationException()
        override fun isOpen(): Boolean = true
        override fun isReadOnly(): Boolean = false
        override fun getSeparator(): String = delegate.separator
        override fun getRootDirectories(): Iterable<Path> = delegate.rootDirectories.map(::wrap)
        override fun getFileStores(): Iterable<FileStore> = delegate.fileStores
        override fun supportedFileAttributeViews(): Set<String> = delegate.supportedFileAttributeViews()
        override fun getPath(first: String, vararg more: String): Path = wrap(delegate.getPath(first, *more))

        override fun getPathMatcher(syntaxAndPattern: String): PathMatcher {
            val matcher = delegate.getPathMatcher(syntaxAndPattern)
            return PathMatcher { matcher.matches(unwrap(it)) }
        }

        override fun getUserPrincipalLookupService(): UserPrincipalLookupService = delegate.userPrincipalLookupService
        override fun newWatchService(): WatchService = throw UnsupportedOperationException()
    }

    private inner class FaultPath(val real: Path) : Path {
        override fun getFileSystem(): FileSystem = faultFileSystem
        override fun isAbsolute(): Boolean = real.isAbsolute
        override fun getRoot(): Path? = real.root?.let(::wrap)
        override fun getFileName(): Path? = real.fileName?.let(::wrap)
        override fun getParent(): Path? = real.parent?.let(::wrap)
        override fun getNameCount(): Int = real.nameCount
        override fun getName(index: Int): Path = wrap(real.getName(index))
        override fun subpath(beginIndex: Int, endIndex: Int): Path = wrap(real.subpath(beginIndex, endIndex))
        override fun startsWith(other: Path): Boolean = other is FaultPath && real.startsWith(other.real)
        override fun endsWith(other: Path): Boolean = other is FaultPath && real.endsWith(other.real)
        override fun normalize(): Path = wrap(real.normalize())
        override fun resolve(other: Path): Path = wrap(real.resolve(unwrap(other)))
        override fun relativize(other: Path): Path = wrap(real.relativize(unwrap(other)))
        override fun toUri(): URI = real.toUri()
        override fun toAbsolutePath(): Path = wrap(real.toAbsolutePath())
        override fun toRealPath(vararg options: LinkOption): Path = wrap(real.toRealPath(*options))
        override fun toFile(): File = real.toFile()

        override fun register(
            watcher: WatchService,
            events: Array<out WatchEvent.Kind<*>>,
            vararg modifiers: WatchEvent.Modifier,
        ): WatchKey = throw UnsupportedOperationException()

        override fun compareTo(other: Path): Int = real.compareTo(unwrap(other))
        override fun equals(other: Any?): Boolean = other is FaultPath && other.real == real
        override fun hashCode(): Int = real.hashCode()
        override fun toString(): String = real.toString()
    }
}
