package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.AclFileAttributeView
import java.security.MessageDigest
import org.junit.Assume.assumeFalse
import kotlin.test.*

class DesktopControlTransferSpoolTest {
    private fun fixture(block: (Path) -> Unit) {
        val parent = Files.createTempDirectory("transfer 東京 ")
        try { block(parent) }
        finally { Files.walk(parent).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun largeContentUsesOnePrivateFileAndSupportsBoundedCrossChunkReads() = fixture { parent ->
        val spool = DesktopControlTransferSpool.create(parent)
        val chunk = ByteArray(65536) { (it % 251).toByte() }
        val digest = MessageDigest.getInstance("SHA-256")
        repeat(161) { spool.append(chunk); digest.update(chunk) }
        assertContentEquals(chunk.takeLast(10).toByteArray() + chunk.take(20).toByteArray(), spool.read(65526, 30))
        assertEquals(digest.digest().joinToString("") { "%02x".format(it) }, spool.sha256())
        assertEquals(spool.sha256(), spool.sha256())
        // Neither tiny nor large append calls accumulate an in-memory per-chunk index.
        assertEquals(1L, Files.walk(parent).use { paths -> paths.filter(Files::isRegularFile).count() })
        spool.erase()
        spool.erase()
        assertEquals(0L, Files.list(parent).use { it.count() })
        assertFails { spool.append(byteArrayOf(1)) }
    }

    @Test fun boundsAndEmptyReadsDoNotAllocateFromUntrustedLengths() = fixture { parent ->
        val spool = DesktopControlTransferSpool.create(parent)
        try {
            spool.append(byteArrayOf(1, 2, 3))
            assertContentEquals(byteArrayOf(), spool.read(3, 0))
            assertFails { spool.read(-1, 1) }
            assertFails { spool.read(Long.MAX_VALUE, 1) }
            assertFails { spool.read(0, 65537) }
            assertFails { spool.read(2, 2) }
            assertFails { spool.append(ByteArray(65537)) }
        } finally { spool.erase() }
    }

    @Test fun spoolAndPayloadArePrivateFromCreation() = fixture { parent ->
        val spool = DesktopControlTransferSpool.create(parent)
        try {
            spool.append("private".toByteArray())
            if (!Platform.isWindows()) Files.walk(parent).use { paths -> paths.filter { it != parent }.forEach {
                assertEquals(PosixFilePermissions.fromString(if (Files.isDirectory(it)) "rwx------" else "rw-------"), Files.getPosixFilePermissions(it))
            } }
            else Files.walk(parent).use { paths -> paths.filter { it != parent }.forEach {
                val owner = Files.getOwner(it)
                assertEquals(it.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name")), owner)
                assertTrue(isPrivateControlAcl(owner, Files.getFileAttributeView(it, AclFileAttributeView::class.java).acl))
            } }
        } finally { spool.erase() }
    }

    @Test fun replacedChunkSymlinkCannotReadOrEraseItsTarget() = fixture { parent ->
        assumeFalse(Platform.isWindows())
        val spool = DesktopControlTransferSpool.create(parent)
        spool.append(byteArrayOf(1, 2))
        val chunk = Files.walk(parent).use { it.filter(Files::isRegularFile).findFirst().orElseThrow() }
        val target = Files.writeString(parent.resolve("outside"), "unchanged")
        Files.delete(chunk)
        Files.createSymbolicLink(chunk, target)
        // The pinned descriptor continues reading its original inode, never the replacement.
        assertContentEquals(byteArrayOf(1, 2), spool.read(0, 2))
        spool.erase()
        assertEquals("unchanged", Files.readString(target))
    }
}
