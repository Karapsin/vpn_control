package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopControlTransferParentTest {
    private fun privateDirectory(parent: Path, name: String): Path = Files.createDirectory(
        parent.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )

    private fun fixture(block: (Path) -> Unit) {
        assumeFalse(Platform.isWindows())
        val root = Files.createTempDirectory("spool-ancestry-東京")
        try { block(root) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun rejectsWritableNonStickyAncestorBeforeCreatingPrivateContent() = fixture { root ->
        val hostile = Files.createDirectory(root.resolve("hostile"))
        Files.setPosixFilePermissions(hostile, PosixFilePermissions.fromString("rwxrwxrwx"))
        val parent = Files.createDirectory(hostile.resolve("parent"))
        assertFails { DesktopControlTransferSpool.create(parent).erase() }
        assertEquals(0L, Files.list(parent).use { it.count() })
    }

    @Test fun rejectsUserControlledSymlinkParent() = fixture { root ->
        val parent = Files.createDirectory(root.resolve("actual"))
        val alias = Files.createSymbolicLink(root.resolve("alias"), parent)
        assertFails { DesktopControlTransferSpool.create(alias).erase() }
        assertEquals(0L, Files.list(parent).use { it.count() })
    }

    @Test fun trustedStickyTemporaryAncestorKeepsDefaultTempSemantics() = fixture { root ->
        val shared = Files.createDirectory(root.resolve("sticky"))
        Files.setAttribute(shared, "unix:mode", 0x3ff) // 01777, owned by the effective user.
        val parent = privateDirectory(shared, "owned")
        val spool = DesktopControlTransferSpool.create(parent)
        spool.append("東京".toByteArray())
        assertContentEquals("東京".toByteArray(), spool.read(0, 6))
        spool.erase()
    }

    @Test fun nativeMacAncestorAclCannotGrantAccessAroundModeBits() = fixture { root ->
        assumeTrue(Platform.isMac())
        val parent = Files.createDirectory(root.resolve("acl"))
        val grant = ProcessBuilder("/bin/chmod", "+a", "everyone allow add_file,delete_child", parent.toString()).start()
        assertEquals(0, grant.waitFor())
        try {
            assertFails { DesktopControlTransferSpool.create(parent).erase() }
            assertEquals(0L, Files.list(parent).use { it.count() })
        } finally {
            assertEquals(0, ProcessBuilder("/bin/chmod", "-N", parent.toString()).start().waitFor())
        }
    }

    @Test fun replacedParentCannotRedirectCleanupToAnotherPrivateFile() = fixture { root ->
        val parent = privateDirectory(root, "parent")
        val spool = DesktopControlTransferSpool.create(parent)
        spool.append(byteArrayOf(1, 2, 3))
        val name = Files.list(parent).use { it.findFirst().orElseThrow().fileName }
        val moved = Files.move(parent, root.resolve("original"))
        privateDirectory(root, "parent")
        val decoy = Files.createDirectory(parent.resolve(name))
        val marker = Files.writeString(decoy.resolve("payload"), "must remain")
        spool.erase()
        assertEquals("must remain", Files.readString(marker))
        assertEquals(0L, Files.list(moved).use { it.count() })
    }
}
