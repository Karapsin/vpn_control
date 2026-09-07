package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32Util
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopWindowsTransferParentNativeTest {
    private fun fixture(block: (Path) -> Unit) {
        assumeTrue(Platform.isWindows())
        val root = Files.createTempDirectory("transfer-native-東京")
        try { block(root) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun nativeHandlesPreventParentAndPrivateDirectoryReplacementUntilErase() = fixture { root ->
        val parent = Files.createDirectory(root.resolve("parent"))
        val spool = DesktopControlTransferSpool.create(parent)
        try {
            val private = Files.list(parent).use { it.findFirst().orElseThrow() }
            assertFails { Files.move(parent, root.resolve("replaced-parent")) }
            assertFails { Files.move(private, parent.resolve("replaced-private")) }
            spool.append("東京".toByteArray())
            assertContentEquals("東京".toByteArray(), spool.read(0, 6))
        } finally { spool.erase() }
        Files.move(parent, root.resolve("released-parent"))
    }
    @Test fun nativeMutableAncestorRetainsNonemptyWitnessWithoutPublicPayloadRights() = fixture { root ->
        val parent = Files.createDirectory(root.resolve("metadata-writable"))
        val witness = Files.writeString(parent.resolve("retained-witness"), "fixture")
        val view = Files.getFileAttributeView(parent, AclFileAttributeView::class.java)
        val prior = view.acl
        val everyone = parent.fileSystem.userPrincipalLookupService.lookupPrincipalByName(Advapi32Util.getAccountBySid("S-1-1-0").name)
        try {
            view.acl = listOf(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(everyone)
                .setPermissions(AclEntryPermission.WRITE_ATTRIBUTES, AclEntryPermission.WRITE_NAMED_ATTRS).build()) + prior
            val spool = DesktopControlTransferSpool.create(parent)
            try {
                assertFails { Files.delete(witness) }
                val private = Files.list(parent).use { paths -> paths.filter { it != witness }.findFirst().orElseThrow() }
                val payloadAcl = Files.getFileAttributeView(private.resolve("payload"), AclFileAttributeView::class.java).acl
                assertFalse(payloadAcl.any { it.type() == AclEntryType.ALLOW && it.principal() == everyone })
                assertFails { Files.move(parent, root.resolve("replaced-parent")) }
            } finally { spool.erase() }
            Files.delete(witness)
        } finally { view.acl = prior }
    }
    @Test fun nativePublicDeleteChildAclIsRejectedBeforePrivateCreation() = fixture { root ->
        val parent = Files.createDirectory(root.resolve("untrusted"))
        val view = Files.getFileAttributeView(parent, AclFileAttributeView::class.java)
        val prior = view.acl
        val everyone = parent.fileSystem.userPrincipalLookupService.lookupPrincipalByName(Advapi32Util.getAccountBySid("S-1-1-0").name)
        try {
            view.acl = listOf(AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(everyone)
                .setPermissions(AclEntryPermission.DELETE_CHILD).build()) + prior
            assertFails { DesktopControlTransferSpool.create(parent).erase() }
            assertEquals(0L, Files.list(parent).use { it.count() })
        } finally { view.acl = prior }
    }
    @Test fun nativeJunctionAncestorIsRejected() = fixture { root ->
        val target = Files.createDirectory(root.resolve("target"))
        val alias = root.resolve("junction")
        val command = ProcessBuilder("cmd.exe", "/c", "mklink", "/J", alias.toString(), target.toString())
            .redirectErrorStream(true).start()
        command.inputStream.use { it.readBytes() }
        assertEquals(0, command.waitFor())
        try {
            assertFails { DesktopControlTransferSpool.create(alias).erase() }
            assertEquals(0L, Files.list(target).use { it.count() })
        } finally { Files.deleteIfExists(alias) }
    }
}
