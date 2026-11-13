package com.kardinal.vpncontrol.desktop

import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinBase
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
    /** Native document row 83484649: a pin refused every other program's rename into the folders it held. */
    @Test fun nativeTransferPinsLetOtherProgramsRenameAndLinkIntoPinnedFoldersButNeverMoveThem() = fixture { root ->
        val pinned = Files.createDirectory(root.resolve("pinned"))
        val outside = Files.createTempDirectory("transfer-native-outside-")
        try {
            // The product's own pins: the folder, its parent and every ancestor up to the volume root.
            val pins = DesktopWindowsTransferPins.open(pinned.toAbsolutePath().toString(),
                JnaWindowsInstallAdmission().currentSid(), JnaWindowsInstallNative())
            try {
                assertFails { Files.delete(pinned) } // empty, so only the pin can refuse its deletion
                assertFails { Files.move(pinned, root.resolve("renamed")) }
                // MoveFileExW and CreateHardLinkW open the folder of the new name for FILE_ADD_FILE.
                Files.move(Files.writeString(outside.resolve("file.txt"), "file"), pinned.resolve("file.txt"))
                Files.createLink(pinned.resolve("file-link.txt"), pinned.resolve("file.txt"))
                Files.move(Files.createDirectory(outside.resolve("folder")), pinned.resolve("folder"))
                Files.move(Files.writeString(outside.resolve("parent.txt"), "parent"), root.resolve("parent.txt"))
                Files.move(root.resolve("parent.txt"), root.resolve("parent-renamed.txt"))
                assertFails { Files.move(pinned, root.resolve("renamed")) }
                assertEquals(setOf("file.txt", "file-link.txt", "folder"), Files.list(pinned).use { paths ->
                    paths.map { it.fileName.toString() }.toList().toSet() })
            } finally { pins.close() }
            Files.move(pinned, root.resolve("released"))
        } finally { Files.walk(outside).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun nativeAdmissionDirectoryPinsLetOtherProgramsRenameIntoTheFolder() = fixture { root ->
        val empty = Files.createDirectory(root.resolve("admitted-empty"))
        val folder = Files.createDirectory(root.resolve("admitted"))
        val admission = JnaWindowsInstallAdmission()
        val handles = listOf(admission.openDirectory(empty.toString()), admission.openDirectory(folder.toString()))
        try {
            assertFails { Files.delete(empty) }
            Files.move(Files.writeString(root.resolve("source.txt"), "source"), folder.resolve("moved.txt"))
            assertFails { Files.move(folder, root.resolve("admitted-renamed")) }
        } finally { handles.asReversed().forEach(admission::close) }
        Files.delete(empty)
        assertTrue(Files.isRegularFile(folder.resolve("moved.txt")))
    }
    /** The rule behind 83484649, shown on the OS: a folder handle that denies write sharing refuses renames into it. */
    @Test fun nativeFolderHandleDenyingWriteSharingRefusesRenamesIntoTheFolder() = fixture { root ->
        val folder = Files.createDirectory(root.resolve("read-sharing-only"))
        // The unfixed pin, written out: LIST_DIRECTORY | READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE, share read,
        // OPEN_EXISTING, BACKUP_SEMANTICS | OPEN_REPARSE_POINT.
        val strict = Kernel32.INSTANCE.CreateFile(folder.toString(), 0x00120081, 1, null, 3, 0x02200000, null)
        assertNotEquals(WinBase.INVALID_HANDLE_VALUE.pointer, strict.pointer)
        try {
            val source = Files.writeString(root.resolve("refused.txt"), "refused")
            assertFailsWith<java.nio.file.FileSystemException> { Files.move(source, folder.resolve("refused.txt")) }
            Files.writeString(folder.resolve("created.txt"), "created") // creating by path opens no folder
        } finally { assertTrue(Kernel32.INSTANCE.CloseHandle(strict)) }
        Files.move(root.resolve("refused.txt"), folder.resolve("refused.txt"))
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
