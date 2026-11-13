package com.kardinal.vpncontrol.desktop

import kotlin.test.*

/**
 * Other programs' renames and hard links into folders the product pins (native document row 83484649).
 *
 * The serve pinned every folder from the volume root to its transfer spool with FILE_LIST_DIRECTORY and
 * read sharing only, for as long as a transfer lived; the installer pinned %LOCALAPPDATA% and its
 * ancestors the same way. A rename or hard link by path makes Windows open the folder of the new name
 * for FILE_ADD_FILE (a folder: FILE_ADD_SUBDIRECTORY) while sharing read and write ([MS-FSA] 2.1.5.15.7,
 * 2.1.5.15.12, Appendix A <183> and <185>). So every rename into %TEMP%, %LOCALAPPDATA%, AppData, the
 * home folder (`git config --global` replaces `.gitconfig` that way), C:\Users or C:\ ended in a sharing
 * violation (WinError 32) meanwhile.
 *
 * [SharingVolume] judges each open as [MS-FSA] 2.1.5.1.2.2 does; each product open is judged with the
 * real [windowsInstallOpenOptions] for the access the product passes, after its token's access check. A
 * pin must keep refusing every open with DELETE of the folder it pins (no rename, no deletion), and only that.
 */
class DesktopWindowsPinSharingTest {
    @Test fun aRetainedTransferLetsOtherProgramsRenameAndLinkIntoTheSpoolParentAndEveryAncestor() {
        val volume = transferVolume()
        val pins = DesktopWindowsTransferPins.open(TEMP, SID, volume, volume.ancestry())
        val private = pins.createDirectory()
        assertEquals(CHAIN + private, volume.live().map { it.path }.filterNot { it == WITNESS })
        volume.assertOthersMayAddEntries(CHAIN)
        volume.assertPinnedAgainstRenameAndDeletion(CHAIN + WITNESS + private)
        volume.assertEveryPinnedFolderKeepsAnUndeletableChild(CHAIN)
        // The private transfer folder stays the product's alone: its DELETE handle refuses the
        // destination open of any rename or link into it.
        assertNotNull(volume.refusal(private, FILE_ADD_FILE or SYNCHRONIZE, SHARE_READ or SHARE_WRITE))
        pins.deleteDirectory()
        pins.close()
        assertTrue(volume.live().isEmpty())
        assertEquals(listOf(private), volume.deleted)
    }

    @Test fun theInstallersInputPinsLetOtherProgramsRenameIntoLocalAppDataAndItsAncestors() {
        // DesktopWindowsInstaller.prepare holds three pin sets until the installation ends:
        // %LOCALAPPDATA%, its private input root and the job's input folder.
        val volume = transferVolume()
        val local = "C:\\Users\\東京\\AppData\\Local"
        val inputs = "$local\\vpn-control-install-inputs"
        val input = "$inputs\\$JOB"
        volume.nodes[inputs] = directory(SID)
        volume.nodes[input] = directory(SID)
        val held = listOf(local, inputs, input).map { DesktopWindowsTransferPins.open(it, SID, volume, volume.ancestry()) }
        val folders = CHAIN.dropLast(1) + inputs + input
        assertEquals(folders.toSet(), volume.live().map { it.path }.filterNot { it == WITNESS }.toSet())
        volume.assertOthersMayAddEntries(folders)
        volume.assertPinnedAgainstRenameAndDeletion(folders + WITNESS)
        held.asReversed().forEach(DesktopWindowsTransferPins::close)
        assertTrue(volume.live().isEmpty())
    }

    @Test fun protectedInstallerStorePinsLetOtherProgramsRenameIntoTheVolumeRootAndProgramData() {
        // The installer store belongs to BUILTIN\Administrators: its backend runs elevated.
        val volume = SharingVolume(SID, SharingVolume.token(SID, elevated = true)).apply {
            nodes["C:\\"] = root()
            // BUILTIN\Users may create and write attributes in C:\ProgramData: its pin keeps a witness.
            nodes["C:\\ProgramData"] = directory(SYSTEM, ace(USERS, 0x116))
            nodes["C:\\ProgramData\\witness"] = directory(SYSTEM)
            witnessParents += "C:\\ProgramData"
        }
        val backend = DesktopWindowsInstallJobBackend(volume, volume.ancestry())
        val root = backend.openRoot(backend.defaultRoot(), create = true)
        val job = root.createJob(JOB)
        val store = "C:\\ProgramData\\vpn-control-install-jobs"
        val folders = listOf("C:\\", "C:\\ProgramData", store, "$store\\$JOB")
        volume.assertOthersMayAddEntries(folders)
        volume.assertPinnedAgainstRenameAndDeletion(folders + "C:\\ProgramData\\witness")
        job.close()
        root.close()
        assertTrue(volume.live().isEmpty())
    }

    @Test fun aRuntimeResourceAdmissionLetsOtherProgramsRenameIntoItsFolderChain() {
        // DesktopWindowsResourceAdmission.capture holds every folder from the volume root to a resource's folder in
        // the user's workspace while it admits the resource, as the broker's PinParents does under the same token.
        val volume = SharingVolume(SID)
        val chain = CHAIN.take(3) + "C:\\Users\\東京\\.vpn-control-desktop"
        for (folder in chain) volume.opens += SharingVolume.Open(folder, 0,
            SharingVolume.fileRights(DesktopWindowsResourceAdmission.FOLDER_PIN_ACCESS), DesktopWindowsResourceAdmission.FOLDER_PIN_SHARE)
        volume.assertOthersMayAddEntries(chain)
        volume.assertPinnedAgainstRenameAndDeletion(chain)
    }

    /**
     * Review of the fix above (pins-security): a folder pin that shares writes also admits another principal's
     * FILE_ADD_FILE handle on the folder, which is FILE_WRITE_DATA, and FSCTL_SET_REPARSE_POINT accepts FILE_WRITE_DATA
     * as well as FILE_WRITE_ATTRIBUTES ([MS-FSA] 2.1.5.10.37). The last folder of a transfer (the spool parent, an
     * export's folder) holds no child of the product until the product creates one by path. If that folder grants
     * another local user FILE_ADD_FILE (a drop box, or C:\Windows\Temp for a CLI run as SYSTEM) and is empty, that user
     * may turn it into a junction between the pins and the creation, and the product creates its entry in the other
     * user's folder. Whatever the product does, nothing it creates may stay outside the folder it pinned, and a
     * transfer that goes on lives in that folder.
     */
    @Test fun anotherUserCannotRedirectATransferOutOfAnEmptyPinnedFolderThroughAJunction() {
        for ((sid, volume, folder) in listOf(Triple(SID, dropVolume(), DROP), Triple(SYSTEM, systemTempVolume(), WINDOWS_TEMP))) {
            val raced = mutableListOf<Int>()
            volume.beforeCreate = { path ->
                if (volume.isChild(path, folder)) raced += volume.mountAs(MALLORY_GROUPS, folder, HIDEOUT, FILE_ADD_FILE)
            }
            val created = runCatching { DesktopWindowsTransferPins.open(folder, sid, volume, volume.ancestry()).use { it.createDirectory() } }
            assertEquals(emptyList(), volume.nodes.keys.filter { volume.isChild(it, HIDEOUT) },
                "$folder: the transfer was created in another user's folder (junction set with FILE_ADD_FILE: $raced, outcome $created)")
            created.onSuccess { path -> assertEquals(path, volume.resolve(path), "$folder: the transfer left the pinned folder") }
            assertTrue(volume.live().isEmpty(), "$folder: ${volume.live()}")
        }
    }

    /** The trust policy's half: FILE_ADD_FILE, like attribute and EA writes, is admitted only beside a retained witness. */
    @Test fun aFolderGrantingAnotherPrincipalAddFileIsPinnedOnlyWhileAWitnessKeepsItNonEmpty() {
        for ((sid, volume, folder) in listOf(Triple(SID, dropVolume(), DROP), Triple(SYSTEM, systemTempVolume(), WINDOWS_TEMP))) {
            // Empty: no child can keep it from becoming a junction, so it is refused before anything is created,
            // with a message that names the folder and what helps.
            val refused = assertFailsWith<IllegalStateException> { DesktopWindowsTransferPins.open(folder, sid, volume, volume.ancestry()) }
            assertEquals(lastFolderRefusal(folder), refused.message)
            assertTrue(volume.live().isEmpty())
            assertTrue(volume.created.isEmpty())
            // Not empty: an entry the token can open is retained as the witness, and the junction can no longer be set.
            // In the drop box the user's own file; in C:\Windows\Temp another program's, which inherits SYSTEM's access.
            volume.nodes["$folder\\witness"] = if (sid == SYSTEM) inheritedFile(MALLORY) else ownFile(sid)
            volume.witnessParents += folder
            val pins = DesktopWindowsTransferPins.open(folder, sid, volume, volume.ancestry())
            assertEquals(145, volume.mountAs(MALLORY_GROUPS, folder, HIDEOUT, FILE_ADD_FILE)) // ERROR_DIR_NOT_EMPTY
            val private = pins.createDirectory()
            assertEquals("$folder\\", private.substringBeforeLast('\\') + "\\")
            assertEquals(private, volume.resolve(private))
            volume.assertOthersMayAddEntries(listOf(folder))
            volume.assertPinnedAgainstRenameAndDeletion(listOf(folder, "$folder\\witness", private))
            pins.deleteDirectory()
            pins.close()
            assertTrue(volume.live().isEmpty())
        }
        // FILE_ADD_SUBDIRECTORY alone cannot set a reparse point: C:\ as shipped (Authenticated Users) needs no witness.
        val volume = dropVolume().apply { nodes[DROP] = directory(SID, ace(USERS, 0x1200a9 or FILE_ADD_SUBDIRECTORY)) }
        DesktopWindowsTransferPins.open(DROP, SID, volume, volume.ancestry()).use { pins ->
            assertEquals(5, volume.mountAs(MALLORY_GROUPS, DROP, HIDEOUT, FILE_ADD_SUBDIRECTORY or FILE_ADD_FILE)) // not granted
            assertEquals(5, volume.mountAs(MALLORY_GROUPS, DROP, HIDEOUT, FILE_ADD_SUBDIRECTORY)) // no FSCTL right
            assertEquals(listOf("C:\\", DROP), volume.live().map { it.path })
            volume.assertOthersMayAddEntries(listOf(DROP))
        }
    }

    /**
     * Review of the hardening: the product opens a witness as it opens anything, without privileges, so an entry
     * private to another user is none (5). A last folder that others may write and that holds only such entries (the
     * files other users dropped in a drop box; a private file in C:\Windows\Temp) is refused before anything is created,
     * with the message an empty one gets; an entry the token can open beside them is retained and the transfer goes on.
     * An intermediate folder without a witness keeps the ancestor message: it is not the folder the user named.
     */
    @Test fun aLastFolderHoldingOnlyEntriesTheUserCannotOpenIsRefusedWithAClearMessage() {
        for ((sid, volume, folder) in listOf(Triple(SID, dropVolume(), DROP), Triple(SYSTEM, systemTempVolume(), WINDOWS_TEMP))) {
            volume.addEntry(folder, "dropped.txt", privateTo(MALLORY))
            assertEquals(5, assertFailsWith<WindowsInstallNativeFailure> {
                volume.open("$folder\\dropped.txt", WindowsInstallNative.PINNED_DIRECTORY, shareDelete = false) }.code)
            val refused = assertFailsWith<IllegalStateException> { DesktopWindowsTransferPins.open(folder, sid, volume, volume.ancestry()) }
            assertEquals(lastFolderRefusal(folder), refused.message)
            assertTrue(volume.live().isEmpty(), "$folder: ${volume.live()}")
            assertTrue(volume.created.isEmpty())
            volume.addEntry(folder, "mine.txt", if (sid == SYSTEM) inheritedFile(MALLORY) else ownFile(sid))
            DesktopWindowsTransferPins.open(folder, sid, volume, volume.ancestry()).use { pins ->
                assertEquals(listOf("$folder\\mine.txt"), volume.live().map { it.path }.filter { volume.isChild(it, folder) })
                assertEquals(145, volume.mountAs(MALLORY_GROUPS, folder, HIDEOUT, FILE_ADD_FILE))
                val private = pins.createDirectory()
                assertTrue(volume.isChild(private, folder), private)
                assertEquals(private, volume.resolve(private))
                pins.deleteDirectory()
            }
            assertTrue(volume.live().isEmpty(), "$folder: ${volume.live()}")
        }
        // In a real folder the next folder of the chain would be a witness, unless 4096 entries came first.
        val volume = dropVolume().apply {
            nodes["$DROP\\inbox"] = directory(SID)
            addEntry(DROP, "dropped.txt", privateTo(MALLORY))
        }
        val refused = assertFailsWith<IllegalStateException> { DesktopWindowsTransferPins.open("$DROP\\inbox", SID, volume, volume.ancestry()) }
        assertEquals("Unpinned mutable transfer ancestor", refused.message)
        assertTrue(volume.live().isEmpty())
    }

    /**
     * The creation's half, independent of the trust policy: whatever turned the pinned folder into a junction between
     * the pins and the creation (here the volume itself, as a trusted principal or an unknown route could), the
     * product proves by handle that its new folder is a child of the pinned one, or deletes it and fails.
     */
    @Test fun aTransferFolderCreatedByPathIsProvenInsideThePinnedFolderOrDeleted() {
        val volume = transferVolume().apply {
            nodes["C:\\Users\\mallory"] = directory(MALLORY)
            nodes[HIDEOUT] = directory(MALLORY)
        }
        volume.beforeCreate = { path -> if (volume.isChild(path, TEMP)) volume.redirect(TEMP, HIDEOUT) }
        val pins = DesktopWindowsTransferPins.open(TEMP, SID, volume, volume.ancestry())
        assertFails { pins.createDirectory() }
        val strays = volume.created.filter { volume.isChild(it, HIDEOUT) }
        assertEquals(1, strays.size, "The model must have redirected the creation: ${volume.created}")
        assertEquals(strays, volume.deleted, "The product must delete what it created behind the junction")
        pins.close()
        assertTrue(volume.live().isEmpty())
    }

    companion object {
        const val SID = "S-1-5-21-1-2-3-1001"
        const val SYSTEM = "S-1-5-18"
        const val ADMINISTRATORS = "S-1-5-32-544"
        const val USERS = "S-1-5-32-545"
        const val JOB = "11111111-2222-3333-4444-555555555555"
        const val TEMP = "C:\\Users\\東京\\AppData\\Local\\Temp"
        const val WITNESS = "C:\\Users\\東京\\AppData\\witness"
        val CHAIN = listOf("C:\\", "C:\\Users", "C:\\Users\\東京", "C:\\Users\\東京\\AppData",
            "C:\\Users\\東京\\AppData\\Local", TEMP)
        /** Another local user, a member of BUILTIN\Users, and the folder of theirs a junction would lead to. */
        const val MALLORY = "S-1-5-21-1-2-3-1002"
        val MALLORY_GROUPS = setOf(MALLORY, USERS, "S-1-5-11", "S-1-1-0")
        const val HIDEOUT = "C:\\Users\\mallory\\hideout"
        /** An export or spool folder that lets Users drop files: list, traverse, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY. */
        const val DROP = "C:\\drop"
        const val WINDOWS_TEMP = "C:\\Windows\\Temp"
        const val TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

        // Access rights ([MS-SMB2] 2.2.13.1.1, [MS-FSCC]) and sharing.
        const val FILE_ADD_FILE = 0x2 // FILE_WRITE_DATA on a folder
        const val FILE_ADD_SUBDIRECTORY = 0x4 // FILE_APPEND_DATA on a folder
        const val FILE_READ_ATTRIBUTES = 0x80
        const val FILE_WRITE_ATTRIBUTES = 0x100
        const val DELETE = 0x10000
        const val SYNCHRONIZE = 0x100000
        const val SHARE_READ = 1
        const val SHARE_WRITE = 2
        const val SHARE_DELETE = 4

        internal fun ace(sid: String, mask: Int, flags: Int = 0) = WindowsInstallAce(0, flags, mask, sid)
        internal fun directory(owner: String, vararg extra: WindowsInstallAce) = WindowsInstallInfo(true, owner = owner,
            dacl = listOf(ace(SYSTEM, 0x1f01ff, 3), ace(ADMINISTRATORS, 0x1f01ff, 3), ace(owner, 0x1f01ff)) + extra)
        /** A file another user dropped with a DACL of their own: no other token, SYSTEM included, may read it. */
        internal fun privateTo(owner: String) = WindowsInstallInfo(false, owner = owner, dacl = listOf(ace(owner, 0x1f01ff)))
        /** A file [owner] created where CREATOR OWNER is granted full control: theirs to open. */
        internal fun ownFile(owner: String) = WindowsInstallInfo(false, owner = owner, dacl = listOf(ace(owner, 0x1f01ff, 0x10)))
        /** A file [owner] created in C:\Windows\Temp: SYSTEM and Administrators inherit full control, as its creator does. */
        internal fun inheritedFile(owner: String) = WindowsInstallInfo(false, owner = owner,
            dacl = listOf(ace(SYSTEM, 0x1f01ff, 0x10), ace(ADMINISTRATORS, 0x1f01ff, 0x10), ace(owner, 0x1f01ff, 0x10)))
        /** What a refused last folder reports: the GUI shows it as an export's status. */
        internal fun lastFolderRefusal(folder: String) = "Cannot use $folder: other accounts can write to it and it holds " +
            "nothing you can open. Add a file of your own to it, or choose a folder only you can change."
        /** C:\ as Windows ships it: Authenticated Users may create folders there (append data). */
        internal fun root() = directory(SYSTEM, ace("S-1-5-11", 0x4), ace(USERS, 0x1200a9, 3))

        /** The spool of the default java.io.tmpdir; AppData grants another principal attribute writes. */
        internal fun transferVolume() = SharingVolume(SID).apply {
            nodes["C:\\"] = root()
            nodes["C:\\Users"] = directory(SYSTEM, ace(USERS, 0x1200a9, 3), ace("S-1-1-0", 0x1200a9, 3))
            for (path in CHAIN.drop(2)) nodes[path] = directory(SID)
            nodes["C:\\Users\\東京\\AppData"] = directory(SID, ace("S-1-1-0", 0x116))
            nodes[WITNESS] = directory(SID)
            witnessParents += "C:\\Users\\東京\\AppData"
        }

        /** The user's empty drop box C:\drop: BUILTIN\Users may list it and add files and folders (0x1200AF). */
        internal fun dropVolume() = SharingVolume(SID).apply {
            nodes["C:\\"] = root()
            nodes[DROP] = directory(SID, ace(USERS, 0x1200a9 or FILE_ADD_FILE or FILE_ADD_SUBDIRECTORY))
            nodes["C:\\Users"] = directory(SYSTEM, ace(USERS, 0x1200a9, 3))
            nodes["C:\\Users\\mallory"] = directory(MALLORY)
            nodes[HIDEOUT] = directory(MALLORY)
        }

        /** java.io.tmpdir of a CLI run as SYSTEM, emptied: Users may traverse it and add files and folders (S,WD,AD,X). */
        internal fun systemTempVolume() = SharingVolume(SYSTEM).apply {
            nodes["C:\\"] = root()
            nodes["C:\\Windows"] = directory(TRUSTED_INSTALLER, ace(USERS, 0x1200a9, 3))
            nodes[WINDOWS_TEMP] = directory(SYSTEM, ace(USERS, 0x100026, 2))
            nodes["C:\\Users"] = directory(SYSTEM, ace(USERS, 0x1200a9, 3))
            nodes["C:\\Users\\mallory"] = directory(MALLORY)
            nodes[HIDEOUT] = directory(MALLORY)
        }

        /**
         * Another principal opens [folder] with [rights] (sharing everything), as its DACL lets [principals], and sends
         * FSCTL_SET_REPARSE_POINT with a mount point of [target]: 0, or the Win32 error that stopped it.
         */
        internal fun SharingVolume.mountAs(principals: Set<String>, folder: String, target: String, rights: Int): Int = try {
            val handle = foreignOpen(folder, principals, rights or SYNCHRONIZE, SHARE_READ or SHARE_WRITE or SHARE_DELETE)
            try { setMountPoint(handle, target); 0 } finally { close(handle) }
        } catch (failure: WindowsInstallNativeFailure) { failure.code }
    }
}

/**
 * A volume whose opens Windows judges by [MS-FSA] 2.1.5.1.2.2 ("Algorithm to Check Sharing Access to an
 * Existing Stream or Directory"): only READ_DATA, EXECUTE, WRITE_DATA, APPEND_DATA and DELETE take part,
 * in both directions, so a metadata-only handle neither refuses nor is refused.
 *
 * Every open of an existing object, the product's (its token holds [principals]) as another principal's,
 * first passes the access check of [granted]: the product enables no privilege, so an entry private to
 * another user refuses it (5) as on Windows.
 *
 * Mount points follow [MS-FSA] 2.1.5.10.37: another principal's open must hold FILE_WRITE_DATA or
 * FILE_WRITE_ATTRIBUTES, as the folder's DACL grants it, and the folder must be empty. A path then
 * resolves through every mount point but in its last component (the product opens with
 * FILE_FLAG_OPEN_REPARSE_POINT), so an entry created by path lands in the mount point's target.
 */
internal class SharingVolume(private val sid: String, val principals: Set<String> = token(sid)) : WindowsInstallNative {
    class Open(val path: String, val access: Int, val rights: Int, val share: Int) : WindowsInstallNative.Handle {
        var closed = false
        override fun toString() = "open($path, access=$access, rights=0x${rights.toString(16)}, share=$share)"
    }
    val nodes = linkedMapOf<String, WindowsInstallInfo>()
    val opens = mutableListOf<Open>()
    val deleted = mutableListOf<String>()
    val witnessParents = mutableSetOf<String>()
    /** More entries an enumeration of a folder lists (after `witness`), by folder key, in order: see [addEntry]. */
    val entries = linkedMapOf<String, MutableList<String>>()
    /** Every entry the product created, at the path where it actually landed. */
    val created = mutableListOf<String>()
    /** Mount points by folder key: their targets. */
    val mounts = linkedMapOf<String, String>()
    /** Runs as the product is about to create [path]: where a racing principal acts. */
    var beforeCreate: (String) -> Unit = {}

    fun live() = opens.filter { !it.closed }
    private fun key(path: String) = path.trimEnd('\\').lowercase()
    private fun parent(path: String) = path.trimEnd('\\').substringBeforeLast('\\').let { if (it.length == 2) "$it\\" else it }
    fun isChild(path: String, folder: String) = key(path) != key(folder) && key(parent(path)) == key(folder)

    /** The object [path] names: every component before the last follows a mount point. */
    fun resolve(path: String): String {
        val up = parent(path)
        if (key(up) == key(path)) return path
        var folder = resolve(up)
        while (true) folder = mounts[key(folder)]?.let(::resolve) ?: break
        return folder.trimEnd('\\') + "\\" + path.trimEnd('\\').substringAfterLast('\\')
    }

    /** [info] as the entry [name] of [folder], which an enumeration of [folder] lists. */
    fun addEntry(folder: String, name: String, info: WindowsInstallInfo) {
        nodes[folder.trimEnd('\\') + "\\" + name] = info
        entries.getOrPut(key(folder)) { mutableListOf() } += name
    }

    /**
     * The rights a token holding [principals] gets on the object at [actual], with no privilege enabled (so
     * FILE_FLAG_BACKUP_SEMANTICS bypasses nothing): its owner's implicit READ_CONTROL and WRITE_DAC unless an
     * OWNER RIGHTS ACE stands for them, then the DACL's ACEs that apply to the object (not inherit-only) in order,
     * each granting or denying only what is not decided yet; FILE_READ_ATTRIBUTES where the folder grants
     * FILE_LIST_DIRECTORY, DELETE where it grants FILE_DELETE_CHILD. No DACL grants everything.
     */
    fun granted(actual: String, principals: Set<String>): Int {
        val info = nodes.getValue(actual)
        val dacl = info.dacl ?: return 0x1f01ff
        val owner = info.owner in principals
        var allowed = if (owner && dacl.none { it.flags and 8 == 0 && it.sid == OWNER_RIGHTS }) 0x60000 else 0
        var denied = 0
        for (ace in dacl) {
            if (ace.flags and 8 != 0 || !(ace.sid in principals || owner && ace.sid == OWNER_RIGHTS)) continue
            val mask = fileRights(ace.mask)
            if (ace.type == 0) allowed = allowed or (mask and denied.inv()) else denied = denied or (mask and allowed.inv())
        }
        val folder = parent(actual)
        if (key(folder) != key(actual) && folder in nodes) {
            val inFolder = granted(folder, principals)
            if (inFolder and 0x1 != 0) allowed = allowed or 0x80 // FILE_LIST_DIRECTORY: FILE_READ_ATTRIBUTES
            if (inFolder and 0x40 != 0) allowed = allowed or DELETE // FILE_DELETE_CHILD: DELETE
        }
        return allowed
    }

    /** Another principal's open: only the rights [granted] gives [principals], then judged for sharing like any other. */
    fun foreignOpen(path: String, principals: Set<String>, rights: Int, share: Int): Open {
        val actual = resolve(path)
        if (actual !in nodes) throw WindowsInstallNativeFailure(2)
        if (rights and granted(actual, principals).inv() != 0) throw WindowsInstallNativeFailure(5)
        if (live().any { key(it.path) == key(actual) && refuses(it, rights, share) }) throw WindowsInstallNativeFailure(32)
        return Open(actual, -1, rights, share).also { opens += it }
    }

    /** FSCTL_SET_REPARSE_POINT with a mount point of [target] on the folder [handle] holds ([MS-FSA] 2.1.5.10.37). */
    fun setMountPoint(handle: Open, target: String) {
        check(!handle.closed)
        if (handle.rights and (0x2 or 0x100) == 0) throw WindowsInstallNativeFailure(5) // FILE_WRITE_DATA or _ATTRIBUTES
        if (nodes.keys.any { isChild(it, handle.path) }) throw WindowsInstallNativeFailure(145) // ERROR_DIR_NOT_EMPTY
        redirect(handle.path, target)
    }

    /** A mount point however it came about, with no access check: what the product must still detect. */
    fun redirect(folder: String, target: String) {
        val actual = resolve(folder)
        nodes[actual] = nodes.getValue(actual).copy(attributes = 0x410, reparseTag = 0xA0000003.toInt())
        mounts[key(actual)] = target
    }

    /** The live handle that makes Windows refuse an open of [path] with [access] and [share], or null. */
    fun refusal(path: String, access: Int, share: Int): Open? {
        val wanted = fileRights(access)
        return live().firstOrNull { key(it.path) == key(path) && refuses(it, wanted, share) }
    }

    /** Rename and hard-link destinations as Windows 11 opens them; creating an entry by path opens no folder. */
    fun assertOthersMayAddEntries(folders: List<String>) {
        for (folder in folders) {
            val sharing = DesktopWindowsPinSharingTest.SHARE_READ or DesktopWindowsPinSharingTest.SHARE_WRITE
            for ((what, access) in listOf("a file or link" to DesktopWindowsPinSharingTest.FILE_ADD_FILE,
                    "a folder" to DesktopWindowsPinSharingTest.FILE_ADD_SUBDIRECTORY)) {
                val refused = refusal(folder, access or DesktopWindowsPinSharingTest.SYNCHRONIZE, sharing)
                assertNull(refused, "Renaming $what into $folder must not end in a sharing violation; refused by $refused")
            }
        }
    }

    /** A rename or deletion of the pinned object itself opens it with DELETE, however generously it shares. */
    fun assertPinnedAgainstRenameAndDeletion(paths: List<String>) {
        for (path in paths) {
            assertNotNull(refusal(path, DesktopWindowsPinSharingTest.DELETE or DesktopWindowsPinSharingTest.SYNCHRONIZE or
                DesktopWindowsPinSharingTest.FILE_READ_ATTRIBUTES, 7), "$path must not be renamed or deleted while pinned")
            // Not the product's choice but the rule's: FSCTL_SET_REPARSE_POINT accepts a handle with FILE_WRITE_DATA
            // or FILE_WRITE_ATTRIBUTES ([MS-FSA] 2.1.5.10.37). FILE_WRITE_ATTRIBUTES takes no part in sharing, and a
            // pin that shares writes admits FILE_WRITE_DATA too: only a non-empty folder takes no reparse point.
            assertNull(refusal(path, DesktopWindowsPinSharingTest.FILE_WRITE_ATTRIBUTES or DesktopWindowsPinSharingTest.SYNCHRONIZE, 0))
        }
    }

    /** What keeps a pinned folder from becoming a junction: a non-empty folder takes none ([MS-FSA] 2.1.5.10.37). */
    fun assertEveryPinnedFolderKeepsAnUndeletableChild(folders: List<String>) {
        for (folder in folders) assertTrue(live().any { key(parent(it.path)) == key(folder) &&
            it.share and DesktopWindowsPinSharingTest.SHARE_DELETE == 0 &&
            it.rights and SHARING_RIGHTS != 0 }, "$folder keeps no undeletable child")
    }

    fun ancestry(): WindowsAdmissionNative = object : WindowsAdmissionNative by JnaWindowsInstallAdmission() {
        override fun children(path: String) =
            (if (path in witnessParents) listOf("witness") else emptyList()) + entries[key(path)].orEmpty()
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + (handle as Open).path
    }

    override fun programData() = "C:\\ProgramData"
    override fun open(path: String, access: Int, shareDelete: Boolean, createSddl: String?): WindowsInstallNative.Handle {
        val options = windowsInstallOpenOptions(access, shareDelete, createSddl != null)
        if (createSddl != null) beforeCreate(path)
        val actual = resolve(path)
        if (createSddl != null) {
            if (actual in nodes) throw WindowsInstallNativeFailure(80)
            nodes[actual] = WindowsInstallInfo(false, owner = ADMINISTRATORS, dacl = emptyList())
            created += actual
        }
        if (actual !in nodes) throw WindowsInstallNativeFailure(2)
        val rights = fileRights(options.rights)
        // The creator of an object is granted what it asked for; an existing object's DACL decides.
        if (createSddl == null && rights and granted(actual, principals).inv() != 0) throw WindowsInstallNativeFailure(5)
        if (live().any { key(it.path) == key(actual) && refuses(it, rights, options.share) }) throw WindowsInstallNativeFailure(32)
        return Open(actual, access, rights, options.share).also { opens += it }
    }
    override fun createDirectory(path: String, sddl: String, allowExisting: Boolean) {
        beforeCreate(path)
        val actual = resolve(path)
        if (actual in nodes) { if (allowExisting) return; throw WindowsInstallNativeFailure(183) }
        check(parent(actual) in nodes) { "No parent for $actual" }
        nodes[actual] = if (sddl == WindowsInstallTrust.directorySddl) WindowsInstallInfo(true, owner = ADMINISTRATORS,
            dacl = listOf(WindowsInstallAce(0, 3, 0x1f01ff, "S-1-5-18"), WindowsInstallAce(0, 3, 0x1f01ff, ADMINISTRATORS),
                WindowsInstallAce(0, 3, 0xA0000000.toInt(), "S-1-5-32-545")))
            else WindowsInstallInfo(true, owner = sid, dacl = listOf(WindowsInstallAce(0, 0, 0x1f01ff, sid)))
        created += actual
    }
    override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
        val open = handle as Open
        check(!open.closed)
        return nodes.getValue(open.path)
    }
    /** Deletion on close, taken at once: the entry leaves its folder. */
    override fun delete(handle: WindowsInstallNative.Handle) { deleted += (handle as Open).path; nodes.remove(handle.path) }
    override fun close(handle: WindowsInstallNative.Handle) { (handle as Open).let { check(!it.closed); it.closed = true } }
    override fun read(handle: WindowsInstallNative.Handle, limit: Int): ByteArray = error("unused")
    override fun writeAndSync(handle: WindowsInstallNative.Handle, bytes: ByteArray) = error("unused")
    override fun rename(handle: WindowsInstallNative.Handle, directory: WindowsInstallNative.Handle, name: String) = error("unused")

    companion object {
        private const val ADMINISTRATORS = "S-1-5-32-544"
        private const val OWNER_RIGHTS = "S-1-3-4"
        private const val READ = 0x1 or 0x20 // FILE_READ_DATA, FILE_EXECUTE
        private const val WRITE = 0x2 or 0x4 // FILE_WRITE_DATA, FILE_APPEND_DATA
        private const val DELETE = 0x10000
        const val SHARING_RIGHTS = READ or WRITE or DELETE

        /**
         * The principals an allow ACE may name in [sid]'s token: LocalSystem's (with BUILTIN\Administrators), or a
         * user's with BUILTIN\Users; an administrator's BUILTIN\Administrators only when [elevated] (UAC leaves it
         * deny-only otherwise).
         */
        fun token(sid: String, elevated: Boolean = false): Set<String> = when {
            sid == "S-1-5-18" -> setOf(sid, ADMINISTRATORS, "S-1-1-0", "S-1-5-11")
            elevated -> setOf(sid, "S-1-5-32-545", ADMINISTRATORS, "S-1-1-0", "S-1-5-11")
            else -> setOf(sid, "S-1-5-32-545", "S-1-1-0", "S-1-5-11")
        }

        /** Generic rights as files map them ([MS-SMB2] 2.2.13.1.1, FILE_GENERIC_*). */
        fun fileRights(mask: Int): Int {
            var rights = mask and 0x0fffffff
            if (mask and 0x80000000.toInt() != 0) rights = rights or 0x120089
            if (mask and 0x40000000 != 0) rights = rights or 0x120116
            if (mask and 0x20000000 != 0) rights = rights or 0x1200a0
            if (mask and 0x10000000 != 0) rights = rights or 0x1f01ff
            return rights
        }

        /** [MS-FSA] 2.1.5.1.2.2 for one existing open, with the new open's rights and sharing. */
        fun refuses(existing: Open, rights: Int, share: Int): Boolean {
            if (rights and SHARING_RIGHTS == 0 || existing.rights and SHARING_RIGHTS == 0) return false
            return existing.share and 1 == 0 && rights and READ != 0 ||
                existing.share and 2 == 0 && rights and WRITE != 0 ||
                existing.share and 4 == 0 && rights and DELETE != 0 ||
                share and 1 == 0 && existing.rights and READ != 0 ||
                share and 2 == 0 && existing.rights and WRITE != 0 ||
                share and 4 == 0 && existing.rights and DELETE != 0
        }
    }
}
