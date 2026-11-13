package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.ADMINISTRATORS
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SID
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SYSTEM
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.USERS
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.ace
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.directory
import java.nio.file.Path
import kotlin.test.*

/**
 * Every packaged process holds its admission until it exits: each folder from the volume root to its own
 * image, and C:\ProgramData. The per-user package lives in %LOCALAPPDATA%\vpn-control, so those folders
 * include the home folder: while the GUI or serve ran, `git config --global` could not replace
 * `.gitconfig`. Folder pins must let other programs rename into them; the image pin must keep refusing
 * writers, because the installer's readiness probe relies on that (windows-install-native.cs TryReady).
 *
 * The admission's real JnaWindowsInstallAdmission opens are judged by [SharingVolume].
 */
class DesktopWindowsAdmissionPinSharingTest {
    @Test fun aRunningProcessLetsOtherProgramsRenameIntoItsInstallationFoldersAndKeepsItsImageFromWriters() {
        val volume = SharingVolume(SID).apply {
            nodes["C:\\"] = DesktopWindowsPinSharingTest.root()
            nodes["C:\\Users"] = directory(SYSTEM, ace(USERS, 0x1200a9, 3))
            for (path in FOLDERS.drop(2)) nodes[path] = directory(SID)
            nodes[IMAGE] = WindowsInstallInfo(false, owner = SID,
                dacl = listOf(ace(SYSTEM, 0x1f01ff), ace(ADMINISTRATORS, 0x1f01ff), ace(SID, 0x1f01ff)))
            // BUILTIN\Users may create and write attributes in C:\ProgramData: its pin keeps a witness.
            nodes[PROGRAM_DATA] = directory(SYSTEM, ace(USERS, 0x116))
            nodes["$PROGRAM_DATA\\witness"] = directory(SYSTEM)
            witnessParents += PROGRAM_DATA
        }
        // No installer gate exists yet: the admission returns its lease with every pin retained.
        val lease = DesktopWindowsInstallAdmission.enter(Path.of(IMAGE), admission(volume))
        assertEquals((FOLDERS + IMAGE + PROGRAM_DATA + "$PROGRAM_DATA\\witness").toSet(), volume.live().map { it.path }.toSet())
        volume.assertOthersMayAddEntries(FOLDERS + PROGRAM_DATA)
        volume.assertPinnedAgainstRenameAndDeletion(FOLDERS + IMAGE + PROGRAM_DATA + "$PROGRAM_DATA\\witness")
        volume.assertEveryPinnedFolderKeepsAnUndeletableChild(FOLDERS)
        // The coordinator's readiness probe: GENERIC_WRITE | READ_CONTROL | READ_ATTRIBUTES, sharing all.
        assertNotNull(volume.refusal(IMAGE, 0x40020080, 7), "A running image must stay pinned against writers")
        lease.close()
        assertTrue(volume.live().isEmpty())
    }

    private fun admission(volume: SharingVolume) = object : WindowsAdmissionNative by JnaWindowsInstallAdmission(volume) {
        override fun currentSid() = SID
        override fun programData() = PROGRAM_DATA
        override fun inspect(handle: WindowsInstallNative.Handle) = volume.inspect(handle)
        override fun persistentAcl(handle: WindowsInstallNative.Handle) = true
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = "\\\\?\\" + (handle as SharingVolume.Open).path
        override fun children(path: String) = if (path in volume.witnessParents) listOf("witness") else emptyList()
        override fun invariantUppercase(value: String) = value.uppercase(java.util.Locale.ROOT)
        override fun close(handle: WindowsInstallNative.Handle) = volume.close(handle)
    }

    companion object {
        const val PROGRAM_DATA = "C:\\ProgramData"
        const val IMAGE = "C:\\Users\\東京\\AppData\\Local\\vpn-control\\vpn-control-cli.exe"
        val FOLDERS = listOf("C:\\", "C:\\Users", "C:\\Users\\東京", "C:\\Users\\東京\\AppData",
            "C:\\Users\\東京\\AppData\\Local", "C:\\Users\\東京\\AppData\\Local\\vpn-control")
    }
}
