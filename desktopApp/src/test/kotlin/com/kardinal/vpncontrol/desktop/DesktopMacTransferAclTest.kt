package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopMacTransferAclTest {
    @Test fun denyOnlyAclIsPermittedOnlyOnAncestorDirectories() {
        requireMacTransferAcl(MacAdmissionAcl.EMPTY, private = true, directory = false)
        requireMacTransferAcl(MacAdmissionAcl.DENY_ONLY, private = false, directory = true)
        for ((private, directory) in listOf(true to true, true to false, false to false))
            assertFails { requireMacTransferAcl(MacAdmissionAcl.DENY_ONLY, private, directory) }
    }

    @Test fun nativePrivateExportThroughDefaultHomeDenyAclKeepsPrivateLeafAndNoReplace() {
        val supplied = System.getProperty("vpn.control.native.macTransferHomeDirectory")
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) && supplied != null)
        val parent = Path.of(requireNotNull(supplied)).toRealPath()
        require(parent.parent == JnaMacInstallAdmission().homeDirectory().toRealPath() &&
            parent.fileName.toString().startsWith("vpn-mac-transfer-"))
        val base = Files.createTempDirectory(parent, "export-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val destination = base.resolve("private.json")
            DesktopPrivateExportWriter.write(destination.toString(), "private-content".encodeToByteArray()).getOrThrow()
            assertEquals("private-content", Files.readString(destination))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(destination))
            assertTrue(DesktopPrivateExportWriter.write(destination.toString(), "replacement".encodeToByteArray()).isFailure)
            assertEquals("private-content", Files.readString(destination))
            assertEquals(listOf(destination), Files.list(base).use { it.toList() })
        } finally { check(base.toFile().deleteRecursively()) }
    }
}
