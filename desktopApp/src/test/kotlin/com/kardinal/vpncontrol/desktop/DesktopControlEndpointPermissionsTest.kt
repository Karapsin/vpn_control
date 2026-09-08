package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DesktopControlEndpointPermissionsTest {
    @Test
    fun jvmAccountNameDoesNotDetermineControllerCredentialOwnership() {
        val directory = Files.createTempDirectory("vpn-control-native-owner")
        val file = directory.resolve("endpoint")
        val endpoint = DesktopControlEndpoint.create(12345)
        val originalName = System.getProperty("user.name")
        try {
            // SYSTEM can have a machine-account JVM name. The same mismatch can be
            // reproduced without Windows or elevation by overriding this property.
            System.setProperty("user.name", "vpn-control-nonexistent-account-${java.util.UUID.randomUUID()}")
            endpoint.publish(file)
            assertEquals(endpoint.token, DesktopControlEndpoint.read(file).token)
        } finally {
            if (originalName == null) System.clearProperty("user.name")
            else System.setProperty("user.name", originalName)
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun publishedDescriptorBelongsToInvokingUserEvenWhenDefaultFileOwnerDiffers() {
        // Elevated Windows tokens commonly create ordinary temp files owned by Administrators.
        // A controller credential must instead belong to the invoking account, from creation.
        val directory = Files.createTempDirectory("vpn-control-endpoint-owner")
        val file = directory.resolve("endpoint")
        try {
            val endpoint = DesktopControlEndpoint.create(12345)
            endpoint.publish(file)
            if (com.sun.jna.Platform.isWindows()) assertCurrentWindowsOwner(file)
            else {
                val invokingUser = file.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name"))
                assertEquals(invokingUser, Files.getOwner(file))
            }
            assertEquals(endpoint.token, DesktopControlEndpoint.read(file).token)
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test
    fun aclMustGrantOwnerReadWithoutGrantingOtherPrincipalsAccess() {
        val owner = UserPrincipal { "owner" }
        val other = UserPrincipal { "other" }
        fun entry(principal: UserPrincipal, type: AclEntryType, permission: AclEntryPermission) =
            AclEntry.newBuilder().setPrincipal(principal).setType(type).setPermissions(permission).build()
        val ownerRead = entry(owner, AclEntryType.ALLOW, AclEntryPermission.READ_DATA)
        assertTrue(isPrivateControlAcl(owner, listOf(ownerRead)))
        assertFalse(isPrivateControlAcl(owner, emptyList()))
        for (permission in listOf(AclEntryPermission.READ_DATA, AclEntryPermission.WRITE_DATA,
            AclEntryPermission.WRITE_ACL, AclEntryPermission.WRITE_OWNER)) {
            assertFalse(isPrivateControlAcl(owner, listOf(ownerRead, entry(other, AclEntryType.ALLOW, permission))))
        }
        assertTrue(isPrivateControlAcl(owner, listOf(ownerRead, entry(other, AclEntryType.DENY, AclEntryPermission.READ_DATA))))
    }

    @Test
    fun descriptorRejectsUnsafePermissionsLinksDirectoriesAndOversizeWithoutLosingMissingState() {
        val directory = Files.createTempDirectory("vpn-control-endpoint-permissions")
        val file = directory.resolve("activation.port")
        try {
            assertFailsWith<NoSuchFileException> { DesktopControlEndpoint.read(file) }
            val endpoint = DesktopControlEndpoint.create(12345)
            endpoint.publish(file)
            assertEquals(endpoint.controllerId, DesktopControlEndpoint.read(file).controllerId)
            assertFailsWith<DesktopControlProtocolException> { DesktopControlEndpoint.read(directory) }
            if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"))
                assertFailsWith<DesktopControlProtocolException> { DesktopControlEndpoint.read(file) }
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"))
                val link = directory.resolve("alias")
                Files.createSymbolicLink(link, file)
                assertFailsWith<DesktopControlProtocolException> { DesktopControlEndpoint.read(link) }
            }
            Files.writeString(file, "x".repeat(4097))
            assertFailsWith<DesktopControlProtocolException> { DesktopControlEndpoint.read(file) }
        } finally { directory.toFile().deleteRecursively() }
    }
}

internal fun assertCurrentWindowsOwner(path: java.nio.file.Path) {
    // Observe ACL metadata without opening a competing data handle: the live spool
    // deliberately retains an exclusive writer. Derive the name from the OS token.
    val account = com.sun.jna.platform.win32.Advapi32Util.getAccountBySid(JnaWindowsInstallAdmission().currentSid())
    val principal = path.fileSystem.userPrincipalLookupService.lookupPrincipalByName(account.fqn)
    assertEquals(principal, Files.getOwner(path, java.nio.file.LinkOption.NOFOLLOW_LINKS))
}
