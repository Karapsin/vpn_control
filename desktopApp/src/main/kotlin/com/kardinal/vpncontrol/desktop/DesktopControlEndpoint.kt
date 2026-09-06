package com.kardinal.vpncontrol.desktop

import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.AclEntry
import java.nio.file.attribute.AclEntryPermission
import java.nio.file.attribute.AclEntryType
import java.nio.file.attribute.AclFileAttributeView
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserPrincipal
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import kotlinx.serialization.json.*

internal class DesktopControlEndpoint(val port: Int, val controllerId: String, val token: String) {
    override fun toString(): String = "DesktopControlEndpoint(<redacted>)"
    fun publish(path: Path) {
        Files.createDirectories(path.parent)
        val temp = path.parent.resolve(".control-endpoint-${UUID.randomUUID()}.tmp")
        try {
            // Native Windows CREATE_NEW sets the token user's owner SID explicitly;
            // elevated tokens must not inherit Administrators as credential owner.
            // All platforms verify private creation before writing the credential.
            DesktopPrivateExportWriter.write(temp.toString(), buildJsonObject {
                put("schemaVersion", 1); put("port", port); put("controllerId", controllerId); put("token", token)
            }.toString().toByteArray(Charsets.UTF_8)).getOrThrow()
            verifyPermissions(temp)
            Files.move(temp, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        } finally { Files.deleteIfExists(temp) }
    }
    companion object {
        fun create(port: Int, controllerId: String = UUID.randomUUID().toString()) = DesktopControlEndpoint(port, controllerId,
            Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32).also { SecureRandom().nextBytes(it) }))
        fun read(path: Path): DesktopControlEndpoint {
            return try {
                require(Files.readAttributes(path, java.nio.file.attribute.BasicFileAttributes::class.java, NOFOLLOW_LINKS).isRegularFile)
                verifyPermissions(path)
                val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(4097) }
                require(bytes.size <= 4096)
                val root = Json.parseToJsonElement(bytes.toString(Charsets.UTF_8)).jsonObject
                require(root.getValue("schemaVersion").jsonPrimitive.int == 1)
                val port = root.getValue("port").jsonPrimitive.int.also { require(it in 1..65535) }
                val id = root.getValue("controllerId").jsonPrimitive.content.also { UUID.fromString(it) }
                val token = root.getValue("token").jsonPrimitive.content.also {
                    require(Base64.getUrlDecoder().decode(it).size == 32)
                }
                DesktopControlEndpoint(port, id, token)
            } catch (missing: java.nio.file.NoSuchFileException) { throw missing }
            catch (_: Exception) { throw DesktopControlProtocolException() }
        }

        private fun verifyPermissions(path: Path) {
            val owner = Files.getOwner(path, NOFOLLOW_LINKS)
            val currentUser = path.fileSystem.userPrincipalLookupService.lookupPrincipalByName(System.getProperty("user.name"))
            require(owner == currentUser)
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                require(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS).all {
                    it in PosixFilePermissions.fromString("rw-------")
                })
            } else {
                val view = Files.getFileAttributeView(path, AclFileAttributeView::class.java, NOFOLLOW_LINKS)
                    ?: throw DesktopControlProtocolException()
                require(isPrivateControlAcl(owner, view.acl))
            }
        }
    }
}

/** Fail closed rather than trying to emulate Windows ACL ordering or group membership. */
internal fun isPrivateControlAcl(owner: UserPrincipal, entries: List<AclEntry>): Boolean =
    entries.any { it.type() == AclEntryType.ALLOW && it.principal() == owner &&
        AclEntryPermission.READ_DATA in it.permissions() } &&
        entries.none { it.type() == AclEntryType.ALLOW && it.principal() != owner && it.permissions().isNotEmpty() }

internal class DesktopControlProtocolException : java.io.IOException("INCOMPATIBLE_PROTOCOL")

/** UTF-8 byte length followed by one JSON string; DTO migration is independent. */
internal object DesktopControlFrames {
    fun write(output: DataOutputStream, payload: String) {
        val bytes = JsonPrimitive(payload).toString().toByteArray(Charsets.UTF_8)
        require(bytes.size <= ControlProtocolCodec.MAX_FRAME_BYTES)
        output.writeInt(bytes.size); output.write(bytes); output.flush()
    }
    fun read(input: DataInputStream): String {
        val size = input.readInt()
        if (size !in 1..ControlProtocolCodec.MAX_FRAME_BYTES) throw DesktopControlProtocolException()
        val bytes = ByteArray(size)
        input.readFully(bytes)
        return try {
            val decoder = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val value = Json.parseToJsonElement(decoder.decode(ByteBuffer.wrap(bytes)).toString()).jsonPrimitive
            if (!value.isString) throw DesktopControlProtocolException()
            value.content
        } catch (_: Exception) { throw DesktopControlProtocolException() }
    }
}
