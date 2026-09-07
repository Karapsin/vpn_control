package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.*

internal fun currentLinuxAuthorizationOwner(): DesktopLinuxAuthorizationOwner? {
    if (!System.getProperty("os.name").startsWith("Linux", true)) return null
    val pid = ProcessHandle.current().pid()
    val uid = (Files.getAttribute(Path.of("/proc/$pid"), "unix:uid") as Number).toLong()
    // An elevated owner cannot register a same-original-user terminal agent.
    return if (uid == 0L) null else DesktopLinuxAuthorizationOwner(pid, linuxInstallProcessStart(pid), uid)
}

internal fun encodeLinuxAuthorizationOwner(owner: DesktopLinuxAuthorizationOwner): JsonObject = buildJsonObject {
    put("pid", owner.pid); put("startTicks", owner.startTicks); put("uid", owner.uid)
}

internal fun decodeLinuxAuthorizationOwner(value: JsonElement?): DesktopLinuxAuthorizationOwner? {
    if (value == null) return null
    val objectValue = value as? JsonObject ?: error("INCOMPATIBLE_PROTOCOL")
    require(objectValue.keys == setOf("pid", "startTicks", "uid"))
    fun integer(name: String): Long {
        val primitive = objectValue.getValue(name) as? JsonPrimitive ?: error("INCOMPATIBLE_PROTOCOL")
        require(!primitive.isString && primitive.content.matches(Regex("[1-9][0-9]*")))
        return primitive.long
    }
    return DesktopLinuxAuthorizationOwner(integer("pid"), integer("startTicks"), integer("uid"))
}

/**
 * Caller must authenticate this exact descriptor (not re-read a replacement endpoint) and validate
 * the response controller ID before calling. A descriptor's token alone is not a process proof.
 * This is deliberately not wired to INSTALL until the owner-side admission gate is ready.
 */
internal fun verifyLinuxAuthorizationOwnerAfterAuthenticatedHandshake(
    endpoint: DesktopControlEndpoint,
    authenticatedControllerId: String,
    verifyNativeOwner: (DesktopLinuxAuthorizationOwner) -> Boolean = ::matchesInstalledLinuxOwner,
): DesktopLinuxAuthorizationOwner {
    check(authenticatedControllerId == endpoint.controllerId) { "CONFLICT" }
    val owner = endpoint.linuxAuthorizationOwner ?: error("INTERACTION_REQUIRED")
    check(verifyNativeOwner(owner)) { "CONFLICT" }
    return owner
}

private fun matchesInstalledLinuxOwner(owner: DesktopLinuxAuthorizationOwner): Boolean = runCatching {
    check(System.getProperty("os.name").startsWith("Linux", true))
    val selfPid = ProcessHandle.current().pid()
    fun uid(pid: Long) = (Files.getAttribute(Path.of("/proc/$pid"), "unix:uid") as Number).toLong()
    check(uid(selfPid) == owner.uid && uid(owner.pid) == owner.uid)
    check(linuxInstallProcessStart(owner.pid) == owner.startTicks)
    val clientImage = Files.readSymbolicLink(Path.of("/proc/$selfPid/exe")).toRealPath()
    val ownerImage = Files.readSymbolicLink(Path.of("/proc/${owner.pid}/exe")).toRealPath()
    // Linux ships one launcher for GUI and CLI. Do not accept java or a matching basename elsewhere.
    check(clientImage == ownerImage && ownerImage.fileName.toString() == "vpn-control")
    verifyTrustedLinuxAuthorizationImage(ownerImage)
    check(uid(owner.pid) == owner.uid && linuxInstallProcessStart(owner.pid) == owner.startTicks)
    true
}.getOrDefault(false)

private fun verifyTrustedLinuxAuthorizationImage(image: Path) {
    var current = image.root
    for (component in image) {
        current = current.resolve(component)
        check(!Files.isSymbolicLink(current))
        val uid = (Files.getAttribute(current, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
        val mode = (Files.getAttribute(current, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
        check(uid == 0L && mode and 0x12 == 0)
    }
    check(Files.isRegularFile(image, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(image))
}
