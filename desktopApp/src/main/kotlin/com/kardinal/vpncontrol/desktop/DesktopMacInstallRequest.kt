package com.kardinal.vpncontrol.desktop

import java.nio.file.Path

internal enum class DesktopMacInstallAuthority { USER_LOCAL, MACHINE }

/** Captured data-only worker input. Authority is explicit and must be independently verified by the worker. */
internal data class DesktopMacInstallRequest(val jobId: String, val authority: DesktopMacInstallAuthority,
    val owner: DesktopMacInstallProcess, val frontend: DesktopMacInstallProcess?,
    val packageFile: String, val packageSize: Long, val packageSha256: String, val stateDirectory: String) {
    val bundle: Path = Path.of(owner.executable).parent.parent.parent
    init {
        require(DesktopInstallJobNames.validJob(jobId))
        require(packageSize > 0 && packageSha256.matches(Regex("[a-f0-9]{64}")))
        listOf(packageFile, stateDirectory, owner.executable).forEach(::path)
        require(Path.of(owner.executable).fileName.toString() == "vpn-control" &&
            Path.of(owner.executable).parent.fileName.toString() == "MacOS" &&
            Path.of(owner.executable).parent.parent.fileName.toString() == "Contents" &&
            bundle.fileName.toString().endsWith(".app"))
        frontend?.let { require(it.uid == owner.uid && it.executable == owner.executable && it.pid != owner.pid) }
    }
    fun encode(): ByteArray = (listOf("1", jobId, authority.name,
        owner.pid.toString(), owner.uid.toString(), owner.startSeconds.toString(), owner.startMicroseconds.toString(),
        frontend?.pid?.toString() ?: "0", frontend?.startSeconds?.toString() ?: "0", frontend?.startMicroseconds?.toString() ?: "0",
        packageSize.toString(), packageSha256, packageFile, owner.executable, stateDirectory)
        .joinToString("\n", postfix = "\n")).encodeToByteArray().also { require(it.size <= 16384) }
    override fun toString() = "DesktopMacInstallRequest(jobId=$jobId, authority=$authority, metadata=<private>)"
    private fun path(value: String) {
        require(value.length <= 4096 && value.none { it.code < 32 || it.code == 127 })
        val path = Path.of(value)
        require(path.isAbsolute && path.normalize() == path && path.toString() == value)
    }
}
