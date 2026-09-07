package com.kardinal.vpncontrol.desktop

/** Fixed data-only records for the captured shell worker; never sourced or evaluated as shell code. */
internal data class DesktopLinuxInstallRequest(
    val jobId: String,
    val ownerPid: Long,
    val ownerStartTicks: Long,
    val ownerUid: Long,
    val packageType: String,
    val packageSha256: String,
    val packageSize: Long,
    val packageFile: String,
    val launcher: String,
    val stateDirectory: String,
    val frontendPid: Long = 0,
    val frontendStartTicks: Long = 0,
) {
    init {
        require(DesktopInstallJobNames.validJob(jobId))
        require(ownerPid in 1..Int.MAX_VALUE && ownerStartTicks > 0 && ownerUid in 1..0xfffffffeL)
        require((frontendPid == 0L && frontendStartTicks == 0L) || (frontendPid in 1..Int.MAX_VALUE && frontendStartTicks > 0))
        require(packageType in setOf("deb", "rpm", "arch-bundle"))
        require(packageSha256.matches(Regex("[a-f0-9]{64}")) && packageSize > 0)
        listOf(packageFile, launcher, stateDirectory).forEach { path ->
            require(path.startsWith('/') && path.length <= 4096 && path.none { it.code < 32 || it.code == 127 })
            require(path.split('/').drop(1).all { it.isNotEmpty() && it !in setOf(".", "..") })
        }
        require(launcher.substringAfterLast('/') == "vpn-control")
    }

    fun encode(): ByteArray = listOf("1", jobId, ownerPid, ownerStartTicks, ownerUid, packageType,
        packageSha256, packageSize, packageFile, launcher, stateDirectory, frontendPid, frontendStartTicks)
        .joinToString("\n", postfix = "\n").encodeToByteArray().also { require(it.size <= 16384) }

    override fun toString() = "DesktopLinuxInstallRequest(jobId=$jobId, metadata=<private>)"
}
