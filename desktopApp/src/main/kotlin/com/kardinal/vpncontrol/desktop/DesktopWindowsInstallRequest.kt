package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlValue

/** Internal private-file input, never a public control request or command-line payload. */
internal data class DesktopWindowsInstallRequest(
    val jobId: String,
    val principalSid: String,
    val ownerPid: Long,
    val ownerStartedAtEpochMillis: Long,
    val launcher: String,
    val packageFile: String,
    val packageSha256: String,
    val packageSize: Long,
    val stateDirectory: String,
    val frontendPid: Long? = null,
    val frontendStartedAtEpochMillis: Long? = null,
) {
    init {
        require(DesktopInstallJobNames.validJob(jobId))
        require(principalSid.matches(Regex("S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}")))
        require(ownerPid in 1..0xffffffffL && ownerStartedAtEpochMillis > 0)
        require((frontendPid == null) == (frontendStartedAtEpochMillis == null))
        require(frontendPid == null || (frontendPid in 1..0xffffffffL && frontendStartedAtEpochMillis!! > 0))
        requireLocalPath(launcher); requireLocalPath(packageFile); requireLocalPath(stateDirectory)
        require(launcher.substringAfterLast('\\').equals("vpn-control.exe", true))
        require(packageFile.endsWith(".msi", true))
        require(packageSha256.matches(Regex("[0-9a-f]{64}")) && packageSize > 0)
    }

    override fun toString() = "DesktopWindowsInstallRequest(jobId=$jobId, metadata=<private>)"

    fun encode(): ByteArray = ControlProtocolCodec.encodeValues(buildMap {
        put("version", ControlValue.IntegerValue(1))
        put("jobId", ControlValue.Text(jobId)); put("principalSid", ControlValue.Text(principalSid))
        put("ownerPid", ControlValue.IntegerValue(ownerPid))
        put("ownerStartedAtEpochMillis", ControlValue.IntegerValue(ownerStartedAtEpochMillis))
        put("launcher", ControlValue.Text(launcher)); put("packageFile", ControlValue.Text(packageFile))
        put("packageSha256", ControlValue.Text(packageSha256)); put("packageSize", ControlValue.IntegerValue(packageSize))
        put("stateDirectory", ControlValue.Text(stateDirectory))
        frontendPid?.let {
            put("frontendPid", ControlValue.IntegerValue(it))
            put("frontendStartedAtEpochMillis", ControlValue.IntegerValue(frontendStartedAtEpochMillis!!))
        }
    }).encodeToByteArray().also { require(it.size <= MAX_BYTES) }

    companion object {
        const val MAX_BYTES = 65536
        private val required = setOf("version", "jobId", "principalSid", "ownerPid", "ownerStartedAtEpochMillis",
            "launcher", "packageFile", "packageSha256", "packageSize", "stateDirectory")
        fun decode(bytes: ByteArray): DesktopWindowsInstallRequest {
            require(bytes.size <= MAX_BYTES)
            val values = ControlProtocolCodec.decodeValues(bytes.decodeToString(throwOnInvalidSequence = true))
            require(values.keys == required || values.keys == required + setOf("frontendPid", "frontendStartedAtEpochMillis"))
            fun text(key: String) = (values.getValue(key) as ControlValue.Text).value
            fun number(key: String) = (values.getValue(key) as ControlValue.IntegerValue).value
            require(number("version") == 1L)
            return DesktopWindowsInstallRequest(text("jobId"), text("principalSid"), number("ownerPid"),
                number("ownerStartedAtEpochMillis"), text("launcher"), text("packageFile"), text("packageSha256"),
                number("packageSize"), text("stateDirectory"), values["frontendPid"]?.let { (it as ControlValue.IntegerValue).value },
                values["frontendStartedAtEpochMillis"]?.let { (it as ControlValue.IntegerValue).value })
        }

        private fun requireLocalPath(path: String) {
            require(path.length in 4..32760 && path[0].isLetter() && path[0].code < 128 && path[1] == ':' && path[2] == '\\')
            require(path.drop(2).none { it == ':' || it == '/' || it.code < 32 || it in "\"<>|?*" })
            require(path.drop(3).split('\\').all { it.isNotEmpty() && it != "." && it != ".." && !it.endsWith('.') && !it.endsWith(' ') })
        }
    }
}
