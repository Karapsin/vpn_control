package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlValue

/** Fixed NativeAOT entry arguments. Paths, executable code and package bytes are private-file inputs. */
internal class DesktopWindowsInstallHelperInvocation(
    val role: Role,
    val jobId: String,
    val ownerPid: Long,
    val ownerCreationFileTime: Long,
) {
    enum class Role(val argument: String) {
        ORIGINAL_USER("install-user"), COORDINATOR("install-coordinator"),
    }

    init {
        require(DesktopInstallJobNames.validJob(jobId))
        require(ownerPid in 1..0xffffffffL && ownerCreationFileTime > 0)
    }

    fun arguments(): List<String> = listOf(role.argument, jobId, ownerPid.toString(), ownerCreationFileTime.toString())

    override fun toString() = "DesktopWindowsInstallHelperInvocation(role=$role, identity=<private>)"

    companion object {
        fun parse(arguments: List<String>): DesktopWindowsInstallHelperInvocation {
            require(arguments.size == 4)
            val role = Role.entries.single { it.argument == arguments[0] }
            fun number(index: Int): Long {
                val text = arguments[index]
                require(text.isNotEmpty() && text.all { it in '0'..'9' })
                val value = requireNotNull(text.toLongOrNull())
                require(value.toString() == text)
                return value
            }
            return DesktopWindowsInstallHelperInvocation(role, arguments[1], number(2), number(3))
        }
    }
}

/** A data record is not process authority: consumers compare every field with a retained native handle. */
internal data class DesktopWindowsInstallWorkerReady(
    val jobId: String,
    val pid: Long,
    val creationFileTime: Long,
    val principalSid: String,
    val helperSha256: String,
) {
    init {
        require(DesktopInstallJobNames.validJob(jobId))
        require(pid in 1..0xffffffffL && creationFileTime > 0)
        requireCanonicalInstallSid(principalSid)
        require(helperSha256.length == 64 && helperSha256.all { it in '0'..'9' || it in 'a'..'f' })
    }

    fun encode(): ByteArray = ControlProtocolCodec.encodeValues(linkedMapOf(
        "version" to ControlValue.IntegerValue(2),
        "jobId" to ControlValue.Text(jobId),
        "pid" to ControlValue.IntegerValue(pid),
        "creationFileTime" to ControlValue.IntegerValue(creationFileTime),
        "principalSid" to ControlValue.Text(principalSid),
        "helperSha256" to ControlValue.Text(helperSha256),
    )).encodeToByteArray().also { require(it.size <= MAX_BYTES) }

    override fun toString() = "DesktopWindowsInstallWorkerReady(identity=<private>)"

    companion object {
        const val MAX_BYTES = 4096
        private val fields = setOf("version", "jobId", "pid", "creationFileTime", "principalSid", "helperSha256")

        fun decode(bytes: ByteArray): DesktopWindowsInstallWorkerReady {
            require(bytes.size <= MAX_BYTES)
            val values = ControlProtocolCodec.decodeValues(bytes.decodeToString(throwOnInvalidSequence = true))
            require(values.keys == fields && values["version"] == ControlValue.IntegerValue(2))
            fun text(name: String) = (values.getValue(name) as ControlValue.Text).value
            fun number(name: String) = (values.getValue(name) as ControlValue.IntegerValue).value
            return DesktopWindowsInstallWorkerReady(text("jobId"), number("pid"), number("creationFileTime"),
                text("principalSid"), text("helperSha256"))
        }
    }
}

/** Canonical revision-1 SID text; this checks syntax only, never grants its principal authority. */
private fun requireCanonicalInstallSid(value: String) {
    val parts = value.split('-')
    require(parts.size in 4..18 && parts[0] == "S" && parts[1] == "1")
    parts.drop(2).forEachIndexed { index, text ->
        require(text.isNotEmpty() && text.all { it in '0'..'9' })
        val number = requireNotNull(text.toLongOrNull())
        require(text == number.toString() && number in 0..if (index == 0) 0xffffffffffffL else 0xffffffffL)
    }
}
