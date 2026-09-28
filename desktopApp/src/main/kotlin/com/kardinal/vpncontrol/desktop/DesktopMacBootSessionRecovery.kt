package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import com.sun.jna.Pointer
import com.sun.jna.ptr.NativeLongByReference
import java.nio.file.Path
import java.util.UUID

/** Kernel-owned boot identity. Failure is deliberately propagated so recovery stays unknown. */
internal object DesktopMacBootSession {
    private interface Api : Library {
        fun sysctlbyname(name: String, oldValue: Pointer?, oldLength: NativeLongByReference,
            newValue: Pointer?, newLength: NativeLong): Int
    }
    private val api: Api by lazy {
        require(System.getProperty("os.name").startsWith("Mac", true) && Native.POINTER_SIZE == 8)
        Native.load("System", Api::class.java)
    }

    fun current(): String {
        val length = NativeLongByReference(NativeLong(MAX_BYTES.toLong()))
        return Memory(MAX_BYTES.toLong()).use { bytes ->
            check(api.sysctlbyname("kern.bootsessionuuid", bytes, length, null, NativeLong(0)) == 0) {
                ControlCode.UNAVAILABLE.name
            }
            val count = length.value.toLong()
            require(count in 37 until MAX_BYTES.toLong() && bytes.getByte(count - 1) == 0.toByte()) {
                ControlCode.UNAVAILABLE.name
            }
            canonical(bytes.getString(0, "US-ASCII"))
        }
    }

    internal fun canonical(value: String): String {
        require(UUID_FORMAT.matches(value)) { ControlCode.UNAVAILABLE.name }
        return UUID.fromString(value).toString()
    }

    private const val MAX_BYTES = 64
    private val UUID_FORMAT = Regex("[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")
}

/** Private launch token written before any coordinator attempt. */
internal object DesktopMacBootSessionRecord {
    const val FILE_NAME = "boot-session"
    private const val HEADER = "VPN_CONTROL_MAC_BOOT_SESSION_V1"
    private const val MAX_BYTES = 256

    fun publish(input: Path, jobId: String, bootSession: String) {
        require(DesktopInstallJobNames.validJob(jobId))
        val canonical = DesktopMacBootSession.canonical(bootSession)
        macInstallPublishRecord(input.resolve(FILE_NAME), "$HEADER\n$jobId\n$canonical\n".encodeToByteArray())
    }

    /** Missing legacy tokens remain unknown. Malformed or insecure tokens fail closed. */
    fun belongsToPreviousBoot(input: Path, jobId: String, currentBootSession: () -> String): Boolean =
        belongsToPreviousBoot(jobId, readPrivateToken(input, jobId), currentBootSession)

    internal fun belongsToPreviousBoot(jobId: String, bytes: ByteArray?, currentBootSession: () -> String): Boolean {
        require(DesktopInstallJobNames.validJob(jobId))
        if (bytes == null) return false
        require(bytes.size in 1..MAX_BYTES)
        val fields = bytes.decodeToString(throwOnInvalidSequence = true).split('\n')
        require(fields.size == 4 && fields[0] == HEADER && fields[1] == jobId && fields[3].isEmpty())
        val launch = DesktopMacBootSession.canonical(fields[2])
        return launch != DesktopMacBootSession.canonical(currentBootSession())
    }

    /** The proof is read from the same no-follow descriptor whose ownership and ACL were checked. */
    internal fun readPrivateToken(input: Path, jobId: String,
        native: MacInstallAdmissionNative = JnaMacInstallAdmission(),
        read: (Int) -> ByteArray = ::readBounded,
    ): ByteArray? {
        require(input.isAbsolute && input == input.normalize() && input.fileName.toString() == jobId &&
            DesktopInstallJobNames.validJob(jobId))
        val uid = native.currentUid()
        val handles = mutableListOf<Int>()
        fun pin(fd: Int, directory: Boolean, ancestry: Boolean): Pair<Int, MacAdmissionInfo> {
            handles += fd
            val info = native.inspect(fd)
            require(info.mode and 0xf000 == if (directory) 0x4000 else 0x8000)
            require(info.uid == uid || ancestry && info.uid == 0L)
            require(info.acl == MacAdmissionAcl.EMPTY || ancestry && info.acl == MacAdmissionAcl.DENY_ONLY)
            if (ancestry) {
                require(info.mode and 0x12 == 0 || info.uid == 0L && info.mode and 0x200 != 0)
            } else {
                require(info.mode and 0xfff == if (directory) 0x1c0 else 0x180)
            }
            require(directory || info.links == 1L && info.size in 1..MAX_BYTES.toLong())
            return fd to info
        }
        try {
            var directory = pin(native.openRoot(), directory = true, ancestry = true).first
            for ((index, part) in input.withIndex()) {
                val child = native.openChild(directory, part.toString(), directory = true, optional = true) ?: return null
                directory = pin(child, directory = true, ancestry = index < input.nameCount - 1).first
            }
            require(native.canonicalPath(directory) == input)
            val file = native.openChild(directory, FILE_NAME, directory = false, optional = true) ?: return null
            val (_, before) = pin(file, directory = false, ancestry = false)
            require(native.canonicalPath(file) == input.resolve(FILE_NAME))
            val bytes = read(file)
            require(bytes.size.toLong() == before.size && native.inspect(file) == before)
            return bytes
        } finally {
            handles.asReversed().forEach { native.close(it) }
        }
    }

    private interface ReaderApi : Library {
        fun pread(fd: Int, bytes: ByteArray, size: Long, offset: Long): Long
    }
    private val reader: ReaderApi by lazy { Native.load("System", ReaderApi::class.java) }
    private fun readBounded(fd: Int): ByteArray {
        val bytes = ByteArray(MAX_BYTES + 1)
        var total = 0
        while (total < bytes.size) {
            val chunk = ByteArray(bytes.size - total)
            val count = reader.pread(fd, chunk, chunk.size.toLong(), total.toLong())
            check(count in 0..chunk.size.toLong()) { ControlCode.UNAVAILABLE.name }
            if (count == 0L) break
            chunk.copyInto(bytes, total, 0, count.toInt())
            total += count.toInt()
        }
        require(total in 1..MAX_BYTES)
        return bytes.copyOf(total)
    }
}

/**
 * A different kernel boot proves every process from the recorded launch is gone. Since the native
 * worker publishes protected PREPARING before staging or replacement, receipt absence then proves
 * that installation never started. The protected-receipt check is repeated by markNotStarted.
 */
internal fun reconcileMacPreauthorizationProcessLoss(
    recovered: List<DesktopInstallCorrelationRecovery>,
    previousBoot: (String) -> Boolean,
    markNotStarted: (DesktopInstallCorrelation, String) -> Unit,
) {
    val abandoned = recovered.filter { record ->
        val binding = record.binding
        binding != null && record.receipt == null && !record.notStarted &&
            record.code == ControlCode.OUTCOME_UNKNOWN &&
            previousBoot(binding.jobId)
    }
    abandoned.forEach { record ->
        val binding = requireNotNull(record.binding)
        markNotStarted(binding.correlation, binding.jobId)
    }
}
