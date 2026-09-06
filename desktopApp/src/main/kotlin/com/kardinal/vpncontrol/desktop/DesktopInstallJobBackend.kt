package com.kardinal.vpncontrol.desktop

import java.nio.file.Path

/**
 * Protected installer IPC, not an authorization or installation admission fence.
 * Implementations pin inspected directories/ancestors and reject links, reparse points, untrusted
 * owners and permissions allowing replacement/mutation. Ordinary creation of unrelated children
 * in a system ancestor is permissible; product/job directories themselves must be immutable to users.
 * No implementation may fall back to unchecked path IO when native guarantees are unavailable.
 */
internal interface DesktopInstallJobBackend {
    fun openRoot(root: Path, create: Boolean): Directory

    enum class Purpose { STATUS_TEMP, CANCEL }

    interface Directory : AutoCloseable {
        fun createJob(jobId: String): Directory
        fun openJob(jobId: String): Directory
        fun createFile(name: String, purpose: Purpose, clientPrincipal: String? = null): File
        /** write=true is permitted only for the existing fixed cancel file (single byte 1). */
        fun openFile(name: String, write: Boolean = false): File
        /** Atomically replace status.json from a newly created status-UUID.tmp, never follow links. */
        fun replaceFile(tempName: String, targetName: String)
        fun deleteFile(name: String)
    }

    interface File : AutoCloseable {
        /** Read from offset zero, rejecting content exceeding the bound, including concurrent growth. */
        fun readBounded(maxBytes: Int): ByteArray
        /** Write from offset zero, truncate to exact length and durably flush before returning. */
        fun writeExact(bytes: ByteArray)
    }
}

internal object DesktopInstallJobNames {
    const val STATUS = "status.json"
    const val CANCEL = "cancel"
    fun validJob(value: String): Boolean = runCatching {
        java.util.UUID.fromString(value).toString() == value
    }.getOrDefault(false)
    fun validTemp(value: String) = value.startsWith("status-") && value.endsWith(".tmp") &&
        validJob(value.removePrefix("status-").removeSuffix(".tmp"))
    fun requireReadable(value: String) { require(value == STATUS || value == CANCEL) }
    fun requireCreate(value: String, purpose: DesktopInstallJobBackend.Purpose) {
        require(if (purpose == DesktopInstallJobBackend.Purpose.CANCEL) value == CANCEL else validTemp(value))
    }
}
