package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Path
import java.util.UUID

internal enum class DesktopInstallJobPhase {
    PREPARING, AUTHORIZED, WAITING_FOR_EXIT, INSTALLING, SUCCEEDED, FAILED, CANCELLED;
    val terminal get() = this in setOf(SUCCEEDED, FAILED, CANCELLED)
}

/** Private helper receipt: deliberately excludes arbitrary strings, paths, payloads and secrets. */
internal data class DesktopInstallJobReceipt(
    val jobId: String, val sequence: Long, val phase: DesktopInstallJobPhase, val code: ControlCode,
) {
    init {
        require(DesktopInstallJobNames.validJob(jobId) && sequence >= 0)
        require(when (phase) {
            DesktopInstallJobPhase.CANCELLED -> code == ControlCode.CANCELLED
            DesktopInstallJobPhase.FAILED -> code !in setOf(ControlCode.OK, ControlCode.ACCEPTED, ControlCode.CANCELLED)
            else -> code == ControlCode.OK
        })
    }

    fun encode(): ByteArray = "{\"version\":1,\"jobId\":\"$jobId\",\"sequence\":$sequence,\"phase\":\"${phase.name}\",\"code\":\"${code.name}\"}".encodeToByteArray()

    companion object {
        const val MAX_BYTES = 4096
        private val format = Regex("""\{"version":1,"jobId":"([a-f0-9-]{36})","sequence":(0|[1-9][0-9]{0,18}),"phase":"([A-Z_]+)","code":"([A-Z_]+)"\}""")
        fun decode(bytes: ByteArray): DesktopInstallJobReceipt {
            require(bytes.size <= MAX_BYTES)
            val match = requireNotNull(format.matchEntire(bytes.decodeToString(throwOnInvalidSequence = true)))
            return DesktopInstallJobReceipt(match.groupValues[1], match.groupValues[2].toLong(),
                DesktopInstallJobPhase.valueOf(match.groupValues[3]), ControlCode.valueOf(match.groupValues[4]))
        }
    }
}

/** A polling reader can skip phases, but cannot go backwards or change an already observed terminal. */
internal class DesktopInstallJobReceiptTracker(private val jobId: String) {
    private var previous: DesktopInstallJobReceipt? = null
    @Synchronized fun accept(receipt: DesktopInstallJobReceipt): DesktopInstallJobReceipt {
        require(receipt.jobId == jobId)
        previous?.let { old ->
            if (receipt == old) return receipt
            require(!old.phase.terminal && receipt.sequence > old.sequence)
            require(receipt.phase.terminal || receipt.phase.ordinal > old.phase.ordinal)
        }
        previous = receipt
        return receipt
    }
}

/**
 * Not yet wired to installation. The privileged creator keeps the cancellation handle open throughout
 * the job; cancellation can never redirect a privileged write or trick the worker into reopening a path.
 */
internal class DesktopInstallJobStore(private val backend: DesktopInstallJobBackend, private val root: Path) {
    companion object {
        /** Selects trusted machine roots; does not create directories or request privilege. */
        fun production(): DesktopInstallJobStore = when {
            System.getProperty("os.name").startsWith("Windows", true) ->
                DesktopWindowsInstallJobBackend().let { DesktopInstallJobStore(it, it.defaultRoot()) }
            System.getProperty("os.name").startsWith("Mac", true) ->
                DesktopInstallJobStore(DesktopMacInstallJobBackend(), Path.of("/Library/Application Support/vpn-control-install-jobs"))
            System.getProperty("os.name").startsWith("Linux", true) ->
                DesktopInstallJobStore(DesktopPosixInstallJobBackend(), Path.of("/var/lib/vpn-control-install-jobs"))
            else -> throw UnsupportedOperationException("Protected installer storage unavailable")
        }
    }
    fun create(jobId: String, clientPrincipal: String): Writer {
        require(DesktopInstallJobNames.validJob(jobId) && clientPrincipal.isNotBlank())
        val rootHandle = backend.openRoot(root, create = true)
        var job: DesktopInstallJobBackend.Directory? = null
        var cancel: DesktopInstallJobBackend.File? = null
        try {
            job = rootHandle.createJob(jobId)
            cancel = job.createFile(DesktopInstallJobNames.CANCEL, DesktopInstallJobBackend.Purpose.CANCEL, clientPrincipal)
            cancel.writeExact(byteArrayOf(0))
            return Writer(rootHandle, job, cancel, jobId).also { it.publish(DesktopInstallJobPhase.PREPARING) }
        } catch (failure: Exception) {
            runCatching { cancel?.close() }; runCatching { job?.close() }; runCatching { rootHandle.close() }
            throw failure
        }
    }

    fun open(jobId: String): Reader {
        require(DesktopInstallJobNames.validJob(jobId))
        val rootHandle = backend.openRoot(root, create = false)
        try { return Reader(rootHandle, rootHandle.openJob(jobId), jobId) }
        catch (failure: Exception) { rootHandle.close(); throw failure }
    }

    class Writer internal constructor(private val root: DesktopInstallJobBackend.Directory,
        private val job: DesktopInstallJobBackend.Directory, private val cancel: DesktopInstallJobBackend.File,
        private val jobId: String,
    ) : AutoCloseable {
        private var current: DesktopInstallJobReceipt? = null
        private var closed = false
        private var cancellationObserved = false

        @Synchronized fun publish(phase: DesktopInstallJobPhase, code: ControlCode = ControlCode.OK): DesktopInstallJobReceipt {
            check(!closed)
            val old = current
            require(if (old == null) phase == DesktopInstallJobPhase.PREPARING else !old.phase.terminal &&
                (phase == DesktopInstallJobPhase.FAILED || phase == DesktopInstallJobPhase.CANCELLED ||
                    phase.ordinal == old.phase.ordinal + 1))
            val receipt = DesktopInstallJobReceipt(jobId, if (old == null) 0 else Math.addExact(old.sequence, 1), phase, code)
            val temporary = "status-${UUID.randomUUID()}.tmp"
            var created = false
            try {
                job.createFile(temporary, DesktopInstallJobBackend.Purpose.STATUS_TEMP).use { file ->
                    created = true; file.writeExact(receipt.encode())
                }
                job.replaceFile(temporary, DesktopInstallJobNames.STATUS)
            } catch (failure: Exception) {
                if (created) runCatching { job.deleteFile(temporary) }
                throw failure
            }
            current = receipt
            return receipt
        }

        @Synchronized fun cancellationRequested(): Boolean {
            check(!closed)
            if (cancellationObserved) return true
            val bytes = cancel.readBounded(1)
            require(bytes.size == 1 && bytes[0] in 0..1)
            cancellationObserved = bytes[0] == 1.toByte()
            return cancellationObserved
        }

        @Synchronized override fun close() {
            if (closed) return
            closed = true
            try { cancel.close() } finally { try { job.close() } finally { root.close() } }
        }
    }

    class Reader internal constructor(private val root: DesktopInstallJobBackend.Directory,
        private val job: DesktopInstallJobBackend.Directory, jobId: String,
    ) : AutoCloseable {
        private val tracker = DesktopInstallJobReceiptTracker(jobId)
        private var closed = false
        @Synchronized fun read(): DesktopInstallJobReceipt {
            check(!closed)
            return job.openFile(DesktopInstallJobNames.STATUS).use {
                tracker.accept(DesktopInstallJobReceipt.decode(it.readBounded(DesktopInstallJobReceipt.MAX_BYTES)))
            }
        }
        @Synchronized fun requestCancellation() {
            check(!closed)
            job.openFile(DesktopInstallJobNames.CANCEL, write = true).use { it.writeExact(byteArrayOf(1)) }
        }
        @Synchronized override fun close() {
            if (closed) return
            closed = true
            try { job.close() } finally { root.close() }
        }
    }
}
