package com.kardinal.vpncontrol.desktop

import java.util.concurrent.TimeUnit

/** Runtime ownership does not imply that the controller has the child's Windows token. */
internal interface DesktopRuntimeProcess : AutoCloseable {
    val isAlive: Boolean
    /** Safe metadata for retained owned bytes, independent of this child's known runtime state. */
    val resourceWarnings: List<DesktopRuntimeResourceWarning> get() = emptyList()
    fun pid(): Long
    fun destroy()
    fun destroyForcibly()
    fun waitFor(timeout: Long, unit: TimeUnit): Boolean
    override fun close() = Unit
}

/** Authorization and native preparation complete without replacing the active runtime. */
internal interface DesktopPreparedRuntimeProcess : AutoCloseable {
    /** One-shot transition. Failure must establish stopped or explicitly report an unknown outcome. */
    fun commit(): DesktopRuntimeProcess

    /** Disposes an uncommitted candidate; after commit the returned process owns its lifetime. */
    override fun close()
}

internal class DesktopLocalRuntimeProcess(private val process: Process) : DesktopRuntimeProcess {
    override val isAlive get() = process.isAlive
    override fun pid() = process.pid()
    override fun destroy() { process.destroy() }
    override fun destroyForcibly() { process.destroyForcibly() }
    override fun waitFor(timeout: Long, unit: TimeUnit) = process.waitFor(timeout, unit)
}
