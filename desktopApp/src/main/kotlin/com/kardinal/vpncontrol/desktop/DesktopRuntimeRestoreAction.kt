package com.kardinal.vpncontrol.desktop

import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.currentCoroutineContext

/** A rollback callback keeps its immutable runtime inputs until the enclosing decision is final. */
internal class DesktopRuntimeRestoreAction(
    private val retained: AutoCloseable?,
    private val action: suspend () -> Result<Unit>,
) : suspend () -> Result<Unit>, AutoCloseable {
    private val closed = AtomicBoolean()
    private val releaseLock = Any()
    private var released = false

    override suspend fun invoke(): Result<Unit> {
        check(!closed.get()) { "ROLLBACK_FAILED" }
        return action()
    }

    override fun close() {
        closed.set(true)
        synchronized(releaseLock) {
            if (!released) {
                retained?.close()
                released = true
            }
        }
    }
}

internal suspend fun retainDesktopRuntimeInputs(inputs: AutoCloseable?) {
    if (inputs != null) currentCoroutineContext()[DesktopOperationProgress]?.retainInputs(inputs)
}

internal suspend fun releaseDesktopRuntimeInputs(inputs: AutoCloseable?) {
    if (inputs == null) return
    val owner = currentCoroutineContext()[DesktopOperationProgress]
    if (owner == null) inputs.close() else owner.releaseInputs(inputs)
}

internal suspend fun releaseDesktopRuntimeRestore(action: (suspend () -> Result<Unit>)?) {
    releaseDesktopRuntimeInputs(action as? AutoCloseable)
}
