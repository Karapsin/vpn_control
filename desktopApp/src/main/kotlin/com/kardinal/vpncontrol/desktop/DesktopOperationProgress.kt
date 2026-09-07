package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.currentCoroutineContext

/** Owner-local progress, never a transport object or a persistent retry instruction. */
internal class DesktopOperationProgress(private val publish: (ControlCode?) -> Unit) :
    AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<DesktopOperationProgress>

    fun pending(code: ControlCode) {
        require(code in setOf(ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE,
            ControlCode.TIMEOUT, ControlCode.INCOMPATIBLE_PROTOCOL))
        publish(code)
    }

    fun confirmed() = publish(null)
}

/** Continue reconciliation in the same action after reporting its unresolved native outcome. */
internal suspend fun desktopControlReportPendingOutcome(code: ControlCode = ControlCode.OUTCOME_UNKNOWN) {
    currentCoroutineContext()[DesktopOperationProgress]?.pending(code)
}

/** Call only after native evidence establishes the outcome, including cancellation cleanup. */
internal suspend fun desktopControlConfirmOutcome() {
    currentCoroutineContext()[DesktopOperationProgress]?.confirmed()
}
