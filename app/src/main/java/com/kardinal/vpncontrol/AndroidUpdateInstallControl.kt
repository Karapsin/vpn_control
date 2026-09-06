package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

internal enum class AndroidInstallStage { WAIT, REQUEST_PERMISSION, DENIED, DISPATCH }
internal fun androidInstallStage(visibleUnlocked: Boolean, permission: Boolean, permissionReturned: Boolean): AndroidInstallStage =
    if (!visibleUnlocked) AndroidInstallStage.WAIT else if (permission) AndroidInstallStage.DISPATCH
    else if (permissionReturned) AndroidInstallStage.DENIED else AndroidInstallStage.REQUEST_PERMISSION

/** Retains a verified private artifact while the OS interaction is pending. Never claims installation. */
internal class AndroidUpdateInstallControl(
    private val engine: AndroidUpdateControl,
    private val interactions: AndroidControlInteractions,
    private val pin: suspend (AndroidUpdateControl.Installation) -> Pinned,
) {
    internal interface Pinned {
        val version: String
        suspend fun verify()
        fun dispatch(launcher: (android.content.Intent) -> Unit)
        fun release(handedOff: Boolean)
    }
    private class Pending(val pin: Pinned, val leaveAwaiting: () -> Boolean) {
        @Volatile var handedOff = false
    }
    private val pins = mutableMapOf<String, Pending>()

    suspend fun execute(operationId: String, awaiting: (Boolean) -> Boolean): AndroidUpdateOutcome {
        val ticket = engine.reserveInstallation() ?: return AndroidUpdateOutcome(
            if (engine.busy()) ControlCode.BUSY else ControlCode.NOT_FOUND, emptyMap())
        var pinned: Pinned? = null
        var token: String? = null
        var pending: Pending? = null
        var handedOff = false
        fun closeInteraction() = synchronized(interactions) {
            token?.let(interactions::finish)
            pending?.handedOff == true
        }
        fun outcome(code: ControlCode) = AndroidUpdateOutcome(code, mapOf(
            "installerStarted" to ControlValue.BooleanValue(handedOff),
            "installed" to ControlValue.Null,
            "availableVersion" to (pinned?.version?.let(ControlValue::Text) ?: ControlValue.Null)))
        return try {
            pinned = pin(ticket)
            token = interactions.create(operationId, ControlOperationId.UPDATES_INSTALL)
            pending = Pending(pinned) { awaiting(false) }
            synchronized(pins) { pins[requireNotNull(token)] = requireNotNull(pending) }
            if (!awaiting(true)) interactions.cancel(operationId)
            val code = interactions.await(token)
            awaiting(false)
            handedOff = synchronized(interactions) { pending?.handedOff == true }
            outcome(if (handedOff) ControlCode.OK else code)
        } catch (_: Exception) {
            // Serialize retirement with synchronous dispatch before interpreting cancellation.
            // A cancelled owner waiter cannot erase an acknowledged OS handoff.
            handedOff = closeInteraction()
            outcome(if (handedOff) ControlCode.OK else ControlCode.RUNTIME_FAILED)
        } finally {
            withContext(NonCancellable) {
                handedOff = closeInteraction() || handedOff
                token?.let { synchronized(pins) { pins.remove(it) } }
                try { pinned?.release(handedOff) } finally { engine.finishInstallation(ticket, handedOff) }
            }
        }
    }

    suspend fun dispatch(token: String, session: String, launcher: (android.content.Intent) -> Unit): Boolean {
        val pending = synchronized(pins) { pins[token] } ?: return false
        val pinned = pending.pin
        return try {
            pinned.verify()
            // Leave the cancellable ledger phase before the registry/OS boundary. Never
            // acquire the ledger while holding the registry lock (cancel takes the reverse).
            if (!pending.leaveAwaiting()) return false
            interactions.dispatchInstall(token, session) {
                pinned.dispatch(launcher)
                pending.handedOff = true
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            interactions.dispatchInstall(token, session) { error("INSTALL_ARTIFACT_INVALID") }
            false
        }
    }

    fun cancel(operationId: String) = interactions.cancel(operationId)
}
