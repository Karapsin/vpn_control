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
    private val recover: () -> Pinned? = { null },
    private val pin: suspend (AndroidUpdateControl.Installation) -> Pinned,
) {
    internal data class PinnedState(
        val session: AppInstallSessionStatus? = null,
        val data: Map<String, ControlValue> = emptyMap(),
    )
    internal interface Pinned {
        val version: String
        suspend fun verify()
        suspend fun prepareDispatch() {}
        fun handedOff(): Boolean = false
        fun snapshot(): PinnedState = PinnedState()
        fun dispatch(launcher: (android.content.Intent) -> Unit)
        fun release(handedOff: Boolean)
    }
    private class Pending(val pin: Pinned, val leaveAwaiting: () -> Boolean) {
        @Volatile var handedOff = false
    }
    private val pins = mutableMapOf<String, Pending>()

    suspend fun execute(operationId: String, awaiting: (Boolean) -> Boolean): AndroidUpdateOutcome {
        if (engine.busy()) return AndroidUpdateOutcome(ControlCode.BUSY, emptyMap())
        val recovered = try { recover() } catch (_: Exception) {
            return AndroidUpdateOutcome(ControlCode.OUTCOME_UNKNOWN,
                mapOf("installationOutcomeUnknown" to ControlValue.BooleanValue(true)))
        }
        val ticket = if (recovered == null) engine.reserveInstallation() else null
        if (recovered == null && ticket == null) return AndroidUpdateOutcome(ControlCode.NOT_FOUND, emptyMap())
        val recoveredTicket = if (recovered != null) engine.reserveRecoveredInstallation() else null
        if (recovered != null && recoveredTicket == null) return AndroidUpdateOutcome(ControlCode.BUSY, emptyMap())
        var pinned: Pinned? = recovered
        var token: String? = null
        var pending: Pending? = null
        var handedOff = false
        fun closeInteraction() = synchronized(interactions) {
            token?.let(interactions::finish)
            pending?.handedOff == true || pinned?.handedOff() == true
        }
        fun outcome(code: ControlCode): AndroidUpdateOutcome {
            val receipt = pinned?.snapshot() ?: PinnedState()
            val reconciled = when (receipt.session?.phase) {
                AppInstallSessionPhase.INSTALLED -> ControlCode.OK
                AppInstallSessionPhase.FAILED -> ControlCode.RUNTIME_FAILED
                AppInstallSessionPhase.CANCELLED -> ControlCode.CANCELLED
                AppInstallSessionPhase.COMMITTING, AppInstallSessionPhase.UNKNOWN -> ControlCode.OUTCOME_UNKNOWN
                else -> code
            }
            return AndroidUpdateOutcome(reconciled, mapOf(
                "installerStarted" to ControlValue.BooleanValue(handedOff),
                "installed" to ControlValue.Null,
                "availableVersion" to (pinned?.version?.let(ControlValue::Text) ?: ControlValue.Null)) + receipt.data)
        }
        return try {
            if (pinned == null) pinned = pin(requireNotNull(ticket))
            token = interactions.create(operationId, ControlOperationId.UPDATES_INSTALL)
            pending = Pending(requireNotNull(pinned)) { awaiting(false) }
            synchronized(pins) { pins[requireNotNull(token)] = requireNotNull(pending) }
            if (!awaiting(true)) interactions.cancel(operationId)
            val code = interactions.await(token)
            awaiting(false)
            handedOff = synchronized(interactions) { pending?.handedOff == true || pinned?.handedOff() == true }
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
                try { pinned?.release(handedOff) } finally {
                    if (ticket != null) engine.finishInstallation(ticket, handedOff)
                    if (recoveredTicket != null) engine.finishRecoveredInstallation(recoveredTicket, handedOff)
                }
            }
        }
    }

    suspend fun dispatch(token: String, session: String, launcher: (android.content.Intent) -> Unit): Boolean {
        val pending = synchronized(pins) { pins[token] } ?: return false
        if (interactions.action(token, session) != ControlOperationId.UPDATES_INSTALL) return false
        val pinned = pending.pin
        return try {
            pinned.verify()
            if (interactions.action(token, session) != ControlOperationId.UPDATES_INSTALL) return false
            // Leave the cancellable ledger phase before the registry/OS boundary. Never
            // acquire the ledger while holding the registry lock (cancel takes the reverse).
            if (!pending.leaveAwaiting()) return false
            pinned.prepareDispatch()
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
