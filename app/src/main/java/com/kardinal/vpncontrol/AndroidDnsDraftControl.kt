package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Opening guards and completion tokens are frontend-local; the owner retains admitted commands. */
internal class AndroidDnsDraftControl(
    private val snapshot: suspend () -> ControlCommitted<PersistedState>,
    private val execute: suspend (ControlRequest) -> ControlResult,
) {
    private data class Guard(val owner: String, val revision: Long)
    internal class Token internal constructor(internal val opening: Any, internal val draft: Any)
    internal class SaveAttempt internal constructor(internal val token: Token, internal val request: ControlRequest?)
    private var generation = Any()
    private var draftRevision = Any()
    private var opening: Guard? = null
    private var saveRequest: ControlRequest? = null
    private var unresolvedRequest: ControlRequest? = null
    var isOpenOrOpening = false
        private set

    fun capture(): Token = Token(generation, draftRevision)
    fun isCurrent(token: Token): Boolean = token.opening === generation && token.draft === draftRevision
    fun isCurrent(attempt: SaveAttempt): Boolean = isCurrent(attempt.token) && attempt.request == saveRequest

    fun beginOpen(): Token {
        close()
        isOpenOrOpening = true
        return capture()
    }

    suspend fun open(token: Token): DnsSettings? {
        val captured = snapshot()
        if (!isCurrent(token) || !isOpenOrOpening) return null
        opening = Guard(captured.controllerId, captured.revision)
        return captured.value.dnsSettings
    }

    fun changed() { draftRevision = Any() }

    fun close() {
        generation = Any()
        draftRevision = Any()
        isOpenOrOpening = false
        opening = null
        saveRequest = null
        unresolvedRequest = null
    }

    fun prepareSave(settings: DnsSettings): SaveAttempt {
        val token = capture()
        val guard = opening ?: return SaveAttempt(token, null)
        val patch = mapOf("dns.mode" to ControlValue.Text(when (settings.mode) {
            DnsMode.AUTOMATIC -> "automatic"
            DnsMode.CUSTOM_DOH -> "custom-doh"
            DnsMode.CUSTOM_DOT -> "custom-dot"
        }), "dns.endpoint" to ControlValue.Text(settings.endpoint))
        val arguments = mapOf("input" to ControlValue.Text(ControlDocumentCodec.encodeValues(patch)))
        check(unresolvedRequest == null || unresolvedRequest?.command?.arguments == arguments) { "OUTCOME_UNKNOWN" }
        val request = saveRequest?.takeIf { it.command.arguments == arguments }
            ?: ControlRequest(UUID.randomUUID().toString(), ControlCommand(ControlOperationId.SETTINGS_APPLY, arguments),
                controllerId = guard.owner, ifRevision = guard.revision).also { saveRequest = it }
        return SaveAttempt(token, request)
    }

    suspend fun save(attempt: SaveAttempt): ControlResult {
        val request = attempt.request ?: return ControlResult(null, UUID.randomUUID().toString(),
            ControlCode.CONFLICT, 0, warnings = listOf("CONFIGURATION_REVISION_UNAVAILABLE"))
        // Closing the frontend never cancels or replays the owner's accepted request.
        unresolvedRequest = request
        // A thrown response leaves this exact request unresolved. Explicit unchanged retry
        // recovers the owner's retained result; changed input never creates a new identity.
        val result = execute(request)
        if (unresolvedRequest == request && result.code != ControlCode.OUTCOME_UNKNOWN) unresolvedRequest = null
        return result
    }

    fun complete(attempt: SaveAttempt): Boolean {
        if (!isCurrent(attempt)) return false
        close()
        return true
    }
}
