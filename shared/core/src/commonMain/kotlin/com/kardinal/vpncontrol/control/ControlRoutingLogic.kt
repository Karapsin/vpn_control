package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/** Only current public routing controls; never interpret dormant rule-set/app writes here. */
object ControlRoutingLogic {
    fun set(state: MainUiState, key: String, value: String): Result<MainUiState> = runCatching {
        val base = MainDraftLogic.applyImportedRoutingRules(state, state.routingRules)
        val draft = when (key) {
            "ignore-rules" -> base.copy(routingIgnoreRulesDraft = value.toBooleanStrict())
            "block-quic-udp443" -> base.copy(routingBlockQuicUdp443Draft = value.toBooleanStrict())
            "direct-domains" -> base.copy(routingDirectDomainsDraft = domainText(value))
            else -> throw IllegalArgumentException("INVALID_ARGUMENT")
        }
        draft.copy(routingRules = MainDraftLogic.buildEditedRoutingRules(draft))
    }

    /** Terminal JSON arrays and existing GUI/plain-text input share the same domain normalization. */
    private fun domainText(value: String): String {
        if (value.trimStart().firstOrNull() !in setOf('[', '{', '"')) return value
        val array = Json.parseToJsonElement(value) as? JsonArray ?: throw IllegalArgumentException("INVALID_ARGUMENT")
        return array.joinToString("\n") {
            val item = it as? JsonPrimitive ?: throw IllegalArgumentException("INVALID_ARGUMENT")
            require(item.isString) { "INVALID_ARGUMENT" }
            item.content
        }
    }
}
