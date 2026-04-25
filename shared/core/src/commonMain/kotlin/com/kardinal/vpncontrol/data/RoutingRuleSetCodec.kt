package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonArrayBuilder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object RoutingRuleSetCodec {
    fun encode(ruleSets: List<RoutingRuleSet>): String {
        if (ruleSets.isEmpty()) return ""
        val array = buildJsonArray {
            ruleSets.forEach { ruleSet ->
                add(ruleSet.toJson())
            }
        }
        return CompactJson.encodeToString(JsonArray.serializer(), array)
    }

    fun decode(raw: String?): List<RoutingRuleSet> {
        if (raw.isNullOrBlank()) return emptyList()
        val array = runCatching {
            CompactJson.parseToJsonElement(raw).jsonArray
        }.getOrElse { return emptyList() }

        return array.mapNotNull { item ->
            item as? JsonObject
        }.mapNotNull { item ->
            item.toRoutingRuleSetOrNull()
        }
    }

    internal fun encodeToJsonArray(ruleSets: List<RoutingRuleSet>): JsonArray {
        return buildJsonArray {
            ruleSets.forEach { add(it.toJson()) }
        }
    }

    private fun RoutingRuleSet.toJson(): JsonObject {
        val normalized = normalized()
        return buildJsonObject {
            put("id", JsonPrimitive(normalized.id))
            put("name", JsonPrimitive(normalized.name))
            put("source_type", JsonPrimitive(normalized.sourceType.name))
            put("format", JsonPrimitive(normalized.format.name))
            put("action", JsonPrimitive(normalized.action.name))
            put("source", JsonPrimitive(normalized.source))
            put("update_interval_hours", JsonPrimitive(normalized.updateIntervalHours))
        }
    }

    private fun JsonObject.toRoutingRuleSetOrNull(): RoutingRuleSet? {
        val id = string("id")
        val name = string("name")
        val source = string("source")
        if (id.isBlank() || name.isBlank() || source.isBlank()) return null

        val sourceType = enumValueOrDefault(
            key = "source_type",
            default = RoutingRuleSetSourceType.REMOTE,
        )
        val format = enumValueOrDefault(
            key = "format",
            default = RoutingRuleSetFormat.SOURCE,
        )
        val action = enumValueOrDefault(
            key = "action",
            default = RoutingRuleSetAction.DIRECT,
        )

        return RoutingRuleSet(
            id = id,
            name = name,
            sourceType = sourceType,
            format = format,
            action = action,
            source = source,
            updateIntervalHours = this["update_interval_hours"]?.jsonPrimitive?.intOrNull?.coerceAtLeast(1) ?: 24,
        ).normalized()
    }

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull?.trim().orEmpty()
    }

    private inline fun <reified T : Enum<T>> JsonObject.enumValueOrDefault(
        key: String,
        default: T,
    ): T {
        val raw = this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
        return enumValues<T>().firstOrNull { it.name == raw } ?: default
    }
}
