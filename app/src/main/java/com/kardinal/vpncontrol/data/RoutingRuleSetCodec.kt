package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import org.json.JSONArray
import org.json.JSONObject

object RoutingRuleSetCodec {
    fun encode(ruleSets: List<RoutingRuleSet>): String {
        if (ruleSets.isEmpty()) return ""
        val array = JSONArray()
        ruleSets.forEach { ruleSet ->
            val normalized = ruleSet.normalized()
            array.put(
                JSONObject()
                    .put("id", normalized.id)
                    .put("name", normalized.name)
                    .put("source_type", normalized.sourceType.name)
                    .put("format", normalized.format.name)
                    .put("action", normalized.action.name)
                    .put("source", normalized.source)
                    .put("update_interval_hours", normalized.updateIntervalHours),
            )
        }
        return array.toString()
    }

    fun decode(raw: String?): List<RoutingRuleSet> {
        if (raw.isNullOrBlank()) return emptyList()
        val array = runCatching { JSONArray(raw) }.getOrElse { return emptyList() }
        val decoded = mutableListOf<RoutingRuleSet>()
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val id = item.optString("id").trim()
            val name = item.optString("name").trim()
            val source = item.optString("source").trim()
            if (id.isBlank() || name.isBlank() || source.isBlank()) {
                continue
            }
            val sourceType = item.optString("source_type")
                .let { rawType ->
                    runCatching { RoutingRuleSetSourceType.valueOf(rawType) }.getOrDefault(RoutingRuleSetSourceType.REMOTE)
                }
            val format = item.optString("format")
                .let { rawFormat ->
                    runCatching { RoutingRuleSetFormat.valueOf(rawFormat) }.getOrDefault(RoutingRuleSetFormat.SOURCE)
                }
            val action = item.optString("action")
                .let { rawAction ->
                    runCatching { RoutingRuleSetAction.valueOf(rawAction) }.getOrDefault(RoutingRuleSetAction.DIRECT)
                }
            decoded += RoutingRuleSet(
                id = id,
                name = name,
                sourceType = sourceType,
                format = format,
                action = action,
                source = source,
                updateIntervalHours = item.optInt("update_interval_hours", 24).coerceAtLeast(1),
            ).normalized()
        }
        return decoded
    }
}
