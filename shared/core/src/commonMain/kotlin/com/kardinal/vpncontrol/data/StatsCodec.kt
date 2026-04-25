package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

object StatsCodec {
    fun encodeProfileTrafficTotals(entries: List<ProfileTrafficTotal>): String {
        return encodeArray(entries) { entry ->
            buildJsonObject {
                put("profile_key", JsonPrimitive(entry.profileKey))
                put("profile_name", JsonPrimitive(entry.profileName))
                put("source_url", JsonPrimitive(entry.sourceUrl))
                put("rx_bytes", JsonPrimitive(entry.rxBytes))
                put("tx_bytes", JsonPrimitive(entry.txBytes))
                put("last_updated_at_epoch_millis", JsonPrimitive(entry.lastUpdatedAtEpochMillis))
            }
        }
    }

    fun decodeProfileTrafficTotals(raw: String?): List<ProfileTrafficTotal> {
        return decodeObjects(raw).map { item ->
            ProfileTrafficTotal(
                profileKey = item.string("profile_key"),
                profileName = item.string("profile_name"),
                sourceUrl = item.string("source_url"),
                rxBytes = item.long("rx_bytes"),
                txBytes = item.long("tx_bytes"),
                lastUpdatedAtEpochMillis = item.long("last_updated_at_epoch_millis"),
            )
        }
    }

    fun encodeLatencyHistory(entries: List<LatencyHistoryEntry>): String {
        return encodeArray(entries) { entry ->
            buildJsonObject {
                put("id", JsonPrimitive(entry.id))
                put("profile_name", JsonPrimitive(entry.profileName))
                put("detail", JsonPrimitive(entry.detail))
                put("primary_status", JsonPrimitive(entry.primaryStatus))
                put("secondary_status", JsonPrimitive(entry.secondaryStatus))
                entry.primaryTotalMs?.let { put("primary_total_ms", JsonPrimitive(it)) }
                entry.secondaryTotalMs?.let { put("secondary_total_ms", JsonPrimitive(it)) }
                put("created_at_epoch_millis", JsonPrimitive(entry.createdAtEpochMillis))
            }
        }
    }

    fun decodeLatencyHistory(raw: String?): List<LatencyHistoryEntry> {
        return decodeObjects(raw).map { item ->
            LatencyHistoryEntry(
                id = item.string("id"),
                profileName = item.string("profile_name"),
                detail = item.string("detail"),
                primaryStatus = item.string("primary_status"),
                secondaryStatus = item.string("secondary_status"),
                primaryTotalMs = item["primary_total_ms"]?.jsonPrimitive?.doubleOrNull,
                secondaryTotalMs = item["secondary_total_ms"]?.jsonPrimitive?.doubleOrNull,
                createdAtEpochMillis = item.long("created_at_epoch_millis"),
            )
        }
    }

    fun encodeConnectionLog(entries: List<ConnectionLogEntry>): String {
        return encodeArray(entries) { entry ->
            buildJsonObject {
                put("id", JsonPrimitive(entry.id))
                put("message", JsonPrimitive(entry.message))
                put("created_at_epoch_millis", JsonPrimitive(entry.createdAtEpochMillis))
            }
        }
    }

    fun decodeConnectionLog(raw: String?): List<ConnectionLogEntry> {
        return decodeObjects(raw).map { item ->
            ConnectionLogEntry(
                id = item.string("id"),
                message = item.string("message"),
                createdAtEpochMillis = item.long("created_at_epoch_millis"),
            )
        }
    }

    private fun <T> encodeArray(
        entries: List<T>,
        transform: (T) -> JsonObject,
    ): String {
        return CompactJson.encodeToString(
            JsonArray.serializer(),
            JsonArray(entries.map(transform)),
        )
    }

    private fun decodeObjects(raw: String?): List<JsonObject> {
        val array = runCatching {
            CompactJson.parseToJsonElement(raw.orEmpty()).jsonArray
        }.getOrElse { return emptyList() }
        return array.mapNotNull { it as? JsonObject }
    }

    private fun JsonObject.string(key: String): String {
        return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
    }

    private fun JsonObject.long(key: String): Long {
        return this[key]?.jsonPrimitive?.longOrNull ?: 0L
    }
}
