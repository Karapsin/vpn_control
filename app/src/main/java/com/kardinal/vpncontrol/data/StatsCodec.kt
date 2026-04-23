package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import org.json.JSONArray
import org.json.JSONObject

object StatsCodec {
    fun encodeProfileTrafficTotals(entries: List<ProfileTrafficTotal>): String {
        return JSONArray().apply {
            entries.forEach { entry ->
                put(
                    JSONObject()
                        .put("profile_key", entry.profileKey)
                        .put("profile_name", entry.profileName)
                        .put("source_url", entry.sourceUrl)
                        .put("rx_bytes", entry.rxBytes)
                        .put("tx_bytes", entry.txBytes)
                        .put("last_updated_at_epoch_millis", entry.lastUpdatedAtEpochMillis),
                )
            }
        }.toString()
    }

    fun decodeProfileTrafficTotals(raw: String?): List<ProfileTrafficTotal> {
        val array = runCatching { JSONArray(raw.orEmpty()) }.getOrNull() ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    ProfileTrafficTotal(
                        profileKey = item.optString("profile_key"),
                        profileName = item.optString("profile_name"),
                        sourceUrl = item.optString("source_url"),
                        rxBytes = item.optLong("rx_bytes"),
                        txBytes = item.optLong("tx_bytes"),
                        lastUpdatedAtEpochMillis = item.optLong("last_updated_at_epoch_millis"),
                    ),
                )
            }
        }
    }

    fun encodeLatencyHistory(entries: List<LatencyHistoryEntry>): String {
        return JSONArray().apply {
            entries.forEach { entry ->
                put(
                    JSONObject()
                        .put("id", entry.id)
                        .put("profile_name", entry.profileName)
                        .put("detail", entry.detail)
                        .put("primary_status", entry.primaryStatus)
                        .put("secondary_status", entry.secondaryStatus)
                        .put("primary_total_ms", entry.primaryTotalMs)
                        .put("secondary_total_ms", entry.secondaryTotalMs)
                        .put("created_at_epoch_millis", entry.createdAtEpochMillis),
                )
            }
        }.toString()
    }

    fun decodeLatencyHistory(raw: String?): List<LatencyHistoryEntry> {
        val array = runCatching { JSONArray(raw.orEmpty()) }.getOrNull() ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    LatencyHistoryEntry(
                        id = item.optString("id"),
                        profileName = item.optString("profile_name"),
                        detail = item.optString("detail"),
                        primaryStatus = item.optString("primary_status"),
                        secondaryStatus = item.optString("secondary_status"),
                        primaryTotalMs = item.optDouble("primary_total_ms").takeUnless { item.isNull("primary_total_ms") },
                        secondaryTotalMs = item.optDouble("secondary_total_ms").takeUnless { item.isNull("secondary_total_ms") },
                        createdAtEpochMillis = item.optLong("created_at_epoch_millis"),
                    ),
                )
            }
        }
    }

    fun encodeConnectionLog(entries: List<ConnectionLogEntry>): String {
        return JSONArray().apply {
            entries.forEach { entry ->
                put(
                    JSONObject()
                        .put("id", entry.id)
                        .put("message", entry.message)
                        .put("created_at_epoch_millis", entry.createdAtEpochMillis),
                )
            }
        }.toString()
    }

    fun decodeConnectionLog(raw: String?): List<ConnectionLogEntry> {
        val array = runCatching { JSONArray(raw.orEmpty()) }.getOrNull() ?: return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    ConnectionLogEntry(
                        id = item.optString("id"),
                        message = item.optString("message"),
                        createdAtEpochMillis = item.optLong("created_at_epoch_millis"),
                    ),
                )
            }
        }
    }
}
