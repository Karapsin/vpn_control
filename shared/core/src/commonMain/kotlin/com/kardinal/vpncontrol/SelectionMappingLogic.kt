package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.LocationConfigs

data class SelectionCandidate(
    val rawLink: String,
    val sourceUrl: String,
    val name: String,
    val server: String,
)

object SelectionMappingLogic {
    fun normalizedStoredKey(rawLink: String): String {
        return LocationConfigs.normalizeStoredReference(rawLink)
    }

    fun selectedStoredKey(selectedProfileJson: String, selectedProfileRawLink: String): String {
        return LocationConfigs.selectedStoredReference(
            selectedProfileJson = selectedProfileJson,
            selectedProfileRawLink = selectedProfileRawLink,
        )
    }

    fun matchesSelectedLocation(
        candidate: SelectionCandidate,
        selectedRawLink: String,
        selectedSourceUrl: String,
        selectedName: String,
        selectedServer: String,
    ): Boolean {
        val selectedRaw = selectedRawLink.takeIf(String::isNotBlank) ?: return false
        if (candidate.rawLink == selectedRaw) return true
        if (normalizedStoredKey(candidate.rawLink) == LocationConfigs.normalizeStoredReference(selectedRaw)) {
            return true
        }
        return candidate.sourceUrl.isNotBlank() &&
            candidate.sourceUrl == selectedSourceUrl &&
            candidate.name == selectedName &&
            candidate.server == selectedServer
    }
}
