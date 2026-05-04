package com.kardinal.vpncontrol

internal object BenchmarkSummaryFormatter {
    private const val BEST_SOURCE_SEPARATOR = " • Best from: "

    fun detailWithoutBestSource(summary: String): String {
        return summary.substringBefore(BEST_SOURCE_SEPARATOR).trim()
    }

    fun compactBestSourceRepeats(summary: String): String {
        val parts = summary.split(BEST_SOURCE_SEPARATOR)
        if (parts.size <= 2) {
            return summary.trim()
        }
        val detail = parts.first().trim()
        val sourceLabel = parts.last().trim()
        return appendBestSource(detail, sourceLabel)
    }

    fun appendBestSource(detail: String, sourceLabel: String): String {
        val baseDetail = detailWithoutBestSource(detail)
        val normalizedSourceLabel = sourceLabel.trim()
        return when {
            baseDetail.isBlank() -> normalizedSourceLabel
            normalizedSourceLabel.isBlank() -> baseDetail
            else -> "$baseDetail$BEST_SOURCE_SEPARATOR$normalizedSourceLabel"
        }
    }
}
