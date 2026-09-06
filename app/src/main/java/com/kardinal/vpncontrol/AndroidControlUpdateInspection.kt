package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.ControlValue

/** Read-only projection of the same immutable update state rendered by Android GUI. */
internal object AndroidControlUpdateInspection {
    fun read(state: AppUpdateState, checked: AndroidUpdateCheck? = null): Map<String, ControlValue> {
        val resolvedAsset = state.phase in setOf(AppUpdatePhase.DOWNLOADING, AppUpdatePhase.VERIFYING,
            AppUpdatePhase.READY, AppUpdatePhase.INSTALLING)
        val manifestResolved = resolvedAsset || state.phase in setOf(AppUpdatePhase.UP_TO_DATE, AppUpdatePhase.UNSUPPORTED)
        fun boolean(value: Boolean?) = value?.let(ControlValue::BooleanValue) ?: ControlValue.Null
        return mapOf(
            "phase" to ControlValue.Text(state.phase.name.lowercase()),
            // FAILED does not retain enough manifest information to invent an
            // availability verdict. A failed check is not "up to date".
            "checked" to boolean(if (checked != null) true else if (state.phase == AppUpdatePhase.FAILED) null else manifestResolved),
            "available" to boolean(when {
                checked != null -> checked.available
                resolvedAsset || state.phase == AppUpdatePhase.UNSUPPORTED -> true
                state.phase == AppUpdatePhase.UP_TO_DATE -> false
                else -> null
            }),
            "compatible" to boolean(when {
                checked != null -> if (checked.available) checked.asset != null else null
                resolvedAsset -> true
                state.phase == AppUpdatePhase.UNSUPPORTED -> false
                else -> null
            }),
            "availableVersion" to (state.availableVersion.takeIf(String::isNotBlank)?.let(ControlValue::Text) ?: ControlValue.Null),
            "downloadedBytes" to ControlValue.IntegerValue(state.downloadedBytes),
            "totalBytes" to (state.totalBytes.takeIf { it > 0 }?.let(ControlValue::IntegerValue) ?: ControlValue.Null),
        )
    }
}
