package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.DiagnosticsSanitizer
import com.kardinal.vpncontrol.model.*
import com.kardinal.vpncontrol.shared.ui.AppStrings
import com.kardinal.vpncontrol.shared.ui.UiText
import java.net.URI

internal enum class DesktopSourceLabelKind { SAVED_LOCATIONS, ALL_SUBSCRIPTIONS, SUBSCRIPTION, DIFFERENT_SUBSCRIPTION, NONE }

/** A display reference, never a subscription URL or credential-bearing selector. */
internal data class DesktopSourceLabel(
    val kind: DesktopSourceLabelKind,
    val subscriptionId: String? = null,
    val displayName: String = "",
) {
    fun render(strings: AppStrings): String = when (kind) {
        DesktopSourceLabelKind.SAVED_LOCATIONS -> strings.get(UiText.SAVED_LOCATIONS)
        DesktopSourceLabelKind.ALL_SUBSCRIPTIONS -> strings.get(UiText.ALL_SUBSCRIPTIONS)
        DesktopSourceLabelKind.DIFFERENT_SUBSCRIPTION -> strings.get(UiText.DIFFERENT_SUBSCRIPTION)
        DesktopSourceLabelKind.NONE -> strings.get(UiText.NONE)
        DesktopSourceLabelKind.SUBSCRIPTION -> displayName
    }

    fun values() = ControlValue.ObjectValue(mapOf(
        "kind" to ControlValue.Text(kind.name.lowercase()),
        "subscriptionId" to (subscriptionId?.let(ControlValue::Text) ?: ControlValue.Null),
        "displayName" to ControlValue.Text(displayName),
    ))
}

internal data class DesktopSourcePresentation(
    val selected: DesktopSourceLabel,
    val current: DesktopSourceLabel,
    val selectedOutsideCurrent: Boolean,
) {
    fun values(): Map<String, ControlValue> = mapOf(
        "selectedSource" to selected.values(), "currentSource" to current.values(),
        "selectedOutsideCurrent" to ControlValue.BooleanValue(selectedOutsideCurrent),
    )

    companion object {
        fun fromValues(values: Map<String, ControlValue>): DesktopSourcePresentation {
            fun read(name: String): DesktopSourceLabel {
                val fields = (values.getValue(name) as ControlValue.ObjectValue).values
                require(fields.keys == setOf("kind", "subscriptionId", "displayName"))
                val kind = DesktopSourceLabelKind.entries.first { it.name.lowercase() == (fields.getValue("kind") as ControlValue.Text).value }
                val id = when (val value = fields.getValue("subscriptionId")) {
                    ControlValue.Null -> null
                    is ControlValue.Text -> value.value.also { require(it.isNotBlank()) }
                    else -> error("INCOMPATIBLE_PROTOCOL")
                }
                val display = (fields.getValue("displayName") as ControlValue.Text).value
                require(kind == DesktopSourceLabelKind.SUBSCRIPTION || (id == null && display.isEmpty()))
                require(kind != DesktopSourceLabelKind.SUBSCRIPTION || display.isNotBlank())
                return DesktopSourceLabel(kind, id, display)
            }
            return DesktopSourcePresentation(read("selectedSource"), read("currentSource"),
                (values.getValue("selectedOutsideCurrent") as ControlValue.BooleanValue).value)
        }

        /** The owner resolves private URLs; the frontend receives only these display references. */
        fun capture(state: MainUiState): DesktopSourcePresentation {
            fun label(kind: DesktopSourceLabelKind) = DesktopSourceLabel(kind)
            val none = label(DesktopSourceLabelKind.NONE)
            if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) {
                val saved = label(DesktopSourceLabelKind.SAVED_LOCATIONS)
                return DesktopSourcePresentation(saved, saved, false)
            }
            val all = isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
            fun source(url: String): DesktopSourceLabel {
                val subscription = state.subscriptions.firstOrNull { it.url == url }
                val display = subscription?.customName?.takeIf(String::isNotBlank)
                    ?: runCatching { URI(url).host }.getOrNull().orEmpty()
                // Malformed/non-URL sources must not fall back to raw input.
                if (display.isBlank()) return label(DesktopSourceLabelKind.DIFFERENT_SUBSCRIPTION)
                return DesktopSourceLabel(DesktopSourceLabelKind.SUBSCRIPTION, subscription?.id,
                    DiagnosticsSanitizer.redactText(display))
            }
            val current = when {
                all -> label(DesktopSourceLabelKind.ALL_SUBSCRIPTIONS)
                else -> state.subscriptions.firstOrNull { it.id == state.activeSubscriptionId }?.let { source(it.url) } ?: none
            }
            val selected = when {
                state.selectedProfileName.isNotBlank() && state.selectedProfileSourceUrl.isNotBlank() -> source(state.selectedProfileSourceUrl.trim())
                state.selectedProfileName.isNotBlank() -> label(DesktopSourceLabelKind.DIFFERENT_SUBSCRIPTION)
                all -> label(DesktopSourceLabelKind.ALL_SUBSCRIPTIONS)
                state.profileUrl.isNotBlank() -> source(state.profileUrl.trim())
                else -> none
            }
            val outside = state.selectedProfileName.isNotBlank() && !all && state.selectedProfileSourceUrl.isNotBlank() &&
                state.selectedProfileSourceUrl !in activeSubscriptionUrls(state.activeSubscriptionId, state.subscriptions)
            return DesktopSourcePresentation(selected, current, outside)
        }
    }
}
