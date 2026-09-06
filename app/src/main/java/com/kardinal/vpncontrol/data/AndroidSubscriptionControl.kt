package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.*

internal class AndroidSubscriptionPlan(
    val subscriptions: List<SubscriptionSource>,
    val activeId: String,
    val mode: ProfileSourceMode,
    val targetId: String,
    val invalidatesSelectedSource: Boolean,
)

internal object AndroidSubscriptionControl {
    fun renamedSelectionNeedsInvalidation(sourceChanged: Boolean, selectedSource: String, oldSource: String, running: Boolean?): Boolean =
        sourceChanged && selectedSource == oldSource && running == false

    val operations = setOf(ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE, ControlOperationId.SUBSCRIPTIONS_DELETE)

    fun arguments(operation: ControlOperationId, values: Map<String, ControlValue>): Map<String, ControlValue> {
        require(operation in operations && values.values.all { it is ControlValue.Text }) { "INVALID_ARGUMENT" }
        val sourceCount = values.keys.count { it == "input" || it == "source" }
        val hasId = operation != ControlOperationId.SUBSCRIPTIONS_ADD
        val allowed = if (operation == ControlOperationId.SUBSCRIPTIONS_DELETE) setOf("id")
            else setOf("source", "input", "name") + if (hasId) setOf("id") else emptySet()
        require(values.keys.all { it in allowed }) { "INVALID_ARGUMENT" }
        require(!hasId || (values["id"] as? ControlValue.Text)?.value?.isNotBlank() == true) { "INVALID_ARGUMENT" }
        require(when (operation) {
            ControlOperationId.SUBSCRIPTIONS_ADD -> sourceCount == 1
            ControlOperationId.SUBSCRIPTIONS_UPDATE -> sourceCount <= 1 && (sourceCount == 1 || "name" in values)
            else -> values.keys == setOf("id")
        }) { "INVALID_ARGUMENT" }
        return values
    }

    fun plan(state: PersistedState, operation: ControlOperationId, values: Map<String, ControlValue>,
             validateSource: (String) -> Result<Unit>, newId: () -> String): AndroidSubscriptionPlan {
        arguments(operation, values)
        fun text(key: String) = (values[key] as? ControlValue.Text)?.value
        val target = text("id")?.let { id -> state.subscriptions.singleOrNull { it.id == id } ?: error("NOT_FOUND") }
        val source = (text("source") ?: text("input"))?.trim()
        if (source != null) require(source.isNotBlank() && validateSource(source).isSuccess) { "INVALID_ARGUMENT" }
        val name = text("name")?.take(80)?.trim()
        val next: List<SubscriptionSource>
        val id: String
        var mode = state.profileSourceMode
        var active = state.activeSubscriptionId
        var invalidatesSelectedSource = false
        when (operation) {
            ControlOperationId.SUBSCRIPTIONS_ADD -> {
                val existing = state.subscriptions.firstOrNull { it.url == source }
                val saved = (existing ?: SubscriptionSource(newId(), requireNotNull(source)))
                    .copy(customName = name.orEmpty().ifBlank { existing?.customName.orEmpty() })
                next = listOf(saved) + state.subscriptions.filterNot { it.id == saved.id }
                id = saved.id; active = id; mode = ProfileSourceMode.SUBSCRIPTION
            }
            ControlOperationId.SUBSCRIPTIONS_UPDATE -> {
                val previous = requireNotNull(target)
                val url = source ?: previous.url
                require(state.subscriptions.none { it.id != previous.id && it.url == url }) { "INVALID_ARGUMENT" }
                val changed = url != previous.url
                invalidatesSelectedSource = changed && state.selectedProfileSourceUrl == previous.url
                val saved = previous.copy(url = url, customName = name ?: previous.customName,
                    cachedLocations = if (changed) emptyList() else previous.cachedLocations,
                    lastRefreshedAtEpochMillis = if (changed) 0 else previous.lastRefreshedAtEpochMillis,
                    lastRefreshStatus = if (changed) "" else previous.lastRefreshStatus)
                next = state.subscriptions.map { if (it.id == previous.id) saved else it }
                id = previous.id
            }
            else -> {
                id = requireNotNull(target).id
                next = state.subscriptions.filterNot { it.id == id }
                if (!(active == ALL_SUBSCRIPTIONS_ID && supportsAllSubscriptionsGroup(next)) && next.none { it.id == active })
                    active = next.firstOrNull()?.id.orEmpty()
            }
        }
        return AndroidSubscriptionPlan(next, active, mode, id, invalidatesSelectedSource)
    }
}
