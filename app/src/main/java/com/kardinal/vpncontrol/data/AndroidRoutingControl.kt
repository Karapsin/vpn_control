package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlCommandArguments
import com.kardinal.vpncontrol.control.ControlRoutingLogic
import com.kardinal.vpncontrol.model.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/** Current Android routing controls, using the same normalization and visible-app filter as GUI. */
internal object AndroidRoutingControl {
    val appOperations = setOf(ControlOperationId.ROUTING_APPS_SET, ControlOperationId.ROUTING_APPS_ADD,
        ControlOperationId.ROUTING_APPS_REMOVE, ControlOperationId.ROUTING_APPS_SELECT_ALL, ControlOperationId.ROUTING_APPS_CLEAR)
    val operations = appOperations + setOf(ControlOperationId.ROUTING_SET, ControlOperationId.ROUTING_IMPORT)

    fun arguments(operation: ControlOperationId, values: Map<String, ControlValue>): Map<String, ControlValue> {
        require(operation in operations && ControlCommandArguments.decode(ControlCommand(operation, values)) != null) { "INVALID_ARGUMENT" }
        return values
    }

    private fun visible(apps: List<InstalledApp>, search: String): List<InstalledApp> {
        val query = search.trim()
        return apps.filter { query.isEmpty() || it.label.contains(query, ignoreCase = true) || it.packageName.contains(query, ignoreCase = true) }
    }

    fun plan(state: PersistedState, operation: ControlOperationId, values: Map<String, ControlValue>, apps: List<InstalledApp>): RoutingRules {
        arguments(operation, values)
        fun text(key: String) = (values.getValue(key) as ControlValue.Text).value
        val rules = state.routingRules
        if (operation == ControlOperationId.ROUTING_SET) return ControlRoutingLogic.set(
            MainUiState(routingRules = rules), text("key"), text("value")).getOrElse { error("INVALID_ARGUMENT") }.routingRules
        if (operation == ControlOperationId.ROUTING_IMPORT) return runCatching {
            MainDraftLogic.sanitizeRoutingRules(RoutingRulesTransfer.import(text("input")))
        }.getOrElse { error("INVALID_ARGUMENT") }
        val known = apps.map { it.packageName }.toSet()
        val selected = rules.proxyPackages.toSet()
        val updated = when (operation) {
            ControlOperationId.ROUTING_APPS_SET -> {
                val requested = runCatching {
                    val input = Json.parseToJsonElement(text("input")) as? JsonArray ?: error("INVALID_ARGUMENT")
                    RoutingRules.normalizePackageNames(input.map {
                        val item = it as? JsonPrimitive ?: error("INVALID_ARGUMENT")
                        require(item.isString && item.content.isNotBlank())
                        item.content
                    })
                }.getOrElse { error("INVALID_ARGUMENT") }
                check(requested.all { it in known }) { "NOT_FOUND" }
                requested.toSet()
            }
            ControlOperationId.ROUTING_APPS_ADD, ControlOperationId.ROUTING_APPS_REMOVE -> {
                val target = text("package").trim()
                check(target in known) { "NOT_FOUND" }
                if (operation == ControlOperationId.ROUTING_APPS_ADD) selected + target else selected - target
            }
            ControlOperationId.ROUTING_APPS_SELECT_ALL, ControlOperationId.ROUTING_APPS_CLEAR -> {
                val matching = visible(apps, (values["search"] as? ControlValue.Text)?.value.orEmpty()).map { it.packageName }.toSet()
                if (operation == ControlOperationId.ROUTING_APPS_SELECT_ALL) selected + matching else selected - matching
            }
            else -> error("INVALID_ARGUMENT")
        }
        return MainDraftLogic.sanitizeRoutingRules(rules.copy(proxyPackages = RoutingRules.normalizePackageNames(updated.toList())))
    }

    fun result(state: PersistedState, operation: ControlOperationId, values: Map<String, ControlValue>): Map<String, ControlValue> {
        val rules = state.routingRules
        val all = mapOf("ignore-rules" to ControlValue.BooleanValue(rules.ignoreRules),
            "block-quic-udp443" to ControlValue.BooleanValue(rules.blockQuicUdp443),
            "direct-domains" to ControlValue.ArrayValue(rules.directDomainSuffixes.map { ControlValue.Text(it) }),
            "proxyPackages" to ControlValue.ArrayValue(rules.proxyPackages.map { ControlValue.Text(it) }))
        return when {
            operation == ControlOperationId.ROUTING_SET -> all.filterKeys { it == (values["key"] as? ControlValue.Text)?.value }
            operation in appOperations -> all.filterKeys { it == "proxyPackages" }
            else -> all
        }
    }

    fun list(state: PersistedState, values: Map<String, ControlValue>, apps: List<InstalledApp>): Map<String, ControlValue> {
        require(ControlCommandArguments.decode(ControlCommand(ControlOperationId.ROUTING_APPS_LIST, values)) != null) { "INVALID_ARGUMENT" }
        return mapOf("apps" to ControlValue.ArrayValue(visible(apps, (values["search"] as? ControlValue.Text)?.value.orEmpty()).map {
            ControlValue.ObjectValue(mapOf("package" to ControlValue.Text(it.packageName), "label" to ControlValue.Text(it.label),
                "system" to ControlValue.BooleanValue(it.isSystemApp), "selected" to ControlValue.BooleanValue(it.packageName in state.routingRules.proxyPackages)))
        }))
    }
}
