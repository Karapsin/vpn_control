package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationId.*
import com.kardinal.vpncontrol.model.ControlPlatform

enum class ControlActionKind { PRODUCT, INSPECTION, PRESENTATION, SERVICE }

/** GUI binding keys are semantic action IDs. Adapters must bind them and prove coverage. */
data class ControlOperationDescriptor(
    val id: ControlOperationId,
    val grammar: String,
    val aliases: List<String> = emptyList(),
    val mutates: Boolean = false,
    val supportsAsync: Boolean = false,
    val requiredCapability: String? = null,
    val kind: ControlActionKind = ControlActionKind.PRODUCT,
    val guiAction: String? = null,
    val contracts: Set<String> = setOf("CLI-001", "CLI-002"),
) {
    val coverageId: String get() = "control.${id.wireName}"
    val commandWords: List<String> get() = id.wireName.split('.')
    val arguments: ControlArgumentSchema get() = ControlCliParser.schema(id)
}

/** Inventory, not an implementation availability claim. Capabilities also need an adapter. */
object ControlOperationRegistry {
    val operations: List<ControlOperationDescriptor> = listOf(
        product(ON, "on", "connection.on", async = true),
        product(OFF, "off", "connection.off", async = true),
        inspect(STATUS, "status [--watch]"),
        product(RESTART, "restart", "connection.restart", async = true),
        product(FIND_BEST, "find-best", "connection.find-best", async = true),
        inspect(SOURCE_SHOW, "source show"),
        product(SOURCE_SET, "source set <current-locations|subscription ID|all>", "source.select"),
        inspect(SUBSCRIPTIONS_LIST, "subscriptions list"),
        inspect(SUBSCRIPTIONS_SHOW, "subscriptions show <id>"),
        product(SUBSCRIPTIONS_ADD, "subscriptions add <--source URL|--input PATH|-|--qr-image PATH> [--name NAME]", "subscription.add", async = true),
        product(SUBSCRIPTIONS_UPDATE, "subscriptions update <id> [--source URL|--input PATH|-] [--name NAME]", "subscription.edit", async = true),
        product(SUBSCRIPTIONS_DELETE, "subscriptions delete <id>", "subscription.delete"),
        product(SUBSCRIPTIONS_REFRESH, "subscriptions refresh <id|active|all>", "subscription.refresh", async = true),
        inspect(LOCATIONS_LIST, "locations list"),
        inspect(LOCATIONS_SHOW, "locations show <selector>"),
        product(LOCATIONS_ADD, "locations add <--input PATH|-|--qr-image PATH>", "location.add"),
        product(LOCATIONS_UPDATE, "locations update <selector> --input PATH|-", "location.edit"),
        product(LOCATIONS_DELETE, "locations delete <selector>", "location.delete", async = true),
        product(LOCATIONS_SELECT, "locations select <selector>", "location.select").copy(aliases = listOf("select")),
        product(LOCATIONS_BENCHMARK, "locations benchmark <selector>", "location.benchmark", async = true),
        product(LOCATIONS_IMPORT, "locations import <--input PATH|-|--qr-image PATH>", "location.import", async = true),
        product(LOCATIONS_EXPORT, "locations export --output PATH|- [--format json|qr-png]", "location.export", mutates = false),
        inspect(ROUTING_SHOW, "routing show"),
        product(ROUTING_SET, "routing set <ignore-rules|direct-domains|block-quic-udp443> <value>", "routing.save"),
        product(ROUTING_IMPORT, "routing import <--input PATH|-|--qr-image PATH>", "routing.import"),
        product(ROUTING_EXPORT, "routing export --output PATH|- [--format json|qr-png]", "routing.export", mutates = false),
        inspect(ROUTING_APPS_LIST, "routing apps list [--search TEXT]", "routing.apps"),
        product(ROUTING_APPS_SET, "routing apps set --input PATH|-", "routing.apps.set", capability = "routing.apps"),
        product(ROUTING_APPS_ADD, "routing apps add <package>", "routing.apps.add", capability = "routing.apps"),
        product(ROUTING_APPS_REMOVE, "routing apps remove <package>", "routing.apps.remove", capability = "routing.apps"),
        product(ROUTING_APPS_SELECT_ALL, "routing apps select-all [--search TEXT]", "routing.apps.select-all", capability = "routing.apps"),
        product(ROUTING_APPS_CLEAR, "routing apps clear [--search TEXT]", "routing.apps.clear", capability = "routing.apps"),
        inspect(SETTINGS_SHOW, "settings show [key]"),
        product(SETTINGS_SET, "settings set <key> <value>", "settings.save"),
        product(SETTINGS_APPLY, "settings apply --input PATH|-", "settings.save"),
        inspect(SETTINGS_LANGUAGES, "settings languages"),
        inspect(SSH_KEY_STATUS, "ssh key status"),
        product(SSH_KEY_IMPORT, "ssh key import --input PATH|-", "ssh.key.import"),
        inspect(STATS, "stats [--watch]"),
        inspect(LOGS, "logs [--follow] [--limit N]"),
        product(DIAGNOSTICS_EXPORT, "diagnostics export --output PATH|-", "diagnostics.export", mutates = false, async = true),
        inspect(OPERATIONS_LIST, "operations list"),
        inspect(OPERATIONS_STATUS, "operations status <id>"),
        inspect(OPERATIONS_WAIT, "operations wait <id>"),
        product(OPERATIONS_CANCEL, "operations cancel <id>", "operation.cancel"),
        inspect(UPDATES_STATUS, "updates status"),
        product(UPDATES_CHECK, "updates check", "updates.check", async = true),
        product(UPDATES_DOWNLOAD, "updates download", "updates.download", async = true),
        product(UPDATES_INSTALL, "updates install", "updates.install", async = true),
        product(UPDATES_CANCEL, "updates cancel", "updates.cancel"),
        product(UPDATES_DISMISS, "updates dismiss", "updates.dismiss"),
        ControlOperationDescriptor(SERVE, "serve", kind = ControlActionKind.SERVICE, requiredCapability = "desktop.lifecycle"),
        ControlOperationDescriptor(GUI_SHOW, "gui show", mutates = true, kind = ControlActionKind.PRESENTATION, requiredCapability = "desktop.gui"),
        ControlOperationDescriptor(GUI_HIDE, "gui hide", mutates = true, kind = ControlActionKind.PRESENTATION, requiredCapability = "desktop.gui"),
        ControlOperationDescriptor(QUIT, "quit", mutates = true, kind = ControlActionKind.SERVICE, requiredCapability = "desktop.lifecycle"),
        inspect(CAPABILITIES, "capabilities"),
    )

    private val byId = operations.associateBy { it.id }

    init {
        check(byId.size == operations.size && byId.keys == ControlOperationId.entries.toSet())
        check(operations.all { it.kind != ControlActionKind.PRODUCT || !it.guiAction.isNullOrBlank() })
    }

    operator fun get(id: ControlOperationId): ControlOperationDescriptor = byId.getValue(id)

    /** OS support is necessary but not sufficient: permission and handler readiness are separate. */
    fun platformSupports(capability: String, platform: ControlPlatform): Boolean = when (capability) {
        "routing.apps" -> platform == ControlPlatform.ANDROID
        "desktop.lifecycle", "desktop.gui" -> platform != ControlPlatform.ANDROID
        "autostart" -> platform == ControlPlatform.LINUX || platform == ControlPlatform.WINDOWS
        "mode.vpn" -> platform != ControlPlatform.MACOS
        "mode.proxy-only" -> true
        else -> false
    }

    private fun product(
        id: ControlOperationId, grammar: String, guiAction: String,
        mutates: Boolean = true, async: Boolean = false, capability: String? = null,
    ) = ControlOperationDescriptor(id, grammar, mutates = mutates, supportsAsync = async,
        requiredCapability = capability, guiAction = guiAction)

    private fun inspect(id: ControlOperationId, grammar: String, capability: String? = null) =
        ControlOperationDescriptor(id, grammar, kind = ControlActionKind.INSPECTION, requiredCapability = capability)
}
