package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlOperationRegistry
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationId.*
import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue

/** Implemented JSON adapter surface, not a claim that the complete product registry is wired. */
internal object DesktopControlSupport {
    val revisionGuardOperations = setOf(SETTINGS_SET, SETTINGS_APPLY, SSH_KEY_IMPORT,
        SUBSCRIPTIONS_ADD, SUBSCRIPTIONS_UPDATE, SUBSCRIPTIONS_DELETE, LOCATIONS_ADD, LOCATIONS_UPDATE,
        LOCATIONS_SELECT, LOCATIONS_DELETE, LOCATIONS_IMPORT, SOURCE_SET, ROUTING_SET, ROUTING_IMPORT, QUIT)
    val asynchronousOperations = setOf(ON, OFF, RESTART, FIND_BEST, LOCATIONS_BENCHMARK, SUBSCRIPTIONS_REFRESH, UPDATES_CHECK, UPDATES_DOWNLOAD,
        SUBSCRIPTIONS_ADD, SUBSCRIPTIONS_UPDATE, LOCATIONS_DELETE, LOCATIONS_IMPORT)
    val cancellableOperations = setOf(UPDATES_CHECK, UPDATES_DOWNLOAD)
    val jsonOperations = asynchronousOperations + DesktopControlInspection.operations + DesktopControlMutations.operations + DesktopControlExports.operations + setOf(SETTINGS_SHOW, SETTINGS_SET, SETTINGS_APPLY,
        OPERATIONS_LIST, OPERATIONS_STATUS, OPERATIONS_WAIT, OPERATIONS_CANCEL, UPDATES_CANCEL, QUIT, GUI_SHOW, GUI_HIDE, CAPABILITIES, STATUS)

    fun describe(platform: ControlPlatform): Map<String, ControlValue> = mapOf(
        "scope" to ControlValue.Text("static-desktop-json-adapter"),
        "platform" to ControlValue.Text(platform.name.lowercase()),
        "runtimeReadinessChecked" to ControlValue.BooleanValue(false),
        "streamingOperations" to ControlValue.ArrayValue(listOf(STATUS, STATS, LOGS).map { ControlValue.Text(it.wireName) }),
        "jsonOperations" to ControlValue.ArrayValue(ControlOperationRegistry.operations.map { descriptor ->
            ControlValue.ObjectValue(mapOf(
                "id" to ControlValue.Text(descriptor.id.wireName),
                "supported" to ControlValue.BooleanValue(descriptor.id in jsonOperations),
                "asynchronous" to ControlValue.BooleanValue(descriptor.id in asynchronousOperations),
                "cancellable" to ControlValue.BooleanValue(descriptor.id in cancellableOperations),
                "reasonCode" to if (descriptor.id in jsonOperations) ControlValue.Null else ControlValue.Text("NOT_IMPLEMENTED"),
            ))
        }),
        "platformCapabilities" to ControlValue.ObjectValue(listOf("mode.vpn", "mode.proxy-only", "autostart", "routing.apps")
            .associateWith { ControlValue.BooleanValue(ControlOperationRegistry.platformSupports(it, platform)) }),
        "publicRevisionGuards" to ControlValue.BooleanValue(true),
        "revisionGuardOperations" to ControlValue.ArrayValue(revisionGuardOperations.map { ControlValue.Text(it.wireName) }),
        "guiAttachDetach" to ControlValue.BooleanValue(true),
    )
}
