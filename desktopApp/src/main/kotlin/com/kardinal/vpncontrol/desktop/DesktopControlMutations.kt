package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCommandArguments
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId.*
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID

/** Transport adaptation only; existing domain services validate, persist and perform effects. */
internal object DesktopControlMutations {
    val operations = setOf(LOCATIONS_SELECT, SOURCE_SET, SUBSCRIPTIONS_ADD, SUBSCRIPTIONS_UPDATE,
        SUBSCRIPTIONS_DELETE, LOCATIONS_ADD, LOCATIONS_UPDATE, LOCATIONS_DELETE, LOCATIONS_IMPORT,
        ROUTING_SET, ROUTING_IMPORT, SSH_KEY_IMPORT, UPDATES_DISMISS)

    fun command(request: ControlCommand): DesktopCliCommand? {
        if (request.operation !in operations) return null
        val parsed = ControlCommandArguments.decode(request) ?: return null
        if ("--qr-image" in parsed.options) return null
        val args = parsed.positional
        val options = parsed.options
        return when (request.operation) {
            LOCATIONS_SELECT -> DesktopCliCommand.Select(args.single())
            SOURCE_SET -> DesktopCliCommand.SourceSet(when (args.first()) {
                "current-locations" -> null
                "all" -> ALL_SUBSCRIPTIONS_ID
                else -> args[1]
            })
            SUBSCRIPTIONS_ADD, SUBSCRIPTIONS_UPDATE -> DesktopCliCommand.SubscriptionSave(
                options["--input"] ?: options["--source"], options["--name"], args.singleOrNull())
            SUBSCRIPTIONS_DELETE -> DesktopCliCommand.SubscriptionDelete(args.single())
            LOCATIONS_ADD, LOCATIONS_UPDATE -> DesktopCliCommand.LocationSave(options.getValue("--input"), args.singleOrNull())
            LOCATIONS_DELETE -> DesktopCliCommand.LocationDelete(args.single())
            LOCATIONS_IMPORT -> DesktopCliCommand.LocationsImport(options.getValue("--input"))
            ROUTING_SET -> DesktopCliCommand.RoutingSet(args[0], args[1])
            ROUTING_IMPORT -> DesktopCliCommand.RoutingImport(options.getValue("--input"))
            SSH_KEY_IMPORT -> DesktopCliCommand.SshKeyImport(options.getValue("--input"))
            UPDATES_DISMISS -> DesktopCliCommand.UpdatesDismiss
            else -> null
        }
    }
}
