package com.kardinal.vpncontrol.data

enum class ImportPreference {
    AUTO,
    SUBSCRIPTION,
    LOCATION,
    ROUTING_RULES,
}

sealed interface IncomingImportPayload {
    data class Subscription(val raw: String) : IncomingImportPayload
    data class Location(val raw: String) : IncomingImportPayload
    data class RoutingRules(val raw: String) : IncomingImportPayload
}

object IncomingImportResolver {
    fun resolve(raw: String, preference: ImportPreference = ImportPreference.AUTO): Result<IncomingImportPayload> =
        runCatching {
            val trimmed = raw.trim()
            require(trimmed.isNotBlank()) { "Import text is empty" }
            when (preference) {
                ImportPreference.SUBSCRIPTION -> {
                    RemoteSourceResolver.validateProfileSource(trimmed).getOrThrow()
                    IncomingImportPayload.Subscription(trimmed)
                }
                ImportPreference.LOCATION -> {
                    LocationConfigs.parseLocationInput(trimmed)
                    IncomingImportPayload.Location(trimmed)
                }
                ImportPreference.ROUTING_RULES -> {
                    RoutingRulesTransfer.import(trimmed)
                    IncomingImportPayload.RoutingRules(trimmed)
                }
                ImportPreference.AUTO -> autoResolve(trimmed)
            }
        }

    private fun autoResolve(trimmed: String): IncomingImportPayload {
        if (RemoteSourceResolver.looksLikeRemoteSourceLink(trimmed)) {
            RemoteSourceResolver.validateProfileSource(trimmed).getOrThrow()
            return IncomingImportPayload.Subscription(trimmed)
        }
        runCatching {
            RoutingRulesTransfer.import(trimmed)
            return IncomingImportPayload.RoutingRules(trimmed)
        }
        runCatching {
            LocationConfigs.parseLocationInput(trimmed)
            return IncomingImportPayload.Location(trimmed)
        }
        error("Shared text is not a supported subscription, location config, or routing rules document")
    }
}
