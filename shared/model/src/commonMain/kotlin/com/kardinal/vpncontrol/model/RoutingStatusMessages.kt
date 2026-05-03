package com.kardinal.vpncontrol.model

object RoutingStatusMessages {
    fun connectionModeSet(mode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.CONNECTION_MODE_SET, mode.name)

    fun ruleSetRemoved(): String =
        StatusMessageCodec.encode(StatusMessageKey.RULE_SET_REMOVED)

    fun switchToSavedLocationsToAddLocations(): String =
        StatusMessageCodec.encode(StatusMessageKey.SWITCH_TO_SAVED_LOCATIONS_TO_ADD_LOCATIONS)

    fun historyEntryDeleted(): String =
        StatusMessageCodec.encode(StatusMessageKey.HISTORY_ENTRY_DELETED)

    fun sampleRuleSetAdded(): String =
        StatusMessageCodec.encode(StatusMessageKey.SAMPLE_RULE_SET_ADDED)

    fun ruleSetDeleted(id: String): String =
        StatusMessageCodec.encode(StatusMessageKey.RULE_SET_DELETED, id)

    fun routingRulesSaved(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_SAVED)

    fun routingRulesSavedRestartRequired(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_SAVED_RESTART_REQUIRED, appMode.name)

    fun routingRulesSaveFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_SAVE_FAILED)

    fun routingRulesImported(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_IMPORTED)

    fun routingRulesImportedRestartRequired(appMode: AppMode): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_IMPORTED_RESTART_REQUIRED, appMode.name)

    fun routingRulesImportFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_IMPORT_FAILED)

    fun routingRulesCopiedToClipboard(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_COPIED_TO_CLIPBOARD)

    fun routingRulesExportCanceled(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_EXPORT_CANCELED)

    fun routingRulesExportedTo(path: String): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_EXPORTED_TO, path)

    fun routingRulesExportFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_EXPORT_FAILED)

    fun routingRulesFileOpenFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.ROUTING_RULES_FILE_OPEN_FAILED)

    fun invalidRuleSet(): String =
        StatusMessageCodec.encode(StatusMessageKey.INVALID_RULE_SET)

    fun ruleSetAdded(): String =
        StatusMessageCodec.encode(StatusMessageKey.RULE_SET_ADDED)

    fun ruleSetUpdated(): String =
        StatusMessageCodec.encode(StatusMessageKey.RULE_SET_UPDATED)
}
