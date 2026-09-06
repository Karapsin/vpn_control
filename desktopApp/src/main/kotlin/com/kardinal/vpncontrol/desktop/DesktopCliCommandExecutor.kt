package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.control.ControlLocationResolution
import com.kardinal.vpncontrol.control.ControlLocationSelection
import com.kardinal.vpncontrol.data.LocationConfigs
import kotlinx.serialization.json.JsonPrimitive

internal suspend fun DesktopAppService.executeCliCommand(command: DesktopCliCommand): DesktopCliResponse {
    if (state.isBusy && !command.bypassesMutationAdmission) {
        return DesktopCliResponse.failure("VPN Control is busy.")
    }
    return when (command) {
        is DesktopCliCommand.ControlFrontendIdentityRead -> DesktopCliResponse.failure("UNSUPPORTED")
        is DesktopCliCommand.ControlFrontendLease -> DesktopCliResponse.failure("UNSUPPORTED")
        is DesktopCliCommand.ControlPresentationRead -> DesktopCliResponse.failure("UNSUPPORTED")
        is DesktopCliCommand.ControlSnapshotRead -> DesktopCliResponse.failure("UNSUPPORTED")
        is DesktopCliCommand.ControlSubmit -> DesktopCliResponse.failure("UNAVAILABLE", 2)
        // The legacy GUI-owned service has no authoritative operation ledger.
        DesktopCliCommand.OperationsList, is DesktopCliCommand.OperationStatus, is DesktopCliCommand.OperationWait,
        is DesktopCliCommand.OperationCancel -> DesktopCliResponse.failure("UNAVAILABLE", 2)
        DesktopCliCommand.UpdatesStatus -> DesktopCliResponse.success(controlUpdateStatus())
        DesktopCliCommand.UpdatesCheck -> checkControlUpdate().fold(
            onSuccess = { if (it.updateAvailable && it.asset == null) DesktopCliResponse.failure("UNSUPPORTED")
                else DesktopCliResponse.success(controlUpdateStatus()) },
            onFailure = { DesktopCliResponse.failure(if (it.message == "BUSY") "BUSY" else "UPDATE_CHECK_FAILED") },
        )
        DesktopCliCommand.UpdatesDownload -> downloadControlUpdate().fold(
            onSuccess = { DesktopCliResponse.success(controlUpdateStatus()) },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("NO_UPDATE_AVAILABLE", "UPDATE_DOWNLOAD_FAILED", "BUSY")
            } ?: "UPDATE_DOWNLOAD_FAILED") },
        )
        DesktopCliCommand.UpdatesDismiss -> dismissControlUpdate().fold(
            onSuccess = { DesktopCliResponse.success(controlUpdateStatus()) },
            onFailure = { DesktopCliResponse.failure("BUSY") },
        )
        DesktopCliCommand.Stats -> DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
            controlReadSnapshot(com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.STATS))
                .values.getOrThrow()))
        is DesktopCliCommand.Logs -> DesktopCliResponse.success(state.connectionLog.takeLast(command.limit).joinToString("\n") {
            "${it.createdAtEpochMillis}\t${JsonPrimitive(com.kardinal.vpncontrol.data.DiagnosticsSanitizer.redactText(it.message))}"
        })
        DesktopCliCommand.DiagnosticsExport -> runCatching { controlDiagnosticsReport() }.fold(
            onSuccess = { DesktopCliResponse.success(it) },
            onFailure = { DesktopCliResponse.failure("DIAGNOSTICS_FAILED") },
        )
        DesktopCliCommand.LocationsExport -> if (state.currentLocations.isEmpty()) DesktopCliResponse.failure("NOT_FOUND")
            else DesktopCliResponse.success(LocationConfigs.export(state.currentLocations).content)
        is DesktopCliCommand.LocationsImport -> importLocationsRaw(command.content).fold(
            onSuccess = { DesktopCliResponse.success("Locations imported.") },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("INVALID_ARGUMENT", "READ_ONLY", "BUSY", "PERSISTENCE_FAILED")
            } ?: "RUNTIME_FAILED") },
        )
        DesktopCliCommand.Languages -> DesktopCliResponse.success(com.kardinal.vpncontrol.model.AppLanguage.entries.joinToString("\n") {
            "${if (it == com.kardinal.vpncontrol.model.AppLanguage.SYSTEM) "system" else it.code}\t${JsonPrimitive(it.nativeName)}"
        })
        DesktopCliCommand.SshKeyStatus -> DesktopCliResponse.success(if (hasHomeSshPrivateKey()) "present" else "absent")
        is DesktopCliCommand.SshKeyImport -> importHomeSshPrivateKey(command.content).fold(
            onSuccess = { DesktopCliResponse.success("Private key imported.") },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("INVALID_ARGUMENT", "PERSISTENCE_FAILED", "ROLLBACK_FAILED", "BUSY", "UNSUPPORTED")
            } ?: "RUNTIME_FAILED") },
        )
        DesktopCliCommand.Unsupported -> DesktopCliResponse.failure("UNSUPPORTED")
        DesktopCliCommand.RoutingShow, DesktopCliCommand.RoutingExport -> DesktopCliResponse.success(
            com.kardinal.vpncontrol.data.RoutingRulesTransfer.export(state.routingRules).content)
        is DesktopCliCommand.RoutingSet -> setControlRouting(command.key, command.value).toRoutingResponse()
        is DesktopCliCommand.RoutingImport -> importControlRouting(command.content).toRoutingResponse(
            warnDesktopPackages = state.routingRules.proxyPackages.isNotEmpty())
        DesktopCliCommand.On -> cliTurnOn()
        DesktopCliCommand.Off -> cliTurnOff()
        DesktopCliCommand.Restart -> restartConnection().fold(
            onSuccess = { cliStatus() },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("BUSY", "NOT_RUNNING", "NOT_FOUND", "PERSISTENCE_FAILED", "ROLLBACK_FAILED")
            } ?: "RUNTIME_FAILED") },
        )
        DesktopCliCommand.Status -> cliStatus()
        DesktopCliCommand.FindBest -> cliFindBest()
        is DesktopCliCommand.Select -> cliSelect(command.target)
        is DesktopCliCommand.SubscriptionDelete -> deleteSubscription(command.id).toDeleteResponse()
        is DesktopCliCommand.SubscriptionRefresh -> refreshControlSubscriptions(command.target).fold(
            onSuccess = { refreshed ->
                val failed = refreshed.outcomes.count { !it.ok }
                val output = kotlinx.serialization.json.buildJsonObject {
                    put("code", JsonPrimitive(if (failed == 0) "OK" else if (refreshed.refreshedCount > 0) "PARTIAL_FAILURE" else "REFRESH_FAILED"))
                    put("sources", kotlinx.serialization.json.JsonArray(refreshed.outcomes.map { outcome ->
                        kotlinx.serialization.json.buildJsonObject {
                            put("id", JsonPrimitive(outcome.id))
                            put("ok", JsonPrimitive(outcome.ok))
                            put("locationCount", JsonPrimitive(outcome.locationCount))
                        }
                    }))
                }.toString()
                if (failed == 0) DesktopCliResponse.success(output) else DesktopCliResponse.failure(output)
            },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                code in setOf("BUSY", "NOT_FOUND", "PERSISTENCE_FAILED", "ROLLBACK_FAILED")
            } ?: "REFRESH_FAILED") },
        )
        is DesktopCliCommand.LocationDelete -> {
            val location = resolveCliLocation(command.target).getOrElse {
                return DesktopCliResponse.failure(it.message ?: "NOT_FOUND")
            }
            deleteLocation(location.index).toDeleteResponse()
        }
        is DesktopCliCommand.LocationBenchmark -> {
            val location = (command.configurationId?.let(::resolveControlLocation)
                ?: resolveCliLocation(command.target)).getOrElse {
                return DesktopCliResponse.failure(it.message ?: "NOT_FOUND")
            }
            benchmarkLocation(location.index, location).fold(
                onSuccess = { if (it.testStatus == "ok") DesktopCliResponse.success("Benchmark passed.")
                    else DesktopCliResponse.failure("BENCHMARK_FAILED") },
                onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
                    code in setOf("BUSY", "NOT_FOUND", "CONFLICT", "INVALID_ARGUMENT", "PERSISTENCE_FAILED", "BENCHMARK_FAILED")
                } ?: "BENCHMARK_FAILED") },
            )
        }
        DesktopCliCommand.SubscriptionsList -> DesktopCliResponse.success(state.subscriptions.joinToString("\n") {
            "${JsonPrimitive(it.id)}\t${JsonPrimitive(it.customName)}\t${it.cachedLocations.size}"
        })
        is DesktopCliCommand.SubscriptionShow -> {
            val target = state.subscriptions.firstOrNull { it.id == command.id }
                ?: return DesktopCliResponse.failure("NOT_FOUND")
            DesktopCliResponse.success(kotlinx.serialization.json.buildJsonObject {
                put("id", JsonPrimitive(target.id))
                put("name", JsonPrimitive(target.customName))
                put("source", JsonPrimitive(target.url))
                put("cachedLocations", JsonPrimitive(target.cachedLocations.size))
            }.toString())
        }
        is DesktopCliCommand.SubscriptionSave -> saveControlSubscription(command.source, command.name, command.id).fold(
            onSuccess = { DesktopCliResponse.success("Saved subscription: ${JsonPrimitive(it)}") },
            onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code -> code in setOf("BUSY", "NOT_FOUND", "INVALID_ARGUMENT", "PERSISTENCE_FAILED") } ?: "RUNTIME_FAILED") },
        )
        is DesktopCliCommand.SettingsShow -> {
            val values = inspectControlSettings()
            if (command.key != null && command.key !in values) DesktopCliResponse.failure("NOT_FOUND")
            else DesktopCliResponse.success(com.kardinal.vpncontrol.control.ControlProtocolCodec.encodeValues(
                if (command.key == null) values else values.filterKeys { it == command.key }))
        }
        is DesktopCliCommand.SettingsApply -> applyControlSettingsResponse(command.values, null).response
        DesktopCliCommand.SourceShow -> DesktopCliResponse.success(
            if (state.profileSourceMode == com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS) "current-locations"
            else "subscription ${JsonPrimitive(state.activeSubscriptionId)}",
        )
        is DesktopCliCommand.SourceSet -> {
            val result = command.subscriptionId?.let { activateSelection(it) }
                ?: setSourceMode(com.kardinal.vpncontrol.model.ProfileSourceMode.CURRENT_LOCATIONS)
            result.fold(onSuccess = { DesktopCliResponse.success("Source selected.") },
                onFailure = { DesktopCliResponse.failure(if (it is DesktopPersistenceException) "PERSISTENCE_FAILED" else "NOT_FOUND") })
        }
        DesktopCliCommand.LocationsList -> DesktopCliResponse.success(visibleDesktopLocations().mapIndexed { index, record ->
            "${index + 1}\t${JsonPrimitive(record.name)}"
        }.joinToString("\n"))
        is DesktopCliCommand.LocationShow -> resolveCliLocation(command.target).fold(
            onSuccess = { DesktopCliResponse.success(LocationConfigs.prettyStoredLocation(it.rawLink)) },
            onFailure = { DesktopCliResponse.failure(it.message ?: "NOT_FOUND") },
        )
        is DesktopCliCommand.LocationSave -> {
            if (command.configurationId != null) return saveControlLocation(command, null).response
            val target = command.target?.let { resolveCliLocation(it) }
            if (target?.isFailure == true) return DesktopCliResponse.failure(target.exceptionOrNull()?.message ?: "NOT_FOUND")
            val record = target?.getOrNull()
            saveLocation(command.content, record?.index, record?.rawLink).fold(
                onSuccess = { DesktopCliResponse.success("Saved location: ${JsonPrimitive(it.name)}") },
                onFailure = { error -> DesktopCliResponse.failure(when (error) {
                    is DesktopPersistenceException -> "PERSISTENCE_FAILED"
                    is IllegalStateException -> error.message?.takeIf { it == "BUSY" || it == "CONFLICT" } ?: "RUNTIME_FAILED"
                    else -> "INVALID_ARGUMENT"
                }) },
            )
        }
    }
}

internal fun DesktopAppService.controlUpdateStatus(): String = kotlinx.serialization.json.buildJsonObject {
    val checked = checkedControlUpdate()
    put("phase", JsonPrimitive(if (state.appUpdate.phase == com.kardinal.vpncontrol.AppUpdatePhase.IDLE && checked?.asset != null)
        "available" else state.appUpdate.phase.name.lowercase(java.util.Locale.ROOT)))
    put("checked", JsonPrimitive(checked != null))
    put("available", JsonPrimitive(checked?.updateAvailable))
    put("compatible", JsonPrimitive(checked?.let { !it.updateAvailable || it.asset != null }))
    put("availableVersion", JsonPrimitive(checked?.asset?.displayVersion))
    put("downloadedBytes", JsonPrimitive(state.appUpdate.downloadedBytes))
    put("totalBytes", JsonPrimitive(checked?.asset?.sizeBytes))
}.toString()

private fun Result<Unit>.toRoutingResponse(warnDesktopPackages: Boolean = false): DesktopCliResponse = fold(
    onSuccess = { DesktopCliResponse.success("Routing saved." + if (warnDesktopPackages)
        " Warning: Android package assignments are retained but unsupported on desktop." else "") },
    onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
        code in setOf("BUSY", "INVALID_ARGUMENT", "PERSISTENCE_FAILED")
    } ?: "RUNTIME_FAILED") },
)

private fun Result<Unit>.toDeleteResponse(): DesktopCliResponse = fold(
    onSuccess = { DesktopCliResponse.success("Deleted.") },
    onFailure = { DesktopCliResponse.failure(it.message?.takeIf { code ->
        code in setOf("BUSY", "NOT_FOUND", "READ_ONLY", "PERSISTENCE_FAILED")
    } ?: "RUNTIME_FAILED") },
)

private fun DesktopAppService.resolveCliLocation(target: String): Result<DesktopLocationRecord> =
    when (val found = ControlLocationSelection.resolve(target, visibleDesktopLocations(), DesktopLocationRecord::name)) {
        is ControlLocationResolution.Found -> Result.success(found.location)
        is ControlLocationResolution.Rejected -> Result.failure(IllegalArgumentException(found.code.wireName))
    }

private fun DesktopAppService.cliStatus(): DesktopCliResponse {
    val mode = (activeDesktopMode() ?: state.appMode).cliLabel()
    val stateLabel = if (state.isVpnRunning) "on" else "off"
    val selected = selectedDesktopLocation()?.name?.takeIf(String::isNotBlank)
    val suffix = selected?.let { "; selected: $it" }.orEmpty()
    val active = activeDesktopLocation()?.name?.let { "; active: ${JsonPrimitive(it)}" }.orEmpty()
    val pending = if (hasPendingRuntimeChanges()) "; pending restart; configured mode: ${state.appMode.cliLabel()}" else ""
    return DesktopCliResponse.success("$mode is $stateLabel$suffix$active$pending")
}

private suspend fun DesktopAppService.cliTurnOn(): DesktopCliResponse {
    if (state.isVpnRunning) {
        return cliStatus()
    }
    val result = startSelectedLocationProxy()
    return if (result.isSuccess) {
        DesktopCliResponse.success("${state.appMode.cliLabel()} started: ${selectedDesktopLocation()?.name.orEmpty()}")
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to start ${state.appMode.cliLabel()}.")
    }
}

private suspend fun DesktopAppService.cliTurnOff(): DesktopCliResponse {
    val mode = activeDesktopMode() ?: state.appMode
    val result = stopDesktopProxy()
    return if (result.isSuccess) {
        DesktopCliResponse.success("${mode.cliLabel()} stopped.")
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to stop ${mode.cliLabel()}.")
    }
}

private suspend fun DesktopAppService.cliFindBest(): DesktopCliResponse {
    val result = findBestLocation()
    return if (result.isSuccess) {
        val selectedLocation = selectedDesktopLocation()
        val target = selectedLocation?.name?.takeIf(String::isNotBlank)
        DesktopCliResponse.success(
            if (target == null) {
                "Best location selected."
            } else {
                "Best location selected: $target"
            },
        )
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to find the best location.")
    }
}

private fun DesktopAppService.cliSelect(target: String): DesktopCliResponse {
    val result = applyCliLocationSelection(target)
    return result.fold(
        onSuccess = { location ->
            DesktopCliResponse.success("Selected location: ${location.name}")
        },
        onFailure = { error ->
            DesktopCliResponse.failure(error.message ?: "Failed to select location.")
        },
    )
}

private fun AppMode.cliLabel(): String {
    return when (this) {
        AppMode.VPN -> "VPN"
        AppMode.PROXY_ONLY -> "Proxy"
    }
}
