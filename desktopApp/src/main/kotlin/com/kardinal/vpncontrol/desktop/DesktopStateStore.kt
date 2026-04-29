@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.data.RoutingRuleSetCodec
import com.kardinal.vpncontrol.data.StatsCodec
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.normalizeSubscriptionRefreshCustomHours
import com.kardinal.vpncontrol.shared.storageapi.PersistedStateStore
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.io.IOException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.TRUNCATE_EXISTING
import java.nio.file.StandardOpenOption.WRITE
import java.time.Instant
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

data class DesktopLocationRecord(
    val index: Int,
    val sourceUrl: String,
    val rawLink: String,
    val name: String,
    val server: String,
    val details: String,
    val benchmarkDetail: String,
    val isValid: Boolean,
    val isSelected: Boolean = false,
)

data class DesktopWorkspace(
    val persistedState: PersistedState,
    val locations: List<DesktopLocationRecord>,
    val resumeConnectionOnLaunch: Boolean = persistedState.isVpnRunning,
)

class DesktopStateStore(
    private val baseDir: Path,
) : PersistedStateStore, RuntimeConfigStore {
    private val workspaceFile = baseDir.resolve("workspace.json")
    private val workspaceRecoveryFile = baseDir.resolve("workspace-recovery.json")
    private val workspaceWriteErrorFile = baseDir.resolve("workspace-write-error.log")
    private val runtimeConfigFile = baseDir.resolve("runtime-config.json")
    private val stateFlow = MutableStateFlow(PersistedState())

    override val state: Flow<PersistedState> = stateFlow.asStateFlow()

    override suspend fun snapshot(): PersistedState = stateFlow.value

    fun runtimeDirectory(): Path = baseDir.resolve("runtime")

    fun validationDirectory(): Path = baseDir.resolve("validation")

    fun loadWorkspace(defaultWorkspace: DesktopWorkspace): DesktopWorkspace {
        val loadedWorkspace = loadStoredWorkspace(defaultWorkspace)
        val workspace = loadedWorkspace.migrateLegacyDesktopDefaults()
        if (workspace != loadedWorkspace) {
            writeWorkspace(workspace)
        }
        stateFlow.value = workspace.persistedState
        return workspace
    }

    fun writeWorkspace(workspace: DesktopWorkspace) {
        runCatching {
            Files.createDirectories(baseDir)
            writeWorkspaceAtomically(
                json.encodeToString(JsonObject.serializer(), encodeWorkspace(workspace)),
            )
            stateFlow.value = workspace.persistedState
        }.onFailure { error ->
            logWorkspaceWriteError(error)
        }
    }

    private fun loadStoredWorkspace(defaultWorkspace: DesktopWorkspace): DesktopWorkspace {
        val workspace = listOf(workspaceFile, workspaceRecoveryFile)
            .filter(Files::exists)
            .sortedByDescending { runCatching { Files.getLastModifiedTime(it).toMillis() }.getOrDefault(0L) }
            .firstNotNullOfOrNull { file ->
                runCatching { decodeWorkspace(Files.readString(file)) }.getOrNull()
            }
        if (workspace != null) {
            return workspace
        }
        writeWorkspace(defaultWorkspace)
        return defaultWorkspace
    }

    private fun writeWorkspaceAtomically(content: String) {
        var primaryError: IOException? = null
        repeat(WORKSPACE_WRITE_ATTEMPTS) { attempt ->
            try {
                writeWorkspaceFile(workspaceFile, content)
                runCatching { Files.deleteIfExists(workspaceRecoveryFile) }
                return
            } catch (error: IOException) {
                primaryError = error
                if (attempt < WORKSPACE_WRITE_ATTEMPTS - 1) {
                    Thread.sleep(WORKSPACE_WRITE_RETRY_DELAY_MILLIS)
                }
            }
        }
        try {
            writeWorkspaceFile(workspaceRecoveryFile, content)
        } catch (recoveryError: IOException) {
            primaryError?.addSuppressed(recoveryError)
            throw primaryError ?: recoveryError
        }
    }

    private fun writeWorkspaceFile(targetFile: Path, content: String) {
        val tempFile = Files.createTempFile(baseDir, "workspace-", ".tmp")
        try {
            Files.writeString(tempFile, content)
            try {
                Files.move(tempFile, targetFile, REPLACE_EXISTING, ATOMIC_MOVE)
            } catch (_: AtomicMoveNotSupportedException) {
                Files.move(tempFile, targetFile, REPLACE_EXISTING)
            } catch (_: IOException) {
                Files.writeString(targetFile, content, CREATE, TRUNCATE_EXISTING, WRITE)
            }
        } finally {
            Files.deleteIfExists(tempFile)
        }
    }

    private fun logWorkspaceWriteError(error: Throwable) {
        runCatching {
            Files.createDirectories(baseDir)
            Files.writeString(
                workspaceWriteErrorFile,
                buildString {
                    append(Instant.now())
                    append(' ')
                    append(error::class.qualifiedName ?: error::class.simpleName ?: "Throwable")
                    append(": ")
                    append(error.message.orEmpty())
                    appendLine()
                    appendLine(error.stackTraceToString())
                },
                CREATE,
                APPEND,
            )
        }
    }

    override suspend fun readRuntimeConfig(): String? {
        return runCatching {
            if (Files.exists(runtimeConfigFile)) {
                Files.readString(runtimeConfigFile)
                    .trim()
                    .takeIf(String::isNotBlank)
            } else {
                null
            }
        }.getOrNull()
    }

    override suspend fun writeRuntimeConfig(configJson: String) {
        runCatching {
            Files.createDirectories(baseDir)
            Files.writeString(runtimeConfigFile, configJson)
        }
    }

    override suspend fun clearRuntimeConfig() {
        runCatching {
            Files.deleteIfExists(runtimeConfigFile)
        }
    }

    companion object {
        fun default(): DesktopStateStore {
            return DesktopStateStore(
                baseDir = Paths.get(
                    System.getProperty("user.home"),
                    ".vpn-control-desktop",
                ),
            )
        }

        private val json = Json {
            explicitNulls = false
            prettyPrint = true
            prettyPrintIndent = "  "
        }
        private const val WORKSPACE_WRITE_ATTEMPTS = 5
        private const val WORKSPACE_WRITE_RETRY_DELAY_MILLIS = 100L
    }

    private fun encodeWorkspace(workspace: DesktopWorkspace): JsonObject {
        return buildJsonObject {
            put("persisted_state", encodePersistedState(workspace.persistedState))
            put("resume_connection_on_launch", JsonPrimitive(workspace.resumeConnectionOnLaunch))
            put("locations", buildJsonArray {
                workspace.locations.forEach { location ->
                    add(
                        buildJsonObject {
                            put("index", JsonPrimitive(location.index))
                            put("source_url", JsonPrimitive(location.sourceUrl))
                            put("raw_link", JsonPrimitive(location.rawLink))
                            put("name", JsonPrimitive(location.name))
                            put("server", JsonPrimitive(location.server))
                            put("details", JsonPrimitive(location.details))
                            put("benchmark_detail", JsonPrimitive(location.benchmarkDetail))
                            put("is_valid", JsonPrimitive(location.isValid))
                            put("is_selected", JsonPrimitive(location.isSelected))
                        },
                    )
                }
            })
        }
    }

    private fun decodeWorkspace(raw: String): DesktopWorkspace {
        val root = json.parseToJsonElement(raw).jsonObject
        val persisted = decodePersistedState(root["persisted_state"]?.jsonObject ?: JsonObject(emptyMap()))
        val locations = root["locations"]?.jsonArray.orEmpty().mapNotNull { element ->
            val item = element as? JsonObject ?: return@mapNotNull null
            val benchmarkDetail = item.string("benchmark_detail")
            val storedIsValid = item.boolean("is_valid", default = true)
            DesktopLocationRecord(
                index = item.int("index"),
                sourceUrl = item.string("source_url"),
                rawLink = item.string("raw_link"),
                name = item.string("name"),
                server = item.string("server"),
                details = item.string("details"),
                benchmarkDetail = benchmarkDetail,
                isValid = benchmarkDetailIndicatesSelectable(benchmarkDetail, storedIsValid),
                isSelected = item.boolean("is_selected", default = false),
            )
        }
        return DesktopWorkspace(
            persistedState = persisted,
            locations = locations,
            resumeConnectionOnLaunch = root.boolean(
                key = "resume_connection_on_launch",
                default = persisted.isVpnRunning,
            ),
        )
    }

    private fun encodePersistedState(state: PersistedState): JsonObject {
        return buildJsonObject {
            put("app_language", JsonPrimitive(state.appLanguage.name))
            put("profile_url", JsonPrimitive(state.profileUrl))
            put("active_subscription_id", JsonPrimitive(state.activeSubscriptionId))
            put("subscriptions", buildJsonArray {
                state.subscriptions.forEach { subscription ->
                    add(
                        buildJsonObject {
                            put("id", JsonPrimitive(subscription.id))
                            put("url", JsonPrimitive(subscription.url))
                            put("custom_name", JsonPrimitive(subscription.customName))
                            put("cached_locations", encodeStringArray(subscription.cachedLocations))
                            put("last_refreshed_at_epoch_millis", JsonPrimitive(subscription.lastRefreshedAtEpochMillis))
                            put("last_refresh_status", JsonPrimitive(subscription.lastRefreshStatus))
                        },
                    )
                }
            })
            put("profile_history", encodeStringArray(state.profileHistory))
            put("profile_history_names", encodeStringMap(state.profileHistoryNames))
            put("profile_source_mode", JsonPrimitive(state.profileSourceMode.name))
            put("app_mode", JsonPrimitive(state.appMode.name))
            put("subscription_refresh_policy", JsonPrimitive(state.subscriptionRefreshPolicy.name))
            put("find_best_after_subscription_refresh", JsonPrimitive(state.findBestAfterSubscriptionRefresh))
            put(
                "subscription_refresh_custom_hours",
                JsonPrimitive(normalizeSubscriptionRefreshCustomHours(state.subscriptionRefreshCustomHours)),
            )
            put(
                "validation_settings",
                buildJsonObject {
                    put("primary_url", JsonPrimitive(state.validationSettings.primaryUrl))
                    put("secondary_url", JsonPrimitive(state.validationSettings.secondaryUrl))
                    put("batch_size", JsonPrimitive(state.validationSettings.batchSize))
                    put("retry_count", JsonPrimitive(state.validationSettings.retryCount))
                },
            )
            put("saved_locations", encodeStringArray(state.savedLocations))
            put("current_locations", encodeStringArray(state.currentLocations))
            put("location_benchmark_details", encodeStringMap(state.locationBenchmarkDetails))
            put("custom_dns", JsonPrimitive(state.customDns))
            put("use_custom_dns", JsonPrimitive(state.useCustomDns))
            put(
                "routing_rules",
                buildJsonObject {
                    put("ignore_rules", JsonPrimitive(state.routingRules.ignoreRules))
                    put("proxy_packages", encodeStringArray(state.routingRules.proxyPackages))
                    put("bypass_packages", encodeStringArray(state.routingRules.bypassPackages))
                    put("national_domain_suffixes", encodeStringArray(state.routingRules.nationalDomainSuffixes))
                    put("direct_domain_suffixes", encodeStringArray(state.routingRules.directDomainSuffixes))
                    put("rule_sets_json", JsonPrimitive(""))
                },
            )
            put("selected_profile_name", JsonPrimitive(state.selectedProfileName))
            put("selected_profile_server", JsonPrimitive(state.selectedProfileServer))
            put("selected_profile_raw_link", JsonPrimitive(state.selectedProfileRawLink))
            put("selected_profile_json", JsonPrimitive(state.selectedProfileJson))
            put("selected_profile_source_url", JsonPrimitive(state.selectedProfileSourceUrl))
            put("last_benchmark_summary", JsonPrimitive(state.lastBenchmarkSummary))
            put("runtime_config_json", JsonPrimitive(state.runtimeConfigJson))
            put("status_message", JsonPrimitive(state.statusMessage))
            put("is_vpn_running", JsonPrimitive(state.isVpnRunning))
            put("session_stats_enabled", JsonPrimitive(state.sessionStatsEnabled))
            put("live_traffic_stats_enabled", JsonPrimitive(state.liveTrafficStatsEnabled))
            put("profile_totals_enabled", JsonPrimitive(state.profileTotalsEnabled))
            put("latency_history_enabled", JsonPrimitive(state.latencyHistoryEnabled))
            put("connection_log_enabled", JsonPrimitive(state.connectionLogEnabled))
            put("connection_test_tools_enabled", JsonPrimitive(state.connectionTestToolsEnabled))
            put("session_started_at_epoch_millis", JsonPrimitive(state.sessionStartedAtEpochMillis))
            put("session_stopped_at_epoch_millis", JsonPrimitive(state.sessionStoppedAtEpochMillis))
            put("session_start_rx_bytes", JsonPrimitive(state.sessionStartRxBytes))
            put("session_start_tx_bytes", JsonPrimitive(state.sessionStartTxBytes))
            put("successful_starts", JsonPrimitive(state.successfulStarts))
            put("successful_stops", JsonPrimitive(state.successfulStops))
            put("profile_traffic_totals_json", JsonPrimitive(StatsCodec.encodeProfileTrafficTotals(state.profileTrafficTotals)))
            put("latency_history_json", JsonPrimitive(StatsCodec.encodeLatencyHistory(state.latencyHistory)))
            put("connection_log_json", JsonPrimitive(StatsCodec.encodeConnectionLog(state.connectionLog)))
        }
    }

    private fun decodePersistedState(root: JsonObject): PersistedState {
        val validation = root["validation_settings"]?.jsonObject ?: JsonObject(emptyMap())
        val routing = root["routing_rules"]?.jsonObject ?: JsonObject(emptyMap())
        return PersistedState(
            appLanguage = root.enum(
                key = "app_language",
                default = AppLanguage.SYSTEM,
            ),
            profileUrl = root.string("profile_url"),
            activeSubscriptionId = root.string("active_subscription_id"),
            subscriptions = root["subscriptions"]?.jsonArray.orEmpty().mapNotNull { element ->
                val item = element as? JsonObject ?: return@mapNotNull null
                SubscriptionSource(
                    id = item.string("id"),
                    url = item.string("url"),
                    customName = item.string("custom_name"),
                    cachedLocations = item.stringList("cached_locations"),
                    lastRefreshedAtEpochMillis = item.long("last_refreshed_at_epoch_millis"),
                    lastRefreshStatus = item.string("last_refresh_status"),
                )
            },
            profileHistory = root.stringList("profile_history"),
            profileHistoryNames = root.stringMap("profile_history_names"),
            profileSourceMode = root.enum(
                key = "profile_source_mode",
                default = ProfileSourceMode.SUBSCRIPTION,
            ),
            appMode = root.enum(
                key = "app_mode",
                default = defaultDesktopAppMode(),
            ),
            subscriptionRefreshPolicy = root.enum(
                key = "subscription_refresh_policy",
                default = SubscriptionRefreshPolicy.OFF,
            ),
            findBestAfterSubscriptionRefresh = root.boolean(
                key = "find_best_after_subscription_refresh",
                default = true,
            ),
            subscriptionRefreshCustomHours = root.double(
                key = "subscription_refresh_custom_hours",
                default = 3.0,
            ).let(::normalizeSubscriptionRefreshCustomHours),
            validationSettings = BenchmarkValidationSettings(
                primaryUrl = validation.string("primary_url"),
                secondaryUrl = validation.string("secondary_url"),
                batchSize = validation.int("batch_size", default = BenchmarkValidationSettings.DEFAULT_BATCH_SIZE),
                retryCount = validation.int("retry_count", default = BenchmarkValidationSettings.DEFAULT_RETRY_COUNT),
            ).normalized(),
            savedLocations = root.stringList("saved_locations"),
            currentLocations = root.stringList("current_locations"),
            locationBenchmarkDetails = root.stringMap("location_benchmark_details"),
            customDns = root.string("custom_dns"),
            useCustomDns = root.boolean("use_custom_dns"),
            routingRules = RoutingRules(
                ignoreRules = routing.boolean("ignore_rules"),
                proxyPackages = routing.stringList("proxy_packages"),
                bypassPackages = routing.stringList("bypass_packages"),
                nationalDomainSuffixes = routing.stringList("national_domain_suffixes"),
                directDomainSuffixes = routing.stringList("direct_domain_suffixes"),
                ruleSets = emptyList(),
            ),
            selectedProfileName = root.string("selected_profile_name"),
            selectedProfileServer = root.string("selected_profile_server"),
            selectedProfileRawLink = root.string("selected_profile_raw_link"),
            selectedProfileJson = root.string("selected_profile_json"),
            selectedProfileSourceUrl = root.string("selected_profile_source_url"),
            lastBenchmarkSummary = root.string("last_benchmark_summary"),
            runtimeConfigJson = root.string("runtime_config_json"),
            statusMessage = root.string("status_message").ifBlank { "Idle" },
            isVpnRunning = root.boolean("is_vpn_running"),
            sessionStatsEnabled = root.boolean("session_stats_enabled"),
            liveTrafficStatsEnabled = root.boolean("live_traffic_stats_enabled"),
            profileTotalsEnabled = root.boolean("profile_totals_enabled"),
            latencyHistoryEnabled = root.boolean("latency_history_enabled"),
            connectionLogEnabled = root.boolean("connection_log_enabled"),
            connectionTestToolsEnabled = root.boolean("connection_test_tools_enabled"),
            sessionStartedAtEpochMillis = root.long("session_started_at_epoch_millis"),
            sessionStoppedAtEpochMillis = root.long("session_stopped_at_epoch_millis"),
            sessionStartRxBytes = root.long("session_start_rx_bytes", default = -1L),
            sessionStartTxBytes = root.long("session_start_tx_bytes", default = -1L),
            successfulStarts = root.int("successful_starts"),
            successfulStops = root.int("successful_stops"),
            profileTrafficTotals = StatsCodec.decodeProfileTrafficTotals(root.string("profile_traffic_totals_json")),
            latencyHistory = StatsCodec.decodeLatencyHistory(root.string("latency_history_json")),
            connectionLog = StatsCodec.decodeConnectionLog(root.string("connection_log_json")),
        )
    }
}

private fun DesktopWorkspace.migrateLegacyDesktopDefaults(): DesktopWorkspace {
    val migratedState = persistedState.migrateLegacyDesktopDefaults()
    return if (migratedState == persistedState) {
        this
    } else {
        copy(persistedState = migratedState)
    }
}

private fun PersistedState.migrateLegacyDesktopDefaults(): PersistedState {
    val migratedMode = if (isLegacyDefaultDesktopShell() && appMode == AppMode.PROXY_ONLY) {
        AppMode.VPN
    } else {
        appMode
    }
    val migratedRules = if (routingRules.isLegacyDefaultDesktopRoutingRules()) {
        RoutingRules()
    } else {
        routingRules
    }
    val migratedStatus = if (statusMessage == "Desktop proxy shell ready") {
        "Desktop VPN shell ready"
    } else {
        statusMessage
    }
    val migratedLog = connectionLog.map { entry ->
        if (entry.message == "Proxy mode available") {
            entry.copy(message = "VPN mode available")
        } else {
            entry
        }
    }
    return copy(
        appMode = migratedMode,
        routingRules = migratedRules,
        statusMessage = migratedStatus,
        connectionLog = migratedLog,
    )
}

private fun PersistedState.isLegacyDefaultDesktopShell(): Boolean {
    return profileUrl == "https://desktop.example.net/whitelists" &&
        activeSubscriptionId == "desktop-sub-1" &&
        subscriptions.map(SubscriptionSource::id) == listOf("desktop-sub-1", "desktop-sub-2") &&
        selectedProfileRawLink == "vless://desktop-nl" &&
        statusMessage == "Desktop proxy shell ready"
}

private fun RoutingRules.isLegacyDefaultDesktopRoutingRules(): Boolean {
    return !ignoreRules &&
        proxyPackages == listOf("com.example.browser", "org.telegram.messenger") &&
        bypassPackages.isEmpty() &&
        nationalDomainSuffixes == listOf("ru", "by") &&
        directDomainSuffixes == listOf("example.com", "intranet.local") &&
        ruleSets.isEmpty()
}

private fun encodeStringArray(values: List<String>): JsonArray = buildJsonArray {
    values.forEach { value -> add(JsonPrimitive(value)) }
}

private fun encodeStringMap(values: Map<String, String>): JsonObject = buildJsonObject {
    values.forEach { (key, value) -> put(key, JsonPrimitive(value)) }
}

private fun JsonObject.string(key: String): String {
    return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
}

private fun JsonObject.int(key: String, default: Int = 0): Int {
    return this[key]?.jsonPrimitive?.intOrNull ?: default
}

private fun JsonObject.long(key: String, default: Long = 0L): Long {
    return this[key]?.jsonPrimitive?.longOrNull ?: default
}

private fun JsonObject.double(key: String, default: Double): Double {
    return this[key]?.jsonPrimitive?.doubleOrNull ?: default
}

private fun JsonObject.boolean(key: String, default: Boolean = false): Boolean {
    return this[key]?.jsonPrimitive?.booleanOrNull ?: default
}

private fun JsonObject.stringList(key: String): List<String> {
    return this[key]?.jsonArray.orEmpty().mapNotNull { item ->
        item.jsonPrimitive.contentOrNull?.takeIf(String::isNotBlank) ?: item.jsonPrimitive.contentOrNull
    }
}

private fun JsonObject.stringMap(key: String): Map<String, String> {
    return this[key]?.jsonObject?.mapValues { (_, value) ->
        value.jsonPrimitive.contentOrNull.orEmpty()
    }.orEmpty()
}

private inline fun <reified T : Enum<T>> JsonObject.enum(
    key: String,
    default: T,
): T {
    val raw = string(key)
    return enumValues<T>().firstOrNull { it.name == raw } ?: default
}
