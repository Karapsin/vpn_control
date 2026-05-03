package com.kardinal.vpncontrol.data

import android.content.Context
import android.net.TrafficStats
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS
import com.kardinal.vpncontrol.model.LatencyHistoryEntry
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.ProfileTrafficTotal
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.activeSubscriptionUrls
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.model.mergedSubscriptionLocations
import com.kardinal.vpncontrol.model.normalizeSubscriptionRefreshCustomHours
import com.kardinal.vpncontrol.model.supportsAllSubscriptionsGroup
import com.kardinal.vpncontrol.shared.storageapi.LocationUpdateResult
import com.kardinal.vpncontrol.shared.storageapi.PersistedStateStore
import com.kardinal.vpncontrol.shared.storageapi.RepositoryStateStore
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import com.kardinal.vpncontrol.shared.storageapi.SearchStateStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.io.File
import java.util.UUID

private val Context.dataStore by preferencesDataStore(name = "vpn_control")

class ProfileStorage(
    private val context: Context,
) : RepositoryStateStore, SearchStateStore {

    private object Keys {
        val profileUrl = stringPreferencesKey("profile_url")
        val profileHistory = stringPreferencesKey("profile_history")
        val profileHistoryNames = stringPreferencesKey("profile_history_names")
        val subscriptions = stringPreferencesKey("subscriptions_json")
        val subscriptionHwid = stringPreferencesKey("subscription_hwid")
        val activeSubscriptionId = stringPreferencesKey("active_subscription_id")
        val profileSourceMode = stringPreferencesKey("profile_source_mode")
        val appMode = stringPreferencesKey("app_mode")
        val appLanguage = stringPreferencesKey("app_language")
        val subscriptionRefreshPolicy = stringPreferencesKey("subscription_refresh_policy")
        val findBestAfterSubscriptionRefresh = booleanPreferencesKey("find_best_after_subscription_refresh")
        val subscriptionRefreshCustomHours = doublePreferencesKey("subscription_refresh_custom_hours_v2")
        val legacySubscriptionRefreshCustomHours = intPreferencesKey("subscription_refresh_custom_hours")
        val validationPrimaryUrl = stringPreferencesKey("validation_primary_url")
        val validationSecondaryUrl = stringPreferencesKey("validation_secondary_url")
        val validationBatchSize = intPreferencesKey("validation_batch_size")
        val validationRetryCount = intPreferencesKey("validation_retry_count")
        val legacyValidationGeneralUrl = stringPreferencesKey("validation_general_url")
        val legacyValidationChatGptUrl = stringPreferencesKey("validation_chatgpt_url")
        val currentLocations = stringPreferencesKey("current_locations")
        val savedLocations = stringPreferencesKey("saved_locations")
        val locationBenchmarkDetails = stringPreferencesKey("location_benchmark_details")
        val customDns = stringPreferencesKey("custom_dns")
        val useCustomDns = booleanPreferencesKey("use_custom_dns")
        val ignoreRules = booleanPreferencesKey("ignore_rules")
        val proxyPackages = stringPreferencesKey("proxy_packages")
        val bypassPackages = stringPreferencesKey("bypass_packages")
        val nationalDomainSuffixes = stringPreferencesKey("national_domain_suffixes")
        val directDomainSuffixes = stringPreferencesKey("direct_domain_suffixes")
        val ruleSets = stringPreferencesKey("rule_sets")
        val selectedProfileName = stringPreferencesKey("selected_profile_name")
        val selectedProfileServer = stringPreferencesKey("selected_profile_server")
        val selectedProfileRawLink = stringPreferencesKey("selected_profile_raw_link")
        val selectedProfileJson = stringPreferencesKey("selected_profile_json")
        val selectedProfileSourceUrl = stringPreferencesKey("selected_profile_source_url")
        val lastBenchmarkSummary = stringPreferencesKey("last_benchmark_summary")
        val runtimeConfigJson = stringPreferencesKey("runtime_config_json")
        val statusMessage = stringPreferencesKey("status_message")
        val isVpnRunning = booleanPreferencesKey("is_vpn_running")
        val sessionStatsEnabled = booleanPreferencesKey("session_stats_enabled")
        val liveTrafficStatsEnabled = booleanPreferencesKey("live_traffic_stats_enabled")
        val profileTotalsEnabled = booleanPreferencesKey("profile_totals_enabled")
        val latencyHistoryEnabled = booleanPreferencesKey("latency_history_enabled")
        val connectionLogEnabled = booleanPreferencesKey("connection_log_enabled")
        val connectionTestToolsEnabled = booleanPreferencesKey("connection_test_tools_enabled")
        val sessionStartedAtEpochMillis = longPreferencesKey("session_started_at_epoch_millis")
        val sessionStoppedAtEpochMillis = longPreferencesKey("session_stopped_at_epoch_millis")
        val sessionStartRxBytes = longPreferencesKey("session_start_rx_bytes")
        val sessionStartTxBytes = longPreferencesKey("session_start_tx_bytes")
        val successfulStarts = intPreferencesKey("successful_starts")
        val successfulStops = intPreferencesKey("successful_stops")
        val profileTrafficTotals = stringPreferencesKey("profile_traffic_totals")
        val latencyHistory = stringPreferencesKey("latency_history")
        val connectionLog = stringPreferencesKey("connection_log")
    }

    override val state: Flow<PersistedState> = context.dataStore.data
        .catch { exception ->
            if (exception is IOException) {
                emit(emptyPreferences())
            } else {
                throw exception
            }
        }
        .map(::mapState)

    override suspend fun ensureSubscriptionHwid(): String {
        var resolved = ""
        context.dataStore.edit { prefs ->
            val existing = prefs[Keys.subscriptionHwid]
                ?.trim()
                .orEmpty()
            resolved = existing.ifBlank { generateSubscriptionHwid() }
            prefs[Keys.subscriptionHwid] = resolved
        }
        return resolved
    }

    override suspend fun updateProfileUrl(url: String, rememberInHistory: Boolean) {
        context.dataStore.edit { prefs ->
            val trimmed = url.trim()
            val subscriptions = decodeSubscriptions(prefs).toMutableList()
            val names = decodeStringMap(prefs[Keys.profileHistoryNames])
            if (trimmed.isBlank()) {
                prefs.remove(Keys.activeSubscriptionId)
                prefs[Keys.profileUrl] = ""
            } else if (rememberInHistory) {
                val existing = subscriptions.indexOfFirst { it.url == trimmed }
                val target = if (existing >= 0) {
                    subscriptions.removeAt(existing)
                } else {
                    SubscriptionSource(
                        id = UUID.randomUUID().toString(),
                        url = trimmed,
                        customName = names[trimmed].orEmpty(),
                    )
                }
                subscriptions.add(0, target)
                prefs[Keys.activeSubscriptionId] = target.id
                prefs[Keys.profileUrl] = target.url
                prefs[Keys.subscriptions] = encodeSubscriptions(subscriptions)
                prefs[Keys.profileHistory] = encodeList(subscriptions.map { it.url })
                prefs[Keys.profileHistoryNames] = encodeStringMap(
                    subscriptions.associateNotNull { subscription ->
                        subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                    },
                )
            } else {
                prefs[Keys.profileUrl] = trimmed
            }
        }
    }

    override suspend fun deleteProfileHistoryEntry(url: String) {
        context.dataStore.edit { prefs ->
            val subscriptions = decodeSubscriptions(prefs)
                .filterNot { it.url == url }
            prefs[Keys.subscriptions] = encodeSubscriptions(subscriptions)
            prefs[Keys.profileHistory] = encodeList(subscriptions.map { it.url })
            prefs[Keys.profileHistoryNames] = encodeStringMap(
                subscriptions.associateNotNull { subscription ->
                    subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                },
            )
            val activeId = prefs[Keys.activeSubscriptionId].orEmpty()
            if (activeId == ALL_SUBSCRIPTIONS_ID && supportsAllSubscriptionsGroup(subscriptions)) {
                prefs[Keys.activeSubscriptionId] = ALL_SUBSCRIPTIONS_ID
                prefs[Keys.profileUrl] = ""
            } else if (activeId.isBlank() || subscriptions.none { it.id == activeId }) {
                val nextActive = subscriptions.firstOrNull()
                if (nextActive == null) {
                    prefs.remove(Keys.activeSubscriptionId)
                    prefs[Keys.profileUrl] = ""
                } else {
                    prefs[Keys.activeSubscriptionId] = nextActive.id
                    prefs[Keys.profileUrl] = nextActive.url
                }
            }
        }
        DiagnosticsLogger.append(context, "Profile history entry deleted")
    }

    override suspend fun updateProfileHistoryName(url: String, name: String) {
        val normalizedName = name.trim()
        context.dataStore.edit { prefs ->
            val subscriptions = decodeSubscriptions(prefs).map { subscription ->
                if (subscription.url == url) {
                    subscription.copy(customName = normalizedName)
                } else {
                    subscription
                }
            }
            prefs[Keys.subscriptions] = encodeSubscriptions(subscriptions)
            prefs[Keys.profileHistoryNames] = encodeStringMap(
                subscriptions.associateNotNull { subscription ->
                    subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                },
            )
        }
        DiagnosticsLogger.append(
            context,
            if (normalizedName.isBlank()) {
                "Profile history name cleared"
            } else {
                "Profile history name updated"
            },
        )
    }

    override suspend fun updateProfileSourceMode(mode: ProfileSourceMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.profileSourceMode] = mode.name
        }
        DiagnosticsLogger.append(context, "Profile source mode updated: $mode")
    }

    override suspend fun selectActiveSubscription(subscriptionId: String) {
        context.dataStore.edit { prefs ->
            val subscriptions = decodeSubscriptions(prefs)
            when {
                isAllSubscriptionsGroupActive(subscriptionId, subscriptions) -> {
                    prefs[Keys.activeSubscriptionId] = ALL_SUBSCRIPTIONS_ID
                    prefs[Keys.profileUrl] = ""
                }
                subscriptions.any { it.id == subscriptionId } -> {
                    val target = subscriptions.first { it.id == subscriptionId }
                    prefs[Keys.activeSubscriptionId] = target.id
                    prefs[Keys.profileUrl] = target.url
                }
                subscriptions.isEmpty() -> {
                    prefs.remove(Keys.activeSubscriptionId)
                    prefs[Keys.profileUrl] = ""
                }
                else -> {
                    val fallback = subscriptions.first()
                    prefs[Keys.activeSubscriptionId] = fallback.id
                    prefs[Keys.profileUrl] = fallback.url
                }
            }
        }
        DiagnosticsLogger.append(context, "Active subscription selected: $subscriptionId")
    }

    override suspend fun updateAppMode(mode: AppMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.appMode] = mode.name
        }
        DiagnosticsLogger.append(context, "App mode updated: $mode")
    }

    override suspend fun updateAppLanguage(language: AppLanguage) {
        context.dataStore.edit { prefs ->
            prefs[Keys.appLanguage] = language.name
        }
        DiagnosticsLogger.append(context, "App language updated: $language")
    }

    override suspend fun updateSubscriptionRefreshPolicy(
        policy: SubscriptionRefreshPolicy,
        customHours: Double,
        findBestAfterRefresh: Boolean,
    ) {
        val normalizedHours = normalizeSubscriptionRefreshCustomHours(customHours)
        context.dataStore.edit { prefs ->
            prefs[Keys.subscriptionRefreshPolicy] = policy.name
            prefs[Keys.findBestAfterSubscriptionRefresh] = findBestAfterRefresh
            prefs[Keys.subscriptionRefreshCustomHours] = normalizedHours
            prefs.remove(Keys.legacySubscriptionRefreshCustomHours)
        }
        DiagnosticsLogger.append(
            context,
            "Subscription refresh policy updated: policy=$policy autoFind=$findBestAfterRefresh customHours=$normalizedHours",
        )
    }

    override suspend fun updateValidationSettings(settings: BenchmarkValidationSettings) {
        val normalized = settings.normalized()
        context.dataStore.edit { prefs ->
            prefs[Keys.validationPrimaryUrl] = normalized.primaryUrl
            prefs[Keys.validationSecondaryUrl] = normalized.secondaryUrl
            prefs[Keys.validationBatchSize] = normalized.batchSize
            prefs[Keys.validationRetryCount] = normalized.retryCount
            prefs.remove(Keys.legacyValidationGeneralUrl)
            prefs.remove(Keys.legacyValidationChatGptUrl)
        }
        DiagnosticsLogger.append(
            context,
            "Validation settings updated: primary=${normalized.primaryUrl} secondary=${normalized.secondaryUrl} batch=${normalized.batchSize} retries=${normalized.retryCount}",
        )
    }

    override suspend fun updateCurrentLocations(rawLinks: List<String>): LocationUpdateResult {
        val normalized = normalizeStoredLocations(rawLinks)
        var result = LocationUpdateResult(
            selectedMissing = false,
        )
        context.dataStore.edit { prefs ->
            val sourceMode = prefs[Keys.profileSourceMode]
            if (sourceMode == ProfileSourceMode.SUBSCRIPTION.name) {
                val subscriptions = decodeSubscriptions(prefs).toMutableList()
                val activeId = resolveActiveSubscriptionId(prefs, subscriptions)
                val updatedSubscriptions = if (isAllSubscriptionsGroupActive(activeId, subscriptions)) {
                    subscriptions
                } else {
                    subscriptions.map { subscription ->
                        if (subscription.id == activeId) {
                            subscription.copy(
                                cachedLocations = normalized,
                                lastRefreshedAtEpochMillis = System.currentTimeMillis(),
                                lastRefreshStatus = StatusMessages.locationsRefreshed(normalized.size),
                            )
                        } else {
                            subscription
                        }
                    }
                }
                prefs[Keys.subscriptions] = encodeSubscriptions(updatedSubscriptions)
                prefs[Keys.profileHistory] = encodeList(updatedSubscriptions.map { it.url })
                prefs[Keys.profileHistoryNames] = encodeStringMap(
                    updatedSubscriptions.associateNotNull { subscription ->
                        subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                    },
                )
                prefs[Keys.profileUrl] = if (isAllSubscriptionsGroupActive(activeId, updatedSubscriptions)) {
                    ""
                } else {
                    updatedSubscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()
                }
            } else {
                prefs[Keys.savedLocations] = encodeList(normalized)
                prefs[Keys.currentLocations] = encodeList(normalized)
            }
            prefs[Keys.locationBenchmarkDetails] = encodeStringMap(
                decodeStringMap(prefs[Keys.locationBenchmarkDetails]).filterKeys { it in normalized },
            )
            val selectedStored = LocationConfigs.selectedStoredReference(
                selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
            )
            val activeUrls = activeSubscriptionUrls(
                activeSubscriptionId = resolveActiveSubscriptionId(prefs, decodeSubscriptions(prefs)),
                subscriptions = decodeSubscriptions(prefs),
            )
            val selectedRelevantToCurrentList = when (sourceMode) {
                ProfileSourceMode.SUBSCRIPTION.name ->
                    prefs[Keys.selectedProfileSourceUrl].orEmpty().isNotBlank() &&
                        prefs[Keys.selectedProfileSourceUrl].orEmpty() in activeUrls
                ProfileSourceMode.CURRENT_LOCATIONS.name -> true
                else -> true
            }
            val selectedMissing =
                selectedStored.isNotBlank() &&
                    selectedRelevantToCurrentList &&
                    selectedStored !in normalized
            val shouldClearSelection = selectedMissing && (
                sourceMode == ProfileSourceMode.SUBSCRIPTION.name ||
                    !(prefs[Keys.isVpnRunning] ?: false)
                )
            if (shouldClearSelection) {
                clearStoredSelection(prefs)
            }
            result = LocationUpdateResult(
                selectedMissing = selectedMissing,
            )
        }
        DiagnosticsLogger.append(context, "Current locations updated: count=${normalized.size}")
        return result
    }

    override suspend fun updateSubscriptionCache(
        subscriptionId: String,
        rawLinks: List<String>,
        refreshStatus: String,
    ): LocationUpdateResult {
        val normalized = normalizeStoredLocations(rawLinks)
        var result = LocationUpdateResult(selectedMissing = false)
        context.dataStore.edit { prefs ->
            val subscriptions = decodeSubscriptions(prefs)
            if (subscriptions.none { it.id == subscriptionId }) {
                return@edit
            }
            val activeId = resolveActiveSubscriptionId(prefs, subscriptions)
            val isActiveSubscription = activeId == subscriptionId
            val updatedSubscriptions = subscriptions.map { subscription ->
                if (subscription.id == subscriptionId) {
                    subscription.copy(
                        cachedLocations = normalized,
                        lastRefreshedAtEpochMillis = System.currentTimeMillis(),
                        lastRefreshStatus = refreshStatus.ifBlank {
                            "Updated ${normalized.size} location" + if (normalized.size == 1) "" else "s"
                        },
                    )
                } else {
                    subscription
                }
            }
            prefs[Keys.subscriptions] = encodeSubscriptions(updatedSubscriptions)
            prefs[Keys.profileHistory] = encodeList(updatedSubscriptions.map { it.url })
            prefs[Keys.profileHistoryNames] = encodeStringMap(
                updatedSubscriptions.associateNotNull { subscription ->
                    subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                },
            )
            prefs[Keys.profileUrl] = if (isAllSubscriptionsGroupActive(activeId, updatedSubscriptions)) {
                ""
            } else {
                updatedSubscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()
            }

            if (prefs[Keys.profileSourceMode] == ProfileSourceMode.SUBSCRIPTION.name &&
                (isActiveSubscription || isAllSubscriptionsGroupActive(activeId, updatedSubscriptions))
            ) {
                val visibleLocations = if (isAllSubscriptionsGroupActive(activeId, updatedSubscriptions)) {
                    mergedSubscriptionLocations(updatedSubscriptions)
                } else {
                    normalized
                }
                prefs[Keys.locationBenchmarkDetails] = encodeStringMap(
                    decodeStringMap(prefs[Keys.locationBenchmarkDetails]).filterKeys { it in visibleLocations },
                )
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                    selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
                )
                val activeUrls = activeSubscriptionUrls(
                    activeSubscriptionId = activeId,
                    subscriptions = updatedSubscriptions,
                )
                val selectedRelevantToCurrentList = if (isAllSubscriptionsGroupActive(activeId, updatedSubscriptions)) {
                    selectedStored.isNotBlank()
                } else {
                    prefs[Keys.selectedProfileSourceUrl].orEmpty().isNotBlank() &&
                        prefs[Keys.selectedProfileSourceUrl].orEmpty() in activeUrls
                }
                val selectedMissing =
                    selectedStored.isNotBlank() &&
                        selectedRelevantToCurrentList &&
                        selectedStored !in visibleLocations
                if (selectedMissing) {
                    clearStoredSelection(prefs)
                }
                result = LocationUpdateResult(selectedMissing = selectedMissing)
            }
        }
        DiagnosticsLogger.append(
            context,
            "Subscription cache updated: subscriptionId=$subscriptionId count=${normalized.size}",
        )
        return result
    }

    override suspend fun updateSubscriptionRefreshStatus(
        subscriptionId: String,
        status: String,
    ) {
        context.dataStore.edit { prefs ->
            val subscriptions = decodeSubscriptions(prefs)
            if (subscriptions.none { it.id == subscriptionId }) {
                return@edit
            }
            val updatedSubscriptions = subscriptions.map { subscription ->
                if (subscription.id == subscriptionId) {
                    subscription.copy(lastRefreshStatus = status.trim())
                } else {
                    subscription
                }
            }
            prefs[Keys.subscriptions] = encodeSubscriptions(updatedSubscriptions)
            prefs[Keys.profileHistory] = encodeList(updatedSubscriptions.map { it.url })
            prefs[Keys.profileHistoryNames] = encodeStringMap(
                updatedSubscriptions.associateNotNull { subscription ->
                    subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
                },
            )
        }
        DiagnosticsLogger.append(context, "Subscription refresh status updated: subscriptionId=$subscriptionId")
    }

    override suspend fun updateLocationBenchmarkDetails(details: Map<String, String>) {
        context.dataStore.edit { prefs ->
            prefs[Keys.locationBenchmarkDetails] = encodeStringMap(details)
        }
        DiagnosticsLogger.append(context, "Location benchmark details updated: count=${details.size}")
    }

    override suspend fun updateDns(dns: String, enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.customDns] = dns
            prefs[Keys.useCustomDns] = enabled
        }
        DiagnosticsLogger.append(context, "Custom DNS updated: enabled=$enabled value=$dns")
    }

    override suspend fun updateRoutingRules(rules: RoutingRules) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ignoreRules] = rules.ignoreRules
            prefs[Keys.proxyPackages] = encodeList(sanitizePackageNames(rules.proxyPackages))
            prefs[Keys.bypassPackages] = encodeList(emptyList())
            prefs[Keys.nationalDomainSuffixes] = encodeList(rules.nationalDomainSuffixes)
            prefs[Keys.directDomainSuffixes] = encodeList(rules.directDomainSuffixes)
            prefs[Keys.ruleSets] = ""
        }
        DiagnosticsLogger.append(
            context,
            "Routing rules updated: ignore=${rules.ignoreRules} vpn_apps=${rules.proxyPackages.size} direct=0 " +
                "national=${rules.nationalDomainSuffixes.size} domains=${rules.directDomainSuffixes.size}",
        )
    }

    override suspend fun updateSelection(
        profile: ProxyProfile,
        summary: String,
        runtimeConfigJson: String,
        sourceUrl: String,
    ) {
        context.dataStore.edit { prefs ->
            prefs[Keys.selectedProfileName] = profile.remarks
            prefs[Keys.selectedProfileServer] = profile.server
            prefs[Keys.selectedProfileRawLink] = profile.rawLink
            prefs[Keys.selectedProfileJson] = LocationConfigs.encodeStoredLocation(profile)
            prefs[Keys.selectedProfileSourceUrl] = sourceUrl
            prefs[Keys.lastBenchmarkSummary] = summary
            prefs[Keys.runtimeConfigJson] = runtimeConfigJson
        }
        DiagnosticsLogger.append(
            context,
            "Selected profile updated: name=${profile.remarks} server=${profile.server} summary=$summary",
        )
    }

    override suspend fun updateStatus(message: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.statusMessage] = message
            val updated = (
                StatsCodec.decodeConnectionLog(prefs[Keys.connectionLog]) +
                    ConnectionLogEntry(
                        id = UUID.randomUUID().toString(),
                        message = message,
                        createdAtEpochMillis = System.currentTimeMillis(),
                    )
                ).takeLast(MAX_CONNECTION_LOG_ITEMS)
            prefs[Keys.connectionLog] = StatsCodec.encodeConnectionLog(updated)
        }
        DiagnosticsLogger.append(context, "Status: $message")
    }

    override suspend fun updateSessionStatsEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.sessionStatsEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Session stats UI enabled: $enabled")
    }

    override suspend fun updateLiveTrafficStatsEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.liveTrafficStatsEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Live traffic stats UI enabled: $enabled")
    }

    override suspend fun updateProfileTotalsEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.profileTotalsEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Profile totals UI enabled: $enabled")
    }

    override suspend fun updateLatencyHistoryEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.latencyHistoryEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Latency history UI enabled: $enabled")
    }

    override suspend fun updateConnectionLogEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.connectionLogEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Connection log UI enabled: $enabled")
    }

    override suspend fun updateConnectionTestToolsEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.connectionTestToolsEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Connection test tools UI enabled: $enabled")
    }

    override suspend fun appendLatencyHistory(entry: LatencyHistoryEntry) {
        context.dataStore.edit { prefs ->
            if (!(prefs[Keys.latencyHistoryEnabled] ?: false)) return@edit
            val updated = (StatsCodec.decodeLatencyHistory(prefs[Keys.latencyHistory]) + entry)
                .takeLast(MAX_LATENCY_HISTORY_ITEMS)
            prefs[Keys.latencyHistory] = StatsCodec.encodeLatencyHistory(updated)
        }
    }

    override suspend fun clearSelection() {
        context.dataStore.edit { prefs ->
            clearStoredSelection(prefs)
        }
        DiagnosticsLogger.append(context, "Stored selection cleared")
    }

    suspend fun restoreSelection(
        state: PersistedState,
        restoreRuntimeArtifacts: Boolean = true,
    ) {
        restoreSelection(state, restoreRuntimeArtifacts, null)
    }

    override suspend fun restoreSelection(
        state: PersistedState,
        restoreRuntimeArtifacts: Boolean,
        sourceUrlOverride: String?,
    ) {
        context.dataStore.edit { prefs ->
            prefs[Keys.selectedProfileName] = state.selectedProfileName
            prefs[Keys.selectedProfileServer] = state.selectedProfileServer
            prefs[Keys.selectedProfileRawLink] = state.selectedProfileRawLink
            prefs[Keys.selectedProfileJson] = state.selectedProfileJson
            prefs[Keys.selectedProfileSourceUrl] = sourceUrlOverride ?: state.selectedProfileSourceUrl
            prefs[Keys.lastBenchmarkSummary] = state.lastBenchmarkSummary
            prefs[Keys.runtimeConfigJson] = state.runtimeConfigJson
        }
        if (restoreRuntimeArtifacts) {
            runCatching {
                if (state.runtimeConfigJson.isBlank()) {
                    runtimeConfigFile().delete()
                } else {
                    runtimeConfigFile().apply {
                        parentFile?.mkdirs()
                        writeText(state.runtimeConfigJson)
                    }
                }
            }
            runCatching {
                if (state.selectedProfileRawLink.isBlank()) {
                    lastProfileFile().delete()
                } else {
                    lastProfileFile().writeText(state.selectedProfileRawLink)
                }
            }
        }
        DiagnosticsLogger.append(context, "Stored selection restored")
    }

    suspend fun updateVpnRunning(running: Boolean) {
        context.dataStore.edit { prefs ->
            val wasRunning = prefs[Keys.isVpnRunning] ?: false
            prefs[Keys.isVpnRunning] = running
            if (!wasRunning && running) {
                val (rxBytes, txBytes) = currentUidTrafficBytes()
                prefs[Keys.sessionStartedAtEpochMillis] = System.currentTimeMillis()
                prefs[Keys.sessionStartRxBytes] = rxBytes
                prefs[Keys.sessionStartTxBytes] = txBytes
                prefs[Keys.successfulStarts] = (prefs[Keys.successfulStarts] ?: 0) + 1
            } else if (wasRunning && !running) {
                prefs[Keys.sessionStoppedAtEpochMillis] = System.currentTimeMillis()
                prefs[Keys.successfulStops] = (prefs[Keys.successfulStops] ?: 0) + 1
                recordProfileTrafficTotals(prefs)
            }
            if (!running) {
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                    selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
                )
                val profileSourceMode = prefs[Keys.profileSourceMode]
                val subscriptions = decodeSubscriptions(prefs)
                val activeSubscriptionId = resolveActiveSubscriptionId(prefs, subscriptions)
                val activeSubscriptionLocations = if (isAllSubscriptionsGroupActive(activeSubscriptionId, subscriptions)) {
                    mergedSubscriptionLocations(subscriptions)
                } else {
                    subscriptions
                        .firstOrNull { it.id == activeSubscriptionId }
                        ?.cachedLocations
                        .orEmpty()
                }
                val activeUrls = activeSubscriptionUrls(activeSubscriptionId, subscriptions)
                val savedLocations = decodeList(prefs[Keys.savedLocations]).ifEmpty {
                    decodeList(prefs[Keys.currentLocations])
                }
                val shouldClearSelection = when (profileSourceMode) {
                    ProfileSourceMode.CURRENT_LOCATIONS.name ->
                        selectedStored.isNotBlank() && selectedStored !in savedLocations
                    ProfileSourceMode.SUBSCRIPTION.name -> {
                        val selectedSource = prefs[Keys.selectedProfileSourceUrl].orEmpty()
                        if (isAllSubscriptionsGroupActive(activeSubscriptionId, subscriptions)) {
                            selectedStored.isNotBlank() && selectedStored !in activeSubscriptionLocations
                        } else {
                            selectedSource.isBlank() ||
                                selectedSource !in activeUrls ||
                                (selectedStored.isNotBlank() &&
                                    selectedSource in activeUrls &&
                                    selectedStored !in activeSubscriptionLocations)
                        }
                    }
                    else -> false
                }
                if (shouldClearSelection) {
                    clearStoredSelection(prefs)
                }
            }
        }
        DiagnosticsLogger.append(context, "VPN running flag: $running")
    }

    override suspend fun snapshot(): PersistedState = state.first()

    override suspend fun readLastSelectedProfile(): String? {
        return lastProfileFile()
            .takeIf(File::exists)
            ?.runCatching { readText() }
            ?.getOrNull()
            ?.trim()
            ?.takeIf { it.isNotBlank() }
    }

    override suspend fun readRuntimeConfig(): String? {
        val fromState = snapshot().runtimeConfigJson.takeIf { it.isNotBlank() }
        if (fromState != null) return fromState
        return runtimeConfigFile()
            .takeIf(File::exists)
            ?.runCatching { readText() }
            ?.getOrNull()
            ?.takeIf { it.isNotBlank() }
    }

    override suspend fun writeRuntimeConfig(configJson: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.runtimeConfigJson] = configJson
        }
        runCatching {
            if (configJson.isBlank()) {
                runtimeConfigFile().delete()
            } else {
                runtimeConfigFile().writeText(configJson)
            }
        }
    }

    override suspend fun clearRuntimeConfig() {
        context.dataStore.edit { prefs ->
            prefs.remove(Keys.runtimeConfigJson)
        }
        runCatching { runtimeConfigFile().delete() }
    }

    fun runtimeConfigFile(): File = RuntimeFiles.runtimeConfigFile(context)

    fun lastProfileFile(): File = RuntimeFiles.selectedProfileFile(context)

    private fun mapState(preferences: Preferences): PersistedState {
        val rawPreferences = preferences.asMap()
        val refreshSettings = decodeSubscriptionRefreshSettings(
            rawPolicy = preferences[Keys.subscriptionRefreshPolicy],
            customHours = preferences[Keys.subscriptionRefreshCustomHours]
                ?: preferences[Keys.legacySubscriptionRefreshCustomHours]?.toDouble()
                ?: DEFAULT_SUBSCRIPTION_REFRESH_CUSTOM_HOURS,
        )
        val findBestAfterRefresh = preferences[Keys.findBestAfterSubscriptionRefresh] ?: true
        val profileSourceMode = preferences[Keys.profileSourceMode]
            ?.let { raw -> runCatching { ProfileSourceMode.valueOf(raw) }.getOrNull() }
            ?: ProfileSourceMode.SUBSCRIPTION
        val appMode = preferences[Keys.appMode]
            ?.let { raw -> runCatching { AppMode.valueOf(raw) }.getOrNull() }
            ?: AppMode.VPN
        val subscriptions = decodeSubscriptions(preferences)
        val activeSubscriptionId = resolveActiveSubscriptionId(preferences, subscriptions)
        val activeSubscription = subscriptions.firstOrNull { it.id == activeSubscriptionId }
        val savedLocations = decodeList(preferences[Keys.savedLocations]).ifEmpty {
            val legacyCurrentLocations = decodeList(preferences[Keys.currentLocations])
            if (profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) {
                legacyCurrentLocations
            } else {
                emptyList()
            }
        }
        val currentLocations = when (profileSourceMode) {
            ProfileSourceMode.SUBSCRIPTION -> if (isAllSubscriptionsGroupActive(activeSubscriptionId, subscriptions)) {
                mergedSubscriptionLocations(subscriptions)
            } else {
                activeSubscription?.cachedLocations.orEmpty()
            }
            ProfileSourceMode.CURRENT_LOCATIONS -> savedLocations
        }
        val historyNames = subscriptions.associateNotNull { subscription ->
            subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
        }
        return PersistedState(
            appLanguage = AppLanguage.fromStoredName(preferences[Keys.appLanguage]),
            subscriptionHwid = preferences[Keys.subscriptionHwid].orEmpty(),
            profileUrl = if (isAllSubscriptionsGroupActive(activeSubscriptionId, subscriptions)) {
                ""
            } else {
                activeSubscription?.url.orEmpty()
            },
            activeSubscriptionId = activeSubscriptionId,
            subscriptions = subscriptions,
            profileHistory = subscriptions.map { it.url },
            profileHistoryNames = historyNames,
            profileSourceMode = profileSourceMode,
            appMode = appMode,
            subscriptionRefreshPolicy = refreshSettings.first,
            findBestAfterSubscriptionRefresh = findBestAfterRefresh,
            subscriptionRefreshCustomHours = refreshSettings.second,
            validationSettings = BenchmarkValidationSettings(
                primaryUrl = preferences[Keys.validationPrimaryUrl]
                    ?: preferences[Keys.legacyValidationGeneralUrl]
                    ?: BenchmarkValidationSettings.DEFAULT_PRIMARY_URL,
                secondaryUrl = preferences[Keys.validationSecondaryUrl]
                    ?: preferences[Keys.legacyValidationChatGptUrl]
                    ?: BenchmarkValidationSettings.DEFAULT_SECONDARY_URL,
                batchSize = preferences[Keys.validationBatchSize]
                    ?: BenchmarkValidationSettings.DEFAULT_BATCH_SIZE,
                retryCount = preferences[Keys.validationRetryCount]
                    ?: BenchmarkValidationSettings.DEFAULT_RETRY_COUNT,
            ).normalized(),
            savedLocations = savedLocations,
            currentLocations = currentLocations,
            locationBenchmarkDetails = decodeStringMap(preferences[Keys.locationBenchmarkDetails]),
            customDns = preferences[Keys.customDns].orEmpty(),
            useCustomDns = preferences[Keys.useCustomDns] ?: false,
            routingRules = RoutingRules(
                ignoreRules = preferences[Keys.ignoreRules] ?: false,
                proxyPackages = sanitizePackageNames(
                    decodeList(preferences[Keys.proxyPackages]),
                ),
                bypassPackages = emptyList(),
                nationalDomainSuffixes = if (rawPreferences.containsKey(Keys.nationalDomainSuffixes)) {
                    RoutingRules.parseNationalDomainSuffixes(
                        encodeList(decodeList(preferences[Keys.nationalDomainSuffixes])),
                    )
                } else {
                    RoutingRules.DEFAULT_NATIONAL_DOMAIN_SUFFIXES
                },
                directDomainSuffixes = if (rawPreferences.containsKey(Keys.directDomainSuffixes)) {
                    RoutingRules.parseDirectDomainSuffixes(
                        encodeList(decodeList(preferences[Keys.directDomainSuffixes])),
                    )
                } else {
                    RoutingRules.DEFAULT_DIRECT_DOMAIN_SUFFIXES
                },
                ruleSets = emptyList(),
            ),
            selectedProfileName = preferences[Keys.selectedProfileName].orEmpty(),
            selectedProfileServer = preferences[Keys.selectedProfileServer].orEmpty(),
            selectedProfileRawLink = preferences[Keys.selectedProfileRawLink].orEmpty(),
            selectedProfileJson = preferences[Keys.selectedProfileJson].orEmpty(),
            selectedProfileSourceUrl = preferences[Keys.selectedProfileSourceUrl].orEmpty(),
            lastBenchmarkSummary = preferences[Keys.lastBenchmarkSummary].orEmpty(),
            runtimeConfigJson = preferences[Keys.runtimeConfigJson].orEmpty(),
            statusMessage = preferences[Keys.statusMessage] ?: "Idle",
            isVpnRunning = preferences[Keys.isVpnRunning] ?: false,
            sessionStatsEnabled = preferences[Keys.sessionStatsEnabled] ?: false,
            liveTrafficStatsEnabled = preferences[Keys.liveTrafficStatsEnabled] ?: false,
            profileTotalsEnabled = preferences[Keys.profileTotalsEnabled] ?: false,
            latencyHistoryEnabled = preferences[Keys.latencyHistoryEnabled] ?: false,
            connectionLogEnabled = preferences[Keys.connectionLogEnabled] ?: false,
            connectionTestToolsEnabled = preferences[Keys.connectionTestToolsEnabled] ?: false,
            sessionStartedAtEpochMillis = preferences[Keys.sessionStartedAtEpochMillis] ?: 0L,
            sessionStoppedAtEpochMillis = preferences[Keys.sessionStoppedAtEpochMillis] ?: 0L,
            sessionStartRxBytes = preferences[Keys.sessionStartRxBytes] ?: -1L,
            sessionStartTxBytes = preferences[Keys.sessionStartTxBytes] ?: -1L,
            successfulStarts = preferences[Keys.successfulStarts] ?: 0,
            successfulStops = preferences[Keys.successfulStops] ?: 0,
            profileTrafficTotals = StatsCodec.decodeProfileTrafficTotals(preferences[Keys.profileTrafficTotals]),
            latencyHistory = StatsCodec.decodeLatencyHistory(preferences[Keys.latencyHistory]),
            connectionLog = StatsCodec.decodeConnectionLog(preferences[Keys.connectionLog]),
        )
    }

    private fun normalizeStoredLocations(rawLinks: List<String>): List<String> {
        return rawLinks
            .mapNotNull { raw ->
                raw.trim()
                    .takeIf { it.isNotBlank() }
                    ?.let { LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(it)) }
            }
            .distinct()
    }

    private fun decodeList(raw: String?): List<String> {
        return raw
            .orEmpty()
            .lineSequence()
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .toList()
    }

    private fun encodeList(values: List<String>): String = values.joinToString(separator = "\n")

    private fun sanitizePackageNames(values: Iterable<String>): List<String> {
        return RoutingRules.normalizePackageNames(values)
            .filterNot { it == context.packageName }
    }

    private fun decodeStringMap(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        return runCatching {
            Json.decodeFromString(
                MapSerializer(String.serializer(), String.serializer()),
                raw,
            )
        }.getOrDefault(emptyMap())
    }

    private fun encodeStringMap(values: Map<String, String>): String {
        if (values.isEmpty()) return ""
        return Json.encodeToString(
            MapSerializer(String.serializer(), String.serializer()),
            values.filterValues { it.isNotBlank() }.toSortedMap(),
        )
    }

    private fun decodeSubscriptionRefreshSettings(
        rawPolicy: String?,
        customHours: Double,
    ): Pair<SubscriptionRefreshPolicy, Double> {
        val normalizedHours = normalizeSubscriptionRefreshCustomHours(customHours)
        return when (rawPolicy) {
            null, SubscriptionRefreshPolicy.OFF.name -> SubscriptionRefreshPolicy.OFF to normalizedHours
            SubscriptionRefreshPolicy.EVERY_HOUR.name, "EVERY_1_HOUR" ->
                SubscriptionRefreshPolicy.EVERY_HOUR to 1.0
            SubscriptionRefreshPolicy.CUSTOM.name ->
                SubscriptionRefreshPolicy.CUSTOM to normalizedHours
            "EVERY_3_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 3.0
            "EVERY_6_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 6.0
            "EVERY_12_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 12.0
            "EVERY_24_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 24.0
            else -> SubscriptionRefreshPolicy.OFF to normalizedHours
        }
    }

    private fun decodeSubscriptions(preferences: Preferences): List<SubscriptionSource> {
        val direct = preferences[Keys.subscriptions]
            ?.takeIf { it.isNotBlank() }
            ?.let(::decodeSubscriptionsJson)
            .orEmpty()
        if (direct.isNotEmpty()) {
            return direct
        }

        val currentMode = preferences[Keys.profileSourceMode]
            ?.let { raw -> runCatching { ProfileSourceMode.valueOf(raw) }.getOrNull() }
            ?: ProfileSourceMode.SUBSCRIPTION
        val legacyHistory = decodeList(preferences[Keys.profileHistory])
        val legacyNames = decodeStringMap(preferences[Keys.profileHistoryNames])
        val legacyActiveUrl = preferences[Keys.profileUrl].orEmpty()
        val legacyCurrentLocations = decodeList(preferences[Keys.currentLocations])
        val urls = buildList {
            legacyActiveUrl.takeIf { it.isNotBlank() }?.let(::add)
            legacyHistory.forEach { url ->
                if (url.isNotBlank() && url !in this) {
                    add(url)
                }
            }
        }
        return urls.mapIndexed { index, url ->
            SubscriptionSource(
                id = "legacy-${index + 1}",
                url = url,
                customName = legacyNames[url].orEmpty(),
                cachedLocations = if (currentMode == ProfileSourceMode.SUBSCRIPTION && url == legacyActiveUrl) {
                    legacyCurrentLocations
                } else {
                    emptyList()
                },
            )
        }
    }

    private fun decodeSubscriptionsJson(raw: String): List<SubscriptionSource> {
        return runCatching {
            val array = JSONArray(raw)
            buildList {
                for (index in 0 until array.length()) {
                    val item = array.optJSONObject(index) ?: continue
                    val id = item.optString("id").ifBlank { UUID.randomUUID().toString() }
                    val url = item.optString("url").trim()
                    if (url.isBlank()) continue
                    add(
                        SubscriptionSource(
                            id = id,
                            url = url,
                            customName = item.optString("custom_name"),
                            cachedLocations = item.optJSONArray("cached_locations")?.let(::decodeJsonStringList).orEmpty(),
                            lastRefreshedAtEpochMillis = item.optLong("last_refreshed_at", 0L),
                            lastRefreshStatus = item.optString("last_refresh_status"),
                        ),
                    )
                }
            }
        }.getOrDefault(emptyList())
    }

    private fun encodeSubscriptions(subscriptions: List<SubscriptionSource>): String {
        if (subscriptions.isEmpty()) return ""
        val array = JSONArray()
        subscriptions.forEach { subscription ->
            array.put(
                JSONObject()
                    .put("id", subscription.id)
                    .put("url", subscription.url)
                    .put("custom_name", subscription.customName)
                    .put("cached_locations", JSONArray(subscription.cachedLocations))
                    .put("last_refreshed_at", subscription.lastRefreshedAtEpochMillis)
                    .put("last_refresh_status", subscription.lastRefreshStatus),
            )
        }
        return array.toString()
    }

    private fun decodeJsonStringList(array: JSONArray): List<String> {
        return buildList {
            for (index in 0 until array.length()) {
                array.optString(index)
                    .trim()
                    .takeIf { it.isNotBlank() }
                    ?.let(::add)
            }
        }
    }

    private fun resolveActiveSubscriptionId(
        preferences: Preferences,
        subscriptions: List<SubscriptionSource>,
    ): String {
        val explicit = preferences[Keys.activeSubscriptionId].orEmpty()
        if (explicit == ALL_SUBSCRIPTIONS_ID && supportsAllSubscriptionsGroup(subscriptions)) {
            return explicit
        }
        if (explicit.isNotBlank() && subscriptions.any { it.id == explicit }) {
            return explicit
        }
        val legacyUrl = preferences[Keys.profileUrl].orEmpty()
        if (legacyUrl.isNotBlank()) {
            subscriptions.firstOrNull { it.url == legacyUrl }?.let { return it.id }
        }
        return subscriptions.firstOrNull()?.id.orEmpty()
    }

    private fun resolveActiveSubscriptionUrl(preferences: Preferences): String {
        val subscriptions = decodeSubscriptions(preferences)
        val activeId = resolveActiveSubscriptionId(preferences, subscriptions)
        if (isAllSubscriptionsGroupActive(activeId, subscriptions)) {
            return ""
        }
        return subscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()
    }

    private fun <T, K, V> Iterable<T>.associateNotNull(transform: (T) -> Pair<K, V>?) = buildMap<K, V> {
        this@associateNotNull.forEach { item ->
            val pair = transform(item) ?: return@forEach
            put(pair.first, pair.second)
        }
    }

    private fun currentUidTrafficBytes(): Pair<Long, Long> {
        val uid = context.applicationInfo.uid
        val rxBytes = TrafficStats.getUidRxBytes(uid).takeIf { it >= 0 } ?: -1L
        val txBytes = TrafficStats.getUidTxBytes(uid).takeIf { it >= 0 } ?: -1L
        return rxBytes to txBytes
    }

    private fun recordProfileTrafficTotals(prefs: MutablePreferences) {
        val startRxBytes = prefs[Keys.sessionStartRxBytes] ?: -1L
        val startTxBytes = prefs[Keys.sessionStartTxBytes] ?: -1L
        if (startRxBytes < 0L || startTxBytes < 0L) return
        val (currentRxBytes, currentTxBytes) = currentUidTrafficBytes()
        if (currentRxBytes < 0L || currentTxBytes < 0L) return

        val profileKey = LocationConfigs.selectedStoredReference(
            selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
            selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
        ).ifBlank { return }

        val rxDelta = (currentRxBytes - startRxBytes).coerceAtLeast(0L)
        val txDelta = (currentTxBytes - startTxBytes).coerceAtLeast(0L)
        val now = System.currentTimeMillis()
        val currentTotals = StatsCodec.decodeProfileTrafficTotals(prefs[Keys.profileTrafficTotals]).toMutableList()
        val existingIndex = currentTotals.indexOfFirst { it.profileKey == profileKey }
        val updatedEntry = if (existingIndex >= 0) {
            currentTotals[existingIndex].copy(
                profileName = prefs[Keys.selectedProfileName].orEmpty().ifBlank { currentTotals[existingIndex].profileName },
                sourceUrl = prefs[Keys.selectedProfileSourceUrl].orEmpty(),
                rxBytes = currentTotals[existingIndex].rxBytes + rxDelta,
                txBytes = currentTotals[existingIndex].txBytes + txDelta,
                lastUpdatedAtEpochMillis = now,
            )
        } else {
            ProfileTrafficTotal(
                profileKey = profileKey,
                profileName = prefs[Keys.selectedProfileName].orEmpty().ifBlank { "Selected profile" },
                sourceUrl = prefs[Keys.selectedProfileSourceUrl].orEmpty(),
                rxBytes = rxDelta,
                txBytes = txDelta,
                lastUpdatedAtEpochMillis = now,
            )
        }
        if (existingIndex >= 0) {
            currentTotals[existingIndex] = updatedEntry
        } else {
            currentTotals += updatedEntry
        }
        prefs[Keys.profileTrafficTotals] = StatsCodec.encodeProfileTrafficTotals(
            currentTotals
                .sortedByDescending { it.lastUpdatedAtEpochMillis }
                .take(MAX_PROFILE_TOTALS_ITEMS),
        )
    }

    private fun clearStoredSelection(prefs: MutablePreferences) {
        prefs.remove(Keys.selectedProfileName)
        prefs.remove(Keys.selectedProfileServer)
        prefs.remove(Keys.selectedProfileRawLink)
        prefs.remove(Keys.selectedProfileJson)
        prefs.remove(Keys.selectedProfileSourceUrl)
        prefs.remove(Keys.lastBenchmarkSummary)
        prefs.remove(Keys.runtimeConfigJson)
        prefs.remove(Keys.sessionStartRxBytes)
        prefs.remove(Keys.sessionStartTxBytes)
        runCatching { runtimeConfigFile().delete() }
        runCatching { lastProfileFile().delete() }
    }

    private companion object {
        const val MAX_CONNECTION_LOG_ITEMS = 120
        const val MAX_LATENCY_HISTORY_ITEMS = 50
        const val MAX_PROFILE_TOTALS_ITEMS = 100

        fun generateSubscriptionHwid(): String {
            return UUID.randomUUID().toString().replace("-", "")
        }
    }
}
