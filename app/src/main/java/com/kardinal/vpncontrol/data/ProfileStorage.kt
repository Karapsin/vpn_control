package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.VlessProfile
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

class ProfileStorage(private val context: Context) {
    data class CurrentLocationsUpdateResult(
        val selectedMissing: Boolean,
    )

    private object Keys {
        val profileUrl = stringPreferencesKey("profile_url")
        val profileHistory = stringPreferencesKey("profile_history")
        val profileHistoryNames = stringPreferencesKey("profile_history_names")
        val subscriptions = stringPreferencesKey("subscriptions_json")
        val activeSubscriptionId = stringPreferencesKey("active_subscription_id")
        val profileSourceMode = stringPreferencesKey("profile_source_mode")
        val appMode = stringPreferencesKey("app_mode")
        val subscriptionRefreshPolicy = stringPreferencesKey("subscription_refresh_policy")
        val subscriptionRefreshCustomHours = intPreferencesKey("subscription_refresh_custom_hours")
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
        val sessionStartedAtEpochMillis = longPreferencesKey("session_started_at_epoch_millis")
        val sessionStoppedAtEpochMillis = longPreferencesKey("session_stopped_at_epoch_millis")
        val successfulStarts = intPreferencesKey("successful_starts")
        val successfulStops = intPreferencesKey("successful_stops")
    }

    val state: Flow<PersistedState> = context.dataStore.data
        .catch { exception ->
            if (exception is IOException) {
                emit(emptyPreferences())
            } else {
                throw exception
            }
        }
        .map(::mapState)

    suspend fun updateProfileUrl(url: String, rememberInHistory: Boolean = false) {
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

    suspend fun deleteProfileHistoryEntry(url: String) {
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
            if (activeId.isBlank() || subscriptions.none { it.id == activeId }) {
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

    suspend fun updateProfileHistoryName(url: String, name: String) {
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

    suspend fun updateProfileSourceMode(mode: ProfileSourceMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.profileSourceMode] = mode.name
        }
        DiagnosticsLogger.append(context, "Profile source mode updated: $mode")
    }

    suspend fun updateAppMode(mode: AppMode) {
        context.dataStore.edit { prefs ->
            prefs[Keys.appMode] = mode.name
        }
        DiagnosticsLogger.append(context, "App mode updated: $mode")
    }

    suspend fun updateSubscriptionRefreshPolicy(policy: SubscriptionRefreshPolicy, customHours: Int) {
        context.dataStore.edit { prefs ->
            prefs[Keys.subscriptionRefreshPolicy] = policy.name
            prefs[Keys.subscriptionRefreshCustomHours] = customHours.coerceAtLeast(1)
        }
        DiagnosticsLogger.append(
            context,
            "Subscription refresh policy updated: policy=$policy customHours=${customHours.coerceAtLeast(1)}",
        )
    }

    suspend fun updateValidationSettings(settings: BenchmarkValidationSettings) {
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

    suspend fun updateCurrentLocations(rawLinks: List<String>): CurrentLocationsUpdateResult {
        val normalized = normalizeStoredLocations(rawLinks)
        var result = CurrentLocationsUpdateResult(
            selectedMissing = false,
        )
        context.dataStore.edit { prefs ->
            val sourceMode = prefs[Keys.profileSourceMode]
            if (sourceMode == ProfileSourceMode.SUBSCRIPTION.name) {
                val subscriptions = decodeSubscriptions(prefs).toMutableList()
                val activeId = resolveActiveSubscriptionId(prefs, subscriptions)
                val updatedSubscriptions = subscriptions.map { subscription ->
                    if (subscription.id == activeId) {
                        subscription.copy(
                            cachedLocations = normalized,
                            lastRefreshedAtEpochMillis = System.currentTimeMillis(),
                            lastRefreshStatus = "Updated ${normalized.size} location" +
                                if (normalized.size == 1) "" else "s",
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
                prefs[Keys.profileUrl] = updatedSubscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()
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
            val activeUrl = resolveActiveSubscriptionUrl(prefs)
            val selectedRelevantToCurrentList = when (sourceMode) {
                ProfileSourceMode.SUBSCRIPTION.name ->
                    prefs[Keys.selectedProfileSourceUrl].orEmpty().isNotBlank() &&
                        prefs[Keys.selectedProfileSourceUrl].orEmpty() == activeUrl
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
            result = CurrentLocationsUpdateResult(
                selectedMissing = selectedMissing,
            )
        }
        DiagnosticsLogger.append(context, "Current locations updated: count=${normalized.size}")
        return result
    }

    suspend fun updateSubscriptionCache(
        subscriptionId: String,
        rawLinks: List<String>,
        refreshStatus: String = "",
    ): CurrentLocationsUpdateResult {
        val normalized = normalizeStoredLocations(rawLinks)
        var result = CurrentLocationsUpdateResult(selectedMissing = false)
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
            prefs[Keys.profileUrl] = updatedSubscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()

            if (isActiveSubscription && prefs[Keys.profileSourceMode] == ProfileSourceMode.SUBSCRIPTION.name) {
                prefs[Keys.locationBenchmarkDetails] = encodeStringMap(
                    decodeStringMap(prefs[Keys.locationBenchmarkDetails]).filterKeys { it in normalized },
                )
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                    selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
                )
                val activeUrl = resolveActiveSubscriptionUrl(prefs)
                val selectedRelevantToCurrentList =
                    prefs[Keys.selectedProfileSourceUrl].orEmpty().isNotBlank() &&
                        prefs[Keys.selectedProfileSourceUrl].orEmpty() == activeUrl
                val selectedMissing =
                    selectedStored.isNotBlank() &&
                        selectedRelevantToCurrentList &&
                        selectedStored !in normalized
                if (selectedMissing) {
                    clearStoredSelection(prefs)
                }
                result = CurrentLocationsUpdateResult(selectedMissing = selectedMissing)
            }
        }
        DiagnosticsLogger.append(
            context,
            "Subscription cache updated: subscriptionId=$subscriptionId count=${normalized.size}",
        )
        return result
    }

    suspend fun updateSubscriptionRefreshStatus(
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

    suspend fun updateLocationBenchmarkDetails(details: Map<String, String>) {
        context.dataStore.edit { prefs ->
            prefs[Keys.locationBenchmarkDetails] = encodeStringMap(details)
        }
        DiagnosticsLogger.append(context, "Location benchmark details updated: count=${details.size}")
    }

    suspend fun updateDns(dns: String, enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.customDns] = dns
            prefs[Keys.useCustomDns] = enabled
        }
        DiagnosticsLogger.append(context, "Custom DNS updated: enabled=$enabled value=$dns")
    }

    suspend fun updateRoutingRules(rules: RoutingRules) {
        context.dataStore.edit { prefs ->
            prefs[Keys.ignoreRules] = rules.ignoreRules
            prefs[Keys.proxyPackages] = encodeList(sanitizePackageNames(rules.proxyPackages))
            prefs[Keys.bypassPackages] = encodeList(sanitizePackageNames(rules.bypassPackages))
            prefs[Keys.nationalDomainSuffixes] = encodeList(rules.nationalDomainSuffixes)
            prefs[Keys.directDomainSuffixes] = encodeList(rules.directDomainSuffixes)
            prefs[Keys.ruleSets] = RoutingRuleSetCodec.encode(rules.ruleSets)
        }
        DiagnosticsLogger.append(
            context,
            "Routing rules updated: ignore=${rules.ignoreRules} proxy=${rules.proxyPackages.size} direct=${rules.bypassPackages.size} " +
                "national=${rules.nationalDomainSuffixes.size} domains=${rules.directDomainSuffixes.size} rulesets=${rules.ruleSets.size}",
        )
    }

    suspend fun updateSelection(
        profile: VlessProfile,
        summary: String,
        runtimeConfigJson: String,
        sourceUrl: String = "",
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

    suspend fun updateStatus(message: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.statusMessage] = message
        }
        DiagnosticsLogger.append(context, "Status: $message")
    }

    suspend fun updateSessionStatsEnabled(enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.sessionStatsEnabled] = enabled
        }
        DiagnosticsLogger.append(context, "Session stats UI enabled: $enabled")
    }

    suspend fun clearSelection() {
        context.dataStore.edit { prefs ->
            clearStoredSelection(prefs)
        }
        DiagnosticsLogger.append(context, "Stored selection cleared")
    }

    suspend fun restoreSelection(
        state: PersistedState,
        restoreRuntimeArtifacts: Boolean = true,
        sourceUrlOverride: String? = null,
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
                prefs[Keys.sessionStartedAtEpochMillis] = System.currentTimeMillis()
                prefs[Keys.successfulStarts] = (prefs[Keys.successfulStarts] ?: 0) + 1
            } else if (wasRunning && !running) {
                prefs[Keys.sessionStoppedAtEpochMillis] = System.currentTimeMillis()
                prefs[Keys.successfulStops] = (prefs[Keys.successfulStops] ?: 0) + 1
            }
            if (!running) {
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                    selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
                )
                val profileSourceMode = prefs[Keys.profileSourceMode]
                val activeSubscriptionLocations = decodeSubscriptions(prefs)
                    .firstOrNull { it.id == resolveActiveSubscriptionId(prefs, decodeSubscriptions(prefs)) }
                    ?.cachedLocations
                    .orEmpty()
                val savedLocations = decodeList(prefs[Keys.savedLocations]).ifEmpty {
                    decodeList(prefs[Keys.currentLocations])
                }
                val shouldClearSelection = when (profileSourceMode) {
                    ProfileSourceMode.CURRENT_LOCATIONS.name ->
                        selectedStored.isNotBlank() && selectedStored !in savedLocations
                    ProfileSourceMode.SUBSCRIPTION.name ->
                        prefs[Keys.selectedProfileSourceUrl].orEmpty().isBlank() ||
                            prefs[Keys.selectedProfileSourceUrl].orEmpty() != resolveActiveSubscriptionUrl(prefs) ||
                            (selectedStored.isNotBlank() &&
                                prefs[Keys.selectedProfileSourceUrl].orEmpty() == resolveActiveSubscriptionUrl(prefs) &&
                                selectedStored !in activeSubscriptionLocations)
                    else -> false
                }
                if (shouldClearSelection) {
                    clearStoredSelection(prefs)
                }
            }
        }
        DiagnosticsLogger.append(context, "VPN running flag: $running")
    }

    suspend fun snapshot(): PersistedState = state.first()

    fun runtimeConfigFile(): File = RuntimeFiles.runtimeConfigFile(context)

    fun lastProfileFile(): File = RuntimeFiles.selectedProfileFile(context)

    private fun mapState(preferences: Preferences): PersistedState {
        val rawPreferences = preferences.asMap()
        val refreshSettings = decodeSubscriptionRefreshSettings(
            rawPolicy = preferences[Keys.subscriptionRefreshPolicy],
            customHours = preferences[Keys.subscriptionRefreshCustomHours] ?: 3,
        )
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
            ProfileSourceMode.SUBSCRIPTION -> activeSubscription?.cachedLocations.orEmpty()
            ProfileSourceMode.CURRENT_LOCATIONS -> savedLocations
        }
        val historyNames = subscriptions.associateNotNull { subscription ->
            subscription.customName.takeIf { it.isNotBlank() }?.let { subscription.url to it }
        }
        return PersistedState(
            profileUrl = activeSubscription?.url.orEmpty(),
            activeSubscriptionId = activeSubscriptionId,
            subscriptions = subscriptions,
            profileHistory = subscriptions.map { it.url },
            profileHistoryNames = historyNames,
            profileSourceMode = profileSourceMode,
            appMode = appMode,
            subscriptionRefreshPolicy = refreshSettings.first,
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
                bypassPackages = sanitizePackageNames(
                    decodeList(preferences[Keys.bypassPackages]),
                ),
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
                ruleSets = RoutingRuleSetCodec.decode(preferences[Keys.ruleSets]),
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
            sessionStartedAtEpochMillis = preferences[Keys.sessionStartedAtEpochMillis] ?: 0L,
            sessionStoppedAtEpochMillis = preferences[Keys.sessionStoppedAtEpochMillis] ?: 0L,
            successfulStarts = preferences[Keys.successfulStarts] ?: 0,
            successfulStops = preferences[Keys.successfulStops] ?: 0,
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
        customHours: Int,
    ): Pair<SubscriptionRefreshPolicy, Int> {
        val normalizedHours = customHours.coerceAtLeast(1)
        return when (rawPolicy) {
            null, SubscriptionRefreshPolicy.OFF.name -> SubscriptionRefreshPolicy.OFF to normalizedHours
            SubscriptionRefreshPolicy.EVERY_HOUR.name, "EVERY_1_HOUR" ->
                SubscriptionRefreshPolicy.EVERY_HOUR to 1
            SubscriptionRefreshPolicy.CUSTOM.name ->
                SubscriptionRefreshPolicy.CUSTOM to normalizedHours
            "EVERY_3_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 3
            "EVERY_6_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 6
            "EVERY_12_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 12
            "EVERY_24_HOURS" -> SubscriptionRefreshPolicy.CUSTOM to 24
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
        return subscriptions.firstOrNull { it.id == activeId }?.url.orEmpty()
    }

    private fun <T, K, V> Iterable<T>.associateNotNull(transform: (T) -> Pair<K, V>?) = buildMap<K, V> {
        this@associateNotNull.forEach { item ->
            val pair = transform(item) ?: return@forEach
            put(pair.first, pair.second)
        }
    }

    private fun clearStoredSelection(prefs: MutablePreferences) {
        prefs.remove(Keys.selectedProfileName)
        prefs.remove(Keys.selectedProfileServer)
        prefs.remove(Keys.selectedProfileRawLink)
        prefs.remove(Keys.selectedProfileJson)
        prefs.remove(Keys.selectedProfileSourceUrl)
        prefs.remove(Keys.lastBenchmarkSummary)
        prefs.remove(Keys.runtimeConfigJson)
        runCatching { runtimeConfigFile().delete() }
        runCatching { lastProfileFile().delete() }
    }
}
