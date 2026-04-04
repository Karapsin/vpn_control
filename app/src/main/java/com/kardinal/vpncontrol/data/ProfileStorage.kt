package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.VlessProfile
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.IOException
import java.io.File

private val Context.dataStore by preferencesDataStore(name = "vpn_control")

class ProfileStorage(private val context: Context) {
    data class CurrentLocationsUpdateResult(
        val selectedMissing: Boolean,
    )

    private object Keys {
        val profileUrl = stringPreferencesKey("profile_url")
        val profileHistory = stringPreferencesKey("profile_history")
        val profileHistoryNames = stringPreferencesKey("profile_history_names")
        val profileSourceMode = stringPreferencesKey("profile_source_mode")
        val subscriptionRefreshPolicy = stringPreferencesKey("subscription_refresh_policy")
        val subscriptionRefreshCustomHours = intPreferencesKey("subscription_refresh_custom_hours")
        val validationPrimaryUrl = stringPreferencesKey("validation_primary_url")
        val validationSecondaryUrl = stringPreferencesKey("validation_secondary_url")
        val validationBatchSize = intPreferencesKey("validation_batch_size")
        val validationRetryCount = intPreferencesKey("validation_retry_count")
        val legacyValidationGeneralUrl = stringPreferencesKey("validation_general_url")
        val legacyValidationChatGptUrl = stringPreferencesKey("validation_chatgpt_url")
        val currentLocations = stringPreferencesKey("current_locations")
        val locationBenchmarkDetails = stringPreferencesKey("location_benchmark_details")
        val customDns = stringPreferencesKey("custom_dns")
        val useCustomDns = booleanPreferencesKey("use_custom_dns")
        val ignoreRules = booleanPreferencesKey("ignore_rules")
        val proxyPackages = stringPreferencesKey("proxy_packages")
        val bypassPackages = stringPreferencesKey("bypass_packages")
        val nationalDomainSuffixes = stringPreferencesKey("national_domain_suffixes")
        val directDomainSuffixes = stringPreferencesKey("direct_domain_suffixes")
        val selectedProfileName = stringPreferencesKey("selected_profile_name")
        val selectedProfileServer = stringPreferencesKey("selected_profile_server")
        val selectedProfileRawLink = stringPreferencesKey("selected_profile_raw_link")
        val selectedProfileJson = stringPreferencesKey("selected_profile_json")
        val selectedProfileSourceUrl = stringPreferencesKey("selected_profile_source_url")
        val lastBenchmarkSummary = stringPreferencesKey("last_benchmark_summary")
        val runtimeConfigJson = stringPreferencesKey("runtime_config_json")
        val statusMessage = stringPreferencesKey("status_message")
        val isVpnRunning = booleanPreferencesKey("is_vpn_running")
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
            prefs[Keys.profileUrl] = url
            if (rememberInHistory) {
                val history = decodeList(prefs[Keys.profileHistory])
                    .toMutableList()
                    .apply {
                        remove(url)
                        add(0, url)
                    }
                val normalizedHistory = history.distinct()
                prefs[Keys.profileHistory] = encodeList(normalizedHistory)
                prefs[Keys.profileHistoryNames] = encodeStringMap(
                    decodeStringMap(prefs[Keys.profileHistoryNames])
                        .filterKeys { it in normalizedHistory.toSet() },
                )
            }
        }
    }

    suspend fun deleteProfileHistoryEntry(url: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.profileHistory] = encodeList(
                decodeList(prefs[Keys.profileHistory]).filterNot { it == url },
            )
            prefs[Keys.profileHistoryNames] = encodeStringMap(
                decodeStringMap(prefs[Keys.profileHistoryNames]).filterKeys { it != url },
            )
        }
        DiagnosticsLogger.append(context, "Profile history entry deleted")
    }

    suspend fun updateProfileHistoryName(url: String, name: String) {
        val normalizedName = name.trim()
        context.dataStore.edit { prefs ->
            val names = decodeStringMap(prefs[Keys.profileHistoryNames]).toMutableMap()
            if (normalizedName.isBlank()) {
                names.remove(url)
            } else {
                names[url] = normalizedName
            }
            prefs[Keys.profileHistoryNames] = encodeStringMap(names)
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
        val normalized = rawLinks
            .mapNotNull { raw ->
                raw.trim()
                    .takeIf { it.isNotBlank() }
                    ?.let { LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(it)) }
            }
            .distinct()
        var result = CurrentLocationsUpdateResult(
            selectedMissing = false,
        )
        context.dataStore.edit { prefs ->
            prefs[Keys.currentLocations] = encodeList(normalized)
            prefs[Keys.locationBenchmarkDetails] = encodeStringMap(
                decodeStringMap(prefs[Keys.locationBenchmarkDetails]).filterKeys { it in normalized },
            )
            val sourceMode = prefs[Keys.profileSourceMode]
            val selectedStored = LocationConfigs.selectedStoredReference(
                selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
            )
            val selectedRelevantToCurrentList = when (sourceMode) {
                ProfileSourceMode.SUBSCRIPTION.name ->
                    prefs[Keys.selectedProfileSourceUrl].orEmpty().isNotBlank() &&
                        prefs[Keys.selectedProfileSourceUrl].orEmpty() == prefs[Keys.profileUrl].orEmpty()
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
        }
        DiagnosticsLogger.append(
            context,
            "Routing rules updated: ignore=${rules.ignoreRules} proxy=${rules.proxyPackages.size} direct=${rules.bypassPackages.size} " +
                "national=${rules.nationalDomainSuffixes.size} domains=${rules.directDomainSuffixes.size}",
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
            prefs[Keys.isVpnRunning] = running
            if (!running) {
                val selectedStored = LocationConfigs.selectedStoredReference(
                    selectedProfileJson = prefs[Keys.selectedProfileJson].orEmpty(),
                    selectedProfileRawLink = prefs[Keys.selectedProfileRawLink].orEmpty(),
                )
                val currentLocations = decodeList(prefs[Keys.currentLocations])
                val shouldClearSelection = when (prefs[Keys.profileSourceMode]) {
                    ProfileSourceMode.CURRENT_LOCATIONS.name ->
                        !selectedStored.isNullOrBlank() && selectedStored !in currentLocations
                    ProfileSourceMode.SUBSCRIPTION.name ->
                        prefs[Keys.selectedProfileSourceUrl].orEmpty().isBlank() ||
                            prefs[Keys.selectedProfileSourceUrl].orEmpty() != prefs[Keys.profileUrl].orEmpty()
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
        return PersistedState(
            profileUrl = preferences[Keys.profileUrl].orEmpty(),
            profileHistory = decodeList(preferences[Keys.profileHistory]),
            profileHistoryNames = decodeStringMap(preferences[Keys.profileHistoryNames]),
            profileSourceMode = preferences[Keys.profileSourceMode]
                ?.let { raw -> runCatching { ProfileSourceMode.valueOf(raw) }.getOrNull() }
                ?: ProfileSourceMode.SUBSCRIPTION,
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
            currentLocations = decodeList(preferences[Keys.currentLocations]),
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
        )
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
