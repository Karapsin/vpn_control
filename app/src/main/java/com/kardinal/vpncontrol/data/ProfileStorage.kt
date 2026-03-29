package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
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
    private object Keys {
        val profileUrl = stringPreferencesKey("profile_url")
        val profileHistory = stringPreferencesKey("profile_history")
        val profileHistoryNames = stringPreferencesKey("profile_history_names")
        val profileSourceMode = stringPreferencesKey("profile_source_mode")
        val subscriptionRefreshPolicy = stringPreferencesKey("subscription_refresh_policy")
        val subscriptionRefreshCustomHours = intPreferencesKey("subscription_refresh_custom_hours")
        val validationGeneralUrl = stringPreferencesKey("validation_general_url")
        val validationChatGptUrl = stringPreferencesKey("validation_chatgpt_url")
        val validationCandidateCount = intPreferencesKey("validation_candidate_count")
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
            prefs[Keys.validationGeneralUrl] = normalized.generalUrl
            prefs[Keys.validationChatGptUrl] = normalized.chatGptUrl
            prefs[Keys.validationCandidateCount] = normalized.candidateCount
        }
        DiagnosticsLogger.append(
            context,
            "Validation settings updated: general=${normalized.generalUrl} chatgpt=${normalized.chatGptUrl} " +
                "candidates=${normalized.candidateCount} concurrency=${normalized.concurrency()}",
        )
    }

    suspend fun updateCurrentLocations(rawLinks: List<String>) {
        val normalized = rawLinks
            .mapNotNull { raw ->
                raw.trim()
                    .takeIf { it.isNotBlank() }
                    ?.let { LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(it)) }
            }
        context.dataStore.edit { prefs ->
            prefs[Keys.currentLocations] = encodeList(normalized)
            prefs[Keys.locationBenchmarkDetails] = encodeStringMap(
                decodeStringMap(prefs[Keys.locationBenchmarkDetails]).filterKeys { it in normalized },
            )
            val selectedStored = prefs[Keys.selectedProfileJson]
                ?: prefs[Keys.selectedProfileRawLink]?.takeIf { it.isNotBlank() }?.let { raw ->
                    runCatching {
                        LocationConfigs.encodeStoredLocation(LocationConfigs.parseLocationInput(raw))
                    }.getOrNull()
                }
            selectedStored
                ?.takeIf { it.isNotBlank() && it !in normalized }
                ?.let {
                    prefs.remove(Keys.selectedProfileName)
                    prefs.remove(Keys.selectedProfileServer)
                    prefs.remove(Keys.selectedProfileRawLink)
                    prefs.remove(Keys.selectedProfileJson)
                    prefs.remove(Keys.lastBenchmarkSummary)
                    prefs.remove(Keys.runtimeConfigJson)
                }
        }
        DiagnosticsLogger.append(context, "Current locations updated: count=${normalized.size}")
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
            prefs[Keys.proxyPackages] = encodeList(rules.proxyPackages)
            prefs[Keys.bypassPackages] = encodeList(rules.bypassPackages)
            prefs[Keys.nationalDomainSuffixes] = encodeList(rules.nationalDomainSuffixes)
            prefs[Keys.directDomainSuffixes] = encodeList(rules.directDomainSuffixes)
        }
        DiagnosticsLogger.append(
            context,
            "Routing rules updated: ignore=${rules.ignoreRules} proxy=${rules.proxyPackages.size} direct=${rules.bypassPackages.size} " +
                "national=${rules.nationalDomainSuffixes.size} domains=${rules.directDomainSuffixes.size}",
        )
    }

    suspend fun updateSelection(profile: VlessProfile, summary: String, runtimeConfigJson: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.selectedProfileName] = profile.remarks
            prefs[Keys.selectedProfileServer] = profile.server
            prefs[Keys.selectedProfileRawLink] = profile.rawLink
            prefs[Keys.selectedProfileJson] = LocationConfigs.encodeStoredLocation(profile)
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

    suspend fun updateVpnRunning(running: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.isVpnRunning] = running
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
                generalUrl = preferences[Keys.validationGeneralUrl]
                    ?: BenchmarkValidationSettings.DEFAULT_GENERAL_URL,
                chatGptUrl = preferences[Keys.validationChatGptUrl]
                    ?: BenchmarkValidationSettings.DEFAULT_CHATGPT_URL,
                candidateCount = preferences[Keys.validationCandidateCount]
                    ?: BenchmarkValidationSettings.DEFAULT_CANDIDATE_COUNT,
            ).normalized(),
            currentLocations = decodeList(preferences[Keys.currentLocations]),
            locationBenchmarkDetails = decodeStringMap(preferences[Keys.locationBenchmarkDetails]),
            customDns = preferences[Keys.customDns].orEmpty(),
            useCustomDns = preferences[Keys.useCustomDns] ?: false,
            routingRules = RoutingRules(
                ignoreRules = preferences[Keys.ignoreRules] ?: false,
                proxyPackages = RoutingRules.normalizePackageNames(
                    decodeList(preferences[Keys.proxyPackages]),
                ),
                bypassPackages = RoutingRules.normalizePackageNames(
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
}
