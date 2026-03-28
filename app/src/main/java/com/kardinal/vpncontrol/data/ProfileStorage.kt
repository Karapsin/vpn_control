package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.IOException
import java.io.File

private val Context.dataStore by preferencesDataStore(name = "vpn_control")

class ProfileStorage(private val context: Context) {
    private object Keys {
        val profileUrl = stringPreferencesKey("profile_url")
        val customDns = stringPreferencesKey("custom_dns")
        val useCustomDns = booleanPreferencesKey("use_custom_dns")
        val proxyPackages = stringPreferencesKey("proxy_packages")
        val bypassPackages = stringPreferencesKey("bypass_packages")
        val nationalDomainSuffixes = stringPreferencesKey("national_domain_suffixes")
        val directDomainSuffixes = stringPreferencesKey("direct_domain_suffixes")
        val selectedProfileName = stringPreferencesKey("selected_profile_name")
        val selectedProfileServer = stringPreferencesKey("selected_profile_server")
        val selectedProfileRawLink = stringPreferencesKey("selected_profile_raw_link")
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

    suspend fun updateProfileUrl(url: String) {
        context.dataStore.edit { prefs ->
            prefs[Keys.profileUrl] = url
        }
    }

    suspend fun updateDns(dns: String, enabled: Boolean) {
        context.dataStore.edit { prefs ->
            prefs[Keys.customDns] = dns
            prefs[Keys.useCustomDns] = enabled
        }
    }

    suspend fun updateRoutingRules(rules: RoutingRules) {
        context.dataStore.edit { prefs ->
            prefs[Keys.proxyPackages] = encodeList(rules.proxyPackages)
            prefs[Keys.bypassPackages] = encodeList(rules.bypassPackages)
            prefs[Keys.nationalDomainSuffixes] = encodeList(rules.nationalDomainSuffixes)
            prefs[Keys.directDomainSuffixes] = encodeList(rules.directDomainSuffixes)
        }
        DiagnosticsLogger.append(
            context,
            "Routing rules updated: proxy=${rules.proxyPackages.size} direct=${rules.bypassPackages.size} " +
                "national=${rules.nationalDomainSuffixes.size} domains=${rules.directDomainSuffixes.size}",
        )
    }

    suspend fun updateSelection(
        name: String,
        server: String,
        rawLink: String,
        summary: String,
        runtimeConfigJson: String,
    ) {
        context.dataStore.edit { prefs ->
            prefs[Keys.selectedProfileName] = name
            prefs[Keys.selectedProfileServer] = server
            prefs[Keys.selectedProfileRawLink] = rawLink
            prefs[Keys.lastBenchmarkSummary] = summary
            prefs[Keys.runtimeConfigJson] = runtimeConfigJson
        }
        DiagnosticsLogger.append(
            context,
            "Selected profile updated: name=$name server=$server summary=$summary",
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
        return PersistedState(
            profileUrl = preferences[Keys.profileUrl].orEmpty(),
            customDns = preferences[Keys.customDns].orEmpty(),
            useCustomDns = preferences[Keys.useCustomDns] ?: false,
            routingRules = RoutingRules(
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
}
