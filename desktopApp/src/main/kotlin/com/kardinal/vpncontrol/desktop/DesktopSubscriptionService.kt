package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SelectionMappingLogic
import com.kardinal.vpncontrol.data.DirectRemoteSourceResolution
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.data.ResolvedRemoteSource
import com.kardinal.vpncontrol.data.SelectionWorkflowService
import com.kardinal.vpncontrol.data.UnsupportedRemoteSourceResolution
import com.kardinal.vpncontrol.data.displayRemoteSourceHost
import com.kardinal.vpncontrol.data.parseDirectRemoteSource
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher
import java.util.UUID

internal data class DesktopSubscriptionRefreshPayload(
    val subscriptionHwid: String,
    val subscriptions: List<SubscriptionSource>,
    val locations: List<DesktopLocationRecord>,
    val refreshedCount: Int,
    val statusMessage: String,
)

internal class DesktopSubscriptionService(
    private val subscriptionContentFetcher: SubscriptionContentFetcher,
    private val clockMillis: () -> Long = { System.currentTimeMillis() },
    private val hwidGenerator: () -> String = ::generateDesktopSubscriptionHwid,
) {
    suspend fun refreshSubscriptions(
        state: MainUiState,
        locations: List<DesktopLocationRecord>,
        subscriptionsToRefresh: List<SubscriptionSource>,
        onProgress: (String) -> Unit,
    ): Result<DesktopSubscriptionRefreshPayload> {
        if (subscriptionsToRefresh.isEmpty()) {
            return Result.failure(DesktopSubscriptionRefreshStatus.noSubscriptionsToRefresh())
        }

        val subscriptionHwid = state.subscriptionHwid.trim().ifBlank(hwidGenerator)
        val now = clockMillis()
        val loadedByUrl = linkedMapOf<String, List<ProxyProfile>>()
        val failedLabels = mutableListOf<String>()
        var currentSubscriptions = state.subscriptions

        for (subscription in subscriptionsToRefresh) {
            onProgress(DesktopSubscriptionRefreshStatus.progress(subscription))
            val result = runCatching {
                loadSubscriptionProfiles(subscription.url, subscriptionHwid)
            }
            currentSubscriptions = currentSubscriptions.map { source ->
                if (source.id != subscription.id) {
                    source
                } else {
                    result.fold(
                        onSuccess = { profiles ->
                            loadedByUrl[source.url] = profiles
                            source.copy(
                                cachedLocations = profiles.map(LocationConfigs::encodeStoredLocation),
                                lastRefreshedAtEpochMillis = now,
                                lastRefreshStatus = DesktopSubscriptionRefreshStatus.successfulLocationRefresh(profiles.size),
                            )
                        },
                        onFailure = { error ->
                            failedLabels += subscriptionDisplayName(source)
                            source.copy(
                                lastRefreshedAtEpochMillis = now,
                                lastRefreshStatus = DesktopSubscriptionRefreshStatus.failedSubscriptionRefresh(source, error),
                            )
                        },
                    )
                }
            }
        }

        val successfulUrls = loadedByUrl.keys
        val preservedLocations = locations.filter { location ->
            location.sourceUrl.isBlank() || location.sourceUrl !in successfulUrls
        }
        val rebuiltLocations = buildList {
            addAll(preservedLocations)
            var nextIndex = nextLocationIndex(preservedLocations)
            loadedByUrl.forEach { (sourceUrl, profiles) ->
                val (mapped, updatedNextIndex) = profilesToDesktopLocations(
                    sourceUrl = sourceUrl,
                    profiles = profiles,
                    existingLocations = locations,
                    startIndex = nextIndex,
                )
                addAll(mapped)
                nextIndex = updatedNextIndex
            }
        }

        val summary = DesktopSubscriptionRefreshStatus.summary(
            refreshedCount = loadedByUrl.size,
            failedSubscriptionNames = failedLabels,
            totalCount = subscriptionsToRefresh.size,
        )
        return Result.success(
            DesktopSubscriptionRefreshPayload(
                subscriptionHwid = subscriptionHwid,
                subscriptions = currentSubscriptions,
                locations = rebuiltLocations,
                refreshedCount = loadedByUrl.size,
                statusMessage = summary,
            ),
        )
    }

    suspend fun loadSubscriptionProfiles(rawSource: String, subscriptionHwid: String): List<ProxyProfile> {
        return SelectionWorkflowService.parseRemoteSourceLocations(
            rawSource = rawSource,
            resolveSource = { source ->
                when (val parsed = parseDirectRemoteSource(source)) {
                    is DirectRemoteSourceResolution -> ResolvedRemoteSource(
                        preview = parsed.preview,
                        fetchUrl = parsed.url,
                    )
                    is UnsupportedRemoteSourceResolution -> error(parsed.errorMessage)
                    null -> error("Remote source must be a valid https:// URL")
                }
            },
            fetchedContent = { url -> subscriptionContentFetcher.fetch(url, subscriptionHwid) },
        )
    }

    private fun profilesToDesktopLocations(
        sourceUrl: String,
        profiles: List<ProxyProfile>,
        existingLocations: List<DesktopLocationRecord>,
        startIndex: Int,
    ): Pair<List<DesktopLocationRecord>, Int> {
        val existingByKey = existingLocations
            .filter { it.sourceUrl == sourceUrl }
            .associateBy { it.normalizedStorageKey() }
        var nextIndex = startIndex
        val mapped = profiles.map { profile ->
            val rawLink = LocationConfigs.encodeStoredLocation(profile)
            val existing = existingByKey[LocationConfigs.normalizeStoredReference(rawLink)]
            DesktopLocationRecord(
                index = existing?.index ?: nextIndex++,
                sourceUrl = sourceUrl,
                rawLink = rawLink,
                name = profile.remarks,
                server = profile.server,
                details = profile.desktopDetails(),
                benchmarkDetail = existing?.benchmarkDetail ?: "Refreshed • not checked yet",
                isValid = existing?.isValid ?: true,
                isSelected = existing?.isSelected ?: false,
            )
        }
        return mapped to nextIndex
    }
}

internal fun subscriptionDisplayName(subscription: SubscriptionSource): String {
    return subscription.customName.ifBlank {
        displayRemoteSourceHost(subscription.url) ?: "Subscription"
    }
}

internal fun generateDesktopSubscriptionHwid(): String {
    return UUID.randomUUID().toString().replace("-", "")
}

internal fun DesktopLocationRecord.normalizedStorageKey(): String {
    return SelectionMappingLogic.normalizedStoredKey(rawLink)
}

internal fun nextLocationIndex(locations: List<DesktopLocationRecord>): Int {
    return (locations.maxOfOrNull(DesktopLocationRecord::index) ?: -1) + 1
}

internal fun ProxyProfile.desktopDetails(): String {
    val protocolLabel = when (protocol) {
        ProxyProtocol.VLESS -> "VLESS"
        ProxyProtocol.TROJAN -> "Trojan"
        ProxyProtocol.SHADOWSOCKS -> "Shadowsocks"
        ProxyProtocol.VMESS -> "VMess"
        ProxyProtocol.SOCKS -> "SOCKS"
        ProxyProtocol.CUSTOM -> "Custom"
    }
    val tags = buildList {
        security.takeIf { it.isNotBlank() && !it.equals("none", ignoreCase = true) }?.let {
            add(it.uppercase())
        }
        network.takeIf { it.isNotBlank() && !it.equals("tcp", ignoreCase = true) }?.let {
            add(it.uppercase())
        }
        if (protocol == ProxyProtocol.SHADOWSOCKS) {
            method.takeIf { it.isNotBlank() }?.let(::add)
        }
    }
    return (listOf(protocolLabel) + tags)
        .joinToString(" ")
        .trim()
}
