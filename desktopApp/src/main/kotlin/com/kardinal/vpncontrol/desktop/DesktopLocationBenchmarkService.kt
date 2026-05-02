package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProfile

internal typealias DesktopLocationBenchmarker = suspend (
    profile: ProxyProfile,
    dnsSettings: DesktopDnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
) -> Result<ProfileBenchmark>

internal class DesktopLocationBenchmarkService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val benchmarkLocation: DesktopLocationBenchmarker,
    private val commitState: (nextState: MainUiState, nextLocations: List<DesktopLocationRecord>) -> Unit,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    suspend fun benchmark(index: Int) {
        val location = locationsProvider().firstOrNull { it.index == index } ?: return
        val profile = runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }
        if (profile.isFailure) {
            updateState { it.withStatus(profile.exceptionOrNull()?.message ?: "Invalid location config") }
            return
        }

        val state = stateProvider()
        updateState { it.copy(isBusy = true).withStatus("Testing ${location.name}...") }
        val validationSettings = state.validationSettings.normalized()
        val benchmark = benchmarkLocation(
            profile.getOrThrow(),
            DesktopDnsSettings(
                enabled = state.useCustomDns,
                value = state.customDns,
            ),
            BenchmarkUrls(
                primary = validationSettings.primaryUrl,
                secondary = validationSettings.secondaryUrl,
            ),
            validationSettings.toDesktopValidationSettings(),
        )

        if (benchmark.isSuccess) {
            val result = benchmark.getOrThrow()
            val updatedLocations = locationsProvider().map { existing ->
                if (existing.index == index) {
                    existing.copy(
                        benchmarkDetail = result.detail.toCompactBenchmarkLabel(),
                        isValid = result.primaryStatus == "ok",
                    )
                } else {
                    existing
                }
            }
            commitState(
                stateProvider().copy(isBusy = false).withStatus(
                    "Benchmarked ${location.name}: ${result.primaryStatus} / ${result.secondaryStatus}",
                ),
                updatedLocations,
            )
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    benchmark.exceptionOrNull()?.message ?: "Failed to benchmark ${location.name}",
                )
            }
        }
    }
}
