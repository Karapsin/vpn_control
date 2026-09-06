package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.BenchmarkStatusMessages
import com.kardinal.vpncontrol.model.LocationStatusMessages
import com.kardinal.vpncontrol.LocationStatusLogic
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.BenchmarkUrls
import com.kardinal.vpncontrol.data.LocationConfigs
import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProxyProfile

internal typealias DesktopLocationBenchmarker = suspend (
    profile: ProxyProfile,
    dnsSettings: DnsSettings,
    benchmarkUrls: BenchmarkUrls,
    settings: DesktopValidationSettings,
) -> Result<ProfileBenchmark>

internal class DesktopLocationBenchmarkService(
    private val stateProvider: () -> MainUiState,
    private val locationsProvider: () -> List<DesktopLocationRecord>,
    private val benchmarkLocation: DesktopLocationBenchmarker,
    private val commitState: (nextState: MainUiState, nextLocations: List<DesktopLocationRecord>) -> Result<Unit>,
    private val updateState: ((MainUiState) -> MainUiState) -> Unit,
) {
    suspend fun benchmark(index: Int, expectedLocation: DesktopLocationRecord? = null): Result<ProfileBenchmark> {
        if (stateProvider().isBusy) return Result.failure(IllegalStateException("BUSY"))
        val location = locationsProvider().firstOrNull { it.index == index }
            ?: return Result.failure(IllegalArgumentException(if (expectedLocation == null) "NOT_FOUND" else "CONFLICT"))
        if (expectedLocation != null && !location.sameConfiguration(expectedLocation)) {
            return Result.failure(IllegalStateException("CONFLICT"))
        }
        val profile = runCatching { LocationConfigs.decodeStoredLocation(location.rawLink) }
        if (profile.isFailure) {
            updateState { it.withStatus(LocationStatusMessages.invalidLocationConfig()) }
            return Result.failure(IllegalArgumentException("INVALID_ARGUMENT"))
        }

        val state = stateProvider()
        updateState { it.copy(isBusy = true).withStatus(LocationStatusLogic.testingLocation(location.name)) }
        val validationSettings = state.validationSettings.normalized()
        val benchmark = try {
            benchmarkLocation(
                profile.getOrThrow(),
                state.dnsSettings,
                BenchmarkUrls(test = validationSettings.testUrl),
                validationSettings.toDesktopValidationSettings(),
            )
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            updateState { it.copy(isBusy = false) }
            throw cancelled
        } catch (_: Exception) {
            Result.failure(IllegalStateException("BENCHMARK_FAILED"))
        }

        if (benchmark.isSuccess) {
            val result = benchmark.getOrThrow()
            val currentLocations = locationsProvider()
            val currentTarget = currentLocations.singleOrNull { it.sameConfiguration(location) }
            if (currentTarget == null) {
                updateState { it.copy(isBusy = false) }
                return Result.failure(IllegalStateException("CONFLICT"))
            }
            val updatedLocations = currentLocations.map { existing ->
                if (existing === currentTarget) {
                    existing.copy(
                        benchmarkDetail = result.detail.toCompactBenchmarkLabel(),
                        isValid = result.testStatus == "ok",
                    )
                } else {
                    existing
                }
            }
            return commitState(
                stateProvider().copy(isBusy = false).withStatus(
                    BenchmarkStatusMessages.benchmarkedLocation(location.name, result.testStatus),
                ),
                updatedLocations,
            ).map { result }.onFailure { updateState { it.copy(isBusy = false) } }
        } else {
            updateState {
                it.copy(isBusy = false).withStatus(
                    BenchmarkStatusMessages.benchmarkLocationFailed(location.name),
                )
            }
            return Result.failure(IllegalStateException("BENCHMARK_FAILED"))
        }
    }

    private fun DesktopLocationRecord.sameConfiguration(other: DesktopLocationRecord): Boolean =
        sourceUrl == other.sourceUrl && rawLink == other.rawLink
}
