package com.kardinal.vpncontrol.model

object BenchmarkStatusMessages {
    fun noLocationsAvailableForBenchmarking(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_LOCATIONS_AVAILABLE_FOR_BENCHMARKING)

    fun bestLocationSearchTimedOut(): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_SEARCH_TIMED_OUT)

    fun retryingBestLocationSearch(attempt: Int, total: Int): String =
        StatusMessageCodec.encode(
            StatusMessageKey.RETRYING_BEST_LOCATION_SEARCH,
            attempt.coerceAtLeast(1).toString(),
            total.coerceAtLeast(1).toString(),
        )

    fun locationSearchCancelled(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_SEARCH_CANCELLED)

    fun locationSearchFailed(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_SEARCH_FAILED)

    fun locationSearchCancelledStopFailed(appMode: AppMode, detail: String = ""): String =
        StatusMessageCodec.encode(StatusMessageKey.LOCATION_SEARCH_CANCELLED_STOP_FAILED, appMode.name, detail)

    fun vpnPermissionRequired(): String =
        StatusMessageCodec.encode(StatusMessageKey.VPN_PERMISSION_REQUIRED)

    fun noSuitableLocationFound(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_SUITABLE_LOCATION_FOUND)

    fun bestLocationNotMapped(): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_NOT_MAPPED)

    fun loadingSavedLocations(): String =
        StatusMessageCodec.encode(StatusMessageKey.LOADING_SAVED_LOCATIONS)

    fun downloadingRemoteSource(): String =
        StatusMessageCodec.encode(StatusMessageKey.DOWNLOADING_REMOTE_SOURCE)

    fun resolvingRemoteSource(sourceLabel: String): String =
        StatusMessageCodec.encode(StatusMessageKey.RESOLVING_REMOTE_SOURCE, sourceLabel)

    fun subscriptionSourceLoadFailed(sourceLabel: String): String =
        StatusMessageCodec.encode(StatusMessageKey.SUBSCRIPTION_SOURCE_LOAD_FAILED, sourceLabel)

    fun noLocationsFoundSelectedSubscription(): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_LOCATIONS_FOUND_SELECTED_SUBSCRIPTION)

    fun noLocationsFoundInSource(sourceLabel: String): String =
        StatusMessageCodec.encode(StatusMessageKey.NO_LOCATIONS_FOUND_IN_SOURCE, sourceLabel)

    fun checkingTcpSpeed(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.CHECKING_TCP_SPEED, remarks)

    fun checkingLocations(count: Int): String =
        StatusMessageCodec.encode(StatusMessageKey.CHECKING_LOCATIONS, count.toString())

    fun checkingLocationSource(count: Int, sourceLabel: String): String =
        StatusMessageCodec.encode(StatusMessageKey.CHECKING_LOCATION_SOURCE, count.toString(), sourceLabel)

    fun testingFastestCandidates(): String =
        StatusMessageCodec.encode(StatusMessageKey.TESTING_FASTEST_CANDIDATES)

    fun testingLocationsRange(start: Int, end: Int, total: Int): String =
        StatusMessageCodec.encode(StatusMessageKey.TESTING_LOCATIONS_RANGE, start.toString(), end.toString(), total.toString())

    fun findBestTestingFastest(sourceMode: ProfileSourceMode): String =
        StatusMessageCodec.encode(StatusMessageKey.FIND_BEST_TESTING_FASTEST, sourceMode.name)

    fun detectingCountry(): String =
        StatusMessageCodec.encode(StatusMessageKey.DETECTING_COUNTRY)

    fun excludingSameCountryLocations(count: Int): String =
        StatusMessageCodec.encode(StatusMessageKey.EXCLUDING_SAME_COUNTRY_LOCATIONS, count.coerceAtLeast(0).toString())

    fun tryingBestCandidate(attempt: Int, total: Int, remarks: String): String =
        StatusMessageCodec.encode(
            StatusMessageKey.TRYING_BEST_CANDIDATE,
            attempt.coerceAtLeast(1).toString(),
            total.coerceAtLeast(1).toString(),
            remarks,
        )

    fun verifyingBlockedResource(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.VERIFYING_BLOCKED_RESOURCE, remarks)

    fun switchingAfterVerificationFailure(remarks: String): String =
        StatusMessageCodec.encode(StatusMessageKey.SWITCHING_AFTER_VERIFICATION_FAILURE, remarks)

    fun bestLocationSummary(remarks: String, detail: String): String =
        StatusMessageCodec.encode(StatusMessageKey.BEST_LOCATION_SUMMARY, remarks, detail)

    fun benchmarkedLocation(locationName: String, testStatus: String): String =
        StatusMessageCodec.encode(StatusMessageKey.BENCHMARKED_LOCATION, locationName, testStatus)

    fun benchmarkLocationFailed(locationName: String): String =
        StatusMessageCodec.encode(StatusMessageKey.BENCHMARK_LOCATION_FAILED, locationName)
}
