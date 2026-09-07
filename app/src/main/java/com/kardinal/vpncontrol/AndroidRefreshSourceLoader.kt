package com.kardinal.vpncontrol

import android.content.Context
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import kotlinx.serialization.json.*

internal fun androidRefreshManagementPort(runtimeJson: String): Int? =
    (Json.parseToJsonElement(runtimeJson).jsonObject["inbounds"] as? JsonArray)
        ?.mapNotNull { it as? JsonObject }
        ?.filter { it["tag"]?.jsonPrimitive?.content in setOf(HomeSshRouteConfigBuilder.MANAGEMENT_INBOUND_TAG, "active-verify-in") &&
            it["type"]?.jsonPrimitive?.content == "mixed" && it["listen"]?.jsonPrimitive?.content == "127.0.0.1" }
        ?.singleOrNull()
        ?.get("listen_port")?.jsonPrimitive?.intOrNull?.takeIf { it in 1..65535 }

internal fun androidRefreshRouteState(committed: PersistedState, observed: AndroidRuntimeObservation,
    point: AndroidRuntimeRestorePoint?, managementPort: Int?): PersistedState = when (observed.knowledge) {
    AndroidRuntimeKnowledge.UNKNOWN -> error("RUNTIME_STATE_UNKNOWN")
    AndroidRuntimeKnowledge.STOPPED -> { check(point == null) { "RUNTIME_COMMAND_STALE" }; committed.copy(isVpnRunning = false) }
    AndroidRuntimeKnowledge.RUNNING -> {
        check(point != null && point.observation == observed) { "RUNTIME_STATE_UNKNOWN" }
        check(managementPort != null && managementPort in 1..65535) { "ACTIVE_MANAGEMENT_ROUTE_UNAVAILABLE" }
        committed.copy(isVpnRunning = true, homeSshRouteSettings = point.configuration.ssh, managementProxyPort = managementPort)
    }
}

internal class AndroidRefreshSourceLoader(private val context: Context, private val storage: ProfileStorage,
    private val observer: AndroidRuntimeObserver) {
    suspend fun prepare(committed: PersistedState, point: AndroidRuntimeRestorePoint?): suspend (SubscriptionSource) -> List<String> {
        val observed = observer.state.value
        check(observed.knowledge != AndroidRuntimeKnowledge.UNKNOWN) { "RUNTIME_STATE_UNKNOWN" }
        val route = if (observed.knowledge == AndroidRuntimeKnowledge.RUNNING) {
            check(point != null && point.observation == observed) { "RUNTIME_STATE_UNKNOWN" }
            val port = androidRefreshManagementPort(point.runtimeJson) ?: error("ACTIVE_MANAGEMENT_ROUTE_UNAVAILABLE")
            androidRefreshRouteState(committed, observed, point, port)
        } else androidRefreshRouteState(committed, observed, point, null)
        val client = SubscriptionDownloadClient("VPNControl/1.0 (Android)", context, stateProvider = { route })
        val hwid = storage.ensureSubscriptionHwid()
        return { source ->
            check(observer.state.value == observed) { "RUNTIME_COMMAND_STALE" }
            val profiles = SelectionWorkflowService.parseRemoteSourceLocations(source.url, RemoteSourceResolver::resolveForFetch) { url ->
                client.fetch(url, subscriptionHwid = hwid)
            }
            check(observer.state.value == observed) { "RUNTIME_COMMAND_STALE" }
            profiles.map(LocationConfigs::encodeStoredLocation)
        }
    }
}
