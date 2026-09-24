package com.kardinal.vpncontrol

import android.content.Context
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import kotlinx.serialization.json.*
import java.io.IOException
import java.security.cert.CertificateException
import java.util.Collections
import java.util.IdentityHashMap
import javax.net.ssl.SSLException

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

internal fun androidRefreshFailure(error: Throwable): SubscriptionRefreshFailureException {
    if (error is SubscriptionRefreshFailureException) return error
    val seen = Collections.newSetFromMap(IdentityHashMap<Throwable, Boolean>())
    val chain = mutableListOf<Throwable>()
    var current: Throwable? = error
    while (current != null && chain.size < 16 && seen.add(current)) {
        chain += current
        current = current.cause
    }
    val reason = when {
        chain.any { it.message in setOf("RUNTIME_STATE_UNKNOWN", "RUNTIME_COMMAND_STALE", "ACTIVE_MANAGEMENT_ROUTE_UNAVAILABLE") } ->
            SubscriptionRefreshFailureReason.PREPARATION
        chain.any { it is SSLException || it is CertificateException } -> SubscriptionRefreshFailureReason.TLS
        chain.any { it is IOException } -> SubscriptionRefreshFailureReason.CONNECTIVITY
        else -> SubscriptionRefreshFailureReason.OTHER
    }
    return SubscriptionRefreshFailureException(reason, error)
}

internal class AndroidRefreshSourceLoader(private val context: Context, private val storage: ProfileStorage,
    private val observer: AndroidRuntimeObserver) {
    suspend fun prepare(committed: PersistedState, point: AndroidRuntimeRestorePoint?): suspend (SubscriptionSource) -> List<String> {
        try {
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
            if (observer.state.value != observed) {
                throw SubscriptionRefreshFailureException(SubscriptionRefreshFailureReason.PREPARATION)
            }
            val profiles = SelectionWorkflowService.parseRemoteSourceLocations(
                source.url,
                RemoteSourceResolver::resolveForFetch,
                { url ->
                    try {
                        client.fetch(url, subscriptionHwid = hwid)
                    } catch (cancel: kotlinx.coroutines.CancellationException) {
                        throw cancel
                    } catch (error: Exception) {
                        throw androidRefreshFailure(error)
                    }
                },
                parsedContentFailure = { error ->
                    SubscriptionRefreshFailureException(SubscriptionRefreshFailureReason.PARSE, error)
                },
            )
            if (observer.state.value != observed) {
                throw SubscriptionRefreshFailureException(SubscriptionRefreshFailureReason.PREPARATION)
            }
            val encoded = profiles.map(LocationConfigs::encodeStoredLocation)
            if (encoded.isEmpty()) throw SubscriptionRefreshFailureException(SubscriptionRefreshFailureReason.PARSE)
            encoded
        }
        } catch (cancel: kotlinx.coroutines.CancellationException) {
            throw cancel
        } catch (failure: SubscriptionRefreshFailureException) {
            throw failure
        } catch (error: Exception) {
            throw SubscriptionRefreshFailureException(SubscriptionRefreshFailureReason.PREPARATION, error)
        }
    }
}
