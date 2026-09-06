package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import com.kardinal.vpncontrol.model.RoutingRules

/** Immutable runtime inputs. Presentation drafts, names and telemetry are deliberately excluded. */
data class ControlRuntimeConfiguration(
    val locationReference: String,
    val sourceReference: String,
    val mode: AppMode,
    val routing: RoutingRules,
    val dns: DnsSettings,
    val ssh: HomeSshRouteSettings,
) {
    override fun toString(): String = "ControlRuntimeConfiguration(<redacted>)"

    fun hasPendingChanges(state: MainUiState): Boolean = this != committed(state)

    companion object {
        fun committed(state: MainUiState): ControlRuntimeConfiguration = ControlRuntimeConfiguration(
            state.selectedProfileRawLink, state.selectedProfileSourceUrl, state.appMode,
            state.routingRules, state.dnsSettings, state.homeSshRouteSettings,
        )
    }
}
