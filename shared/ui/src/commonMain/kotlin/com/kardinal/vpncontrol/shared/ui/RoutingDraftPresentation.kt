package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.RoutingRules

internal fun routingDirectDomainCount(state: MainUiState): Int =
    state.routingDirectDomainSuffixesDraft?.size
        ?: RoutingRules.parseDirectDomainSuffixes(state.routingDirectDomainsDraft).size

/** Summary composition must not retain the full immutable routing document. */
internal data class RoutingSummaryPresentation(
    val directDomainCount: Int,
    val proxyAppCount: Int,
    val ignoreRules: Boolean,
    val ignoreRulesDescription: String,
    val restartDescription: String?,
)

internal fun routingSummaryPresentation(
    state: MainUiState,
    showAppAssignments: Boolean,
    strings: AppStrings,
) = RoutingSummaryPresentation(
    directDomainCount = routingDirectDomainCount(state),
    proxyAppCount = state.routingProxyPackagesDraft.size,
    ignoreRules = state.routingIgnoreRulesDraft,
    ignoreRulesDescription = ignoreRulesDescription(state, showAppAssignments, strings),
    restartDescription = if (!state.isVpnRunning) null else strings.get(
        if (state.appMode == AppMode.VPN) UiText.RESTART_VPN_AFTER_RULES else UiText.RESTART_PROXY_AFTER_RULES,
    ),
)
