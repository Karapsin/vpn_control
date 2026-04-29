package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.InstalledApp

@Composable
fun RoutingRulesScreen(
    state: MainUiState,
    onIgnoreRulesChange: (Boolean) -> Unit,
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onNationalDomainsChange: (String) -> Unit,
    onDirectDomainsChange: (String) -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
    showAppAssignments: Boolean = true,
    controls: @Composable () -> Unit = {},
) {
    val strings = LocalAppStrings.current
    val query = state.routingAppSearch.trim().lowercase()
    val filteredApps = if (showAppAssignments) {
        state.installedApps
            .asSequence()
            .filter { app ->
                query.isBlank() ||
                    app.label.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
            }
            .sortedWith(
                compareBy<InstalledApp> { assignmentRank(it.packageName, state) }
                    .thenBy { it.isSystemApp }
                    .thenBy { it.label.lowercase() },
            )
            .toList()
    } else {
        emptyList()
    }

    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        contentColor = Color.White,
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 20.dp, top = 18.dp, end = 20.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            contentPadding = PaddingValues(bottom = 0.dp),
        ) {
            item {
                Button(
                    onClick = onSave,
                    enabled = !state.isBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = darkButtonColors(),
                ) {
                    Text(strings.get(UiText.SAVE_RULES))
                }
            }
            item {
                controls()
            }
            item {
                ScreenHeaderCard(
                    title = strings.get(UiText.ROUTING_RULES_TITLE),
                    description = if (!showAppAssignments) {
                        strings.get(UiText.ROUTING_DESCRIPTION_DESKTOP)
                    } else if (state.appMode == AppMode.VPN) {
                        strings.get(UiText.ROUTING_DESCRIPTION_VPN)
                    } else {
                        strings.get(UiText.ROUTING_DESCRIPTION_PROXY)
                    },
                )
            }
            item {
                CompactSummaryCard(state, showAppAssignments)
            }
            if (state.appMode == AppMode.PROXY_ONLY && showAppAssignments) {
                item {
                    ProxyOnlyRulesNoteCard()
                }
            }
            item {
                IgnoreRulesCard(
                    enabled = state.routingIgnoreRulesDraft,
                    appMode = state.appMode,
                    showAppAssignments = showAppAssignments,
                    onEnabledChange = onIgnoreRulesChange,
                )
            }
            if (showAppAssignments) {
                item {
                    AppSelectionSectionCard(
                        title = strings.get(UiText.APP_ASSIGNMENTS),
                        count = state.routingProxyPackagesDraft.size,
                        description = if (state.appMode == AppMode.VPN) {
                            strings.get(UiText.APP_ASSIGNMENTS_DESCRIPTION_VPN)
                        } else {
                            strings.get(UiText.APP_ASSIGNMENTS_DESCRIPTION_PROXY)
                        },
                        onSelectAll = onSelectAllProxyApps,
                        onClearAll = onClearAllProxyApps,
                        enableSelectAll = !state.installedAppsLoading && filteredApps.isNotEmpty(),
                        enableClearAll = !state.installedAppsLoading && state.routingProxyPackagesDraft.isNotEmpty(),
                    )
                }
            }
            item {
                RuleTextField(
                    title = strings.get(UiText.COUNTRY_CODE_DOMAINS),
                    description = strings.get(UiText.COUNTRY_CODE_DOMAINS_DESCRIPTION),
                    value = state.routingNationalDomainsDraft,
                    onValueChange = onNationalDomainsChange,
                )
            }
            item {
                RuleTextField(
                    title = strings.get(UiText.BYPASS_DOMAINS),
                    description = strings.get(UiText.BYPASS_DOMAINS_DESCRIPTION),
                    value = state.routingDirectDomainsDraft,
                    onValueChange = onDirectDomainsChange,
                )
            }
            if (showAppAssignments) {
                item {
                    Card(
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Text(strings.get(UiText.APP_ASSIGNMENTS), color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                                Text(
                                    strings.format(UiText.SHOWN_COUNT, filteredApps.size),
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            OutlinedTextField(
                                value = state.routingAppSearch,
                                onValueChange = onAppSearchChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text(strings.get(UiText.SEARCH_APPS_OR_PACKAGES)) },
                                singleLine = true,
                                colors = routingTextFieldColors(),
                            )
                            Text(
                                text = strings.get(UiText.APP_ASSIGNMENTS_HELP),
                                color = Color(0xFFD3E3EE),
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
                item {
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(320.dp),
                        shape = RoundedCornerShape(18.dp),
                        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
                    ) {
                        when {
                            state.installedAppsLoading -> {
                                Box(
                                    modifier = Modifier.fillMaxSize(),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    CircularProgressIndicator(color = Color.White)
                                }
                            }

                            filteredApps.isEmpty() -> {
                                Box(
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .padding(18.dp),
                                    contentAlignment = Alignment.Center,
                                ) {
                                    Text(
                                        text = if (state.installedAppsLoaded) {
                                            strings.get(UiText.NO_APPS_MATCH)
                                        } else {
                                            strings.get(UiText.APPS_NOT_LOADED)
                                        },
                                        color = Color(0xFFD3E3EE),
                                    )
                                }
                            }

                            else -> {
                                LazyColumn(
                                    modifier = Modifier.fillMaxSize(),
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 8.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    items(filteredApps, key = { it.packageName }) { app ->
                                        AppAssignmentRow(
                                            app = app,
                                            isProxy = app.packageName in state.routingProxyPackagesDraft,
                                            onToggleProxy = { onToggleProxyApp(app.packageName) },
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CompactSummaryCard(
    state: MainUiState,
    showAppAssignments: Boolean,
) {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(strings.get(UiText.CURRENT_RULES), color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            if (showAppAssignments) {
                Text(
                    strings.format(UiText.VPN_APPS_ASSIGNED, state.routingProxyPackagesDraft.size),
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                )
            }
            Text(
                strings.format(
                    UiText.DOMAIN_RULE_COUNTS,
                    state.routingNationalDomainsDraft.countEntries(),
                    state.routingDirectDomainsDraft.countEntries(),
                ),
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                if (!showAppAssignments) {
                    if (state.routingIgnoreRulesDraft) {
                        strings.get(UiText.IGNORE_RULES_ON_DOMAINS_ONLY)
                    } else {
                        strings.get(UiText.IGNORE_RULES_OFF_DOMAINS_ONLY)
                    }
                } else if (state.routingIgnoreRulesDraft) {
                    strings.get(UiText.IGNORE_RULES_ON_APPS)
                } else {
                    strings.get(UiText.IGNORE_RULES_OFF_APPS)
                },
                color = if (state.routingIgnoreRulesDraft) Color(0xFFFFE0A3) else Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            if (state.isVpnRunning) {
                Text(
                    text = if (state.appMode == AppMode.VPN) {
                        strings.get(UiText.RESTART_VPN_AFTER_RULES)
                    } else {
                        strings.get(UiText.RESTART_PROXY_AFTER_RULES)
                    },
                    color = Color(0xFFFFE0A3),
                    fontSize = 12.sp,
                )
            }
        }
    }
}

@Composable
private fun IgnoreRulesCard(
    enabled: Boolean,
    appMode: AppMode,
    showAppAssignments: Boolean,
    onEnabledChange: (Boolean) -> Unit,
) {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(strings.get(UiText.IGNORE_RULES), color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(
                    if (!showAppAssignments) {
                        if (enabled) {
                            strings.get(UiText.IGNORE_RULES_ON_DOMAINS_ONLY)
                        } else {
                            strings.get(UiText.IGNORE_RULES_OFF_DOMAINS_ONLY)
                        }
                    } else if (enabled) {
                        if (appMode == AppMode.VPN) {
                            strings.get(UiText.IGNORE_RULES_ON_APPS)
                        } else {
                            strings.get(UiText.IGNORE_RULES_ON_PROXY)
                        }
                    } else {
                        if (appMode == AppMode.VPN) {
                            strings.get(UiText.IGNORE_RULES_OFF_APPS)
                        } else {
                            strings.get(UiText.IGNORE_RULES_OFF_PROXY)
                        }
                    },
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = onEnabledChange,
            )
        }
    }
}

@Composable
private fun AppSelectionSectionCard(
    title: String,
    count: Int,
    description: String,
    onSelectAll: () -> Unit,
    onClearAll: () -> Unit,
    enableSelectAll: Boolean,
    enableClearAll: Boolean,
) {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(title, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(strings.format(UiText.SELECTED_COUNT, count), color = Color(0xFFD3E3EE), fontSize = 12.sp)
            }
            Text(description, color = Color(0xFFD3E3EE), fontSize = 12.sp)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(
                    onClick = onSelectAll,
                    enabled = enableSelectAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
                ) {
                    Text(strings.get(UiText.SELECT_ALL))
                }
                OutlinedButton(
                    onClick = onClearAll,
                    enabled = enableClearAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
                ) {
                    Text(strings.get(UiText.CLEAR_ALL))
                }
            }
        }
    }
}

@Composable
private fun ProxyOnlyRulesNoteCard() {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x332A3E12)),
        border = BorderStroke(1.dp, Color(0xFFFFC857)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = strings.get(UiText.PROXY_ONLY),
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = strings.get(UiText.PROXY_ONLY_RULES_DESCRIPTION),
                color = Color(0xFFFFF0CC),
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun RuleTextField(
    title: String,
    description: String,
    value: String,
    onValueChange: (String) -> Unit,
) {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(title, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(description, color = Color(0xFFD3E3EE), fontSize = 12.sp)
            OutlinedTextField(
                value = value,
                onValueChange = onValueChange,
                modifier = Modifier.fillMaxWidth(),
                minLines = 2,
                colors = routingTextFieldColors(),
            )
        }
    }
}

@Composable
private fun AppAssignmentRow(
    app: InstalledApp,
    isProxy: Boolean,
    onToggleProxy: () -> Unit,
) {
    val strings = LocalAppStrings.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                isProxy -> Color(0x333983FF)
                else -> Color(0x1F203041)
            },
        ),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(1.dp),
            ) {
                Text(
                    text = app.label,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = app.packageName,
                    color = Color(0xFFD3E3EE),
                    fontSize = 11.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = if (isProxy) strings.get(UiText.VPN_ON) else strings.get(UiText.VPN_OFF),
                    color = if (isProxy) Color(0xFF83B7FF) else Color(0xFFD3E3EE),
                    fontSize = 11.sp,
                )
                Switch(
                    checked = isProxy,
                    onCheckedChange = { onToggleProxy() },
                )
                if (app.isSystemApp) {
                    Text(
                        text = strings.get(UiText.SYSTEM_APP),
                        color = Color(0xFF9ED6FF),
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}

@Composable
private fun darkOutlinedButtonColors() = androidx.compose.material3.ButtonDefaults.outlinedButtonColors(
    contentColor = Color.White,
    disabledContentColor = Color(0xFF9FB8C8),
)

@Composable
private fun routingTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = Color.White,
    unfocusedTextColor = Color.White,
    disabledTextColor = Color(0xFFD3E3EE),
    cursorColor = Color(0xFF9ED6FF),
    focusedBorderColor = Color(0xFF9ED6FF),
    unfocusedBorderColor = Color(0xFF5F7D92),
    focusedLabelColor = Color(0xFF9ED6FF),
    unfocusedLabelColor = Color(0xFFD3E3EE),
    focusedPlaceholderColor = Color(0xFF9FB8C8),
    unfocusedPlaceholderColor = Color(0xFF9FB8C8),
)

private fun String.countEntries(): Int {
    return split(Regex("[,\\n\\r\\t ]+"))
        .map { it.trim() }
        .count { it.isNotBlank() }
}

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        else -> 1
    }
}
