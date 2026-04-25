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
                    Text("Save Rules")
                }
            }
            item {
                controls()
            }
            item {
                ScreenHeaderCard(
                    title = "Routing Rules",
                    description = if (!showAppAssignments) {
                        "Choose domain bypass behavior for this desktop runtime. Per-app assignments are hidden on desktop because they need OS-level enforcement."
                    } else if (state.appMode == AppMode.VPN) {
                        "Choose which apps use the VPN and which domains bypass it. When Ignore Rules is on, normal app traffic goes through the VPN."
                    } else {
                        "Choose which domains go direct when using proxy-only mode. App assignments are still saved for VPN mode."
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
                        title = "App Assignments",
                        count = state.routingProxyPackagesDraft.size,
                        description = if (state.appMode == AppMode.VPN) {
                            "Only enabled apps use the VPN while Ignore Rules is off. Domain bypass rules still apply to those apps."
                        } else {
                            "Saved for VPN mode only. Proxy-only mode does not support per-app routing."
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
                    title = "Country-code Domains",
                    description = "One per line. Traffic to these domains goes directly, without VPN. Example: ru",
                    value = state.routingNationalDomainsDraft,
                    onValueChange = onNationalDomainsChange,
                )
            }
            item {
                RuleTextField(
                    title = "Bypass Domains",
                    description = "One per line. Traffic to these domains goes directly, without VPN. Example: magnit.com",
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
                                Text("App Assignments", color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                                Text(
                                    "${filteredApps.size} shown",
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            OutlinedTextField(
                                value = state.routingAppSearch,
                                onValueChange = onAppSearchChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Search apps or packages") },
                                singleLine = true,
                                colors = routingTextFieldColors(),
                            )
                            Text(
                                text = "Turn apps on to route them through the VPN. Assigned apps are listed first.",
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
                                            "No apps match the current search."
                                        } else {
                                            "Installed apps have not loaded yet."
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
            Text("Current Rules", color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            if (showAppAssignments) {
                Text(
                    "${state.routingProxyPackagesDraft.size} VPN apps assigned",
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                )
            }
            Text(
                "${state.routingNationalDomainsDraft.countEntries()} country-code domains • " +
                    "${state.routingDirectDomainsDraft.countEntries()} bypass domains",
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                if (!showAppAssignments) {
                    if (state.routingIgnoreRulesDraft) {
                        "Ignore rules is on. Domain rules are saved but not applied."
                    } else {
                        "Ignore rules is off. Domain rules are active."
                    }
                } else if (state.routingIgnoreRulesDraft) {
                    "Ignore rules is on. App/domain rules are saved but not applied."
                } else {
                    "Ignore rules is off. Only assigned apps use the VPN and saved domain rules are active."
                },
                color = if (state.routingIgnoreRulesDraft) Color(0xFFFFE0A3) else Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            if (state.isVpnRunning) {
                Text(
                    text = if (state.appMode == AppMode.VPN) {
                        "Restart the VPN after saving or importing rules."
                    } else {
                        "Restart the local proxy after saving or importing rules."
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
                Text("Ignore Rules", color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                Text(
                    if (!showAppAssignments) {
                        if (enabled) {
                            "Desktop domain rules are ignored."
                        } else {
                            "Desktop domain rules are applied."
                        }
                    } else if (enabled) {
                        if (appMode == AppMode.VPN) {
                            "Saved app assignments and domain rules are ignored. Normal app traffic goes through the VPN."
                        } else {
                            "User-defined domain rules are ignored. Proxy-only mode sends all proxied traffic through the selected connection."
                        }
                    } else {
                        if (appMode == AppMode.VPN) {
                            "Only assigned apps use the VPN. Saved domain rules are applied."
                        } else {
                            "User-defined domain rules are applied. App assignments stay saved for VPN mode."
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
                Text("$count selected", color = Color(0xFFD3E3EE), fontSize = 12.sp)
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
                    Text("Select All")
                }
                OutlinedButton(
                    onClick = onClearAll,
                    enabled = enableClearAll,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(14.dp),
                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                    colors = darkOutlinedButtonColors(),
                ) {
                    Text("Clear All")
                }
            }
        }
    }
}

@Composable
private fun ProxyOnlyRulesNoteCard() {
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
                text = "Proxy-only mode",
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = "Only domain rules apply in proxy-only mode. App assignments are kept for when you switch back to VPN mode.",
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
                    text = if (isProxy) "VPN on" else "VPN off",
                    color = if (isProxy) Color(0xFF83B7FF) else Color(0xFFD3E3EE),
                    fontSize = 11.sp,
                )
                Switch(
                    checked = isProxy,
                    onCheckedChange = { onToggleProxy() },
                )
                if (app.isSystemApp) {
                    Text(
                        text = "System",
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
