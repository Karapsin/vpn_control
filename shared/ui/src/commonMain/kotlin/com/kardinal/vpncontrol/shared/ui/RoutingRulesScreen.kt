package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.RoutingRules

@Composable
fun RoutingRulesScreen(
    state: MainUiState,
    onAppSearchChange: (String) -> Unit,
    onToggleProxyApp: (String) -> Unit,
    onSelectAllProxyApps: () -> Unit,
    onClearAllProxyApps: () -> Unit,
    onDirectDomainsChange: (String) -> Unit,
    onBlockQuicUdp443Change: (Boolean) -> Unit,
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
                DirectDomainTagCloud(
                    value = state.routingDirectDomainsDraft,
                    onValueChange = onDirectDomainsChange,
                )
            }
            if (showAppAssignments && state.appMode == AppMode.VPN) {
                item {
                    QuicCompatibilityCard(
                        enabled = state.routingBlockQuicUdp443Draft,
                        onEnabledChange = onBlockQuicUdp443Change,
                    )
                }
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
                                    strings.format(UiText.SELECTED_COUNT, state.routingProxyPackagesDraft.size),
                                    color = Color(0xFFD3E3EE),
                                    fontSize = 12.sp,
                                )
                            }
                            Text(
                                text = if (state.appMode == AppMode.VPN) {
                                    strings.get(UiText.APP_ASSIGNMENTS_DESCRIPTION_VPN)
                                } else {
                                    strings.get(UiText.APP_ASSIGNMENTS_DESCRIPTION_PROXY)
                                },
                                color = Color(0xFFD3E3EE),
                                fontSize = 12.sp,
                            )
                            OutlinedTextField(
                                value = state.routingAppSearch,
                                onValueChange = onAppSearchChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text(strings.get(UiText.SEARCH_APPS_OR_PACKAGES)) },
                                singleLine = true,
                                colors = routingTextFieldColors(),
                            )
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                OutlinedButton(
                                    onClick = onSelectAllProxyApps,
                                    enabled = !state.installedAppsLoading && filteredApps.isNotEmpty(),
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp),
                                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                                    colors = darkOutlinedButtonColors(),
                                ) {
                                    Text(strings.get(UiText.SELECT_ALL))
                                }
                                OutlinedButton(
                                    onClick = onClearAllProxyApps,
                                    enabled = !state.installedAppsLoading && state.routingProxyPackagesDraft.isNotEmpty(),
                                    modifier = Modifier.weight(1f),
                                    shape = RoundedCornerShape(14.dp),
                                    border = BorderStroke(1.dp, Color(0xFF9ED6FF)),
                                    colors = darkOutlinedButtonColors(),
                                ) {
                                    Text(strings.get(UiText.CLEAR_ALL))
                                }
                            }
                            Text(
                                text = strings.get(UiText.APP_ASSIGNMENTS_HELP),
                                color = Color(0xFFD3E3EE),
                                fontSize = 12.sp,
                            )
                            Text(
                                strings.format(UiText.SHOWN_COUNT, filteredApps.size),
                                color = Color(0xFFD3E3EE),
                                fontSize = 12.sp,
                            )
                            Box(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(320.dp),
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
                                            contentPadding = PaddingValues(vertical = 8.dp),
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
    }
}

@Composable
private fun QuicCompatibilityCard(
    enabled: Boolean,
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
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = strings.get(UiText.QUIC_COMPATIBILITY),
                    color = Color.White,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = strings.get(UiText.QUIC_COMPATIBILITY_DESCRIPTION),
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
                Text(
                    text = strings.get(UiText.BLOCK_QUIC_UDP_443_HELP),
                    color = Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                )
            }
            Column(
                horizontalAlignment = Alignment.End,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(
                    text = strings.get(UiText.BLOCK_QUIC_UDP_443),
                    color = if (enabled) Color(0xFF83B7FF) else Color(0xFFD3E3EE),
                    fontSize = 12.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Switch(
                    checked = enabled,
                    onCheckedChange = onEnabledChange,
                )
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
                    RoutingRules.parseDirectDomainSuffixes(state.routingDirectDomainsDraft).size,
                ),
                color = Color(0xFFD3E3EE),
                fontSize = 13.sp,
            )
            Text(
                ignoreRulesDescription(state, showAppAssignments, strings),
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
private fun ProxyOnlyRulesNoteCard() {
    val strings = LocalAppStrings.current
    Card(
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x33421F0A)),
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

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun DirectDomainTagCloud(
    value: String,
    onValueChange: (String) -> Unit,
) {
    val strings = LocalAppStrings.current
    val domains = remember(value) {
        RoutingRules.parseDirectDomainSuffixes(value).sortedForDirectDomainCloud()
    }
    var input by remember { mutableStateOf("") }
    var isAdding by remember { mutableStateOf(false) }
    val inputFocusRequester = remember { FocusRequester() }

    LaunchedEffect(isAdding) {
        if (isAdding) {
            inputFocusRequester.requestFocus()
        }
    }

    fun emitDomains(nextDomains: List<String>) {
        onValueChange(nextDomains.sortedForDirectDomainCloud().joinToString(separator = "\n"))
    }

    fun commitInput() {
        val normalized = RoutingRules.parseDirectDomainSuffixes(input)
        if (normalized.isEmpty()) {
            isAdding = false
            return
        }
        emitDomains(domains + normalized)
        input = ""
        isAdding = false
    }

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
            Text(strings.get(UiText.BYPASS_DOMAINS), color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Bold)
            Text(strings.get(UiText.BYPASS_DOMAINS_DESCRIPTION), color = Color(0xFFD3E3EE), fontSize = 12.sp)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                domains.forEach { domain ->
                    DirectDomainChip(
                        domain = domain,
                        onRemove = { emitDomains(domains.filterNot { it == domain }) },
                    )
                }
                if (isAdding) {
                    DirectDomainInputChip(
                        value = input,
                        focusRequester = inputFocusRequester,
                        onValueChange = { input = it },
                        onCommit = ::commitInput,
                        onCancel = {
                            input = ""
                            isAdding = false
                        },
                    )
                } else {
                    DirectDomainAddChip(
                        onClick = { isAdding = true },
                    )
                }
            }
        }
    }
}

@Composable
private fun DirectDomainChip(
    domain: String,
    onRemove: () -> Unit,
) {
    Row(
        modifier = Modifier
            .background(Color(0x333983FF), RoundedCornerShape(14.dp))
            .height(32.dp)
            .padding(start = 10.dp, end = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = domain,
            modifier = Modifier.widthIn(max = 220.dp),
            color = Color.White,
            fontSize = 13.sp,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
        TextButton(
            onClick = onRemove,
            modifier = Modifier.size(28.dp),
            contentPadding = PaddingValues(0.dp),
        ) {
            Text("x", color = Color(0xFFD3E3EE), fontSize = 13.sp)
        }
    }
}

@Composable
private fun DirectDomainAddChip(
    onClick: () -> Unit,
) {
    Box(
        modifier = Modifier
            .background(Color(0x1F9ED6FF), RoundedCornerShape(14.dp))
            .height(32.dp)
            .defaultMinSize(minWidth = 44.dp)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = onClick,
            )
            .padding(horizontal = 14.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text("+", color = Color(0xFFD3E3EE), fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun DirectDomainInputChip(
    value: String,
    focusRequester: FocusRequester,
    onValueChange: (String) -> Unit,
    onCommit: () -> Unit,
    onCancel: () -> Unit,
) {
    val visibleLength = if (value.isBlank()) "domain".length else value.length
    val width = ((visibleLength.coerceIn(2, 24) * 8) + 44).dp
    BasicTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = Modifier
            .width(width)
            .focusRequester(focusRequester)
            .onPreviewKeyEvent { event ->
                if (event.type == KeyEventType.KeyUp && event.key == Key.Enter) {
                    onCommit()
                    true
                } else {
                    false
                }
            },
        singleLine = true,
        textStyle = TextStyle(color = Color.White, fontSize = 13.sp),
        cursorBrush = SolidColor(Color(0xFF9ED6FF)),
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { onCommit() }),
        decorationBox = { innerTextField ->
            Row(
                modifier = Modifier
                    .background(Color(0x333983FF), RoundedCornerShape(14.dp))
                    .height(32.dp)
                    .padding(start = 10.dp, end = 2.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Box(modifier = Modifier.weight(1f)) {
                    if (value.isBlank()) {
                        Text(
                            text = "domain",
                            color = Color(0xFF9FB8C8),
                            fontSize = 13.sp,
                            maxLines = 1,
                        )
                    }
                    innerTextField()
                }
                TextButton(
                    onClick = onCancel,
                    modifier = Modifier.size(28.dp),
                    contentPadding = PaddingValues(0.dp),
                ) {
                    Text("x", color = Color(0xFFD3E3EE), fontSize = 13.sp)
                }
            }
        },
    )
}

private fun List<String>.sortedForDirectDomainCloud(): List<String> {
    return distinct()
        .sortedWith(
            compareByDescending<String> { it.isSingleLabelDomainSuffix() }
                .thenBy { it },
        )
}

private fun String.isSingleLabelDomainSuffix(): Boolean {
    return trim('.').isNotBlank() && '.' !in trim('.')
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

private fun assignmentRank(packageName: String, state: MainUiState): Int {
    return when {
        packageName in state.routingProxyPackagesDraft -> 0
        else -> 1
    }
}
