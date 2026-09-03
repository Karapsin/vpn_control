package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import com.kardinal.vpncontrol.AppScreen

@Composable
fun HomeTabScaffold(
    currentScreen: AppScreen,
    onOpenMainTab: () -> Unit,
    onOpenProfileTab: () -> Unit,
    onOpenLocationsTab: () -> Unit,
    onOpenStatsTab: () -> Unit,
    onOpenRoutingRules: () -> Unit,
    mainIcon: ImageVector,
    profileIcon: ImageVector,
    locationsIcon: ImageVector,
    statsIcon: ImageVector,
    rulesIcon: ImageVector,
    modifier: Modifier = Modifier,
    content: @Composable BoxScope.() -> Unit,
) {
    val strings = LocalAppStrings.current
    Scaffold(
        modifier = modifier.fillMaxSize(),
        containerColor = Color.Transparent,
        contentColor = Color.White,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        bottomBar = {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color(0xCC141F2D))
                    .navigationBarsPadding(),
            ) {
                TabRow(
                    selectedTabIndex = selectedTabIndex(currentScreen),
                    modifier = Modifier.fillMaxWidth(),
                    containerColor = Color.Transparent,
                    contentColor = Color.White,
                    divider = {},
                ) {
                    Tab(
                        modifier = Modifier.testTag("tab-main"),
                        selected = currentScreen == AppScreen.MAIN,
                        onClick = onOpenMainTab,
                        icon = {
                            Icon(imageVector = mainIcon, contentDescription = strings.get(UiText.TAB_MAIN))
                        },
                    )
                    Tab(
                        modifier = Modifier.testTag("tab-profile"),
                        selected = currentScreen == AppScreen.PROFILE,
                        onClick = onOpenProfileTab,
                        icon = {
                            Icon(imageVector = profileIcon, contentDescription = strings.get(UiText.TAB_PROFILE))
                        },
                    )
                    Tab(
                        modifier = Modifier.testTag("tab-locations"),
                        selected = currentScreen == AppScreen.LOCATIONS,
                        onClick = onOpenLocationsTab,
                        icon = {
                            Icon(imageVector = locationsIcon, contentDescription = strings.get(UiText.TAB_LOCATIONS))
                        },
                    )
                    Tab(
                        modifier = Modifier.testTag("tab-stats"),
                        selected = currentScreen == AppScreen.STATS,
                        onClick = onOpenStatsTab,
                        icon = {
                            Icon(imageVector = statsIcon, contentDescription = strings.get(UiText.TAB_STATS))
                        },
                    )
                    Tab(
                        modifier = Modifier.testTag("tab-rules"),
                        selected = currentScreen == AppScreen.ROUTING_RULES,
                        onClick = onOpenRoutingRules,
                        icon = {
                            Icon(imageVector = rulesIcon, contentDescription = strings.get(UiText.TAB_RULES))
                        },
                    )
                }
            }
        },
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .fillMaxSize()
                .padding(padding)
                .background(Color.Transparent),
            content = content,
        )
    }
}
