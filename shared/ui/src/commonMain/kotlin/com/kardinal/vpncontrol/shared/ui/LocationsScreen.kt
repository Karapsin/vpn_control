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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.SelectionMappingLogic

data class SavedLocationRow(
    val index: Int,
    val rawLink: String,
    val name: String,
    val server: String,
    val details: String,
    val benchmarkDetail: String,
    val autoSelectable: Boolean,
    val isSelected: Boolean,
)

internal data class SavedLocationVisualState(
    val isSelected: Boolean,
    val isInUse: Boolean,
    val togglesConnection: Boolean,
)

@Suppress("UNUSED_PARAMETER")
internal fun savedLocationManualActionEnabled(
    appEnabled: Boolean,
    autoSelectable: Boolean,
): Boolean = appEnabled

internal fun savedLocationVisualState(
    location: SavedLocationRow,
    state: MainUiState,
): SavedLocationVisualState {
    val selectedKey = SelectionMappingLogic.selectedStoredKey(
        selectedProfileJson = state.selectedProfileJson,
        selectedProfileRawLink = state.selectedProfileRawLink,
    )
    val normalizedSelectedKey = SelectionMappingLogic.normalizedStoredKey(selectedKey)
    val matchesPersistedSelection = selectedKey.isNotBlank() &&
        (
            location.rawLink == state.selectedProfileRawLink ||
                location.rawLink == selectedKey ||
                SelectionMappingLogic.normalizedStoredKey(location.rawLink) == normalizedSelectedKey
            )
    val fallbackSelected = selectedKey.isBlank() && !state.isVpnRunning && location.isSelected
    val isSelected = matchesPersistedSelection || fallbackSelected
    val isInUse = state.isVpnRunning && matchesPersistedSelection
    return SavedLocationVisualState(
        isSelected = isSelected,
        isInUse = isInUse,
        togglesConnection = isInUse || (!state.isVpnRunning && isSelected),
    )
}

@Composable
fun LocationsScreen(
    state: MainUiState,
    locations: List<SavedLocationRow>,
    selectedName: String?,
    activeProfileLabel: String,
    showSubscriptionMismatchWarning: Boolean,
    onShowAddLocation: (() -> Unit)?,
    onToggleSelectedLocationVpn: () -> Unit,
    onBenchmarkLocation: (Int) -> Unit,
    onSelectLocation: (Int) -> Unit,
    onEditLocation: (Int) -> Unit,
    onDeleteLocation: (Int) -> Unit,
    modifier: Modifier = Modifier,
    controls: @Composable () -> Unit = {},
) {
    val strings = LocalAppStrings.current
    Scaffold(
        modifier = modifier,
        containerColor = Color.Transparent,
        contentColor = Color.White,
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(start = 20.dp, top = 24.dp, end = 20.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            ScreenHeaderCard(
                title = strings.get(UiText.LOCATIONS_TITLE),
                description = if (state.profileSourceMode == com.kardinal.vpncontrol.model.ProfileSourceMode.SUBSCRIPTION) {
                    strings.get(UiText.LOCATIONS_DESCRIPTION_SUBSCRIPTION)
                } else {
                    strings.get(UiText.LOCATIONS_DESCRIPTION_SAVED)
                },
                footer = {
                    Text(
                        strings.format(UiText.SAVED_LOCATIONS_COUNT, locations.size),
                        color = Color(0xFF9ED6FF),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = if (selectedName.isNullOrBlank()) {
                            strings.get(UiText.SELECTED_NONE)
                        } else {
                            strings.format(UiText.SELECTED_VALUE, selectedName)
                        },
                        color = Color(0xFFD3E3EE),
                        fontSize = 13.sp,
                    )
                },
            )

            if (showSubscriptionMismatchWarning) {
                SubscriptionMismatchWarningCard(activeProfileLabel = activeProfileLabel)
            }

            onShowAddLocation?.let { onClick ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Button(
                        onClick = onClick,
                        enabled = !state.isBusy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(18.dp),
                    ) {
                        Text(strings.get(UiText.ADD_LOCATION))
                    }
                }
            }

            controls()

            Card(
                modifier = Modifier.fillMaxSize(),
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
            ) {
                if (locations.isEmpty()) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(20.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            text = if (state.profileSourceMode == com.kardinal.vpncontrol.model.ProfileSourceMode.SUBSCRIPTION) {
                                strings.get(UiText.NO_LOCATIONS_CACHED)
                            } else {
                                strings.get(UiText.NO_SAVED_LOCATIONS)
                            },
                            color = Color(0xFFD3E3EE),
                        )
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(locations, key = { "${it.index}:${it.rawLink}" }) { location ->
                            val visualState = savedLocationVisualState(location, state)
                            LocationRowCard(
                                location = location,
                                appMode = state.appMode,
                                visualState = visualState,
                                enabled = !state.isBusy,
                                onPrimaryAction = {
                                    if (visualState.togglesConnection) {
                                        onToggleSelectedLocationVpn()
                                    } else {
                                        onSelectLocation(location.index)
                                    }
                                },
                                onRefresh = { onBenchmarkLocation(location.index) },
                                onEdit = { onEditLocation(location.index) },
                                onDelete = { onDeleteLocation(location.index) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun LocationRowCard(
    location: SavedLocationRow,
    appMode: com.kardinal.vpncontrol.model.AppMode,
    visualState: SavedLocationVisualState,
    enabled: Boolean,
    onPrimaryAction: () -> Unit,
    onRefresh: () -> Unit,
    onEdit: (() -> Unit)?,
    onDelete: (() -> Unit)?,
) {
    val strings = LocalAppStrings.current
    val connection = if (appMode == com.kardinal.vpncontrol.model.AppMode.VPN) {
        strings.get(UiText.VPN)
    } else {
        strings.get(UiText.PROXY)
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                !location.autoSelectable -> Color(0x33A44A4A)
                visualState.isSelected -> Color(0x334B7BE5)
                else -> Color(0x1F203041)
            },
        ),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = location.name,
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 16.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = location.server,
                    color = Color(0xFFD3E3EE),
                    fontSize = 13.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    text = location.details,
                    color = if (location.autoSelectable) Color(0xFF9ED6FF) else Color(0xFFFFC4C4),
                    fontSize = 12.sp,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                if (location.benchmarkDetail.isNotBlank()) {
                    Text(
                        text = location.benchmarkDetail,
                        color = Color(0xFFD3E3EE),
                        fontSize = 11.sp,
                        maxLines = 3,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                if (visualState.isInUse || visualState.isSelected) {
                    Text(
                        text = if (visualState.isInUse) strings.get(UiText.IN_USE) else strings.get(UiText.SELECTED),
                        color = Color(0xFFFFE0A3),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.Start),
            ) {
                OutlinedButton(
                    onClick = onPrimaryAction,
                    enabled = savedLocationManualActionEnabled(enabled, location.autoSelectable),
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = if (visualState.isSelected) Color(0xFFFFE0A3) else Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = when {
                            visualState.isInUse -> Icons.Filled.Close
                            else -> Icons.Filled.PlayArrow
                        },
                        contentDescription = when {
                            visualState.isInUse -> strings.format(UiText.STOP_CONNECTION_FOR_LOCATION, connection)
                            visualState.togglesConnection -> strings.format(UiText.START_CONNECTION_FOR_LOCATION, connection)
                            else -> strings.get(UiText.SELECT_THIS_LOCATION)
                        },
                    )
                }
                OutlinedButton(
                    onClick = onRefresh,
                    enabled = savedLocationManualActionEnabled(enabled, location.autoSelectable),
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = strings.get(UiText.RECHECK_LOCATION),
                    )
                }
                if (onEdit != null) {
                    OutlinedButton(
                        onClick = onEdit,
                        enabled = enabled,
                        modifier = Modifier.size(48.dp),
                        contentPadding = PaddingValues(0.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color.White,
                        ),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Edit,
                            contentDescription = strings.get(UiText.EDIT_LOCATION),
                        )
                    }
                }
                if (onDelete != null) {
                    OutlinedButton(
                        onClick = onDelete,
                        enabled = enabled,
                        modifier = Modifier.size(48.dp),
                        contentPadding = PaddingValues(0.dp),
                        shape = RoundedCornerShape(14.dp),
                        colors = ButtonDefaults.outlinedButtonColors(
                            contentColor = Color(0xFFFFC4C4),
                        ),
                    ) {
                        Icon(
                            imageVector = Icons.Filled.Delete,
                            contentDescription = strings.get(UiText.DELETE_LOCATION),
                        )
                    }
                }
            }
        }
    }
}
