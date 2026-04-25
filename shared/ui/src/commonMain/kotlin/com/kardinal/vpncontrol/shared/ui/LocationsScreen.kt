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

data class SavedLocationRow(
    val index: Int,
    val rawLink: String,
    val name: String,
    val server: String,
    val details: String,
    val benchmarkDetail: String,
    val isValid: Boolean,
    val isSelected: Boolean,
)

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
                title = "Locations",
                description = if (state.profileSourceMode == com.kardinal.vpncontrol.model.ProfileSourceMode.SUBSCRIPTION) {
                    "Location search uses the remote source saved on the Profile tab. This list is updated from it each time."
                } else {
                    "Location search uses the saved locations below. No subscription is required."
                },
                footer = {
                    Text(
                        "Saved locations: ${locations.size}",
                        color = Color(0xFF9ED6FF),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        text = if (selectedName.isNullOrBlank()) {
                            "Selected: none"
                        } else {
                            "Selected: $selectedName"
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
                        Text("Add Location")
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
                                "No locations cached yet. Find the best location in subscription mode to load them, or add your own."
                            } else {
                                "No saved locations yet. Add one manually or switch back to subscription mode."
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
                            LocationRowCard(
                                location = location,
                                appMode = state.appMode,
                                isVpnRunning = state.isVpnRunning,
                                enabled = !state.isBusy,
                                onPrimaryAction = {
                                    if (location.isSelected) {
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
    isVpnRunning: Boolean,
    enabled: Boolean,
    onPrimaryAction: () -> Unit,
    onRefresh: () -> Unit,
    onEdit: (() -> Unit)?,
    onDelete: (() -> Unit)?,
) {
    val isSelectedAndRunning = location.isSelected && isVpnRunning
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = when {
                !location.isValid -> Color(0x33A44A4A)
                location.isSelected -> Color(0x334B7BE5)
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
                    color = if (location.isValid) Color(0xFF9ED6FF) else Color(0xFFFFC4C4),
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
                if (location.isSelected) {
                    Text(
                        text = if (isVpnRunning) "In use" else "Selected",
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
                    enabled = enabled && location.isValid,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = if (location.isSelected) Color(0xFFFFE0A3) else Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = when {
                            isSelectedAndRunning -> Icons.Filled.Close
                            else -> Icons.Filled.PlayArrow
                        },
                        contentDescription = when {
                            isSelectedAndRunning -> "Stop ${connectionLabel(appMode)} for this location"
                            location.isSelected -> "Start ${connectionLabel(appMode)} for this location"
                            else -> "Select this location"
                        },
                    )
                }
                OutlinedButton(
                    onClick = onRefresh,
                    enabled = enabled && location.isValid,
                    modifier = Modifier.size(48.dp),
                    contentPadding = PaddingValues(0.dp),
                    shape = RoundedCornerShape(14.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color.White,
                    ),
                ) {
                    Icon(
                        imageVector = Icons.Filled.Refresh,
                        contentDescription = "Recheck this location",
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
                            contentDescription = "Edit location",
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
                            contentDescription = "Delete location",
                        )
                    }
                }
            }
        }
    }
}
