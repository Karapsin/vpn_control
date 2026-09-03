package com.kardinal.vpncontrol.shared.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import kotlinx.coroutines.delay

data class StatsClock(
    val nowMillis: () -> Long,
    val liveUpdates: Boolean,
)

val LocalStatsClock = compositionLocalOf {
    StatsClock(nowMillis = ::currentTimeMillis, liveUpdates = true)
}

@Composable
fun StatsScreen(
    state: MainUiState,
) {
    val strings = LocalAppStrings.current
    Scaffold(
        containerColor = Color(0xFF141F2D),
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
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                ScreenHeaderCard(
                    title = strings.get(UiText.STATS_TITLE),
                    description = strings.get(UiText.STATS_DESCRIPTION),
                )
                SessionCard(state)
                ConnectionLogCard(state.connectionLog)
            }
        }
    }
}

@Composable
private fun SessionCard(state: MainUiState) {
    val strings = LocalAppStrings.current
    val clock = LocalStatsClock.current
    val now by produceState(
        initialValue = clock.nowMillis(),
        key1 = state.isVpnRunning,
        key2 = state.sessionStartedAtEpochMillis,
        key3 = clock,
    ) {
        value = clock.nowMillis()
        if (state.isVpnRunning && clock.liveUpdates) {
            while (true) {
                delay(30_000L)
                value = clock.nowMillis()
            }
        }
    }
    Card(
        modifier = Modifier.testTag("session-stats"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Text(strings.get(UiText.SESSION), color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            Text(
                text = if (state.isVpnRunning) {
                    strings.format(UiText.RUNNING_FOR, state.sessionStartedAtEpochMillis.elapsedLabel(now))
                } else {
                    strings.get(UiText.STOPPED)
                },
                modifier = Modifier.testTag(if (state.isVpnRunning) "session-duration" else "session-stopped"),
                color = Color.White,
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = strings.format(UiText.STARTED, strings.statusTime(state.sessionStartedAtEpochMillis)),
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Text(
                text = "${strings.get(UiText.STOPPED)}: ${strings.statusTime(state.sessionStoppedAtEpochMillis)}",
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
            Text(
                text = strings.format(UiText.SUCCESSFUL_STARTS_STOPS, state.successfulStarts, state.successfulStops),
                color = Color(0xFFD3E3EE),
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun ConnectionLogCard(connectionLog: List<ConnectionLogEntry>) {
    val strings = LocalAppStrings.current
    Card(
        modifier = Modifier.testTag("connection-log"),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(strings.get(UiText.CONNECTION_LOG), color = Color(0xFF9ED6FF), fontWeight = FontWeight.SemiBold)
            if (connectionLog.isEmpty()) {
                Text(strings.get(UiText.NO_RECENT_EVENTS), color = Color(0xFFD3E3EE))
            } else {
                Card(
                    shape = RoundedCornerShape(18.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x1F08111F)),
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 160.dp, max = 300.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 12.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        items(connectionLog.asReversed(), key = { it.id }) { entry ->
                            Column(
                                modifier = Modifier.testTag("connection-log-row-${entry.id}"),
                                verticalArrangement = Arrangement.spacedBy(2.dp),
                            ) {
                                Text(strings.statusMessage(entry.message), color = Color.White, fontSize = 13.sp)
                                Text(
                                    text = strings.statusTime(entry.createdAtEpochMillis),
                                    color = Color(0xFF9FB8C8),
                                    fontSize = 11.sp,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun Long.elapsedLabel(now: Long = currentTimeMillis()): String {
    if (this <= 0L || now <= this) return "0m"
    val totalMinutes = ((now - this) / 60_000L).coerceAtLeast(0L)
    val hours = totalMinutes / 60
    val minutes = totalMinutes % 60
    return if (hours > 0) {
        "${hours}h ${minutes}m"
    } else {
        "${minutes}m"
    }
}

private fun currentTimeMillis(): Long = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
