@file:OptIn(androidx.compose.ui.test.ExperimentalTestApi::class)

package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.runDesktopComposeUiTest
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.shared.ui.RoutingRulesScreen
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import java.lang.ref.WeakReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopRoutingSnapshotRetentionTest {
    @Test
    fun offscreenCardsReleaseTheSupersededCanonicalDomainBacking() = runDesktopComposeUiTest(width = 420, height = 700) {
        val state = mutableStateOf(MainUiState(currentScreen = AppScreen.ROUTING_RULES, appMode = AppMode.VPN))
        val previous = replaceDomains(state, 'a', 1)
        setContent {
            VpnControlTheme {
                RoutingRulesScreen(
                    state = state.value,
                    onAppSearchChange = {},
                    onToggleProxyApp = {},
                    onSelectAllProxyApps = {},
                    onClearAllProxyApps = {},
                    onDirectDomainsChange = {},
                    onBlockQuicUdp443Change = {},
                    onDirectDomainListChange = {},
                )
            }
        }
        waitUntil(timeoutMillis = 10_000) {
            onAllNodesWithText(domain('a', 0), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        // Reproduce the actual Android lifecycle: render the summary, then
        // scroll it out of view while the domain editor remains visible.
        val summaryBottom = onNodeWithTag("direct-domains").fetchSemanticsNode().boundsInRoot.bottom
        onNodeWithTag("routing-list").performSemanticsAction(SemanticsActions.ScrollBy) { scroll ->
            scroll(0f, summaryBottom + 10f)
        }
        waitForIdle()
        onNodeWithTag("direct-domain-list").assertIsDisplayed()
        val replacement = runOnIdle { replaceDomains(state, 'b', 2) }
        waitUntil(timeoutMillis = 10_000) {
            onAllNodesWithText(domain('b', 0), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()
        }
        // Advance the snapshot once more without replacing the current data;
        // this removes a transient writer snapshot as a possible GC root.
        runOnIdle { state.value = state.value.copy(routingDraftGeneration = 3) }
        waitForIdle()
        repeat(12) {
            if (previous.get() == null) return@repeat
            System.gc()
            Thread.sleep(20)
        }
        assertTrue(previous.get() == null, "An offscreen routing card retained the superseded 56,000-domain backing")
        assertEquals(56_000, replacement.get()?.size, "The active immutable draft must remain owned")
        assertEquals(domain('b', 0), state.value.routingDirectDomainSuffixesDraft?.first())
    }

    private fun replaceDomains(state: MutableState<MainUiState>, marker: Char, generation: Long): WeakReference<List<String>> {
        val domains = PackedDomains(marker)
        state.value = state.value.copy(
            routingRules = RoutingRules(directDomainSuffixes = domains),
            routingDirectDomainSuffixesDraft = domains,
            routingDirectDomainsDraft = "",
            routingDraftGeneration = generation,
        )
        return WeakReference(domains)
    }

    /** Mirrors the immutable newline-backed Android view without materializing 56,000 Strings. */
    private class PackedDomains(marker: Char) : AbstractList<String>() {
        override val size = 56_000
        private val stride = domain(marker, 0).length + 1
        private val source = buildString(size * stride) {
            repeat(size) { index -> append(domain(marker, index)).append('\n') }
        }

        override fun get(index: Int): String {
            if (index !in indices) throw IndexOutOfBoundsException(index)
            return source.substring(index * stride, (index + 1) * stride - 1)
        }
    }

    companion object {
        private val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
        private fun domain(marker: Char, index: Int) = "$marker${index.toString().padStart(5, '0')}.$suffix"
    }
}
