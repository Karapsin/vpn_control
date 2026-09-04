@file:OptIn(androidx.compose.ui.test.ExperimentalTestApi::class)

package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.key
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.requiredSize
import androidx.compose.ui.test.ComposeUiTest
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.isRoot
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.runDesktopComposeUiTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RuntimeStatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import com.kardinal.vpncontrol.shared.ui.LocalStatsClock
import com.kardinal.vpncontrol.shared.ui.StatsClock
import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Test

class VisualCaptureTest {
    private lateinit var compose: ComposeUiTest

    @Test
    fun captureRequestedScenes() {
        if (System.getenv("VPN_CONTROL_VISUAL_OUTPUT") == null) return
        runDesktopComposeUiTest(width = 1280, height = 800) capture@{
        compose = this@capture
        val platform = requireNotNull(System.getenv("VPN_CONTROL_VISUAL_PLATFORM"))
        val manifestPath = Path.of(requireNotNull(System.getenv("VPN_CONTROL_VISUAL_MANIFEST")))
        val output = Path.of(requireNotNull(System.getenv("VPN_CONTROL_VISUAL_OUTPUT")))
        val requested = System.getenv("VPN_CONTROL_VISUAL_SCENES")
            .orEmpty()
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toSet()
        val scenes = visualScenes(manifestPath, platform, requested)
        Files.createDirectories(output)

        val testRoot = output.resolve("state")
        Files.createDirectories(testRoot)
        val locations = visualLocations()
        val store = DesktopStateStore(testRoot)
        val service = DesktopAppServiceFactory.createForTesting(store = store)
        val sceneKey = mutableStateOf("initial")
        val viewport = mutableStateOf(VisualViewport())

        compose.setContent {
            key(sceneKey.value) {
                CompositionLocalProvider(
                    LocalDensity provides Density(viewport.value.density, viewport.value.fontScale),
                    LocalStatsClock provides StatsClock(
                        nowMillis = { 1_700_003_600_000L },
                        liveUpdates = false,
                    ),
                ) {
                    Box(
                        modifier = Modifier.requiredSize(
                            (viewport.value.width / viewport.value.density).dp,
                            (viewport.value.height / viewport.value.density).dp,
                        ),
                    ) {
                        VpnControlTheme {
                            DesktopVpnControlApp(
                                windowProvider = {
                                    error("Native file dialogs are not invoked during app-owned visual capture")
                                },
                                service = service,
                                onCheckAndDownloadUpdate = {},
                                onDismissOrCancelUpdate = {},
                                onInstallUpdate = {},
                            )
                        }
                    }
                }
            }
        }

        scenes.forEach { scene ->
            val sceneId = scene.getValue("id").jsonPrimitive.content
            compose.runOnIdle {
                val sceneState = visualState(sceneId)
                val sceneLocations = when (sceneId) {
                    "locations-empty", "locations-empty-desktop" -> emptyList()
                    "locations-populated" -> locations.map { it.copy(isSelected = false) }
                    else -> locations
                }
                val stressScene = sceneId == "stress-narrow-long-german"
                service.replaceStateForVisualCapture(
                    sceneState,
                    sceneLocations,
                    runtimeStatusDetails = if (stressScene) {
                        emptyList()
                    } else {
                        buildList {
                            add(RuntimeStatusMessages.runtimeMode(sceneState.appMode.name))
                            if (sceneState.appMode == AppMode.VPN) {
                                add(RuntimeStatusMessages.desktopVpnCapabilityReady())
                            }
                        }
                    },
                )
                viewport.value = visualViewport(sceneId)
                sceneKey.value = sceneId
            }
            compose.waitForIdle()
            openSceneMenu(sceneId)
            compose.waitForIdle()

            val image = captureScene(
                output.resolve("$sceneId.png"),
                viewport.value.width,
                viewport.value.height,
            )
            if (scene["geometry_required"]?.jsonPrimitive?.content != "false") {
                writeGeometry(
                    output.resolve("$sceneId.geometry.json"),
                    image,
                    scene,
                    viewport.value.density,
                )
            }
        }
        }
    }

    private fun openSceneMenu(sceneId: String) {
        val scrollTarget = when (sceneId) {
            "profile-add-editor-desktop" -> "profile-save"
            "settings-language-english" -> "language-en"
            "settings-ssh-key" -> "ssh-key"
            "settings-refresh-custom-hours" -> "refresh-hours"
            "stress-narrow-long-german", "stress-large-font" -> "export-diagnostics"
            else -> null
        }
        if (scrollTarget != null) {
            compose.onNodeWithTag(scrollTarget, useUnmergedTree = true).performScrollTo()
            compose.waitForIdle()
        }
        val tag = when (sceneId) {
            "main-settings-menu-desktop" -> "main-settings"
            "locations-import-menu-desktop" -> "locations-import-menu"
            "locations-export-menu-desktop" -> "locations-export-menu"
            "routing-import-menu-desktop" -> "routing-import-menu"
            "routing-export-menu-desktop" -> "routing-export-menu"
            else -> null
        }
        if (tag != null) compose.onNodeWithTag(tag, useUnmergedTree = true).performClick()
    }

    private fun captureScene(path: Path, width: Int, height: Int): BufferedImage {
        val roots = compose.onAllNodes(isRoot(), useUnmergedTree = true)
        val nodes = roots.fetchSemanticsNodes(atLeastOneRootRequired = true)
        val canvas = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        val graphics = canvas.createGraphics()
        try {
            nodes.forEachIndexed { index, node ->
                val image = roots[index].captureToImage().toBufferedImage()
                val bounds = node.boundsInWindow
                graphics.drawImage(image, bounds.left.toInt(), bounds.top.toInt(), null)
            }
        } finally {
            graphics.dispose()
        }
        ImageIO.write(canvas, "png", path.toFile())
        return canvas
    }

    private fun writeGeometry(path: Path, image: BufferedImage, scene: JsonObject, density: Float) {
        val required = scene["required_elements"]?.jsonArray.orEmpty().map { it.jsonPrimitive.content }
        val sceneId = scene.getValue("id").jsonPrimitive.content
        val elements = buildJsonArray {
            required.forEach { id ->
                val mergedNode = runCatching {
                    compose.onAllNodes(hasTestTag(id), useUnmergedTree = false)
                        .fetchSemanticsNodes(atLeastOneRootRequired = false)
                        .firstOrNull()
                }.getOrNull()
                val unmergedNode = runCatching {
                    compose.onAllNodes(hasTestTag(id), useUnmergedTree = true)
                        .fetchSemanticsNodes(atLeastOneRootRequired = false)
                        .firstOrNull()
                }.getOrNull()
                val node = mergedNode ?: unmergedNode
                val measured = requireNotNull(node) {
                    "$sceneId is missing required production testTag '$id'"
                }
                val bounds = measured.boundsInWindow
                val interactive = measured.config.contains(SemanticsActions.OnClick) ||
                    measured.config.contains(SemanticsActions.OnLongClick) ||
                    measured.config.contains(SemanticsActions.SetText) ||
                    measured.config.contains(SemanticsActions.SetProgress)
                val semanticsText = measured.config.getOrNull(SemanticsProperties.Text)
                    ?.joinToString(" ") { it.text }
                    .orEmpty()
                val editableText = measured.config.getOrNull(SemanticsProperties.EditableText)?.text.orEmpty()
                val label = measured.config.getOrNull(SemanticsProperties.ContentDescription)
                    ?.joinToString(" ")
                    .orEmpty()
                    .ifBlank { semanticsText }
                    .ifBlank { editableText }
                    .ifBlank { measured.config.getOrNull(SemanticsProperties.StateDescription).orEmpty() }
                val isText = semanticsText.isNotBlank() || editableText.isNotBlank()
                add(
                    buildJsonObject {
                        put("id", JsonPrimitive(id))
                        put("visible", JsonPrimitive(true))
                        put("interactive", JsonPrimitive(interactive))
                        put("text", JsonPrimitive(isText))
                        put("label", JsonPrimitive(label))
                        if (id in setOf("connect", "disconnect", "start-proxy", "stop-proxy")) {
                            put("large_text", JsonPrimitive(true))
                        }
                        visualOverlapExceptions(id).takeIf { it.isNotEmpty() }?.let { allowed ->
                            put("allow_overlap_with", JsonArray(allowed.map(::JsonPrimitive)))
                        }
                        if (isText) {
                            val textBounds = unmergedNode?.firstTextDescendant()?.boundsInWindow ?: bounds
                            put("contrast_ratio", JsonPrimitive(measuredContrast(image, textBounds)))
                        }
                        put(
                            "bounds",
                            JsonArray(
                                listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)
                                    .map { JsonPrimitive(it.toDouble()) },
                            ),
                        )
                        put("measurement", JsonPrimitive("semantics"))
                    },
                )
            }
        }
        val document = buildJsonObject {
            put("schema_version", JsonPrimitive(1))
            put("viewport", JsonArray(listOf(JsonPrimitive(image.width), JsonPrimitive(image.height))))
            put("density", JsonPrimitive(density))
            put("elements", elements)
        }
        Files.writeString(path, Json { prettyPrint = true }.encodeToString(JsonObject.serializer(), document) + "\n")
    }
}

private data class VisualViewport(
    val width: Int = 1280,
    val height: Int = 800,
    val density: Float = 1.0f,
    val fontScale: Float = 1.0f,
)

private fun visualViewport(sceneId: String): VisualViewport = when (sceneId) {
    "stress-narrow-long-german" -> VisualViewport(width = 960, height = 720, density = 1.25f)
    "stress-large-font" -> VisualViewport(fontScale = 1.3f)
    else -> VisualViewport()
}

private fun visualOverlapExceptions(id: String): List<String> = when (id) {
    "profile-current-source" -> listOf("profile-refresh", "profile-rename", "profile-delete")
    "profile-all-subscriptions" -> listOf("profile-refresh-all")
    else -> emptyList()
}

private fun SemanticsNode.firstTextDescendant(): SemanticsNode? {
    children.firstNotNullOfOrNull { it.firstTextDescendant() }?.let { return it }
    if (
        config.getOrNull(SemanticsProperties.Text)?.isNotEmpty() == true ||
        config.getOrNull(SemanticsProperties.EditableText) != null
    ) {
        return this
    }
    return null
}

private fun measuredContrast(image: BufferedImage, bounds: androidx.compose.ui.geometry.Rect): Double {
    val left = bounds.left.toInt().coerceIn(0, image.width - 1)
    val top = bounds.top.toInt().coerceIn(0, image.height - 1)
    val right = kotlin.math.ceil(bounds.right.toDouble()).toInt().coerceIn(left + 1, image.width)
    val bottom = kotlin.math.ceil(bounds.bottom.toDouble()).toInt().coerceIn(top + 1, image.height)
    val luminance = ArrayList<Double>((right - left) * (bottom - top))
    for (y in top until bottom) {
        for (x in left until right) {
            val color = image.getRGB(x, y)
            luminance += relativeLuminance(
                red = color ushr 16 and 0xff,
                green = color ushr 8 and 0xff,
                blue = color and 0xff,
            )
        }
    }
    if (luminance.isEmpty()) return 1.0
    luminance.sort()
    val low = luminance[(luminance.lastIndex * 0.02).toInt()]
    val high = luminance[(luminance.lastIndex * 0.98).toInt()]
    return (high + 0.05) / (low + 0.05)
}

private fun relativeLuminance(red: Int, green: Int, blue: Int): Double {
    fun channel(value: Int): Double {
        val normalized = value / 255.0
        return if (normalized <= 0.04045) normalized / 12.92 else Math.pow((normalized + 0.055) / 1.055, 2.4)
    }
    return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue)
}

private fun visualScenes(manifestPath: Path, platform: String, requested: Set<String>): List<JsonObject> {
    val root = Json.parseToJsonElement(Files.readString(manifestPath)).jsonObject
    return root.getValue("scenes").jsonArray
        .map { it.jsonObject }
        .filter { scene -> platform in scene.getValue("platforms").jsonArray.map { it.jsonPrimitive.content } }
        .filter { scene -> scene["geometry_required"]?.jsonPrimitive?.content != "false" }
        .filter { scene -> requested.isEmpty() || scene.getValue("id").jsonPrimitive.content in requested }
}

internal fun visualLocations(): List<DesktopLocationRecord> = listOf(
    DesktopLocationRecord(
        index = 0,
        sourceUrl = "https://example.invalid/subscription-a",
        rawLink = "vless://00000000-0000-0000-0000-000000000001@example.invalid:443#Berlin",
        name = "Berlin",
        server = "example.invalid:443",
        details = "VLESS · TLS · TCP",
        benchmarkDetail = "Primary 42 ms · verification 118 ms",
        isValid = true,
        isSelected = true,
    ),
    DesktopLocationRecord(
        index = 1,
        sourceUrl = "https://example.invalid/subscription-b",
        rawLink = "trojan://visual@example.net:443#Tokyo",
        name = "Tokyo",
        server = "example.net:443",
        details = "Trojan · TLS · TCP",
        benchmarkDetail = "Validation failed: synthetic timeout",
        isValid = false,
    ),
)

internal fun visualState(sceneId: String): MainUiState {
    val locations = visualLocations()
    val first = locations.first()
    val subscriptions = listOf(
        SubscriptionSource(
            id = "visual-a",
            url = "https://example.invalid/subscription-a",
            customName = "Work",
            cachedLocations = listOf(first.rawLink),
            lastRefreshedAtEpochMillis = 1_700_000_000_000L,
            lastRefreshStatus = "Updated 1 location",
        ),
        SubscriptionSource(
            id = "visual-b",
            url = "https://example.invalid/subscription-b",
            customName = "Travel",
            cachedLocations = listOf(locations[1].rawLink),
            lastRefreshedAtEpochMillis = 1_700_000_000_000L,
            lastRefreshStatus = "Validation warning",
        ),
    )
    val screen = when {
        sceneId.startsWith("profile-") -> AppScreen.PROFILE
        sceneId.startsWith("locations-") -> AppScreen.LOCATIONS
        sceneId.startsWith("routing-") -> AppScreen.ROUTING_RULES
        sceneId.startsWith("stats-") -> AppScreen.STATS
        else -> AppScreen.MAIN
    }
    var state = MainUiState(
        currentScreen = screen,
        subscriptions = subscriptions,
        activeSubscriptionId = subscriptions.first().id,
        profileUrl = subscriptions.first().url,
        profileHistory = subscriptions.map(SubscriptionSource::url),
        profileHistoryNames = subscriptions.associate { it.url to it.customName },
        currentLocations = locations.map(DesktopLocationRecord::rawLink),
        locationBenchmarkDetails = locations.associate { it.rawLink to it.benchmarkDetail },
        selectedProfileName = first.name,
        selectedProfileServer = first.server,
        selectedProfileRawLink = first.rawLink,
        selectedProfileSourceUrl = first.sourceUrl,
        selectedProfileJson = "{\"outbounds\":[]}",
        installedApps = listOf(
            InstalledApp("com.example.browser", "Browser", false),
            InstalledApp("com.example.chat", "Chat", false),
        ),
        installedAppsLoaded = true,
        routingProxyPackagesDraft = setOf("com.example.browser"),
        routingDirectDomainsDraft = "example.org\ninternal.example",
        routingRuleSetsDraft = listOf(
            RoutingRuleSet(
                id = "visual-rule",
                name = "Private networks",
                source = "https://example.invalid/rules.json",
                action = RoutingRuleSetAction.DIRECT,
            ),
        ),
        hasVpnPermission = true,
        appUpdate = AppUpdateState(
            currentVersion = "2.0.0",
            availableVersion = "2.0.0",
        ),
        statusMessage = "Ready for visual inspection",
        sessionStartedAtEpochMillis = 1_700_000_000_000L,
        sessionStoppedAtEpochMillis = 1_699_999_000_000L,
        successfulStarts = 4,
        successfulStops = 3,
    )

    state = when (sceneId) {
        "main-connected" -> state.copy(isVpnRunning = true, statusMessage = "Connected through Berlin")
        "main-proxy-only" -> state.copy(appMode = AppMode.PROXY_ONLY, statusMessage = "Proxy-only mode ready")
        "main-busy-progress" -> state.copy(isRefreshing = true, isBusy = true, statusMessage = "Checking locations…")
        "main-subscription-mismatch" -> state.copy(selectedProfileSourceUrl = subscriptions[1].url)
        "profile-empty" -> state.copy(subscriptions = emptyList(), activeSubscriptionId = "", profileHistory = emptyList())
        "profile-all-subscriptions" -> state.copy(activeSubscriptionId = ALL_SUBSCRIPTIONS_ID)
        "profile-current-locations" -> state.copy(profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS)
        "profile-add-editor", "profile-add-editor-desktop", "profile-import-menu" -> state.copy(
            showAddSubscriptionEditor = true,
            profileDraft = "https://example.invalid/new-subscription",
            profileTitleDraft = "Visual fixture",
        )
        "profile-preview-warning" -> state.copy(
            showAddSubscriptionEditor = true,
            profileDraft = "vpn://invalid",
            profileTitleDraft = "Unsupported visual fixture",
        )
        "profile-rename-dialog" -> state.copy(
            showProfileHistoryRenameDialog = true,
            profileHistoryRenameUrlDraft = subscriptions.first().url,
            profileHistoryRenameDraft = "Work renamed",
        )
        "locations-empty", "locations-empty-desktop" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = emptyList(),
            subscriptions = emptyList(),
            selectedProfileName = "",
            selectedProfileServer = "",
            selectedProfileRawLink = "",
            selectedProfileSourceUrl = "",
        )
        "locations-populated" -> state.copy(
            selectedProfileName = "",
            selectedProfileServer = "",
            selectedProfileRawLink = "",
            selectedProfileJson = "",
        )
        "locations-selected" -> state.copy(isVpnRunning = true)
        "locations-add-dialog" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            showLocationDialog = true,
            locationDraft = "vless://visual@example.invalid:443#New",
        )
        "locations-edit-dialog" -> state.copy(showLocationDialog = true, editingLocationIndex = 0, locationDraft = first.rawLink)
        "locations-mutation-blocked" -> state.copy(
            showLocationMutationBlockedDialog = true,
            locationMutationBlockedMessage = "Disconnect before changing this active location.",
        )
        "routing-add-rule" -> state.copy(showRuleSetDialog = true, routingRuleSetNameDraft = "New direct rule")
        "routing-edit-rule" -> state.copy(
            showRuleSetDialog = true,
            editingRuleSetId = "visual-rule",
            routingRuleSetNameDraft = "Private networks",
            routingRuleSetSourceDraft = "https://example.invalid/rules.json",
        )
        "routing-search-results" -> state.copy(routingAppSearch = "browser")
        "routing-error" -> state.copy(routingDirectDomainsDraft = List(180) { "domain-$it.example" }.joinToString("\n"))
        "stats-disabled" -> state.copy(sessionStatsEnabled = false)
        "stats-active" -> state.copy(isVpnRunning = true, sessionStatsEnabled = true, liveTrafficStatsEnabled = true)
        "stats-stopped" -> state.copy(sessionStatsEnabled = true)
        "stats-profile-totals" -> state.copy(profileTotalsEnabled = true)
        "stats-latency" -> state.copy(latencyHistoryEnabled = true)
        "stats-connection-log" -> state.copy(
            connectionLogEnabled = true,
            connectionLog = listOf(ConnectionLogEntry("0", "Connected through synthetic Berlin", 1_700_000_000_000L)),
        )
        "settings-language", "settings-language-english" -> state.copy(showLanguageDialog = true)
        "settings-dns-automatic" -> state.copy(showDnsDialog = true, dnsModeDraft = DnsMode.AUTOMATIC)
        "settings-dns-custom-error" -> state.copy(
            showDnsDialog = true,
            dnsModeDraft = DnsMode.CUSTOM_DOH,
            customDnsEndpointDraft = "http://insecure.invalid",
        )
        "settings-ssh-disabled", "settings-ssh-key" -> state.copy(showHomeSshRouteDialog = true)
        "settings-ssh-pending-restart" -> state.copy(
            showHomeSshRestartDialog = true,
            homeSshRestartPending = true,
        )
        "settings-app-mode" -> state.copy(showAppModeDialog = true)
        "settings-refresh-policy", "settings-refresh-custom-hours" -> state.copy(
            showRefreshPolicyDialog = true,
            subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.CUSTOM,
            subscriptionRefreshCustomHoursDraft = "2.5",
        )
        "settings-validation" -> state.copy(showValidationSettingsDialog = true)
        "update-checking" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.CHECKING))
        "update-downloading" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.DOWNLOADING))
        "update-verifying" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.VERIFYING))
        "update-ready" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.READY))
        "update-up-to-date" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.UP_TO_DATE))
        "update-installing" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.INSTALLING))
        "update-unsupported" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.UNSUPPORTED))
        "update-failed" -> state.copy(appUpdate = visualUpdate(AppUpdatePhase.FAILED))
        "stress-narrow-long-german" -> state.copy(
            appLanguage = AppLanguage.GERMAN,
            subscriptions = emptyList(),
            activeSubscriptionId = "",
            profileUrl = "",
            profileHistory = emptyList(),
            profileHistoryNames = emptyMap(),
            selectedProfileName = "",
            selectedProfileServer = "",
            selectedProfileRawLink = "",
            selectedProfileSourceUrl = "",
            selectedProfileJson = "",
        )
        "stress-arabic-rtl" -> state.copy(appLanguage = AppLanguage.ARABIC)
        else -> state
    }
    return state
}

private fun visualUpdate(phase: AppUpdatePhase): AppUpdateState = AppUpdateState(
    showDialog = true,
    phase = phase,
    currentVersion = "2.0.0",
    availableVersion = "2.0.0",
    releaseNotesUrl = if (phase == AppUpdatePhase.READY) "https://example.invalid/release-notes" else "",
    downloadedBytes = 4_000_000L,
    totalBytes = 10_000_000L,
    message = when (phase) {
        AppUpdatePhase.FAILED -> "Synthetic checksum verification failed."
        AppUpdatePhase.UNSUPPORTED -> "Use the package for this operating system."
        else -> "Deterministic visual update fixture"
    },
)

private fun ImageBitmap.toBufferedImage(): BufferedImage {
    val pixels = IntArray(width * height)
    readPixels(pixels)
    val image = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
    image.setRGB(0, 0, width, height, pixels, 0, width)
    return image
}
