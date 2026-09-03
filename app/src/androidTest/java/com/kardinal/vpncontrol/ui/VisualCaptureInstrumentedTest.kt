package com.kardinal.vpncontrol.ui

import android.content.Intent
import android.graphics.BitmapFactory
import android.graphics.Bitmap
import android.net.Uri
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.content.FileProvider
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.AppUpdateState
import com.kardinal.vpncontrol.MainActivity
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.QrCaptureActivity
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ConnectionLogEntry
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.SubscriptionSource
import java.io.File
import java.io.FileInputStream
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

private const val NATIVE_HOST_CAPTURE_HOLD_MILLIS = 2_000L

@RunWith(AndroidJUnit4::class)
class VisualCaptureInstrumentedTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun captureRequestedScenes() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val requested = InstrumentationRegistry.getArguments().getString("visualScenes")
            .orEmpty()
            .split(',')
            .map(String::trim)
            .filter(String::isNotEmpty)
            .toSet()
        val manifest = JSONObject(
            instrumentation.context.assets.open("scenes.json").bufferedReader().use { it.readText() },
        )
        val output = File(requireNotNull(instrumentation.targetContext.getExternalFilesDir(null)), "visual-capture")
        output.mkdirs()
        val remoteOutput = "/data/local/tmp/vpn-control-visual"
        instrumentation.shell("rm -rf $remoteOutput")
        instrumentation.shell("mkdir -p $remoteOutput")
        val device = UiDevice.getInstance(instrumentation)

        val scenes = manifest.getJSONArray("scenes").objects()
            .filter { "android" in it.getJSONArray("platforms").strings() }
            .filter { requested.isEmpty() || it.getString("id") in requested }
        var configuredFontScale = 1.0f
        var configuredLandscape = false
        try {
            scenes.forEach { scene ->
                val sceneId = scene.getString("id")
                val requestedFontScale = if (sceneId == "stress-large-font") 1.3f else 1.0f
                val requestedLandscape = sceneId == "stress-android-landscape"
                if (requestedLandscape != configuredLandscape) {
                    if (requestedLandscape) device.setOrientationLeft() else device.setOrientationNatural()
                    device.waitForIdle(2_000L)
                    configuredLandscape = requestedLandscape
                }
                if (requestedFontScale != configuredFontScale) {
                    instrumentation.shell("settings put system font_scale $requestedFontScale")
                    compose.activityRule.scenario.recreate()
                    compose.waitForIdle()
                    configuredFontScale = requestedFontScale
                }
                compose.activityRule.scenario.onActivity { activity ->
                    activity.replaceStateForVisualCapture(androidVisualState(sceneId))
                }
                compose.waitForIdle()

                if (scene.optBoolean("geometry_required", true)) {
                    openAppScene(sceneId)
                    device.waitForIdle(1_000L)
                    SystemClock.sleep(500L)
                    val screenshot = File(output, "$sceneId.png")
                    check(device.takeScreenshot(screenshot))
                    val image = requireNotNull(BitmapFactory.decodeFile(screenshot.path))
                    writeGeometry(File(output, "$sceneId.geometry.json"), image, scene)
                    instrumentation.shell("cp ${output.path}/$sceneId.png $remoteOutput/$sceneId.png")
                    instrumentation.shell(
                        "cp ${output.path}/$sceneId.geometry.json $remoteOutput/$sceneId.geometry.json",
                    )
                } else {
                    openNativeScene(sceneId, instrumentation, device)
                    waitForNativeSurface(sceneId, device)
                    device.waitForIdle(3_000L)
                    check(device.takeScreenshot(File(output, "$sceneId.png")))
                    if (sceneId == "android-camera-qr") {
                        assertCameraScannerChrome(File(output, "$sceneId.png"))
                    }
                    instrumentation.shell("cp ${output.path}/$sceneId.png $remoteOutput/$sceneId.png")
                    SystemClock.sleep(NATIVE_HOST_CAPTURE_HOLD_MILLIS)
                    if (sceneId == "android-vpn-consent") {
                        val cancel = requireNotNull(device.findObject(By.text("Cancel"))) {
                            "VPN consent did not expose its Cancel action"
                        }
                        cancel.click()
                        check(device.wait(Until.gone(By.pkg("com.android.vpndialogs")), 5_000L)) {
                            "VPN consent did not close after cancellation"
                        }
                    } else if (sceneId != "android-system-bars") {
                        device.pressBack()
                        device.waitForIdle(1_000L)
                    }
                }
            }
        } finally {
            if (configuredFontScale != 1.0f) {
                instrumentation.shell("settings put system font_scale 1.0")
            }
            if (configuredLandscape) device.setOrientationNatural()
            device.unfreezeRotation()
        }
    }

    private fun openAppScene(sceneId: String) {
        val scrollTarget = when (sceneId) {
            "profile-add-editor", "profile-preview-warning" -> "profile-save"
            "settings-language-english" -> "language-en"
            "settings-ssh-key" -> "ssh-key"
            "settings-refresh-custom-hours" -> "refresh-hours"
            "routing-android-assignments" -> "app-search"
            "routing-search-results" -> "proxy-app-list"
            "stress-narrow-long-german", "stress-large-font" -> "export-diagnostics"
            "stress-android-landscape" -> "connect"
            else -> null
        }
        if (scrollTarget != null) {
            compose.onNodeWithTag(scrollTarget, useUnmergedTree = true).performScrollTo()
            compose.waitForIdle()
        }
        if (sceneId == "routing-search-results") {
            compose.onNodeWithTag("routing-list", useUnmergedTree = true).performSemanticsAction(
                SemanticsActions.ScrollBy,
            ) { scrollBy ->
                scrollBy(0f, 420f)
            }
            compose.waitForIdle()
        }
        val clicks = when (sceneId) {
            "main-settings-menu" -> listOf("main-settings")
            "profile-import-menu" -> listOf("profile-import-menu")
            "locations-import-menu" -> listOf("locations-import-menu")
            "locations-export-menu" -> listOf("locations-export")
            "locations-qr", "locations-error" -> listOf("locations-export", "export-qr")
            "routing-transfer-menu" -> listOf("routing-import-menu")
            "routing-qr", "routing-error" -> listOf("routing-export-menu", "export-qr")
            else -> emptyList()
        }
        clicks.forEach { tag ->
            compose.onNodeWithTag(tag, useUnmergedTree = true).performClick()
            compose.waitForIdle()
        }
    }

    private fun openNativeScene(
        sceneId: String,
        instrumentation: android.app.Instrumentation,
        device: UiDevice,
    ) {
        val packageName = instrumentation.targetContext.packageName
        when (sceneId) {
            "android-camera-qr" -> instrumentation.shell("pm grant $packageName android.permission.CAMERA")
            "android-package-installer" -> instrumentation.shell(
                "appops set $packageName REQUEST_INSTALL_PACKAGES allow",
            )
            "android-vpn-notification" -> instrumentation.shell(
                "pm grant $packageName android.permission.POST_NOTIFICATIONS",
            )
        }
        compose.activityRule.scenario.onActivity { activity ->
            val intent = when (sceneId) {
                "android-vpn-consent" -> {
                    activity.launchVpnConsentForVisualCapture()
                    null
                }
                "android-open-document" -> Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/json"
                }
                "android-create-document" -> Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "application/json"
                    putExtra(Intent.EXTRA_TITLE, "vpn-control-locations.json")
                }
                "android-camera-qr" -> Intent(activity, QrCaptureActivity::class.java).apply {
                    putExtra(QrCaptureActivity.EXTRA_VISUAL_CAPTURE, true)
                }
                "android-share-chooser" -> Intent.createChooser(
                    Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"
                        putExtra(Intent.EXTRA_TEXT, "VPN Control visual fixture")
                    },
                    "Share VPN Control diagnostics",
                )
                "android-package-installer" -> {
                    val updateDirectory = File(activity.cacheDir, "updates").apply { mkdirs() }
                    val apk = File(updateDirectory, "vpn-control-visual.apk")
                    File(activity.applicationInfo.sourceDir).copyTo(apk, overwrite = true)
                    val uri = FileProvider.getUriForFile(
                        activity,
                        "${activity.packageName}.fileprovider",
                        apk,
                    )
                    Intent(Intent.ACTION_INSTALL_PACKAGE).apply {
                        data = uri
                        flags = Intent.FLAG_GRANT_READ_URI_PERMISSION
                        putExtra(Intent.EXTRA_NOT_UNKNOWN_SOURCE, true)
                    }
                }
                "android-vpn-notification" -> {
                    val manager = activity.getSystemService(NotificationManager::class.java)
                    val channel = NotificationChannel(
                        "visual-vpn",
                        "VPN Control visual fixture",
                        NotificationManager.IMPORTANCE_LOW,
                    )
                    manager.createNotificationChannel(channel)
                    manager.notify(
                        4242,
                        NotificationCompat.Builder(activity, channel.id)
                            .setSmallIcon(android.R.drawable.stat_sys_warning)
                            .setContentTitle("VPN Control")
                            .setContentText("Connected through synthetic Berlin")
                            .setOngoing(true)
                            .build(),
                    )
                    null
                }
                else -> null
            }
            if (intent != null) {
                activity.startActivity(intent)
            }
        }
        if (sceneId == "android-vpn-notification") {
            device.openNotification()
        }
    }

    private fun waitForNativeSurface(sceneId: String, device: UiDevice) {
        val expected = when (sceneId) {
            "android-system-bars" -> return
            "android-vpn-consent" -> "com.android.vpndialogs"
            "android-open-document", "android-create-document" -> "documentsui"
            "android-camera-qr" -> "QrCaptureActivity"
            "android-share-chooser" -> "ChooserActivity"
            "android-package-installer" -> "PackageInstallerActivity"
            "android-vpn-notification" -> "NotificationShade"
            else -> error("Unknown Android native scene: $sceneId")
        }
        val timeout = when (sceneId) {
            // A cold emulator camera can need more than ten seconds to initialize.
            "android-camera-qr", "android-package-installer" -> 30_000L
            else -> 10_000L
        }
        val deadline = SystemClock.elapsedRealtime() + timeout
        var firstMatchAt = 0L
        while (SystemClock.elapsedRealtime() < deadline) {
            val surface = device.executeShellCommand("dumpsys window")
                .lineSequence()
                .filter { "mCurrentFocus" in it }
                .joinToString("\n")
            if (expected in surface) {
                if (firstMatchAt == 0L) firstMatchAt = SystemClock.elapsedRealtime()
                if (SystemClock.elapsedRealtime() - firstMatchAt >= 300L) return
            } else {
                firstMatchAt = 0L
            }
            SystemClock.sleep(100L)
        }
        error("$sceneId did not display expected native surface $expected")
    }

    private fun assertCameraScannerChrome(screenshot: File) {
        val image = requireNotNull(BitmapFactory.decodeFile(screenshot.path))
        var darkBluePixels = 0
        for (y in 0 until image.height step 8) {
            for (x in 0 until image.width step 8) {
                val color = image.getPixel(x, y)
                val red = android.graphics.Color.red(color)
                val green = android.graphics.Color.green(color)
                val blue = android.graphics.Color.blue(color)
                if (blue > red + 20 && blue > green + 5) darkBluePixels += 1
            }
        }
        check(darkBluePixels >= 1_000) {
            "QR scanner chrome was not visible above the camera preview"
        }
    }

    private fun writeGeometry(file: File, image: Bitmap, scene: JSONObject) {
        val sceneId = scene.getString("id")
        val elements = JSONArray()
        scene.optJSONArray("required_elements")?.strings().orEmpty().forEach { id ->
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
            elements.put(
                JSONObject()
                    .put("id", id)
                    .put("visible", true)
                    .put("interactive", interactive)
                    .put("text", isText)
                    .put("label", label)
                    .apply {
                        if (id in setOf("connect", "disconnect", "start-proxy", "stop-proxy")) {
                            put("large_text", true)
                        }
                        val allowed = visualOverlapExceptions(id)
                        if (allowed.isNotEmpty()) put("allow_overlap_with", JSONArray(allowed))
                        if (isText) {
                            val textBounds = unmergedNode?.firstTextDescendant()?.boundsInWindow ?: bounds
                            val elementImage = runCatching {
                                compose.onAllNodes(hasTestTag(id), useUnmergedTree = mergedNode == null)[0]
                                    .captureToImage()
                                    .asAndroidBitmap()
                            }.getOrNull()
                            val localTextBounds = androidx.compose.ui.geometry.Rect(
                                left = textBounds.left - bounds.left,
                                top = textBounds.top - bounds.top,
                                right = textBounds.right - bounds.left,
                                bottom = textBounds.bottom - bounds.top,
                            )
                            put(
                                "contrast_ratio",
                                elementImage?.let { measuredContrast(it, localTextBounds) }
                                    ?: measuredContrast(image, textBounds),
                            )
                        }
                    }
                    .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
                    .put("measurement", "semantics"),
            )
        }
        file.writeText(
            JSONObject()
                .put("schema_version", 1)
                .put("viewport", JSONArray(listOf(image.width, image.height)))
                .put("density", compose.activity.resources.displayMetrics.density)
                .put("elements", elements)
                .toString(2) + "\n",
        )
    }
}

private fun android.app.Instrumentation.shell(command: String) {
    uiAutomation.executeShellCommand(command).use { descriptor ->
        FileInputStream(descriptor.fileDescriptor).use { it.readBytes() }
    }
}

private fun JSONArray.objects(): List<JSONObject> = (0 until length()).map(::getJSONObject)
private fun JSONArray.strings(): List<String> = (0 until length()).map(::getString)

private fun androidVisualState(sceneId: String): MainUiState {
    val firstLocation = "vless://00000000-0000-0000-0000-000000000001@example.invalid:443#Berlin"
    val secondLocation = "trojan://visual@example.net:443#Tokyo"
    val subscriptions = listOf(
        SubscriptionSource(
            id = "visual-a",
            url = "https://example.invalid/subscription-a",
            customName = "Work",
            cachedLocations = listOf(firstLocation),
            lastRefreshedAtEpochMillis = 1_700_000_000_000L,
            lastRefreshStatus = "Updated 1 location",
        ),
        SubscriptionSource(
            id = "visual-b",
            url = "https://example.invalid/subscription-b",
            customName = "Travel",
            cachedLocations = listOf(secondLocation),
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
        currentLocations = listOf(firstLocation, secondLocation),
        locationBenchmarkDetails = mapOf(
            firstLocation to "Primary 42 ms · verification 118 ms",
            secondLocation to "Validation failed: synthetic timeout",
        ),
        selectedProfileName = "Berlin",
        selectedProfileServer = "example.invalid:443",
        selectedProfileRawLink = firstLocation,
        selectedProfileSourceUrl = subscriptions.first().url,
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
        hasVpnPermission = sceneId != "main-permission-required",
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
        "profile-add-editor", "profile-import-menu" -> state.copy(
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
        "locations-empty" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = emptyList(),
            subscriptions = emptyList(),
        )
        "locations-populated" -> state.copy(
            selectedProfileName = "",
            selectedProfileServer = "",
            selectedProfileRawLink = "",
            selectedProfileJson = "",
        )
        "locations-invalid" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = listOf(firstLocation, "not-a-supported-location"),
        )
        "locations-import-menu", "locations-export-menu", "locations-qr" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
        )
        "locations-error" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            currentLocations = List(80) { index -> firstLocation.replace("#Berlin", "#Berlin-$index") },
        )
        "locations-selected" -> state.copy(isVpnRunning = true)
        "locations-add-dialog" -> state.copy(
            profileSourceMode = ProfileSourceMode.CURRENT_LOCATIONS,
            showLocationDialog = true,
            locationDraft = "vless://visual@example.invalid:443#New",
        )
        "locations-edit-dialog" -> state.copy(showLocationDialog = true, editingLocationIndex = 0, locationDraft = firstLocation)
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
        "settings-ssh-pending-restart" -> state.copy(showHomeSshRestartDialog = true, homeSshRestartPending = true)
        "settings-app-mode" -> state.copy(showAppModeDialog = true)
        "settings-refresh-policy" -> state.copy(
            showRefreshPolicyDialog = true,
            subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.EVERY_HOUR,
        )
        "settings-refresh-custom-hours" -> state.copy(
            showRefreshPolicyDialog = true,
            subscriptionRefreshPolicyDraft = SubscriptionRefreshPolicy.CUSTOM,
            subscriptionRefreshCustomHoursDraft = "2.5",
        )
        "settings-validation" -> state.copy(showValidationSettingsDialog = true)
        "update-checking" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.CHECKING))
        "update-downloading" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.DOWNLOADING))
        "update-verifying" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.VERIFYING))
        "update-ready" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.READY))
        "update-up-to-date" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.UP_TO_DATE))
        "update-installing" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.INSTALLING))
        "update-unsupported" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.UNSUPPORTED))
        "update-failed" -> state.copy(appUpdate = androidVisualUpdate(AppUpdatePhase.FAILED))
        "stress-narrow-long-german" -> state.copy(appLanguage = AppLanguage.GERMAN)
        "stress-arabic-rtl" -> state.copy(appLanguage = AppLanguage.ARABIC)
        else -> state
    }
    return state
}

private fun androidVisualUpdate(phase: AppUpdatePhase): AppUpdateState = AppUpdateState(
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

private fun visualOverlapExceptions(id: String): List<String> = when (id) {
    "profile-current-source" -> listOf("profile-refresh", "profile-rename", "profile-delete")
    "profile-all-subscriptions" -> listOf("profile-refresh-all")
    else -> emptyList()
}

private fun measuredContrast(image: Bitmap, bounds: androidx.compose.ui.geometry.Rect): Double {
    val left = bounds.left.toInt().coerceIn(0, image.width - 1)
    val top = bounds.top.toInt().coerceIn(0, image.height - 1)
    val right = kotlin.math.ceil(bounds.right.toDouble()).toInt().coerceIn(left + 1, image.width)
    val bottom = kotlin.math.ceil(bounds.bottom.toDouble()).toInt().coerceIn(top + 1, image.height)
    val luminance = ArrayList<Double>((right - left) * (bottom - top))
    for (y in top until bottom) {
        for (x in left until right) {
            val color = image.getPixel(x, y)
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
