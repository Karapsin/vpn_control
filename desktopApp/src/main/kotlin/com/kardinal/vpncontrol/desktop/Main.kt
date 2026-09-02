package com.kardinal.vpncontrol.desktop

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.MyLocation
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.QueryStats
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.awt.ComposeWindow
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import com.kardinal.vpncontrol.AppScreen
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.shared.ui.HomeTabScaffold
import com.kardinal.vpncontrol.shared.ui.LanguageSettingsDialog
import com.kardinal.vpncontrol.shared.ui.AppUpdateDialog
import com.kardinal.vpncontrol.shared.ui.LocalAppStrings
import com.kardinal.vpncontrol.shared.ui.LocationsScreen
import com.kardinal.vpncontrol.shared.ui.MainScreen
import com.kardinal.vpncontrol.shared.ui.ProfileScreen
import com.kardinal.vpncontrol.shared.ui.RoutingRulesScreen
import com.kardinal.vpncontrol.shared.ui.SavedLocationRow
import com.kardinal.vpncontrol.shared.ui.StatsScreen
import com.kardinal.vpncontrol.shared.ui.UiText
import com.kardinal.vpncontrol.shared.ui.activeProfileLabel
import com.kardinal.vpncontrol.shared.ui.currentSubscriptionSelectionLabel
import com.kardinal.vpncontrol.shared.ui.formatLocationCountLabel
import com.kardinal.vpncontrol.shared.ui.ignoreRulesDescription
import com.kardinal.vpncontrol.shared.ui.selectedLocationOutsideCurrentSubscription
import com.kardinal.vpncontrol.shared.ui.rememberAppStrings
import java.awt.GraphicsEnvironment
import java.util.Locale
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    DesktopSmokeTest.handleArgs(args)?.let { exitProcess(it) }
    DesktopHeadlessController.handleArgs(args)?.let { exitProcess(it) }
    DesktopCli.handleArgs(args)?.let { exitProcess(it) }
    DesktopWindowsElevation.elevateIfRequired(args)?.let { exitProcess(it) }
    DesktopVpnIntegrationTest.handleArgs(args)?.let { exitProcess(it) }
    if (!isDesktopDisplayAvailable()) {
        println("VPN Control needs a graphical desktop session; DISPLAY or WAYLAND_DISPLAY is not available.")
        return
    }
    val instanceLock = DesktopSingleInstanceLock.acquire()
    if (instanceLock == null) {
        when (DesktopActivationServer.requestShow()) {
            DesktopActivationShowResult.SHOWN -> Unit
            DesktopActivationShowResult.HEADLESS ->
                println("VPN Control is running headless. Run `vpn-control off` before launching the GUI.")
            DesktopActivationShowResult.UNAVAILABLE -> println("VPN Control is already running.")
        }
        return
    }
    val activationEvents = DesktopActivationEvents()
    val activationServer = DesktopActivationServer.start(
        onShowWindow = {
            activationEvents.requestShowWindow()
            DesktopActivationShowResult.SHOWN
        },
        onCliCommand = activationEvents::requestCliCommand,
    )
    val startInTray = args.any { it == "--autostart" || it == "--tray" || it == "--minimized" }
    try {
        application {
            DesktopApplication(
                startInTray = startInTray,
                activationEvents = activationEvents,
                onExitApplication = ::exitApplication,
            )
        }
    } finally {
        activationServer?.close()
        instanceLock.close()
    }
}

@Composable
private fun DesktopApplication(
    startInTray: Boolean,
    activationEvents: DesktopActivationEvents,
    onExitApplication: () -> Unit,
) {
    val service = remember { DesktopAppServiceFactory.default() }
    val coroutineScope = rememberCoroutineScope()
    val autoRefreshScheduler = remember { DesktopAutoRefreshScheduler(service, coroutineScope) }
    var trayWindowState by remember {
        mutableStateOf(
            initialDesktopTrayWindowState(
                startInTray = startInTray,
                traySupported = isDesktopTraySupported(),
            ),
        )
    }
    var exitRequested by remember { mutableStateOf(false) }
    var updateJob by remember { mutableStateOf<Job?>(null) }
    val state = service.state
    val appStrings = rememberAppStrings(state.appLanguage, Locale.getDefault().language)
    DisposableEffect(activationEvents) {
        activationEvents.setShowWindowHandler {
            trayWindowState = trayWindowState.withWindowShown()
        }
        activationEvents.setCliCommandHandler { command, future ->
            coroutineScope.launch {
                val response = runCatching { service.executeCliCommand(command) }
                    .getOrElse { error ->
                        DesktopCliResponse.failure(error.message ?: "VPN Control CLI command failed.")
                    }
                future.complete(response)
            }
        }
        onDispose {
            activationEvents.setShowWindowHandler(null)
            activationEvents.setCliCommandHandler(null)
        }
    }

    fun exitAfterStoppingRuntime() {
        if (exitRequested) return
        exitRequested = true
        coroutineScope.launch {
            service.shutdownForExit()
            onExitApplication()
        }
    }

    fun checkAndDownloadUpdate() {
        if (updateJob?.isActive == true) return
        updateJob = coroutineScope.launch {
            service.checkAndDownloadUpdate()
            updateJob = null
        }
    }

    fun dismissOrCancelUpdate() {
        updateJob?.cancel()
        updateJob = null
        service.dismissUpdate()
    }

    fun installPreparedUpdate() {
        if (updateJob?.isActive == true) return
        updateJob = coroutineScope.launch {
            val authorized = service.authorizeUpdateInstaller()
            if (authorized.isSuccess) {
                val stopped = service.shutdownForExit()
                if (stopped.isSuccess) {
                    onExitApplication()
                } else {
                    service.cancelUpdateInstaller()
                    service.reportUpdateInstallFailure(
                        stopped.exceptionOrNull()?.message ?: "Could not stop the active connection for update",
                    )
                }
            }
            updateJob = null
        }
    }

    LaunchedEffect(Unit) {
        service.resumePreviousConnectionIfNeeded()
    }

    LaunchedEffect(
        state.profileSourceMode,
        state.subscriptionRefreshPolicy,
        state.subscriptionRefreshCustomHours,
        state.activeSubscriptionId,
        state.subscriptions,
    ) {
        autoRefreshScheduler.sync(state)
    }

    DisposableEffect(Unit) {
        onDispose {
            autoRefreshScheduler.cancel()
        }
    }

    if (trayWindowState.traySupported) {
        DesktopTrayIcon(
            appTitle = appStrings.get(UiText.APP_TITLE),
            connectionActionLabel = trayConnectionActionLabel(state, appStrings),
            findBestLabel = appStrings.get(UiText.FIND_BEST),
            showWindowLabel = appStrings.get(UiText.SHOW_WINDOW),
            hideWindowLabel = appStrings.get(UiText.HIDE_WINDOW),
            exitLabel = appStrings.get(UiText.EXIT),
            connectionActionEnabled = !state.isBusy,
            findBestEnabled = !state.isBusy,
            onToggleConnection = {
                if (!service.state.isBusy) {
                    coroutineScope.launch { service.toggleSelectedLocationProxy() }
                }
            },
            onFindBest = {
                if (!service.state.isBusy) {
                    coroutineScope.launch { service.findBestLocation() }
                }
            },
            onShowWindow = {
                trayWindowState = trayWindowState.withWindowShown()
            },
            onHideWindow = {
                trayWindowState = trayWindowState.withHideWindowRequested()
            },
            onExit = ::exitAfterStoppingRuntime,
            onTrayAvailable = {
                trayWindowState = trayWindowState.withTrayAvailable()
            },
            onTrayUnavailable = {
                trayWindowState = trayWindowState.withTrayUnavailable()
            },
        )
    }

    Window(
        visible = trayWindowState.windowVisible,
        onCloseRequest = {
            if (trayWindowState.canHideToTray) {
                trayWindowState = trayWindowState.withCloseRequestHiddenToTray()
            } else {
                exitAfterStoppingRuntime()
            }
        },
        title = appStrings.get(UiText.APP_TITLE),
    ) {
        LaunchedEffect(trayWindowState.windowVisible) {
            if (trayWindowState.windowVisible) {
                window.toFront()
                window.requestFocus()
            }
        }
        MaterialTheme(
            colorScheme = darkColorScheme(
                background = Color(0xFF08111F),
                surface = Color(0xFF141F2D),
                primary = Color(0xFF4B7BE5),
                secondary = Color(0xFF9ED6FF),
            ),
        ) {
            Surface(color = Color.Transparent) {
                DesktopVpnControlApp(
                    window = window,
                    service = service,
                    onCheckAndDownloadUpdate = ::checkAndDownloadUpdate,
                    onDismissOrCancelUpdate = ::dismissOrCancelUpdate,
                    onInstallUpdate = ::installPreparedUpdate,
                )
            }
        }
    }
}

internal data class DesktopTrayWindowState(
    val traySupported: Boolean,
    val trayAvailable: Boolean,
    val hideOnFirstTrayAvailable: Boolean,
    val windowVisible: Boolean,
) {
    val canHideToTray: Boolean
        get() = traySupported && trayAvailable
}

internal fun initialDesktopTrayWindowState(
    startInTray: Boolean,
    traySupported: Boolean,
): DesktopTrayWindowState {
    return DesktopTrayWindowState(
        traySupported = traySupported,
        trayAvailable = false,
        hideOnFirstTrayAvailable = startInTray,
        windowVisible = true,
    )
}

internal fun DesktopTrayWindowState.withWindowShown(): DesktopTrayWindowState {
    return copy(windowVisible = true)
}

internal fun DesktopTrayWindowState.withHideWindowRequested(): DesktopTrayWindowState {
    return if (canHideToTray) {
        copy(windowVisible = false)
    } else {
        copy(windowVisible = true)
    }
}

internal fun DesktopTrayWindowState.withTrayAvailable(): DesktopTrayWindowState {
    val shouldHide = hideOnFirstTrayAvailable
    return copy(
        trayAvailable = true,
        hideOnFirstTrayAvailable = false,
        windowVisible = if (shouldHide) false else windowVisible,
    )
}

internal fun DesktopTrayWindowState.withTrayUnavailable(): DesktopTrayWindowState {
    return copy(
        traySupported = false,
        trayAvailable = false,
        hideOnFirstTrayAvailable = false,
        windowVisible = true,
    )
}

internal fun DesktopTrayWindowState.withCloseRequestHiddenToTray(): DesktopTrayWindowState {
    return if (canHideToTray) {
        copy(windowVisible = false)
    } else {
        copy(windowVisible = true)
    }
}

internal fun isDesktopDisplayAvailable(
    osName: String = System.getProperty("os.name"),
    env: Map<String, String> = System.getenv(),
    isHeadless: Boolean = runCatching { GraphicsEnvironment.isHeadless() }.getOrDefault(true),
): Boolean {
    if (isHeadless) return false
    return when (desktopTrayPlatform(osName)) {
        DesktopTrayPlatform.Linux -> !env["DISPLAY"].isNullOrBlank() || !env["WAYLAND_DISPLAY"].isNullOrBlank()
        DesktopTrayPlatform.Windows,
        DesktopTrayPlatform.MacOs,
        DesktopTrayPlatform.Other,
        -> true
    }
}

@Composable
private fun DesktopVpnControlApp(
    window: ComposeWindow,
    service: DesktopAppService,
    onCheckAndDownloadUpdate: () -> Unit,
    onDismissOrCancelUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
) {
    val coroutineScope = rememberCoroutineScope()
    val state = service.state
    val showMismatchWarning = selectedLocationOutsideCurrentSubscription(state)
    val systemLanguageCode = Locale.getDefault().language
    val appStrings = rememberAppStrings(state.appLanguage, systemLanguageCode)
    val activeProfile = activeProfileLabel(state, service::sourceLabelFor, appStrings)
    val currentSelection = currentSubscriptionSelectionLabel(state, service::sourceLabelFor, appStrings)

    CompositionLocalProvider(LocalAppStrings provides appStrings) {
    AppUpdateDialog(
        state = state.appUpdate,
        onDismiss = onDismissOrCancelUpdate,
        onRetry = onCheckAndDownloadUpdate,
        onInstall = onInstallUpdate,
        onOpenReleaseNotes = {
            runCatching {
                java.awt.Desktop.getDesktop().browse(java.net.URI(state.appUpdate.releaseNotesUrl))
            }
        },
    )
    DesktopSettingsDialogs(
        state = state,
        systemLanguageCode = systemLanguageCode,
        onToggleDnsDialog = service::toggleDnsDialog,
        onDnsModeDraftChange = service::setDnsModeDraft,
        onCustomDnsDraftChange = service::setCustomDnsDraft,
        onSaveDns = service::saveDns,
        onToggleHomeSshRouteDialog = service::toggleHomeSshRouteDialog,
        onHomeSshEnabledChange = service::setHomeSshEnabledDraft,
        onHomeSshHostChange = service::setHomeSshHostDraft,
        onHomeSshPortChange = service::setHomeSshPortDraft,
        onHomeSshUserChange = service::setHomeSshUserDraft,
        onHomeSshHostKeysChange = service::setHomeSshHostKeysDraft,
        onHomeSshRelayPortChange = service::setHomeSshRelayPortDraft,
        onImportHomeSshPrivateKey = {
            DesktopTextTransfer.openTextFile(
                window,
                appStrings.get(UiText.IMPORT_PRIVATE_KEY),
            ).onSuccess { content -> content?.let(service::importHomeSshPrivateKey) }
                .onFailure { error -> service.postStatus(error.message ?: "SSH private key import failed") }
        },
        onSaveHomeSshRoute = service::saveHomeSshRoute,
        onDismissHomeSshRestart = service::dismissHomeSshRestartDialog,
        onRestartForHomeSsh = {
            coroutineScope.launch { service.restartForHomeSshSettings() }
        },
        onToggleAppModeDialog = service::toggleAppModeDialog,
        onSetAppMode = { mode ->
            if (!state.isBusy) {
                coroutineScope.launch { service.setAppMode(mode) }
            }
        },
        onToggleRefreshPolicyDialog = service::toggleRefreshPolicyDialog,
        onSubscriptionRefreshPolicyDraftChange = service::setSubscriptionRefreshPolicyDraft,
        onFindBestAfterSubscriptionRefreshDraftChange = service::setFindBestAfterSubscriptionRefreshDraft,
        onSubscriptionRefreshCustomHoursDraftChange = service::setSubscriptionRefreshCustomHoursDraft,
        onSaveSubscriptionRefreshPolicy = service::saveSubscriptionRefreshPolicy,
        onToggleValidationSettingsDialog = service::toggleValidationSettingsDialog,
        onValidationTestUrlDraftChange = service::setValidationTestUrlDraft,
        onValidationBatchSizeDraftChange = service::setValidationBatchSizeDraft,
        onValidationSubscriptionRefreshConcurrencyDraftChange =
            service::setValidationSubscriptionRefreshConcurrencyDraft,
        onValidationRetryCountDraftChange = service::setValidationRetryCountDraft,
        onValidationActiveVerificationWindowSizeDraftChange =
            service::setValidationActiveVerificationWindowSizeDraft,
        onSaveValidationSettings = service::saveValidationSettings,
        onToggleLanguageDialog = service::toggleLanguageDialog,
        onSetAppLanguage = service::setAppLanguage,
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(Color(0xFF08111F), Color(0xFF12304B), Color(0xFF3D6B59)),
                ),
            ),
    ) {
        HomeTabScaffold(
            currentScreen = state.currentScreen,
            onOpenMainTab = { service.openScreen(AppScreen.MAIN) },
            onOpenProfileTab = { service.openScreen(AppScreen.PROFILE) },
            onOpenLocationsTab = { service.openScreen(AppScreen.LOCATIONS) },
            onOpenStatsTab = { service.openScreen(AppScreen.STATS) },
            onOpenRoutingRules = { service.openScreen(AppScreen.ROUTING_RULES) },
            mainIcon = Icons.Filled.Home,
            profileIcon = Icons.Filled.Person,
            locationsIcon = Icons.Filled.Public,
            statsIcon = Icons.Filled.QueryStats,
            rulesIcon = Icons.Filled.Tune,
        ) {
            when (state.currentScreen) {
                AppScreen.MAIN -> MainScreen(
                    state = state,
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    statusDetails = service.runtimeStatusDetails(),
                    onToggleVpn = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { service.toggleSelectedLocationProxy() }
                    },
                    onRefresh = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { service.findBestLocation() }
                    },
                    onExportDiagnostics = {
                        if (state.isBusy) return@MainScreen
                        val selection = DesktopTextTransfer.chooseSaveFile(
                            window = window,
                            title = appStrings.get(UiText.EXPORT_DIAGNOSTICS),
                            suggestedFileName = DesktopDiagnosticsExporter.suggestedFileName(),
                        )
                        coroutineScope.launch { service.exportDiagnostics(selection) }
                    },
                    powerIcon = Icons.Filled.PowerSettingsNew,
                    findBestIcon = Icons.Filled.MyLocation,
                    headerActions = {
                        DesktopAdditionalSettingsMenu(
                            state = state,
                            onToggleDnsDialog = service::toggleDnsDialog,
                            onToggleHomeSshRouteDialog = service::toggleHomeSshRouteDialog,
                            onSetStartOnBootEnabled = service::setStartOnBootEnabled,
                            onSetAppMode = { mode ->
                                if (!state.isBusy) {
                                    coroutineScope.launch { service.setAppMode(mode) }
                                }
                            },
                            onToggleRefreshPolicyDialog = service::toggleRefreshPolicyDialog,
                            onToggleValidationSettingsDialog = service::toggleValidationSettingsDialog,
                            onToggleLanguageDialog = service::toggleLanguageDialog,
                            onCheckAndDownloadUpdate = onCheckAndDownloadUpdate,
                            onIgnoreRulesChange = service::setRoutingIgnoreRulesDraft,
                        )
                    },
                )

                AppScreen.PROFILE -> ProfileScreen(
                    activeProfileLabel = activeProfile,
                    currentSelectionLabel = currentSelection,
                ) {
                    DesktopProfileContent(
                        state = state,
                        resolveSourceLabel = service::sourceLabelFor,
                        onActivateSelection = service::activateSelection,
                        onSetSourceMode = service::setSourceMode,
                        onToggleAddSubscriptionEditor = service::toggleAddSubscriptionEditor,
                        onProfileDraftChange = service::setProfileDraft,
                        onProfileTitleDraftChange = service::setProfileTitleDraft,
                        onClearProfileDraft = service::clearProfileDraft,
                        onSaveSubscriptionDraft = service::saveSubscriptionDraft,
                        onDeleteSubscription = { subscriptionId ->
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.deleteSubscription(subscriptionId) }
                        },
                        onShowSubscriptionRenameDialog = service::showSubscriptionRenameDialog,
                        onCloseSubscriptionRenameDialog = service::closeSubscriptionRenameDialog,
                        onSubscriptionRenameUrlDraftChange = service::setSubscriptionRenameUrlDraft,
                        onSubscriptionRenameDraftChange = service::setSubscriptionRenameDraft,
                        onSaveSubscriptionRename = service::saveSubscriptionRename,
                        onRefreshSubscription = { subscriptionId ->
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.refreshSubscription(subscriptionId) }
                        },
                        onRefreshAllSubscriptions = {
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { service.refreshAllSubscriptions() }
                        },
                    )
                }

                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    locations = service.visibleDesktopLocations().map { it.toSharedRow() },
                    selectedName = state.selectedProfileName.takeIf(String::isNotBlank),
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    onShowAddLocation = if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) ({
                        service.addSampleLocation()
                    }) else null,
                    onToggleSelectedLocationVpn = {
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.toggleSelectedLocationProxy() }
                    },
                    onBenchmarkLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.benchmarkLocation(index) }
                    },
                    onSelectLocation = { index -> service.applyLocationSelection(index) },
                    onEditLocation = { index -> service.editLocation(index) },
                    onDeleteLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { service.deleteLocation(index) }
                    },
                    controls = {
                        DesktopActionRow(
                            onImportFile = {
                                val selection = DesktopTextTransfer.chooseOpenFile(
                                    window = window,
                                    title = appStrings.get(UiText.IMPORT),
                                )
                                coroutineScope.launch { service.importLocationsFromFile(selection) }
                            },
                            onImportClipboard = { coroutineScope.launch { service.importLocationsFromClipboard() } },
                            onExportFile = {
                                service.exportLocationsToFile(
                                    window = window,
                                    title = appStrings.get(UiText.LOCATIONS_EXPORT_TITLE),
                                )
                            },
                            onExportClipboard = service::exportLocationsToClipboard,
                        )
                    },
                )

                AppScreen.ROUTING_RULES -> RoutingRulesScreen(
                    state = state,
                    onAppSearchChange = service::setRoutingAppSearch,
                    onToggleProxyApp = service::toggleProxyApp,
                    onSelectAllProxyApps = service::selectAllProxyApps,
                    onClearAllProxyApps = service::clearAllProxyApps,
                    onDirectDomainsChange = service::setRoutingDirectDomainsDraft,
                    onBlockQuicUdp443Change = {},
                    showAppAssignments = false,
                    controls = {
                        DesktopActionRow(
                            onImportFile = {
                                service.importRoutingRulesFromFile(
                                    window = window,
                                    title = appStrings.get(UiText.IMPORT),
                                )
                            },
                            onImportClipboard = service::importRoutingRulesFromClipboard,
                            onExportFile = {
                                service.exportRoutingRulesToFile(
                                    window = window,
                                    title = appStrings.get(UiText.RULES_EXPORT_TITLE),
                                )
                            },
                            onExportClipboard = service::exportRoutingRulesToClipboard,
                        )
                    },
                )

                AppScreen.STATS -> StatsScreen(state = state)
            }
        }
    }
    }
}

private fun trayConnectionActionLabel(
    state: MainUiState,
    strings: com.kardinal.vpncontrol.shared.ui.AppStrings,
): String {
    return when (state.appMode) {
        AppMode.VPN -> if (state.isVpnRunning) strings.get(UiText.STOP_VPN) else strings.get(UiText.START_VPN)
        AppMode.PROXY_ONLY -> if (state.isVpnRunning) strings.get(UiText.STOP_PROXY) else strings.get(UiText.START_PROXY)
    }
}

@Composable
private fun DesktopProfileContent(
    state: MainUiState,
    resolveSourceLabel: (String) -> String,
    onActivateSelection: (String) -> Unit,
    onSetSourceMode: (ProfileSourceMode) -> Unit,
    onToggleAddSubscriptionEditor: () -> Unit,
    onProfileDraftChange: (String) -> Unit,
    onProfileTitleDraftChange: (String) -> Unit,
    onClearProfileDraft: () -> Unit,
    onSaveSubscriptionDraft: () -> Unit,
    onDeleteSubscription: (String) -> Unit,
    onShowSubscriptionRenameDialog: (String) -> Unit,
    onCloseSubscriptionRenameDialog: () -> Unit,
    onSubscriptionRenameUrlDraftChange: (String) -> Unit,
    onSubscriptionRenameDraftChange: (String) -> Unit,
    onSaveSubscriptionRename: () -> Unit,
    onRefreshSubscription: (String) -> Unit,
    onRefreshAllSubscriptions: () -> Unit,
) {
    val strings = LocalAppStrings.current
    if (state.showProfileHistoryRenameDialog) {
        AlertDialog(
            onDismissRequest = onCloseSubscriptionRenameDialog,
            confirmButton = {
                TextButton(onClick = onSaveSubscriptionRename) {
                    Text(strings.get(UiText.SAVE))
                }
            },
            dismissButton = {
                TextButton(onClick = onCloseSubscriptionRenameDialog) {
                    Text(strings.get(UiText.CANCEL))
                }
            },
            title = {
                Text(strings.get(UiText.RENAME_SUBSCRIPTION))
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = state.profileHistoryRenameUrlDraft,
                        onValueChange = onSubscriptionRenameUrlDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.SUBSCRIPTION_URL)) },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.profileHistoryRenameDraft,
                        onValueChange = onSubscriptionRenameDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.SUBSCRIPTION_NAME)) },
                        placeholder = { Text(strings.get(UiText.OPTIONAL_CUSTOM_NAME)) },
                        singleLine = true,
                    )
                }
            },
        )
    }

    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0x291D2934)),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(
                        modifier = Modifier.fillMaxWidth(0.78f),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Text(
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                strings.get(UiText.SUBSCRIPTION_MODE)
                            } else {
                                strings.get(UiText.SAVED_LOCATIONS)
                            },
                            color = Color.White,
                        )
                        Text(
                            if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                strings.get(UiText.PROFILE_SOURCE_DESKTOP_USE_SAVED_HINT)
                            } else {
                                strings.get(UiText.PROFILE_SOURCE_DESKTOP_USE_SUBSCRIPTION_HINT)
                            },
                            color = Color(0xFFD3E3EE),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Switch(
                        checked = state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION,
                        onCheckedChange = { enabled ->
                            onSetSourceMode(
                                if (enabled) {
                                    ProfileSourceMode.SUBSCRIPTION
                                } else {
                                    ProfileSourceMode.CURRENT_LOCATIONS
                                },
                            )
                        },
                    )
                }
            }
        }

        Card(
            shape = RoundedCornerShape(20.dp),
            colors = CardDefaults.cardColors(containerColor = Color(0x24141F2D)),
        ) {
            val selectedContainerColor = Color(0x263C7AE6)
            val selectedBorderColor = Color(0xFF9ED6FF)
            val normalContainerColor = Color.Transparent
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(
                    strings.get(UiText.SUBSCRIPTIONS),
                    color = Color.White,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold,
                    fontSize = 22.sp,
                )
                if (state.subscriptions.size > 1) {
                    val allSelected = state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onActivateSelection(ALL_SUBSCRIPTIONS_ID) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (allSelected) Color(0x334B7BE5) else Color(0x1B213246),
                        ),
                        border = if (allSelected) BorderStroke(1.dp, selectedBorderColor) else null,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(42.dp)
                                    .background(Color(0x223C7AE6), RoundedCornerShape(14.dp)),
                                contentAlignment = Alignment.Center,
                            ) {
                                Icon(
                                    imageVector = Icons.Filled.Public,
                                    contentDescription = strings.get(UiText.ALL_SUBSCRIPTIONS),
                                    tint = Color.White,
                                )
                            }
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    strings.format(
                                        UiText.ALL_SUBSCRIPTIONS_TITLE,
                                        strings.locationCountLabel(
                                            state.subscriptions.sumOf { it.cachedLocations.size },
                                            merged = true,
                                        ),
                                    ),
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                )
                                Text(
                                    strings.get(UiText.ALL_SUBSCRIPTIONS_DESCRIPTION),
                                    color = if (allSelected) selectedBorderColor else Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Row(
                                horizontalArrangement = Arrangement.spacedBy(2.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                if (allSelected) {
                                    Box(
                                        modifier = Modifier
                                            .background(Color(0xFF2B4F7C), RoundedCornerShape(999.dp))
                                            .padding(horizontal = 12.dp, vertical = 6.dp),
                                    ) {
                                        Text(
                                            strings.get(UiText.ACTIVE),
                                            color = Color.White,
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.SemiBold,
                                        )
                                    }
                                }
                                IconButton(
                                    onClick = onRefreshAllSubscriptions,
                                    enabled = !state.isBusy,
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = strings.get(UiText.REFRESH_ALL),
                                        tint = if (!state.isBusy) Color.White else Color(0xFF9FB8C8),
                                    )
                                }
                            }
                        }
                    }
                }
                state.subscriptions.forEach { subscription ->
                    val isSelected = state.activeSubscriptionId == subscription.id
                    val refreshStatus = subscription.lastRefreshStatus
                        .takeIf { it.isNotBlank() }
                        ?.let(strings::statusMessage)
                        ?: strings.get(UiText.NOT_REFRESHED_YET)
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onActivateSelection(subscription.id) },
                        shape = RoundedCornerShape(16.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = if (isSelected) selectedContainerColor else normalContainerColor,
                        ),
                        border = if (isSelected) BorderStroke(1.dp, selectedBorderColor) else null,
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.Top,
                        ) {
                            Column(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    resolveSourceLabel(subscription.url),
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                )
                                if (isSelected) {
                                    Text(
                                        strings.get(UiText.SELECTED_SUBSCRIPTION),
                                        color = selectedBorderColor,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.SemiBold,
                                    )
                                }
                                Text(
                                    "${strings.locationCountLabel(subscription.cachedLocations.size)} • $refreshStatus",
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                                IconButton(
                                    onClick = { onRefreshSubscription(subscription.id) },
                                    enabled = !state.isBusy,
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = strings.get(UiText.REFRESH_ACTIVE),
                                        tint = if (!state.isBusy) Color.White else Color(0xFF9FB8C8),
                                    )
                                }
                                IconButton(onClick = { onShowSubscriptionRenameDialog(subscription.id) }) {
                                    Icon(
                                        imageVector = Icons.Filled.Edit,
                                        contentDescription = strings.get(UiText.RENAME_SUBSCRIPTION),
                                        tint = Color.White,
                                    )
                                }
                                IconButton(onClick = { onDeleteSubscription(subscription.id) }) {
                                    Icon(
                                        imageVector = Icons.Filled.Delete,
                                        contentDescription = strings.get(UiText.DELETE_SUBSCRIPTION),
                                        tint = Color(0xFFFFA6A6),
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
            if (state.showAddSubscriptionEditor) {
                Card(
                    shape = RoundedCornerShape(16.dp),
                    colors = CardDefaults.cardColors(containerColor = Color(0x1C3C7AE6)),
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalArrangement = Arrangement.spacedBy(10.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                strings.get(UiText.ADD_NEW_SUBSCRIPTION),
                                color = Color.White,
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                IconButton(onClick = onClearProfileDraft) {
                                    Icon(
                                        imageVector = Icons.Filled.DeleteSweep,
                                        contentDescription = strings.get(UiText.CLEAR_REMOTE_SOURCE),
                                        tint = Color.White,
                                    )
                                }
                                IconButton(onClick = onToggleAddSubscriptionEditor) {
                                    Icon(
                                        imageVector = Icons.Filled.Close,
                                        contentDescription = strings.get(UiText.CLOSE_SUBSCRIPTION_EDITOR),
                                        tint = Color.White,
                                    )
                                }
                            }
                        }
                        OutlinedTextField(
                            value = state.profileDraft,
                            onValueChange = onProfileDraftChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text(strings.get(UiText.SUBSCRIPTION_URL)) },
                            placeholder = { Text("https://example.com/subscription.txt") },
                            singleLine = true,
                        )
                        OutlinedTextField(
                            value = state.profileTitleDraft,
                            onValueChange = onProfileTitleDraftChange,
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text(strings.get(UiText.SUBSCRIPTION_NAME)) },
                            placeholder = { Text(strings.get(UiText.OPTIONAL_CUSTOM_NAME)) },
                            singleLine = true,
                        )
                        Text(
                            strings.get(UiText.DESKTOP_SUBSCRIPTION_URL_HELP),
                            color = Color(0xFFD3E3EE),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(onClick = onSaveSubscriptionDraft) {
                            Text(strings.get(UiText.SAVE_SUBSCRIPTION))
                        }
                    }
                }
            } else {
                DesktopAddSubscriptionLauncherCard(
                    onClick = onToggleAddSubscriptionEditor,
                )
            }
        }
    }
}

@Composable
private fun DesktopAdditionalSettingsMenu(
    state: MainUiState,
    onToggleDnsDialog: () -> Unit,
    onToggleHomeSshRouteDialog: () -> Unit,
    onSetStartOnBootEnabled: (Boolean) -> Unit,
    onSetAppMode: (AppMode) -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onToggleLanguageDialog: () -> Unit,
    onCheckAndDownloadUpdate: () -> Unit,
    onIgnoreRulesChange: (Boolean) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val strings = LocalAppStrings.current
    val refreshScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
        strings.get(UiText.SETTINGS_ALL_SUBSCRIPTIONS)
    } else {
        strings.get(UiText.SETTINGS_SELECTED_SUBSCRIPTION)
    }

    Box {
        OutlinedButton(
            onClick = { expanded = true },
            colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
        ) {
            Icon(
                imageVector = Icons.Filled.Settings,
                contentDescription = strings.get(UiText.ADDITIONAL_SETTINGS),
                modifier = Modifier.size(18.dp),
            )
        }
        DropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_HOME_SSH_ROUTE))
                        Text(
                            strings.get(
                                if (state.homeSshRouteSettings.enabled) UiText.SETTINGS_ENABLED else UiText.SETTINGS_DISABLED,
                            ) + if (state.homeSshRestartPending) " • ${strings.get(UiText.HOME_SSH_PENDING)}" else "",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleHomeSshRouteDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_LANGUAGE))
                        Text(
                            strings.languageDisplayName(state.appLanguage, Locale.getDefault().language),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleLanguageDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_START_ON_LOGIN))
                        Text(
                            if (state.startOnBootEnabled) strings.get(UiText.SETTINGS_ENABLED) else strings.get(UiText.SETTINGS_DISABLED),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = state.startOnBootEnabled,
                        onCheckedChange = { enabled ->
                            onSetStartOnBootEnabled(enabled)
                        },
                    )
                },
                onClick = {
                    onSetStartOnBootEnabled(!state.startOnBootEnabled)
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_VPN_PROXY_MODE))
                        Text(
                            if (state.appMode == AppMode.VPN) strings.get(UiText.SETTINGS_VPN_MODE) else strings.get(UiText.SETTINGS_PROXY_ONLY),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = state.appMode == AppMode.VPN,
                        onCheckedChange = { enabled ->
                            onSetAppMode(if (enabled) AppMode.VPN else AppMode.PROXY_ONLY)
                        },
                    )
                },
                onClick = {
                    onSetAppMode(
                        if (state.appMode == AppMode.VPN) {
                            AppMode.PROXY_ONLY
                        } else {
                            AppMode.VPN
                        },
                    )
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.IGNORE_RULES))
                        Text(
                            ignoreRulesDescription(state, showAppAssignments = false, strings = strings),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                trailingIcon = {
                    Switch(
                        checked = !state.routingIgnoreRulesDraft,
                        onCheckedChange = { enabled ->
                            onIgnoreRulesChange(!enabled)
                        },
                    )
                },
                onClick = {
                    onIgnoreRulesChange(!state.routingIgnoreRulesDraft)
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_SUBSCRIPTION_REFRESH))
                        Text(
                            "${strings.refreshPolicyDisplay(state.subscriptionRefreshPolicy, state.subscriptionRefreshCustomHours)} • $refreshScope",
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleRefreshPolicyDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_LOCATION_TEST))
                        Text(
                            strings.validationSummary(state.validationSettings),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleValidationSettingsDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_CUSTOM_DNS))
                        Text(
                            strings.get(state.dnsSettings.mode.uiText()),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onToggleDnsDialog()
                },
            )
            DropdownMenuItem(
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_UPDATE))
                        Text(
                            strings.format(UiText.SETTINGS_CURRENT_VERSION, DesktopBuildInfo.current().displayVersion),
                            color = Color(0xFF4A6070),
                            fontSize = 12.sp,
                        )
                    }
                },
                onClick = {
                    expanded = false
                    onCheckAndDownloadUpdate()
                },
            )
        }
    }
}

@Composable
private fun DesktopSettingsDialogs(
    state: MainUiState,
    systemLanguageCode: String?,
    onToggleDnsDialog: () -> Unit,
    onDnsModeDraftChange: (DnsMode) -> Unit,
    onCustomDnsDraftChange: (String) -> Unit,
    onSaveDns: () -> Unit,
    onToggleHomeSshRouteDialog: () -> Unit,
    onHomeSshEnabledChange: (Boolean) -> Unit,
    onHomeSshHostChange: (String) -> Unit,
    onHomeSshPortChange: (String) -> Unit,
    onHomeSshUserChange: (String) -> Unit,
    onHomeSshHostKeysChange: (String) -> Unit,
    onHomeSshRelayPortChange: (String) -> Unit,
    onImportHomeSshPrivateKey: () -> Unit,
    onSaveHomeSshRoute: () -> Unit,
    onDismissHomeSshRestart: () -> Unit,
    onRestartForHomeSsh: () -> Unit,
    onToggleAppModeDialog: () -> Unit,
    onSetAppMode: (AppMode) -> Unit,
    onToggleRefreshPolicyDialog: () -> Unit,
    onSubscriptionRefreshPolicyDraftChange: (SubscriptionRefreshPolicy) -> Unit,
    onFindBestAfterSubscriptionRefreshDraftChange: (Boolean) -> Unit,
    onSubscriptionRefreshCustomHoursDraftChange: (String) -> Unit,
    onSaveSubscriptionRefreshPolicy: () -> Unit,
    onToggleValidationSettingsDialog: () -> Unit,
    onValidationTestUrlDraftChange: (String) -> Unit,
    onValidationBatchSizeDraftChange: (String) -> Unit,
    onValidationSubscriptionRefreshConcurrencyDraftChange: (String) -> Unit,
    onValidationRetryCountDraftChange: (String) -> Unit,
    onValidationActiveVerificationWindowSizeDraftChange: (String) -> Unit,
    onSaveValidationSettings: () -> Unit,
    onToggleLanguageDialog: () -> Unit,
    onSetAppLanguage: (AppLanguage) -> Unit,
) {
    val strings = LocalAppStrings.current

    if (state.showLanguageDialog) {
        LanguageSettingsDialog(
            selectedLanguage = state.appLanguage,
            systemLanguageCode = systemLanguageCode,
            onSelectLanguage = onSetAppLanguage,
            onDismiss = onToggleLanguageDialog,
        )
    }

    if (state.showDnsDialog) {
        AlertDialog(
            onDismissRequest = onToggleDnsDialog,
            title = { Text(strings.get(UiText.SETTINGS_CUSTOM_DNS), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        strings.get(UiText.DNS_APPLIES_NEW_DESKTOP_SESSIONS),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    DnsMode.entries.forEach { mode ->
                        DesktopSecureDnsModeOption(
                            label = strings.get(mode.uiText()),
                            selected = state.dnsModeDraft == mode,
                            onClick = { onDnsModeDraftChange(mode) },
                        )
                    }
                    if (state.dnsSettings.legacyRawAddress.isNotBlank()) {
                        Text(
                            strings.get(UiText.DNS_LEGACY_MIGRATION_NOTICE),
                            color = Color(0xFFFFD18B),
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    OutlinedTextField(
                        value = state.customDnsEndpointDraft,
                        onValueChange = onCustomDnsDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.DNS_SECURE_ENDPOINT)) },
                        placeholder = {
                            Text(
                                if (state.dnsModeDraft == DnsMode.CUSTOM_DOT) {
                                    "tls://dns.example:853"
                                } else {
                                    "https://dns.example/dns-query"
                                },
                            )
                        },
                        enabled = state.dnsModeDraft != DnsMode.AUTOMATIC,
                        singleLine = true,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveDns) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleDnsDialog) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showHomeSshRouteDialog) {
        AlertDialog(
            onDismissRequest = onToggleHomeSshRouteDialog,
            title = { Text(strings.get(UiText.SETTINGS_HOME_SSH_ROUTE), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(strings.get(UiText.HOME_SSH_DESCRIPTION), color = Color(0xFFD3E3EE))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(strings.get(UiText.HOME_SSH_ENABLED))
                        Switch(checked = state.homeSshEnabledDraft, onCheckedChange = onHomeSshEnabledChange)
                    }
                    OutlinedTextField(
                        value = state.homeSshHostDraft,
                        onValueChange = onHomeSshHostChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.HOME_SSH_HOST)) },
                        placeholder = { Text("example.com") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshPortDraft,
                        onValueChange = onHomeSshPortChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.HOME_SSH_PORT)) },
                        placeholder = { Text("228") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshUserDraft,
                        onValueChange = onHomeSshUserChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.HOME_SSH_USER)) },
                        placeholder = { Text("kardinal") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshHostKeysDraft,
                        onValueChange = onHomeSshHostKeysChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.HOME_SSH_HOST_KEYS)) },
                        supportingText = { Text(strings.get(UiText.HOME_SSH_HOST_KEYS_HELP)) },
                        minLines = 2,
                    )
                    OutlinedTextField(
                        value = state.homeSshRelayPortDraft,
                        onValueChange = onHomeSshRelayPortChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.HOME_SSH_RELAY_PORT)) },
                        placeholder = { Text("10808") },
                        singleLine = true,
                    )
                    OutlinedButton(onClick = onImportHomeSshPrivateKey, modifier = Modifier.fillMaxWidth()) {
                        Text(strings.get(UiText.IMPORT_PRIVATE_KEY))
                    }
                    Text(
                        strings.get(
                            if (state.homeSshRouteSettings.credentialVersion > 0L) {
                                UiText.HOME_SSH_KEY_IMPORTED
                            } else {
                                UiText.HOME_SSH_KEY_MISSING
                            },
                        ),
                        color = Color(0xFFD3E3EE),
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveHomeSshRoute) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleHomeSshRouteDialog) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showHomeSshRestartDialog) {
        AlertDialog(
            onDismissRequest = onDismissHomeSshRestart,
            title = { Text(strings.get(UiText.HOME_SSH_RESTART_TITLE), color = Color.White) },
            text = { Text(strings.get(UiText.HOME_SSH_RESTART_DESCRIPTION), color = Color(0xFFD3E3EE)) },
            containerColor = Color(0xFF141F2D),
            confirmButton = {
                TextButton(onClick = onRestartForHomeSsh) {
                    Text(strings.get(UiText.RESTART_NOW), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissHomeSshRestart) {
                    Text(strings.get(UiText.RESTART_LATER), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showAppModeDialog) {
        AlertDialog(
            onDismissRequest = onToggleAppModeDialog,
            title = { Text(strings.get(UiText.SETTINGS_VPN_PROXY_MODE), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = strings.get(UiText.APP_MODE_DESKTOP_DESCRIPTION),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
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
                                modifier = Modifier.fillMaxWidth(0.76f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = if (state.appMode == AppMode.VPN) {
                                        strings.get(UiText.VPN_MODE_LABEL)
                                    } else {
                                        strings.get(UiText.PROXY_ONLY)
                                    },
                                    color = Color.White,
                                    fontSize = 18.sp,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = if (state.appMode == AppMode.VPN) {
                                        strings.get(UiText.APP_MODE_DESKTOP_VPN_DETAIL)
                                    } else {
                                        strings.get(UiText.APP_MODE_DESKTOP_PROXY_DETAIL)
                                    },
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Switch(
                                checked = state.appMode == AppMode.VPN,
                                onCheckedChange = { enabled ->
                                    onSetAppMode(
                                        if (enabled) {
                                            AppMode.VPN
                                        } else {
                                            AppMode.PROXY_ONLY
                                        },
                                    )
                                },
                            )
                        }
                    }
                    Text(
                        text = strings.get(UiText.APP_MODE_DESKTOP_CHANGE_WARNING),
                        color = Color(0xFF9BB3C6),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {},
            dismissButton = {
                TextButton(onClick = onToggleAppModeDialog) {
                    Text(strings.get(UiText.CLOSE), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showRefreshPolicyDialog) {
        val refreshTarget = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
            strings.get(UiText.SETTINGS_ALL_SUBSCRIPTIONS)
        } else {
            strings.get(UiText.SETTINGS_SELECTED_SUBSCRIPTION)
        }
        AlertDialog(
            onDismissRequest = onToggleRefreshPolicyDialog,
            title = { Text(strings.get(UiText.SETTINGS_SUBSCRIPTION_REFRESH), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    Text(
                        text = strings.format(UiText.REFRESH_DESCRIPTION_DESKTOP, refreshTarget),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    listOf(
                        SubscriptionRefreshPolicy.OFF,
                        SubscriptionRefreshPolicy.EVERY_HOUR,
                        SubscriptionRefreshPolicy.CUSTOM,
                    ).forEach { policy ->
                        DesktopSettingsOption(
                            title = strings.refreshPolicyTitle(policy),
                            description = when (policy) {
                                SubscriptionRefreshPolicy.OFF -> strings.get(UiText.REFRESH_POLICY_OFF_DESCRIPTION)
                                SubscriptionRefreshPolicy.EVERY_HOUR -> strings.get(UiText.REFRESH_POLICY_HOURLY_DESCRIPTION)
                                SubscriptionRefreshPolicy.CUSTOM -> strings.get(UiText.REFRESH_POLICY_CUSTOM_DESCRIPTION)
                            },
                            selected = state.subscriptionRefreshPolicyDraft == policy,
                            onClick = { onSubscriptionRefreshPolicyDraftChange(policy) },
                        )
                    }
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
                                modifier = Modifier.fillMaxWidth(0.76f),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(
                                    text = if (state.findBestAfterSubscriptionRefreshDraft) {
                                        strings.get(UiText.FIND_BEST_AFTER_REFRESH)
                                    } else {
                                        strings.get(UiText.KEEP_CURRENT_LOCATION_AFTER_REFRESH)
                                    },
                                    color = Color.White,
                                    fontWeight = FontWeight.Bold,
                                )
                                Text(
                                    text = strings.get(UiText.FIND_BEST_AFTER_REFRESH_DESCRIPTION),
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Switch(
                                checked = state.findBestAfterSubscriptionRefreshDraft,
                                onCheckedChange = onFindBestAfterSubscriptionRefreshDraftChange,
                            )
                        }
                    }
                    if (state.subscriptionRefreshPolicyDraft == SubscriptionRefreshPolicy.CUSTOM) {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            OutlinedTextField(
                                value = state.subscriptionRefreshCustomHoursDraft,
                                onValueChange = onSubscriptionRefreshCustomHoursDraftChange,
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text(strings.get(UiText.CUSTOM_INTERVAL_HOURS)) },
                                placeholder = { Text("0.5") },
                                singleLine = true,
                            )
                            Text(
                                text = strings.get(UiText.CUSTOM_INTERVAL_HELP),
                                color = Color(0xFF9BB3C6),
                                fontSize = 12.sp,
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveSubscriptionRefreshPolicy) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleRefreshPolicyDialog) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showValidationSettingsDialog) {
        val searchScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && state.subscriptions.size > 1) {
            strings.get(UiText.SETTINGS_ALL_SUBSCRIPTIONS)
        } else {
            strings.get(UiText.SETTINGS_SELECTED_SUBSCRIPTION)
        }
        AlertDialog(
            onDismissRequest = onToggleValidationSettingsDialog,
            title = { Text(strings.get(UiText.SETTINGS_LOCATION_TEST), color = Color.White) },
            containerColor = Color(0xFF141F2D),
            textContentColor = Color.White,
            text = {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 420.dp)
                        .verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        text = strings.format(UiText.VALIDATION_DESCRIPTION_DESKTOP, searchScope),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = state.validationTestUrlDraft,
                        onValueChange = onValidationTestUrlDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.TEST_SITE)) },
                        placeholder = { Text(strings.get(UiText.TEST_SITE_PLACEHOLDER)) },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationBatchSizeDraft,
                        onValueChange = onValidationBatchSizeDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.BATCH_SIZE)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationSubscriptionRefreshConcurrencyDraft,
                        onValueChange = onValidationSubscriptionRefreshConcurrencyDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.SUBSCRIPTION_REFRESH_CONCURRENCY)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationRetryCountDraft,
                        onValueChange = onValidationRetryCountDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.RETRY_COUNT)) },
                        placeholder = { Text("1") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationActiveVerificationWindowSizeDraft,
                        onValueChange = onValidationActiveVerificationWindowSizeDraftChange,
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text(strings.get(UiText.ACTIVE_VERIFICATION_WINDOW)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    Text(
                        text = strings.format(
                            UiText.VALIDATION_DESKTOP_SUMMARY,
                            strings.validationSummary(state.validationSettings),
                        ),
                        color = Color(0xFF9ED6FF),
                        fontSize = 12.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = onSaveValidationSettings) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleValidationSettingsDialog) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }
}

@Composable
private fun DesktopSecureDnsModeOption(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label, color = Color.White)
    }
}

private fun DnsMode.uiText(): UiText = when (this) {
    DnsMode.AUTOMATIC -> UiText.DNS_MODE_AUTOMATIC
    DnsMode.CUSTOM_DOH -> UiText.DNS_MODE_DOH
    DnsMode.CUSTOM_DOT -> UiText.DNS_MODE_DOT
}

@Composable
private fun DesktopSettingsOption(
    title: String,
    description: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (selected) Color(0x334B7BE5) else Color(0x24141F2D),
        ),
        border = if (selected) BorderStroke(1.dp, Color(0xFF9ED6FF)) else null,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = title,
                color = Color.White,
                fontWeight = FontWeight.Bold,
            )
            Text(
                text = description,
                color = Color(0xFFD3E3EE),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun DesktopAddSubscriptionLauncherCard(
    onClick: () -> Unit,
) {
    val strings = LocalAppStrings.current
    val borderColor = Color(0xFF9ED6FF)
    val cornerRadius = 20.dp
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .drawBehind {
                drawRoundRect(
                    color = borderColor,
                    topLeft = androidx.compose.ui.geometry.Offset(1.dp.toPx(), 1.dp.toPx()),
                    size = size.copy(
                        width = size.width - 2.dp.toPx(),
                        height = size.height - 2.dp.toPx(),
                    ),
                    cornerRadius = CornerRadius(cornerRadius.toPx(), cornerRadius.toPx()),
                    style = Stroke(
                        width = 1.5.dp.toPx(),
                        pathEffect = PathEffect.dashPathEffect(
                            floatArrayOf(12.dp.toPx(), 10.dp.toPx()),
                        ),
                    ),
                )
            },
        shape = RoundedCornerShape(cornerRadius),
        colors = CardDefaults.cardColors(containerColor = Color(0x141D2934)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 22.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(42.dp)
                    .background(Color(0x223C7AE6), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.Filled.Add,
                    contentDescription = strings.get(UiText.ADD_NEW_SUBSCRIPTION),
                    tint = Color.White,
                )
            }
            Text(
                text = strings.get(UiText.ADD_NEW_SUBSCRIPTION),
                color = Color.White,
                fontSize = 16.sp,
            )
        }
    }
}

@Composable
private fun DesktopActionRow(
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onExportFile: () -> Unit,
    onExportClipboard: () -> Unit,
) {
    val strings = LocalAppStrings.current
    var showImportMenu by remember { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box {
            OutlinedButton(
                onClick = { showImportMenu = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.IMPORT))
            }
            DropdownMenu(
                expanded = showImportMenu,
                onDismissRequest = { showImportMenu = false },
            ) {
                DropdownMenuItem(
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showImportMenu = false
                        onImportFile()
                    },
                )
                DropdownMenuItem(
                    text = { Text(strings.get(UiText.CLIPBOARD)) },
                    onClick = {
                        showImportMenu = false
                        onImportClipboard()
                    },
                )
            }
        }
        Box {
            OutlinedButton(
                onClick = { showExportMenu = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.EXPORT))
            }
            DropdownMenu(
                expanded = showExportMenu,
                onDismissRequest = { showExportMenu = false },
            ) {
                DropdownMenuItem(
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showExportMenu = false
                        onExportFile()
                    },
                )
                DropdownMenuItem(
                    text = { Text(strings.get(UiText.CLIPBOARD)) },
                    onClick = {
                        showExportMenu = false
                        onExportClipboard()
                    },
                )
            }
        }
    }
}

private fun DesktopLocationRecord.toSharedRow(): SavedLocationRow {
    return SavedLocationRow(
        index = index,
        rawLink = rawLink,
        name = name,
        server = server,
        details = details,
        benchmarkDetail = benchmarkDetail,
        autoSelectable = isValid,
        isSelected = isSelected,
    )
}
