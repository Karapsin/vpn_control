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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalLayoutDirection
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
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.ControlCode
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
import com.kardinal.vpncontrol.shared.ui.VpnControlColors
import com.kardinal.vpncontrol.shared.ui.VpnControlTheme
import com.kardinal.vpncontrol.shared.ui.appLayoutDirection
import com.kardinal.vpncontrol.shared.ui.formatLocationCountLabel
import com.kardinal.vpncontrol.shared.ui.ignoreRulesDescription
import com.kardinal.vpncontrol.shared.ui.rememberAppStrings
import java.awt.GraphicsEnvironment
import java.util.Locale
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlin.system.exitProcess

fun main(rawArgs: Array<String>) {
    val invocation = DesktopWorkspacePaths.parse(rawArgs.toList()).getOrElse {
        if (desktopCliWantsJson(rawArgs.toList())) {
            desktopCliPrintLine(desktopCliJsonFailure(com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT,
                java.util.UUID.randomUUID().toString()).message)
        } else desktopCliPrintLine("INVALID_ARGUMENT: invalid state directory or command.")
        exitProcess(1)
    }
    DesktopWorkspacePaths.configure(invocation)
    val requestedFrontendOwner = if (invocation.arguments.firstOrNull() == DESKTOP_FRONTEND_OWNER_ARGUMENT) {
        val value = invocation.arguments.getOrNull(1)
        if (invocation.arguments.size != 2 || value == null ||
            runCatching { java.util.UUID.fromString(value).toString() == value }.getOrDefault(false).not()) {
            desktopCliPrintLine("INVALID_ARGUMENT")
            exitProcess(1)
        }
        value
    } else null
    val args = if (requestedFrontendOwner != null) emptyArray() else invocation.arguments.toTypedArray()
    DesktopSmokeTest.handleArgs(args)?.let { exitProcess(it) }
    DesktopHeadlessController.handleArgs(args)?.let { exitProcess(it) }
    DesktopCli.handleArgs(args)?.let { exitProcess(it) }
    val relaunchArgs = (if (requestedFrontendOwner != null) arrayOf(DESKTOP_FRONTEND_OWNER_ARGUMENT, requestedFrontendOwner) else args) +
        invocation.directory?.let { arrayOf("--state-dir", it.toString()) }.orEmpty()
    DesktopWindowsElevation.elevateIfRequired(relaunchArgs)?.let { exitProcess(it) }
    DesktopVpnIntegrationTest.handleArgs(args)?.let { exitProcess(it) }
    if (!isDesktopDisplayAvailable()) {
        println("VPN Control needs a graphical desktop session; DISPLAY or WAYLAND_DISPLAY is not available.")
        return
    }
    val activationEvents = DesktopActivationEvents()
    val hideEvents = DesktopActivationEvents()
    val visibility = DesktopFrontendVisibility()
    val frontendRegistration = DesktopFrontendInstance.start(DesktopWorkspacePaths.root(), visibility)
    if (frontendRegistration == null) {
        if (requestedFrontendOwner == null) DesktopFrontendInstance.show(DesktopWorkspacePaths.root())
        else runCatching {
            val endpoint = DesktopFrontendInstance.endpoint(DesktopWorkspacePaths.root())
            val existing = DesktopControlEndpoint.read(endpoint)
            DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(
                com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
                    com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.GUI_SHOW,
                        mapOf("owner" to com.kardinal.vpncontrol.model.ControlValue.Text(requestedFrontendOwner))),
                    controllerId = existing.controllerId), 3), endpoint)
        }
        return
    }
    val frontendScope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
    val connection = kotlinx.coroutines.runBlocking {
        DesktopGuiOwnerConnection.connect(frontendScope, frontendRegistration.identity, expectedOwnerId = requestedFrontendOwner)
    }.getOrElse {
        frontendRegistration.close()
        frontendScope.coroutineContext[Job]?.cancel()
        desktopCliPrintLine("UNAVAILABLE: could not attach graphical frontend.")
        return
    }
    val frontend = DesktopFrontendClient(connection.session, connection.session.presentations, connection.failure)
    visibility.ownerId = connection.session.snapshots.value.controllerId
    visibility.available = { connection.failure.value == null }
    val startInTray = args.any { it == "--autostart" || it == "--tray" || it == "--minimized" }
    try {
        application {
            DesktopApplication(startInTray, activationEvents, hideEvents, frontend, visibility, ::exitApplication)
        }
    } finally {
        connection.close()
        frontendRegistration.close()
        frontendScope.coroutineContext[Job]?.cancel()
    }
}

@Composable
private fun DesktopApplication(
    startInTray: Boolean,
    activationEvents: DesktopActivationEvents,
    hideEvents: DesktopActivationEvents,
    frontend: DesktopFrontendClient,
    visibility: DesktopFrontendVisibility,
    onExitApplication: () -> Unit,
) {
    val coroutineScope = rememberCoroutineScope()
    var trayWindowState by remember {
        mutableStateOf(
            initialDesktopTrayWindowState(
                startInTray = startInTray,
                traySupported = isDesktopTraySupported(),
            ),
        )
    }
    var exitRequested by remember { mutableStateOf(false) }
    var commandFailure by remember { mutableStateOf<com.kardinal.vpncontrol.model.ControlCode?>(null) }
    var updateJob by remember { mutableStateOf<Job?>(null) }
    var updateDialogRequested by remember { mutableStateOf(false) }
    val presentation by frontend.presentations.collectAsState()
    val connectionFailure by frontend.failure.collectAsState()
    val state = presentation?.toFrontendUiState() ?: return
    val appStrings = rememberAppStrings(state.appLanguage, Locale.getDefault().language)
    suspend fun executeGuiCommand(command: DesktopCliCommand): DesktopCliResponse = executeDesktopGuiCommand(
        command, frontend::execute,
    ) { code ->
        commandFailure = code
        trayWindowState = trayWindowState.withWindowShown()
    }
    DisposableEffect(activationEvents) {
        activationEvents.setShowWindowHandler {
            trayWindowState = trayWindowState.withWindowShown()
        }
        onDispose {
            activationEvents.setShowWindowHandler(null)
        }
    }
    DisposableEffect(hideEvents) {
        hideEvents.setShowWindowHandler { trayWindowState = trayWindowState.withHideWindowRequested() }
        onDispose { hideEvents.setShowWindowHandler(null) }
    }

    fun detachFrontend() {
        if (exitRequested) return
        exitRequested = true
        coroutineScope.launch {
            javax.swing.SwingUtilities.invokeLater { onExitApplication() }
        }
    }
    fun quitOwner() {
        if (exitRequested) return
        coroutineScope.launch {
            val result = frontend.read(ControlOperationId.QUIT)
            if (result.ok && result.final) detachFrontend() else commandFailure = result.code
        }
    }

    fun checkAndDownloadUpdate() {
        if (updateJob?.isActive == true) return
        updateDialogRequested = true
        updateJob = coroutineScope.launch {
            val checked = frontend.read(ControlOperationId.UPDATES_CHECK)
            if (!checked.ok) commandFailure = checked.code
            else {
                val status = frontend.read(ControlOperationId.UPDATES_STATUS)
                if (!status.ok) commandFailure = status.code
                else if ((status.data["available"] as? ControlValue.BooleanValue)?.value == true) {
                    val downloaded = frontend.read(ControlOperationId.UPDATES_DOWNLOAD)
                    if (!downloaded.ok) commandFailure = downloaded.code
                }
            }
            updateJob = null
        }
    }

    fun dismissOrCancelUpdate() {
        updateDialogRequested = false
        updateJob?.cancel()
        updateJob = null
        coroutineScope.launch {
            val result = frontend.read(ControlOperationId.UPDATES_CANCEL)
            if (!result.ok) commandFailure = result.code
        }
    }

    fun installPreparedUpdate() {
        if (updateJob?.isActive == true) return
        updateJob = coroutineScope.launch {
            val result = frontend.read(ControlOperationId.UPDATES_INSTALL)
            if (!result.ok) commandFailure = result.code
            else javax.swing.SwingUtilities.invokeLater { onExitApplication() }
            updateJob = null
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
            connectionActionEnabled = !state.isBusy && connectionFailure == null,
            findBestEnabled = !state.isBusy && connectionFailure == null,
            onToggleConnection = {
                if (!state.isBusy && connectionFailure == null) {
                    coroutineScope.launch { executeGuiCommand(if (state.isVpnRunning) DesktopCliCommand.Off else DesktopCliCommand.On) }
                }
            },
            onFindBest = {
                if (!state.isBusy && connectionFailure == null) {
                    coroutineScope.launch { executeGuiCommand(DesktopCliCommand.FindBest) }
                }
            },
            onShowWindow = {
                trayWindowState = trayWindowState.withWindowShown()
            },
            onHideWindow = {
                trayWindowState = trayWindowState.withHideWindowRequested()
            },
            onExit = ::quitOwner,
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
                detachFrontend()
            }
        },
        title = appStrings.get(UiText.APP_TITLE),
    ) {
        DisposableEffect(window, visibility, trayWindowState.canHideToTray) {
            visibility.install { shown ->
                if (!shown && !trayWindowState.canHideToTray) com.kardinal.vpncontrol.model.ControlCode.UNSUPPORTED
                else {
                    trayWindowState = if (shown) trayWindowState.withWindowShown() else trayWindowState.withHideWindowRequested()
                    window.isVisible = shown
                    if (shown) {
                        window.extendedState = window.extendedState and java.awt.Frame.ICONIFIED.inv()
                        window.toFront(); window.requestFocus()
                    }
                    if (window.isVisible == shown) com.kardinal.vpncontrol.model.ControlCode.OK
                    else com.kardinal.vpncontrol.model.ControlCode.UNAVAILABLE
                }
            }
            onDispose { visibility.install(null) }
        }
        LaunchedEffect(trayWindowState.windowVisible) {
            if (trayWindowState.windowVisible) {
                window.toFront()
                window.requestFocus()
            }
        }
        VpnControlTheme {
            commandFailure?.let { failure ->
                AlertDialog(
                    onDismissRequest = { commandFailure = null },
                    title = { Text(appStrings.get(UiText.STATUS)) },
                    text = { Text(failure.wireName) },
                    confirmButton = {
                        TextButton(onClick = { commandFailure = null }) { Text(appStrings.get(UiText.CLOSE)) }
                    },
                )
            }
            Surface(color = Color.Transparent) {
                DesktopVpnControlApp(
                    windowProvider = { window },
                    frontend = frontend,
                    showUpdateDialog = updateDialogRequested,
                    executeCommand = ::executeGuiCommand,
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
internal fun DesktopVpnControlApp(
    windowProvider: () -> ComposeWindow,
    frontend: DesktopFrontendClient,
    onCheckAndDownloadUpdate: () -> Unit,
    onDismissOrCancelUpdate: () -> Unit,
    onInstallUpdate: () -> Unit,
    actionScope: kotlinx.coroutines.CoroutineScope? = null,
    executeCommand: suspend (DesktopCliCommand) -> DesktopCliResponse = frontend::execute,
    previewState: MainUiState? = null,
    showUpdateDialog: Boolean = false,
) {
    val controlSession = frontend.session
    val presentation by frontend.presentations.collectAsState()
    val connectionFailure by frontend.failure.collectAsState()
    val ownerFrame = presentation ?: return
    val frame = ownerFrame.frontend
    val localScope = rememberCoroutineScope()
    val coroutineScope = actionScope ?: localScope
    val locationActionIdentity = remember { java.util.UUID.randomUUID().toString() }
    var currentScreen by remember { mutableStateOf(previewState?.currentScreen ?: AppScreen.MAIN) }
    val renderedState = previewState ?: ownerFrame.toFrontendUiState().let { it.copy(appUpdate = it.appUpdate.copy(showDialog = showUpdateDialog)) }
    val state = renderedState.copy(currentScreen = currentScreen,
        isBusy = connectionFailure != null || frame.activity.busy)
    var dnsDraft by remember {
        mutableStateOf(if (state.showDnsDialog && previewState != null) DesktopDnsDraft(ownerFrame.controllerId, ownerFrame.configurationRevision,
            state.dnsModeDraft, state.customDnsEndpointDraft) else null)
    }
    var dnsSaving by remember { mutableStateOf(false) }
    var dnsOpening by remember { mutableStateOf(false) }
    var dnsOpenFailure by remember { mutableStateOf<com.kardinal.vpncontrol.model.ControlCode?>(null) }
    LaunchedEffect(connectionFailure) { if (connectionFailure != null) dnsOpenFailure = connectionFailure }
    var settingsDraft by remember { mutableStateOf<DesktopSettingsDraft?>(null) }
    var settingsSaving by remember { mutableStateOf(false) }
    var settingsOpening by remember { mutableStateOf(false) }
    var routingDraft by remember { mutableStateOf<DesktopFrontendRoutingDraft?>(null) }
    var routingSaving by remember { mutableStateOf(false) }
    var logs by remember { mutableStateOf(previewState?.connectionLog) }
    var logsFailure by remember { mutableStateOf<ControlCode?>(null) }
    LaunchedEffect(currentScreen) {
        if (currentScreen == AppScreen.STATS && previewState == null) while (true) {
            val result = frontend.read(ControlOperationId.LOGS, mapOf("limit" to ControlValue.Text("100")))
            if (result.ok) {
                runCatching { desktopFrontendLogs(result) }.onSuccess { logs = it; logsFailure = null }
                    .onFailure { logsFailure = ControlCode.INCOMPATIBLE_PROTOCOL }
            } else logsFailure = result.code
            kotlinx.coroutines.delay(1_000)
        }
    }
    fun guardedAction(command: ControlCommand) {
        val request = desktopFrontendGuardedRequest(ownerFrame, command, locationActionIdentity)
        coroutineScope.launch {
            val result = frontend.submit(request)
            if (!result.ok) dnsOpenFailure = result.code
            else if (command.operation == ControlOperationId.ROUTING_IMPORT) {
                val read = frontend.read(ControlOperationId.ROUTING_SHOW)
                if (!read.ok) dnsOpenFailure = read.code
                else routingDraft = runCatching { DesktopFrontendRoutingDraft.from(read) }.getOrElse {
                    dnsOpenFailure = ControlCode.INCOMPATIBLE_PROTOCOL; routingDraft
                }
            }
        }
    }
    fun importContent(operation: ControlOperationId, content: Result<String?>) {
        content.fold(onSuccess = { text -> if (text != null) guardedAction(ControlCommand(operation,
            mapOf("input" to ControlValue.Text(text)))) }, onFailure = { dnsOpenFailure = ControlCode.INVALID_ARGUMENT })
    }
    fun exportContent(operation: ControlOperationId, clipboard: Boolean, title: String, filename: String) {
        coroutineScope.launch {
            val result = frontend.read(operation)
            val content = (result.data["content"] as? ControlValue.Text)?.value
            if (!result.ok || content == null) dnsOpenFailure = if (!result.ok) result.code else ControlCode.INCOMPATIBLE_PROTOCOL
            else {
                val written = if (clipboard) DesktopTextTransfer.writeClipboardText(content)
                    else DesktopTextTransfer.saveTextFile(windowProvider(), title, filename, content).map { Unit }
                if (written.isFailure) dnsOpenFailure = ControlCode.PERSISTENCE_FAILED
            }
        }
    }
    LaunchedEffect(currentScreen) {
        if (currentScreen == AppScreen.ROUTING_RULES && previewState == null) {
            val result = frontend.read(ControlOperationId.ROUTING_SHOW)
            if (result.ok) routingDraft = runCatching { DesktopFrontendRoutingDraft.from(result) }.getOrElse {
                dnsOpenFailure = ControlCode.INCOMPATIBLE_PROTOCOL; null
            } else dnsOpenFailure = result.code
        }
    }
    LaunchedEffect(routingDraft, routingSaving) {
        val captured = routingDraft ?: return@LaunchedEffect
        if (captured.failure != null || routingSaving || captured.domains == captured.committedDomains) return@LaunchedEffect
        kotlinx.coroutines.delay(350)
        routingSaving = true
        coroutineScope.launch {
        try {
            val result = frontend.submit(captured.request())
            if (routingDraft?.openingId == captured.openingId) {
                if (!result.ok) { routingDraft = routingDraft?.copy(failure = result.code); dnsOpenFailure = result.code }
                else routingDraft = routingDraft?.copy(revision = result.configurationRevision, committedDomains = captured.domains)
            }
        } finally { routingSaving = false }
        }
    }
    var subscriptionDraft by remember {
        mutableStateOf(if (previewState != null && state.showAddSubscriptionEditor)
            DesktopSubscriptionDraft(ownerFrame.controllerId, ownerFrame.configurationRevision, null, state.profileDraft, state.profileTitleDraft)
        else if (previewState != null && state.showProfileHistoryRenameDialog)
            state.subscriptions.singleOrNull { it.url == state.profileHistoryRenameSource }?.let {
                DesktopSubscriptionDraft(ownerFrame.controllerId, ownerFrame.configurationRevision, it.id,
                    state.profileHistoryRenameUrlDraft, state.profileHistoryRenameDraft)
            }
        else null)
    }
    var subscriptionOpening by remember { mutableStateOf(false) }
    var subscriptionSaving by remember { mutableStateOf(false) }
    fun openSubscriptionEditor(id: String?) {
        if (subscriptionOpening) return
        subscriptionOpening = true
        dnsOpenFailure = null
        coroutineScope.launch {
            try {
                val command = if (id == null) com.kardinal.vpncontrol.model.ControlCommand(
                    com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SHOW) else com.kardinal.vpncontrol.model.ControlCommand(
                    com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_SHOW,
                    mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(id)))
                val result = frontend.read(command.operation, command.arguments)
                if (result.ok) subscriptionDraft = DesktopSubscriptionDraft.from(result, id) else dnsOpenFailure = result.code
            } finally { subscriptionOpening = false }
        }
    }
    fun saveSubscriptionEditor() {
        val captured = subscriptionDraft ?: return
        if (subscriptionSaving) return
        subscriptionSaving = true
        coroutineScope.launch {
            try {
                val code = frontend.submit(captured.request()).code
                if (subscriptionDraft?.openingId == captured.openingId) {
                    subscriptionDraft = if (code == com.kardinal.vpncontrol.model.ControlCode.OK && subscriptionDraft == captured) null
                        else subscriptionDraft?.copy(failure = if (code == com.kardinal.vpncontrol.model.ControlCode.OK)
                            com.kardinal.vpncontrol.model.ControlCode.CONFLICT else code)
                }
            } finally { subscriptionSaving = false }
        }
    }
    var sshRestartDialog by remember { mutableStateOf(state.showHomeSshRestartDialog) }
    var sshKeyImport by remember { mutableStateOf<DesktopSshKeyImportAction?>(null) }
    var sshKeyImporting by remember { mutableStateOf(false) }
    var sshKeyPresent by remember { mutableStateOf(previewState?.let { it.homeSshRouteSettings.credentialVersion > 0L }) }
    fun toggleLocalSettings(group: DesktopSettingsDraftGroup, onOpened: ((DesktopSettingsDraft) -> Unit)? = null) {
        if (settingsDraft?.group == group && onOpened == null) { settingsDraft = null; sshKeyImport = null; return }
        if (settingsOpening) return
        sshKeyImport = null
        settingsOpening = true
        dnsOpenFailure = null
        coroutineScope.launch {
            try {
                val result = frontend.read(com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SHOW)
                if (result.ok) {
                    val opened = DesktopSettingsDraft.from(group, result)
                    settingsDraft = opened
                    onOpened?.invoke(opened)
                    if (group == DesktopSettingsDraftGroup.SSH) {
                        val key = frontend.read(ControlOperationId.SSH_KEY_STATUS)
                        sshKeyPresent = if (key.ok) (key.data["present"] as? ControlValue.BooleanValue)?.value else null
                    }
                } else dnsOpenFailure = result.code
            } finally { settingsOpening = false }
        }
    }
    fun editLocalSettings(key: String, value: String) { settingsDraft = settingsDraft?.edit(key, value) }
    fun saveLocalSettings(captured: DesktopSettingsDraft? = settingsDraft) {
        captured ?: return
        if (settingsSaving) return
        val request = captured.request().getOrElse {
            settingsDraft = captured.copy(failure = com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT)
            return
        }
        settingsSaving = true
        coroutineScope.launch {
            try {
                val result = frontend.submit(request)
                val code = result.code
                if (frontendSettingsNeedsRestart(captured.group, result)) sshRestartDialog = true
                if (captured.group == DesktopSettingsDraftGroup.LANGUAGE && code != com.kardinal.vpncontrol.model.ControlCode.OK)
                    dnsOpenFailure = code
                if (settingsDraft?.openingId == captured.openingId) {
                    settingsDraft = if (code == com.kardinal.vpncontrol.model.ControlCode.OK && settingsDraft == captured) null
                        else settingsDraft?.copy(failure = if (code == com.kardinal.vpncontrol.model.ControlCode.OK)
                            com.kardinal.vpncontrol.model.ControlCode.CONFLICT else code)
                    if (settingsDraft == null) sshKeyImport = null
                }
            } finally { settingsSaving = false }
        }
    }
    fun toggleLocalDns() {
        if (dnsDraft != null) { dnsDraft = null; return }
        if (dnsOpening) return
        dnsOpening = true
        dnsOpenFailure = null
        coroutineScope.launch {
            try {
                val result = frontend.read(com.kardinal.vpncontrol.model.ControlOperationId.SETTINGS_SHOW)
                if (result.ok) dnsDraft = DesktopDnsDraft.from(result) else dnsOpenFailure = result.code
            } finally { dnsOpening = false }
        }
    }
    fun saveLocalDns() {
        val captured = dnsDraft ?: return
        if (dnsSaving) return
        dnsSaving = true
        coroutineScope.launch {
            try {
                val code = frontend.submit(captured.request()).code
                if (dnsDraft?.openingId == captured.openingId) {
                    dnsDraft = if (code == com.kardinal.vpncontrol.model.ControlCode.OK && dnsDraft == captured) null
                        else dnsDraft?.copy(failure = if (code == com.kardinal.vpncontrol.model.ControlCode.OK)
                            com.kardinal.vpncontrol.model.ControlCode.CONFLICT else code)
                }
            } finally { dnsSaving = false }
        }
    }
    LaunchedEffect(controlSession) {
        if (controlSession != null && state.showDnsDialog && dnsDraft == null) toggleLocalDns()
        if (state.showRefreshPolicyDialog) toggleLocalSettings(DesktopSettingsDraftGroup.REFRESH)
        else if (state.showValidationSettingsDialog) toggleLocalSettings(DesktopSettingsDraftGroup.VALIDATION)
        else if (state.showLanguageDialog) toggleLocalSettings(DesktopSettingsDraftGroup.LANGUAGE)
        else if (state.showHomeSshRouteDialog) toggleLocalSettings(DesktopSettingsDraftGroup.SSH)
        else if (state.showAppModeDialog) toggleLocalSettings(DesktopSettingsDraftGroup.MODE)
    }
    val sourcePresentation = frame.source
    val showMismatchWarning = sourcePresentation.selectedOutsideCurrent
    val systemLanguageCode = Locale.getDefault().language
    val appStrings = rememberAppStrings(state.appLanguage, systemLanguageCode)
    val activeProfile = sourcePresentation.selected.render(appStrings)
    val currentSelection = sourcePresentation.current.render(appStrings)
    var locationEditorOpen by remember { mutableStateOf(state.showLocationDialog) }
    var locationEditorTarget by remember {
        mutableStateOf(state.editingLocationIndex?.let { frame.locations.getOrNull(it)?.id })
    }
    var locationEditorText by remember { mutableStateOf(state.locationDraft) }
    var locationEditorError by remember { mutableStateOf<String?>(null) }
    var locationEditorOpening by remember { mutableStateOf(false) }
    var locationEditorSaving by remember { mutableStateOf(false) }
    var locationDraft by remember {
        mutableStateOf(if (previewState != null && state.showLocationDialog) DesktopLocationDraft(ownerFrame.controllerId,
            ownerFrame.configurationRevision, locationEditorTarget, state.locationDraft) else null)
    }

    CompositionLocalProvider(
        LocalAppStrings provides appStrings,
        LocalLayoutDirection provides appLayoutDirection(appStrings.language),
    ) {
    dnsOpenFailure?.let { failure ->
        AlertDialog(onDismissRequest = { dnsOpenFailure = null },
            title = { Text(appStrings.get(UiText.STATUS)) }, text = { Text(failure.wireName) },
            confirmButton = { TextButton(onClick = { dnsOpenFailure = null }) { Text(appStrings.get(UiText.CLOSE)) } })
    }
    if (locationEditorOpen) {
        AlertDialog(
            onDismissRequest = { locationEditorOpen = false; locationDraft = null },
            containerColor = Color(0xFF141F2D), textContentColor = Color.White,
            title = { Text(appStrings.get(if (locationEditorTarget == null) UiText.ADD_LOCATION else UiText.EDIT_LOCATION), color = Color.White) },
            text = {
                Column(modifier = Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    OutlinedTextField(
                        value = locationEditorText, onValueChange = { locationEditorText = it; locationEditorError = null },
                        modifier = Modifier.fillMaxWidth().testTag("location-draft"),
                        minLines = 5, maxLines = 12,
                        label = { Text(appStrings.get(UiText.LOCATION_CONFIG_LABEL)) },
                    )
                    Text(appStrings.get(UiText.LOCATION_CONFIG_HELP), color = Color(0xFFD3E3EE), fontSize = 12.sp)
                    locationEditorError?.let { Text(appStrings.statusMessage(it), color = MaterialTheme.colorScheme.error) }
                }
            },
            confirmButton = {
                TextButton(enabled = !state.isBusy && !locationEditorSaving, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save"), onClick = {
                    val captured = locationDraft?.copy(content = locationEditorText)
                    if (captured != null && !locationEditorSaving) {
                        locationEditorSaving = true
                        coroutineScope.launch {
                            try {
                                val code = frontend.submit(captured.request()).code
                                if (locationDraft?.openingId == captured.openingId) {
                                    if (code == com.kardinal.vpncontrol.model.ControlCode.OK && locationEditorText == captured.content) {
                                        locationEditorOpen = false; locationDraft = null
                                    } else locationEditorError = if (code == com.kardinal.vpncontrol.model.ControlCode.OK) "CONFLICT" else code.wireName
                                }
                            } finally { locationEditorSaving = false }
                        }
                    }
                }) { Text(appStrings.get(UiText.SAVE)) }
            },
            dismissButton = {
                TextButton(onClick = { locationEditorOpen = false; locationDraft = null }, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel")) {
                    Text(appStrings.get(UiText.CANCEL))
                }
            },
        )
    }
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
        subscriptionCount = frame.subscriptions.size,
        state = (settingsDraft?.overlay(state) ?: state.copy(showRefreshPolicyDialog = false, showValidationSettingsDialog = false,
            showLanguageDialog = false, showHomeSshRouteDialog = false, showAppModeDialog = false))
            .copy(showDnsDialog = dnsDraft != null, dnsModeDraft = dnsDraft?.mode ?: state.dnsSettings.mode,
                customDnsEndpointDraft = dnsDraft?.endpoint ?: state.dnsSettings.endpoint,
                showHomeSshRestartDialog = sshRestartDialog),
        dnsFailure = dnsDraft?.failure,
        dnsSaving = dnsSaving,
        settingsFailure = settingsDraft?.failure,
        settingsSaving = settingsSaving,
        sshKeyRetryAvailable = sshKeyImport != null && !sshKeyImporting,
        sshKeyImporting = sshKeyImporting,
        sshKeyPresent = sshKeyPresent,
        systemLanguageCode = systemLanguageCode,
        onToggleDnsDialog = ::toggleLocalDns,
        onDnsModeDraftChange = { mode -> dnsDraft = dnsDraft?.copy(mode = mode) },
        onCustomDnsDraftChange = { endpoint -> dnsDraft = dnsDraft?.copy(endpoint = endpoint) },
        onSaveDns = ::saveLocalDns,
        onToggleHomeSshRouteDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.SSH) },
        onHomeSshEnabledChange = { editLocalSettings("ssh.enabled", it.toString()) },
        onHomeSshHostChange = { editLocalSettings("ssh.host", it) },
        onHomeSshPortChange = { editLocalSettings("ssh.port", it) },
        onHomeSshUserChange = { editLocalSettings("ssh.user", it) },
        onHomeSshHostKeysChange = { editLocalSettings("ssh.host-keys", it) },
        onHomeSshRelayPortChange = { editLocalSettings("ssh.relay-port", it) },
        onImportHomeSshPrivateKey = {
            if (!sshKeyImporting) {
                val capturedSnapshot = ownerFrame
                val revision = capturedSnapshot.configurationRevision
                val action = sshKeyImport ?: DesktopTextTransfer.openTextFile(
                    windowProvider(), appStrings.get(UiText.IMPORT_PRIVATE_KEY),
                ).fold(onSuccess = { content -> content?.let {
                    DesktopSshKeyImportAction(capturedSnapshot.controllerId, revision, it)
                } }, onFailure = { dnsOpenFailure = com.kardinal.vpncontrol.model.ControlCode.INVALID_ARGUMENT; null })
                if (action != null) {
                sshKeyImport = action
                sshKeyImporting = true
                coroutineScope.launch {
                    try {
                        val result = frontend.submit(action.request())
                        if (sshKeyImport?.openingId == action.openingId) {
                            if (result.ok) {
                                sshKeyImport = null
                                sshKeyPresent = true
                                if (result.restartRequired) sshRestartDialog = true
                            } else settingsDraft = settingsDraft?.copy(failure = result.code)
                        }
                    } finally { sshKeyImporting = false }
                }
                }
            }
        },
        onSaveHomeSshRoute = { saveLocalSettings() },
        onDismissHomeSshRestart = { sshRestartDialog = false },
        onRestartForHomeSsh = {
            coroutineScope.launch {
                if (executeCommand(DesktopCliCommand.Restart).success) sshRestartDialog = false
            }
        },
        onToggleAppModeDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.MODE) },
        onSetAppMode = { mode ->
            if (!settingsSaving) settingsDraft?.edit("mode", if (mode == AppMode.VPN) "vpn" else "proxy-only")?.let {
                settingsDraft = it
                saveLocalSettings(it)
            }
        },
        onToggleRefreshPolicyDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.REFRESH) },
        onSubscriptionRefreshPolicyDraftChange = { editLocalSettings("refresh.policy", when (it) {
            SubscriptionRefreshPolicy.OFF -> "off"; SubscriptionRefreshPolicy.EVERY_HOUR -> "every-hour"; SubscriptionRefreshPolicy.CUSTOM -> "custom"
        }) },
        onFindBestAfterSubscriptionRefreshDraftChange = { editLocalSettings("refresh.find-best-after-refresh", it.toString()) },
        onSubscriptionRefreshCustomHoursDraftChange = { editLocalSettings("refresh.custom-hours", it) },
        onSaveSubscriptionRefreshPolicy = { saveLocalSettings() },
        onToggleValidationSettingsDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.VALIDATION) },
        onValidationTestUrlDraftChange = { editLocalSettings("validation.test-url", it) },
        onValidationBatchSizeDraftChange = { editLocalSettings("validation.batch-size", it) },
        onValidationSubscriptionRefreshConcurrencyDraftChange =
            { editLocalSettings("validation.subscription-refresh-concurrency", it) },
        onValidationRetryCountDraftChange = { editLocalSettings("validation.retry-count", it) },
        onValidationActiveVerificationWindowSizeDraftChange =
            { editLocalSettings("validation.active-verification-window-size", it) },
        onSaveValidationSettings = { saveLocalSettings() },
        onToggleLanguageDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.LANGUAGE) },
        onSetAppLanguage = { language ->
            if (!settingsSaving) settingsDraft?.edit("language", if (language == AppLanguage.SYSTEM) "system" else language.code)?.let {
                settingsDraft = it
                saveLocalSettings(it)
            }
        },
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                VpnControlColors.AppBackground,
            ),
    ) {
        HomeTabScaffold(
            currentScreen = state.currentScreen,
            onOpenMainTab = { currentScreen = AppScreen.MAIN },
            onOpenProfileTab = { currentScreen = AppScreen.PROFILE },
            onOpenLocationsTab = { currentScreen = AppScreen.LOCATIONS },
            onOpenStatsTab = { currentScreen = AppScreen.STATS },
            onOpenRoutingRules = { currentScreen = AppScreen.ROUTING_RULES },
            mainIcon = Icons.Filled.Home,
            profileIcon = Icons.Filled.Person,
            locationsIcon = Icons.Filled.Public,
            statsIcon = Icons.Filled.QueryStats,
            rulesIcon = Icons.Filled.Tune,
        ) {
            val rowRuntime = ownerFrame
            val presentationLocations = rowRuntime.locations
            fun submitSource(command: com.kardinal.vpncontrol.model.ControlCommand) {
                val request = desktopGuiSourceAction(locationActionIdentity,
                    rowRuntime.controllerId, rowRuntime.configurationRevision, command)
                coroutineScope.launch {
                    val code = frontend.submit(request).code
                    if (code != com.kardinal.vpncontrol.model.ControlCode.OK) dnsOpenFailure = code
                }
            }
            when (state.currentScreen) {
                AppScreen.MAIN -> MainScreen(
                    state = state,
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    statusDetails = frame.activity.runtimeDetails.messages(),
                    onToggleVpn = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { executeCommand(if (state.isVpnRunning) DesktopCliCommand.Off else DesktopCliCommand.On) }
                    },
                    onRefresh = {
                        if (state.isBusy) return@MainScreen
                        coroutineScope.launch { executeCommand(DesktopCliCommand.FindBest) }
                    },
                    onExportDiagnostics = {
                        if (state.isBusy) return@MainScreen
                        exportContent(ControlOperationId.DIAGNOSTICS_EXPORT, false, appStrings.get(UiText.EXPORT_DIAGNOSTICS),
                            DesktopDiagnosticsExporter.suggestedFileName())
                    },
                    powerIcon = Icons.Filled.PowerSettingsNew,
                    findBestIcon = Icons.Filled.MyLocation,
                    headerActions = {
                        DesktopAdditionalSettingsMenu(
                            subscriptionCount = frame.subscriptions.size,
                            state = state,
                            onToggleDnsDialog = ::toggleLocalDns,
                            onToggleHomeSshRouteDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.SSH) },
                            onSetStartOnBootEnabled = { guardedAction(ControlCommand(ControlOperationId.SETTINGS_SET,
                                mapOf("key" to ControlValue.Text("autostart"), "value" to ControlValue.Text(it.toString())))) },
                            onSetAppMode = { mode ->
                                if (!settingsSaving) toggleLocalSettings(DesktopSettingsDraftGroup.MODE) { opened ->
                                    val edited = opened.edit("mode", if (mode == AppMode.VPN) "vpn" else "proxy-only")
                                    settingsDraft = edited
                                    saveLocalSettings(edited)
                                }
                            },
                            onToggleRefreshPolicyDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.REFRESH) },
                            onToggleValidationSettingsDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.VALIDATION) },
                            onToggleLanguageDialog = { toggleLocalSettings(DesktopSettingsDraftGroup.LANGUAGE) },
                            onCheckAndDownloadUpdate = onCheckAndDownloadUpdate,
                            onIgnoreRulesChange = { guardedAction(ControlCommand(ControlOperationId.ROUTING_SET,
                                mapOf("key" to ControlValue.Text("ignore-rules"), "value" to ControlValue.Text(it.toString())))) },
                        )
                    },
                )

                AppScreen.PROFILE -> ProfileScreen(
                    activeProfileLabel = activeProfile,
                    currentSelectionLabel = currentSelection,
                ) {
                    DesktopProfileContent(
                        state = state.copy(showAddSubscriptionEditor = subscriptionDraft?.subscriptionId == null && subscriptionDraft != null,
                            profileDraft = subscriptionDraft?.source.orEmpty(), profileTitleDraft = subscriptionDraft?.name.orEmpty(),
                            showProfileHistoryRenameDialog = subscriptionDraft?.subscriptionId != null,
                            profileHistoryRenameUrlDraft = subscriptionDraft?.source.orEmpty(),
                            profileHistoryRenameDraft = subscriptionDraft?.name.orEmpty()),
                        editorFailure = subscriptionDraft?.failure,
                        editorSaving = subscriptionSaving,
                        subscriptions = frame.subscriptions,
                        onActivateSelection = { id -> submitSource(com.kardinal.vpncontrol.model.ControlCommand(
                            com.kardinal.vpncontrol.model.ControlOperationId.SOURCE_SET,
                            if (id == com.kardinal.vpncontrol.model.ALL_SUBSCRIPTIONS_ID) mapOf("source" to com.kardinal.vpncontrol.model.ControlValue.Text("all"))
                            else mapOf("source" to com.kardinal.vpncontrol.model.ControlValue.Text("subscription"),
                                "subscription-id" to com.kardinal.vpncontrol.model.ControlValue.Text(id)))) },
                        onSetSourceMode = { mode -> submitSource(com.kardinal.vpncontrol.model.ControlCommand(
                            com.kardinal.vpncontrol.model.ControlOperationId.SOURCE_SET,
                            mapOf("mode" to com.kardinal.vpncontrol.model.ControlValue.Text(
                                if (mode == ProfileSourceMode.CURRENT_LOCATIONS) "current-locations" else "subscription")))) },
                        onToggleAddSubscriptionEditor = { if (subscriptionDraft != null) subscriptionDraft = null else openSubscriptionEditor(null) },
                        onProfileDraftChange = { subscriptionDraft = subscriptionDraft?.copy(source = it) },
                        onProfileTitleDraftChange = { subscriptionDraft = subscriptionDraft?.editName(it) },
                        onClearProfileDraft = { subscriptionDraft = subscriptionDraft?.copy(source = "", name = "") },
                        onSaveSubscriptionDraft = ::saveSubscriptionEditor,
                        onDeleteSubscription = { subscriptionId ->
                            if (state.isBusy) return@DesktopProfileContent
                            submitSource(com.kardinal.vpncontrol.model.ControlCommand(
                                com.kardinal.vpncontrol.model.ControlOperationId.SUBSCRIPTIONS_DELETE,
                                mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(subscriptionId))))
                        },
                        onShowSubscriptionRenameDialog = ::openSubscriptionEditor,
                        onCloseSubscriptionRenameDialog = { subscriptionDraft = null },
                        onSubscriptionRenameUrlDraftChange = { subscriptionDraft = subscriptionDraft?.copy(source = it) },
                        onSubscriptionRenameDraftChange = { subscriptionDraft = subscriptionDraft?.editName(it) },
                        onSaveSubscriptionRename = ::saveSubscriptionEditor,
                        onRefreshSubscription = { subscriptionId ->
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { executeCommand(DesktopCliCommand.SubscriptionRefresh(subscriptionId)) }
                        },
                        onRefreshAllSubscriptions = {
                            if (state.isBusy) return@DesktopProfileContent
                            coroutineScope.launch { executeCommand(DesktopCliCommand.SubscriptionRefresh("all")) }
                        },
                    )
                }

                AppScreen.LOCATIONS -> LocationsScreen(
                    state = state,
                    locations = presentationLocations.map { it.toSharedRow() },
                    selectedName = state.selectedProfileName.takeIf(String::isNotBlank),
                    activeProfileLabel = activeProfile,
                    showSubscriptionMismatchWarning = showMismatchWarning,
                    onShowAddLocation = if (state.profileSourceMode == ProfileSourceMode.CURRENT_LOCATIONS) ({
                        if (!locationEditorOpening) {
                            locationEditorOpening = true
                            coroutineScope.launch {
                                try {
                                    val result = frontend.read(com.kardinal.vpncontrol.model.ControlOperationId.STATUS)
                                    if (result.ok) {
                                        locationDraft = DesktopLocationDraft.from(result, null)
                                        locationEditorTarget = null; locationEditorText = ""; locationEditorError = null; locationEditorOpen = true
                                    } else dnsOpenFailure = result.code
                                } finally { locationEditorOpening = false }
                            }
                        }
                    }) else null,
                    onToggleSelectedLocationVpn = {
                        if (state.isBusy) return@LocationsScreen
                        coroutineScope.launch { executeCommand(if (state.isVpnRunning) DesktopCliCommand.Off else DesktopCliCommand.On) }
                    },
                    onBenchmarkLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        val id = presentationLocations.getOrNull(index)?.id ?: return@LocationsScreen
                        val command = DesktopCliCommand.LocationBenchmark(target = "", configurationId = id)
                        coroutineScope.launch { executeCommand(command) }
                    },
                    onSelectLocation = { index ->
                        presentationLocations.getOrNull(index)?.id?.let { id ->
                            val request = desktopGuiLocationAction(locationActionIdentity, rowRuntime.controllerId,
                                rowRuntime.configurationRevision, id, com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_SELECT)
                            coroutineScope.launch {
                                val code = frontend.submit(request).code
                                if (code != com.kardinal.vpncontrol.model.ControlCode.OK) dnsOpenFailure = code
                            }
                        }
                    },
                    onEditLocation = { index ->
                        presentationLocations.getOrNull(index)?.let { target ->
                            if (!locationEditorOpening) {
                                locationEditorOpening = true
                                val id = presentationLocations.getOrNull(index)?.id
                                val epoch = rowRuntime.controllerId
                                coroutineScope.launch {
                                    try {
                                        val read = com.kardinal.vpncontrol.model.ControlCommand(com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_SHOW,
                                            mapOf("id" to com.kardinal.vpncontrol.model.ControlValue.Text(id.orEmpty())))
                                        val result = frontend.submit(
                                            com.kardinal.vpncontrol.model.ControlRequest(java.util.UUID.randomUUID().toString(),
                                                read, controllerId = epoch))
                                        val content = (result.data["configuration"] as? com.kardinal.vpncontrol.model.ControlValue.Text)?.value
                                        if (!result.ok || content == null) {
                                            dnsOpenFailure = if (!result.ok) result.code
                                                else com.kardinal.vpncontrol.model.ControlCode.INCOMPATIBLE_PROTOCOL
                                        } else {
                                            locationEditorTarget = target.id
                                            locationDraft = DesktopLocationDraft.from(result, id)
                                            locationEditorText = content
                                            locationEditorError = null
                                            locationEditorOpen = true
                                        }
                                    } finally { locationEditorOpening = false }
                                }
                            }
                        }
                    },
                    onDeleteLocation = { index ->
                        if (state.isBusy) return@LocationsScreen
                        presentationLocations.getOrNull(index)?.id?.let { id ->
                            val request = desktopGuiLocationAction(locationActionIdentity, rowRuntime.controllerId,
                                rowRuntime.configurationRevision, id, com.kardinal.vpncontrol.model.ControlOperationId.LOCATIONS_DELETE)
                            coroutineScope.launch {
                                val code = frontend.submit(request).code
                                if (code != com.kardinal.vpncontrol.model.ControlCode.OK) dnsOpenFailure = code
                            }
                        }
                    },
                    controls = {
                        DesktopActionRow(
                            visualScope = "locations",
                            onImportFile = {
                                importContent(ControlOperationId.LOCATIONS_IMPORT,
                                    DesktopTextTransfer.openTextFile(windowProvider(), appStrings.get(UiText.IMPORT)))
                            },
                            onImportClipboard = { importContent(ControlOperationId.LOCATIONS_IMPORT, DesktopTextTransfer.readClipboardText()) },
                            onExportFile = {
                                exportContent(ControlOperationId.LOCATIONS_EXPORT, false, appStrings.get(UiText.LOCATIONS_EXPORT_TITLE), "locations.json")
                            },
                            onExportClipboard = { exportContent(ControlOperationId.LOCATIONS_EXPORT, true, "", "") },
                        )
                    },
                )

                AppScreen.ROUTING_RULES -> RoutingRulesScreen(
                    state = state.copy(routingDirectDomainsDraft = routingDraft?.domains ?: state.routingDirectDomainsDraft),
                    onAppSearchChange = {},
                    onToggleProxyApp = {},
                    onSelectAllProxyApps = {},
                    onClearAllProxyApps = {},
                    onDirectDomainsChange = { routingDraft = routingDraft?.copy(domains = it) },
                    onBlockQuicUdp443Change = {},
                    showAppAssignments = false,
                    controls = {
                        DesktopActionRow(
                            visualScope = "routing",
                            onImportFile = {
                                importContent(ControlOperationId.ROUTING_IMPORT,
                                    DesktopTextTransfer.openTextFile(windowProvider(), appStrings.get(UiText.IMPORT)))
                            },
                            onImportClipboard = { importContent(ControlOperationId.ROUTING_IMPORT, DesktopTextTransfer.readClipboardText()) },
                            onExportFile = {
                                exportContent(ControlOperationId.ROUTING_EXPORT, false, appStrings.get(UiText.RULES_EXPORT_TITLE), "routing-rules.json")
                            },
                            onExportClipboard = { exportContent(ControlOperationId.ROUTING_EXPORT, true, "", "") },
                        )
                    },
                )

                AppScreen.STATS -> if (logs != null && logsFailure == null) StatsScreen(state = state.copy(connectionLog = logs.orEmpty()))
                    else Text((logsFailure ?: ControlCode.UNAVAILABLE).wireName, color = MaterialTheme.colorScheme.error)
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
    subscriptions: List<DesktopPresentationSubscription>,
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
    editorFailure: com.kardinal.vpncontrol.model.ControlCode? = null,
    editorSaving: Boolean = false,
) {
    val strings = LocalAppStrings.current
    if (state.showProfileHistoryRenameDialog) {
        AlertDialog(
            onDismissRequest = onCloseSubscriptionRenameDialog,
            confirmButton = {
                TextButton(
                    onClick = onSaveSubscriptionRename,
                    enabled = !editorSaving,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save"),
                ) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = onCloseSubscriptionRenameDialog,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel"),
                ) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
            title = {
                Text(strings.get(UiText.RENAME_SUBSCRIPTION))
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    editorFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
                    OutlinedTextField(
                        value = state.profileHistoryRenameUrlDraft,
                        onValueChange = onSubscriptionRenameUrlDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("profile-rename-url"),
                        label = { Text(strings.get(UiText.SUBSCRIPTION_URL)) },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.profileHistoryRenameDraft,
                        onValueChange = onSubscriptionRenameDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("profile-rename-name"),
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
            modifier = Modifier.testTag("profile-source-mode"),
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
                            modifier = Modifier.testTag(
                                if (state.profileSourceMode == ProfileSourceMode.SUBSCRIPTION) {
                                    "profile-source-selection"
                                } else {
                                    "profile-current-locations"
                                },
                            ),
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
                if (subscriptions.size > 1) {
                    val allSelected = state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("profile-all-subscriptions")
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
                                            subscriptions.sumOf { it.locationCount }.toInt(),
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
                                    modifier = Modifier.size(48.dp).testTag("profile-refresh-all"),
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
                subscriptions.forEachIndexed { visualIndex, subscription ->
                    val isSelected = state.activeSubscriptionId == subscription.id
                    val refreshStatus = subscription.refreshStatus?.encoded().orEmpty()
                        .takeIf { it.isNotBlank() }
                        ?.let(strings::statusMessage)
                        ?: strings.get(UiText.NOT_REFRESHED_YET)
                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag(if (visualIndex == 0) "profile-current-source" else "profile-source-$visualIndex")
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
                                    subscription.name,
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
                                    "${strings.locationCountLabel(subscription.locationCount.toInt())} • $refreshStatus",
                                    color = Color(0xFFD3E3EE),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                                IconButton(
                                    onClick = { onRefreshSubscription(subscription.id) },
                                    enabled = !state.isBusy,
                                    modifier = Modifier.size(48.dp).testTag(
                                        if (visualIndex == 0) "profile-refresh" else "profile-refresh-$visualIndex",
                                    ),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Refresh,
                                        contentDescription = strings.get(UiText.REFRESH_ACTIVE),
                                        tint = if (!state.isBusy) Color.White else Color(0xFF9FB8C8),
                                    )
                                }
                                IconButton(
                                    onClick = { onShowSubscriptionRenameDialog(subscription.id) },
                                    modifier = Modifier.size(48.dp).testTag(
                                        if (visualIndex == 0) "profile-rename" else "profile-rename-$visualIndex",
                                    ),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Edit,
                                        contentDescription = strings.get(UiText.RENAME_SUBSCRIPTION),
                                        tint = Color.White,
                                    )
                                }
                                IconButton(
                                    onClick = { onDeleteSubscription(subscription.id) },
                                    modifier = Modifier.size(48.dp).testTag(
                                        if (visualIndex == 0) "profile-delete" else "profile-delete-$visualIndex",
                                    ),
                                ) {
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
                                IconButton(
                                    onClick = onToggleAddSubscriptionEditor,
                                    modifier = Modifier.size(48.dp).testTag("profile-cancel"),
                                ) {
                                    Icon(
                                        imageVector = Icons.Filled.Close,
                                        contentDescription = strings.get(UiText.CLOSE_SUBSCRIPTION_EDITOR),
                                        tint = Color.White,
                                    )
                                }
                            }
                        }
                        editorFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
                        OutlinedTextField(
                            value = state.profileDraft,
                            onValueChange = onProfileDraftChange,
                            modifier = Modifier.fillMaxWidth().testTag("profile-url"),
                            label = { Text(strings.get(UiText.SUBSCRIPTION_URL)) },
                            placeholder = { Text("https://example.com/subscription.txt") },
                            singleLine = true,
                        )
                        OutlinedTextField(
                            value = state.profileTitleDraft,
                            onValueChange = onProfileTitleDraftChange,
                            modifier = Modifier.fillMaxWidth().testTag("profile-title"),
                            label = { Text(strings.get(UiText.SUBSCRIPTION_NAME)) },
                            placeholder = { Text(strings.get(UiText.OPTIONAL_CUSTOM_NAME)) },
                            singleLine = true,
                        )
                        Text(
                            strings.get(UiText.DESKTOP_SUBSCRIPTION_URL_HELP),
                            color = Color(0xFFD3E3EE),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(
                            onClick = onSaveSubscriptionDraft,
                            enabled = !editorSaving,
                            modifier = Modifier.heightIn(min = 48.dp).testTag("profile-save"),
                        ) {
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
    subscriptionCount: Int,
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
    val refreshScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && subscriptionCount > 1) {
        strings.get(UiText.SETTINGS_ALL_SUBSCRIPTIONS)
    } else {
        strings.get(UiText.SETTINGS_SELECTED_SUBSCRIPTION)
    }

    Box {
        OutlinedButton(
            onClick = { expanded = true },
            modifier = Modifier.heightIn(min = 48.dp).testTag("main-settings"),
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
                modifier = Modifier.testTag("settings-ssh"),
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
                modifier = Modifier.testTag("settings-language"),
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
                modifier = Modifier.testTag("settings-start-login"),
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
                modifier = Modifier.testTag("settings-mode"),
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
                modifier = Modifier.testTag("settings-rules"),
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
                modifier = Modifier.testTag("settings-refresh"),
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
                modifier = Modifier.testTag("settings-validation"),
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
                modifier = Modifier.testTag("settings-dns"),
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
                modifier = Modifier.testTag("settings-update"),
                text = {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(strings.get(UiText.SETTINGS_UPDATE))
                        Text(
                            strings.format(
                                UiText.SETTINGS_CURRENT_VERSION,
                                state.appUpdate.currentVersion.ifBlank {
                                    DesktopBuildInfo.current().displayVersion
                                },
                            ),
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
    subscriptionCount: Int,
    sshKeyPresent: Boolean?,
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
    dnsFailure: com.kardinal.vpncontrol.model.ControlCode? = null,
    dnsSaving: Boolean = false,
    settingsFailure: com.kardinal.vpncontrol.model.ControlCode? = null,
    settingsSaving: Boolean = false,
    sshKeyRetryAvailable: Boolean = false,
    sshKeyImporting: Boolean = false,
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
                    dnsFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
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
                            visualId = when (mode) {
                                DnsMode.AUTOMATIC -> "dns-automatic"
                                DnsMode.CUSTOM_DOH -> "dns-doh"
                                DnsMode.CUSTOM_DOT -> "dns-dot"
                            },
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
                        modifier = Modifier.fillMaxWidth().testTag("dns-endpoint"),
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
                TextButton(enabled = !dnsSaving, onClick = onSaveDns, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save")) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleDnsDialog, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel")) {
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
                    settingsFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
                    Text(strings.get(UiText.HOME_SSH_DESCRIPTION), color = Color(0xFFD3E3EE))
                    Row(
                        modifier = Modifier.fillMaxWidth().testTag("ssh-enabled"),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(strings.get(UiText.HOME_SSH_ENABLED))
                        Switch(checked = state.homeSshEnabledDraft, onCheckedChange = onHomeSshEnabledChange)
                    }
                    OutlinedTextField(
                        value = state.homeSshHostDraft,
                        onValueChange = onHomeSshHostChange,
                        modifier = Modifier.fillMaxWidth().testTag("ssh-host"),
                        label = { Text(strings.get(UiText.HOME_SSH_HOST)) },
                        placeholder = { Text("example.com") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshPortDraft,
                        onValueChange = onHomeSshPortChange,
                        modifier = Modifier.fillMaxWidth().testTag("ssh-port"),
                        label = { Text(strings.get(UiText.HOME_SSH_PORT)) },
                        placeholder = { Text("228") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshUserDraft,
                        onValueChange = onHomeSshUserChange,
                        modifier = Modifier.fillMaxWidth().testTag("ssh-user"),
                        label = { Text(strings.get(UiText.HOME_SSH_USER)) },
                        placeholder = { Text("kardinal") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.homeSshHostKeysDraft,
                        onValueChange = onHomeSshHostKeysChange,
                        modifier = Modifier.fillMaxWidth().testTag("ssh-host-keys"),
                        label = { Text(strings.get(UiText.HOME_SSH_HOST_KEYS)) },
                        supportingText = { Text(strings.get(UiText.HOME_SSH_HOST_KEYS_HELP)) },
                        minLines = 2,
                    )
                    OutlinedTextField(
                        value = state.homeSshRelayPortDraft,
                        onValueChange = onHomeSshRelayPortChange,
                        modifier = Modifier.fillMaxWidth().testTag("ssh-relay-port"),
                        label = { Text(strings.get(UiText.HOME_SSH_RELAY_PORT)) },
                        placeholder = { Text("10808") },
                        singleLine = true,
                    )
                    OutlinedButton(
                        onClick = onImportHomeSshPrivateKey,
                        enabled = !sshKeyImporting,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).testTag("ssh-key"),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFF9ED6FF)),
                    ) {
                        Text(strings.get(if (sshKeyRetryAvailable) UiText.UPDATE_RETRY else UiText.IMPORT_PRIVATE_KEY))
                    }
                    Text(
                        if (sshKeyPresent == null) ControlCode.UNAVAILABLE.wireName else strings.get(
                            if (sshKeyPresent) {
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
                TextButton(enabled = !settingsSaving, onClick = onSaveHomeSshRoute, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save")) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleHomeSshRouteDialog, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel")) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showHomeSshRestartDialog) {
        AlertDialog(
            onDismissRequest = onDismissHomeSshRestart,
            title = { Text(strings.get(UiText.HOME_SSH_RESTART_TITLE), color = Color.White) },
            text = {
                Text(
                    strings.get(UiText.HOME_SSH_RESTART_DESCRIPTION),
                    color = Color(0xFFD3E3EE),
                    modifier = Modifier.testTag("ssh-restart-description"),
                )
            },
            containerColor = Color(0xFF141F2D),
            confirmButton = {
                TextButton(onClick = onRestartForHomeSsh, modifier = Modifier.heightIn(min = 48.dp).testTag("restart-now")) {
                    Text(strings.get(UiText.RESTART_NOW), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onDismissHomeSshRestart, modifier = Modifier.heightIn(min = 48.dp).testTag("restart-later")) {
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
                    settingsFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
                    Text(
                        text = strings.get(UiText.APP_MODE_DESKTOP_DESCRIPTION),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Card(
                        modifier = Modifier.testTag("mode-switch"),
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
                TextButton(onClick = onToggleAppModeDialog, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-close")) {
                    Text(strings.get(UiText.CLOSE), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showRefreshPolicyDialog) {
        val refreshTarget = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && subscriptionCount > 1) {
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
                    settingsFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
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
                            visualId = when (policy) {
                                SubscriptionRefreshPolicy.OFF -> "refresh-off"
                                SubscriptionRefreshPolicy.EVERY_HOUR -> "refresh-hourly"
                                SubscriptionRefreshPolicy.CUSTOM -> "refresh-custom"
                            },
                        )
                    }
                    Card(
                        modifier = Modifier.testTag("refresh-find-best"),
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
                                modifier = Modifier.fillMaxWidth().testTag("refresh-hours"),
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
                TextButton(
                    onClick = onSaveSubscriptionRefreshPolicy,
                    enabled = !settingsSaving,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save"),
                ) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(onClick = onToggleRefreshPolicyDialog, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel")) {
                    Text(strings.get(UiText.CANCEL), color = Color(0xFFD3E3EE))
                }
            },
        )
    }

    if (state.showValidationSettingsDialog) {
        val searchScope = if (state.activeSubscriptionId == ALL_SUBSCRIPTIONS_ID && subscriptionCount > 1) {
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
                    settingsFailure?.let { Text(it.wireName, color = MaterialTheme.colorScheme.error) }
                    Text(
                        text = strings.format(UiText.VALIDATION_DESCRIPTION_DESKTOP, searchScope),
                        color = Color(0xFFD3E3EE),
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = state.validationTestUrlDraft,
                        onValueChange = onValidationTestUrlDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("validation-url"),
                        label = { Text(strings.get(UiText.TEST_SITE)) },
                        placeholder = { Text(strings.get(UiText.TEST_SITE_PLACEHOLDER)) },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationBatchSizeDraft,
                        onValueChange = onValidationBatchSizeDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("validation-batch"),
                        label = { Text(strings.get(UiText.BATCH_SIZE)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationSubscriptionRefreshConcurrencyDraft,
                        onValueChange = onValidationSubscriptionRefreshConcurrencyDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("validation-concurrency"),
                        label = { Text(strings.get(UiText.SUBSCRIPTION_REFRESH_CONCURRENCY)) },
                        placeholder = { Text("3") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationRetryCountDraft,
                        onValueChange = onValidationRetryCountDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("validation-retries"),
                        label = { Text(strings.get(UiText.RETRY_COUNT)) },
                        placeholder = { Text("1") },
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.validationActiveVerificationWindowSizeDraft,
                        onValueChange = onValidationActiveVerificationWindowSizeDraftChange,
                        modifier = Modifier.fillMaxWidth().testTag("validation-window"),
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
                TextButton(enabled = !settingsSaving, onClick = onSaveValidationSettings, modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-save")) {
                    Text(strings.get(UiText.SAVE), color = Color(0xFF9ED6FF))
                }
            },
            dismissButton = {
                TextButton(
                    onClick = onToggleValidationSettingsDialog,
                    modifier = Modifier.heightIn(min = 48.dp).testTag("dialog-cancel"),
                ) {
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
    visualId: String,
) {
    Row(
        modifier = Modifier.fillMaxWidth().testTag(visualId).clickable(onClick = onClick),
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
    visualId: String,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(visualId)
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
            .testTag("profile-add-subscription")
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
    visualScope: String,
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
                modifier = Modifier.heightIn(min = 48.dp).testTag("$visualScope-import-menu"),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.IMPORT))
            }
            DropdownMenu(
                expanded = showImportMenu,
                onDismissRequest = { showImportMenu = false },
            ) {
                DropdownMenuItem(
                    modifier = Modifier.testTag("import-file"),
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showImportMenu = false
                        onImportFile()
                    },
                )
                DropdownMenuItem(
                    modifier = Modifier.testTag("import-clipboard"),
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
                modifier = Modifier.heightIn(min = 48.dp).testTag("$visualScope-export-menu"),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.EXPORT))
            }
            DropdownMenu(
                expanded = showExportMenu,
                onDismissRequest = { showExportMenu = false },
            ) {
                DropdownMenuItem(
                    modifier = Modifier.testTag("export-file"),
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showExportMenu = false
                        onExportFile()
                    },
                )
                DropdownMenuItem(
                    modifier = Modifier.testTag("export-clipboard"),
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

internal fun DesktopLocationRecord.toSharedRow(configurationId: String?, selectedId: String?, activeId: String?): SavedLocationRow {
    return SavedLocationRow(
        index = index,
        rawLink = rawLink,
        name = name,
        server = server,
        details = details,
        benchmarkDetail = benchmarkDetail,
        autoSelectable = isValid,
        isSelected = isSelected,
        selection = com.kardinal.vpncontrol.shared.ui.SavedLocationSelection(
            selected = configurationId != null && configurationId == selectedId,
            active = configurationId != null && configurationId == activeId,
        ),
    )
}
