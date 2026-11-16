package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.shared.ui.AppStrings
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * PRODUCT-003 asks the GUI status to report a saved workspace that could not be read, and DESKTOP-004 asks GUI
 * startup to restore the remembered reconnect intent once. When the older copy that loads carries that intent, the
 * notice outranks the launch restore in the status line: it is the first status, and it is shown again when the
 * restore ends, whatever the restore's outcome, which stays in the connection log. The GUI log renders the notice
 * through its typed status, not as raw `KEY(args)`.
 */
class DesktopUnreadableWorkspaceLaunchNoticeTest {
    @Test
    fun noticeIsTheFirstStatusWhenTheOlderCopyCarriesReconnectIntent() = withDirectory { directory ->
        val kept = olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory)

        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = FakeLaunchRuntime())

        val status = service.controlPresentationSnapshot("owner").frontend.activity.status
        assertEquals(OLDER_COPY_LOADED, status?.key?.name, "the GUI status did not report the kept workspace first")
        assertEquals(listOf(kept), status?.args)
    }

    @Test
    fun noticeReturnsAfterASuccessfulLaunchRestore() = withDirectory { directory ->
        olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory)
        val runtime = FakeLaunchRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime)
        val notice = service.state.connectionLog.single { key(it.message) == OLDER_COPY_LOADED }.message

        runBlocking { service.resumePreviousConnectionIfNeeded() }

        assertEquals(1, runtime.startCalls, "the launch restore did not run")
        assertTrue(service.state.isVpnRunning)
        assertEquals(notice, service.state.statusMessage, "the restore replaced the notice: ${service.state.statusMessage}")
        assertEquals(OLDER_COPY_LOADED, service.controlPresentationSnapshot("owner").frontend.activity.status?.key?.name)
        assertEquals(1, service.state.connectionLog.count { it.message == notice }, "the notice was logged twice")
        assertTrue(service.state.connectionLog.any { key(it.message) == "RESTORING_PREVIOUS_CONNECTION" },
            "the restore left no log entry")
        assertNotEquals(notice, service.state.connectionLog.last().message, "the restore's own result is not in the log")
    }

    @Test
    fun noticeReturnsAfterAFailedLaunchRestore() = withDirectory { directory ->
        olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory)
        val runtime = FakeLaunchRuntime(fail = true)
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime)
        val notice = service.state.connectionLog.single { key(it.message) == OLDER_COPY_LOADED }.message

        runBlocking { service.resumePreviousConnectionIfNeeded() }

        assertEquals(1, runtime.startCalls, "the launch restore did not run")
        assertFalse(service.state.isVpnRunning)
        assertEquals(notice, service.state.statusMessage, "the failed restore replaced the notice: ${service.state.statusMessage}")
        assertEquals(1, service.state.connectionLog.count { it.message == notice }, "the notice was logged twice")
        assertNotEquals(notice, service.state.connectionLog.last().message, "the restore's failure is not in the log")
    }

    @Test
    fun noticeReturnsWhenThePreviousLocationIsUnavailable() = withDirectory { directory ->
        olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory, withLocation = false)
        val runtime = FakeLaunchRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime)
        val notice = service.state.connectionLog.single { key(it.message) == OLDER_COPY_LOADED }.message

        runBlocking { service.resumePreviousConnectionIfNeeded() }

        assertEquals(0, runtime.startCalls)
        assertEquals(notice, service.state.statusMessage, "the unavailable location replaced the notice: ${service.state.statusMessage}")
        assertTrue(service.state.connectionLog.any { key(it.message) == "PREVIOUS_LOCATION_UNAVAILABLE" },
            "the unavailable location left no log entry")
        assertEquals(1, service.state.connectionLog.count { it.message == notice }, "the notice was logged twice")
    }

    @Test
    fun launchRestoreWithoutANoticeKeepsItsOwnStatuses() = withDirectory { directory ->
        // Guard: a readable workspace with reconnect intent shows the pending restore and then the restore's result.
        assertTrue(DesktopStateStore(directory).writeWorkspace(workspaceWithReconnectIntent(withLocation = true)).isSuccess)
        val runtime = FakeLaunchRuntime()
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = runtime)
        assertEquals("PREVIOUS_CONNECTION_RESTORE_PENDING", key(service.state.statusMessage))

        runBlocking { service.resumePreviousConnectionIfNeeded() }

        assertEquals(1, runtime.startCalls)
        assertTrue(service.state.isVpnRunning)
        assertEquals(service.state.connectionLog.last().message, service.state.statusMessage)
        assertFalse(service.state.connectionLog.any { key(it.message)?.startsWith("SAVED_SETTINGS_UNREADABLE") == true })
    }

    @Test
    fun guiLogRendersTheNoticeAsATranslatedStatus() = withDirectory { directory ->
        val kept = olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory)
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory), runtimeController = FakeLaunchRuntime())
        val owner = DesktopControllerOwner(service)
        try {
            val result = runBlocking {
                owner.submit(ControlRequest("logs", ControlCommand(ControlOperationId.LOGS,
                    mapOf("limit" to ControlValue.Text("100"))), controllerId = owner.controllerId))
            }
            val strings = AppStrings(AppLanguage.ENGLISH)
            val rendered = desktopFrontendLogs(result).map { strings.statusMessage(it.message) }
            val notice = rendered.singleOrNull { kept in it }
            assertNotNull(notice, "the GUI log has no notice naming $kept: $rendered")
            assertFalse(OLDER_COPY_LOADED in notice, "the GUI log shows the raw status key: $notice")
            assertEquals(strings.statusMessage(StatusMessages.encode(
                com.kardinal.vpncontrol.model.StatusMessageKey.SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED, kept)), notice)
        } finally {
            owner.close()
        }
    }

    /** A newer unreadable workspace.json beside an older readable recovery file that remembers a connection. */
    private fun olderCopyWithReconnectIntentBehindAnUnreadableWorkspace(directory: Path, withLocation: Boolean = true): String {
        val source = Files.createTempDirectory("vpn-control-launch-notice-copy")
        try {
            assertTrue(DesktopStateStore(source).writeWorkspace(workspaceWithReconnectIntent(withLocation)).isSuccess)
            write(directory.resolve(RECOVERY), Files.readAllBytes(source.resolve(PRIMARY)), ageSeconds = 60)
        } finally {
            source.toFile().deleteRecursively()
        }
        write(directory.resolve(PRIMARY), "{\"persisted_state\": {\"subscriptions\": [".toByteArray(), ageSeconds = 0)
        val loaded = DesktopStateStore(directory).loadWorkspace(defaultDesktopWorkspace())
        assertEquals(OLDER_COPY_LOADED, key(loaded.persistedState.statusMessage))
        assertTrue(loaded.resumeConnectionOnLaunch, "the older copy lost its reconnect intent")
        val kept = Files.list(directory).use { entries ->
            entries.map { it.fileName.toString() }.filter { it.startsWith("$PRIMARY.unreadable-") }.toList()
        }
        return kept.single()
    }

    private fun workspaceWithReconnectIntent(withLocation: Boolean): DesktopWorkspace {
        val location = DesktopLocationRecord(index = 0, sourceUrl = "", rawLink = RAW, name = "Selected",
            server = "127.0.0.1", details = "SOCKS", benchmarkDetail = "", isValid = true, isSelected = true)
        return DesktopWorkspace(
            PersistedState(
                appMode = AppMode.PROXY_ONLY,
                currentLocations = if (withLocation) listOf(RAW) else emptyList(),
                selectedProfileRawLink = RAW,
                selectedProfileName = "Selected",
            ),
            if (withLocation) listOf(location) else emptyList(),
            resumeConnectionOnLaunch = true,
        )
    }

    private fun key(message: String): String? = StatusMessages.decode(message)?.key?.name

    private fun write(file: Path, bytes: ByteArray, ageSeconds: Long) {
        Files.write(file, bytes)
        Files.setLastModifiedTime(file, FileTime.fromMillis(System.currentTimeMillis() - ageSeconds * 1_000))
    }

    private fun withDirectory(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-control-launch-notice")
        try {
            block(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private companion object {
        const val PRIMARY = "workspace.json"
        const val RECOVERY = "workspace-recovery.json"
        const val OLDER_COPY_LOADED = "SAVED_SETTINGS_UNREADABLE_OLDER_COPY_LOADED"
        const val RAW = "socks://127.0.0.1:1080#Selected"
    }
}

private class FakeLaunchRuntime(private val fail: Boolean = false) : DesktopRuntimeController {
    var startCalls = 0
    private var running = false
    private var mode: AppMode? = null

    override suspend fun start(
        profile: ProxyProfile,
        routingRules: RoutingRules,
        dnsSettings: DnsSettings,
        appMode: AppMode,
        activeVerificationPort: Int?,
        homeSshRouteSettings: com.kardinal.vpncontrol.model.HomeSshRouteSettings,
    ): Result<DesktopRuntimeSession> {
        startCalls += 1
        if (fail) return Result.failure(IllegalStateException("runtime refused to start"))
        running = true
        mode = appMode
        return Result.success(DesktopRuntimeSession(appMode = appMode, listenPort = 1080, interfaceName = null,
            configJson = "{}", logFile = Paths.get("runtime.log"), processId = 1L))
    }

    override suspend fun stop(): Result<Unit> {
        running = false
        mode = null
        return Result.success(Unit)
    }

    override fun isRunning(): Boolean = running

    override fun currentMode(): AppMode? = mode.takeIf { running }

    override fun currentPort(): Int? = 1080.takeIf { running }
}
