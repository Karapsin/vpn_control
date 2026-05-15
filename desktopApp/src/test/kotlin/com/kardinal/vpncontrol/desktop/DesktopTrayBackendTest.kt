package com.kardinal.vpncontrol.desktop

import java.net.URL
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DesktopTrayBackendTest {
    @Test
    fun linuxSelectsNativeBackendBeforeAwtFallback() {
        val backends = selectDesktopTrayBackendKinds(
            osName = "Linux",
            isHeadless = false,
            awtSupported = false,
        )

        assertEquals(
            listOf(DesktopTrayBackendKind.NativeLinux, DesktopTrayBackendKind.Awt),
            backends,
        )
    }

    @Test
    fun linuxCanPreferAwtBackendForXEmbedTraySessions() {
        val backends = selectDesktopTrayBackendKinds(
            osName = "Linux",
            isHeadless = false,
            awtSupported = true,
            linuxPreference = LinuxTrayBackendPreference.AwtFirst,
        )

        assertEquals(
            listOf(DesktopTrayBackendKind.Awt, DesktopTrayBackendKind.NativeLinux),
            backends,
        )
    }

    @Test
    fun i3SessionPrefersAwtLinuxTrayBackend() {
        val preference = detectLinuxTrayBackendPreference(
            env = mapOf("XDG_CURRENT_DESKTOP" to "i3"),
            property = { null },
            processCommands = { emptySequence() },
        )

        assertEquals(LinuxTrayBackendPreference.AwtFirst, preference)
    }

    @Test
    fun runningPolybarPrefersAwtLinuxTrayBackend() {
        val preference = detectLinuxTrayBackendPreference(
            env = emptyMap(),
            property = { null },
            processCommands = { sequenceOf("/usr/bin/polybar") },
        )

        assertEquals(LinuxTrayBackendPreference.AwtFirst, preference)
    }

    @Test
    fun explicitNativeLinuxTrayBackendOverridesXEmbedDetection() {
        val preference = detectLinuxTrayBackendPreference(
            env = mapOf(
                "XDG_CURRENT_DESKTOP" to "i3",
                "VPN_CONTROL_LINUX_TRAY_BACKEND" to "awt",
            ),
            property = { name ->
                if (name == "vpn.control.linux.trayBackend") "native" else null
            },
            processCommands = { sequenceOf("/usr/bin/polybar") },
        )

        assertEquals(LinuxTrayBackendPreference.NativeFirst, preference)
    }

    @Test
    fun linuxFallsBackToAwtWhenNativeBackendIsUnavailable() {
        val attempts = mutableListOf<String>()
        val awtHandle = FakeDesktopTrayHandle()
        var availableCalls = 0
        val installer = DesktopTrayBackendInstaller(
            listOf(
                FakeDesktopTrayBackend("native", attempts, handle = null),
                FakeDesktopTrayBackend("awt", attempts, handle = awtHandle),
            ),
        )

        val handle = installer.install(
            appTitle = { "VPN Control" },
            menuState = { sampleTrayMenuState() },
            onAvailable = { availableCalls += 1 },
        )

        assertSame(awtHandle, handle)
        assertEquals(listOf("native", "awt"), attempts)
        assertEquals(1, availableCalls)
    }

    @Test
    fun windowsAndMacosSelectAwtBackend() {
        assertEquals(
            listOf(DesktopTrayBackendKind.Awt),
            selectDesktopTrayBackendKinds(
                osName = "Windows 11",
                isHeadless = false,
                awtSupported = true,
            ),
        )
        assertEquals(
            listOf(DesktopTrayBackendKind.Awt),
            selectDesktopTrayBackendKinds(
                osName = "Mac OS X",
                isHeadless = false,
                awtSupported = true,
            ),
        )
    }

}

class NativeLinuxTrayBackendTest {
    @Test
    fun showAndHideCallbacksAreMappedToNativeMenuItems() {
        val peer = FakeNativeLinuxTrayPeer()
        var showCalls = 0
        var hideCalls = 0
        installNativeTray(
            peer = peer,
            menuState = sampleTrayMenuState(
                onShowWindow = { showCalls += 1 },
                onHideWindow = { hideCalls += 1 },
            ),
        )

        peer.items[0].click()
        peer.items[1].click()

        assertEquals(1, showCalls)
        assertEquals(1, hideCalls)
    }

    @Test
    fun connectionActionUsesCurrentLabelAndEnabledState() {
        val peer = FakeNativeLinuxTrayPeer()
        var toggleCalls = 0
        val handle = installNativeTray(
            peer = peer,
            menuState = sampleTrayMenuState(
                connectionActionLabel = "Start",
                connectionActionEnabled = false,
                onToggleConnection = { toggleCalls += 1 },
            ),
        )
        val connectionItem = peer.items[2]

        assertEquals("Start", connectionItem.text)
        assertFalse(connectionItem.enabled)
        connectionItem.click()
        assertEquals(0, toggleCalls)

        handle.update(
            appTitle = "VPN Control",
            menuState = sampleTrayMenuState(
                connectionActionLabel = "Stop",
                connectionActionEnabled = true,
                onToggleConnection = { toggleCalls += 1 },
            ),
        )
        connectionItem.click()

        assertEquals("Stop", connectionItem.text)
        assertTrue(connectionItem.enabled)
        assertEquals(1, toggleCalls)
    }

    @Test
    fun findBestDisabledStateIsPreserved() {
        val peer = FakeNativeLinuxTrayPeer()
        var findBestCalls = 0
        installNativeTray(
            peer = peer,
            menuState = sampleTrayMenuState(
                findBestEnabled = false,
                onFindBest = { findBestCalls += 1 },
            ),
        )
        val findBestItem = peer.items[3]

        assertEquals("Find Best", findBestItem.text)
        assertFalse(findBestItem.enabled)
        findBestItem.click()

        assertEquals(0, findBestCalls)
    }

    @Test
    fun exitDisposesTrayBeforeInvokingExitFlow() {
        val events = mutableListOf<String>()
        val peer = FakeNativeLinuxTrayPeer(events)
        installNativeTray(
            peer = peer,
            menuState = sampleTrayMenuState(
                onExit = { events += "exit" },
            ),
        )

        peer.items[4].click()

        assertEquals(listOf("shutdown", "exit"), events.takeLast(2))
        assertEquals(1, peer.shutdownCalls)
    }

    @Test
    fun nativeMenuIsBuiltBeforeTrayIconIsActivated() {
        val events = mutableListOf<String>()
        val peer = FakeNativeLinuxTrayPeer(events)
        var availableCalls = 0

        installNativeTray(
            peer = peer,
            menuState = sampleTrayMenuState(),
            onAvailable = { availableCalls += 1 },
        )

        assertEquals(
            listOf(
                "tooltip:VPN Control",
                "item:Show Window",
                "item:Hide Window",
                "separator",
                "item:Start",
                "item:Find Best",
                "separator",
                "item:Exit",
                "image:file:/tmp/vpn-control-tray-icon.png",
            ),
            events,
        )
        assertEquals(1, availableCalls)
    }
}

private fun installNativeTray(
    peer: FakeNativeLinuxTrayPeer,
    menuState: TrayMenuState,
    onAvailable: () -> Unit = {},
    onUnavailable: () -> Unit = {},
): DesktopTrayHandle {
    val backend = NativeLinuxTrayBackend(
        gateway = NativeLinuxTrayGateway { peer },
        iconResolver = NativeTrayIconResolver { URL("file:/tmp/vpn-control-tray-icon.png") },
        dispatcher = TrayActionDispatcher { action -> action() },
        isHeadless = { false },
    )
    return assertNotNull(
        backend.install(
            appTitle = { "VPN Control" },
            menuState = { menuState },
            onAvailable = onAvailable,
            onUnavailable = onUnavailable,
        ),
    )
}

private class FakeDesktopTrayBackend(
    private val name: String,
    private val attempts: MutableList<String>,
    private val handle: DesktopTrayHandle?,
) : DesktopTrayBackend {
    override fun install(
        appTitle: () -> String,
        menuState: () -> TrayMenuState,
        onAvailable: () -> Unit,
        onUnavailable: () -> Unit,
    ): DesktopTrayHandle? {
        attempts += name
        if (handle != null) {
            onAvailable()
        }
        return handle
    }
}

private class FakeDesktopTrayHandle : DesktopTrayHandle {
    override fun update(appTitle: String, menuState: TrayMenuState) = Unit

    override fun dispose() = Unit
}

private class FakeNativeLinuxTrayPeer(
    private val events: MutableList<String> = mutableListOf(),
) : NativeLinuxTrayPeer {
    val items = mutableListOf<FakeNativeLinuxTrayMenuItem>()
    val separators = mutableListOf<Int>()
    var imageUrl: URL? = null
        private set
    var tooltip: String? = null
        private set
    var shutdownCalls = 0
        private set

    override fun setImage(imageUrl: URL) {
        this.imageUrl = imageUrl
        events += "image:$imageUrl"
    }

    override fun setTooltip(text: String) {
        tooltip = text
        events += "tooltip:$text"
    }

    override fun addMenuItem(
        text: String,
        enabled: Boolean,
        action: () -> Unit,
    ): NativeLinuxTrayMenuItem {
        events += "item:$text"
        return FakeNativeLinuxTrayMenuItem(text, enabled, action)
            .also(items::add)
    }

    override fun addSeparator() {
        separators += items.size
        events += "separator"
    }

    override fun shutdown() {
        shutdownCalls += 1
        events += "shutdown"
    }
}

private class FakeNativeLinuxTrayMenuItem(
    text: String,
    enabled: Boolean,
    private val action: () -> Unit,
) : NativeLinuxTrayMenuItem {
    private var currentText = text
    private var currentEnabled = enabled

    val text: String
        get() = currentText

    val enabled: Boolean
        get() = currentEnabled

    override fun setText(text: String) {
        currentText = text
    }

    override fun setEnabled(enabled: Boolean) {
        currentEnabled = enabled
    }

    fun click() {
        if (currentEnabled) action()
    }
}

private fun sampleTrayMenuState(
    connectionActionLabel: String = "Start",
    findBestLabel: String = "Find Best",
    showWindowLabel: String = "Show Window",
    hideWindowLabel: String = "Hide Window",
    exitLabel: String = "Exit",
    connectionActionEnabled: Boolean = true,
    findBestEnabled: Boolean = true,
    onToggleConnection: () -> Unit = {},
    onFindBest: () -> Unit = {},
    onShowWindow: () -> Unit = {},
    onHideWindow: () -> Unit = {},
    onExit: () -> Unit = {},
): TrayMenuState {
    return TrayMenuState(
        connectionActionLabel = connectionActionLabel,
        findBestLabel = findBestLabel,
        showWindowLabel = showWindowLabel,
        hideWindowLabel = hideWindowLabel,
        exitLabel = exitLabel,
        connectionActionEnabled = connectionActionEnabled,
        findBestEnabled = findBestEnabled,
        onToggleConnection = onToggleConnection,
        onFindBest = onFindBest,
        onShowWindow = onShowWindow,
        onHideWindow = onHideWindow,
        onExit = onExit,
    )
}
