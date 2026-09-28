package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.control.ControlCliRequestBuilder
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.ProfileSourceMode
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DesktopSourceModeParityTest {
    @Test fun publicCliCanRestoreSubscriptionModeInAnEmptyWorkspaceLikeGuiSwitch() = runTest {
        exerciseModeParity(rememberSubscription = false)
    }

    @Test fun publicCliCanRestoreRememberedSubscriptionModeLikeGuiSwitch() = runTest {
        exerciseModeParity(rememberSubscription = true)
    }

    private suspend fun kotlinx.coroutines.test.TestScope.exerciseModeParity(rememberSubscription: Boolean) {
        val directory = Files.createTempDirectory("source-mode-parity-")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        val owner = DesktopControllerOwner(service, scope = backgroundScope)
        try {
            val remembered = if (rememberSubscription)
                service.saveControlSubscription("https://example.test/subscription", "Remembered", null).getOrThrow()
            else null
            if (remembered != null) service.activateSelection(remembered).getOrThrow()

            fun gui(mode: String) = desktopGuiSourceAction("frontend", owner.controllerId,
                service.configurationRevision, ControlCommand(ControlOperationId.SOURCE_SET,
                    mapOf("mode" to ControlValue.Text(mode))))
            assertEquals(ControlCode.OK, owner.submit(gui("current-locations")).code)
            val beforeGui = service.configurationRevision
            assertEquals(ControlCode.OK, owner.submit(gui("subscription")).code)
            val guiMode = service.state.profileSourceMode
            val guiId = service.state.activeSubscriptionId
            val guiRevisionChange = service.configurationRevision - beforeGui
            assertEquals(ProfileSourceMode.SUBSCRIPTION, guiMode)
            assertEquals(remembered.orEmpty(), guiId)

            assertEquals(ControlCode.OK, owner.submit(gui("current-locations")).code)
            val beforeCli = service.configurationRevision
            val parsed = assertIs<ControlCliParseResult.Invocation>(ControlCliParser.parse(listOf(
                "--controller-id", owner.controllerId, "--if-revision", beforeCli.toString(),
                "source", "set", "subscription")))
            val request = ControlCliRequestBuilder.build(parsed, "cli-mode", { error("unexpected input") },
                { error("unexpected QR input") }).getOrThrow()
            assertEquals(ControlCode.OK, owner.submit(request).code)
            assertEquals(guiMode, service.state.profileSourceMode)
            assertEquals(guiId, service.state.activeSubscriptionId)
            assertEquals(guiRevisionChange, service.configurationRevision - beforeCli)
        } finally {
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
