package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlin.test.*

class DesktopGuiVisibilityControlTest {
    private val owner = UUID.randomUUID().toString()
    private fun input(operation: ControlOperationId = ControlOperationId.GUI_SHOW) = ControlRequest(
        UUID.randomUUID().toString(), ControlCommand(operation), controllerId = owner)
    private fun decoded(response: DesktopCliResponse) = ControlProtocolCodec.decodeResult(response.message)

    @Test fun acknowledgementWaitsForActualUiAndExpiredQueueCannotActLater() {
        val queued = java.util.concurrent.atomic.AtomicReference<(() -> Unit)?>()
        val arrived = CountDownLatch(1)
        val visibility = DesktopFrontendVisibility({ queued.set(it); arrived.countDown() }, 500)
        visibility.ownerId = owner
        visibility.available = { true }
        var actions = 0
        visibility.install { actions++; ControlCode.OK }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val result = executor.submit<ControlCode> { visibility.request(true) }
            assertTrue(arrived.await(2, TimeUnit.SECONDS))
            assertFalse(result.isDone)
            assertEquals(0, actions)
            queued.getAndSet(null)!!.invoke()
            assertEquals(ControlCode.OK, result.get(2, TimeUnit.SECONDS))
            assertEquals(1, actions)
            val expired = executor.submit<ControlCode> { visibility.request(false) }
            assertEquals(ControlCode.TIMEOUT, expired.get(2, TimeUnit.SECONDS))
            queued.getAndSet(null)!!.invoke()
            assertEquals(1, actions)
        } finally { executor.shutdownNow() }
    }

    @Test fun staleOwnerUnavailableAndNoTrayNeverAcknowledgeHidden() {
        val visibility = DesktopFrontendVisibility({ it() })
        visibility.ownerId = owner
        visibility.available = { true }
        var visible = true
        visibility.install { shown -> if (!shown) ControlCode.UNSUPPORTED else { visible = true; ControlCode.OK } }
        assertEquals(ControlCode.CONFLICT, visibility.request(false, "replacement"))
        assertEquals(ControlCode.UNSUPPORTED, visibility.request(false))
        assertTrue(visible)
        visibility.available = { false }
        assertEquals(ControlCode.UNAVAILABLE, visibility.request(true))
    }

    @Test fun newlyRegisteredFrontendWaitsForOwnerBindingAndWindowReadiness() {
        val visibility = DesktopFrontendVisibility({ it() })
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pending = executor.submit<ControlCode> { visibility.request(true, owner) }
            assertFailsWith<java.util.concurrent.TimeoutException> { pending.get(100, TimeUnit.MILLISECONDS) }
            visibility.ownerId = owner
            visibility.available = { true }
            visibility.install { ControlCode.OK }
            assertEquals(ControlCode.OK, pending.get(3, TimeUnit.SECONDS))
        } finally { executor.shutdownNow() }
    }

    @Test fun hideDoesNotLaunchAndShowPinsRegistrationAndDeduplicates() = runTest {
        var frontend: String? = null
        var launches = 0
        var requests = 0
        val registrationId = UUID.randomUUID().toString()
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(7, true) }, { frontend },
            directory = Path.of("unused-test-workspace"),
            launch = { _, epoch -> assertEquals(owner, epoch); launches++; frontend = registrationId; ControlCode.OK },
            request = { command, _ ->
                requests++
                val request = (command as DesktopCliCommand.ControlSubmit).request
                assertEquals(registrationId, request.controllerId)
                assertEquals(mapOf("owner" to ControlValue.Text(owner)), request.command.arguments)
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(registrationId,
                    request.requestId, ControlCode.OK, 0)))
            }, pause = {})
        assertEquals(ControlCode.NOT_FOUND, decoded(control.execute(input(ControlOperationId.GUI_HIDE))).code)
        assertEquals(0, launches)
        val show = input()
        val first = decoded(control.execute(show))
        assertEquals(ControlCode.OK, first.code)
        assertEquals(7, first.configurationRevision)
        assertTrue(first.restartRequired)
        frontend = UUID.randomUUID().toString()
        assertEquals(first, decoded(control.execute(show)))
        assertEquals(1, launches)
        assertEquals(1, requests)
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(show.copy(
            command = ControlCommand(ControlOperationId.GUI_HIDE)))).code)
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(input().copy(controllerId = "stale"))).code)
    }

    @Test fun replacedRegistrationAndMalformedAcknowledgementFailWithoutRetarget() = runTest {
        var frontend = UUID.randomUUID().toString()
        var calls = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            launch = { _, _ -> error("must not launch") }, request = { command, _ ->
                calls++
                val request = (command as DesktopCliCommand.ControlSubmit).request
                frontend = UUID.randomUUID().toString()
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(request.controllerId,
                    request.requestId, ControlCode.OK, 0)))
            })
        val show = input()
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(show)).code)
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(show)).code)
        assertEquals(1, calls)
        val unavailable = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { null },
            launch = { _, _ -> ControlCode.UNAVAILABLE }, request = { _, _ -> error("must not request") })
        assertEquals(ControlCode.UNAVAILABLE, decoded(unavailable.execute(input())).code)
        val malformed = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            launch = { _, _ -> error("must not launch") }, request = { _, _ -> DesktopCliResponse.success("queued") })
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, decoded(malformed.execute(input())).code)
    }

    @Test fun showStartupIsBoundedAndConcurrentPresentationRequestsAreBusy() = runTest {
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        var launches = 0
        var waits = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { null },
            launch = { _, _ -> launches++; ControlCode.OK },
            request = { _, _ -> error("no registered frontend") }, pause = {
                waits++; started.complete(Unit); release.await()
            }, attempts = 2)
        val show = input()
        val pending = async { control.execute(show) }
        started.await()
        assertEquals(ControlCode.BUSY, decoded(control.execute(input(ControlOperationId.GUI_HIDE))).code)
        release.complete(Unit)
        val timeout = decoded(pending.await())
        assertEquals(ControlCode.TIMEOUT, timeout.code)
        assertFalse(timeout.final)
        assertEquals(ControlCode.TIMEOUT, decoded(control.execute(show)).code)
        assertEquals(1, launches)
        assertEquals(2, waits)
    }

    @Test fun publicTextAndJsonHideNeverBootstrapAndShowUsesTypedCommand() {
        for (json in listOf(false, true)) {
            val output = mutableListOf<String>()
            val args = listOf("gui", "hide") + if (json) listOf("--json") else emptyList()
            assertEquals(2, DesktopCli.handleArgs(args.toTypedArray(), output::add,
                requestCommand = { assertEquals(ControlOperationId.GUI_HIDE,
                    (it as DesktopCliCommand.ControlSubmit).request.command.operation); DesktopCliResponse.notRunning() },
                startHeadlessController = { error("hide must not start owner") }))
            output.clear()
            val showArgs = listOf("gui", "show") + if (json) listOf("--json") else emptyList()
            assertEquals(0, DesktopCli.handleArgs(showArgs.toTypedArray(), output::add, requestCommand = {
                val request = (it as DesktopCliCommand.ControlSubmit).request
                assertEquals(ControlOperationId.GUI_SHOW, request.command.operation)
                DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(owner,
                    request.requestId, ControlCode.OK, 0)))
            }, startHeadlessController = { error("existing owner") }))
            if (json) assertEquals(ControlCode.OK, ControlProtocolCodec.decodeResult(output.single()).code)
            else assertEquals("OK", output.single())
        }
    }

    @Test fun publicQuitWithoutOwnerDoesNotBootstrapAReplacementToShutDown() {
        for (json in listOf(false, true)) {
            val output = mutableListOf<String>()
            val arguments = listOf("quit") + if (json) listOf("--json") else emptyList()
            assertEquals(2, DesktopCli.handleArgs(arguments.toTypedArray(), output::add,
                requestCommand = { assertEquals(ControlOperationId.QUIT,
                    (it as DesktopCliCommand.ControlSubmit).request.command.operation); DesktopCliResponse.notRunning() },
                startHeadlessController = { error("quit must not start an absent owner") }))
            if (json) {
                val result = ControlProtocolCodec.decodeResult(output.single())
                assertEquals(ControlCode.UNAVAILABLE, result.code)
                assertNull(result.controllerId)
            }
        }
    }

    @Test fun packagedAndDevelopmentLaunchKeepOwnerAndWorkspaceArgumentsWithoutHeadlessFlag() {
        val directory = Path.of("space 東京 workspace")
        val command = desktopFrontendLaunchCommand(owner, directory, "java", null, "space classpath")!!
        assertFalse(command.contains("-Djava.awt.headless=true"))
        assertFalse(command.contains(DesktopHeadlessController.ARG))
        assertEquals(listOf(DESKTOP_FRONTEND_OWNER_ARGUMENT, owner, "--state-dir", directory.toString()), command.takeLast(4))
        val windows = desktopFrontendLaunchCommand(owner, directory, "unused", "C:\\Program Files\\vpn-control-cli.exe", "")!!
        assertEquals("C:\\Program Files\\vpn-control.exe", windows.first())
        for (literalClasspath in listOf(DesktopHeadlessController.ARG, "-Djava.awt.headless=true")) {
            val literal = desktopFrontendLaunchCommand(owner, directory, "java", null, literalClasspath)!!
            assertEquals(listOf("java", "-cp", literalClasspath, "com.kardinal.vpncontrol.desktop.MainKt"), literal.take(4))
        }
    }

    @Test fun uncertainFrontendResponseStaysNonterminalAndRetryDoesNotRepeatUiAction() = runTest {
        val frontend = UUID.randomUUID().toString()
        var actions = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            request = { command, _ ->
                actions++
                val request = (command as DesktopCliCommand.ControlSubmit).request
                DesktopCliResponse(false, ControlProtocolCodec.encodeResult(ControlResult(frontend,
                    request.requestId, ControlCode.TIMEOUT, 0, final = false)), 2)
            })
        val show = input()
        val result = decoded(control.execute(show))
        assertEquals(ControlCode.TIMEOUT, result.code)
        assertFalse(result.final)
        assertEquals(result, decoded(control.execute(show)))
        assertEquals(1, actions)
    }

    @Test fun authenticatedFrontendRequiresBothRegistrationAndOwnerBeforeUiEffects() {
        val directory = Files.createTempDirectory("visibility-authenticated")
        val visibility = DesktopFrontendVisibility({ it() })
        visibility.ownerId = owner
        visibility.available = { true }
        var actions = 0
        visibility.install { actions++; ControlCode.OK }
        val frontend = assertNotNull(DesktopFrontendInstance.start(directory, visibility))
        try {
            fun request(epoch: String, registration: String): DesktopCliResponse {
                val command = input().copy(controllerId = registration, command = ControlCommand(ControlOperationId.GUI_SHOW,
                    mapOf("owner" to ControlValue.Text(epoch))))
                return DesktopActivationServer.requestCliCommand(DesktopCliCommand.ControlSubmit(command, 3),
                    DesktopFrontendInstance.endpoint(directory))
            }
            assertFalse(request(owner, UUID.randomUUID().toString()).success)
            assertEquals(ControlCode.CONFLICT, decoded(request("stale", frontend.identity)).code)
            assertEquals(0, actions)
            assertEquals(ControlCode.OK, decoded(request(owner, frontend.identity)).code)
            assertEquals(1, actions)
            visibility.install { actions++; ControlCode.TIMEOUT }
            val uncertain = decoded(request(owner, frontend.identity))
            assertEquals(ControlCode.TIMEOUT, uncertain.code)
            assertFalse(uncertain.final)
        } finally { frontend.close(); directory.toFile().deleteRecursively() }
    }
}
