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
    @Test fun packagedMacFrontendUsesLaunchServicesToLeaveTheHeadlessOwnerSession() {
        // The command builder checks host-provider absolute paths even with an injected macOS name.
        val bundle = desktopMacTestPath("/Applications/東京 space/vpn-control.app").toString().replace('\\', '/')
        val launcher = "$bundle/Contents/MacOS/vpn-control"
        val directory = desktopMacTestPath("/tmp/space workspace")
        assertEquals(listOf("/usr/bin/open", "-n", "-a", bundle, "--args",
            "--frontend-owner", "owner", "--state-dir", directory.toString()),
            desktopFrontendLaunchCommand("owner", directory,
                currentCommand = launcher, packagedLauncher = launcher, classPath = "", osName = "Mac OS X"))
    }

    private val owner = UUID.randomUUID().toString()
    private fun input(operation: ControlOperationId = ControlOperationId.GUI_SHOW) = ControlRequest(
        UUID.randomUUID().toString(), ControlCommand(operation), controllerId = owner)
    private fun decoded(response: DesktopCliResponse) = ControlProtocolCodec.decodeResult(response.message)
    private fun identityResponse(command: DesktopCliCommand.ControlFrontendIdentityRead) =
        DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(command.frontendId,
            command.requestId, ControlCode.OK, 0, data = mapOf(
                "pid" to ControlValue.IntegerValue(123), "startedAtEpochMillis" to ControlValue.IntegerValue(456)))))

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

    @Test fun coldPackagedFrontendCanFinishInitializationBeforeVisibilityAcknowledgement() {
        val visibility = DesktopFrontendVisibility({ it() })
        val executor = Executors.newSingleThreadExecutor()
        try {
            val pending = executor.submit<ControlCode> { visibility.request(true, owner) }
            // A real packaged macOS frontend exceeded the old two-second UI deadline.
            assertFailsWith<java.util.concurrent.TimeoutException> { pending.get(2_200, TimeUnit.MILLISECONDS) }
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
                when (command) {
                    is DesktopCliCommand.ControlFrontendIdentityRead -> identityResponse(command)
                    is DesktopCliCommand.ControlSubmit -> {
                        val request = command.request
                        assertTrue(command.clientTimeoutSeconds * 1000 > DESKTOP_FRONTEND_VISIBILITY_TIMEOUT_MILLIS)
                        assertEquals(registrationId, request.controllerId)
                        assertEquals(mapOf("owner" to ControlValue.Text(owner)), request.command.arguments)
                        DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(registrationId,
                            request.requestId, ControlCode.OK, 0)))
                    }
                    else -> error("unexpected command $command")
                }
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
        assertEquals(2, requests)
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
                when (command) {
                    is DesktopCliCommand.ControlFrontendIdentityRead -> identityResponse(command)
                    is DesktopCliCommand.ControlSubmit -> {
                        val request = command.request
                        frontend = UUID.randomUUID().toString()
                        DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(request.controllerId,
                            request.requestId, ControlCode.OK, 0)))
                    }
                    else -> error("unexpected command $command")
                }
            })
        val show = input()
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(show)).code)
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(show)).code)
        assertEquals(2, calls)
        val unavailable = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { null },
            launch = { _, _ -> ControlCode.UNAVAILABLE }, request = { _, _ -> error("must not request") })
        assertEquals(ControlCode.UNAVAILABLE, decoded(unavailable.execute(input())).code)
        val malformed = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            launch = { _, _ -> error("must not launch") }, request = { command, _ -> when (command) {
                is DesktopCliCommand.ControlFrontendIdentityRead -> identityResponse(command)
                else -> DesktopCliResponse.success("queued")
            } })
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, decoded(malformed.execute(input())).code)
    }

    @Test fun deadRegisteredFrontendIsReplacedAndShownInTheSameRequest() = runTest {
        val stale = UUID.randomUUID().toString()
        val replacement = UUID.randomUUID().toString()
        var frontend: String? = stale
        var launches = 0
        var requests = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(7, true) }, { frontend },
            revokeRegistration = { id -> if (frontend == id) { frontend = null; true } else false },
            launch = { _, epoch ->
                assertEquals(owner, epoch)
                assertNull(frontend, "A dead frontend must be released before relaunch")
                launches++
                frontend = replacement
                ControlCode.OK
            }, request = { command, _ ->
                requests++
                when (command) {
                    is DesktopCliCommand.ControlFrontendIdentityRead -> {
                        when (command.frontendId) {
                            stale -> DesktopCliResponse.notRunning()
                            replacement -> identityResponse(command)
                            else -> error("unexpected frontend ${command.frontendId}")
                        }
                    }
                    is DesktopCliCommand.ControlSubmit -> {
                        val request = command.request
                        when (request.controllerId) {
                            stale -> DesktopCliResponse.notRunning()
                            replacement -> DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(replacement,
                                request.requestId, ControlCode.OK, 0)))
                            else -> error("unexpected frontend ${request.controllerId}")
                        }
                    }
                    else -> error("unexpected command $command")
                }
            }, pause = {})
        val show = input()
        val result = decoded(control.execute(show))
        assertEquals(ControlCode.OK, result.code)
        assertEquals(owner, result.controllerId)
        assertEquals(show.requestId, result.requestId)
        assertEquals(7, result.configurationRevision)
        assertTrue(result.restartRequired)
        assertEquals(1, launches)
        assertEquals(3, requests)
    }

    @Test fun rawUnavailableIdentityReplyNeverRevokesOrLaunches() = runTest {
        val frontend = UUID.randomUUID().toString()
        var revocations = 0
        var launches = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            revokeRegistration = { revocations++; true }, launch = { _, _ -> launches++; ControlCode.OK },
            request = { command, _ ->
                assertIs<DesktopCliCommand.ControlFrontendIdentityRead>(command)
                DesktopCliResponse.failure("UNAVAILABLE", 2)
            })
        assertEquals(ControlCode.UNAVAILABLE, decoded(control.execute(input())).code)
        assertEquals(0, revocations)
        assertEquals(0, launches)
    }

    @Test fun malformedSuccessfulIdentityReplyNeverAdmitsUiAction() = runTest {
        for (probeAnswer in listOf(DesktopCliResponse.success("OK"), DesktopCliResponse(false, "OK", 0))) {
            val frontend = UUID.randomUUID().toString()
            var revocations = 0
            var submits = 0
            val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
                revokeRegistration = { revocations++; true }, request = { command, _ -> when (command) {
                    is DesktopCliCommand.ControlFrontendIdentityRead -> probeAnswer
                    is DesktopCliCommand.ControlSubmit -> {
                        submits++
                        DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(frontend,
                            command.request.requestId, ControlCode.OK, 0)))
                    }
                    else -> error("unexpected command $command")
                } })
            assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, decoded(control.execute(input())).code)
            assertEquals(0, revocations)
            assertEquals(0, submits)
        }
    }

    @Test fun leaseExpiryDuringDeadIdentityProbeStillLaunchesOneReplacement() = runTest {
        var now = 0L
        val stale = UUID.randomUUID().toString()
        val replacement = UUID.randomUUID().toString()
        val lifecycle = DesktopOwnerFrontendLifecycle(owner, backgroundScope, {}, { DesktopControlMetadata(0, false) }, { now })
        fun attach(id: String) = lifecycle.execute(DesktopCliCommand.ControlFrontendLease(UUID.randomUUID().toString(), owner,
            id, DesktopFrontendLeaseAction.ATTACH))
        assertEquals(ControlCode.OK, decoded(attach(stale)).code)
        var launches = 0
        var submits = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, lifecycle::registration,
            launch = { _, _ ->
                launches++
                assertEquals(ControlCode.OK, decoded(attach(replacement)).code)
                ControlCode.OK
            }, request = { command, _ -> when (command) {
                is DesktopCliCommand.ControlFrontendIdentityRead -> when (command.frontendId) {
                    stale -> { now = DesktopOwnerFrontendLifecycle.LEASE_MILLIS; DesktopCliResponse.notRunning() }
                    replacement -> identityResponse(command)
                    else -> error("unexpected frontend ${command.frontendId}")
                }
                is DesktopCliCommand.ControlSubmit -> {
                    submits++
                    assertEquals(replacement, command.request.controllerId)
                    DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(replacement,
                        command.request.requestId, ControlCode.OK, 0)))
                }
                else -> error("unexpected command $command")
            } }, pause = {}, revokeRegistration = lifecycle::revokeIfCurrent)
        assertEquals(ControlCode.OK, decoded(control.execute(input())).code)
        assertEquals(1, launches)
        assertEquals(1, submits)
    }

    @Test fun registrationChangedAfterSuccessfulProbeNeverReceivesUiCommand() = runTest {
        val stale = UUID.randomUUID().toString()
        var frontend = stale
        var submits = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            launch = { _, _ -> error("must not launch") }, request = { command, _ -> when (command) {
                is DesktopCliCommand.ControlFrontendIdentityRead -> {
                    val response = identityResponse(command)
                    frontend = UUID.randomUUID().toString()
                    response
                }
                is DesktopCliCommand.ControlSubmit -> { submits++; error("must not submit after registration changes") }
                else -> error("unexpected command $command")
            } })
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(input())).code)
        assertEquals(0, submits)
    }

    @Test fun deadFrontendProofNeverReplacesAConcurrentRegistration() = runTest {
        val stale = UUID.randomUUID().toString()
        var frontend = stale
        var launches = 0
        val control = DesktopGuiVisibilityControl(owner, { DesktopControlMetadata(0, false) }, { frontend },
            revokeRegistration = { id -> assertEquals(stale, id); frontend == id },
            launch = { _, _ -> launches++; ControlCode.OK }, request = { command, _ ->
                assertIs<DesktopCliCommand.ControlFrontendIdentityRead>(command)
                assertEquals(stale, command.frontendId)
                frontend = UUID.randomUUID().toString()
                DesktopCliResponse.notRunning()
            })
        assertEquals(ControlCode.CONFLICT, decoded(control.execute(input())).code)
        assertEquals(0, launches)
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
            else {
                assertEquals("OK", output.single().lineSequence().first())
                assertTrue(output.single().contains("Controller: $owner"))
            }
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
                when (command) {
                    is DesktopCliCommand.ControlFrontendIdentityRead -> identityResponse(command)
                    is DesktopCliCommand.ControlSubmit -> {
                        actions++
                        val request = command.request
                        DesktopCliResponse(false, ControlProtocolCodec.encodeResult(ControlResult(frontend,
                            request.requestId, ControlCode.TIMEOUT, 0, final = false)), 2)
                    }
                    else -> error("unexpected command $command")
                }
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
