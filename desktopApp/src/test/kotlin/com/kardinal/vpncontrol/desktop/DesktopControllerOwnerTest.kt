package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class DesktopControllerOwnerTest {
    @Test
    fun processOwnerHandlesModernCliBeforeAnyGuiIsComposedAndSerializesStartup() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-process-owner")
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)))
        val endpoint = directory.resolve("activation.port")
        val server = assertNotNull(DesktopActivationServer.start(
            onShowWindow = { DesktopActivationShowResult.SHOWN },
            onCliCommand = { runBlocking { owner.session.execute(it) } },
            portFile = endpoint, controllerId = owner.controllerId))
        val started = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        try {
            fun invoke(vararg args: String): Pair<Int?, com.kardinal.vpncontrol.model.ControlResult> {
                val output = mutableListOf<String>()
                val code = DesktopCli.handleArgs(arrayOf("--json", *args), output::add,
                    requestCommand = { DesktopActivationServer.requestCliCommand(it, endpoint) },
                    startHeadlessController = { error("Already owned") })
                return code to ControlProtocolCodec.decodeResult(output.single())
            }
            val initialization = owner.scope.launch {
                owner.session.initialize { started.complete(Unit); finish.await() }
            }
            started.await()
            val status = invoke("status")
            assertEquals(0, status.first)
            assertEquals(owner.controllerId, status.second.controllerId)
            assertEquals(ControlValue.BooleanValue(false), status.second.data["runtimeRunning"])
            assertEquals(ControlCode.BUSY, invoke("settings", "set", "validation.batch-size", "7").second.code)
            finish.complete(Unit)
            initialization.join()
            assertEquals(0, invoke("settings", "set", "validation.batch-size", "7").first)
            assertEquals(7, owner.service.state.validationSettings.batchSize)
            assertEquals(ControlValue.IntegerValue(7), invoke("settings", "show", "validation.batch-size").second.data["validation.batch-size"])
        } finally {
            finish.complete(Unit)
            server.close()
            owner.close()
            directory.toFile().deleteRecursively()
        }
    }
}
