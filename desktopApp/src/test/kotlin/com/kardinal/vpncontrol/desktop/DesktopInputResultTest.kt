package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DesktopInputResultTest {
    @Test fun importAllocationFailureIsUnavailableBeforeOwnerSubmission() {
        for (operation in listOf(ControlOperationId.LOCATIONS_IMPORT, ControlOperationId.ROUTING_IMPORT)) {
            val commands = mutableListOf<ControlCommand>()
            val failures = mutableListOf<ControlCode>()
            desktopImportContent(operation, Result.failure(OutOfMemoryError("controlled allocation failure")),
                { commands.add(it) }, { failures.add(it) })
            assertEquals(listOf(ControlCode.UNAVAILABLE), failures)
            assertTrue(commands.isEmpty())
        }
    }

    @Test fun otherAcquisitionFailuresKeepInvalidArgumentAndNoSubmission() {
        for (failure in listOf(IllegalArgumentException("invalid text"), IOException("controlled read failure"))) {
            val failures = mutableListOf<ControlCode>()
            desktopImportContent(ControlOperationId.LOCATIONS_IMPORT, Result.failure(failure),
                { error("Acquisition failure submitted an owner command") }, { failures.add(it) })
            assertEquals(listOf(ControlCode.INVALID_ARGUMENT), failures)
        }
    }

    @Test fun cancellationIsSilentAndSuccessfulContentRemainsUnparsedOwnerInput() {
        val commands = mutableListOf<ControlCommand>()
        val failures = mutableListOf<ControlCode>()
        desktopImportContent(ControlOperationId.ROUTING_IMPORT, Result.success(null),
            { commands.add(it) }, { failures.add(it) })
        assertTrue(commands.isEmpty())
        assertTrue(failures.isEmpty())
        for (text in listOf("", "invalid document", "routing-東\n")) {
            desktopImportContent(ControlOperationId.ROUTING_IMPORT, Result.success(text),
                { commands.add(it) }, { failures.add(it) })
            assertEquals(ControlCommand(ControlOperationId.ROUTING_IMPORT,
                mapOf("input" to ControlValue.Text(text))), commands.last())
        }
        assertEquals(3, commands.size)
        assertTrue(failures.isEmpty())
    }

    @Test fun sshAllocationFailureNeverConstructsAnActionAndCancellationIsSilent() {
        val failures = mutableListOf<ControlCode>()
        assertNull(desktopSshKeyInput(Result.failure(OutOfMemoryError("controlled allocation failure")),
            "owner", 7, { failures.add(it) }))
        assertEquals(listOf(ControlCode.UNAVAILABLE), failures)
        failures.clear()
        assertNull(desktopSshKeyInput(Result.success(null), "owner", 7, { failures.add(it) }))
        assertTrue(failures.isEmpty())
    }

    @Test fun sshSuccessfulInputKeepsOriginalControllerRevisionAndBytes() {
        val text = "harmless source-control text\n"
        val action = requireNotNull(desktopSshKeyInput(Result.success(text), "owner", 7,
            { error("Successful input classified as a failure") }))
        assertEquals("owner", action.controllerId)
        assertEquals(7L, action.revision)
        assertEquals(text, action.content)
        assertEquals(ControlOperationId.SSH_KEY_IMPORT, action.request().command.operation)
        assertEquals(ControlValue.Text(text), action.request().command.arguments["input"])
    }

    @Test fun actualCliBuilderAndGuiKeepTheSameAllocationFailureCode() {
        val output = mutableListOf<String>()
        assertEquals(2, DesktopCli.handleArgs(arrayOf("--json", "locations", "import", "--input", "controlled"),
            output::add, requestCommand = { error("Acquisition failure reached transport") },
            startHeadlessController = { error("Acquisition failure started an owner") },
            readInput = { Result.failure(OutOfMemoryError("controlled allocation failure")) }))
        assertEquals(ControlCode.UNAVAILABLE, ControlProtocolCodec.decodeResult(output.single()).code)
        assertTrue(!output.single().contains("controlled allocation failure"))
    }
}
