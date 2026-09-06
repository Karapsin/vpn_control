package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlResult
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import kotlinx.coroutines.test.runTest

class DesktopGuiCommandsTest {
    @Test
    fun guiRejectionsProduceSafeLocalFeedbackAndSuccessDoesNot() = runTest {
        val feedback = mutableListOf<ControlCode>()
        for (code in listOf(ControlCode.BUSY, ControlCode.CONFLICT, ControlCode.UNSUPPORTED)) {
            val response = DesktopCliResponse.failure(code.wireName)
            assertEquals(response, executeDesktopGuiCommand(DesktopCliCommand.On, { response }, feedback::add))
        }
        assertEquals(listOf(ControlCode.BUSY, ControlCode.CONFLICT, ControlCode.UNSUPPORTED), feedback)
        executeDesktopGuiCommand(DesktopCliCommand.On, { DesktopCliResponse.success("ACCEPTED") }, feedback::add)
        assertEquals(3, feedback.size)
        executeDesktopGuiCommand(DesktopCliCommand.On, {
            DesktopCliResponse.failure("BUSY https://private.example/token secret input")
        }, feedback::add)
        assertEquals(ControlCode.RUNTIME_FAILED, feedback.last())
        assertEquals(ControlCode.RUNTIME_FAILED, desktopGuiCommandFailure(DesktopCliResponse.failure("ACCEPTED")))
        val encoded = ControlProtocolCodec.encodeResult(ControlResult("owner", "request", ControlCode.CONFLICT, 1,
            message = "private controller text", warnings = listOf("private warning")))
        assertEquals(ControlCode.CONFLICT, desktopGuiCommandFailure(DesktopCliResponse.failure(encoded)))
        val accepted = ControlProtocolCodec.encodeResult(ControlResult("owner", "request", ControlCode.ACCEPTED, 1,
            final = false, operationId = "operation"))
        assertEquals(null, desktopGuiCommandFailure(DesktopCliResponse.success(accepted)))
    }

    @Test
    fun benchmarkReferenceSurvivesNumericNamesAndReorderingButRejectsReplacement() {
        val records = listOf("socks://127.0.0.1:1080#2", "socks://127.0.0.2:1080#Same")
            .toDesktopLocationRecords(1).mapIndexed { index, record -> record.copy(index = 10 + index * 20) }
        val identity = DesktopControlLocationIdentity()
        val id: (DesktopLocationRecord) -> String? = { identity.id(it.sourceUrl, it.rawLink) }
        val command = assertNotNull(desktopGuiBenchmarkCommand(30, records, id))
        val reference = assertNotNull(command.configurationId)
        assertEquals(records[1], resolveDesktopConfigurationReference(reference, records, id).getOrThrow())
        val reordered = records.reversed().mapIndexed { index, record -> record.copy(index = index) }
        assertEquals(reordered[0], resolveDesktopConfigurationReference(reference, reordered, id).getOrThrow())
        assertEquals(command, DesktopCliProtocol.decodeCommand(DesktopCliProtocol.encodeCommand(command)).getOrThrow())
        assertNotEquals(DesktopCliProtocol.encodeCommand(command), DesktopCliProtocol.encodeCommand(
            assertNotNull(desktopGuiBenchmarkCommand(10, records, id))))
        assertEquals(null, desktopGuiBenchmarkCommand(20, records, id))
        for (changed in listOf(records.take(1), listOf(records[1].copy(rawLink = records[0].rawLink)),
            listOf(records[1], records[1].copy(index = 99)))) {
            assertEquals("CONFLICT", resolveDesktopConfigurationReference(reference, changed, id).exceptionOrNull()?.message)
        }
    }
}
