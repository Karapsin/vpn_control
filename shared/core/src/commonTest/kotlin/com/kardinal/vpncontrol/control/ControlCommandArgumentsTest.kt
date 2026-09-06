package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class ControlCommandArgumentsTest {
    @Test
    fun typedInputsUseGrammarWithoutInterpretingContentAsOptionsOrPaths() {
        val key = "-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic\n-----END OPENSSH PRIVATE KEY-----"
        val parsed = assertNotNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.SSH_KEY_IMPORT,
            mapOf("input" to ControlValue.Text(key)))))
        assertEquals(key, parsed.options["--input"])
        val selection = assertNotNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.LOCATIONS_SELECT,
            mapOf("selector" to ControlValue.Text("--json")))))
        assertEquals(listOf("--json"), selection.positional)
        assertFalse(selection.client.json)
        assertNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.SOURCE_SET,
            mapOf("subscription-id" to ControlValue.Text("id")))))
        assertNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.SOURCE_SET,
            mapOf("source" to ControlValue.Text("all"), "subscription-id" to ControlValue.Text("id")))))
        assertNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.SUBSCRIPTIONS_ADD,
            mapOf("source" to ControlValue.Text("https://example.test"), "input" to ControlValue.Text("content")))))
        assertNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.LOCATIONS_DELETE,
            mapOf("selector" to ControlValue.IntegerValue(1)))))
        assertNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.UPDATES_DISMISS,
            mapOf("unknown" to ControlValue.Text("private")))))
        assertNotNull(ControlCommandArguments.decode(ControlCommand(ControlOperationId.SUBSCRIPTIONS_UPDATE,
            mapOf("id" to ControlValue.Text("id"), "name" to ControlValue.Text("")))))
    }
}
