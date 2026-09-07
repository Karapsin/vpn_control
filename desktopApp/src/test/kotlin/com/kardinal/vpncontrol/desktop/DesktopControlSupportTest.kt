package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.control.ControlOperationRegistry
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class DesktopControlSupportTest {
    @Test
    fun capabilityReportCoversRegistryWithoutClaimingUnimplementedJsonOrPlatformFeatures() {
        for (platform in listOf(ControlPlatform.LINUX, ControlPlatform.WINDOWS, ControlPlatform.MACOS)) {
            val report = DesktopControlSupport.describe(platform)
            val operations = (report.getValue("jsonOperations") as ControlValue.ArrayValue).values
                .map { (it as ControlValue.ObjectValue).values }
                .associateBy { (it.getValue("id") as ControlValue.Text).value }
            assertEquals(ControlOperationId.entries.map { it.wireName }.toSet(), operations.keys)
            for (id in ControlOperationId.entries) {
                assertEquals(ControlValue.BooleanValue(id in DesktopControlSupport.jsonOperations &&
                    (id != ControlOperationId.UPDATES_INSTALL || platform in setOf(ControlPlatform.WINDOWS, ControlPlatform.LINUX, ControlPlatform.MACOS))),
                    operations.getValue(id.wireName)["supported"])
                assertEquals(ControlValue.ArrayValue(if (id in DesktopControlSupport.jsonOperations)
                    ControlOperationRegistry[id].arguments.flags.sorted().map(ControlValue::Text) else emptyList()),
                    operations.getValue(id.wireName)["flags"])
            }
            val installation = operations.getValue(ControlOperationId.UPDATES_INSTALL.wireName)
            assertEquals(ControlValue.ArrayValue(when (platform) {
                ControlPlatform.LINUX -> listOf("deb", "rpm", "arch-bundle")
                ControlPlatform.WINDOWS -> listOf("msi")
                ControlPlatform.MACOS -> listOf("dmg")
                else -> emptyList()
            }.map(ControlValue::Text)), installation["packageTypes"])
            assertEquals(ControlValue.Null, installation["reasonCode"])
            assertEquals(ControlValue.BooleanValue(false), report["runtimeReadinessChecked"])
            assertEquals(ControlValue.BooleanValue(true), report["humanUsesJsonAdapter"])
            assertEquals(ControlValue.Text("UNSUPPORTED"), operations.getValue(ControlOperationId.ROUTING_APPS_LIST.wireName)["reasonCode"])
            assertEquals(ControlValue.BooleanValue(true), report["guiAttachDetach"])
            assertEquals(ControlValue.BooleanValue(true), report["publicRevisionGuards"])
            assertEquals(DesktopControlSupport.revisionGuardOperations.map { ControlValue.Text(it.wireName) },
                (report.getValue("revisionGuardOperations") as ControlValue.ArrayValue).values)
            val platformValues = (report.getValue("platformCapabilities") as ControlValue.ObjectValue).values
            assertEquals(ControlValue.BooleanValue(platform != ControlPlatform.MACOS), platformValues["mode.vpn"])
            assertEquals(ControlValue.BooleanValue(false), platformValues["routing.apps"])
        }
    }

    @Test
    fun staticCapabilitiesDoNotContactOrStartAnOwner() {
        for (args in listOf(arrayOf("capabilities"), arrayOf("--json", "capabilities"))) {
            val output = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs(args, output::add,
                requestCommand = { error("Static inspection contacted owner") },
                startHeadlessController = { error("Static inspection started owner") }))
            assertFalse(output.single().isBlank())
            if (args.first() == "--json") {
                val result = ControlProtocolCodec.decodeResult(output.single())
                assertEquals(null, result.controllerId)
                assertEquals(ControlValue.Text("static-desktop-json-adapter"), result.data["scope"])
            }
        }
    }
}
