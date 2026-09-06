package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.*
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingControlTest {
    private val apps = listOf(InstalledApp("app.browser", "Browser", false), InstalledApp("app.mail", "Mail", false))
    private fun values(vararg entries: Pair<String, String>) = entries.associate { it.first to ControlValue.Text(it.second) }

    @Test fun setAndImportMatchGuiNormalizationWithoutDormantRules() {
        val changed = AndroidRoutingControl.plan(PersistedState(), ControlOperationId.ROUTING_SET,
            values("key" to "direct-domains", "value" to "[\"EXAMPLE.COM\",\"example.com\"]"), emptyList())
        assertEquals(listOf("example.com"), changed.directDomainSuffixes)
        val imported = AndroidRoutingControl.plan(PersistedState(), ControlOperationId.ROUTING_IMPORT,
            values("input" to RoutingRulesTransfer.export(changed.copy(proxyPackages = listOf("not.installed"))).content), emptyList())
        assertEquals(changed.copy(proxyPackages = listOf("not.installed")), imported)
        val result = AndroidRoutingControl.result(PersistedState(routingRules = changed), ControlOperationId.ROUTING_SET,
            values("key" to "direct-domains", "value" to "ignored"))
        assertEquals(setOf("direct-domains"), result.keys)
    }

    @Test fun visibleSearchBulkActionsPreserveOtherAssignmentsAndReadCheckboxes() {
        val state = PersistedState(routingRules = RoutingRules(proxyPackages = listOf("app.mail", "old.uninstalled")))
        val selected = AndroidRoutingControl.plan(state, ControlOperationId.ROUTING_APPS_SELECT_ALL,
            values("search" to " browSER "), apps)
        assertEquals(setOf("app.mail", "old.uninstalled", "app.browser"), selected.proxyPackages.toSet())
        val cleared = AndroidRoutingControl.plan(state.copy(routingRules = selected), ControlOperationId.ROUTING_APPS_CLEAR,
            values("search" to "app.browser"), apps)
        assertEquals(state.routingRules.proxyPackages.toSet(), cleared.proxyPackages.toSet())
        val rows = (AndroidRoutingControl.list(state, values("search" to "MAIL"), apps).getValue("apps") as ControlValue.ArrayValue).values
        val row = (rows.single() as ControlValue.ObjectValue).values
        assertEquals(ControlValue.Text("app.mail"), row["package"])
        assertEquals(ControlValue.BooleanValue(true), row["selected"])
    }

    @Test fun packageInputIsStrictAndUnknownAddCannotCreateInvisibleSelection() {
        val state = PersistedState()
        for (input in listOf("{}", "[1]", "[null]", "[\"\"]", "not-json")) {
            assertEquals("INVALID_ARGUMENT", runCatching { AndroidRoutingControl.plan(state, ControlOperationId.ROUTING_APPS_SET,
                values("input" to input), apps) }.exceptionOrNull()?.message)
        }
        assertEquals("NOT_FOUND", runCatching { AndroidRoutingControl.plan(state, ControlOperationId.ROUTING_APPS_ADD,
            values("package" to "unknown.package"), apps) }.exceptionOrNull()?.message)
        val set = AndroidRoutingControl.plan(state, ControlOperationId.ROUTING_APPS_SET,
            values("input" to "[\"app.mail\",\"app.mail\"]"), apps)
        assertEquals(listOf("app.mail"), set.proxyPackages)
        val removed = AndroidRoutingControl.plan(state.copy(routingRules = set), ControlOperationId.ROUTING_APPS_REMOVE,
            values("package" to "app.mail"), apps)
        assertTrue(removed.proxyPackages.isEmpty())
        assertTrue(AndroidRoutingControl.plan(state.copy(routingRules = set), ControlOperationId.ROUTING_APPS_SET,
            values("input" to "[]"), apps).proxyPackages.isEmpty())
    }
}
