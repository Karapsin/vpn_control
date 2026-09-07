package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.RoutingRules
import kotlin.test.*

class RoutingGuiProjectionTest {
    @Test fun committedEqualDraftReleasesIndexedViewOfObsoletePersistedSource() {
        val old = listOf("one.test", "removed.test", "two.test")
        val draft = DirectDomainDrafts.remove(old, 1)
        val canonical = listOf("one.test", "two.test")
        val committed = RoutingRules(directDomainSuffixes = canonical)
        val controller = MainController(MainUiState(routingRules = committed,
            routingDirectDomainSuffixesDraft = draft))
        controller.applyImportedRoutingRules(committed)
        assertSame(canonical, controller.currentState().routingDirectDomainSuffixesDraft,
            "Equal draft contents must not retain the old large preference through an indexed view")
    }

    @Test fun indexedRemovalAndDraftHandoffDoNotReadOrCopyAllDomainStrings() {
        var reads = 0
        val domains = object : AbstractList<String>() {
            override val size = 56_000
            override fun get(index: Int): String { reads++; return "d$index.test" }
        }
        val removed = DirectDomainDrafts.remove(domains, 10)
        val controller = MainController()
        controller.onRoutingDirectDomainSuffixesDraftChanged(removed)
        assertEquals(0, reads)
        assertSame(removed, controller.currentState().routingDirectDomainSuffixesDraft)
        assertEquals("d11.test", removed[10])
        assertEquals(55_999, removed.size)
    }

    @Test fun editsPreserveNormalizationOrderingAndOpeningInput() {
        val original = listOf("z.example", "com", "a.example")
        val added = DirectDomainDrafts.add(original, "*.A.Example, .z. new.example")
        assertEquals(listOf("com", "z", "a.example", "new.example", "z.example"),
            DirectDomainDrafts.orderedIndices(added).map { added[it] })
        val removed = DirectDomainDrafts.remove(added, 0)
        assertFalse("z.example" in removed)
        assertEquals(listOf("z.example", "com", "a.example"), original)
        val input = mutableListOf("*.X.Test", "x.test")
        val controller = MainController()
        controller.onRoutingDirectDomainSuffixesDraftChanged(input)
        input.clear()
        assertEquals(listOf("x.test"), MainDraftLogic.buildEditedRoutingRules(controller.currentState()).directDomainSuffixes)
        controller.onRoutingDirectDomainsDraftChanged("y.test")
        assertEquals(listOf("y.test"), MainDraftLogic.buildEditedRoutingRules(controller.currentState()).directDomainSuffixes)
    }

    @Test fun openingAndRefreshingGuiDoesNotReadEveryDomainIntoEditorText() {
        val domains = object : AbstractList<String>() {
            override val size = 56_000
            override fun get(index: Int): String = error("GUI projection materialized domain $index")
        }
        val persisted = PersistedState(routingRules = RoutingRules(directDomainSuffixes = domains))
        val controller = MainController()
        controller.mergePersistedState(persisted)
        val initial = controller.currentState()
        assertEquals("", initial.routingDirectDomainsDraft)
        val opened = MainUiStateTransitions.prepareRoutingRulesScreen(initial)
        val imported = MainDraftLogic.applyImportedRoutingRules(opened, persisted.routingRules)
        assertSame(domains, MainDraftLogic.buildEditedRoutingRules(imported).directDomainSuffixes)
    }
}
