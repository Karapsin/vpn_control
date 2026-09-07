package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.kardinal.vpncontrol.model.*
import java.io.ByteArrayOutputStream
import java.io.StringReader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class AndroidRoutingDraftFeedbackTest {
    @Test fun failedAutosaveKeepsInputAndVisibleTypedFeedbackAcrossUnrelatedUpdates() = runTest {
        val fixture = Fixture(this)
        fixture.service.onRoutingDirectDomainSuffixesDraftChanged(listOf("edited.test"))
        runCurrent()
        assertEquals(RoutingStatusMessages.routingRulesSaveFailed(), fixture.controller.currentState().routingDraftFailure)
        assertTrue(fixture.controller.currentState().routingDraftRetryAvailable)
        assertEquals(listOf("edited.test"), fixture.controller.currentState().routingDirectDomainSuffixesDraft)
        assertEquals(listOf("committed.test"), fixture.controller.currentState().routingRules.directDomainSuffixes)
        assertEquals(RoutingStatusMessages.routingRulesSaveFailed(), fixture.statuses.single())
        fixture.controller.update { it.copy(statusMessage = "Unrelated observation") }
        fixture.service.onRoutingAppSearchChanged("browser")
        assertEquals(RoutingStatusMessages.routingRulesSaveFailed(), fixture.controller.currentState().routingDraftFailure)
        fixture.service.openEditor()
        assertNull(fixture.controller.currentState().routingDraftFailure)
        assertFalse(fixture.controller.currentState().routingDraftRetryAvailable)
    }

    @Test fun uncertainResourceResultKeepsSameIdentityForExplicitUnchangedSaveRetry() = runTest {
        val fixture = Fixture(this)
        fixture.reply = { request -> fixture.result(request, ControlCode.RUNTIME_FAILED,
            warnings = listOf("RESOURCE_EXHAUSTED", "CONFIGURATION_OUTCOME_UNKNOWN")) }
        fixture.service.onRoutingDirectDomainSuffixesDraftChanged(listOf("edited.test"))
        runCurrent()
        assertEquals(RoutingStatusMessages.routingRulesOutcomeUnknown(), fixture.controller.currentState().routingDraftFailure)
        assertTrue(fixture.controller.currentState().routingDraftRetryAvailable)
        fixture.reply = { request ->
            fixture.committed = fixture.committed.copy(revision = 8,
                value = PersistedState(routingRules = RoutingRules(directDomainSuffixes = listOf("edited.test"))))
            fixture.result(request, ControlCode.OK, revision = 8)
        }
        fixture.service.saveRoutingRules()
        runCurrent()
        assertEquals(2, fixture.requests.size)
        assertEquals(fixture.requests.first(), fixture.requests.last())
        assertEquals(7L, fixture.requests.last().ifRevision)
        assertNull(fixture.controller.currentState().routingDraftFailure)
        assertFalse(fixture.controller.currentState().routingDraftRetryAvailable)
        assertEquals(listOf("edited.test"), fixture.controller.currentState().routingRules.directDomainSuffixes)
    }

    @Test fun staleSaveKeepsOpeningGuardAndDraftWithReopenFeedback() = runTest {
        val fixture = Fixture(this)
        fixture.service.observe(fixture.committed.copy(revision = 99))
        fixture.reply = { request -> fixture.result(request, ControlCode.CONFLICT) }
        fixture.service.onRoutingDirectDomainSuffixesDraftChanged(listOf("edited.test"))
        runCurrent()
        assertEquals(RoutingStatusMessages.routingRulesStaleDraft(), fixture.controller.currentState().routingDraftFailure)
        assertFalse(fixture.controller.currentState().routingDraftRetryAvailable)
        assertEquals(7L, fixture.requests.single().ifRevision)
        assertEquals(listOf("edited.test"), fixture.controller.currentState().routingDirectDomainSuffixesDraft)
    }

    @Test fun uncertainImportCannotOfferSavingTheUnrelatedEditorDraft() = runTest {
        val fixture = Fixture(this)
        fixture.reply = { request -> fixture.result(request, ControlCode.OUTCOME_UNKNOWN, final = false) }
        fixture.service.beginImport { }
        fixture.service.importRoutingReader { StringReader("{\"direct_domain_suffixes\":[\"imported.test\"]}") }
        runCurrent()
        assertEquals(RoutingStatusMessages.routingRulesOutcomeUnknown(), fixture.controller.currentState().routingDraftFailure)
        assertFalse(fixture.controller.currentState().routingDraftRetryAvailable)
        assertEquals(listOf("committed.test"), fixture.controller.currentState().routingDirectDomainSuffixesDraft)
        fixture.service.cancelImport()
        assertNull(fixture.controller.currentState().routingDraftFailure)
    }

    private class Fixture(scope: TestScope) {
        val initial = RoutingRules(directDomainSuffixes = listOf("committed.test"))
        val controller = MainController(MainUiState(currentScreen = AppScreen.ROUTING_RULES,
            routingRules = initial, routingDirectDomainSuffixesDraft = initial.directDomainSuffixes))
        var committed = ControlCommitted("owner", 7, PersistedState(routingRules = initial))
        val statuses = mutableListOf<String>()
        val requests = mutableListOf<ControlRequest>()
        var reply: (ControlRequest) -> ControlResult = { result(it, ControlCode.PERSISTENCE_FAILED) }
        val guarded = AndroidRoutingDraftControl({
            AndroidControlInputSpool(object : ControlTransferSpool {
                val bytes = ByteArrayOutputStream()
                override fun append(value: ByteArray) { bytes.write(value) }
                override fun read(offset: Long, length: Int) = bytes.toByteArray().copyOfRange(offset.toInt(), offset.toInt() + length)
                override fun sha256(): String = error("unused")
                override fun erase() { bytes.reset() }
            })
        }, { request, input ->
            requests += request
            input.close()
            CompletableDeferred(reply(request))
        }, { "operation" }, StandardTestDispatcher(scope.testScheduler))
        val service = AndroidRoutingActionsService(controller, controller::currentState, AndroidControllerEffectSink {},
            { work -> scope.backgroundScope.launch { work() } }, {}, { error("guarded owner required") },
            { statuses += it }, guarded, { committed })

        init { service.observe(committed); check(service.openEditor()) }

        fun result(request: ControlRequest, code: ControlCode, revision: Long = 7,
            final: Boolean = true, warnings: List<String> = emptyList()) =
            ControlResult("owner", request.requestId, code, revision, final = final, operationId = "operation",
                message = "UNTRUSTED_PRIVATE_FAILURE", warnings = warnings)
    }
}
