package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlCommitted
import com.kardinal.vpncontrol.control.ControlTransferSpool
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidControlResourceBoundaryTest {
    @Test fun preparedSpoolWriteFailurePreservesDiskAndRetainsTypedFailure() = preparedPersistenceFailure(
        java.io.IOException("PRIVATE_SPOOL_PAYLOAD"), ControlCode.PERSISTENCE_FAILED)

    @Test fun preparedSpoolAllocationFailureKeepsUnknownOutcomeHonestAndReleasesAdmission() = preparedPersistenceFailure(
        OutOfMemoryError("PRIVATE_SPOOL_PAYLOAD"), ControlCode.RUNTIME_FAILED)

    private fun preparedPersistenceFailure(failure: Throwable, expected: ControlCode) = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler))
        val directory = java.nio.file.Files.createTempDirectory("prepared-routing-failure-").toFile()
        try {
            val disk = java.io.File(directory, "configuration.preferences_pb")
            val domains = androidx.datastore.preferences.core.stringPreferencesKey("direct_domain_suffixes")
            val store = androidx.datastore.core.DataStoreFactory.create(
                serializer = AndroidPreferencesSerializer(directory.toPath()), scope = scope) { disk }
            val configuration = AndroidConfigurationStore(store, { prefs -> PersistedState(routingRules =
                RoutingRules(directDomainSuffixes = AndroidPersistedDomainSuffixes.decode(prefs[domains]))) }, "owner")
            configuration.edit { it[domains] = "old.test" }
            val previousBytes = disk.readBytes()
            val jobs = AndroidCommandJobs(scope)
            var fail = true
            var calls = 0
            var erased = 0
            val control = AndroidSettingsControl("owner", scope, configuration::snapshot,
                { _, _, _ -> error("not settings") }, {}, { false }, mutationJobs = jobs,
                routingImport = { rules, epoch, revision ->
                    calls++
                    val committed = configuration.editProjected(epoch, revision) { prefs, _ ->
                        prefs[domains] = rules.consume {
                            val spool = AndroidControlTransferSpool.create(directory.toPath())
                            object : ControlTransferSpool by spool {
                                override fun append(bytes: ByteArray) { if (fail) throw failure else spool.append(bytes) }
                                override fun erase() { erased++; spool.erase() }
                            }
                        }.directDomainSuffixes
                    }
                    AndroidSettingsCommit(committed, false)
                })
            val request = ControlRequest("prepared-failure", ControlCommand(ControlOperationId.ROUTING_IMPORT,
                mapOf("input" to ControlValue.Text("""{"direct_domain_suffixes":["first.test","second.test"]}"""))),
                controllerId = "owner", ifRevision = 1)
            val result = control.execute(request)
            assertEquals(expected, result.code)
            assertArrayEquals(previousBytes, disk.readBytes())
            assertEquals(1, configuration.snapshot().revision)
            assertEquals(listOf("old.test"), configuration.snapshot().value.routingRules.directDomainSuffixes)
            assertEquals(1, erased)
            assertFalse(jobs.busy.value)
            assertFalse(com.kardinal.vpncontrol.control.ControlDocumentCodec.encodeResult(result).contains("PRIVATE_SPOOL_PAYLOAD"))
            if (failure is OutOfMemoryError) {
                assertTrue("RESOURCE_EXHAUSTED" in result.warnings)
                assertTrue("CONFIGURATION_OUTCOME_UNKNOWN" in result.warnings)
                assertFalse("CONFIGURATION_COMMITTED" in result.warnings)
            } else {
                assertEquals(1, result.configurationRevision)
                assertTrue(result.warnings.isEmpty())
            }
            assertEquals(result, control.execute(request))
            assertEquals(1, calls)
            fail = false
            val saved = control.execute(request.copy(requestId = "next"))
            assertEquals(ControlCode.OK, saved.code)
            assertEquals(2, saved.configurationRevision)
            assertEquals(listOf("first.test", "second.test"), configuration.snapshot().value.routingRules.directDomainSuffixes)
            assertEquals(result, control.execute(request))
            assertEquals(2, calls)
        } finally { scope.coroutineContext[Job]?.cancelAndJoin(); directory.deleteRecursively() }
    }

    @Test fun boundaryDoesNotSwallowUnrelatedErrors() = runTest {
        for (error in listOf(AssertionError("assertion"), ThreadDeath())) {
            assertSame(error, runCatching {
                androidControlResourceBoundary("owner", "request", "operation") { throw error }
            }.exceptionOrNull())
        }
    }
    @Test fun ownerContainsAllocationFailureRetainsRetryAndReleasesAdmission() = runTest {
        val uncaught = mutableListOf<Throwable>()
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler) + CoroutineExceptionHandler { _, e -> uncaught.add(e) })
        try {
            val jobs = AndroidCommandJobs(scope)
            var calls = 0
            val control = AndroidSettingsControl("owner", scope, { ControlCommitted("owner", 0, PersistedState()) },
                { _, _, _ -> error("not settings") }, {}, { false }, mutationJobs = jobs,
                routing = { _, _, _, _ -> calls++; throw OutOfMemoryError("PRIVATE_INPUT") })
            val request = ControlRequest("oom", ControlCommand(ControlOperationId.ROUTING_IMPORT,
                mapOf("input" to ControlValue.Text("{}"))), controllerId = "owner")
            val result = control.execute(request)
            assertTrue("Owner must not dispatch OOM to Android uncaught handler", uncaught.isEmpty())
            assertEquals(ControlCode.RUNTIME_FAILED, result.code)
            assertTrue(result.warnings.contains("RESOURCE_EXHAUSTED"))
            assertTrue(result.warnings.contains("CONFIGURATION_REVISION_UNAVAILABLE"))
            assertFalse(result.toString().contains("PRIVATE_INPUT"))
            assertEquals(result, control.execute(request))
            assertEquals(1, calls)
            assertFalse(jobs.busy.value)
        } finally { scope.cancel() }
    }

    @Test fun allocationAfterDurableCommitKeepsExactRevisionAndCommittedOutcome() = runTest {
        val scope = CoroutineScope(SupervisorJob() + StandardTestDispatcher(testScheduler) + CoroutineExceptionHandler { _, _ -> })
        try {
            val committed = ControlCommitted("owner", 7, PersistedState())
            val control = AndroidSettingsControl("owner", scope, { committed },
                { _, _, _ -> AndroidSettingsCommit(committed, true) }, { throw OutOfMemoryError("PRIVATE") }, { false })
            val result = control.execute(ControlRequest("durable", ControlCommand(ControlOperationId.SETTINGS_SET,
                mapOf("key" to ControlValue.Text("language"), "value" to ControlValue.Text("en"))), controllerId = "owner"))
            assertEquals(ControlCode.RUNTIME_FAILED, result.code)
            assertEquals(7L, result.configurationRevision)
            assertEquals(ControlValue.BooleanValue(true), result.data["configurationCommitted"])
            assertTrue(result.warnings.contains("RESOURCE_EXHAUSTED"))
            assertTrue(result.warnings.contains("CONFIGURATION_COMMITTED"))
            assertTrue(result.warnings.contains("POST_COMMIT_RESULT_UNAVAILABLE"))
            assertFalse(result.warnings.contains("SCHEDULING_FAILED_OR_UNKNOWN"))
        } finally { scope.cancel() }
    }
}
