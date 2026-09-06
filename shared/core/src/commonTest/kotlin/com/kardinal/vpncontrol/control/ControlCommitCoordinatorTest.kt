package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ControlCommitCoordinatorTest {
    private data class State(val selected: String = "A", val telemetry: Int = 0)

    @Test
    fun failureLeavesRevisionAndPublishedStateUnchanged() = runTest {
        val coordinator = ControlCommitCoordinator("owner", State(), State::selected) {
            Result.failure(IllegalStateException("SECRET"))
        }
        val result = coordinator.commit { it.copy(selected = "B") }
        assertEquals(ControlCode.PERSISTENCE_FAILED, assertIs<ControlCommitResult.Rejected>(result).code)
        assertEquals(State(), coordinator.committed.value.value)
        assertEquals(0, coordinator.committed.value.revision)
    }

    @Test
    fun staleDraftAndDifferentControllerEpochCannotOverwriteCommittedChanges() = runTest {
        val coordinator = ControlCommitCoordinator("owner", State(), State::selected) { Result.success(Unit) }
        coordinator.commit("owner", 0) { it.copy(selected = "B") }
        assertEquals(ControlCode.CONFLICT, assertIs<ControlCommitResult.Rejected>(
            coordinator.commit("owner", 0) { it.copy(selected = "C") }).code)
        assertEquals(ControlCode.CONFLICT, assertIs<ControlCommitResult.Rejected>(
            coordinator.commit("previous-owner", 1) { it.copy(selected = "C") }).code)
        assertEquals(State(selected = "B"), coordinator.committed.value.value)
    }

    @Test
    fun telemetryPersistsWithoutInvalidatingAnOpenConfigurationDraft() = runTest {
        val coordinator = ControlCommitCoordinator("owner", State(), State::selected) { Result.success(Unit) }
        coordinator.commit { it.copy(telemetry = 7) }
        assertEquals(0, coordinator.committed.value.revision)
        assertIs<ControlCommitResult.Applied<State>>(coordinator.commit("owner", 0) { it.copy(selected = "B") })
        assertEquals(State("B", 7), coordinator.committed.value.value)
        assertEquals(1, coordinator.committed.value.revision)
    }

    @Test
    fun noOpDoesNotWriteOrIncrementRevision() = runTest {
        var writes = 0
        val coordinator = ControlCommitCoordinator("owner", State(), State::selected) { writes++; Result.success(Unit) }
        assertEquals(false, assertIs<ControlCommitResult.Applied<State>>(coordinator.commit { it }).changed)
        assertEquals(0, writes)
        assertEquals(0, coordinator.committed.value.revision)
    }

    @Test
    fun slowDurableCommitKeepsReadsResponsiveAndRejectsAConflictingMutation() = runTest {
        val entered = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        val coordinator = ControlCommitCoordinator("owner", State(), State::selected) {
            entered.complete(Unit)
            finish.await()
            Result.success(Unit)
        }
        val write = async { coordinator.commit { it.copy(selected = "B") } }
        entered.await()
        assertEquals(State(), coordinator.committed.value.value)
        assertEquals(ControlCode.BUSY, assertIs<ControlCommitResult.Rejected>(coordinator.commit { it.copy(selected = "C") }).code)
        finish.complete(Unit)
        write.await()
        assertEquals(State("B"), coordinator.committed.value.value)
    }

    @Test
    fun cancellationDuringDurableWriteCannotLeaveMemoryBehindDisk() = runTest {
        val entered = CompletableDeferred<Unit>()
        val finish = CompletableDeferred<Unit>()
        var disk = State()
        val coordinator = ControlCommitCoordinator("owner", disk, State::selected) {
            entered.complete(Unit)
            finish.await()
            disk = it
            Result.success(Unit)
        }
        val write = async { coordinator.commit { it.copy(selected = "B") } }
        entered.await()
        write.cancel()
        finish.complete(Unit)
        write.join()
        assertEquals(State("B"), disk)
        assertEquals(disk, coordinator.committed.value.value)
        assertEquals(1, coordinator.committed.value.revision)
    }
}
