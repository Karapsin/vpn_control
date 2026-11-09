package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.util.UUID
import kotlinx.coroutines.test.runTest
import kotlin.test.*

/** What an ATTACH that finds another frontend's lease observes, and what it never releases. */
class DesktopFrontendReattachObservationTest {
    private suspend fun attach(owner: DesktopControllerOwner, frontend: String): ControlCode =
        ControlProtocolCodec.decodeResult(owner.execute(DesktopCliCommand.ControlFrontendLease(UUID.randomUUID().toString(),
            owner.controllerId, frontend, DesktopFrontendLeaseAction.ATTACH)).message).code

    @Test fun an_unknown_observation_of_the_captured_frontend_keeps_its_lease() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-unknown")
        val observed = mutableListOf<DesktopFrontendProcessIdentity>()
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)),
            scope = backgroundScope, observeFrontend = { observed += it; DesktopFrontendProcessObservation.UNKNOWN })
        val held = UUID.randomUUID().toString()
        try {
            assertEquals(ControlCode.OK, attach(owner, held))
            val identity = DesktopFrontendProcessIdentity(held, 42, 7)
            assertTrue(owner.frontends.captureProcessIdentity(held, identity))
            assertEquals(ControlCode.BUSY, attach(owner, UUID.randomUUID().toString()))
            assertEquals(held, owner.frontends.registration())
            assertEquals(listOf(identity), observed, "The exact captured generation is observed once, and uncertainty keeps it")
            // A re-attach of the held registration itself observes nothing.
            assertEquals(ControlCode.OK, attach(owner, held))
            assertEquals(1, observed.size)
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun an_uncaptured_lease_answers_busy_until_it_expires() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-expiry")
        var now = 0L
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)),
            scope = backgroundScope, observeFrontend = { fail("No captured identity exists to observe") },
            frontendNowMillis = { now })
        val held = UUID.randomUUID().toString()
        val next = UUID.randomUUID().toString()
        try {
            assertEquals(ControlCode.OK, attach(owner, held))
            now = DesktopOwnerFrontendLifecycle.LEASE_MILLIS - 1
            assertEquals(ControlCode.BUSY, attach(owner, next))
            assertEquals(held, owner.frontends.registration())
            now = DesktopOwnerFrontendLifecycle.LEASE_MILLIS
            assertEquals(ControlCode.OK, attach(owner, next))
            assertEquals(next, owner.frontends.registration())
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }

    @Test fun a_gone_observation_releases_only_that_lease_and_the_new_frontend_holds_it() = runTest {
        val directory = Files.createTempDirectory("owner-reattach-gone-observed")
        val gone = mutableSetOf<String>()
        val owner = DesktopControllerOwner(DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory)),
            scope = backgroundScope, observeFrontend = {
                if (it.registrationId in gone) DesktopFrontendProcessObservation.GONE else DesktopFrontendProcessObservation.SAME
            })
        val crashed = UUID.randomUUID().toString()
        val reopened = UUID.randomUUID().toString()
        try {
            assertEquals(ControlCode.OK, attach(owner, crashed))
            assertTrue(owner.frontends.captureProcessIdentity(crashed, DesktopFrontendProcessIdentity(crashed, 42, 7)))
            assertEquals(ControlCode.BUSY, attach(owner, reopened), "SAME keeps the lease")
            gone += crashed
            assertEquals(ControlCode.OK, attach(owner, reopened))
            assertEquals(reopened, owner.frontends.registration())
            // The reopened frontend now holds the lease; a third one is refused while it lives.
            assertTrue(owner.frontends.captureProcessIdentity(reopened, DesktopFrontendProcessIdentity(reopened, 43, 8)))
            assertEquals(ControlCode.BUSY, attach(owner, UUID.randomUUID().toString()))
        } finally { owner.close(); directory.toFile().deleteRecursively() }
    }
}
