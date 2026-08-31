package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.HomeSshRouteSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class HomeSshRouteLogicTest {
    @Test
    fun subscriptionRoutePrefersActiveSessionRegardlessOfHomeSetting() {
        assertEquals(
            SubscriptionDownloadRoutePlan(SubscriptionDownloadRoute.ACTIVE_SESSION),
            SubscriptionDownloadRouteLogic.plan(true, false),
        )
        assertEquals(
            SubscriptionDownloadRoutePlan(
                SubscriptionDownloadRoute.ACTIVE_SESSION,
                SubscriptionDownloadRoute.HOME_RELAY,
            ),
            SubscriptionDownloadRouteLogic.plan(true, true),
        )
    }

    @Test
    fun inactiveRouteUsesHomeWhenEnabledAndDirectOtherwise() {
        assertEquals(
            SubscriptionDownloadRoute.HOME_RELAY,
            SubscriptionDownloadRouteLogic.plan(false, true).primary,
        )
        assertEquals(
            SubscriptionDownloadRoute.DIRECT,
            SubscriptionDownloadRouteLogic.plan(false, false).primary,
        )
    }

    @Test
    fun activeRuntimeWithoutManagementPortNeverFallsBackToDirect() {
        assertEquals(
            SubscriptionDownloadRoutePlan(SubscriptionDownloadRoute.ACTIVE_SESSION),
            SubscriptionDownloadRouteLogic.plan(true, false),
        )
        assertEquals(
            SubscriptionDownloadRoutePlan(
                SubscriptionDownloadRoute.ACTIVE_SESSION,
                SubscriptionDownloadRoute.HOME_RELAY,
            ),
            SubscriptionDownloadRouteLogic.plan(true, true),
        )
    }

    @Test
    fun hostKeyScanLineIsNormalizedAndRequired() {
        val validated = HomeSshRouteLogic.validate(
            HomeSshRouteSettings(
                enabled = true,
                host = "ssh.example",
                user = "vpn",
                hostKeys = listOf("[ssh.example]:228 ssh-ed25519 $TEST_HOST_KEY comment"),
            ),
            credentialAvailable = true,
        ).getOrThrow()

        assertEquals(listOf("ssh-ed25519 $TEST_HOST_KEY"), validated.hostKeys)
        assertTrue(HomeSshRouteLogic.validate(validated, credentialAvailable = false).isFailure)
    }

    @Test
    fun invalidHostKeyLineIsRejectedInsteadOfSilentlyDropped() {
        val result = HomeSshRouteLogic.validate(
            HomeSshRouteSettings(
                enabled = true,
                host = "ssh.example",
                user = "vpn",
                hostKeys = listOf("ssh-ed25519 not-base64!"),
            ),
            credentialAvailable = true,
        )

        assertTrue(result.isFailure)
    }

    private companion object {
        const val TEST_HOST_KEY =
            "AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"
    }
}
