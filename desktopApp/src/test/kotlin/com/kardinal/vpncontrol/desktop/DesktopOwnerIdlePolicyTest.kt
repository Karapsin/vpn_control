package com.kardinal.vpncontrol.desktop

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopOwnerIdlePolicyTest {
    @Test
    fun activityAndBackgroundWorkRestartTheFullIdleWindow() {
        var now = 0L
        val policy = DesktopOwnerIdlePolicy(false, { now })
        now = 29_999
        assertFalse(policy.shouldExit(false))
        policy.activity()
        now = 30_000
        assertFalse(policy.shouldExit(false))
        now = 90_000
        assertFalse(policy.shouldExit(true))
        now = 119_999
        assertFalse(policy.shouldExit(false))
        now = 120_000
        assertTrue(policy.shouldExit(false))
    }

    @Test
    fun serviceDoesNotExitWhenIdle() {
        var now = 0L
        val policy = DesktopOwnerIdlePolicy(true, { now })
        now = 1_000_000
        assertFalse(policy.shouldExit(false))
    }
}
