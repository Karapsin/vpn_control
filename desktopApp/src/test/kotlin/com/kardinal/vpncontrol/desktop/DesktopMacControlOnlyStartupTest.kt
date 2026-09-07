package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopMacControlOnlyStartupTest {
    @Test fun clearStatusKeepsNormalStartupAndPendingStatusRetainsLeaseUntilClientExit() {
        for (pending in listOf(false, true)) {
            val fake = DesktopMacInstallAdmissionTest.Fake().apply { bytes[8] = if (pending) 1 else 0 }
            var controlOnly = false
            var release: (() -> Unit)? = null
            val args = listOf("--json", "status")
            DesktopMacProcessAdmission.install(mac = true, executable = { fake.currentExecutable() },
                enter = { path, allow, callback -> DesktopMacInstallAdmission.enter(path, fake,
                    roots = DesktopMacInstallAdmissionTest.ROOTS, allowPendingControl = allow, onPendingControl = callback) },
                allowPendingControl = DesktopWindowsControlOnlyStartup.allowsPending(args),
                onPendingControl = { controlOnly = true }, retainUntilExit = { release = it })
            assertEquals(pending, controlOnly)
            assertTrue(fake.closed.isEmpty())
            if (controlOnly) {
                var requests = 0
                assertEquals(2, DesktopWindowsControlOnlyStartup.execute(args.toTypedArray(), {}, {
                    requests++; DesktopCliResponse.failure("UNAVAILABLE", 2)
                }))
                assertEquals(1, requests)
                assertTrue(fake.closed.isEmpty(), "Existing-owner-only client must retain admission through response")
            }
            release!!.invoke()
            assertEquals(fake.paths.size, fake.closed.size)
        }
    }

    @Test fun pendingGateRejectsBootstrapMutationAndBlockingWaitBeforeStartup() {
        for (args in listOf(emptyList(), listOf("serve"), listOf("on"), listOf("updates", "install"),
            listOf("operations", "wait", "operation"))) {
            val fake = DesktopMacInstallAdmissionTest.Fake().apply { bytes[8] = 1 }
            assertEquals("BUSY", assertFails {
                DesktopMacProcessAdmission.install(mac = true, executable = { fake.currentExecutable() },
                    enter = { path, allow, callback -> DesktopMacInstallAdmission.enter(path, fake,
                        roots = DesktopMacInstallAdmissionTest.ROOTS, allowPendingControl = allow, onPendingControl = callback) },
                    allowPendingControl = DesktopWindowsControlOnlyStartup.allowsPending(args),
                    onPendingControl = { error("Unapproved control role") }, retainUntilExit = { error("Admission failed") })
            }.message)
            assertEquals(fake.paths.size, fake.closed.size)
        }
        assertTrue(DesktopWindowsControlOnlyStartup.isBlockingWait(listOf("operations", "wait", "operation")))
    }
}
