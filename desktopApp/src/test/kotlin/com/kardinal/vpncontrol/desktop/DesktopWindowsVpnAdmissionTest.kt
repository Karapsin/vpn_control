package com.kardinal.vpncontrol.desktop

import kotlin.test.*

class DesktopWindowsVpnAdmissionTest {
    @Test fun mutableEmptyAncestorCannotReachAuthorization() {
        val native = Fake().apply { childNames = emptyList() }
        var authorized = false
        assertFails {
            DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) {
                authorized = true
                prepared()
            }
        }
        assertFalse(authorized)
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun linkedWitnessAndActualAncestorsRemainPinnedUntilNativeReadiness() {
        val native = Fake()
        val prepared = prepared()
        val result = DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) { sid ->
            assertEquals(SID, sid)
            assertEquals(setOf("C:\\", "C:\\ProgramData", "C:\\ProgramData\\witness"),
                native.handles.map { it.path }.toSet())
            assertTrue(native.handles.none { it.closed })
            prepared
        }
        assertSame(prepared, result)
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun failedAdmissionRetainsUnclosedHandlesForExplicitRetry() {
        val native = Fake().apply { childNames = emptyList(); rejectClose = true }
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) { error("Authorization must not be reached") }
        }
        val retained = assertNotNull(failure.retainedAdmission, "Failed closure discarded native pin ownership")
        assertTrue(native.handles.any { !it.closed })
        native.rejectClose = false
        retained.close()
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun rejectedWitnessRetainsItsHandleWhenNativeCloseFails() {
        val native = Fake().apply {
            transform = { path, info -> if (path.endsWith("witness")) info.copy(reparseTag = 1) else info }
            rejectClose = true
        }
        var authorizationReached = false
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) {
                authorizationReached = true
                prepared()
            }
        }
        assertFalse(authorizationReached, "Rejected witness reached authorization")
        val witness = native.handles.single { it.path.endsWith("witness") }
        assertFalse(witness.closed)
        val retained = assertNotNull(failure.retainedAdmission, "Failed native closure lost admission ownership")
        native.rejectClose = false
        retained.close()
        assertTrue(witness.closed, "Explicit retry lost the rejected witness handle")
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun readyChildAndUnclosedAdmissionAreBothRetainedAfterCleanupFailure() {
        val native = Fake().apply { rejectClose = true }
        val child = object : DesktopRuntimeProcess {
            override val isAlive = true
            override fun pid() = 77L
            override fun destroy() = Unit
            override fun destroyForcibly() = Unit
            override fun waitFor(timeout: Long, unit: java.util.concurrent.TimeUnit) = false
        }
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) {
                object : DesktopPreparedRuntimeProcess {
                    override fun commit(): DesktopRuntimeProcess = error("Failed admission cannot commit")
                    override fun close() { throw DesktopWindowsRuntimeFailure("OUTCOME_UNKNOWN", child) }
                }
            }
        }
        assertSame(child, failure.unresolvedRuntime)
        val retained = assertNotNull(failure.retainedAdmission, "Child ownership hid the failed admission closure")
        native.rejectClose = false
        retained.close()
        assertTrue(native.handles.all { it.closed })
    }

    @Test fun racedOrUnlinkedWitnessAndUnknownRightsCannotAuthorizePreparation() {
        val changes: List<Fake.() -> Unit> = listOf(
            { canonical = { path -> if (path.endsWith("witness")) "\\\\?\\C:\\elsewhere\\witness" else "\\\\?\\$path" } },
            { transform = { path, info -> if (path.endsWith("witness")) info.copy(attributes = 0x400) else info } },
            { transform = { path, info -> if (path == "C:\\ProgramData") info.copy(dacl = info.dacl.orEmpty() +
                WindowsInstallAce(0, 0, 0x40, "S-1-5-32-545")) else info } },
            { transform = { path, info -> if (path == "C:\\ProgramData") info.copy(owner = "S-1-5-80-1") else info } },
            { aclVolume = false },
            {
                var reads = 0
                transform = { path, info ->
                    if (path == "C:\\ProgramData" && ++reads > 1) info.copy(reparseTag = 1) else info
                }
            },
        )
        for (change in changes) {
            val native = Fake().apply(change)
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsVpnBroker.withNativeOwnerAdmission(native) { error("Unsafe witness reached authorization") }
            }
            assertEquals("PERMISSION_DENIED", failure.code)
            assertTrue(native.handles.all { it.closed })
        }
    }

    internal class Fake : WindowsAdmissionNative {
        class Handle(val path: String) : WindowsInstallNative.Handle { var closed = false }
        val handles = mutableListOf<Handle>()
        var childNames = listOf("witness")
        var transform: (String, WindowsInstallInfo) -> WindowsInstallInfo = { _, value -> value }
        var canonical: (String) -> String = { "\\\\?\\$it" }
        var aclVolume = true
        var rejectClose = false
        override fun currentSid() = SID
        override fun programData() = "C:\\ProgramData"
        override fun openDirectory(path: String) = Handle(path).also { handles += it }
        override fun inspect(handle: WindowsInstallNative.Handle): WindowsInstallInfo {
            val path = (handle as Handle).path
            return transform(path, WindowsInstallInfo(directory = true, owner = "S-1-5-18",
                dacl = listOf(WindowsInstallAce(0, 0,
                    if (path == "C:\\ProgramData") 0x116 else 0x1200a9, "S-1-5-32-545"))))
        }
        override fun persistentAcl(handle: WindowsInstallNative.Handle) = aclVolume
        override fun canonicalPath(handle: WindowsInstallNative.Handle) = canonical((handle as Handle).path)
        override fun children(path: String) = childNames
        override fun close(handle: WindowsInstallNative.Handle) {
            if (rejectClose) throw WindowsInstallNativeFailure(32)
            check(!(handle as Handle).closed)
            handle.closed = true
        }
        override fun invariantUppercase(value: String) = value.uppercase(java.util.Locale.ROOT)
        override fun openGate(path: String): WindowsInstallNative.Handle = error("VPN admission never opens installer gates")
        override fun lockShared(handle: WindowsInstallNative.Handle): Boolean = error("Unused")
        override fun readGate(handle: WindowsInstallNative.Handle): ByteArray = error("Unused")
        override fun unlockShared(handle: WindowsInstallNative.Handle) = error("Unused")
    }

    companion object {
        private const val SID = "S-1-5-21-1-2-3-1001"
        private fun prepared() = object : DesktopPreparedRuntimeProcess {
            override fun commit(): DesktopRuntimeProcess = error("Admission fixture does not commit")
            override fun close() = Unit
        }
    }
}
