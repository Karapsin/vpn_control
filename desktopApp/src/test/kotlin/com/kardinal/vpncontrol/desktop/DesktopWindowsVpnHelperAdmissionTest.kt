package com.kardinal.vpncontrol.desktop

import com.sun.jna.Pointer
import com.sun.jna.platform.win32.WinNT
import kotlinx.serialization.json.*
import kotlin.test.*

class DesktopWindowsVpnHelperAdmissionTest {
    @Test fun shortOwnerAliasPinsTheQueriedLeafBeforeCanonicalAncestry() {
        val fake = Fake().apply {
            image = SHORT_IMAGE
            admission.canonicalTransform = { if (it == SHORT_IMAGE) OWNER_IMAGE else it }
            identityTransform = { if (it == SHORT_IMAGE) OWNER_IMAGE else it }
            onOpen = { path ->
                if (path != SHORT_IMAGE) {
                    assertTrue(admission.handles.first().path == SHORT_IMAGE && !admission.handles.first().closed,
                        "The original queried leaf must remain pinned before every canonical ancestry open")
                }
            }
        }
        val lease = DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake)
        assertEquals(SHORT_IMAGE, fake.admission.handles.first().path)
        assertTrue(fake.admission.handles.any { it.path == OWNER_IMAGE })
        assertEquals(HELPER_PATH, lease.executable)
        val original = fake.admission.handles.first()
        fake.admission.closeFailure = fake.admission.handles.single { it.path == HELPER_PATH }
        assertFailsWith<WindowsInstallNativeFailure> { lease.close() }
        assertFalse(original.closed, "A failed dependent close must retain the original queried leaf")
        assertTrue(fake.admission.handles.any { it.gate && !it.closed })
        lease.close()
        assertTrue(fake.admission.handles.all { it.closed })
    }

    @Test fun canonicalOwnerMustMatchTheRetainedQueriedLeaf() {
        for (canonical in listOf(OWNER_IMAGE, "C:\\Apps\\VPN\\java.exe")) {
            val fake = Fake().apply {
                image = SHORT_IMAGE
                admission.canonicalTransform = { if (it == SHORT_IMAGE) canonical else it }
                identityTransform = { if (it == SHORT_IMAGE) "changed-physical-object" else it }
            }
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertEquals(SHORT_IMAGE, fake.admission.handles.firstOrNull()?.path,
                "Reject only after retaining and inspecting the actual queried file")
            assertFalse(fake.admission.handles.any { it.path == HELPER_PATH })
            assertTrue(fake.admission.handles.all { it.closed })
        }
    }

    @Test fun actualProducerManifestAdmitsExactlyItsCapturedRuntimeAndImage() {
        fun resource(name: String): ByteArray = requireNotNull(javaClass.getResourceAsStream("/$name")).use { it.readBytes() }
        val document = resource("windows-vpn-helper-producer-fixture.json")
        val image = resource("windows-vpn-helper-producer-image.bin")
        val runtime = resource("windows-vpn-helper-producer-runtime.bin")
        val runtimeDigest = java.security.MessageDigest.getInstance("SHA-256").digest(runtime)
            .joinToString("") { "%02x".format(it) }
        val fake = Fake().apply {
            manifest = document
            observed = DesktopWindowsVpnHelperPe.inspect(image.size.toLong(), DesktopWindowsVpnHelperAdmission.MAX_HELPER_BYTES) {
                offset, count -> image.copyOfRange(offset.toInt(), offset.toInt() + count)
            }
        }
        DesktopWindowsVpnHelperAdmission.retain(runtimeDigest, runtime.size.toLong(), fake).use { lease ->
            assertEquals(HELPER_PATH, lease.executable)
            assertEquals(listOf(PIPE, "123", "456", SID, runtimeDigest)
                .joinToString(" ", transform = ::windowsInstallArgument), lease.parameters(PIPE))
        }
        assertTrue(fake.admission.handles.all { it.closed })
    }

    @Test fun actualNativeIdentitySuppliesTheOnlyHelperPathAndFiveArguments() {
        val fake = Fake()
        val previous = System.getProperty("vpn.control.appDir")
        System.setProperty("vpn.control.appDir", "C:\\attacker")
        try {
            DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake).use { lease ->
                assertEquals(HELPER_PATH, lease.executable)
                assertEquals(123L, lease.owner.processId)
                assertEquals(456L, lease.owner.creationFileTime)
                assertEquals(SID, lease.owner.sid)
                assertEquals(listOf(PIPE, "123", "456", SID, RUNTIME).joinToString(" ", transform = ::windowsInstallArgument),
                    lease.parameters(PIPE))
                assertTrue(fake.admission.handles.all { !it.closed })
                assertEquals(2, fake.processReads, "A fresh value instance must compare native fields, not object references")
            }
            assertTrue(fake.admission.handles.all { it.closed })
            assertTrue(fake.adapterClosed)
        } finally {
            if (previous == null) System.clearProperty("vpn.control.appDir") else System.setProperty("vpn.control.appDir", previous)
        }
    }

    @Test fun jvmImageAndNativeGenerationMismatchNeverAdmitAHelper() {
        for (fake in listOf(Fake().apply { image = "C:\\Apps\\VPN\\java.exe" },
            Fake().apply { ownerAfterFirstRead = owner(created = 457) },
            Fake().apply { ownerAfterFirstRead = owner(pid = 124) },
            Fake().apply { ownerAfterFirstRead = owner(sid = "S-1-5-21-1-2-3-1002") },
            Fake().apply { machine = 0xaa64 })) {
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertTrue(fake.admission.handles.all { it.closed })
            assertTrue(fake.adapterClosed)
        }
    }

    @Test fun helperAndManifestMustRemainLinkedRegularPrivateObjects() {
        val hostile: List<(WindowsInstallInfo) -> WindowsInstallInfo> = listOf(
            { it.copy(owner = "S-1-5-21-1-2-3-1002") }, { it.copy(dacl = null) },
            { it.copy(links = 2) }, { it.copy(attributes = 0x400) }, { it.copy(reparseTag = 1) },
            { it.copy(disk = false) }, { it.copy(directory = true) },
            { it.copy(dacl = it.dacl.orEmpty() + WindowsInstallAce(0, 0, 0x40000000, "S-1-1-0")) },
        )
        for (leaf in listOf("vpn-control-vpn-broker.exe", "native-helpers.json")) for (change in hostile) {
            val fake = Fake().apply { transform = { path, info -> if (path.endsWith(leaf)) change(info) else info } }
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertTrue(fake.admission.handles.all { it.closed })
        }
        val linked = Fake().apply {
            admission.canonicalTransform = { if (it == HELPER_PATH) "C:\\elsewhere\\vpn-control-vpn-broker.exe" else it }
        }
        assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, linked) }
        assertTrue(linked.admission.handles.all { it.closed })
    }

    @Test fun manifestRuntimeIdentityAndRetainedImageBytesMustAgree() {
        val fakeCases = listOf(
            Fake().apply { manifest = manifest().replace(RUNTIME, "d".repeat(64)).encodeToByteArray() },
            Fake().apply { manifest = manifest().replace("\"runtimeSizeBytes\":1024", "\"runtimeSizeBytes\":1025").encodeToByteArray() },
            Fake().apply { observed = observed.copy(sha256 = "e".repeat(64)) },
            Fake().apply { observed = observed.copy(size = 4097) },
            Fake().apply { observed = observed.copy(machine = 0xaa64) },
            Fake().apply { observed = observed.copy(clrHeader = true) },
            Fake().apply { observed = observed.copy(dependentLoadFlags = 0) },
        )
        for (fake in fakeCases) {
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertTrue(fake.admission.handles.all { it.closed })
        }
    }

    @Test fun boundedManifestRejectsDuplicateKeysWrongScalarTypesAndInvalidUtf8() {
        val documents = listOf(
            "", "x".repeat(65537),
            manifest().replace("\"schemaVersion\":1", "\"schemaVersion\":0,\"schemaVersion\":1"),
            manifest().replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
            manifest().replace("\"runtimeSizeBytes\":1024", "\"runtimeSizeBytes\":\"1024\""),
            manifest().replace("\"clrHeader\":false", "\"clrHeader\":\"false\""),
            manifest().replace("\"sizeBytes\":4096", "\"sizeBytes\":67108865"),
        ).map(String::encodeToByteArray) + byteArrayOf(0xc3.toByte(), 0x28)
        for (document in documents) {
            val fake = Fake().apply { manifest = document }
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertTrue(fake.admission.handles.all { it.closed })
        }
    }

    @Test fun runtimeAuthorityRequiresTheExactProducerRecord() {
        val document = Json.parseToJsonElement(manifest()).jsonObject
        val authority = document.getValue("runtimeAuthority").jsonObject
        val invalidAuthorities = listOf(
            JsonNull,
            JsonObject(authority - "authoritySourceSha256"),
            JsonObject(authority + ("authoritySourceSha256" to JsonPrimitive("not-a-digest"))),
            JsonObject(authority + ("authoritySourceSha256" to JsonPrimitive(true))),
            JsonObject(authority + ("runtimeSizeBytes" to JsonPrimitive(true))),
            JsonObject(authority + ("unexpected" to JsonPrimitive(1))),
        )
        val documents = invalidAuthorities.map {
            JsonObject(document + ("runtimeAuthority" to it)).toString().encodeToByteArray()
        } + JsonObject(document - "runtimeAuthority").toString().encodeToByteArray()
        for (bytes in documents) {
            val fake = Fake().apply { manifest = bytes }
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertTrue(fake.admission.handles.all { it.closed })
        }
    }

    @Test fun pendingOrCorruptProtectedGateRejectsBeforeHelperCapture() {
        for (fake in listOf(Fake().apply { admission.bytes[8] = 1 },
            Fake().apply { admission.bytes = ByteArray(16) },
            Fake().apply { admission.lockAvailable = false })) {
            assertFails { DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake) }
            assertFalse(fake.admission.handles.any { it.path == HELPER_PATH })
            assertTrue(fake.admission.handles.all { it.closed })
        }
    }

    @Test fun peerComesFromTheRetainedProcessAndMustMatchThePinnedHelper() {
        val fake = Fake()
        val lease = DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake)
        val process = WinNT.HANDLE(Pointer.createConstant(901))
        lease.verifyStartedProcess(process)
        assertSame(process, fake.peerHandle)
        fake.peerIdentityChanged = true
        assertFails { lease.verifyStartedProcess(process) }
        assertTrue(fake.admission.handles.all { !it.closed }, "Failed peer verification leaves every input owned for abort/close")
        lease.close()
        assertTrue(fake.admission.handles.all { it.closed })
    }

    @Test fun helperCloseFailureRetainsTheInstallationGateUntilRetry() {
        val fake = Fake()
        val lease = DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake)
        val helper = fake.admission.handles.single { it.path == HELPER_PATH }
        fake.admission.closeFailure = helper
        assertFailsWith<WindowsInstallNativeFailure> { lease.close() }
        assertFalse(helper.closed)
        assertTrue(fake.admission.handles.any { it.gate && !it.closed })
        assertFalse(fake.adapterClosed)
        lease.close()
        lease.close()
        assertTrue(fake.admission.handles.all { it.closed })
        assertTrue(fake.adapterClosed)
    }

    @Test fun rejectedExistingAdmissionWitnessStaysOwnedAfterRepeatedCloseFailure() {
        val fake = Fake().apply {
            transform = { path, info -> if (path == "C:\\ProgramData") info.copy(
                dacl = info.dacl.orEmpty() + WindowsInstallAce(0, 0, 0x116, "S-1-5-32-545")) else info }
            admission.canonicalTransform = { if (it.endsWith("witness")) "C:\\elsewhere\\witness" else it }
            witnessCloseFailures = 2
        }
        val failure = assertFailsWith<DesktopWindowsAdmissionCleanupFailure> {
            DesktopWindowsVpnHelperAdmission.retain(RUNTIME, 1024, fake)
        }
        val witness = fake.admission.handles.single { it.path.endsWith("witness") }
        assertFalse(witness.closed)
        assertFalse(fake.adapterClosed)
        failure.retained.close()
        assertTrue(fake.admission.handles.all { it.closed })
        assertTrue(fake.adapterClosed)
    }

    private class Fake(val admission: DesktopWindowsInstallAdmissionTest.Fake = DesktopWindowsInstallAdmissionTest.Fake()) :
        WindowsVpnHelperNative, WindowsAdmissionNative by admission {
        var image = "C:\\Apps\\VPN\\vpn-control-cli.exe"
        var manifest = manifest().encodeToByteArray()
        var machine = 0x8664
        var observed = DesktopWindowsPinnedExecutable(HELPER_DIGEST, 4096, 0x8664, false, 0x800)
        var ownerAfterFirstRead: DesktopWindowsRuntimeResourceNativeOwner? = null
        var processReads = 0
        var adapterClosed = false
        var peerHandle: WinNT.HANDLE? = null
        var peerIdentityChanged = false
        var witnessCloseFailures = 0
        var identityTransform: (String) -> String = { it }
        var onOpen: (String) -> Unit = {}
        var transform: (String, WindowsInstallInfo) -> WindowsInstallInfo = { _, value -> value }
        init {
            admission.inspectTransform = { path, info ->
                transform(path, if (path.endsWith("native-helpers.json")) info.copy(directory = false, size = manifest.size.toLong()) else info)
            }
        }
        override fun currentProcess(): DesktopWindowsNativeOwnerImage {
            processReads++
            return DesktopWindowsNativeOwnerImage(image, if (processReads > 1) ownerAfterFirstRead ?: owner() else owner())
        }
        override fun processImage(process: WinNT.HANDLE): String { peerHandle = process; return HELPER_PATH }
        override fun openDirectory(path: String): WindowsInstallNative.Handle {
            onOpen(path)
            return admission.openDirectory(path)
        }
        override fun read(handle: WindowsInstallNative.Handle, limit: Int) = manifest.copyOf()
        override fun machine(handle: WindowsInstallNative.Handle) = machine
        override fun identity(handle: WindowsInstallNative.Handle) =
            identityTransform((handle as DesktopWindowsInstallAdmissionTest.Fake.Handle).path) +
                if (peerIdentityChanged) "-changed" else ""
        override fun executable(handle: WindowsInstallNative.Handle, maximum: Long) = observed
        override fun close(handle: WindowsInstallNative.Handle) {
            if ((handle as DesktopWindowsInstallAdmissionTest.Fake.Handle).path.endsWith("witness") && witnessCloseFailures > 0) {
                witnessCloseFailures--; throw WindowsInstallNativeFailure(32)
            }
            admission.close(handle)
        }
        override fun close() { adapterClosed = true }
    }

    companion object {
        private const val SID = "S-1-5-21-1-2-3-1001"
        private const val PIPE = "vpn-control-vpn-00000000-0000-0000-0000-000000000041"
        private const val OWNER_IMAGE = "C:\\Apps\\VPN\\vpn-control-cli.exe"
        private const val SHORT_IMAGE = "C:\\Apps\\VPN\\vpn-co~1.exe"
        private const val HELPER_PATH = "C:\\Apps\\VPN\\app\\native\\windows-amd64\\vpn-control-vpn-broker.exe"
        private val RUNTIME = "a".repeat(64)
        private val HELPER_DIGEST = "b".repeat(64)
        private fun owner(pid: Long = 123, created: Long = 456, sid: String = SID) =
            DesktopWindowsRuntimeResourceNativeOwner(pid, created, sid)
        private fun manifest(): String = buildJsonObject {
            put("schemaVersion", 1)
            put("policySha256", "c".repeat(64))
            putJsonObject("runtimeAuthority") {
                put("runtimeSha256", RUNTIME)
                put("runtimeSizeBytes", 1024)
                put("authoritySourceSha256", "f".repeat(64))
            }
            putJsonArray("artifacts") {
                add(buildJsonObject { put("name", "vpn-control-install-helper.exe") })
                add(buildJsonObject {
                    put("name", "vpn-control-vpn-broker.exe")
                    put("machine", "AMD64"); put("clrHeader", false); put("dependentLoadFlags", 2048)
                    putJsonArray("operations") { add("authenticated-runtime-channel") }
                    put("sizeBytes", 4096); put("sha256", HELPER_DIGEST)
                })
            }
        }.toString()
    }
}
