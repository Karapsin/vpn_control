package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlValue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

/** Prepared source tests only; this proposal has not executed Kotlin or native APIs. */
class DesktopWindowsInputCustodyTest {
    // Actual managed C# writer output using synthetic original inputs and modeled native IDs.
    // Embedded bytes keep the eventual routine test independent of ignored runtime leaves.
    private val cSharpGolden = """{"version":1,"jobId":"11111111-2222-4333-8444-555555555555","principalSid":"S-1-5-21-11-22-33-1000","workspaceSha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","inputRootNativeId":"000000000000000000000000000000000000000000000001","inputJobNativeId":"000000000000000000000000000000000000000000000002","protectedMachineNativeId":"000000000000000000000000000000000000000000000003","protectedJobNativeId":"000000000000000000000000000000000000000000000004","workerPid":11,"workerCreationFileTime":101,"workerHelperSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","coordinatorPid":20,"coordinatorCreationFileTime":201,"coordinatorHelperSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request.json.nativeId":"00000000000000000000000000000000000000000000000a","request.json.size":366,"request.json.sha256":"a143332f8607a470229747f28e3277e8ce6f004cddc806a600bd88d45989cfc8","package.msi.nativeId":"00000000000000000000000000000000000000000000000b","package.msi.size":7,"package.msi.sha256":"32bbe378a25091502b2baf9f7258c19444e7a43ee4593b08030acd790bd66e6a","commit.json.nativeId":"00000000000000000000000000000000000000000000000c","commit.json.size":60,"commit.json.sha256":"55d1fbeb6e1bc5ba64646ccf2a4d51920ccb82e75a5b2ec800a0522a1dc9672a","worker-ready.json.nativeId":"00000000000000000000000000000000000000000000000d","worker-ready.json.size":214,"worker-ready.json.sha256":"317a71435016060fc33376daef5d237e3e8ed9ded8683cdd8091da09499d230e","worker-result.json.nativeId":"00000000000000000000000000000000000000000000000e","worker-result.json.size":73,"worker-result.json.sha256":"4f3e5d80c970c3218e6b6fc06413a7f355089a19dfedc202647f6380ee1929ff"}""".encodeToByteArray()
    private fun record() = DesktopWindowsInputCustody.decode(cSharpGolden)
    private fun values() = ControlProtocolCodec.decodeValues(cSharpGolden.decodeToString())
    private fun decode(values: Map<String, ControlValue>) =
        DesktopWindowsInputCustody.decode(ControlProtocolCodec.encodeValues(values).encodeToByteArray())
    private fun reject(frame: String) = assertFails { DesktopWindowsInputCustody.decode(frame.encodeToByteArray()) }
    private fun binding(value: DesktopWindowsInputCustody = record()) = DesktopInstallCorrelationRecord(
        DesktopInstallCorrelation("controller", "request", "operation"), value.jobId, value.workspaceSha256,
    )
    private fun receipt(value: DesktopWindowsInputCustody = record()) =
        DesktopInstallJobReceipt(value.jobId, 4, DesktopInstallJobPhase.SUCCEEDED, ControlCode.OK)

    @Test fun actualManagedCSharpBytesRoundTripExactly() {
        val value = record()
        assertContentEquals(cSharpGolden, value.encode())
        assertEquals(value, DesktopWindowsInputCustody.decode(value.encode()))
        assertEquals(29, values().size)
        assertEquals("input-custody.json", DesktopWindowsInputCustody.NAME)
        assertEquals(4096, DesktopWindowsInputCustody.MAX_BYTES)
        assertEquals(11L, value.worker.pid)
        assertEquals(101L, value.worker.creationFileTime)
        assertEquals(20L, value.coordinator.pid)
        assertEquals(201L, value.coordinator.creationFileTime)
        assertEquals(7L, value.packageFile.size)
        assertEquals(listOf("request.json", "package.msi", "commit.json", "worker-ready.json", "worker-result.json"),
            value.files.map { it.name })
        for (leaf in DesktopWindowsInputCustodyLeaf.entries) assertEquals(leaf, value.file(leaf).leaf)
    }

    @Test fun fieldOrderWhitespaceAndDecodedAsciiEscapesRemainNativeCompatible() {
        val expected = record()
        val reversed = values().entries.reversed().associate { it.key to it.value }
        assertEquals(expected, decode(reversed))
        assertEquals(expected, DesktopWindowsInputCustody.decode((" \r\n" + cSharpGolden.decodeToString() + "\t ").encodeToByteArray()))
        assertEquals(expected, DesktopWindowsInputCustody.decode(cSharpGolden.decodeToString()
            .replace("\"jobId\"", "\"job\\u0049d\"").encodeToByteArray()))
    }

    @Test fun allFiveLeavesAndAllTwentyNineFieldsAreMandatory() {
        for (key in values().keys) assertFails { decode(values() - key) }
        for (leaf in DesktopWindowsInputCustodyLeaf.entries) {
            for (suffix in listOf(".nativeId", ".size", ".sha256")) {
                val key = leaf.nameOnDisk + suffix
                assertFails { decode((values() - key) + ("foreign.json" + suffix to values().getValue(key))) }
            }
        }
    }

    @Test fun extraPathAuthorityAndForeignLeafFieldsRefuse() {
        for (key in listOf("path", "cleanupOK", "actorClosed", "foreign.json.nativeId", "terminal")) {
            assertFails { decode(values() + (key to ControlValue.Text("caller-value"))) }
        }
        assertFails { decode(values() + ("cleanupOK" to ControlValue.BooleanValue(true))) }
    }

    @Test fun duplicateAndDecodedDuplicateKeysRefuse() {
        val encoded = cSharpGolden.decodeToString()
        reject(encoded.replaceFirst("{", "{\"version\":1,"))
        reject(encoded.replaceFirst("{", "{\"vers\\u0069on\":1,"))
        reject(encoded.replaceFirst("{", "{\"request.json.size\":595,"))
    }

    @Test fun scalarTypesAreExactForEveryField() {
        for ((name, valid) in values()) {
            val invalid = if (valid is ControlValue.Text) ControlValue.IntegerValue(1) else ControlValue.Text("1")
            assertFails { decode(values() + (name to invalid)) }
            for (replacement in listOf(ControlValue.Null, ControlValue.BooleanValue(true),
                ControlValue.ArrayValue(emptyList()), ControlValue.ObjectValue(emptyMap()))) {
                assertFails { decode(values() + (name to replacement)) }
            }
        }
    }

    @Test fun wrongVersionAndNoncanonicalNumericWireNeverNormalizeIntoAdmission() {
        val encoded = cSharpGolden.decodeToString()
        for (operand in listOf("0", "2", "01", "1.0", "1e0", "+1", "-1", "true", "null", "\"1\"")) {
            reject(encoded.replace("\"version\":1", "\"version\":$operand"))
        }
        for (operand in listOf("011", "11.0", "11e0", "+11", "-11", "NaN", "Infinity")) {
            reject(encoded.replace("\"workerPid\":11", "\"workerPid\":$operand"))
        }
        assertFails { decode(values() + ("version" to ControlValue.DecimalValue(1.0))) }
    }

    @Test fun pidNativeBirthAndSizeBoundsRefuse() {
        for (key in listOf("workerPid", "coordinatorPid")) {
            for (value in listOf(0L, -1L, 0x100000000L, Long.MAX_VALUE)) {
                assertFails { decode(values() + (key to ControlValue.IntegerValue(value))) }
            }
        }
        for (key in listOf("workerCreationFileTime", "coordinatorCreationFileTime") +
            DesktopWindowsInputCustodyLeaf.entries.map { it.nameOnDisk + ".size" }) {
            for (value in listOf(0L, -1L)) assertFails { decode(values() + (key to ControlValue.IntegerValue(value))) }
        }
        reject(cSharpGolden.decodeToString().replace("\"workerCreationFileTime\":101", "\"workerCreationFileTime\":9223372036854775808"))
    }

    @Test fun nativeBirthAndPidRemainFullWidthIntegers() {
        val value = record().copy(
            worker = record().worker.copy(pid = 0xffffffffL, creationFileTime = Long.MAX_VALUE),
            packageFile = record().packageFile.copy(size = Long.MAX_VALUE),
        )
        assertEquals(value, DesktopWindowsInputCustody.decode(value.encode()))
        assertNotEquals(value, value.copy(worker = value.worker.copy(creationFileTime = Long.MAX_VALUE - 1)))
    }

    @Test fun fixedNativeIdsRequireTwentyFourCanonicalBytes() {
        val nativeKeys = values().keys.filter { it.endsWith("NativeId") || it.endsWith(".nativeId") }
        assertEquals(9, nativeKeys.size)
        for (key in nativeKeys) {
            for (identity in listOf("", "a".repeat(47), "a".repeat(49), "A".repeat(48),
                "g".repeat(48), "０".repeat(48), "0".repeat(48), "a".repeat(47) + "\n")) {
                assertFails { decode(values() + (key to ControlValue.Text(identity))) }
            }
        }
    }

    @Test fun allOriginalObjectIdsAreDistinctIncludingDirectories() {
        val nativeKeys = values().keys.filter { it.endsWith("NativeId") || it.endsWith(".nativeId") }
        for (first in nativeKeys.indices) for (second in first + 1 until nativeKeys.size) {
            assertFails { decode(values() + (nativeKeys[second] to values().getValue(nativeKeys[first]))) }
        }
    }

    @Test fun sha256GrammarIsExactForWorkspaceActorsAndLeaves() {
        val hashKeys = values().keys.filter { it.endsWith("Sha256") || it.endsWith(".sha256") }
        assertEquals(8, hashKeys.size)
        for (key in hashKeys) {
            for (digest in listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64),
                "０".repeat(64), "a".repeat(63) + "\n")) {
                assertFails { decode(values() + (key to ControlValue.Text(digest))) }
            }
        }
    }

    @Test fun workerAndCoordinatorPreserveSameHelperAndDistinctProcessInvariant() {
        val value = record()
        assertFails { value.copy(coordinator = value.coordinator.copy(pid = value.worker.pid)) }
        assertFails { value.copy(coordinator = value.coordinator.copy(helperSha256 = "c".repeat(64))) }
        assertFails { decode(values() + ("coordinatorHelperSha256" to ControlValue.Text("c".repeat(64)))) }
    }

    @Test fun canonicalJobAndSidGrammarMatchTheManagedProducer() {
        val value = record()
        for (job in listOf("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", "", "{${value.jobId}}", "../" + value.jobId, value.jobId + "\n")) {
            assertFails { value.copy(jobId = job) }
        }
        for (sid in listOf("", "S-1-5", "s-1-5-1", "S-1-05-1", "S-1-5-01", "S-1-5-4294967296",
            "S-1-281474976710656-1", "S-1-５-1", "S-1-5-" + List(16) { "1" }.joinToString("-"))) {
            assertFails { value.copy(principalSid = sid) }
        }
        assertEquals("S-1-281474976710655-4294967295",
            value.copy(principalSid = "S-1-281474976710655-4294967295").principalSid)
    }

    @Test fun byteCapIncludesUtf8AndRetainsExactBoundary() {
        val padding = ByteArray(DesktopWindowsInputCustody.MAX_BYTES - cSharpGolden.size) { 32 }
        assertEquals(record(), DesktopWindowsInputCustody.decode(cSharpGolden + padding))
        assertFails { DesktopWindowsInputCustody.decode(cSharpGolden + padding + byteArrayOf(32)) }
        assertFails { DesktopWindowsInputCustody.decode(("{\"unknown\":\"" + "東".repeat(2000) + "\"}").encodeToByteArray()) }
    }

    @Test fun invalidUtf8RawControlSurrogateAndTrailingRecordsRefuse() {
        assertFails { DesktopWindowsInputCustody.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
        reject(cSharpGolden.decodeToString() + "{}")
        reject(cSharpGolden.decodeToString().replace(record().jobId, record().jobId + "\n"))
        reject(cSharpGolden.decodeToString().replace(record().workspaceSha256, "\\ud800"))
        reject("[]")
        reject("{}")
    }

    @Test fun allFivePositionsRemainFixedAndRecordViewsCannotMutateCustody() {
        val value = record()
        assertFails { value.copy(request = value.packageFile) }
        assertFails { value.copy(commit = value.workerResult) }
        val view = value.files as? MutableList<DesktopWindowsInputCustodyFile>
        if (view != null) runCatching { view[0] = value.packageFile }
        assertEquals(DesktopWindowsInputCustodyLeaf.REQUEST, value.file(DesktopWindowsInputCustodyLeaf.REQUEST).leaf)
        assertEquals(value, record())
    }

    @Test fun exactSuccessfulMachineJobSidAndWorkspaceDataBind() {
        val value = record()
        value.requireBinding(binding(value), receipt(value), value.principalSid, value.workspaceSha256)
        value.requireSame(record())
    }

    @Test fun foreignJobSidWorkspaceAndAuthorityRefuseBinding() {
        val value = record()
        val otherJob = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        val bound = binding(value)
        assertFails { value.requireBinding(bound.copy(jobId = otherJob), receipt(value), value.principalSid, value.workspaceSha256) }
        assertFails { value.requireBinding(bound, receipt(value).copy(jobId = otherJob), value.principalSid, value.workspaceSha256) }
        assertFails { value.requireBinding(bound, receipt(value), "S-1-5-21-11-22-33-1001", value.workspaceSha256) }
        assertFails { value.requireBinding(bound.copy(workspaceKey = "c".repeat(64)), receipt(value), value.principalSid, value.workspaceSha256) }
        assertFails { value.requireBinding(bound, receipt(value), value.principalSid, "c".repeat(64)) }
        assertFails { value.requireBinding(bound.copy(receiptAuthority = DesktopInstallReceiptAuthority.MACOS_USER_LOCAL),
            receipt(value), value.principalSid, value.workspaceSha256) }
    }

    @Test fun failedCancelledAndNonterminalReceiptsNeverBindAsSuccess() {
        val value = record()
        for (receipt in listOf(
            receipt(value).copy(phase = DesktopInstallJobPhase.FAILED, code = ControlCode.RUNTIME_FAILED),
            receipt(value).copy(phase = DesktopInstallJobPhase.CANCELLED, code = ControlCode.CANCELLED),
            receipt(value).copy(phase = DesktopInstallJobPhase.INSTALLING),
            receipt(value).copy(phase = DesktopInstallJobPhase.WAITING_FOR_EXIT),
        )) assertFails { value.requireBinding(binding(value), receipt, value.principalSid, value.workspaceSha256) }
    }

    @Test fun sameRecordComparisonIncludesEveryOriginalAndActorField() {
        val value = record()
        for (foreign in listOf(
            value.copy(workspaceSha256 = "c".repeat(64)),
            value.copy(inputRootNativeId = "f".repeat(48)),
            value.copy(protectedJobNativeId = "f".repeat(48)),
            value.copy(worker = value.worker.copy(creationFileTime = value.worker.creationFileTime + 1)),
            value.copy(request = value.request.copy(sha256 = "c".repeat(64))),
            value.copy(packageFile = value.packageFile.copy(size = value.packageFile.size + 1)),
        )) assertFails { value.requireSame(foreign) }
    }

    @Test fun terminalFiveFieldReceiptIsNeverCustody() {
        assertFails { DesktopWindowsInputCustody.decode(receipt().encode()) }
    }

    @Test fun metadataStringRepresentationsRedactIdentities() {
        val value = record()
        for (rendered in listOf(value.toString(), value.worker.toString(), value.coordinator.toString()) +
            value.files.map { it.toString() }) {
            for (privateValue in listOf(value.jobId, value.principalSid, value.workspaceSha256, value.inputJobNativeId,
                value.worker.helperSha256, value.request.sha256)) assertFalse(rendered.contains(privateValue))
        }
    }
}
