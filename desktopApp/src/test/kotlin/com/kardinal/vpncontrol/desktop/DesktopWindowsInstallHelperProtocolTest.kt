package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopWindowsInstallHelperProtocolTest {
    private val job = "00000000-0000-0000-0000-00000000000a"
    private val sid = "S-1-5-21-10-20-30-1001"
    private val created = 134_332_558_909_139_351L
    private fun ready() = DesktopWindowsInstallWorkerReady(job, 912, created, sid, "a".repeat(64))

    @Test fun bothFixedRolesCarryOnlyOpaqueCanonicalIdentityArguments() {
        for (role in DesktopWindowsInstallHelperInvocation.Role.entries) {
            val invocation = DesktopWindowsInstallHelperInvocation(role, job, 912, created)
            assertEquals(listOf(role.argument, job, "912", created.toString()), invocation.arguments())
            val decoded = DesktopWindowsInstallHelperInvocation.parse(invocation.arguments())
            assertEquals(role, decoded.role)
            assertEquals(job, decoded.jobId)
            assertEquals(912L, decoded.ownerPid)
            assertEquals(created, decoded.ownerCreationFileTime)
        }
    }

    @Test fun commandOrPathOperandsNeverReachTheFixedHelper() {
        val valid = DesktopWindowsInstallHelperInvocation(
            DesktopWindowsInstallHelperInvocation.Role.COORDINATOR, job, 912, created).arguments()
        for (operation in listOf("-Command", "powershell.exe", "C:\\helper.exe", "INSTALL-COORDINATOR", "install-coordinator\u0000")) {
            assertFails { DesktopWindowsInstallHelperInvocation.parse(valid.toMutableList().also { it[0] = operation }) }
        }
        for (identity in listOf(job.uppercase(), "$job;whoami", "../$job", "C:\\$job", "")) {
            assertFails { DesktopWindowsInstallHelperInvocation.parse(valid.toMutableList().also { it[1] = identity }) }
        }
        assertFails { DesktopWindowsInstallHelperInvocation.parse(valid + "C:\\package.msi") }
        assertFails { DesktopWindowsInstallHelperInvocation.parse(valid.dropLast(1)) }
    }

    @Test fun nativeGenerationNeverRoundsThroughFloatingPointOrMilliseconds() {
        val input = DesktopWindowsInstallHelperInvocation(DesktopWindowsInstallHelperInvocation.Role.ORIGINAL_USER,
            job, 0xffffffffL, Long.MAX_VALUE)
        val decoded = DesktopWindowsInstallHelperInvocation.parse(input.arguments())
        assertEquals(Long.MAX_VALUE, decoded.ownerCreationFileTime)
        assertEquals(0xffffffffL, decoded.ownerPid)
        val current = ready()
        assertEquals(current, DesktopWindowsInstallWorkerReady.decode(current.encode()))
        assertNotEquals(current, current.copy(creationFileTime = current.creationFileTime + 1))
    }

    @Test fun numericArgumentsRejectAlternateRepresentationsAndOverflow() {
        val valid = DesktopWindowsInstallHelperInvocation(DesktopWindowsInstallHelperInvocation.Role.ORIGINAL_USER,
            job, 912, created).arguments()
        for (text in listOf("", "0", "01", "-1", "+1", " 1", "1 ", "１", "1e2", "1.0", "9223372036854775808")) {
            for (index in listOf(2, 3)) {
                assertFails { DesktopWindowsInstallHelperInvocation.parse(valid.toMutableList().also { it[index] = text }) }
            }
        }
        assertFails { DesktopWindowsInstallHelperInvocation.parse(valid.toMutableList().also { it[2] = "4294967296" }) }
    }

    @Test fun readinessRejectsUnknownDuplicateWrongTypeAndOlderGenerationFields() {
        val encoded = ready().encode().decodeToString()
        fun reject(text: String) = assertFails { DesktopWindowsInstallWorkerReady.decode(text.encodeToByteArray()) }
        reject(encoded.replaceFirst("{", "{\"extra\":1,"))
        reject(encoded.replaceFirst("{", "{\"pid\":912,"))
        reject(encoded.replace("\"version\":2", "\"version\":1"))
        reject(encoded.replace("\"pid\":912", "\"pid\":\"912\""))
        reject(encoded.replace("\"creationFileTime\"", "\"startedAtEpochMillis\""))
        reject(encoded.replace("\"creationFileTime\":$created", "\"creationFileTime\":0"))
        assertFails { DesktopWindowsInstallWorkerReady.decode(ByteArray(4097)) }
        assertFails { DesktopWindowsInstallWorkerReady.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
    }

    @Test fun readinessSidAndDigestUseCanonicalBoundedAscii() {
        for (principal in listOf("S-1-５-21-1", "s-1-5-21", "S-1-05-21", "S-1-5-021", "S-1-5-4294967296",
            "S-1-281474976710656-1", "S-1-5-" + List(16) { "1" }.joinToString("-"), "S-1-5")) {
            assertFails { ready().copy(principalSid = principal) }
        }
        assertEquals("S-1-281474976710655-4294967295",
            ready().copy(principalSid = "S-1-281474976710655-4294967295").principalSid)
        for (digest in listOf("a".repeat(63), "A".repeat(64), "０".repeat(64), "a".repeat(63) + "\n")) {
            assertFails { ready().copy(helperSha256 = digest) }
        }
    }

    @Test fun retainedMetadataHasRedactedStringRepresentations() {
        val invocation = DesktopWindowsInstallHelperInvocation(DesktopWindowsInstallHelperInvocation.Role.ORIGINAL_USER,
            job, 912, created)
        for (text in listOf(invocation.toString(), ready().toString())) {
            for (privateValue in listOf(job, sid, created.toString(), "a".repeat(64))) assertFalse(text.contains(privateValue))
        }
    }

    @Test fun actualFixedNativeCodecAcceptsKotlinBytesAndRejectsMalformedRecordsWithoutNativeEffects() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val directory = Files.createTempDirectory("vpn-install-helper-protocol-")
        val files = listOf("windows-install-native.cs", "windows-install-helper-protocol.cs").map { name ->
            directory.resolve(name).also { path ->
                javaClass.getResourceAsStream("/$name")!!.use { Files.copy(it, path) }
            }
        }
        try {
            val request = DesktopWindowsInstallRequest(job, sid, 912, 1_788_800_000_001L,
                "C:\\Users\\Тест 空間\\VPN Control\\vpn-control.exe", "C:\\private\\package.msi", "b".repeat(64), 8123,
                "D:\\Работа 空間\\VPN ' & $ % workspace", 913, 1_788_800_000_002L)
            fun base64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
            val paths = files.joinToString(",") { path ->
                "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${base64(path.toString().encodeToByteArray())}')))"
            }
            val invalidReady = buildList {
                val text = ready().encode().decodeToString()
                add(text.replaceFirst("{", "{\"pid\":912,"))
                add(text.replace("\"version\":2", "\"version\":1"))
                add(text.replace("\"creationFileTime\":$created", "\"creationFileTime\":0"))
                add(text.replace(sid, "S-1-５-21-10"))
            }.joinToString(",") { "'${base64(it.encodeToByteArray())}'" }
            val values = ControlProtocolCodec.decodeValues(request.encode().decodeToString())
            val invalidRequests = listOf(
                values + ("stateDirectory" to ControlValue.Text("C:\\escape\\..\\target")),
                values + ("launcher" to ControlValue.Text("C:\\Windows\\powershell.exe")),
                values - "frontendPid",
                values + ("packageSize" to ControlValue.Text("8123")),
            ).joinToString(",") { "'${base64(ControlProtocolCodec.encodeValues(it).encodeToByteArray())}'" }
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                Add-Type -Path @($paths)
                function Reject([scriptblock]${'$'}action) {
                    ${'$'}rejected=${'$'}false
                    try { ${'$'}null=& ${'$'}action } catch { ${'$'}rejected=${'$'}true }
                    if (-not ${'$'}rejected) { throw 'Malformed helper metadata accepted' }
                }
                foreach(${'$'}role in @('install-user','install-coordinator')) {
                    ${'$'}parsed=[VpnInstallHelperProtocol]::ParseInvocation(@(${'$'}role,'$job','4294967295','9223372036854775807'))
                    if (${'$'}parsed.OwnerPid -ne [uint32]::MaxValue -or ${'$'}parsed.OwnerCreationFileTime -ne [long]::MaxValue) { throw 'Native identity rounded' }
                }
                foreach(${'$'}invalid in @('0','01','-1','1e2','9223372036854775808')) {
                    Reject { [VpnInstallHelperProtocol]::ParseInvocation(@('install-user','$job','912',${'$'}invalid)) }
                }
                Reject { [VpnInstallHelperProtocol]::ParseInvocation(@('-Command','$job','912','$created')) }
                ${'$'}ready=[VpnInstallHelperProtocol]::ParseWorkerReady([Convert]::FromBase64String('${base64(ready().encode())}'))
                if (${'$'}ready.CreationFileTime -ne [long]$created -or ${'$'}ready.Pid -ne 912) { throw 'Readiness identity mismatch' }
                foreach(${'$'}bad in @($invalidReady)) { Reject { [VpnInstallHelperProtocol]::ParseWorkerReady([Convert]::FromBase64String(${'$'}bad)) } }
                ${'$'}request=[VpnInstallHelperProtocol]::ParseRequest([Convert]::FromBase64String('${base64(request.encode())}'))
                if (${'$'}request.FrontendPid -ne 913 -or ${'$'}request.PackageSize -ne 8123) { throw 'Request field mismatch' }
                foreach(${'$'}bad in @($invalidRequests)) { Reject { [VpnInstallHelperProtocol]::ParseRequest([Convert]::FromBase64String(${'$'}bad)) } }
                Write-Output ('STATE_BASE64:'+ [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(${'$'}request.StateDirectory)))
                Write-Output ('READY_BASE64:'+ [Convert]::ToBase64String([VpnInstallHelperProtocol]::EncodeWorkerReady('$job',912,[long]$created,'$sid','${"a".repeat(64)}')))
                Write-Output 'NATIVE_INSTALL_HELPER_PROTOCOL_OK'
            """.trimIndent()
            assertTrue(script.all { it.code < 128 } && script.length < 30000)
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
                .redirectErrorStream(true).start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Native fixed codec fixture timed out")
                val output = process.inputStream.bufferedReader().readText()
                assertEquals(0, process.exitValue(), output)
                assertTrue(output.contains("NATIVE_INSTALL_HELPER_PROTOCOL_OK"), output)
                val nativeReady = output.lineSequence().single { it.startsWith("READY_BASE64:") }.substringAfter(':')
                val nativeState = output.lineSequence().single { it.startsWith("STATE_BASE64:") }.substringAfter(':')
                assertEquals(ready(), DesktopWindowsInstallWorkerReady.decode(Base64.getDecoder().decode(nativeReady)))
                assertEquals(request.stateDirectory, Base64.getDecoder().decode(nativeState).decodeToString())
            } finally { if (process.isAlive) process.destroyForcibly() }
        } finally {
            files.forEach(Files::delete)
            Files.delete(directory)
        }
    }
}
