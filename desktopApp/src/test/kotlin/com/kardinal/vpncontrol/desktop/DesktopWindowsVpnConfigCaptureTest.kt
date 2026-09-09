package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import java.nio.file.Path
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlinx.serialization.json.*
import kotlin.test.*

class DesktopWindowsVpnConfigCaptureTest {
    @Test fun failedInitialResourceCopyRetainsItsPartiallyWrittenSpool() {
        val directory = Files.createTempDirectory("vpn-capture-cleanup-")
        val source = directory.resolve("rule.json")
        Files.writeString(source, "fixture")
        var erases = 0
        val spool = object : com.kardinal.vpncontrol.control.ControlTransferSpool {
            override fun append(bytes: ByteArray) { throw java.io.IOException("private partial spool") }
            override fun read(offset: Long, length: Int): ByteArray = error("unused")
            override fun sha256() = "0".repeat(64)
            override fun erase() { if (++erases == 1) throw java.io.IOException("private cleanup path") }
        }
        try {
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsCapturedResource.capture(source, directory) { spool }
            }
            assertEquals("UNAVAILABLE", failure.code)
            assertEquals(1, erases)
            assertNotNull(failure.retainedAdmission).close()
            assertEquals(2, erases)
            assertFalse(failure.toString().contains("private"))
        } finally { Files.delete(source); Files.delete(directory) }
    }

    @Test fun resourceAdmissionRetainsItsOwnUnfinishedCleanup() {
        var closes = 0
        val admission = AutoCloseable { if (++closes == 1) throw java.io.IOException("private fixture path") }
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnConfigCapture.capture(
                """{"route":{"rule_set":[{"type":"local","path":"first.json"}]}}""", Path.of("fixture"),
                captureResource = { _, _ -> throw DesktopWindowsRuntimeFailure("PERMISSION_DENIED", retainedAdmission = admission) },
            )
        }
        assertEquals("PERMISSION_DENIED", failure.code)
        assertEquals(1, closes)
        assertNotNull(failure.retainedAdmission).close()
        assertEquals(2, closes)
        assertFalse(failure.toString().contains("private fixture path"))
    }

    @Test fun rejectedConfigurationRetainsFailedPrivateSpoolCleanupForOwnerRetry() {
        var erases = 0
        val spool = object : com.kardinal.vpncontrol.control.ControlTransferSpool {
            override fun append(bytes: ByteArray) = error("unused")
            override fun read(offset: Long, length: Int): ByteArray = error("unused")
            override fun sha256() = "0".repeat(64)
            override fun erase() { if (++erases == 1) throw java.io.IOException("private fixture path") }
        }
        val resource = DesktopWindowsCapturedResource("fixture", ".json", 0, "0".repeat(64), spool)
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnConfigCapture.capture(
                """{"route":{"rule_set":[{"type":"local","path":"first.json"}]},"experimental":{"clash_api":{"external_ui":"second-ui"}}}""",
                Path.of("fixture"), captureResource = { _, _ -> resource },
            )
        }
        assertEquals("UNSUPPORTED", failure.code)
        assertEquals(1, erases)
        val retained = assertNotNull(failure.retainedAdmission)
        retained.close()
        retained.close()
        assertEquals(2, erases)
        assertFalse(failure.toString().contains("private fixture path"))
    }

    private val nativeBrokerModules = listOf(
        "windows-vpn-broker.cs", "windows-vpn-user-files.cs", "windows-vpn-cache-resources.cs",
    )

    private fun captureNativeBrokerModules(prefix: String): Path {
        val directory = Files.createTempDirectory(prefix)
        try {
            nativeBrokerModules.forEach { name ->
                requireNotNull(javaClass.getResourceAsStream("/$name")).use { input ->
                    Files.newOutputStream(directory.resolve(name)).use { output -> input.copyTo(output) }
                }
            }
            return directory
        } catch (failure: Throwable) {
            deleteNativeBrokerModules(directory)
            throw failure
        }
    }

    private fun deleteNativeBrokerModules(directory: Path) {
        (nativeBrokerModules + "pin-probe.cs").forEach { Files.deleteIfExists(directory.resolve(it)) }
        Files.delete(directory)
    }

    @Test fun resourceAdmissionFailureIsNotReportedAsInvalidConfiguration() {
        for ((cause, code) in listOf(
            IllegalArgumentException("Unsupported installer access mask") to "PERMISSION_DENIED",
            java.nio.file.AccessDeniedException("private-path") to "PERMISSION_DENIED",
            SecurityException("private-path") to "PERMISSION_DENIED",
            WindowsInstallNativeFailure(5) to "PERMISSION_DENIED",
            WindowsInstallNativeFailure(112) to "RESOURCE_EXHAUSTED",
            OutOfMemoryError("private-path") to "RESOURCE_EXHAUSTED",
            java.io.IOException("private-path") to "UNAVAILABLE",
            IllegalStateException("CONFLICT") to "CONFLICT",
        )) {
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsVpnConfigCapture.capture(
                    """{"route":{"rule_set":[{"type":"local","path":"fixture.json"}]}}""", Path.of("fixture"),
                    captureResource = { _, _ -> throw cause },
                )
            }
            assertEquals(code, failure.code)
            assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, failure.stage)
            assertFalse(failure.toString().contains("private-path"))
        }
    }
    @Test fun actualGeneratedDefaultWindowsVpnDnsPathIsNotTreatedAsPrivilegedFile() {
        val profile = ProxyProfile(protocol = ProxyProtocol.SOCKS, remarks = "fixture", server = "127.0.0.1", serverPort = 1080,
            network = "tcp", flow = "", security = "", sni = "", fingerprint = "", publicKey = "", shortId = "", path = "",
            hostHeader = "", serviceName = "", headerType = "", rawLink = "socks://127.0.0.1:1080")
        val config = DesktopProxyConfigFactory.buildVpnConfig(profile, DnsSettings(), RoutingRules(ignoreRules = true), osName = "Windows 11")
        val captured = DesktopWindowsVpnConfigCapture.prepare(config)
        assertEquals("/dns-query", Json.parseToJsonElement(captured).jsonObject["dns"]!!.jsonObject["servers"]!!.jsonArray[1].jsonObject["path"]!!.jsonPrimitive.content)
        assertEquals(Json.parseToJsonElement(config), Json.parseToJsonElement(captured))
    }
    @Test fun wsUrlPathAndRemoteRuleCacheAreAllowedOnlyAtTheirExactContexts() {
        val input = """{"outbounds":[{"type":"vless","transport":{"type":"ws","path":"/websocket"}}],"experimental":{"cache_file":{"enabled":true}}}"""
        val output = Json.parseToJsonElement(DesktopWindowsVpnConfigCapture.prepare(input)).jsonObject
        assertEquals("/websocket", output["outbounds"]!!.jsonArray[0].jsonObject["transport"]!!.jsonObject["path"]!!.jsonPrimitive.content)
        assertEquals("cache.db", output["experimental"]!!.jsonObject["cache_file"]!!.jsonObject["path"]!!.jsonPrimitive.content)
        assertFalse(input.contains("cache.db"))
    }
    @Test fun onlyExactManagedSshFieldIsCapturedInlineWithoutMutatingCallerConfig() {
        val managed = Path.of("managed-key")
        val input = """{"outbounds":[{"type":"ssh","private_key_path":"managed-key"}]}"""
        var reads = 0
        val output = DesktopWindowsVpnConfigCapture.prepare(input, managed) { path ->
            reads++; assertEquals(managed, path); "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----"
        }
        val ssh = Json.parseToJsonElement(output).jsonObject["outbounds"]!!.jsonArray.single().jsonObject
        assertEquals(1, reads)
        assertFalse("private_key_path" in ssh)
        assertTrue(ssh["private_key"]!!.jsonPrimitive.content.startsWith("-----BEGIN OPENSSH"))
        assertTrue(input.contains("private_key_path"))
    }
    @Test fun filesystemPathsDirectoriesAndUnauthorizedKeysFailBeforeReading() {
        val forbidden = listOf(
            """{"log":{"output":"outside.log"}}""",
            """{"dns":{"servers":[{"type":"hosts","path":"outside"}]}}""",
            """{"outbounds":[{"type":"ssh","private_key_path":"foreign-key"}]}""",
            """{"experimental":{"cache_file":{"enabled":true,"path":"outside"}}}""",
            """{"inbounds":[{"type":"hysteria2","masquerade":{"type":"file","directory":"outside"}}]}""",
            """{"inbounds":[{"type":"hysteria2","masquerade":"file:///outside"}]}""",
            """{"services":[{"type":"derp","mesh_psk_file":"outside"}]}""",
            """{"inbounds":[{"tls":{"acme":{"data_directory":"outside"}}}]}""",
            """{"endpoints":[{"type":"tailscale","state_directory":"outside"}]}""")
        for (config in forbidden) assertFailsWith<IllegalArgumentException>(config) {
            DesktopWindowsVpnConfigCapture.prepare(config, Path.of("managed-key")) { error("Unauthorized read") }
        }
    }

    @Test fun customNetworkPathsRemainNetworkValuesAndCapturedFilesAreImmutablePrivateInputs() {
        val directory = Files.createTempDirectory("vpn-captured-resource-")
        val source = directory.resolve("fixture-漢.json")
        val bytes = "{\"version\":3,\"rules\":[]}\n".toByteArray()
        Files.write(source, bytes)
        val input = buildJsonObject {
            put("outbounds", buildJsonArray { add(buildJsonObject {
                put("type", "vless"); put("tcp_multi_path", true)
                put("transport", buildJsonObject { put("type", "httpupgrade"); put("path", "//opaque/path?value=1") })
            }) })
            put("route", buildJsonObject { put("rule_set", buildJsonArray { add(buildJsonObject {
                put("type", "local"); put("path", source.fileName.toString())
            }) }) })
        }.toString()
        try {
            val captured = DesktopWindowsVpnConfigCapture.capture(input, directory)
            assertFalse(captured.toString().contains("fixture"))
            val resource = captured.withSnapshot { config, resources ->
                assertEquals(1, resources.size)
                assertFalse(config.contains(source.fileName.toString()))
                assertTrue(config.contains("//opaque/path?value=1"))
                assertTrue(config.contains(resources.single().reference))
                assertEquals(".json", resources.single().extension)
                resources.single()
            }
            Files.writeString(source, "changed after capture")
            captured.withSnapshot { _, _ -> assertContentEquals(bytes, resource.read(0, bytes.size)) }
            captured.withSnapshot { _, _ ->
                captured.close()
                assertContentEquals(bytes, resource.read(0, bytes.size), "An in-flight transfer retains its capture")
            }
            assertFailsWith<IllegalStateException> { captured.withSnapshot { _, _ -> } }
            assertFailsWith<IllegalStateException> { resource.read(0, bytes.size) }
            assertEquals(listOf(source), Files.list(directory).use { it.toList() })
            assertTrue(input.contains(source.fileName.toString()))
        } finally {
            Files.delete(source); Files.delete(directory)
        }
    }

    @Test fun persistentCacheStaysOpaqueAndRequiresWorkspaceScopeBeforeAuthorization() {
        val directory = Files.createTempDirectory("vpn-captured-cache-")
        try {
            val input = """{"experimental":{"cache_file":{"enabled":true,"cache_id":"fixture","store_fakeip":true,"store_rdrc":true,"rdrc_timeout":"24h"}}}"""
            val resource = DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000041",
                DesktopWindowsRuntimeResourceKind.CACHE, DesktopWindowsResourceDestination("C:\\private-fixture\\cache.db", "0".repeat(24)))
            val captured = DesktopWindowsVpnConfigCapture.capture(input, directory, admitMutableResource = { path, kind ->
                assertEquals(directory.resolve("cache.db"), path)
                assertEquals(DesktopWindowsRuntimeResourceKind.CACHE, kind)
                resource
            })
            captured.use {
                assertEquals(listOf(resource), captured.mutableResources)
                captured.withSnapshot { config, readonly ->
                    assertTrue(readonly.isEmpty(), "A mutable cache was frozen as a read-only input before A stopped")
                    val cache = Json.parseToJsonElement(config).jsonObject["experimental"]!!.jsonObject["cache_file"]!!.jsonObject
                    assertEquals(resource.reference, cache["path"]!!.jsonPrimitive.content)
                    assertEquals("fixture", cache["cache_id"]!!.jsonPrimitive.content)
                    assertTrue(cache["store_fakeip"]!!.jsonPrimitive.boolean)
                    assertTrue(cache["store_rdrc"]!!.jsonPrimitive.boolean)
                    assertEquals("24h", cache["rdrc_timeout"]!!.jsonPrimitive.content)
                    assertFalse(config.contains("private-fixture"))
                }
                var progress = false
                val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                    DesktopWindowsVpnBroker.prepareRetained(captured, directory.resolve("runtime.log")) { progress = true }
                }
                assertEquals("UNAVAILABLE", failure.code)
                assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, failure.stage)
                assertFalse(progress, "Unbound mutable resources reached native authorization")
            }
        } finally { Files.delete(directory) }
    }

    @Test fun consoleLogOutputsPreserveTheirMeaningWithoutFilesystemAdmission() {
        for (destination in listOf("", "stdout", "stderr")) {
            val input = buildJsonObject { put("log", buildJsonObject {
                put("output", destination); put("level", "debug"); put("timestamp", true)
            }) }.toString()
            assertEquals(Json.parseToJsonElement(input), Json.parseToJsonElement(DesktopWindowsVpnConfigCapture.prepare(input)))
            DesktopWindowsVpnConfigCapture.capture(input, Path.of("fixture"),
                captureResource = { _, _ -> error("Console output cannot become an immutable input") },
                admitMutableResource = { _, _ -> error("Console output cannot become a file destination") },
            ).use { captured ->
                assertTrue(captured.mutableResources.isEmpty())
                captured.withSnapshot { config, resources ->
                    assertTrue(resources.isEmpty())
                    assertEquals(Json.parseToJsonElement(input), Json.parseToJsonElement(config))
                }
            }
        }
    }

    @Test fun logFileRemainsAnOpaqueOutputDestinationUntilFreshJobCommit() {
        val directory = Path.of("fixture-base")
        val input = """{"log":{"output":"logs/session.log","level":"info","timestamp":true}}"""
        val resource = DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000042",
            DesktopWindowsRuntimeResourceKind.OUTPUT,
            DesktopWindowsResourceDestination("C:\\private-fixture\\session.log", "0".repeat(24)))
        var admissions = 0
        DesktopWindowsVpnConfigCapture.capture(input, directory,
            captureResource = { _, _ -> error("A running A may still append to this output") },
            admitMutableResource = { path, kind ->
                admissions++
                assertEquals(directory.resolve("logs/session.log"), path)
                assertEquals(DesktopWindowsRuntimeResourceKind.OUTPUT, kind)
                resource
            },
        ).use { captured ->
            assertEquals(1, admissions)
            assertEquals(listOf(resource), captured.mutableResources)
            captured.withSnapshot { config, resources ->
                assertTrue(resources.isEmpty())
                val log = Json.parseToJsonElement(config).jsonObject["log"]!!.jsonObject
                assertEquals(resource.reference, log["output"]!!.jsonPrimitive.content)
                assertEquals("info", log["level"]!!.jsonPrimitive.content)
                assertTrue(log["timestamp"]!!.jsonPrimitive.boolean)
                assertFalse(config.contains("logs/session.log"))
                assertFalse(config.contains("private-fixture"))
            }
            var progress = false
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsVpnBroker.prepareRetained(captured, directory.resolve("broker.log")) { progress = true }
            }
            assertEquals("UNAVAILABLE", failure.code)
            assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, failure.stage)
            assertFalse(progress, "Unbound output destination reached authorization")
        }
        assertTrue(input.contains("logs/session.log"))
    }

    @Test fun disabledLogDoesNotCaptureOrOpenItsUnusedOutput() {
        val input = """{"log":{"disabled":true,"output":"private-unused-output","level":"debug"}}"""
        DesktopWindowsVpnConfigCapture.capture(input, Path.of("fixture"),
            captureResource = { _, _ -> error("Disabled log input access") },
            admitMutableResource = { _, _ -> error("Disabled log destination access") },
        ).use { captured ->
            assertTrue(captured.mutableResources.isEmpty())
            captured.withSnapshot { config, resources ->
                assertTrue(resources.isEmpty())
                assertFalse(config.contains("private-unused-output"))
                val log = Json.parseToJsonElement(config).jsonObject["log"]!!.jsonObject
                assertTrue(log["disabled"]!!.jsonPrimitive.boolean)
                assertEquals("", log["output"]!!.jsonPrimitive.content)
                assertEquals("debug", log["level"]!!.jsonPrimitive.content)
            }
        }
    }

    @Test fun outputAdmissionRequiresExactLogContextAndStringSemantics() {
        for ((input, code) in listOf(
            """{"log":{"output":false}}""" to "INVALID_ARGUMENT",
            """{"log":{"output":[]}}""" to "INVALID_ARGUMENT",
            """{"log":{"disabled":"true","output":"unused.log"}}""" to "INVALID_ARGUMENT",
            """{"experimental":{"cache_file":{"enabled":"true","path":"cache.db"}}}""" to "INVALID_ARGUMENT",
            """{"outbounds":[{"type":"direct","output":"stdout"}]}""" to "UNSUPPORTED",
            """{"other/log":{"output":"stdout"}}""" to "UNSUPPORTED",
        )) {
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure>(input) {
                DesktopWindowsVpnConfigCapture.capture(input, Path.of("fixture"),
                    admitMutableResource = { _, _ -> error("Unvalidated output reached file admission") })
            }
            assertEquals(code, failure.code)
        }
        var admitted = false
        DesktopWindowsVpnConfigCapture.capture("""{"log":{"output":"STDOUT"}}""", Path.of("fixture"),
            admitMutableResource = { path, kind ->
                assertEquals(Path.of("fixture", "STDOUT"), path)
                assertEquals(DesktopWindowsRuntimeResourceKind.OUTPUT, kind)
                admitted = true
                DesktopWindowsRuntimeResource("00000000-0000-0000-0000-000000000043", kind,
                    DesktopWindowsResourceDestination("C:\\fixture\\STDOUT", "0".repeat(24)))
            },
        ).close()
        assertTrue(admitted, "Console sentinels are exact lowercase sing-box values")
    }

    @Test fun samePhysicalMutableDestinationIsRejectedBeforeAuthorization() {
        var admissions = 0
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnConfigCapture.capture(
                """{"log":{"output":"trace.log"},"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}""",
                Path.of("fixture"), captureResource = { _, _ -> error("Mutable bytes opened before commit") },
                admitMutableResource = { _, kind ->
                    admissions++
                    // Two captured path spellings name the same physical parent and Windows leaf.
                    val destination = if (admissions == 1) "C:\\fixture\\shared.db" else "Z:\\same-parent\\SHARED.DB"
                    DesktopWindowsRuntimeResource(java.util.UUID.randomUUID().toString(), kind,
                        DesktopWindowsResourceDestination(destination, "0".repeat(24)))
                },
            ).close()
        }
        assertEquals(2, admissions)
        assertEquals("CONFLICT", failure.code)
        assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, failure.stage)
    }

    @Test fun cacheAndOutputKeepDistinctMutableIdentitiesWithoutReadingEither() {
        val kinds = mutableListOf<DesktopWindowsRuntimeResourceKind>()
        DesktopWindowsVpnConfigCapture.capture(
            """{"log":{"output":"session.log"},"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}""",
            Path.of("fixture"), captureResource = { _, _ -> error("Mutable bytes captured before commit") },
            admitMutableResource = { path, kind ->
                kinds += kind
                DesktopWindowsRuntimeResource(java.util.UUID.randomUUID().toString(), kind,
                    DesktopWindowsResourceDestination("C:\\fixture\\${path.fileName}", "0".repeat(24)))
            },
        ).use { captured ->
            assertEquals(listOf(DesktopWindowsRuntimeResourceKind.OUTPUT, DesktopWindowsRuntimeResourceKind.CACHE), kinds)
            assertEquals(2, captured.mutableResources.map { it.id }.distinct().size)
            captured.withSnapshot { config, resources ->
                assertTrue(resources.isEmpty())
                val document = Json.parseToJsonElement(config).jsonObject
                assertEquals(captured.mutableResources[0].reference, document["log"]!!.jsonObject["output"]!!.jsonPrimitive.content)
                assertEquals(captured.mutableResources[1].reference,
                    document["experimental"]!!.jsonObject["cache_file"]!!.jsonObject["path"]!!.jsonPrimitive.content)
            }
        }
    }

    @Test fun disabledCacheAndNetworkUrlDoNotAdmitMutableFilesystemResources() {
        val input = """{"experimental":{"cache_file":{"enabled":false,"path":"private-unused-cache","cache_id":"same"}},"dns":{"servers":[{"type":"https","path":"/dns-query"}]}}"""
        DesktopWindowsVpnConfigCapture.capture(input, Path.of("unused"), admitMutableResource = { _, _ -> error("Unused cache admission") }).use { captured ->
            assertTrue(captured.mutableResources.isEmpty())
            captured.withSnapshot { config, _ ->
                assertFalse(config.contains("private-unused-cache"))
                assertTrue(config.contains("/dns-query"))
                assertFalse(Json.parseToJsonElement(config).jsonObject["experimental"]!!.jsonObject["cache_file"]!!.jsonObject["enabled"]!!.jsonPrimitive.boolean)
            }
        }
    }
    @Test fun managedKeyReadIsBoundedAndDoesNotFollowLeafSymlink() {
        val directory = Files.createTempDirectory("vpn-capture-key-")
        try {
            val key = directory.resolve("key")
            Files.writeString(key, "fixture-key")
            fun input(path: Path) = buildJsonObject { put("outbounds", buildJsonArray {
                add(buildJsonObject { put("type", "ssh"); put("private_key_path", path.toString()) })
            }) }.toString()
            assertTrue(DesktopWindowsVpnConfigCapture.prepare(input(key), key).contains("fixture-key"))
            Files.writeString(key, "x".repeat(512 * 1024 + 1))
            assertFailsWith<IllegalArgumentException> { DesktopWindowsVpnConfigCapture.prepare(input(key), key) }
            val link = directory.resolve("link")
            if (runCatching { Files.createSymbolicLink(link, key) }.isSuccess)
                assertFails { DesktopWindowsVpnConfigCapture.prepare(input(link), link) }
        } finally {
            Files.list(directory).use { it.toList() }.forEach(Files::delete)
            Files.delete(directory)
        }
    }

    @Test fun nativeCsharpCompilerAndAuthoritativePolicyAgreeWithoutLaunchingAChild() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val source = captureNativeBrokerModules("vpn-broker-policy-")
        try {
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                ${'$'}ProgressPreference='SilentlyContinue'
                ${'$'}sources=@(${nativeBrokerModules.joinToString(",") { "'$it'" }}) | ForEach-Object { Join-Path ${'$'}env:VPN_CONTROL_BROKER_POLICY_SOURCE ${'$'}_ }
                Add-Type -Path ${'$'}sources -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
                ${'$'}rows=[Console]::In.ReadToEnd()|ConvertFrom-Json
                foreach(${'$'}row in ${'$'}rows) {
                    ${'$'}accepted=${'$'}false
                    try { ${'$'}result=[VpnRuntimeBroker]::NormalizeConfiguration(${'$'}row.config,'C:\protected-fixture'); ${'$'}accepted=${'$'}true } catch {}
                    if(${'$'}accepted -ne ${'$'}row.accept) { throw 'Authoritative config policy mismatch' }
                    if(${'$'}row.cache -and ((${'$'}result|ConvertFrom-Json).experimental.cache_file.path -ne 'C:\protected-fixture\cache.db')) { throw 'Cache path was not confined' }
                }
                [Console]::Write('POLICY_OK')
            """.trimIndent()
            val rows = buildJsonArray {
                fun row(config: String, accept: Boolean, cache: Boolean = false) {
                    add(buildJsonObject { put("config", config); put("accept", accept); put("cache", cache) })
                }
                row("""{"dns":{"servers":[{"type":"https","path":"/dns-query"}]}}""", true)
                row("""{"outbounds":[{"transport":{"type":"ws","path":"/ws"}}]}""", true)
                row("""{"outbounds":[{"tcp_multi_path":true,"transport":{"type":"httpupgrade","path":"//opaque/path?value=1"}}]}""", true)
                row("""{"experimental":{"cache_file":{"enabled":true,"path":"cache.db"}}}""", true, true)
                row("""{"dns":{"servers":[{"type":"hosts","path":"C:\\foreign"}]}}""", false)
                row("""{"experimental":{"cache_file":{"enabled":true,"path":"C:\\foreign"}}}""", false)
                row("""{"tls":{"acme":{"data_directory":"C:\\foreign"}}}""", false)
                row("""{"endpoints":[{"type":"tailscale","state_directory":"C:\\foreign"}]}""", false)
                row("""{"outbounds":[{"type":"ssh","private_key_path":"C:\\foreign"}]}""", false)
                row("""{"inbounds":[{"type":"hysteria2","masquerade":{"type":"file","directory":"C:\\foreign"}}]}""", false)
                row("""{"inbounds":[{"type":"hysteria2","masquerade":"file:///C:/foreign"}]}""", false)
                row("""{"services":[{"type":"derp","mesh_psk_file":"C:\\foreign"}]}""", false)
            }
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))).redirectErrorStream(true)
                .also { it.environment()["VPN_CONTROL_BROKER_POLICY_SOURCE"] = source.toString() }.start()
            process.outputStream.use { it.write(rows.toString().encodeToByteArray()) }
            if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); fail("Native config compiler timeout") }
            val diagnostics = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
            assertEquals(0, process.exitValue(), diagnostics)
            assertTrue(diagnostics.endsWith("POLICY_OK"), diagnostics)
        } finally { deleteNativeBrokerModules(source) }
    }

    @Test fun nativeRetainedPrivilegedDirectoryCannotBeRenamedWhilePinned() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv("VPN_CONTROL_TEST_WINDOWS_PRIVILEGED_PIN") == "1")
        val source = captureNativeBrokerModules("vpn-broker-pin-")
        try {
            val script = """
                ${'$'}ErrorActionPreference='Stop'
                ${'$'}ProgressPreference='SilentlyContinue'
                ${'$'}wrapper=' public static class PinProbe { public static System.IDisposable Hold(string path) { return (System.IDisposable)typeof(VpnRuntimeBroker).GetMethod("Pin",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static).Invoke(null,new object[]{path,true,new System.Collections.Generic.List<Microsoft.Win32.SafeHandles.SafeFileHandle>()}); } }'
                ${'$'}wrapperPath=Join-Path ${'$'}env:VPN_CONTROL_BROKER_POLICY_SOURCE 'pin-probe.cs'
                [IO.File]::WriteAllText(${'$'}wrapperPath,${'$'}wrapper)
                ${'$'}sources=@(${nativeBrokerModules.joinToString(",") { "'$it'" }}) | ForEach-Object { Join-Path ${'$'}env:VPN_CONTROL_BROKER_POLICY_SOURCE ${'$'}_ }
                Add-Type -Path (@(${'$'}sources)+${'$'}wrapperPath) -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
                ${'$'}stage=Join-Path ${'$'}env:ProgramData ('vpn-broker-pin-'+[Guid]::NewGuid().ToString('D'))
                ${'$'}acl=New-Object Security.AccessControl.DirectorySecurity
                ${'$'}acl.SetAccessRuleProtection(${'$'}true,${'$'}false)
                ${'$'}acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
                foreach(${'$'}sid in @('S-1-5-18','S-1-5-32-544')) { ${'$'}acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier(${'$'}sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))) }
                [IO.Directory]::CreateDirectory(${'$'}stage,${'$'}acl)|Out-Null
                ${'$'}handle=${'$'}null; ${'$'}moved=${'$'}false
                try {
                    ${'$'}handle=[PinProbe]::Hold(${'$'}stage)
                    try { [IO.Directory]::Move(${'$'}stage,${'$'}stage+'-moved'); ${'$'}moved=${'$'}true } catch [IO.IOException] {}
                    if(${'$'}moved) { throw 'Retained directory was replaced' }
                    [Console]::Write('PIN_OK')
                } finally {
                    if(${'$'}handle) { ${'$'}handle.Dispose() }
                    if(${'$'}moved) { [IO.Directory]::Delete(${'$'}stage+'-moved') } else { [IO.Directory]::Delete(${'$'}stage) }
                }
            """.trimIndent()
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE))).redirectErrorStream(true)
                .also { it.environment()["VPN_CONTROL_BROKER_POLICY_SOURCE"] = source.toString() }.start()
            if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); fail("Native pin regression timeout") }
            val diagnostics = process.inputStream.use { it.readNBytes(8193).decodeToString().take(8192) }
            assertEquals(0, process.exitValue(), diagnostics)
            assertTrue(diagnostics.endsWith("PIN_OK"), diagnostics)
        } finally { deleteNativeBrokerModules(source) }
    }
}
