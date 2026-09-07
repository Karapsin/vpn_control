package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeTrue
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.*

class DesktopWindowsVpnBrokerTest {
    @Test fun failedPreparationNeverDiscardsUnconfirmedNativeOwnership() {
        var closed = false
        val retained = object : DesktopRuntimeProcess {
            override val isAlive = true
            override fun pid() = 42L
            override fun destroy() = Unit
            override fun destroyForcibly() = Unit
            override fun waitFor(timeout: Long, unit: TimeUnit) = false
        }
        val failure = desktopWindowsPreparationFailure(java.io.IOException("private fixture detail"),
            DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS,
            abort = { false }, close = { closed = true }, unresolved = { retained })
        assertEquals("OUTCOME_UNKNOWN", failure.code)
        assertSame(retained, failure.unresolvedRuntime)
        assertFalse(closed, "Unconfirmed native ownership was released")
        assertFalse(failure.toString().contains("private fixture"))
    }

    @Test fun captureCleanupFailureDisposesAnAcceptedCandidateBeforeItsIdentityCanBeLost() {
        val resource = DesktopWindowsCapturedResource("00000000-0000-0000-0000-000000000041", ".bin", 0, "0".repeat(64),
            object : com.kardinal.vpncontrol.control.ControlTransferSpool {
                override fun append(bytes: ByteArray) = error("Unused")
                override fun read(offset: Long, length: Int) = error("Unused")
                override fun sha256() = "0".repeat(64)
                override fun erase() { throw java.io.IOException("private fixture path must not be reported") }
            })
        val captured = DesktopWindowsCapturedConfiguration("{}", listOf(resource))
        var disposed = 0
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnBroker.prepareCapturedInput(captured) { _, _ ->
                object : DesktopPreparedRuntimeProcess {
                    override fun commit(): DesktopRuntimeProcess = error("Cleanup failure must precede commit")
                    override fun close() { disposed++ }
                }
            }
        }
        assertEquals(1, disposed)
        assertEquals("UNAVAILABLE", failure.code)
        assertFalse(failure.message.orEmpty().contains("private fixture"))
    }
    @Test fun nativeCompletionFieldsSurviveSubsequentJnaCalls() {
        val event = com.sun.jna.platform.win32.WinNT.HANDLE(com.sun.jna.Pointer.createConstant(5))
        val overlapped = DesktopWindowsVpnBroker.retainedOverlapped(event)
        overlapped.write()
        // WriteFile returns pending. A native kernel completion races with the next JNA invocation.
        val memory = overlapped.pointer
        memory.setLong(0, 259)
        memory.setLong(com.sun.jna.Native.POINTER_SIZE.toLong(), 0)
        overlapped.autoRead()
        memory.setLong(0, 0)
        memory.setLong(com.sun.jna.Native.POINTER_SIZE.toLong(), 65536)
        overlapped.autoWrite()
        assertEquals(0L, memory.getLong(0), "JNA rewrote the native completion status")
        assertEquals(65536L, memory.getLong(com.sun.jna.Native.POINTER_SIZE.toLong()), "JNA erased the transfer count")
    }
    @Test fun configurationTransferPreservesLargeUnicodeDocumentAndUsesBoundedFrames() {
        val configuration = "{\"payload\":\"" + "x\uD83D\uDE80漢".repeat(1_200_000) + "\"}"
        val encoded = ByteArrayOutputStream()
        DesktopWindowsVpnBroker.writeConfiguration(configuration) { bytes, offset, size ->
            assertTrue(size <= 65536)
            encoded.write(bytes, offset, size)
        }
        val frame = ByteBuffer.wrap(encoded.toByteArray()).order(ByteOrder.LITTLE_ENDIAN)
        val body = ByteArrayOutputStream()
        while (true) {
            val count = frame.int
            if (count == 0) break
            assertTrue(count in 1..65536)
            val chunk = ByteArray(count); frame.get(chunk); body.write(chunk)
        }
        val actual = body.toByteArray()
        assertTrue(actual.size > 8 * 1024 * 1024)
        assertEquals(actual.size.toLong(), frame.long)
        assertContentEquals(MessageDigest.getInstance("SHA-256").digest(actual), ByteArray(32).also { frame.get(it) })
        assertEquals(0, frame.remaining())
        assertEquals(configuration, actual.decodeToString())
    }
    @Test fun malformedUtf16CannotSilentlyChangeCapturedConfiguration() {
        assertFailsWith<java.nio.charset.CharacterCodingException> {
            DesktopWindowsVpnBroker.writeConfiguration("{\"x\":\"\uD800\"}") { _, _, _ -> }
        }
    }
    @Test fun runtimeArchitectureIsEstablishedFromExecutableBytes() {
        val fixture = ByteArray(512)
        val header = ByteBuffer.wrap(fixture).order(ByteOrder.LITTLE_ENDIAN)
        fixture[0] = 0x4d; fixture[1] = 0x5a
        header.putInt(0x3c, 128); header.putInt(128, 0x4550); header.putShort(132, 0x8664.toShort())
        DesktopWindowsVpnBroker.requireAmd64Executable(fixture)
        for (machine in listOf(0xaa64, 0x14c, 0)) {
            header.putShort(132, machine.toShort())
            assertFailsWith<IllegalArgumentException> { DesktopWindowsVpnBroker.requireAmd64Executable(fixture) }
        }
        header.putInt(0x3c, Int.MAX_VALUE)
        assertFailsWith<IllegalArgumentException> { DesktopWindowsVpnBroker.requireAmd64Executable(fixture) }
    }
    @Test fun uacDenialHasCancellationIdentityWithoutNativeExceptionText() {
        assertEquals("CANCELLED", DesktopWindowsVpnBroker.launchFailure(1223).code)
        assertEquals("PERMISSION_DENIED", DesktopWindowsVpnBroker.launchFailure(5).code)
        assertEquals("UNAVAILABLE", DesktopWindowsVpnBroker.launchFailure(2).code)
    }
    @Test fun capturedCommandIsBoundedAndContainsOnlyNonsecretPeerIdentity() {
        val command = DesktopWindowsVpnBroker.command("vpn-control-vpn-00000000-0000-0000-0000-000000000041",
            123, 456, "S-1-5-21-1-2-3-1001", "a".repeat(64))
        assertTrue(DesktopWindowsVpnBroker.commandParameters("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", command).length < 32767)
        assertTrue(command.contains("[VpnRuntimeBroker]::Run("))
        assertTrue(command.contains("GZipStream"))
        assertFalse(command.contains("private_key"))
        assertFailsWith<IllegalArgumentException> {
            DesktopWindowsVpnBroker.command("pipe';injection", 123, 456, "S-1-5-18", "a".repeat(64))
        }
        for (sid in listOf("S-1-5-18';throw 'injection", "S-1-5-18\u0000", "S-1-5-18\n")) {
            assertFailsWith<IllegalArgumentException> {
                DesktopWindowsVpnBroker.command("vpn-control-vpn-00000000-0000-0000-0000-000000000041", 123, 456, sid, "a".repeat(64))
            }
        }
    }

    @Test fun capturedBootstrapUsesSingleAsciiCommandWithoutDoubleEncoding() {
        val command = DesktopWindowsVpnBroker.command("vpn-control-vpn-00000000-0000-0000-0000-000000000041",
            123, 456, "S-1-5-21-1-2-3-1001", "a".repeat(64))
        assertTrue(command.startsWith("\u0024ErrorActionPreference='Stop'"), "Bootstrap must be a captured ASCII script")
        assertTrue(command.all { it.code in 1..127 })
        val source = Regex("FromBase64String\\('([A-Za-z0-9+/=]+)'\\)").find(command)?.groupValues?.get(1)
        assertNotNull(source)
        val captured = java.util.zip.GZIPInputStream(Base64.getDecoder().decode(source).inputStream()).use {
            it.readBytes().decodeToString()
        }
        assertTrue(captured.contains("class VpnRuntimeBroker"))
        assertTrue(captured.contains("class OriginalUser"), "Original-user resource code must be captured before authorization")
        assertFalse(command.contains("-EncodedCommand"))
    }

    @Test fun capturedBootstrapReportsTheActualNativeArgvBoundAsResourceFailure() {
        val executable = "C:\\path with spaces\\powershell.exe"
        val one = DesktopWindowsVpnBroker.commandParameters(executable, "x")
        val remaining = 32767 - windowsInstallArgument(executable).length - one.length - 2
        DesktopWindowsVpnBroker.commandParameters(executable, "x".repeat(remaining + 1))
        val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
            DesktopWindowsVpnBroker.commandParameters(executable, "x".repeat(remaining + 2))
        }
        assertEquals("RESOURCE_EXHAUSTED", failure.code)
        assertEquals(DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS, failure.stage)
        assertFailsWith<IllegalArgumentException> { DesktopWindowsVpnBroker.commandParameters(executable, "x\u0000y") }
    }

    @Test fun nativeCapturedBootstrapQuotingPreservesOneScriptAndLiteralPowerShellMetacharacters() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv("VPN_CONTROL_TEST_SCOPED_BROKER") == "1")
        val values = listOf("", "C:\\path with spaces\\", "a\\\"b", "literal '; throw 'invalid", "\u0024([Console]::Write('injected')); ` & | > <", "line\nbreak")
        val argv = listOf("C:\\trusted path\\probe.exe") + values + "Unicode: \uD83D\uDE80漢"
        assertContentEquals(argv.toTypedArray(), com.sun.jna.platform.win32.Shell32Util.CommandLineToArgv(
            argv.joinToString(" ", transform = ::windowsInstallArgument)))
        val expected = Base64.getEncoder().encodeToString(values.joinToString("\u0000").encodeToByteArray())
        val script = "\u0024values=@(${values.joinToString(",") { "'" + it.replace("'", "''") + "'" }});" +
            "\u0024actual=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((\u0024values-join[char]0)));" +
            "if(\u0024actual -ceq '$expected'){exit 0}else{exit 7}"
        val executable = java.nio.file.Path.of(System.getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toString()
        val parameters = DesktopWindowsVpnBroker.commandParameters(executable, script)
        val parsed = com.sun.jna.platform.win32.Shell32Util.CommandLineToArgv(windowsInstallArgument(executable) + " " + parameters)
        assertEquals(script, parsed.last())
        assertEquals("-Command", parsed[parsed.lastIndex - 1])
        // Exercise the product's raw ShellExecute parameter path. Relaunching the parsed script via
        // ProcessBuilder applies Java's different quoting again and changes backslash-quote literals.
        val launch = com.sun.jna.platform.win32.ShellAPI.SHELLEXECUTEINFO().also {
            it.fMask = 0x40
            it.lpVerb = "open" // The fixed literal-rendering probe requires no elevation.
            it.lpFile = executable
            it.lpParameters = parameters
            it.nShow = 0
        }
        assertTrue(com.sun.jna.platform.win32.Shell32.INSTANCE.ShellExecuteEx(launch))
        val process = assertNotNull(launch.hProcess)
        try {
            if (com.sun.jna.platform.win32.Kernel32.INSTANCE.WaitForSingleObject(process, 30000) != 0) {
                // This exact ordinary probe owns no runtime or installer.
                com.sun.jna.platform.win32.Kernel32.INSTANCE.TerminateProcess(process, 1)
                fail("Native bootstrap quoting probe timed out")
            }
            val code = com.sun.jna.ptr.IntByReference()
            assertTrue(com.sun.jna.platform.win32.Kernel32.INSTANCE.GetExitCodeProcess(process, code))
            assertEquals(0, code.value, "PowerShell changed captured literal data")
        } finally {
            assertTrue(com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(process))
        }
    }

    @Test fun nativeScopedChildStartsAndStopsWithoutTunOrWholeApplicationElevation() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv("VPN_CONTROL_TEST_SCOPED_BROKER") == "1")
        val previousStages = privateStages()
        val log = Files.createTempFile("vpn-scoped-native-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        // Only loopback proxy binding: no TUN, routing changes, remote connections, or personal workspace.
        val config = """{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$port}],"outbounds":[{"type":"direct","tag":"direct"}]}"""
        var runtime: DesktopRuntimeProcess? = null
        try {
            val prepared = DesktopWindowsVpnBroker.prepare(config, log) { stage ->
                System.err.println("Native broker preparation: $stage")
            }
            assertFailsWith<java.net.ConnectException> { Socket("127.0.0.1", port).use { } }
            val started = prepared.use { it.commit() }
            runtime = started
            assertTrue(started.pid() > 0)
            var ready = false
            repeat(40) {
                if (!ready) {
                    assertTrue(started.isAlive)
                    ready = runCatching { Socket("127.0.0.1", port).use { } }.isSuccess
                    if (!ready) Thread.sleep(100)
                }
            }
            assertTrue(ready, "Owned loopback child did not become ready")
            started.destroy()
            assertTrue(started.waitFor(15, TimeUnit.SECONDS), "Exact owned child exit not confirmed")
            assertFalse(started.isAlive)
        } finally {
            runtime?.let {
                if (it.isAlive) { it.destroyForcibly(); check(it.waitFor(15, TimeUnit.SECONDS)) }
                it.close()
            }
            Files.delete(log)
        }
        assertStagesRemoved(previousStages)
    }

    @Test fun nativePreparedChildCanBeAbandonedWithoutStartingOrElevatedTerminationRights() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER")
        val previousStages = privateStages()
        val log = Files.createTempFile("vpn-scoped-abandon-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        try {
            DesktopWindowsVpnBroker.prepare(loopbackConfig(port), log).use {
                assertFailsWith<java.net.ConnectException> { Socket("127.0.0.1", port).use { } }
            }
            assertFailsWith<java.net.ConnectException> { Socket("127.0.0.1", port).use { } }
            assertStagesRemoved(previousStages)
        } finally { Files.delete(log) }
    }

    @Test fun nativeTransientExecutableReaderDoesNotLeaveTerminalPrivateInputs() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER")
        assumeTrue(System.getenv("VPN_CONTROL_TEST_WINDOWS_PRIVILEGED_PIN") == "1")
        val previous = privateStages()
        val log = Files.createTempFile("vpn-scoped-retained-image-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        val runtime = DesktopWindowsVpnBroker.start(loopbackConfig(port), log)
        var retained: com.sun.jna.platform.win32.WinNT.HANDLE? = null
        var release: Thread? = null
        try {
            awaitListener(runtime, port)
            val name = privateStages().minus(previous).single()
            val image = java.nio.file.Path.of(System.getenv("ProgramData"), name, "sing-box.exe")
            retained = com.sun.jna.platform.win32.Kernel32.INSTANCE.CreateFile(image.toString(),
                1, 1, null, 3, 0, null)
            assertNotEquals(com.sun.jna.platform.win32.WinBase.INVALID_HANDLE_VALUE, retained)
            val handle = requireNotNull(retained)
            release = Thread {
                // A short antivirus/indexer reader may outlive the exact runtime child.
                Thread.sleep(750)
                com.sun.jna.platform.win32.Kernel32.INSTANCE.CloseHandle(handle)
            }.also { it.start() }
            retained = null
            runtime.destroy()
            assertTrue(runtime.waitFor(15, TimeUnit.SECONDS))
            runtime.close()
            release.join()
            assertStagesRemoved(previous)
        } finally {
            retained?.let(com.sun.jna.platform.win32.Kernel32.INSTANCE::CloseHandle)
            release?.join()
            if (runtime.isAlive) { runtime.destroyForcibly(); check(runtime.waitFor(15, TimeUnit.SECONDS)) }
            runtime.close()
            Files.delete(log)
        }
    }

    @Test fun nativeFailureBeforeChildIdentityCannotLoseSuspendedCandidate() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER")
        val previous = privateStages()
        val log = Files.createTempFile("vpn-scoped-lost-child-ack-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        var created = false
        try {
            val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                DesktopWindowsVpnBroker.prepare(loopbackConfig(port), log) { stage ->
                    if (stage == DesktopWindowsRuntimePreparationStage.CHILD_CREATED) {
                        created = true
                        throw java.io.IOException("fixture response loss before native identity")
                    }
                }
            }
            assertTrue(created, "Fixture never reached the native acknowledgment boundary")
            failure.unresolvedRuntime?.let { owned ->
                owned.destroyForcibly()
                assertTrue(owned.waitFor(15, TimeUnit.SECONDS))
                owned.close()
            }
            assertFalse(runCatching { Socket("127.0.0.1", port).use { } }.isSuccess,
                "An uncommitted candidate executed after response loss")
            assertStagesRemoved(previous)
        } finally { Files.delete(log) }
    }

    @Test fun nativeDeniedReplacementKeepsExistingChildAndProxyTraffic() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER_DENIAL")
        val log = Files.createTempFile("vpn-scoped-denial-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        val candidatePort = ServerSocket(0).use { it.localPort }
        val serving = AtomicBoolean(true)
        val sampling = AtomicBoolean(true)
        val successes = AtomicInteger()
        val failures = AtomicInteger()
        ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress()).use { target ->
            target.soTimeout = 100
            val responder = thread(name = "broker-native-fixture") {
                while (serving.get()) {
                    val accepted = try { target.accept() } catch (_: java.net.SocketTimeoutException) { continue }
                    accepted.use { socket -> socket.soTimeout = 1000; socket.getOutputStream().write(socket.getInputStream().read()) }
                }
            }
            var runtime: DesktopRuntimeProcess? = null
            var sampler: Thread? = null
            try {
                System.err.println("Native fixture: approve initial helper")
                runtime = DesktopWindowsVpnBroker.start(loopbackConfig(port), log)
                awaitListener(runtime, port)
                val initialPid = runtime.pid()
                fun exchange() {
                    Socket(java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", port))).use { socket ->
                        socket.soTimeout = 1000
                        socket.connect(java.net.InetSocketAddress("127.0.0.1", target.localPort), 1000)
                        socket.getOutputStream().write(42)
                        check(socket.getInputStream().read() == 42)
                    }
                }
                exchange()
                sampler = thread(name = "broker-native-traffic") {
                    while (sampling.get()) {
                        try { exchange(); successes.incrementAndGet() } catch (_: Exception) { failures.incrementAndGet() }
                        Thread.sleep(50)
                    }
                }
                System.err.println("Native fixture: deny replacement helper; existing traffic remains sampled")
                val failure = assertFailsWith<DesktopWindowsRuntimeFailure> {
                    DesktopWindowsVpnBroker.prepare(loopbackConfig(candidatePort), log).use { error("Expected visible UAC denial") }
                }
                assertEquals("CANCELLED", failure.code)
                assertEquals(initialPid, runtime.pid())
                assertTrue(runtime.isAlive)
                exchange()
                assertTrue(successes.get() > 2, "Fixture did not sample during consent")
                assertEquals(0, failures.get(), "Active traffic failed during denied preparation")
                System.err.println("Native fixture: denied replacement preserved ${successes.get()} successful samples")
            } finally {
                sampling.set(false); sampler?.join(2000)
                runtime?.let { it.destroy(); check(it.waitFor(15, TimeUnit.SECONDS)); it.close() }
                serving.set(false); responder.join(2000)
                Files.delete(log)
            }
        }
    }

    @Test fun nativeConfigurationAboveEightMebibytesStartsTheCapturedRuntime() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER_LARGE")
        val log = Files.createTempFile("vpn-scoped-large-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        val domains = buildString {
            repeat(140000) { index ->
                if (index != 0) append(',')
                append('"').append("domain$index.this-is-the-large-native-captured-routing-fixture.example").append('"')
            }
        }
        val config = loopbackConfig(port).dropLast(1) + ",\"route\":{\"rules\":[{\"domain_suffix\":[$domains],\"outbound\":\"direct\"}]}}"
        assertTrue(config.toByteArray().size > 8 * 1024 * 1024)
        try {
            val runtime = DesktopWindowsVpnBroker.start(config, log)
            try { awaitListener(runtime, port) }
            finally { runtime.destroy(); check(runtime.waitFor(15, TimeUnit.SECONDS)); runtime.close() }
        } finally { Files.delete(log) }
    }

    @Test fun nativeRuntimeReadsCapturedCustomResourceAfterOriginalInputChanges() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER_RESOURCES")
        val directory = Files.createTempDirectory("vpn-scoped-resource-")
        val source = directory.resolve("routing-漢.json")
        val log = directory.resolve("runtime.log")
        val port = ServerSocket(0).use { it.localPort }
        val input = """{"version":3,"rules":[{"ip_cidr":["127.0.0.0/8"]}]}"""
        Files.writeString(source, input); Files.createFile(log)
        val resourcePath = kotlinx.serialization.json.JsonPrimitive(source.fileName.toString()).toString()
        val config = loopbackConfig(port).dropLast(1) + ",\"route\":{\"rule_set\":[{\"type\":\"local\",\"tag\":\"fixture-rules\",\"format\":\"source\",\"path\":$resourcePath}],\"rules\":[{\"rule_set\":[\"fixture-rules\"],\"outbound\":\"direct\"}]}}"
        try {
            val prepared = DesktopWindowsVpnConfigCapture.capture(config, directory).use { captured ->
                Files.writeString(source, "invalid after ordinary-authority capture")
                DesktopWindowsVpnBroker.prepare(captured, log)
            }
            val runtime = prepared.use { it.commit() }
            try { awaitListener(runtime, port) }
            finally { runtime.destroy(); check(runtime.waitFor(15, TimeUnit.SECONDS)); runtime.close() }
            assertEquals("invalid after ordinary-authority capture", Files.readString(source))
        } finally { Files.delete(source); Files.delete(log); Files.delete(directory) }
    }

    @Test fun nativeTunForwardsDisposableGuestTrafficAndStopsItsExactChild() {
        assumeNative("VPN_CONTROL_TEST_SCOPED_BROKER_TUN")
        val target = requireNotNull(System.getenv("VPN_CONTROL_TEST_SCOPED_BROKER_TRAFFIC_URL"))
        val expected = requireNotNull(System.getenv("VPN_CONTROL_TEST_SCOPED_BROKER_TRAFFIC_BODY"))
        val log = Files.createTempFile("vpn-scoped-tun-", ".log")
        val port = ServerSocket(0).use { it.localPort }
        val config = """{"log":{"level":"error"},"inbounds":[{"type":"tun","interface_name":"vpn-control-native-fixture","address":["172.31.255.1/30"],"auto_route":true,"strict_route":true,"stack":"system"},{"type":"mixed","listen":"127.0.0.1","listen_port":$port}],"route":{"auto_detect_interface":true,"final":"direct"},"outbounds":[{"type":"direct","tag":"direct"}]}"""
        try {
            val runtime = DesktopWindowsVpnBroker.start(config, log)
            try {
                awaitListener(runtime, port)
                val connection = java.net.URI(target).toURL().openConnection(java.net.Proxy.NO_PROXY)
                connection.connectTimeout = 10000; connection.readTimeout = 10000
                assertEquals(expected, connection.getInputStream().bufferedReader().use { it.readText() })
            } finally { runtime.destroy(); check(runtime.waitFor(15, TimeUnit.SECONDS)); runtime.close() }
        } finally { Files.delete(log) }
    }

    private fun assumeNative(optIn: String) {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        assumeTrue(System.getenv(optIn) == "1")
    }
    private fun loopbackConfig(port: Int) = """{"log":{"level":"error"},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":$port}],"outbounds":[{"type":"direct","tag":"direct"}]}"""
    private fun awaitListener(runtime: DesktopRuntimeProcess, port: Int) {
        repeat(100) {
            assertTrue(runtime.isAlive, "Captured child exited before listener readiness")
            if (runCatching { Socket("127.0.0.1", port).use { } }.isSuccess) return
            Thread.sleep(100)
        }
        fail("Owned loopback child did not become ready")
    }
    private fun privateStages(): Set<String> = Files.list(java.nio.file.Path.of(System.getenv("ProgramData"))).use { entries ->
        entries.map { it.fileName.toString() }.filter { it.startsWith("vpn-control-vpn-") }.toList().toSet()
    }
    private fun assertStagesRemoved(previous: Set<String>) {
        repeat(40) { if (privateStages().minus(previous).isEmpty()) return; Thread.sleep(100) }
        assertTrue(privateStages().minus(previous).isEmpty(), "Confirmed terminal child left private input staging")
    }
}
