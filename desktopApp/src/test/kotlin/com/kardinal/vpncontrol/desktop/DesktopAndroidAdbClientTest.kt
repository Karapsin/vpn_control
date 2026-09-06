package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class DesktopAndroidAdbClientTest {
    @Test fun publicLocationAddUpdateAndSelectBindOwnerAndKeepInputPrivate() = fixture { client, root ->
        val input = root.resolve("location 東京.json").also { Files.writeString(it, "socks://127.0.0.1:1080#PRIVATE_LOCATION") }
        for ((arguments, operation) in listOf(
            listOf("locations", "add", "--input", input.toString()) to ControlOperationId.LOCATIONS_ADD,
            listOf("locations", "update", "2", "--input", input.toString()) to ControlOperationId.LOCATIONS_UPDATE,
            listOf("select", "2") to ControlOperationId.LOCATIONS_SELECT,
            listOf("locations", "delete", "2") to ControlOperationId.LOCATIONS_DELETE,
            listOf("locations", "import", "--input", input.toString()) to ControlOperationId.LOCATIONS_IMPORT)) {
            val output = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs((listOf("--android", "--json") + arguments).toTypedArray(),
                printLine = output::add, androidRequest = client::request))
            val sent = ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request")))
            assertEquals(operation, sent.command.operation); assertEquals("android-test-owner", sent.controllerId)
            if (operation !in setOf(ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_IMPORT)) assertEquals(ControlValue.Text("2"), sent.command.arguments["selector"])
            if (operation !in setOf(ControlOperationId.LOCATIONS_SELECT, ControlOperationId.LOCATIONS_DELETE)) assertEquals(ControlValue.Text("socks://127.0.0.1:1080#PRIVATE_LOCATION"), sent.command.arguments["input"])
        }
        assertFalse(Files.readString(root.resolve("argv")).contains("PRIVATE_LOCATION"))
    }

    @Test fun publicSubscriptionCommandsReachAuthenticatedProviderWithContentOnlyInStdin() = fixture { client, root ->
        val input = root.resolve("subscription 東京.txt").also { Files.writeString(it, "https://private.invalid/token") }
        val commands = listOf(
            listOf("add", "--input", input.toString(), "--name", "東京"),
            listOf("update", "stable-id", "--source", "https://private.invalid/new", "--name", ""),
            listOf("delete", "stable-id"))
        val operations = listOf(ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE, ControlOperationId.SUBSCRIPTIONS_DELETE)
        commands.forEachIndexed { index, arguments ->
            val output = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs((listOf("--android", "--json", "subscriptions") + arguments).toTypedArray(),
                printLine = output::add, androidRequest = client::request))
            val sent = ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request")))
            assertEquals(operations[index], sent.command.operation)
            assertEquals("android-test-owner", sent.controllerId)
            if (index == 0) assertEquals(ControlValue.Text("https://private.invalid/token"), sent.command.arguments["input"])
            else assertEquals(ControlValue.Text("stable-id"), sent.command.arguments["id"])
            assertEquals(ControlCode.OK, ControlProtocolCodec.decodeResult(output.single()).code)
        }
        assertFalse(Files.readString(root.resolve("argv")).contains("private.invalid"))
    }

    @Test fun publicSourceCommandsBindOwnerAndPreserveExplicitGuardsThroughRealTransport() = fixture { client, root ->
        for (arguments in listOf(listOf("current-locations"), listOf("subscription", "subscription-東京"), listOf("all"))) {
            val output = mutableListOf<String>()
            assertEquals(0, DesktopCli.handleArgs((listOf("--android", "--json", "source", "set") + arguments).toTypedArray(),
                printLine = output::add, androidRequest = client::request))
            val sent = ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request")))
            assertEquals(ControlOperationId.SOURCE_SET, sent.command.operation)
            assertEquals("android-test-owner", sent.controllerId)
            assertNull(sent.ifRevision)
            assertEquals(ControlValue.Text(arguments.first()), sent.command.arguments["source"])
            assertEquals(arguments.getOrNull(1)?.let(ControlValue::Text), sent.command.arguments["subscription-id"])
            assertEquals(ControlCode.OK, ControlProtocolCodec.decodeResult(output.single()).code)
        }
        val output = mutableListOf<String>()
        assertEquals(0, DesktopCli.handleArgs(arrayOf("--android", "--json", "--controller-id", "android-test-owner", "--if-revision", "7",
            "source", "set", "all"), printLine = output::add, androidRequest = client::request))
        assertEquals(7L, ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).ifRevision)
        output.clear()
        assertEquals(ControlCode.CONFLICT.exitCode, DesktopCli.handleArgs(arrayOf("--android", "--json", "--controller-id", "old-owner", "--if-revision", "7",
            "source", "set", "current-locations"), printLine = output::add, androidRequest = client::request))
        assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(output.single()).code)
        assertEquals("old-owner", ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).controllerId)
        assertFalse(Files.readString(root.resolve("argv")).contains("subscription-東京"))
    }

    @Test fun sourceWithoutAuthenticatedOwnerNeverWritesRequest() = fixture("no-owner") { client, root ->
        val source = ControlRequest("source", ControlCommand(ControlOperationId.SOURCE_SET, mapOf("source" to ControlValue.Text("all"))))
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL, ControlProtocolCodec.decodeResult(client.request(source, null, 20).message).code)
        assertFalse(Files.exists(root.resolve("request")))
    }

    @Test fun operationListAndCancelBindOnlyMissingOwner() = fixture { client, root ->
        for (operation in listOf(ControlOperationId.OPERATIONS_LIST, ControlOperationId.OPERATIONS_CANCEL)) {
            val request = ControlRequest("operation-${operation.wireName}", ControlCommand(operation,
                if (operation == ControlOperationId.OPERATIONS_CANCEL) mapOf("id" to ControlValue.Text("target")) else emptyMap()))
            assertEquals(0, client.request(request, null, 20).exitCode)
            assertEquals("android-test-owner", ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).controllerId)
            val stale = request.copy(controllerId = "previous-owner")
            assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(client.request(stale, null, 20).message).code)
            assertEquals(stale, ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))))
        }
    }
    @Test fun interactiveRuntimeLaunchesOnlyProtectedOpaqueActivityThenWaitsForSameOperation() = fixture("interactive") { client, root ->
        val on = ControlRequest("interactive-on", ControlCommand(ControlOperationId.ON), interactive = true)
        val result = ControlProtocolCodec.decodeResult(client.request(on, null, 20).message)
        assertEquals(ControlCode.OK, result.code)
        assertEquals(on.requestId, result.requestId)
        val argv = Files.readString(root.resolve("argv"))
        assertEquals(1, argv.lineSequence().count { it.contains("\tam\tstart\t") })
        assertTrue(argv.contains("com.kardinal.vpncontrol/.AndroidControlInteractionActivity"))
        assertFalse(argv.contains("keyevent") || argv.contains("run-as") || argv.contains("\tgrant\t"))
        val last = ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request")))
        assertEquals(ControlOperationId.OPERATIONS_STATUS, last.command.operation)
        assertEquals("android-test-owner", last.controllerId)
    }

    @Test fun noninteractiveRuntimeNeverLaunchesAnActivity() = fixture("interaction-required") { client, root ->
        val on = ControlRequest("no-interaction", ControlCommand(ControlOperationId.ON))
        assertEquals(ControlCode.INTERACTION_REQUIRED, ControlProtocolCodec.decodeResult(client.request(on, null, 20).message).code)
        assertFalse(Files.readString(root.resolve("argv")).contains("\tam\t"))
    }

    @Test fun interactiveInstallUsesProtectedTokenContinuationAndNoninteractiveDoesNotLaunch() {
        fixture("interactive") { client, root ->
            val request = ControlRequest("interactive-install", ControlCommand(ControlOperationId.UPDATES_INSTALL), interactive = true)
            val result = ControlProtocolCodec.decodeResult(client.request(request, null, 20).message)
            assertEquals(ControlCode.OK, result.code)
            assertEquals(request.requestId, result.requestId)
            val argv = Files.readString(root.resolve("argv"))
            assertEquals(1, argv.lineSequence().count { it.contains("\tam\tstart\t") })
            assertFalse(argv.contains(".apk") || argv.contains("\tgrant\t"))
        }
        fixture("interaction-required") { client, root ->
            val request = ControlRequest("install", ControlCommand(ControlOperationId.UPDATES_INSTALL))
            assertEquals(ControlCode.INTERACTION_REQUIRED, ControlProtocolCodec.decodeResult(client.request(request, null, 20).message).code)
            assertFalse(Files.readString(root.resolve("argv")).contains("\tam\tstart\t"))
            assertEquals("android-test-owner", ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).controllerId)
        }
    }
    @Test fun offBindsMissingOwnerButPreservesExplicitStaleEpoch() = fixture { client, root ->
        val off = ControlRequest("off-request", ControlCommand(ControlOperationId.OFF))
        assertEquals(0, client.request(off, null, 20).exitCode)
        assertEquals("android-test-owner", ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).controllerId)
        val stale = off.copy(controllerId = "previous-owner")
        assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(client.request(stale, null, 20).message).code)
        assertEquals(stale, ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))))
    }
    private fun fixture(mode: String = "normal", action: (DesktopAndroidAdbClient, Path) -> Unit) {
        val root = Files.createTempDirectory("fake-adb-東京 space")
        val javaExecutable = Path.of(System.getProperty("java.home"), "bin",
            if (System.getProperty("os.name").lowercase().contains("windows")) "java.exe" else "java")
        val classes = Path.of(FakeAdbMain::class.java.protectionDomain.codeSource.location.toURI())
        val classpath = classes.toString() + java.io.File.pathSeparator + requireNotNull(System.getProperty("vpnControl.test.mainClasspath"))
        // Java17's Windows launcher converts Unicode argv through the active ANSI code page.
        // Keep the fixture path Unicode on disk, but bootstrap it as ASCII; production data still
        // travels through genuine stdin/UTF8 and the packaged launcher has its own manifest tests.
        val rootArgument = "base64:" + java.util.Base64.getEncoder().encodeToString(root.toString().toByteArray(Charsets.UTF_8))
        val process = DesktopAdbProcess(listOf(javaExecutable.toString(), "-cp", classpath, FakeAdbMain::class.java.name, rootArgument, mode))
        try { action(DesktopAndroidAdbClient(process::execute), root) }
        finally { root.toFile().deleteRecursively() }
    }

    private fun request() = ControlRequest("test-request", ControlCommand(ControlOperationId.SETTINGS_SET,
        mapOf("key" to ControlValue.Text("ssh.host"), "value" to ControlValue.Text("private-secret-東京"))))

    @Test fun realSubprocessTransfersContentOnlyThroughStdinThenDiscardsOpaqueTransfer() = fixture { client, root ->
        val response = client.request(request(), null, 20)
        assertEquals(0, response.exitCode)
        val result = ControlProtocolCodec.decodeResult(response.message)
        assertEquals("東京", (result.data["echo"] as ControlValue.Text).value)
        assertEquals("test-request", result.requestId)
        val arguments = Files.readString(root.resolve("argv"))
        assertFalse(arguments.contains("private-secret"))
        assertTrue(arguments.contains("shell\t-T\tcontent"))
        assertTrue(arguments.contains("discard"))
        assertEquals(request().copy(controllerId = "android-test-owner"), ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))))
    }

    @Test fun explicitStaleOwnerIsNeverReboundToCurrentProvider() = fixture { client, root ->
        val stale = request().copy(controllerId = "previous-owner")
        assertEquals(ControlCode.CONFLICT, ControlProtocolCodec.decodeResult(client.request(stale, null, 20).message).code)
        assertEquals(stale, ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))))
    }

    @Test fun sshKeyImportBindsOwnerAndKeepsPayloadOutOfProcessArguments() = fixture { client, root ->
        val key = ControlRequest("key-request", ControlCommand(ControlOperationId.SSH_KEY_IMPORT,
            mapOf("input" to ControlValue.Text("PRIVATE_KEY_SECRET"))))
        assertEquals(0, client.request(key, null, 20).exitCode)
        assertEquals(key.copy(controllerId = "android-test-owner"),
            ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))))
        assertFalse(Files.readString(root.resolve("argv")).contains("PRIVATE_KEY_SECRET"))
    }

    @Test fun settingsRequireCreateOwnerButLegacyReadTransportRemainsCompatible() = fixture("no-owner") { client, root ->
        assertEquals(ControlCode.INCOMPATIBLE_PROTOCOL,
            ControlProtocolCodec.decodeResult(client.request(request(), null, 20).message).code)
        assertFalse(Files.exists(root.resolve("request")))
        val read = ControlRequest("read", ControlCommand(ControlOperationId.SETTINGS_SHOW))
        assertEquals(0, client.request(read, null, 20).exitCode)
        assertNull(ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request"))).controllerId)
    }

    @Test fun choosesExactlyOneAuthorizedDeviceAndNeverFallsBackFromExplicitSerial() {
        assertEquals("ready", DesktopAndroidAdbClient.selectDevice("List of devices attached\nready\tdevice\nother\tunauthorized\n", null))
        assertEquals("second", DesktopAndroidAdbClient.selectDevice("List of devices attached\nfirst\tdevice\nsecond\tdevice\n", "second"))
        for ((text, serial) in listOf(
            "List of devices attached\n" to null,
            "List of devices attached\nfirst\tdevice\nsecond\tdevice\n" to null,
            "List of devices attached\nready\tdevice\nother\toffline\n" to "other",
            "List of devices attached\nready\tdevice\n" to "missing",
        )) assertFails { DesktopAndroidAdbClient.selectDevice(text, serial) }
        fixture("multiple") { client, root ->
            assertEquals(2, client.request(request(), null, 20).exitCode)
            assertEquals("devices\n", Files.readString(root.resolve("argv")))
            assertEquals(0, client.request(request(), "second", 20).exitCode)
        }
    }

    @Test fun providerErrorsBadUtf8AndMismatchedRepliesAreSanitized() {
        for ((mode, code) in listOf("permission" to ControlCode.PERMISSION_DENIED,
                "bad-uri" to ControlCode.INCOMPATIBLE_PROTOCOL, "wrong-id" to ControlCode.INCOMPATIBLE_PROTOCOL,
                "bad-utf8" to ControlCode.INCOMPATIBLE_PROTOCOL)) {
            fixture(mode) { client, root ->
                val result = ControlProtocolCodec.decodeResult(client.request(request(), null, 20).message)
                assertEquals(code, result.code, mode)
                assertFalse(result.toString().contains("private-secret"))
                if (mode in setOf("wrong-id", "bad-utf8")) assertTrue(Files.readString(root.resolve("argv")).contains("discard"))
                if (mode == "bad-uri") assertFalse(Files.readString(root.resolve("argv")).contains("write"))
            }
        }
    }

    @Test fun timeoutDoesNotReplayOrCancelTheProviderOperation() = fixture("pending") { client, root ->
        val result = ControlProtocolCodec.decodeResult(client.request(request(), null, 3).message)
        assertEquals(ControlCode.TIMEOUT, result.code)
        assertFalse(result.final)
        val commands = Files.readAllLines(root.resolve("argv"))
        assertEquals(1, commands.count { it.contains("\twrite\t") })
        assertTrue(commands.any { it.contains("discard") })
        assertFalse(commands.any { it.contains("cancel") || it.contains("kill-server") })
    }
}

/** Test-owned portable subprocess impersonating adb. Never invokes Android, a shell, or a device. */
object FakeAdbMain {
    @JvmStatic fun main(args: Array<String>) {
        val root = decodeRoot(args[0])
        val mode = args[1]
        val command = args.drop(2)
        Files.writeString(root.resolve("argv"), command.joinToString("\t") + "\n",
            java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND)
        Files.writeString(root.resolve("pid"), ProcessHandle.current().pid().toString())
        if (mode == "flood") { System.out.write(ByteArray(1_048_578)); return }
        if (mode == "stall") { Thread.sleep(60_000); return }
        fun output(text: String) { System.out.write(text.toByteArray(Charsets.UTF_8)); System.out.flush() }
        if (command == listOf("devices")) {
            output("List of devices attached\nfirst\tdevice\n" + if (mode == "multiple") "second\tdevice\n" else "")
            return
        }
        if (command.getOrNull(4) == "am") {
            check(mode == "interactive")
            Files.writeString(root.resolve("activity-started"), "yes")
            output("Starting: Intent { cmp=com.kardinal.vpncontrol/.AndroidControlInteractionActivity }\nStatus: ok\n")
            return
        }
        check(command.take(5).let { it[0] == "-s" && it.drop(2) == listOf("shell", "-T", "content") })
        val id = "5e488dfb-6d5f-4f04-883c-582047af8793"
        val uri = "content://com.kardinal.vpncontrol.control"
        when (command[5]) {
            "call" -> when (command[9]) {
                "create" -> if (mode == "permission") {
                    System.err.print("SecurityException private-secret path")
                } else output("Result: Bundle[{id=$id, requestUri=${if (mode == "bad-uri") "evil;command" else "$uri/requests/$id"}, resultUri=$uri/results/$id${if (mode == "no-owner") "" else ", controllerId=android-test-owner"}}]\n")
                "status" -> output("Result: Bundle[{state=${if (mode == "pending") "pending" else "complete"}}]\n")
                "interaction" -> output("Result: Bundle[{state=waiting, token=9ceba854-65c2-4a19-b93d-372b4c9474a0}]\n")
                "discard" -> output("Result: Bundle[{}]\n")
                else -> error("Unexpected test method")
            }
            "write" -> Files.write(root.resolve("request"), System.`in`.readAllBytes())
            "read" -> if (mode == "bad-utf8") System.out.write(byteArrayOf(0xC3.toByte(), 0x28)) else {
                val request = ControlProtocolCodec.decodeRequest(Files.readString(root.resolve("request")))
                if (mode == "interaction-required") {
                    output(ControlProtocolCodec.encodeResult(ControlResult("android-test-owner", request.requestId, ControlCode.INTERACTION_REQUIRED, 0)))
                    return
                }
                if (mode == "interactive") {
                    val complete = request.command.operation == ControlOperationId.OPERATIONS_STATUS && Files.exists(root.resolve("activity-started"))
                    output(ControlProtocolCodec.encodeResult(ControlResult("android-test-owner", request.requestId,
                        if (complete) ControlCode.OK else ControlCode.ACCEPTED, 0, final = complete,
                        operationId = "22a658de-80b4-45e9-b72e-8a1907baf861",
                        data = mapOf("phase" to ControlValue.Text(if (complete) "succeeded" else "awaiting-user")))))
                    return
                }
                output(ControlProtocolCodec.encodeResult(ControlResult("android-test-owner",
                    if (mode == "wrong-id") "wrong" else request.requestId,
                    if (request.controllerId != null && request.controllerId != "android-test-owner") ControlCode.CONFLICT else ControlCode.OK, 0,
                    data = mapOf("echo" to ControlValue.Text("東京")))))
            }
            else -> error("Unexpected test adb command")
        }
    }

    internal fun decodeRoot(argument: String): Path = Path.of(if (argument.startsWith("base64:"))
        java.util.Base64.getDecoder().decode(argument.removePrefix("base64:")).toString(Charsets.UTF_8) else argument)
}
