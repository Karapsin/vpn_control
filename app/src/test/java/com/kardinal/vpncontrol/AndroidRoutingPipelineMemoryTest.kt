package com.kardinal.vpncontrol

import androidx.datastore.preferences.core.stringPreferencesKey
import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingPipelineMemoryTest {
    @Test fun largePersistedRoutingCanBuildRuntimeConfigWithin48MiB() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("android-routing-runtime-memory-").toFile()
        val log = File(directory, "runtime.log")
        try {
            val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
                "-Xmx48m", "-XX:+UseSerialGC",
                "-Djava.library.path=${System.getProperty("java.library.path")}",
                "-cp", classpath, AndroidRoutingPipelineMemoryProbe::class.java.name,
                directory.path, "original", "warm", "runtime")
                .redirectErrorStream(true).redirectOutput(log).start()
            try {
                assertTrue("Runtime configuration probe timed out", process.waitFor(90, TimeUnit.SECONDS))
                assertEquals(log.readText(), 0, process.exitValue())
                print(log.readText())
            } finally { if (process.isAlive) process.destroyForcibly() }
        } finally { directory.deleteRecursively() }
    }

    @Test fun fullRoutingDocumentUsesRealDataStoreWithin48MiBWithCompactingJvmCollector() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val evidence = java.nio.file.Files.createTempDirectory("android-routing-memory-evidence-").toFile()
        val persisted = java.nio.file.Files.createTempDirectory("android-routing-cold-store-").toFile()
        try { repeat(3) { pass ->
        // Pin the collector for this deterministic heap-budget proxy. Host G1's
        // humongous-region and test-classpath overhead differs from Android ART;
        // this does not replace the same 48 MiB chain on a nondebuggable API29 APK.
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:+UseSerialGC", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=${File(evidence, "heap.hprof")}",
            "-Djava.library.path=${System.getProperty("java.library.path")}",
            "-cp", classpath, AndroidRoutingPipelineMemoryProbe::class.java.name, persisted.path,
            if (pass == 2) "replace" else "original", if (pass == 1) "cold" else "warm")
            .redirectErrorStream(true).start()
        try {
            assertTrue("Pipeline probe timed out", process.waitFor(90, TimeUnit.SECONDS))
            assertEquals("Cold process pass=$pass: " + process.inputStream.bufferedReader().readText(), 0, process.exitValue())
        } finally { if (process.isAlive) process.destroyForcibly() }
        } } finally { persisted.deleteRecursively() }
    }
}

object AndroidRoutingPipelineMemoryProbe {
    @JvmStatic fun main(args: Array<String>) = runBlocking {
        val directory = args.firstOrNull()?.let(::File) ?: java.nio.file.Files.createTempDirectory("android-routing-pipeline-").toFile()
        val replacement = args.getOrNull(1) == "replace"
        val cold = args.getOrNull(2) == "cold"
        val expectedRevision = if (replacement) 2L else 1L
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        try {
            val input = File(directory, "input.json")
            fixture(input, replacement = replacement)
            val domains = stringPreferencesKey("direct_domain_suffixes")
            val disk = File(directory, "configuration.preferences_pb")
            val store = androidx.datastore.core.DataStoreFactory.create(serializer = AndroidPreferencesSerializer(directory.toPath()), scope = scope) { disk }
            val configuration = AndroidConfigurationStore(store, { prefs ->
                PersistedState(routingRules = RoutingRules(directDomainSuffixes =
                    AndroidPersistedDomainSuffixes.decode(prefs[domains])))
            }, "owner")
            // API29 starts a cold owner while framework/app allocations already consume
            // part of its 48 MiB growth limit. Hold a bounded equivalent through the
            // initial DataStore decode: stock protobuf decoding of a >11 MiB preference
            // must not require another full Java String at this point.
            // ART's running Activity, renderer, WorkManager and loaded app graph account
            // for about 24 MiB before the 11.7 MiB protobuf string allocation on API29.
            // This retained baseline makes the JVM subprocess exercise that same allocation
            // boundary without changing the 48 MiB budget or the transfer fixture.
            val coldPressure = if (cold) ByteArray(24 * 1024 * 1024) else null
            if (cold) {
                // Isolate the native failure boundary. This first read invokes the
                // configured Preferences serializer, before PersistedState mapping or
                // AndroidPersistedDomainSuffixes normalization can allocate anything.
                println("stage=cold-preferences-before heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
                store.data.first()
                println("stage=cold-preferences-after heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
                check(configuration.snapshot().value.routingRules.directDomainSuffixes.size == 56_000)
                check(coldPressure!![0] == 0.toByte())
                println("stage=cold-reopen-ready")
            }
            var raw: java.lang.ref.WeakReference<String>? = null
            val control = AndroidSettingsControl("owner", scope, configuration::snapshot,
                { _, _, _ -> error("not settings") }, {}, { false },
                routingImport = { rules, epoch, revision ->
                    println("stage=persistence domains=${rules.domainCount}")
                    println("rawReachable=${raw?.get() != null} heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
                    val committed = try {
                        configuration.editProjected(epoch, revision) { prefs, prior ->
                            if (rules.matches(prior.routingRules)) rules.discard()
                            else prefs[domains] = rules.consume { AndroidControlTransferSpool.create(directory.toPath()) }.directDomainSuffixes
                        }
                    } catch (failure: OutOfMemoryError) {
                        // Synthetic fixture only: identify the actual allocation stage.
                        failure.printStackTrace(System.out)
                        throw failure
                    }
                    println("stage=committed revision=${committed.revision}")
                    AndroidSettingsCommit(committed, false)
                })
            val observer = AndroidRuntimeObserver(initiallyStopped = true)
            val reader = AndroidControlReader("owner", { configuration.snapshot().value }, readTimeoutMillis = 80_000,
                committedSnapshot = {
                    try { configuration.snapshot() }
                    catch (failure: OutOfMemoryError) { println("stage=read-snapshot-oom"); failure.printStackTrace(System.out); throw failure }
                }, statusSnapshot = { state ->
                    try { observer.controlStatus(state) }
                    catch (failure: OutOfMemoryError) { println("stage=read-status-projection-oom"); failure.printStackTrace(System.out); throw failure }
                },
                pendingRestart = observer::pendingRestart,
                inputSpool = { AndroidControlInputSpool(AndroidControlTransferSpool.create(directory.toPath())) },
                routingDocumentAdmission = control::admitRoutingDocument,
                routingAdmission = { request ->
                    raw = java.lang.ref.WeakReference((request.command.arguments.getValue("input") as ControlValue.Text).value)
                    control.admitRoutingImport(request)
                }, operationIdForRequest = control::operationIdForRequest)
            AndroidControlDocuments("owner", { AndroidControlTransferSpool.create(directory.toPath()) }).use { documents ->
                val transfer = documents.begin(2000, java.util.UUID.randomUUID().toString())
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                var offset = 0L
                input.inputStream().use { source ->
                    val buffer = ByteArray(65536)
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        val chunk = buffer.copyOf(count)
                        documents.append(2000, transfer.id, offset, chunk)
                        digest.update(chunk); offset += count
                    }
                }
                documents.seal(2000, transfer.id, offset, digest.digest().joinToString("") { "%02x".format(it) })
                val result = requireNotNull(documents.claim(2000, transfer.id)).use { claimed ->
                    claimed.stream().use { reader.documentResult(it, transfer.id) }
                }
                check(result.code == ControlCode.OK) { "Pipeline did not commit successfully: ${result.code} ${result.warnings}" }
                documents.complete(2000, transfer.id, result)
                val output = documents.result(2000, transfer.id)
                check(output.byteCount > 10 * 1024 * 1024)
                check(disk.length() > 10 * 1024 * 1024)
                offset = 0L
                digest.reset()
                while (offset < output.byteCount) {
                    val chunk = documents.read(2000, transfer.id, offset, minOf(65536L, output.byteCount - offset).toInt())
                    digest.update(chunk.bytes); offset += chunk.bytes.size
                }
                check(output.sha256 == digest.digest().joinToString("") { "%02x".format(it) })
                println("stage=complete bytes=${output.byteCount}")
                for (operation in listOf(ControlOperationId.STATUS, ControlOperationId.ROUTING_SHOW, ControlOperationId.ROUTING_EXPORT)) {
                    val bytes = ControlDocumentCodec.encodeRequest(ControlRequest("read-${operation.wireName}", ControlCommand(operation))).toByteArray()
                    val read = reader.documentResponse(java.io.ByteArrayInputStream(bytes), "read")
                    check(read.result.code == ControlCode.OK && read.result.configurationRevision == expectedRevision) { "Read failed: ${operation.wireName} ${read.result.code}" }
                    val next = documents.begin(2000, java.util.UUID.randomUUID().toString())
                    documents.append(2000, next.id, 0, bytes)
                    documents.seal(2000, next.id, bytes.size.toLong(), java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
                    requireNotNull(documents.claim(2000, next.id)).close()
                    documents.complete(2000, next.id, read)
                    val manifest = documents.result(2000, next.id)
                    check(if (operation == ControlOperationId.STATUS) manifest.byteCount < 4096 else manifest.byteCount > 10 * 1024 * 1024)
                    println("stage=read-${operation.wireName} bytes=${manifest.byteCount}")
                    documents.discard(2000, next.id)
                }
                for (requestId in listOf("memory", "memory-noop")) {
                    fixture(input, requestId, replacement)
                    val retry = upload(documents, input)
                    val read = requireNotNull(documents.claim(2000, retry)).use { claimed ->
                        claimed.stream().use { reader.documentResult(it, retry) }
                    }
                    check(read.code == ControlCode.OK && read.configurationRevision == expectedRevision) {
                        "Retry failed: $requestId ${read.code} ${read.warnings}"
                    }
                    documents.complete(2000, retry, read)
                    check(documents.result(2000, retry).byteCount > 10 * 1024 * 1024)
                    println("stage=$requestId-replayed revision=${read.configurationRevision}")
                    documents.discard(2000, retry)
                }
            }
            if (args.getOrNull(3) == "runtime") {
                val state = configuration.snapshot().value
                check(state.routingRules.directDomainSuffixes.size == 56_000)
                println("stage=runtime-config-before heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
                val profile = ProxyProfile(protocol = ProxyProtocol.SOCKS, remarks = "Memory fixture",
                    server = "127.0.0.1", serverPort = 1080, username = "", password = "",
                    network = "tcp", flow = "", security = "", sni = "", fingerprint = "",
                    publicKey = "", shortId = "", path = "", hostHeader = "", serviceName = "",
                    headerType = "none", rawLink = "")
                val assets = AndroidDirectDomainRuleSetStore(File(directory, "runtime-rule-sets"))
                AndroidRuntimeConfigBuilder(assets).build(profile, state.dnsSettings, state.routingRules,
                    AppMode.VPN, null, null).use { built ->
                    check(built.json.length < 64 * 1024) // Domains live in the complete native source file.
                    val asset = requireNotNull(assets.acquireFromConfig(built.json))
                    asset.use {
                        val file = File(it.path)
                        check(file.length() > 10 * 1024 * 1024)
                        val expected = java.security.MessageDigest.getInstance("SHA-256")
                        expected.update("{\"version\":1,\"rules\":[{\"domain_suffix\":[".toByteArray())
                        state.routingRules.directDomainSuffixes.forEachIndexed { index, domain ->
                            expected.update((if (index == 0) "" else ",").toByteArray())
                            expected.update("\".$domain\"".toByteArray())
                        }
                        expected.update("]}]}".toByteArray())
                        val actual = java.security.MessageDigest.getInstance("SHA-256")
                        file.inputStream().use { input ->
                            val buffer = ByteArray(8192)
                            while (true) { val count = input.read(buffer); if (count < 0) break; actual.update(buffer, 0, count) }
                        }
                        check(java.security.MessageDigest.isEqual(expected.digest(), actual.digest()))
                    }
                    println("stage=runtime-config-after chars=${built.json.length}")
                }
            }
        } finally {
            scope.cancel()
            if (args.isEmpty()) directory.deleteRecursively()
        }
    }

    private fun upload(documents: AndroidControlDocuments, file: File): String {
        val transfer = documents.begin(2000, java.util.UUID.randomUUID().toString())
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        var offset = 0L
        file.inputStream().use { source ->
            val buffer = ByteArray(65536)
            while (true) {
                val count = source.read(buffer)
                if (count < 0) break
                val chunk = buffer.copyOf(count)
                documents.append(2000, transfer.id, offset, chunk)
                digest.update(chunk); offset += count
            }
        }
        documents.seal(2000, transfer.id, offset, digest.digest().joinToString("") { "%02x".format(it) })
        return transfer.id
    }

    private fun fixture(file: File, requestId: String = "memory", replacement: Boolean = false) {
        val marker = "PAYLOAD"
        val envelope = ControlDocumentCodec.encodeRequest(ControlRequest(requestId, ControlCommand(ControlOperationId.ROUTING_IMPORT,
            mapOf("input" to ControlValue.Text(marker))), controllerId = "owner"))
        val offset = envelope.indexOf(marker)
        val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
        file.bufferedWriter().use { writer ->
            writer.write(envelope.substring(0, offset))
            writer.write("{\\\"direct_domain_suffixes\\\":[")
            repeat(56_000) { index ->
                if (index != 0) writer.write(",")
                writer.write("\\\"${if (replacement && index == 0) "e" else "d"}$index.$suffix\\\"")
            }
            writer.write("]}")
            writer.write(envelope.substring(offset + marker.length))
        }
    }
}
