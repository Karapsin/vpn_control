package com.kardinal.vpncontrol

import androidx.datastore.preferences.core.stringPreferencesKey
import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.data.*
import com.kardinal.vpncontrol.model.*
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test

class AndroidRoutingConsecutiveMemoryTest {
    @Test fun consecutiveFullEditsRetainExactOperationResultsWithin48MiB() {
        val classpath = requireNotNull(System.getProperty("vpnControl.test.runtimeClasspath"))
        val directory = java.nio.file.Files.createTempDirectory("android-routing-consecutive-memory-").toFile()
        val process = ProcessBuilder(File(System.getProperty("java.home"), "bin/java").path,
            "-Xmx48m", "-XX:+UseSerialGC", "-XX:+HeapDumpOnOutOfMemoryError",
            "-Djava.library.path=${System.getProperty("java.library.path")}",
            "-XX:HeapDumpPath=${File(directory, "heap.hprof")}",
            "-Xlog:exceptions=info:file=${File(directory, "exceptions.log")}",
            "-cp", classpath, AndroidRoutingConsecutiveMemoryProbe::class.java.name, directory.path)
            .redirectErrorStream(true).start()
        var passed = false
        try {
            assertTrue("Consecutive routing probe timed out; evidence=$directory", process.waitFor(120, TimeUnit.SECONDS))
            assertEquals("evidence=$directory\n" + process.inputStream.bufferedReader().readText(), 0, process.exitValue())
            // Each complete result is checked outside the owner heap. Waiting
            // must recover the original data and revision, not current settings.
            for (pass in 0..2) {
                val result = ControlDocumentCodec.decodeResult(File(directory, "retained-$pass.json").readText())
                assertEquals(ControlCode.OK, result.code)
                assertEquals(pass + 1L, result.configurationRevision)
                val values = (result.data.getValue("direct-domains") as ControlValue.ArrayValue).values
                assertEquals(56_000, values.size)
                values.forEachIndexed { index, value ->
                    assertEquals(AndroidRoutingConsecutiveMemoryProbe.domain(pass, index), (value as ControlValue.Text).value)
                }
            }
            passed = true
        } finally {
            if (process.isAlive) process.destroyForcibly()
            if (passed) directory.deleteRecursively()
        }
    }
}

/** Same-owner heap proxy with real DataStore, retained results and canonical GUI draft publication. */
object AndroidRoutingConsecutiveMemoryProbe {
    private const val count = 56_000
    private val suffix = "a".repeat(62) + "." + "b".repeat(62) + "." + "c".repeat(62) + ".example.test"
    internal fun domain(pass: Int, index: Int): String =
        "${if (index == 0) ('a'.code + pass).toChar() else 'd'}${index.toString().padStart(5, '0')}.$suffix"

    @JvmStatic fun main(arguments: Array<String>) = runBlocking {
        val directory = File(arguments.single())
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val ui = Array(8) { ByteArray(1024 * 1024) { (it % 127).toByte() } }
        try {
            val key = stringPreferencesKey("direct_domain_suffixes")
            val dataStore = androidx.datastore.core.DataStoreFactory.create(
                serializer = AndroidPreferencesSerializer(directory.toPath()), scope = scope,
            ) { File(directory, "preferences.pb") }
            val storage = AndroidConfigurationStore(dataStore, { preferences ->
                PersistedState(routingRules = RoutingRules(directDomainSuffixes = AndroidPersistedDomainSuffixes.decode(preferences[key])))
            }, "owner")
            val controller = MainController(MainUiState(currentScreen = AppScreen.ROUTING_RULES))
            val control = AndroidSettingsControl("owner", scope, storage::snapshot,
                { _, _, _ -> error("not settings") }, {}, { false }, routingImport = { rules, epoch, revision ->
                    println("stage=write-start revision=$revision domains=${rules.domainCount}")
                    val committed = try {
                        storage.editProjected(epoch, revision) { preferences, prior ->
                            if (rules.matches(prior.routingRules)) rules.discard()
                            else preferences[key] = rules.consume { AndroidControlTransferSpool.create(directory.toPath()) }.directDomainSuffixes
                        }
                    } catch (failure: OutOfMemoryError) {
                        failure.printStackTrace(System.out)
                        throw failure
                    }
                    AndroidSettingsCommit(committed, false)
                }, retainedResults = AndroidRetainedControlResults { AndroidControlTransferSpool.create(directory.toPath()) })
            val identities = mutableListOf<String>()
            repeat(3) { pass ->
                println("stage=full-edit-$pass-start heapUsed=${Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory()}")
                identities += import(control, directory, pass)
                val committed = storage.snapshot()
                controller.mergePersistedState(committed.value)
                controller.applyImportedRoutingRules(committed.value.routingRules)
                check(controller.currentState().routingDirectDomainSuffixesDraft === committed.value.routingRules.directDomainSuffixes)
                check(committed.revision == pass + 1L)
                // A full readback runs while both the current GUI state and prior
                // successful operation results remain owned by the same process.
                File(directory, "readback-$pass.json").bufferedWriter().use { output ->
                    RoutingRulesTransfer.writeExport(controller.currentState().routingRules, "1970-01-01T00:00:00Z", output)
                }
                println("stage=full-edit-$pass-committed revision=${committed.revision}")
            }
            identities.forEachIndexed { pass, id -> retained(control, directory, pass, id) }
            check(ui.sumOf { it.size } == 8 * 1024 * 1024 && ui.all { it.last() == ((it.size - 1) % 127).toByte() })
            check(controller.currentState().routingDirectDomainSuffixesDraft?.size == count)
            println("consecutive-full-edits-and-retained-results domains=$count heapLimit=${Runtime.getRuntime().maxMemory()}")
        } finally { scope.cancel() }
    }

    /** Return only small operation identity so caller locals do not pin old payloads. */
    private suspend fun import(control: AndroidSettingsControl, directory: File, pass: Int): String {
        val input = AndroidControlInputSpool(AndroidControlTransferSpool.create(directory.toPath()))
        input.append("{\"direct_domain_suffixes\":[")
        repeat(count) { index ->
            if (index != 0) input.append(',')
            input.append('"').append(domain(pass, index)).append('"')
        }
        input.append("]}"); input.seal()
        check(input.length > 11 * 1024 * 1024)
        val request = ControlRequest("edit-$pass", ControlCommand(ControlOperationId.ROUTING_IMPORT),
            controllerId = "owner", ifRevision = pass.toLong())
        val result = control.admitRoutingDocument(request, input).await()
        check(result.code == ControlCode.OK && result.configurationRevision == pass + 1L) {
            "Full edit pass=$pass failed: ${result.code} ${result.warnings}"
        }
        return requireNotNull(result.operationId)
    }

    private suspend fun retained(control: AndroidSettingsControl, directory: File, pass: Int, operationId: String) {
        val result = control.execute(ControlRequest("wait-$pass", ControlCommand(ControlOperationId.OPERATIONS_WAIT,
            mapOf("id" to ControlValue.Text(operationId))), controllerId = "owner"))
        check(result.code == ControlCode.OK && result.configurationRevision == pass + 1L)
        File(directory, "retained-$pass.json").bufferedWriter().use { ControlDocumentCodec.writeResult(result, it) }
    }
}
