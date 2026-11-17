package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A standard user approves the broker's UAC prompt with another administrator's credentials (over-the-shoulder
 * elevation), so the broker runs as that administrator. The standard user's process DACL never grants another
 * account PROCESS_DUP_HANDLE, so the broker's plain OpenProcess(0x101040) of its owner was denied and it exited
 * before its pipe existed: approved scoped-TUN starts ended RUNTIME_FAILED with A untouched.
 */
class DesktopWindowsBrokerOwnerAccessTest {
    @Test fun theBrokerAndItsAdmissionOpenTheOwnerOnlyThroughTheOverTheShoulderFallback() {
        val broker = code("windows-vpn-broker.cs")
        val admission = code("windows-vpn-helper-admission.cs")
        val fallback = classBody(broker, "VpnBrokerOwnerProcess")
        val problems = mutableListOf<String>()
        for ((name, text) in listOf("windows-vpn-broker.cs" to broker, "windows-vpn-helper-admission.cs" to admission)) {
            for (call in Regex("""(?<![\w.])OpenProcess\s*\(""").findAll(text)) {
                if (name != "windows-vpn-broker.cs" || fallback == null || call.range.first !in fallback)
                    problems += "$name opens a process outside VpnBrokerOwnerProcess: ${line(text, call.range.first)}"
            }
        }
        if (!Regex("""VpnBrokerOwnerProcess\.Open\(\s*ownerPid\s*,\s*0x101040\s*,""").containsMatchIn(broker))
            problems += "VpnRuntimeBroker.Run does not open its owner (SYNCHRONIZE, QUERY_LIMITED, DUP_HANDLE) through the fallback"
        if (!Regex("""VpnBrokerOwnerProcess\.Open\(\s*pid\s*,\s*0x00101000\s*,""").containsMatchIn(admission))
            problems += "VpnPackagedBrokerAdmission.OpenOwner does not open its owner through the fallback"
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test fun theDebugPrivilegeIsEnabledOnlyOnAThreadTokenOfTheBrokersOwnIdentity() {
        val compiled = Regex("""<Compile\s+Include="[^"$]*\\([^"\\$]+\.cs)"""")
            .findAll(Files.readString(projectFile("desktopApp/native/windows/VpnBroker/VpnBroker.csproj")))
            .map { it.groupValues[1] }.toList()
        assertTrue("windows-vpn-broker.cs" in compiled, compiled.toString())
        val broker = code("windows-vpn-broker.cs")
        val fallback = classBody(broker, "VpnBrokerOwnerProcess")
        val problems = mutableListOf<String>()
        if (fallback == null) problems += "windows-vpn-broker.cs has no VpnBrokerOwnerProcess"
        for (name in compiled) {
            val text = code(name)
            for (use in Regex("""AdjustTokenPrivileges\s*\(|SeDebugPrivilege|\bSetThreadToken\s*\(""").findAll(text)) {
                if (name != "windows-vpn-broker.cs" || fallback == null || use.range.first !in fallback)
                    problems += "$name changes privileges outside the owner fallback: ${line(text, use.range.first)}"
            }
            for (open in Regex("""OpenProcessToken\s*\(\s*GetCurrentProcess\s*\(\s*\)\s*,\s*(\w+)""").findAll(text)) {
                val access = open.groupValues[1].let { if (it.startsWith("0x")) it.drop(2).toLong(16) else it.toLongOrNull() }
                if (access == null || access and 0x20L != 0L)
                    problems += "$name may adjust the process token, which the runtime child inherits: ${line(text, open.range.first)}"
            }
        }
        if (fallback != null) {
            val body = broker.substring(fallback.first, fallback.last + 1)
            val impersonate = body.indexOf("ImpersonateSelf(2)")
            val thread = body.indexOf("OpenThreadToken(GetCurrentThread(),0x28,true,")
            val adjust = body.indexOf("AdjustTokenPrivileges(token,")
            if (impersonate < 0 || thread < impersonate || adjust < thread)
                problems += "SeDebugPrivilege is not enabled on this thread's own impersonation token"
            if (!body.contains("if(!RevertToSelf()) Environment.FailFast(")) problems += "the privilege scope does not revert the thread, or survives a failed revert"
            if (!Regex("""if\s*\(\s*error\s*!=\s*AccessDenied\s*\)\s*return\s+IntPtr\.Zero""").containsMatchIn(body))
                problems += "the privileged retry is not limited to an ACCESS_DENIED plain open"
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    @Test fun theClientReadsTheExitedBrokersStepAfterAbortAndBeforeClose() {
        val order = mutableListOf<String>()
        val unresolved = { error("no unresolved runtime") }
        val gone = desktopWindowsPreparationFailure(IllegalStateException("UNAVAILABLE"),
            DesktopWindowsRuntimePreparationStage.HELPER_CONNECTION, abort = { order += "abort"; true },
            close = { order += "close" }, unresolved = unresolved, brokerExit = { order += "exit"; 21 })
        assertEquals(listOf("abort", "exit", "close"), order, "the exit code must be read before close releases the handle")
        assertEquals("UNAVAILABLE", gone.code)
        assertEquals(21, gone.brokerExit)
        assertEquals("scoped Windows broker ended at step owner-token (exit 21, stage HELPER_CONNECTION, code UNAVAILABLE)",
            DesktopWindowsBrokerExit.describe(gone))
        val reported = desktopWindowsPreparationFailure(DesktopWindowsRuntimeFailure("PERMISSION_DENIED",
            stage = DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS), DesktopWindowsRuntimePreparationStage.CAPTURED_INPUTS,
            abort = { true }, close = {}, unresolved = unresolved, brokerExit = { 34 })
        assertEquals("PERMISSION_DENIED", reported.code)
        assertEquals("job", DesktopWindowsBrokerExit.step(assertNotNull(reported.brokerExit)))
        val original = DesktopWindowsRuntimeFailure("PERMISSION_DENIED")
        assertSame(original, original.withBrokerExit(34).cause, "the diagnostic copy lost the original failure")
        assertSame(original, original.withBrokerExit(null), "no exit, no copy")
        var read = false
        val unknown = desktopWindowsPreparationFailure(IllegalStateException("UNAVAILABLE"),
            DesktopWindowsRuntimePreparationStage.HELPER_CONNECTION, abort = { false }, close = {},
            unresolved = { object : DesktopRuntimeProcess {
                override val isAlive = true
                override fun pid() = 7L
                override fun destroy() = Unit
                override fun destroyForcibly() = Unit
                override fun waitFor(timeout: Long, unit: TimeUnit) = false
            } }, brokerExit = { read = true; 21 })
        assertEquals("OUTCOME_UNKNOWN", unknown.code)
        assertFalse(read, "a broker that may still run has no exit code")
        assertEquals("unclassified", DesktopWindowsBrokerExit.step(1))
        assertEquals("unknown", DesktopWindowsBrokerExit.step(259))
        val log = Files.createTempFile("vpn-broker-step-", ".log")
        try {
            assertEquals(DesktopWindowsBrokerExit.describe(gone), DesktopWindowsBrokerExit.record(gone, log))
            assertEquals("vpn-control: ${DesktopWindowsBrokerExit.describe(gone)}\n", Files.readString(log))
            assertNull(DesktopWindowsBrokerExit.record(DesktopWindowsRuntimeFailure("UNAVAILABLE"), log), "no exit, no line")
        } finally { Files.delete(log) }
    }

    @Test fun theClientStepTableIsTheBrokersExitCodes() {
        val broker = code("windows-vpn-broker.cs")
        val body = classBody(broker, "VpnBrokerStep")
        assertNotNull(body, "windows-vpn-broker.cs has no VpnBrokerStep")
        val declaration = Regex("""public\s+const\s+int\s+([^;]+);""").find(broker.substring(body.first, body.last + 1))
        val native = assertNotNull(declaration).groupValues[1].split(',').associate { item ->
            val (name, value) = item.split('=').map { it.trim() }
            value.toInt() to name.replace(Regex("(?<=[a-z])(?=[A-Z])"), "-").lowercase()
        } + (0 to "success")
        assertEquals(native.toSortedMap(), DesktopWindowsBrokerExit.STEPS.toSortedMap())
        assertEquals(native.size, native.keys.toSet().size)
    }

    @Test fun theBrokerEntersEachStepBeforeItsRefusalPoints() {
        fun steps(text: String, within: IntRange) = Regex("""VpnBrokerStep\.Enter\(VpnBrokerStep\.(\w+)\)""")
            .findAll(text.substring(within.first, within.last + 1)).map { it.groupValues[1] }.toList()
        fun method(text: String, declaration: String): IntRange {
            val start = Regex(declaration).find(text)?.range?.last ?: error("no $declaration")
            var depth = 0
            for (index in text.indexOf('{', start) until text.length) when (text[index]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return start..index
            }
            error("unclosed $declaration")
        }
        val broker = code("windows-vpn-broker.cs")
        assertEquals(listOf("OwnerOpen", "OwnerQuery", "OwnerIdentity", "OwnerToken", "OwnerIdentity", "PipeCreate", "PipeConnect", "Peer",
            "Protocol", "Job", "ResourcePreparation", "RuntimeImage", "Stage", "OriginalUser", "Stage", "Configuration",
            "ChildCreate", "ReadyAck", "Running"), steps(broker, method(broker, """public\s+static\s+void\s+Run\s*\(""")))
        val admission = code("windows-vpn-helper-admission.cs")
        assertEquals(listOf("OwnerOpen", "OwnerQuery", "OwnerIdentity", "PackageAdmission", "OwnerQuery", "OwnerIdentity", "Unclassified"),
            steps(admission, method(admission, """internal\s+static\s+Lease\s+Retain\s*\([^)]*Native\s+native\)""")))
        assertEquals(listOf("OwnerToken", "OwnerIdentity"),
            steps(admission, method(admission, """public\s+Owner\s+ObserveOwner\s*\(""")))
        val entry = code("windows-vpn-broker-main.cs")
        val execute = method(entry, """internal\s+static\s+int\s+Execute\s*\(""")
        assertEquals(listOf("Arguments", "RuntimeAuthority", "Unclassified"), steps(entry, execute))
        val returns = Regex("""return\s+([^;]+);""").findAll(entry.substring(execute.first, execute.last + 1)).map { it.groupValues[1] }.toList()
        assertEquals(listOf("0", "VpnBrokerStep.Current", "VpnBrokerStep.Current", "VpnBrokerStep.Current", "VpnBrokerStep.Current"), returns)
    }

    /**
     * Several Windows tests compile resources joined into one Add-Type unit. A using directive must precede every
     * other element of its namespace (CS1529), so a probe's file-level usings after the broker sources fail to
     * compile, and only on Windows. Check every such joined list here, on every OS.
     */
    @Test fun everyJoinedCompileUnitKeepsItsUsingDirectivesAheadOfTheOtherElementsOfTheirNamespace() {
        val root = listOf(java.nio.file.Path.of("src/test/kotlin"), java.nio.file.Path.of("desktopApp/src/test/kotlin"))
            .first(Files::isDirectory)
        val joined = Regex("""listOf\(((?:\s*"/?[\w.-]+\.cs"\s*,?)+)\s*\)\s*\.joinToString\(\s*"\\n"\s*\)""")
        val units = Files.walk(root).use { paths ->
            paths.filter { it.toString().endsWith(".kt") }.toList().flatMap { file ->
                joined.findAll(Files.readString(file)).map { match ->
                    file.fileName.toString() to Regex(""""/?([\w.-]+\.cs)"""").findAll(match.groupValues[1]).map { it.groupValues[1] }.toList()
                }.toList()
            }
        }
        assertTrue(units.any { "windows-vpn-broker-owner-probe.cs" in it.second }, units.toString())
        val problems = units.flatMap { (test, names) ->
            misplacedUsings(names.joinToString("\n") { name -> code(name) }).map { "$test joins ${names.joinToString()}: $it" }
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
    }

    /** Lines of a masked C# unit whose using directive follows another element of the same namespace. */
    private fun misplacedUsings(unit: String): List<String> {
        val directive = Regex("""^\s*using\s+(?:static\s+)?[A-Za-z_][\w.]*(?:\s*=\s*[\w.<>, ]+)?\s*;\s*$""")
        class Scope(val depth: Int) { var element = false }
        val scopes = ArrayDeque(listOf(Scope(0)))
        var depth = 0
        val problems = mutableListOf<String>()
        for ((index, line) in unit.lines().withIndex()) {
            val text = line.trim()
            if (text.isEmpty() || text.startsWith("extern alias")) Unit
            else if (directive.matches(line)) {
                if (scopes.last().element) problems += "line ${index + 1}: $text"
            } else {
                scopes.last().element = true
                if (Regex("""^namespace\s+[\w.]+\s*\{""").containsMatchIn(text)) scopes.addLast(Scope(depth + 1))
            }
            depth += line.count { it == '{' } - line.count { it == '}' }
            while (scopes.size > 1 && depth < scopes.last().depth) scopes.removeLast()
        }
        return problems
    }

    @Test fun theUsingGuardRejectsAFileLevelUsingAfterAnotherUnitsElements() {
        assertEquals(listOf("line 3: using System;"), misplacedUsings("public static class A { }\n\nusing System;\nclass B { }"))
        assertEquals(emptyList(), misplacedUsings("public static class A { }\nnamespace N {\n using System;\n class B { }\n}"))
        assertEquals(listOf("line 4: using System;"),
            misplacedUsings("namespace N {\n class B { void M() { using(var x=y) { } } }\n}\nusing System;"))
    }

    /** Fake identities through the compiled decision, then this process's own token through the real natives. */
    @Test fun theOwnerOpenRetriesOnlyADeniedOpenUnderARevertedThreadPrivilege() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val root = Files.createTempDirectory("vpn-broker-owner-")
        val report = root.resolve("probe.log")
        val source = listOf("/windows-vpn-broker.cs", "/windows-vpn-user-files.cs", "/windows-vpn-cache-resources.cs",
            "/windows-vpn-broker-owner-probe.cs").joinToString("\n") { resource ->
            requireNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes().decodeToString() }
        }
        val script = """
            ${'$'}ErrorActionPreference='Stop';${'$'}ProgressPreference='SilentlyContinue'
            Add-Type -TypeDefinition ([Console]::In.ReadToEnd()) -ReferencedAssemblies @('System.dll','System.Core.dll','System.Web.Extensions.dll')
            [Console]::Write([VpnBrokerFixtures.OwnerAccessProbe]::Run())
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).redirectOutput(report.toFile()).start()
        process.outputStream.use { it.write(source.encodeToByteArray()) }
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly() // Only this compiler and its own-process probe are owned.
            fail("Broker owner access probe timed out; evidence retained at $report")
        }
        val output = Files.newInputStream(report).use { it.readNBytes(8193).decodeToString().take(8192) }
        assertEquals(0, process.exitValue(), output)
        assertTrue(output.endsWith("BROKER_OWNER_ACCESS_OK:7"), output)
        Files.delete(report)
        Files.delete(root)
    }

    private fun projectFile(path: String) = listOf(java.nio.file.Path.of(path), java.nio.file.Path.of(path.removePrefix("desktopApp/")))
        .firstOrNull(Files::isRegularFile) ?: error("Missing $path")

    private fun line(text: String, at: Int) = text.substring(text.lastIndexOf('\n', at) + 1, text.indexOf('\n', at).let { if (it < 0) text.length else it }).trim()

    /** The braces of `class [name] {`, or null. Comments are masked by [code], so braces in them never count. */
    private fun classBody(text: String, name: String): IntRange? {
        val start = Regex("""\bclass\s+$name\s*\{""").find(text)?.range?.last ?: return null
        var depth = 0
        for (index in start until text.length) {
            when (text[index]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return start..index
            }
        }
        return null
    }

    /** The resource with comments and string/char literal contents blanked, offsets kept. */
    private fun code(name: String): String {
        val text = requireNotNull(javaClass.getResource("/$name")) { "Missing resource $name" }.readText()
        val out = StringBuilder(text)
        var index = 0
        fun blank(from: Int, to: Int) { for (i in from until minOf(to, text.length)) if (out[i] != '\n') out[i] = ' ' }
        while (index < text.length) {
            when {
                text.startsWith("//", index) -> { val end = text.indexOf('\n', index).let { if (it < 0) text.length else it }; blank(index, end); index = end }
                text.startsWith("/*", index) -> { val end = text.indexOf("*/", index + 2).let { if (it < 0) text.length else it + 2 }; blank(index, end); index = end }
                text.startsWith("@\"", index) -> {
                    var end = index + 2
                    while (end < text.length && !(text[end] == '"' && (end + 1 >= text.length || text[end + 1] != '"'))) end += if (text[end] == '"') 2 else 1
                    blank(index + 2, end); index = end + 1
                }
                text[index] == '"' || text[index] == '\'' -> {
                    val quote = text[index]
                    var end = index + 1
                    while (end < text.length && text[end] != quote) end += if (text[end] == '\\') 2 else 1
                    // Keep the privilege name readable: it is the one literal these checks look for.
                    if (text.substring(index + 1, minOf(end, text.length)) != "SeDebugPrivilege") blank(index + 1, end)
                    index = end + 1
                }
                else -> index++
            }
        }
        return out.toString()
    }
}
