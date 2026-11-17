package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.util.Base64
import java.util.concurrent.TimeUnit
import org.junit.Assume.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
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
            if (!body.contains("if(!RevertToSelf()) throw")) problems += "the privilege scope does not revert the thread, or ignores a failed revert"
            if (!Regex("""if\s*\(\s*error\s*!=\s*AccessDenied\s*\)\s*return\s+IntPtr\.Zero""").containsMatchIn(body))
                problems += "the privileged retry is not limited to an ACCESS_DENIED plain open"
        }
        assertTrue(problems.isEmpty(), problems.joinToString("\n"))
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
        assertTrue(output.endsWith("BROKER_OWNER_ACCESS_OK:6"), output)
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
