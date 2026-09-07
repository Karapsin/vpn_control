package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeFalse
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** Executes only the actual fixed parser or sh -n, never the privileged worker body. */
class DesktopLinuxInstallWorkerTest {
    @Test fun capturedWorkerCannotImpersonatePkexecAuthorizationRejection() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        // Substitute only the captured worker body with inert exit statements.
        // Execute the production wrapper; no privileged body ever runs.
        for (workerExit in listOf(0, 1, 125, 126, 127, 130)) {
            val arguments = DesktopLinuxCapturedInstallWorker.arguments(job, 123).toMutableList()
            assertTrue(arguments[4].contains("read_request()"))
            arguments[4] = "exit $workerExit"
            val process = ProcessBuilder(arguments).redirectErrorStream(true).start()
            process.outputStream.close()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS))
            assertEquals(if (workerExit in setOf(126, 127)) 125 else workerExit, process.exitValue(),
                "Worker exit $workerExit must not impersonate authorization rejection: " + process.inputStream.bufferedReader().readText())
        }
    }

    @Test fun debianInstallResolvesDependenciesWithoutGlobalRepairOrRemoval() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        // Execute the actual worker dispatch with inert shell functions. No package
        // manager, protected file, or privileged worker is executed by this regression.
        val dispatch = source().substringAfter("set +e\n").substringBefore("\ninstaller_result=")
        val script = """
            set -eu
            record_apt() { printf '%s\n' "apt-get" "${'$'}@"; }
            alias apt-get=record_apt
            dpkg() { printf '%s\n' "dpkg" "${'$'}@"; }
            package_type=deb
            verified_package='/protected/job/package.deb'
            $dispatch
        """.trimIndent()
        val process = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true).start()
        process.outputStream.close()
        assertTrue(process.waitFor(10, TimeUnit.SECONDS))
        val output = process.inputStream.bufferedReader().readText()
        assertEquals(0, process.exitValue(), output)
        assertEquals(listOf("apt-get", "--assume-yes", "--no-remove", "--no-install-recommends",
            "--reinstall", "install", "--", "/protected/job/package.deb"), output.trim().lines())
    }

    private val job = "00000000-0000-0000-0000-000000000001"
    private fun source() = DesktopLinuxCapturedInstallWorker.arguments(job, 123)[4]
    private fun parser() = source().substringAfter("read_request() {").substringBefore("\n}").let { "read_request() {$it\n}\n" }
    private fun request() = DesktopLinuxInstallRequest(job, 123, 456, 1000, "deb", "a".repeat(64), 12,
        "/home/user/\$(printf INJECTED); '東京'.deb", "/opt/vpn-control/bin/vpn-control", "/home/user/state")

    @Test fun fixedWorkerHasValidPosixShellSyntax() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        for (script in listOf(source(), DesktopLinuxCapturedInstallWorker.arguments(job, 123)[2],
            DesktopLinuxCapturedInstallWorker.watcherArguments(job, 123)[2])) {
        val process = ProcessBuilder("/bin/sh", "-n").redirectErrorStream(true).start()
        process.outputStream.use { it.write(script.encodeToByteArray()) }
        assertTrue(process.waitFor(10, TimeUnit.SECONDS))
        assertEquals(0, process.exitValue(), process.inputStream.bufferedReader().readText())
        }
    }

    @Test fun actualFixedParserPreservesMetacharactersAndRejectsAdditionalPartialRecords() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        val script = "set -eu\n" + parser() + "read_request\nprintf '%s' \"\${package_file}\"\n"
        val valid = request()
        for ((bytes, accepted) in listOf(valid.encode() to true,
            (valid.encode() + "extra-without-newline".encodeToByteArray()) to false,
            (valid.encode() + "\n".encodeToByteArray()) to false,
            valid.encode().dropLast(1).toByteArray() to false)) {
            val process = ProcessBuilder("/bin/sh", "-c", script).redirectErrorStream(true).start()
            process.outputStream.use { it.write(bytes) }
            assertTrue(process.waitFor(10, TimeUnit.SECONDS))
            val output = process.inputStream.bufferedReader().readText()
            if (accepted) { assertEquals(0, process.exitValue(), output); assertEquals(valid.packageFile, output) }
            else { assertNotEquals(0, process.exitValue()); assertEquals("", output) }
        }
    }
}
