package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Native windows-autostart-migration.pre 06ef5879 (S_D7, 2.3.2 of 79fe27be): with a legacy HighestAvailable task
 * present, `settings set autostart true` reached the migration's `schtasks /Change /TN "VPN Control" /RL LIMITED`,
 * the first command of that path never run natively before. It never ended, and the autostart runner waited on it
 * without a bound, with the child's stdin an open pipe nobody writes. The serve held the service monitor and the task
 * lock for good: the CLI and the cleanup `quit` each ended TIMEOUT and the serve never ended.
 *
 * The world is Windows' command line as these processes: every command the manager runs is a [WorldProcess], and only
 * `/Change` misbehaves. Everything from the service's settings write down to the process is the product's.
 */
class DesktopAutostartBoundedCommandTest {
    @Test
    fun aMigrationWhoseChangeNeverEndsIsATypedFailureInBoundedTimeAndTheServiceStaysUsable() =
        withWorld(changeEnding = WorldProcess.Ending.NEVER, timeoutMillis = 500) { world, service ->
            val first = within(15_000) {
                service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
            } ?: fail("settings set autostart true never returned while schtasks /Change never ended")
            assertEquals("PERSISTENCE_FAILED", first.exceptionOrNull()?.message)
            val change = world.started.single { it.argv.take(2) == listOf("schtasks", "/Change") }
            assertTrue(change.destroyed, "the timed-out schtasks /Change was left running")
            assertEquals("HighestAvailable", world.runLevel, "nothing changed the task")

            // The serve stays healthy: the monitor and the task lock were released, so the next write runs.
            world.changeEnding = WorldProcess.Ending.AT_ONCE
            val second = within(15_000) {
                service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
            } ?: fail("the next settings write was blocked by the first one")
            assertTrue(second.isSuccess, "second migration: ${second.exceptionOrNull()?.message}")
            assertEquals("LeastPrivilege", world.runLevel)
        }

    @Test
    fun aMigrationWhoseChangeWaitsForAnAnswerOnStdinGetsEndOfInputAtOnce() =
        // The timeout is far longer than the bound below: only an end of input releases this child.
        withWorld(changeEnding = WorldProcess.Ending.AT_STDIN_EOF, timeoutMillis = 120_000) { world, service ->
            val result = within(15_000) {
                service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
            } ?: fail("settings set autostart true waited on a prompt nobody can answer")
            assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
            assertTrue(world.started.all { it.stdinClosed }, "a command kept an open stdin")
            assertEquals("HighestAvailable", world.runLevel)
        }

    @Test
    fun everyAutostartCommandEndsWithinItsBoundAndOrdinaryOutputIsUnchanged() {
        val ordinary = WorldProcess(listOf("whoami.exe"), "\"ME\\user\",\"S-1-5-21-1\"", 0, WorldProcess.Ending.AT_ONCE)
        assertEquals(DesktopAutostartCommandResult(0, "\"ME\\user\",\"S-1-5-21-1\""),
            runAutostartCommand(ordinary.argv, { ordinary }, 1_000))
        val wedged = WorldProcess(listOf("schtasks", "/Change"), "", 0, WorldProcess.Ending.NEVER)
        val result = within(10_000) { runAutostartCommand(wedged.argv, { wedged }, 300) }
            ?: run { wedged.destroy(); fail("the runner waited on a child that never ends") }
        assertEquals(-1, result.exitCode)
        assertEquals("TIMEOUT", result.output)
        assertTrue(wedged.destroyed)
        val missing = runAutostartCommand(listOf("missing.exe"), { throw java.io.IOException("not found") }, 1_000)
        assertEquals(DesktopAutostartCommandResult(-1, "not found"), missing)
    }

    private class World(@Volatile var changeEnding: WorldProcess.Ending) {
        @Volatile var runLevel = "HighestAvailable"
        val started = CopyOnWriteArrayList<WorldProcess>()

        fun start(argv: List<String>): Process {
            val process = when {
                argv.first() == "powershell.exe" -> WorldProcess(argv, "ABSENT", 0, WorldProcess.Ending.AT_ONCE)
                argv.first() == "whoami.exe" -> WorldProcess(argv, "\"ME\\user\",\"S-1-5-21-1\"", 0, WorldProcess.Ending.AT_ONCE)
                argv.take(2) == listOf("reg", "query") ->
                    WorldProcess(argv, "ERROR: The system cannot find the file specified.", 1, WorldProcess.Ending.AT_ONCE)
                argv.take(2) == listOf("schtasks", "/Query") -> WorldProcess(argv, taskXml(runLevel), 0, WorldProcess.Ending.AT_ONCE)
                argv == listOf("schtasks", "/Change", "/TN", "VPN Control", "/RL", "LIMITED") -> when (changeEnding) {
                    WorldProcess.Ending.AT_ONCE -> {
                        runLevel = "LeastPrivilege"
                        WorldProcess(argv, "SUCCESS: The parameters of scheduled task \"VPN Control\" have been changed.", 0,
                            WorldProcess.Ending.AT_ONCE)
                    }
                    else -> WorldProcess(argv, "Please enter the run as password for ME\\user: ", 1, changeEnding)
                }
                else -> error("Unexpected OS action: $argv")
            }
            started += process
            return process
        }

        // The native legacy task's shape: an any-user logon trigger serialized bare, an interactive token.
        private fun taskXml(runLevel: String) = """
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <Principals><Principal id="Author"><UserId>S-1-5-21-1</UserId><LogonType>InteractiveToken</LogonType><RunLevel>$runLevel</RunLevel></Principal></Principals>
              <Triggers><LogonTrigger /></Triggers>
              <Actions Context="Author"><Exec><Command>$COMMAND</Command><Arguments>--autostart</Arguments></Exec></Actions>
            </Task>
        """.trimIndent()
    }

    /** A child process as the runner sees it: output that ends with the process, and a stdin pipe. */
    private class WorldProcess(val argv: List<String>, output: String, private val exitCode: Int, private val ending: Ending) : Process() {
        enum class Ending { AT_ONCE, AT_STDIN_EOF, NEVER }

        private val finished = CountDownLatch(if (ending == Ending.AT_ONCE) 0 else 1)
        private val bytes = output.toByteArray()
        @Volatile var destroyed = false
        @Volatile var stdinClosed = false

        private val stdin = object : OutputStream() {
            override fun write(b: Int) = Unit
            override fun close() {
                stdinClosed = true
                if (ending == Ending.AT_STDIN_EOF) finished.countDown()
            }
        }
        private val stdout = object : InputStream() {
            private var position = 0
            override fun read(): Int {
                finished.await()
                return if (position < bytes.size) bytes[position++].toInt() and 0xff else -1
            }
        }

        override fun getOutputStream(): OutputStream = stdin
        override fun getInputStream(): InputStream = stdout
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun waitFor(): Int { finished.await(); return exitValue() }
        override fun waitFor(timeout: Long, unit: TimeUnit): Boolean = finished.await(timeout, unit)
        override fun exitValue(): Int {
            if (finished.count > 0) throw IllegalThreadStateException("running")
            return if (destroyed) 1 else exitCode
        }
        override fun isAlive(): Boolean = finished.count > 0
        override fun destroy() { destroyed = true; finished.countDown() }
        override fun destroyForcibly(): Process { destroy(); return this }
    }

    private fun withWorld(
        changeEnding: WorldProcess.Ending,
        timeoutMillis: Long,
        body: (World, DesktopAppService) -> Unit,
    ) {
        val directory = Files.createTempDirectory("vpn-control-autostart-bounded")
        val world = World(changeEnding)
        try {
            val manager = DesktopAutostartManager(
                configHome = directory.resolve("config"),
                platform = DesktopAutostartPlatform.WINDOWS,
                commandResolver = { COMMAND },
                processStarter = world::start,
                commandTimeoutMillis = timeoutMillis,
            )
            Files.createDirectories(directory.resolve("config"))
            val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory.resolve("state")),
                autostartManager = manager, controlPlatform = ControlPlatform.WINDOWS)
            body(world, service)
        } finally {
            // Release anything a failing (RED) run left waiting, so the test JVM can end.
            world.started.forEach(WorldProcess::destroy)
            directory.toFile().deleteRecursively()
        }
    }

    private fun <T> within(millis: Long, action: () -> T): T? {
        val result = AtomicReference<Result<T>?>()
        val thread = Thread { result.set(runCatching(action)) }.apply { isDaemon = true; start() }
        thread.join(millis)
        return result.get()?.getOrThrow()
    }

    private companion object {
        const val COMMAND = "C:\\Users\\me\\AppData\\Local\\vpn-control\\vpn-control.exe"
    }
}
