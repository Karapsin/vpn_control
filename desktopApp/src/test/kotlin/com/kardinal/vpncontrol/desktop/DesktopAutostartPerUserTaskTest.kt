package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlPlatform
import com.kardinal.vpncontrol.model.ControlValue
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
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
 * DESKTOP-003: the Windows autostart task is per-user, and a legacy any-user HighestAvailable task migrates to that
 * shape without elevation or a password prompt (native 06ef5879: `schtasks /Change /RL LIMITED` never ended).
 *
 * The world is Task Scheduler as an unelevated standard user meets it, through the processes the product starts:
 * - `schtasks /Change` without /RP asks for the run-as password on its stdin, and fails once stdin ends;
 * - registering a HighestAvailable task, or a logon trigger for any user, is denied (an administrator's right);
 * - a trigger registered with a SID reads back as the account name (native 7ca6638a).
 * Everything from the service's settings write down to each started process is the product's.
 */
class DesktopAutostartPerUserTaskTest {
    @Test
    fun aLegacyAnyUserHighestTaskBecomesThisUsersOrdinaryTaskWithoutElevationOrPassword() = withWorld(LEGACY) { world, service ->
        val result = within(15_000) {
            service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
        } ?: fail("settings set autostart true waited on the legacy task's migration")
        assertTrue(result.isSuccess, "migration: ${result.exceptionOrNull()?.message}; OS calls ${world.calls()}")
        assertEquals(mapOf("autostart" to ControlValue.BooleanValue(true)), result.getOrNull())

        val task = assertNotNull(world.task)
        assertEquals(listOf("LeastPrivilege"), taskElementTexts(task, "RunLevel"))
        assertEquals(listOf(ACCOUNT), taskElementTexts(logonTriggerText(task), "UserId"))
        // Everything else is the legacy task's own: principal, action, settings, description and security descriptor.
        for (field in listOf("UserId", "LogonType", "Command", "Arguments", "SecurityDescriptor", "Description",
                "DisallowStartIfOnBatteries", "StopIfGoingOnBatteries", "ExecutionTimeLimit", "MultipleInstancesPolicy",
                "StopOnIdleEnd", "RestartOnIdle")) {
            val expected = taskElementTexts(LEGACY, field).let { if (field == "UserId") it + ACCOUNT else it }
            assertEquals(expected, taskElementTexts(task, field), field)
        }
        assertTrue(world.argv.none { it.take(2) in listOf(listOf("schtasks", "/Change"), listOf("schtasks", "/Delete")) },
            "a password prompt or a delete: ${world.calls()}")
        assertTrue(world.argv.filter { it.take(2) == listOf("schtasks", "/Create") }.all { "/XML" in it && it.last() == "/F" })
        assertTrue(service.state.startOnBootEnabled)
    }

    @Test
    fun aFreshEnableRegistersThisUsersOwnTaskWithoutElevation() = withWorld(null) { world, service ->
        val result = within(15_000) {
            service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
        } ?: fail("settings set autostart true never returned")
        assertTrue(result.isSuccess, "fresh enable: ${result.exceptionOrNull()?.message}; OS calls ${world.calls()}")

        val task = assertNotNull(world.task)
        assertEquals(listOf(SID, ACCOUNT), taskElementTexts(task, "UserId"))
        assertEquals(listOf(ACCOUNT), taskElementTexts(logonTriggerText(task), "UserId"))
        assertEquals(listOf("InteractiveToken"), taskElementTexts(task, "LogonType"))
        assertEquals(listOf("LeastPrivilege"), taskElementTexts(task, "RunLevel"))
        assertEquals(listOf(COMMAND), taskElementTexts(task, "Command"))
        assertEquals(listOf("--autostart"), taskElementTexts(task, "Arguments"))
        // A fresh task never replaces one: the registration carries no /F.
        assertTrue(world.argv.single { it.take(2) == listOf("schtasks", "/Create") }.let { "/XML" in it && "/F" !in it })

        val off = within(15_000) { service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(false))) }
        assertTrue(assertNotNull(off).isSuccess)
        assertEquals(null, world.task)
    }

    @Test
    fun aRefusedReRegistrationLeavesTheLegacyTaskInPlaceAndAnswersPersistenceFailed() = withWorld(LEGACY) { world, service ->
        world.refuseEveryRegistration = true
        val result = within(15_000) {
            service.applyControlSettings(mapOf("autostart" to ControlValue.BooleanValue(true)))
        } ?: fail("settings set autostart true never returned")
        assertEquals("PERSISTENCE_FAILED", result.exceptionOrNull()?.message)
        assertEquals(LEGACY, world.task, "a failed migration changed or removed the legacy task")
        assertTrue(world.argv.none { it.take(2) == listOf("schtasks", "/Delete") })
        assertTrue(service.state.startOnBootEnabled, "the legacy task still starts the app")
    }

    private class World(@Volatile var task: String?) {
        @Volatile var refuseEveryRegistration = false
        val argv = CopyOnWriteArrayList<List<String>>()
        val started = CopyOnWriteArrayList<WorldProcess>()

        fun calls(): List<String> = argv.map { it.take(2).joinToString(" ") }

        fun start(command: List<String>): Process {
            argv += command
            val process = when {
                command.first() == "whoami.exe" -> done("\"${ACCOUNT.lowercase()}\",\"$SID\"")
                // The task-absence probe asks the scheduler; the Run-value probe finds no legacy Run entry.
                command.first() == "powershell.exe" ->
                    done(if ("GetTask" in command.last() && task != null) "PRESENT" else "ABSENT")
                command.take(2) == listOf("reg", "query") -> done("ERROR: The system cannot find the file specified.", 1)
                command.take(2) == listOf("schtasks", "/Query") ->
                    task?.let { done(it) } ?: done("ERROR: The system cannot find the file specified.", 1)
                command.take(2) == listOf("schtasks", "/Delete") -> { task = null; done("SUCCESS") }
                // /Change without /RP: Task Scheduler needs the run-as password, and schtasks asks for it.
                command.take(2) == listOf("schtasks", "/Change") && "/RP" !in command ->
                    WorldProcess("Please enter the run as password for $ACCOUNT: ", 1, WorldProcess.Ending.AT_STDIN_EOF)
                command.take(2) == listOf("schtasks", "/Create") && "/XML" in command -> {
                    val definition = requireNotNull(registeredTaskXml(command))
                    if (task != null && "/F" !in command) done("ERROR: Cannot create a file when that file already exists.", 1)
                    else register(definition)
                }
                // schtasks /Create /SC ONLOGON without /RU: a logon trigger for any user.
                command.take(2) == listOf("schtasks", "/Create") -> register(null)
                else -> error("Unexpected OS action: $command")
            }
            started += process
            return process
        }

        private fun register(definition: String?): WorldProcess {
            val anyUserTrigger = definition == null || taskElementTexts(logonTriggerText(definition), "UserId").isEmpty()
            val highest = definition != null && "HighestAvailable" in taskElementTexts(definition, "RunLevel")
            if (refuseEveryRegistration || anyUserTrigger || highest) return done("ERROR: Access is denied.", 1)
            // Task Scheduler keeps the principal's SID but writes the trigger's user back as the account name.
            val trigger = logonTriggerText(definition!!)
            task = definition.replace(trigger, trigger.replace(Regex(">\\s*$SID\\s*<"), Regex.escapeReplacement(">$ACCOUNT<")))
            return done("SUCCESS: The scheduled task \"VPN Control\" has successfully been created.")
        }

        private fun done(output: String, exitCode: Int = 0) = WorldProcess(output, exitCode, WorldProcess.Ending.AT_ONCE)
    }

    private class WorldProcess(output: String, private val exitCode: Int, private val ending: Ending) : Process() {
        enum class Ending { AT_ONCE, AT_STDIN_EOF }

        private val finished = CountDownLatch(if (ending == Ending.AT_ONCE) 0 else 1)
        private val bytes = output.toByteArray()
        @Volatile var destroyed = false

        private val stdin = object : OutputStream() {
            override fun write(b: Int) = Unit
            override fun close() { if (ending == Ending.AT_STDIN_EOF) finished.countDown() }
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

    private fun withWorld(initialTask: String?, body: (World, DesktopAppService) -> Unit) {
        val directory = Files.createTempDirectory("vpn-control-autostart-per-user")
        val world = World(initialTask)
        try {
            Files.createDirectories(directory.resolve("config"))
            val manager = DesktopAutostartManager(
                configHome = directory.resolve("config"),
                platform = DesktopAutostartPlatform.WINDOWS,
                commandResolver = { COMMAND },
                processStarter = world::start,
                commandTimeoutMillis = 120_000,
            )
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
        const val COMMAND = "C:\\Users\\fixtureuser\\AppData\\Local\\vpn-control\\vpn-control.exe"
        const val SID = "S-1-5-21-1831234757-1298199345-3772319866-1004"
        const val ACCOUNT = "DESKTOP-4MOOMEI\\fixtureuser"

        /** The native 06ef5879 legacy task, as `schtasks /Query /XML` printed it, for this world's command and SID. */
        val LEGACY = """
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <SecurityDescriptor>D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;$SID)</SecurityDescriptor>
                <Description>VPN Control owned acceptance legacy run-level fixture</Description>
                <URI>\VPN Control</URI>
              </RegistrationInfo>
              <Principals>
                <Principal id="Author">
                  <UserId>$SID</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <IdleSettings>
                  <StopOnIdleEnd>true</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
              </Settings>
              <Triggers>
                <LogonTrigger />
              </Triggers>
              <Actions Context="Author">
                <Exec>
                  <Command>$COMMAND</Command>
                  <Arguments>--autostart</Arguments>
                </Exec>
              </Actions>
            </Task>
        """.trimIndent().replace("\n", "\r\n")
    }
}
