package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.control.ControlRoutingLogic
import com.kardinal.vpncontrol.desktop.DesktopWindowsLauncherArguments.Process
import com.kardinal.vpncontrol.desktop.DesktopWindowsLauncherArguments.escape
import com.kardinal.vpncontrol.desktop.DesktopWindowsLauncherArguments.forMain
import com.kardinal.vpncontrol.desktop.DesktopWindowsLauncherArguments.restartCommandLine
import com.kardinal.vpncontrol.desktop.DesktopWindowsLauncherArguments.restored
import com.kardinal.vpncontrol.model.ControlOperationId
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DesktopWindowsLauncherArgumentsTest {
    private val exe = """C:\Users\vpn user\AppData\Local\vpn-control\vpn-control-cli.exe"""
    private val owner = "5c0ffee0-0d1e-4d2a-9a9f-3b1e2a7c4d10"
    private val typed = listOf("--json", "--controller-id", owner, "--if-revision", "3",
        "routing", "set", "direct-domains", "[\"Example.test\"]")
    private val nativeParentLine = list2cmdline(listOf(exe) + typed)

    /** What main receives natively: the parent splits its line, Executor joins it again, the child splits that. */
    private fun restarted(parentLine: String, program: String = exe): List<String> =
        shell32(restartCommandLine(program, shell32(parentLine).drop(1))).drop(1)

    private fun windows(
        self: Process = Process(exe, 200L, null),
        parentId: Long? = 4242L,
        parent: Process? = Process(exe, 100L, nativeParentLine),
        splitter: (String) -> List<String> = ::shell32,
    ) = object : DesktopWindowsLauncherArguments.Source {
        override fun current() = self
        override fun parentPid() = parentId
        override fun open(pid: Long) = parent.takeIf { pid == parentId }
        override fun split(commandLine: String) = splitter(commandLine)
    }

    @Test fun windowsMainHandsTheCliTheJsonArrayTheUserTypedAfterTheLauncherRestart() {
        // As in the disconnected family's routing case on the Windows 11 guest (operation 98c8c95a): CPython
        // wrote the parent line, the 2.2.16 launcher (JDK 17.0.21) restarted itself, main got [Example.test].
        assertEquals("\"$exe\" --json --controller-id $owner --if-revision 3 routing set direct-domains " +
            "[\\\"Example.test\\\"]", nativeParentLine)
        val received = restarted(nativeParentLine)
        assertEquals(typed.dropLast(1) + "[Example.test]", received)
        assertTrue(ControlRoutingLogic.set(MainUiState(), "direct-domains", received.last()).isFailure,
            "The received value is the native INVALID_ARGUMENT")

        val handed = forMain(received.toTypedArray(), "Windows 11") { windows() }.toList()

        assertEquals(typed, handed)
        val invocation = assertIs<ControlCliParseResult.Invocation>(
            ControlCliParser.parse(DesktopWorkspacePaths.parse(handed).getOrThrow().arguments))
        assertEquals(ControlOperationId.ROUTING_SET, invocation.operation)
        assertEquals(listOf("direct-domains", "[\"Example.test\"]"), invocation.positional)
        assertEquals(listOf("example.test"), ControlRoutingLogic.set(MainUiState(), "direct-domains",
            invocation.positional[1]).getOrThrow().routingRules.directDomainSuffixes)
    }

    @Test fun windowsMainHandsTheCliTheEmptyNameTheUserTypedAfterTheLauncherRestart() {
        // An empty --name clears a subscription's name; the restart dropped it, leaving --name without a value.
        val clear = listOf("--json", "subscriptions", "update", "sub-1", "--name", "")
        val parentLine = list2cmdline(listOf(exe) + clear)
        val received = restarted(parentLine)
        assertEquals(clear.dropLast(1), received)
        assertIs<ControlCliParseResult.Invalid>(ControlCliParser.parse(received))

        val handed = forMain(received.toTypedArray(), "Windows 11") {
            windows(parent = Process(exe, 100L, parentLine))
        }.toList()

        assertEquals(clear, handed)
        assertEquals("", assertIs<ControlCliParseResult.Invocation>(ControlCliParser.parse(handed)).options["--name"])
    }

    @Test fun escapeIsJpackageEscapeArg() {
        assertEquals("", escape(""))
        assertEquals("plain", escape("plain"))
        assertEquals("\"a b\"", escape("a b"))
        assertEquals("\"a\tb\"", escape("a\tb"))
        assertEquals("\"quoted\"", escape("\"quoted\""))
        assertEquals("\"a b\"", escape("\"a b\""))
        assertEquals("\"", escape("\""))
        assertEquals("[\"Example.test\"]", escape("[\"Example.test\"]"))
        assertEquals("\"C:\\a b\\\"", escape("C:\\a b\\"))
    }

    @Test fun theRestartLineJoinsTheImageAndEveryEscapedValueWithOneSpace() {
        assertEquals("\"$exe\" a  \"b c\" ", restartCommandLine(exe, listOf("a", "", "b c", "")))
        assertEquals("\"$exe\"", restartCommandLine(exe, emptyList()))
        assertEquals("C:\\cli\\cli.exe --json", restartCommandLine("C:\\cli\\cli.exe", listOf("--json")))
    }

    @Test fun theShell32ModelFollowsTheDocumentedRules() {
        // Microsoft's documented examples, behind a path as argv[0].
        assertEquals(listOf("exe", "abc", "d", "e"), shell32("exe \"abc\" d e"))
        assertEquals(listOf("exe", """a\\b""", "de fg", "h"), shell32("""exe a\\b d"e f"g h"""))
        assertEquals(listOf("exe", """a\"b""", "c", "d"), shell32("""exe a\\\"b c d"""))
        assertEquals(listOf("exe", """a\\b c""", "d", "e"), shell32("""exe a\\\\"b c" d e"""))
        // argv[0] has no escapes; leading whitespace makes it empty; trailing whitespace adds nothing.
        assertEquals(listOf("C:\\Program Files\\x.exe", "a"), shell32("\"C:\\Program Files\\x.exe\" a"))
        assertEquals(listOf("C:\\dir\\", "b"), shell32("\"C:\\dir\\\" b"))
        assertEquals(listOf("", "a", "b"), shell32(" a b"))
        assertEquals(listOf("exe", "a"), shell32("exe\ta \t "))
        assertEquals(listOf("exe", "", "b"), shell32("exe \"\" b"))
        assertEquals(listOf("exe", "a b"), shell32("exe \"a b"))
    }

    @Test fun everyValueAPythonCallerPassesIsRestartedAsTheResearchModelSaysAndComesBackExactly() {
        val head = listOf("routing", "set", "direct-domains")
        // Child arguments as model/roundtrip.py printed them for the same values.
        val cases = listOf(
            "[\"Example.test\"]" to head + listOf("[Example.test]", "--json"),
            "[\"a.test\",\"b.test\"]" to head + listOf("[a.test,b.test]", "--json"),
            "[\"a b\"]" to head + listOf("[a", "b]", "--json"),
            "{\"k\":1}" to head + listOf("{k:1}", "--json"),
            "Example.test,other.test" to head + listOf("Example.test,other.test", "--json"),
            "Example.test other.test" to head + listOf("Example.test other.test", "--json"),
            "" to head + listOf("--json"),
            "\"quoted\"" to head + listOf("quoted", "--json"),
            "C:\\dir with space\\" to head + listOf("C:\\dir with space\" --json"),
            "C:\\dir\\" to head + listOf("C:\\dir\\", "--json"),
            "пример.рф" to head + listOf("пример.рф", "--json"),
            "a\\\"b" to head + listOf("a\"b", "--json"),
            "[\\\"Example.test\\\"]" to head + listOf("[\"Example.test\"]", "--json"),
        )
        for ((value, child) in cases) {
            val argv = head + value + "--json"
            val parentLine = list2cmdline(listOf(exe) + argv)
            assertEquals(argv, shell32(parentLine).drop(1), value)
            assertEquals(child, restarted(parentLine), value)
            assertEquals(argv, restored(child, exe, parentLine, ::shell32), value)
        }
        for (argv in listOf(
            listOf("settings", "set", "", ""),
            listOf("routing", "set", "direct-domains", "[\"пример.рф\",\"東京.test\"]", ""),
            listOf("locations", "export", "--output", "C:\\a b\\", "--format", "json"),
            listOf("subscriptions", "add", "--source", "\"", "--name", "\ttab\\\\"),
            listOf("routing", "import", "--input", "C:\\Users\\vpn user\\routing 東京 json.json"),
        )) {
            val parentLine = list2cmdline(listOf(exe) + argv)
            assertEquals(argv, restored(restarted(parentLine), exe, parentLine, ::shell32), argv.toString())
        }
    }

    @Test fun aParentLineThatDoesNotReproduceTheReceivedArgumentsIsNeverUsed() {
        val received = restarted(nativeParentLine)
        val other = list2cmdline(listOf(exe) + typed.dropLast(1) + "[\"Other.test\"]")
        assertNull(restored(received, exe, other, ::shell32))
        assertNull(restored(received + "--json", exe, nativeParentLine, ::shell32))
        assertNull(restored(received.dropLast(1), exe, nativeParentLine, ::shell32))
        // A launcher without the UTF-8 code page would have turned these letters into '?'.
        val unicode = list2cmdline(listOf(exe, "routing", "set", "direct-domains", "[\"пример.рф\"]"))
        assertNull(restored(restarted(unicode).map { it.replace(Regex("[^\\x00-\\x7f]"), "?") }, exe, unicode, ::shell32))

        val array = received.toTypedArray()
        assertSame(array, forMain(array, "Windows 11") { windows(parent = Process(exe, 100L, other)) })
    }

    @Test fun aQuotedValueEndingInOneBackslashKeepsWhatCommandLineToArgvMakesOfIt() {
        // cmd.exe and Windows PowerShell 5.1 can leave the backslash before a closing quote single. CommandLineToArgvW
        // then reads that quote as a literal and keeps the value quoted until the next unescaped quote, here none, so
        // to the end of the line. The restart used to split it again by accident; main now gets what every other
        // Windows program gets from the line.
        val single = "\"$exe\" --state-dir \"C:\\VPN State\\\" status"
        val received = restarted(single)
        assertEquals(listOf("--state-dir", "C:\\VPN State", "status"), received)
        val handed = forMain(received.toTypedArray(), "Windows 11") { windows(parent = Process(exe, 100L, single)) }
        assertEquals(listOf("--state-dir", "C:\\VPN State\" status"), handed.toList())
        assertEquals(shell32(single).drop(1), handed.toList())
        // A later quoted value's opening quote ends that quoting: the value takes in the arguments before it and runs
        // on to the next space, and the quotes after it pair up anew.
        val later = "\"$exe\" --state-dir \"C:\\VPN State\\\" --name \"My Sub\" status"
        val laterReceived = restarted(later)
        assertEquals(listOf("--state-dir", "C:\\VPN State", "--name", "My Sub", "status"), laterReceived)
        val laterHanded = forMain(laterReceived.toTypedArray(), "Windows 11") {
            windows(parent = Process(exe, 100L, later))
        }.toList()
        assertEquals(listOf("--state-dir", "C:\\VPN State\" --name My", "Sub status"), laterHanded)
        assertEquals(shell32(later).drop(1), laterHanded)
        // Doubled before the closing quote, as CommandLineToArgvW requires, the value ends where it was meant to.
        val doubled = "\"$exe\" --state-dir \"C:\\VPN State\\\\\" status"
        assertEquals(listOf("--state-dir", "C:\\VPN State\" status"), restarted(doubled))
        assertEquals(listOf("--state-dir", "C:\\VPN State\\", "status"), forMain(restarted(doubled).toTypedArray(),
            "Windows 11") { windows(parent = Process(exe, 100L, doubled)) }.toList())
    }

    @Test fun theConfiguredHelpOfAnEmptyRestartIsNotRewritten() {
        // vpn-control-cli.cfg passes --help when the child line holds no argument, as after a lone "".
        for (parentLine in listOf("\"$exe\"", "\"$exe\" \"\"")) {
            val received = arrayOf("--help")
            assertSame(received, forMain(received, "Windows 11") { windows(parent = Process(exe, 100L, parentLine)) })
        }
    }

    @Test fun aRestartThatPassedEverythingIntactChangesNothing() {
        val gui = """C:\Users\vpn user\AppData\Local\vpn-control\vpn-control.exe"""
        for (argv in listOf(emptyList(), listOf("--autostart"),
                listOf("--state-dir", "C:\\Users\\vpn user\\東京 workspace", "status"))) {
            val parentLine = list2cmdline(listOf(gui) + argv)
            val received = restarted(parentLine, gui)
            assertEquals(argv, received)
            assertEquals(argv, forMain(received.toTypedArray(), "Windows 10") {
                windows(self = Process(gui, 200L, null), parent = Process(gui, 100L, parentLine))
            }.toList())
        }
    }

    @Test fun onlyAParentOfTheSameImageNotBornLaterIsTheRestart() {
        val received = restarted(nativeParentLine).toTypedArray()
        fun handed(parent: Process) = forMain(received, "Windows 11") { windows(parent = parent) }
        assertEquals(typed, handed(Process(exe, 199L, nativeParentLine)).toList())
        // An equal creation time is kept, as OpenJDK's ProcessHandleImpl keeps it. The real parent is earlier in
        // practice: native creation times are finer than 1 ms, and that parent runs before it creates its child.
        assertEquals(typed, handed(Process(exe, 200L, nativeParentLine)).toList())
        // Born after this process: the parent's PID was reused.
        assertSame(received, handed(Process(exe, 201L, nativeParentLine)))
        assertSame(received, handed(Process("""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""", 100L,
            nativeParentLine)))
        assertSame(received, handed(Process(exe.replace("""\vpn-control\""", """\vpn-control-old\"""), 100L,
            nativeParentLine)))
    }

    @Test fun aMissingParentOrAnyFailedReadKeepsTheReceivedArguments() {
        val received = restarted(nativeParentLine).toTypedArray()
        val failing = listOf(
            windows(parentId = null),
            windows(parent = null),
            windows(self = Process(null, 200L, null)),
            windows(self = Process(exe, null, null)),
            windows(parent = Process(null, 100L, nativeParentLine)),
            windows(parent = Process(exe, null, nativeParentLine)),
            windows(parent = Process(exe, 100L, null)),
            windows(splitter = { error("CommandLineToArgvW failed") }),
            object : DesktopWindowsLauncherArguments.Source {
                override fun current(): Process = error("QueryFullProcessImageNameW failed")
                override fun parentPid() = 4242L
                override fun open(pid: Long) = Process(exe, 100L, nativeParentLine)
                override fun split(commandLine: String) = shell32(commandLine)
            },
        )
        for (source in failing) assertSame(received, forMain(received, "Windows 11") { source })
        assertSame(received, forMain(received, "Windows 11") { error("JNA unavailable") })
    }

    @Test fun macOsAndLinuxNeverAskWindows() {
        val received = restarted(nativeParentLine).toTypedArray()
        for (osName in listOf("Mac OS X", "Linux", "")) {
            var asked = false
            assertSame(received, forMain(received, osName) { asked = true; windows() })
            assertFalse(asked, osName)
        }
    }
}

/**
 * Shell32 CommandLineToArgvW for hosts without it, as Wine and Go model it against the real function.
 * argv[0] is a path: quoted up to the next quote, otherwise up to whitespace. Afterwards 2n backslashes and
 * a quote give n backslashes and a delimiter, 2n+1 give n and a literal quote, other backslashes stay, and
 * a doubled quote inside quotes is one literal quote that ends the quoted part.
 */
private fun shell32(line: String): List<String> {
    if (line.isEmpty()) return listOf("") // Shell32 returns its own module path here.
    val argv = mutableListOf<String>()
    var i: Int
    if (line[0] == '"') {
        val end = line.indexOf('"', 1).let { if (it < 0) line.length else it }
        argv += line.substring(1, end)
        i = minOf(end + 1, line.length)
    } else {
        i = line.indexOfFirst { it == ' ' || it == '\t' }.let { if (it < 0) line.length else it }
        argv += line.substring(0, i)
    }
    while (true) {
        while (i < line.length && (line[i] == ' ' || line[i] == '\t')) i++
        if (i == line.length) return argv
        val argument = StringBuilder()
        var quoted = false
        while (i < line.length && (quoted || (line[i] != ' ' && line[i] != '\t'))) {
            when (line[i]) {
                '\\' -> {
                    var end = i
                    while (end < line.length && line[end] == '\\') end++
                    val slashes = end - i
                    if (end < line.length && line[end] == '"') {
                        argument.append("\\".repeat(slashes / 2))
                        if (slashes % 2 == 1) argument.append('"')
                        i = if (slashes % 2 == 1) end + 1 else end
                    } else {
                        argument.append("\\".repeat(slashes))
                        i = end
                    }
                }
                '"' -> if (quoted && i + 1 < line.length && line[i + 1] == '"') {
                    argument.append('"')
                    quoted = false
                    i += 2
                } else {
                    quoted = !quoted
                    i++
                }
                else -> argument.append(line[i++])
            }
        }
        argv += argument.toString()
    }
}

/** CPython subprocess.list2cmdline, which wrote the parent line on the guest. */
private fun list2cmdline(argv: List<String>): String = argv.joinToString(" ") { argument ->
    val quote = argument.isEmpty() || ' ' in argument || '\t' in argument
    val line = StringBuilder(if (quote) "\"" else "")
    var slashes = 0
    for (c in argument) when (c) {
        '\\' -> slashes++
        '"' -> { line.append("\\".repeat(2 * slashes)).append("\\\""); slashes = 0 }
        else -> { line.append("\\".repeat(slashes)).append(c); slashes = 0 }
    }
    line.append("\\".repeat(slashes))
    if (quote) line.append("\\".repeat(slashes)).append('"')
    line.toString()
}
