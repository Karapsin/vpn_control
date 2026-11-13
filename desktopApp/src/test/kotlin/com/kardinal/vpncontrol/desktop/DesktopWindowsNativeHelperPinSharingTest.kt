package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.DELETE
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.FILE_ADD_FILE
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.FILE_ADD_SUBDIRECTORY
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.FILE_READ_ATTRIBUTES
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SHARE_READ
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SHARE_WRITE
import com.kardinal.vpncontrol.desktop.DesktopWindowsPinSharingTest.Companion.SYNCHRONIZE
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

/**
 * The native helpers' own pins, judged on every platform (the C# half of the folder-pin fix for row 83484649).
 *
 * While VPN mode is connected the elevated broker holds its admission: every folder from C:\ to its owner's
 * image and to its own image, and C:\ProgramData (windows-vpn-helper-admission.cs). For the per-user package in
 * %LOCALAPPDATA%\vpn-control those folders include the home folder. The install helper holds %LOCALAPPDATA% and
 * its ancestors, the installation and the installer store during an installation (windows-install-native.cs,
 * windows-install-helper-sessions.cs), and the broker holds a runtime resource's folder chain for each capture
 * and publication (windows-vpn-user-files.cs). They pinned with FILE_LIST_DIRECTORY and read sharing only, and a
 * rename or hard link by path opens the folder of the new name for FILE_ADD_FILE or FILE_ADD_SUBDIRECTORY
 * ([MS-FSA] 2.1.5.15.12, 2.1.5.15.7): every other program's rename into those folders failed meanwhile, as
 * `git config --global` does when it replaces `.gitconfig`.
 *
 * There is no C# compiler here. Each test reads the helper source, resolves the access, sharing and flags that
 * each pin passes to CreateFile for the role its call site gives it (for the broker admission, by evaluating
 * the routing condition itself), and judges them as Windows does ([SharingVolume], [MS-FSA] 2.1.5.1.2.2).
 * Folder pins and witnesses must admit rename and link destinations and refuse DELETE. Executables, inputs and
 * private objects must also refuse writers: the installer's readiness probe takes a refused write open of the
 * owner's image as a live product process. Compilation and the OS behaviour itself are shown only on Windows
 * (DesktopWindowsNativeHelperPinSharingNativeTest, the helper probes and the Windows package build).
 */
class DesktopWindowsNativeHelperPinSharingTest {
    @Test fun theInstallHelperPinsFoldersSharingWritesAndKeepsItsImageAndInputsFromWriters() {
        val native = source("windows-install-native.cs")
        val sessions = source("windows-install-helper-sessions.cs")
        val folder = native.pin(native.body(OPEN_DIRECTORY))
        val problems = mutableListOf<String>()
        assertEquals(SESSION_FOLDERS.keys, sessions.calls("VpnInstallNative.OpenDirectory").map { it.operand }.toSet(),
            "Every folder the install helper pins is classified")
        SESSION_FOLDERS.values.forEach { problems += folder.judge(it, Role.FOLDER) }
        assertEquals(listOf("root", "currentPath"), native.calls("OpenDirectory", native.body(IMAGE_OBJECT_PIN)).map { it.operand })
        problems += folder.judge("every folder from the volume root to the install helper's own image while its original-user child starts", Role.FOLDER)
        assertEquals(listOf("candidate"), native.calls("OpenDirectory", native.body(PIN_NON_EMPTY_ANCESTOR)).map { it.operand })
        problems += folder.judge("the child that keeps a pinned C:\\ProgramData non-empty (another program's file or folder)", Role.FOLDER)
        assertTrue(Regex("""\[VpnInstallNative]::OpenDirectory\(""").containsMatchIn(resource("windows-install-common.ps1")))
        problems += folder.judge("the captured PowerShell worker's Pin-Directory (no production caller)", Role.FOLDER)
        // The helper's own image (ImageObjectPin) and every input it reads by handle keep refusing writers.
        val reads = native.calls("OpenRead") + sessions.calls("VpnInstallNative.OpenRead")
        assertTrue(reads.size >= 10, "OpenRead sites: ${reads.size}")
        for (call in reads) problems += native.pin(native.body(OPEN_READ), native.bind(OPEN_READ, call.arguments))
            .judge("the file OpenRead(${call.text})", Role.IMMUTABLE)
        assertNoProblems(problems)
    }

    @Test fun theVpnBrokerAdmissionPinsFoldersSharingWritesAndItsImagesDenyingWriters() {
        val native = source("windows-install-native.cs")
        val admission = source("windows-vpn-helper-admission.cs")
        val fixed = admission.body(FIXED_NATIVE)
        // FixedNative's path openers delegate to VpnInstallNative: resolve what each one passes to CreateFileW.
        val openers = mutableMapOf<String, NativeOpen>()
        fun opener(name: String) = openers.getOrPut(name) {
            val body = admission.body(Regex("""public\s+Handle\s+$name\s*\(\s*string\s+path\s*\)"""), fixed)
            val delegate = Regex("""VpnInstallNative\.(\w+)\s*\(\s*path\s*\)""")
                .findAll(admission.masked.substring(body.first, body.last + 1)).single().groupValues[1]
            native.pin(native.body(Regex("""public\s+static\s+SafeFileHandle\s+$delegate\s*\(\s*string\s+path\s*\)""")))
        }
        val problems = mutableListOf<String>()
        val seen = mutableSetOf<String>()
        for (method in listOf(RETAIN, PIN_ANCESTRY, TAIL_ANCESTOR)) for (keep in admission.calls("lease.Keep", admission.body(method))) {
            val routed = admission.route(keep.arguments.single())
            val openings = listOfNotNull(routed.whenTrue, routed.whenFalse)
            if (openings.all { it.opener in setOf("OpenOwner", "OpenGate") }) continue // a process handle and the cooperating gate
            val operand = openings.map { it.operand }.distinct().singleOrNull()
            val pinned = operand?.let { ADMISSION_PINS[it] }
            if (operand == null || pinned == null || openings.any { it.opener !in setOf("Open", "OpenFile") }) {
                problems += "Unclassified admission pin lease.Keep(${keep.text})"
                continue
            }
            seen += operand
            val (what, role) = pinned
            if (role != null) {
                // A fixed role: one opener, whatever the routing.
                check(routed.whenFalse == null) { "Routed fixed admission pin lease.Keep(${keep.text})" }
                problems += opener(routed.whenTrue.opener).judge("$what, opened by native.${routed.whenTrue.opener}", role)
                continue
            }
            // PinAncestry: each folder of a path, and the image when the path names one, decided per element.
            val judged = mutableSetOf<Pair<String, Role>>()
            for (directory in listOf(false, true)) for (count in 1..4) for (index in 0 until count) {
                val names = mapOf<String, Any>("directory" to directory, "index" to index.toLong(), "paths.Count" to count.toLong())
                val opening = if (routed.condition == null || evaluate(routed.condition, names) == true) routed.whenTrue
                    else requireNotNull(routed.whenFalse)
                val element = if (!directory && index == count - 1) Role.IMMUTABLE else Role.FOLDER
                if (judged.add(opening.opener to element)) problems += opener(opening.opener).judge(
                    (if (element == Role.FOLDER) "every folder of the owner's and the broker's paths and of C:\\ProgramData"
                    else "the image that ends the owner's or the broker's path") + ", opened by native.${opening.opener}", element)
            }
            assertEquals(setOf(Role.FOLDER, Role.IMMUTABLE), judged.map { it.second }.toSet())
        }
        assertEquals(ADMISSION_PINS.keys, seen, "Every classified admission pin is still opened")
        assertNoProblems(problems)
    }

    @Test fun theVpnBrokerPinsAResourceFolderChainSharingWritesWhileItsFilesDenyWriters() {
        val files = source("windows-vpn-user-files.cs")
        val user = files.body(ORIGINAL_USER)
        val open = files.body(USER_OPEN, user)
        val parents = files.body(PIN_PARENTS, user)
        val match = files.body(MATCH, user)
        val problems = mutableListOf<String>()
        problems += files.pin(open, files.bind(USER_OPEN, files.calls("Open", parents).single().arguments)).judge(
            "every folder from the volume root to a runtime resource's folder, under the original user's token, " +
                "for each capture and publication", Role.FOLDER)
        val matched = files.calls("Open", match).single()
        for (call in files.calls("Match", user)) problems += files.pin(open,
            files.bind(USER_OPEN, matched.arguments, files.bind(MATCH, call.arguments))).judge("the resource file Match(${call.text})", Role.IMMUTABLE)
        val others = files.calls("Open", user).filter { it.at !in parents && it.at !in match }
        assertTrue(others.size >= 4, "Open sites: ${others.size}")
        for (call in others) problems += files.pin(open, files.bind(USER_OPEN, call.arguments)).judge("the resource file Open(${call.text})", Role.IMMUTABLE)
        problems += files.pin(files.body(CREATE_PRIVATE, user)).judge("a publication's private temporary file", Role.IMMUTABLE)
        assertNoProblems(problems)
    }

    @Test fun theVpnBrokerRuntimePinsShareWritesAndItsPrivateResourcesDenyWriters() {
        val broker = source("windows-vpn-broker.cs")
        assertNoProblems(
            broker.pin(broker.body(BROKER_PIN)).judge(
                "every folder from the volume root to C:\\ProgramData and the broker's private stage, while its runtime runs", Role.FOLDER) +
                broker.pin(broker.body(BROKER_PIN_WITNESS)).judge("the child that keeps a pinned C:\\ProgramData non-empty", Role.FOLDER) +
                broker.pin(broker.body(BROKER_PRIVATE_RESOURCE)).judge("a private runtime resource in the stage", Role.IMMUTABLE))
    }

    @Test fun everyFolderCapableOpenCompiledIntoTheNativeHelpersIsJudgedByItsRole() {
        val compiled = listOf("InstallHelper/InstallHelper.csproj", "VpnBroker/VpnBroker.csproj").flatMap { project ->
            val file = listOf(Path.of("native/windows", project), Path.of("desktopApp/native/windows", project))
                .firstOrNull(Files::isRegularFile) ?: error("Missing native helper project $project")
            Regex("""<Compile\s+Include="([^"$]+)"""").findAll(Files.readString(file)).map { it.groupValues[1].substringAfterLast('\\') }.toList()
        }.toSortedSet()
        assertTrue(compiled.containsAll(JUDGED.keys), compiled.toString())
        val problems = mutableListOf<String>()
        for (name in compiled) {
            val file = source(name)
            val spans = JUDGED[name].orEmpty().mapNotNull { file.bodyOrNull(it) }
            for (call in file.nativeOpens()) {
                val flags = runCatching { evaluate(call.arguments[5].text, file.constants) as Long }.getOrNull()
                if (flags == null) problems += "$name: unreadable flags in CreateFile(${call.text})"
                else if (flags and BACKUP_SEMANTICS != 0L && spans.none { call.at in it })
                    problems += "$name: unjudged open that may name a folder, CreateFile(${call.text})"
            }
        }
        // The two folder-capable opens that pin no folder of other programs.
        val native = source("windows-install-native.cs")
        problems += native.pin(native.body(OPEN_INPUT_DELETE)).judge("the original user's private input object, held to verify and delete it", Role.IMMUTABLE)
        problems += native.pin(native.body(OPEN_INPUT_NAMED_METADATA)).judge("a metadata-only lookup of a private input", Role.METADATA)
        assertNoProblems(problems)
    }

    private fun resource(name: String) = requireNotNull(javaClass.getResource("/$name")) { "Missing resource $name" }.readText()
    private fun source(name: String) = CSharpSource(name, resource(name))
    private fun assertNoProblems(problems: List<String>) =
        assertTrue(problems.isEmpty(), problems.joinToString("\n", "${problems.size} native pin problem(s):\n"))

    private enum class Role { FOLDER, IMMUTABLE, METADATA }

    /** What one native open passes to CreateFile, judged by [SharingVolume] for the role of the object it pins. */
    private data class NativeOpen(val rights: Long, val share: Long, val flags: Long) {
        fun judge(what: String, role: Role): List<String> {
            val pin = SharingVolume.Open(what, 0, SharingVolume.fileRights(rights.toInt()), share.toInt())
            fun refuses(access: Int, sharing: Int) = SharingVolume.refuses(pin, SharingVolume.fileRights(access), sharing)
            val removal = DELETE or SYNCHRONIZE or FILE_READ_ATTRIBUTES // a rename or deletion of the pinned object
            val destination = SHARE_READ or SHARE_WRITE // a rename or link destination as Windows 11 opens it
            val problems = when (role) {
                Role.FOLDER -> listOfNotNull(
                    "refuses other programs' renames and hard links of files into it".takeIf { refuses(FILE_ADD_FILE or SYNCHRONIZE, destination) },
                    "refuses other programs' renames of folders into it".takeIf { refuses(FILE_ADD_SUBDIRECTORY or SYNCHRONIZE, destination) },
                    "lets another program rename or delete it".takeUnless { refuses(removal, 7) })
                Role.IMMUTABLE -> listOfNotNull(
                    "lets another program open it for writing".takeUnless { refuses(READINESS_PROBE, 7) },
                    "lets another program rename or delete it".takeUnless { refuses(removal, 7) })
                Role.METADATA -> listOfNotNull("takes part in sharing".takeIf { pin.rights and SharingVolume.SHARING_RIGHTS != 0 })
            }
            return problems.map { "$what [${role.name.lowercase()} pin: rights=0x${rights.toString(16)}, share=$share]: $it" }
        }
    }

    /**
     * Just enough C# to find a declared body, the calls inside it and their constant arguments. String and character
     * literals and comments are masked (offsets kept), so brackets and commas inside them never count.
     */
    private class CSharpSource(val name: String, val text: String) {
        class Argument(val text: String, val masked: String)
        class Call(val at: Int, val arguments: List<Argument>) {
            val operand get() = arguments.first().text.replace(Regex("""\s+"""), "")
            val text get() = arguments.joinToString(",") { it.text.replace(Regex("""\s+"""), "") }
        }
        class Opening(val opener: String, val operand: String)
        class Routed(val condition: String?, val whenTrue: Opening, val whenFalse: Opening?)

        val masked = mask(text)
        /** Integer constants this reader can evaluate; others (`64*1024*1024`) are left out. */
        val constants: Map<String, Any> = buildMap<String, Any> {
            for (declaration in Regex("""\bconst\s+(?:u?int|u?long)\s+([^;]+);""").findAll(masked)) for (item in declaration.groupValues[1].split(','))
                runCatching { evaluate(item.substringAfter('='), this) }.onSuccess { put(item.substringBefore('=').trim(), it) }
        }
        private val extern = Regex("""\bextern\s+SafeFileHandle\s+(CreateFileW?)\s*\(""").find(masked)?.groupValues?.get(1) ?: "CreateFileW"

        fun bodyOrNull(declaration: Regex, within: IntRange = masked.indices): IntRange? {
            val found = declaration.findAll(masked).filter { it.range.first in within }.toList()
            check(found.size <= 1) { "$name: ambiguous ${declaration.pattern}" }
            var at = (found.singleOrNull() ?: return null).range.last + 1
            while (masked[at] != '{') { check(masked[at].isWhitespace()) { "$name: no body after ${declaration.pattern}" }; at++ }
            return at..closing(at)
        }
        fun body(declaration: Regex, within: IntRange = masked.indices) =
            requireNotNull(bodyOrNull(declaration, within)) { "$name: no ${declaration.pattern}" }

        /** Calls of [callee] (as written: "VpnInstallNative.OpenRead", "native.Open", "OpenRead") inside [within]. */
        fun calls(callee: String, within: IntRange = masked.indices): List<Call> =
            Regex("""(?<![\w.])${Regex.escape(callee)}\s*\(""").findAll(masked)
                .filter { it.range.first in within && !declared(it.range.first) }
                .map { Call(it.range.first, arguments(it.range.last, closing(it.range.last))) }.toList()

        fun nativeOpens(within: IntRange = masked.indices) = calls(extern, within)

        /** The single CreateFile call in [body], with its access, sharing and flags evaluated. */
        fun pin(body: IntRange, names: Map<String, Any> = emptyMap()): NativeOpen {
            val call = nativeOpens(body).single()
            fun value(index: Int) = evaluate(call.arguments[index].text, constants + names) as Long
            return NativeOpen(value(1), value(2), value(5))
        }

        /** The parameters of [declaration] bound to those [arguments] whose value is constant. */
        fun bind(declaration: Regex, arguments: List<Argument>, names: Map<String, Any> = emptyMap()): Map<String, Any> {
            val open = masked.indexOf('(', declaration.findAll(masked).single().range.first)
            val parameters = text.substring(open + 1, closing(open)).split(',')
                .map { it.substringBefore('=').trim().split(Regex("""\s+""")).last() }
            return parameters.zip(arguments).mapNotNull { (parameter, argument) ->
                runCatching { parameter to evaluate(argument.text, constants + names) }.getOrNull()
            }.toMap()
        }

        /** `native.X(operand)`, or `condition ? native.X(operand) : native.Y(operand)`. */
        fun route(argument: Argument): Routed {
            fun opening(value: String): Opening {
                val match = Regex("""^native\.(\w+)\s*\((.*)\)$""", RegexOption.DOT_MATCHES_ALL).find(value.trim())
                    ?: error("$name: unreadable admission open $value")
                return Opening(match.groupValues[1], match.groupValues[2].replace(Regex("""\s+"""), ""))
            }
            val question = topLevel(argument.masked, '?') ?: return Routed(null, opening(argument.text), null)
            val colon = topLevel(argument.masked, ':', question + 1) ?: error("$name: unreadable condition ${argument.text}")
            return Routed(argument.text.substring(0, question), opening(argument.text.substring(question + 1, colon)),
                opening(argument.text.substring(colon + 1)))
        }

        private fun topLevel(value: String, wanted: Char, from: Int = 0): Int? {
            var depth = 0
            for (index in from until value.length) when (value[index]) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth--
                wanted -> if (depth == 0) return index
            }
            return null
        }

        fun closing(open: Int): Int {
            var depth = 0
            for (index in open until masked.length) when (masked[index]) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> if (--depth == 0) return index
            }
            error("$name: unbalanced bracket at $open")
        }

        private fun arguments(open: Int, close: Int): List<Argument> {
            val ranges = mutableListOf<IntRange>()
            var depth = 0
            var start = open + 1
            for (index in open + 1 until close) when (masked[index]) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> depth--
                ',' -> if (depth == 0) { ranges += start until index; start = index + 1 }
            }
            if (ranges.isNotEmpty() || masked.substring(open + 1, close).isNotBlank()) ranges += start until close
            return ranges.map { range ->
                var first = range.first
                var last = range.last
                while (first <= last && masked[first].isWhitespace()) first++
                while (last >= first && masked[last].isWhitespace()) last--
                Argument(text.substring(first, last + 1), masked.substring(first, last + 1))
            }
        }

        /** A declaration names a type before the method; a call follows an operator, a bracket or a keyword. */
        private fun declared(at: Int): Boolean {
            var index = at - 1
            while (index >= 0 && masked[index].isWhitespace()) index--
            val end = index + 1
            while (index >= 0 && (masked[index].isLetterOrDigit() || masked[index] in "_<>[].")) index--
            val word = masked.substring(index + 1, end)
            return word.isNotEmpty() && (word[0].isLetter() || word[0] == '_') &&
                word !in setOf("return", "throw", "await", "else", "in", "yield", "case", "new")
        }

        private companion object {
            fun mask(text: String): String {
                val out = StringBuilder(text)
                fun blank(from: Int, to: Int) { for (index in from until minOf(to, text.length)) if (out[index] != '\n') out[index] = ' ' }
                var at = 0
                while (at < text.length) {
                    when {
                        text.startsWith("//", at) -> { val end = text.indexOf('\n', at).let { if (it < 0) text.length else it }; blank(at, end); at = end }
                        text.startsWith("/*", at) -> { val end = text.indexOf("*/", at + 2).let { if (it < 0) text.length else it + 2 }; blank(at, end); at = end }
                        text.startsWith("@\"", at) -> {
                            var end = at + 2
                            while (end < text.length && !(text[end] == '"' && text.getOrNull(end + 1) != '"')) end += if (text[end] == '"') 2 else 1
                            blank(at + 2, end); at = end + 1
                        }
                        text[at] == '"' || text[at] == '\'' -> {
                            val quote = text[at]
                            var end = at + 1
                            while (end < text.length && text[end] != quote) end += if (text[end] == '\\') 2 else 1
                            blank(at + 1, end); at = end + 1
                        }
                        else -> at++
                    }
                }
                return out.toString()
            }
        }
    }

    private companion object {
        const val READINESS_PROBE = 0x40020080 // GENERIC_WRITE | READ_CONTROL | READ_ATTRIBUTES, sharing all (TryReady)
        const val BACKUP_SEMANTICS = 0x02000000L // FILE_FLAG_BACKUP_SEMANTICS: the open may name a folder

        val OPEN_DIRECTORY = Regex("""public\s+static\s+SafeFileHandle\s+OpenDirectory\s*\(\s*string\s+path\s*\)""")
        val OPEN_FILE = Regex("""public\s+static\s+SafeFileHandle\s+OpenFile\s*\(\s*string\s+path\s*\)""")
        val OPEN_READ = Regex("""public\s+static\s+SafeFileHandle\s+OpenRead\s*\(\s*string\s+path\s*,\s*bool\s+cancellation\s*\)""")
        val OPEN_INPUT_DELETE = Regex("""static\s+SafeFileHandle\s+OpenInputDelete\s*\(\s*string\s+path\s*\)""")
        val OPEN_INPUT_NAMED_METADATA = Regex("""static\s+SafeFileHandle\s+OpenInputNamedMetadata\s*\(\s*string\s+path\s*\)""")
        val IMAGE_OBJECT_PIN = Regex("""\bImageObjectPin\s*\(\s*string\s+value\s*,\s*string\s+principal\s*\)""")
        val PIN_NON_EMPTY_ANCESTOR = Regex("""public\s+static\s+SafeFileHandle\s+PinNonEmptyAncestor\s*\([^)]*\)""")
        val FIXED_NATIVE = Regex("""sealed\s+class\s+FixedNative\s*:\s*Native""")
        val RETAIN = Regex("""internal\s+static\s+Lease\s+Retain\s*\([^)]*\bNative\s+native\s*\)""")
        val PIN_ANCESTRY = Regex("""static\s+List<Handle>\s+PinAncestry\s*\([^)]*\)""")
        val TAIL_ANCESTOR = Regex("""static\s+void\s+TailAncestor\s*\([^)]*\)""")
        val ORIGINAL_USER = Regex("""public\s+sealed\s+class\s+OriginalUser\s*:\s*IDisposable""")
        val USER_OPEN = Regex("""static\s+SafeFileHandle\s+Open\s*\(\s*string\s+path\s*,\s*uint\s+access\s*,\s*uint\s+share\s*,\s*bool\s+allowMissing\s*=\s*false\s*\)""")
        val PIN_PARENTS = Regex("""static\s+Parents\s+PinParents\s*\([^)]*\)""")
        val MATCH = Regex("""static\s+SafeFileHandle\s+Match\s*\(\s*Target\s+target\s*,\s*uint\s+access\s*\)""")
        val CREATE_PRIVATE = Regex("""SafeFileHandle\s+CreatePrivate\s*\(\s*string\s+path\s*\)""")
        val BROKER_PIN = Regex("""static\s+SafeFileHandle\s+Pin\s*\(\s*string\s+path\s*,\s*bool\s+leaf\s*,[^)]*\)""")
        val BROKER_PIN_WITNESS = Regex("""static\s+void\s+PinWitness\s*\([^)]*\)""")
        val BROKER_PRIVATE_RESOURCE = Regex("""static\s+FileStream\s+OpenPrivateResource\s*\([^)]*\)""")

        /** The methods whose folder-capable opens the tests above judge, per compiled helper source. */
        val JUDGED = mapOf(
            "windows-install-native.cs" to listOf(OPEN_DIRECTORY, OPEN_FILE, OPEN_INPUT_DELETE, OPEN_INPUT_NAMED_METADATA),
            "windows-vpn-broker.cs" to listOf(BROKER_PIN, BROKER_PIN_WITNESS),
            "windows-vpn-user-files.cs" to listOf(USER_OPEN),
        )

        /** Every folder the install helper pins with VpnInstallNative.OpenDirectory, by the operand it passes. */
        val SESSION_FOLDERS = mapOf(
            "launcherDirectory" to "the installation folder (%LOCALAPPDATA%\\vpn-control for a per-user install), " +
                "held by the coordinator's readiness set and the original user's return gate",
            "jobPath" to "the protected job folder, while the coordinator runs",
            "programData" to "C:\\ProgramData, while the coordinator or the original user holds the installer store",
            "machine" to "the installer store C:\\ProgramData\\vpn-control-install-jobs",
            "Path.Combine(VpnInstallNative.ProgramData(),\"vpn-control-install-jobs\",JobId)" to
                "the protected job folder, during the original user's input cleanup",
            "root" to "the volume root of the original user's %LOCALAPPDATA% and of the package's folder",
            "path" to "every folder from there to %LOCALAPPDATA%, its private input root and the job's input folder, " +
                "from request admission until the installation ends",
        )

        /** The broker admission's path pins by operand, with their fixed role, or none for PinAncestry's elements. */
        val ADMISSION_PINS: Map<String, Pair<String, Role?>> = mapOf(
            "query" to ("the owner's image (vpn-control.exe or vpn-control-cli.exe in the installation)" to Role.IMMUTABLE),
            "PlainPath(native.CurrentImage())" to ("the broker's own image" to Role.IMMUTABLE),
            "paths[index]" to ("PinAncestry" to null),
            "programData+\"\\\\vpn-control-install-jobs\"" to ("the installer store C:\\ProgramData\\vpn-control-install-jobs" to Role.FOLDER),
            "root+\"\\\\\"+name" to ("the child that keeps a pinned C:\\ProgramData non-empty" to Role.FOLDER),
        )

        /** Constant C# expressions: integer literals, names, `!`, `-`, `+`, comparisons, `|`, `&`, `&&`, `||` and `?:`. */
        fun evaluate(expression: String, names: Map<String, Any> = emptyMap()): Any {
            val tokens = Regex("""0[xX][0-9A-Fa-f]+[uUlL]*|\d+[uUlL]*|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*|\|\||&&|==|!=|<=|>=|\S""")
                .findAll(expression).map { it.value }.toList()
            var at = 0
            fun take(token: String) = (tokens.getOrNull(at) == token).also { if (it) at++ }
            lateinit var conditional: () -> Any
            fun primary(): Any {
                val token = tokens.getOrNull(at++) ?: error("Truncated expression $expression")
                return when {
                    token == "(" -> conditional().also { check(take(")")) { "Unclosed group in $expression" } }
                    token == "true" -> true
                    token == "false" -> false
                    token[0].isDigit() -> token.trimEnd('u', 'U', 'l', 'L')
                        .let { if (it.length > 2 && it[1] in "xX") it.substring(2).toLong(16) else it.toLong() }
                    else -> names[token] ?: error("Unknown name $token in $expression")
                }
            }
            fun unary(): Any = when {
                take("!") -> !(unary() as Boolean)
                take("-") -> -(unary() as Long)
                else -> primary()
            }
            fun additive(): Any {
                var value = unary()
                while (true) value = when {
                    take("+") -> value as Long + unary() as Long
                    take("-") -> value as Long - unary() as Long
                    else -> return value
                }
            }
            fun relational(): Any {
                val value = additive()
                return when {
                    take("<") -> (value as Long) < additive() as Long
                    take(">") -> (value as Long) > additive() as Long
                    take("<=") -> (value as Long) <= additive() as Long
                    take(">=") -> (value as Long) >= additive() as Long
                    else -> value
                }
            }
            fun equality(): Any {
                var value = relational()
                while (true) value = when {
                    take("==") -> value == relational()
                    take("!=") -> value != relational()
                    else -> return value
                }
            }
            fun bitAnd(): Any { var value = equality(); while (take("&")) value = value as Long and equality() as Long; return value }
            fun bitOr(): Any { var value = bitAnd(); while (take("|")) value = value as Long or bitAnd() as Long; return value }
            fun conjunction(): Any { var value = bitOr(); while (take("&&")) { val right = bitOr(); value = value as Boolean && right as Boolean }; return value }
            fun disjunction(): Any { var value = conjunction(); while (take("||")) { val right = conjunction(); value = value as Boolean || right as Boolean }; return value }
            conditional = {
                val condition = disjunction()
                if (!take("?")) condition else {
                    val whenTrue = conditional()
                    check(take(":")) { "Incomplete condition in $expression" }
                    val whenFalse = conditional()
                    if (condition as Boolean) whenTrue else whenFalse
                }
            }
            return conditional().also { check(at == tokens.size) { "Unread ${tokens.drop(at)} in $expression" } }
        }
    }
}
