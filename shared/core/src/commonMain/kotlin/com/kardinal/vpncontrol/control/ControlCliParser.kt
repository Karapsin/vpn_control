package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlOperationId.*

/** Client-side options. Paths must be consumed locally, not sent to an elevated owner. */
data class ControlClientOptions(
    val json: Boolean = false,
    val stateDirectory: String? = null,
    val android: Boolean = false,
    val serial: String? = null,
    val interactive: Boolean = false,
    val asynchronous: Boolean = false,
    val timeoutSeconds: Long = 600,
    val ifRevision: Long? = null,
    val controllerId: String? = null,
)

sealed interface ControlCliParseResult {
    data class Gui(val options: List<String>) : ControlCliParseResult
    data class Help(val operation: ControlOperationId? = null) : ControlCliParseResult
    data object Version : ControlCliParseResult
    data class Invalid(val reason: String) : ControlCliParseResult
    data class Invocation(
        val operation: ControlOperationId,
        val client: ControlClientOptions,
        val positional: List<String>,
        val options: Map<String, String>,
        val flags: Set<String>,
    ) : ControlCliParseResult {
        // Positional values may be source URLs or settings; never log raw invocation arguments.
        override fun toString(): String = "Invocation(operation=${operation.wireName}, arguments=<redacted>)"
    }
}

data class ControlArgumentSchema(
    val positional: List<String> = emptyList(),
    val minimumPositionals: Int = positional.size,
    val valuedOptions: Set<String> = emptySet(),
    val flags: Set<String> = emptySet(),
)

/** Pure token parser, used before any platform startup, workspace access or native UI work. */
object ControlCliParser {
    private val globalFlags = setOf("--json", "--android", "--interactive", "--async", "--help", "--version")
    private val globalValues = setOf("--state-dir", "--serial", "--timeout-seconds", "--if-revision", "--controller-id")
    private val guiFlags = setOf("--autostart", "--tray", "--minimized")
    private val input = setOf("--input", "--qr-image")
    private val output = setOf("--output", "--format")

    fun schema(id: ControlOperationId): ControlArgumentSchema = when (id) {
        STATUS, STATS -> ControlArgumentSchema(flags = setOf("--watch"))
        LOGS -> ControlArgumentSchema(valuedOptions = setOf("--limit"), flags = setOf("--follow"))
        SOURCE_SET -> ControlArgumentSchema(listOf("source", "subscription-id"), 1)
        SUBSCRIPTIONS_SHOW, SUBSCRIPTIONS_DELETE, SUBSCRIPTIONS_REFRESH,
        OPERATIONS_STATUS, OPERATIONS_WAIT, OPERATIONS_CANCEL -> ControlArgumentSchema(listOf("id"))
        SUBSCRIPTIONS_ADD -> ControlArgumentSchema(valuedOptions = input + setOf("--source", "--name"))
        SUBSCRIPTIONS_UPDATE -> ControlArgumentSchema(listOf("id"), valuedOptions = setOf("--source", "--input", "--name"))
        LOCATIONS_SHOW, LOCATIONS_DELETE, LOCATIONS_SELECT, LOCATIONS_BENCHMARK -> ControlArgumentSchema(listOf("selector"))
        LOCATIONS_ADD, LOCATIONS_IMPORT, ROUTING_IMPORT -> ControlArgumentSchema(valuedOptions = input)
        LOCATIONS_UPDATE -> ControlArgumentSchema(listOf("selector"), valuedOptions = setOf("--input"))
        LOCATIONS_EXPORT, ROUTING_EXPORT -> ControlArgumentSchema(valuedOptions = output)
        ROUTING_SET -> ControlArgumentSchema(listOf("key", "value"))
        ROUTING_APPS_LIST, ROUTING_APPS_SELECT_ALL, ROUTING_APPS_CLEAR -> ControlArgumentSchema(valuedOptions = setOf("--search"))
        ROUTING_APPS_ADD, ROUTING_APPS_REMOVE -> ControlArgumentSchema(listOf("package"))
        ROUTING_APPS_SET, SETTINGS_APPLY, SSH_KEY_IMPORT -> ControlArgumentSchema(valuedOptions = setOf("--input"))
        SETTINGS_SHOW -> ControlArgumentSchema(listOf("key"), 0)
        SETTINGS_SET -> ControlArgumentSchema(listOf("key", "value"))
        DIAGNOSTICS_EXPORT -> ControlArgumentSchema(valuedOptions = setOf("--output"))
        ON, OFF, RESTART, FIND_BEST, SOURCE_SHOW, SUBSCRIPTIONS_LIST, LOCATIONS_LIST,
        ROUTING_SHOW, SETTINGS_LANGUAGES, SSH_KEY_STATUS, OPERATIONS_LIST, UPDATES_STATUS,
        UPDATES_CHECK, UPDATES_DOWNLOAD, UPDATES_INSTALL, UPDATES_CANCEL, UPDATES_DISMISS,
        SERVE, GUI_SHOW, GUI_HIDE, QUIT, CAPABILITIES -> ControlArgumentSchema()
    }

    fun parse(args: List<String>): ControlCliParseResult {
        if (args.isEmpty()) return ControlCliParseResult.Gui(emptyList())
        if (args.all { it in guiFlags }) return ControlCliParseResult.Gui(args.distinct())
        val globals = linkedMapOf<String, String>()
        val globalSwitches = linkedSetOf<String>()
        val remaining = mutableListOf<String>()
        var index = 0
        var literal = false
        // Global options precede the command. Local parsing below also accepts them after it.
        while (index < args.size) {
            val token = args[index]
            if (literal) {
                remaining += token
            } else when {
                token == "--" -> { remaining += token; literal = true }
                token in globalFlags -> {
                    if (!globalSwitches.add(token)) return invalid("Duplicate global option.")
                }
                token in globalValues -> {
                    val value = args.getOrNull(++index) ?: return invalid("Missing global option value.")
                    if (value.startsWith("--") || value.isEmpty()) return invalid("Missing global option value.")
                    if (globals.put(token, value) != null) return invalid("Duplicate global option.")
                }
                token.startsWith("--") -> {
                    // Preserve local option and its argument as a unit: a path may equal a global flag.
                    remaining += token
                    val allLocalValues = ControlOperationId.entries.flatMap { schema(it).valuedOptions }.toSet()
                    if (token in allLocalValues) {
                        val value = args.getOrNull(++index) ?: return invalid("Missing command option value.")
                        remaining += value
                    }
                }
                else -> remaining += token
            }
            index++
        }
        val timeout = globals["--timeout-seconds"]?.toLongOrNull() ?: if ("--timeout-seconds" in globals) {
            return invalid("Timeout must be a non-negative integer.")
        } else 600L
        if (timeout < 0 || timeout > Long.MAX_VALUE / 1000) return invalid("Timeout is outside the supported range.")
        val revision = globals["--if-revision"]?.toLongOrNull()
        if ("--if-revision" in globals && (revision == null || revision < 0)) return invalid("Revision must be a non-negative integer.")
        val controllerId = globals["--controller-id"]
        if (controllerId != null && (controllerId.isBlank() || controllerId.length > 256 || controllerId.any { it.isWhitespace() || it.isISOControl() }))
            return invalid("Invalid controller identity.")
        if (revision != null && controllerId == null) return invalid("Revision guards require --controller-id from the observed snapshot.")
        val client = ControlClientOptions(
            json = "--json" in globalSwitches, stateDirectory = globals["--state-dir"],
            android = "--android" in globalSwitches, serial = globals["--serial"],
            interactive = "--interactive" in globalSwitches, asynchronous = "--async" in globalSwitches,
            timeoutSeconds = timeout, ifRevision = revision, controllerId = controllerId,
        )
        if (client.serial != null && !client.android) return invalid("Serial requires Android target.")
        if (client.stateDirectory != null && client.android) return invalid("State directory is desktop-only.")
        if ("--help" in globalSwitches && "--version" in globalSwitches) return invalid("Choose help or version.")
        if ("--version" in globalSwitches) {
            return if (remaining.isEmpty()) ControlCliParseResult.Version else invalid("Version takes no command.")
        }
        if (remaining == listOf("help") || (remaining.isEmpty() && "--help" in globalSwitches)) return ControlCliParseResult.Help()
        if (remaining.isEmpty()) return invalid("Missing command.")
        val matches = ControlOperationRegistry.operations.flatMap { descriptor ->
            (listOf(descriptor.commandWords) + descriptor.aliases.map { it.split(' ') }).map { descriptor to it }
        }.filter { (_, words) -> remaining.take(words.size) == words }
        val match = matches.maxByOrNull { it.second.size } ?: return invalid("Unknown command or option.")
        val descriptor = match.first
        val schema = schema(descriptor.id)
        val positionals = mutableListOf<String>()
        val options = linkedMapOf<String, String>()
        val flags = linkedSetOf<String>()
        index = match.second.size
        literal = false
        while (index < remaining.size) {
            val token = remaining[index]
            when {
                literal -> positionals += token
                token == "--" -> literal = true
                token in schema.flags -> if (!flags.add(token)) return invalid("Duplicate command option.")
                token in schema.valuedOptions -> {
                    val value = remaining.getOrNull(++index) ?: return invalid("Missing command option value.")
                    val allowsEmptyName = token == "--name" && descriptor.id in setOf(SUBSCRIPTIONS_ADD, SUBSCRIPTIONS_UPDATE)
                    if ((value.isEmpty() && !allowsEmptyName) || value.startsWith("--")) return invalid("Missing command option value.")
                    if (options.put(token, value) != null) return invalid("Duplicate command option.")
                }
                token.startsWith('-') -> return invalid("Unknown command option.")
                else -> positionals += token
            }
            index++
        }
        if ("--help" in globalSwitches) {
            return if (positionals.isEmpty() && options.isEmpty() && flags.isEmpty()) {
                ControlCliParseResult.Help(descriptor.id)
            } else invalid("Command help takes no arguments.")
        }
        // Legacy select accepted an unquoted multi-word name. Keep it without changing other grammar.
        val normalizedPositionals = if (match.second == listOf("select") && positionals.isNotEmpty()) {
            listOf(positionals.joinToString(" "))
        } else positionals.toList()
        if (normalizedPositionals.size !in schema.minimumPositionals..schema.positional.size ||
            normalizedPositionals.any { it.isBlank() }) return invalid("Incorrect command arguments.")
        if (client.asynchronous && !descriptor.supportsAsync) return invalid("This command does not support asynchronous execution.")
        if (client.ifRevision != null && !descriptor.mutates) return invalid("Revision guards apply only to mutations.")
        if (client.json && options["--output"] == "-") return invalid("JSON output cannot be combined with a raw stdout export.")
        if ("--format" in options && options["--format"] !in setOf("json", "qr-png")) return invalid("Unsupported export format.")
        if ("--limit" in options && (options["--limit"]?.toIntOrNull()?.let { it >= 0 } != true)) return invalid("Log limit must be a non-negative integer.")
        val inputCount = options.keys.count { it in input || it == "--source" }
        when (descriptor.id) {
            SUBSCRIPTIONS_ADD, LOCATIONS_ADD, LOCATIONS_UPDATE, LOCATIONS_IMPORT,
            ROUTING_IMPORT, ROUTING_APPS_SET, SETTINGS_APPLY, SSH_KEY_IMPORT ->
                if (inputCount != 1) return invalid("Exactly one input is required.")
            SUBSCRIPTIONS_UPDATE ->
                if (inputCount > 1 || (inputCount == 0 && "--name" !in options)) return invalid("Provide a name or one input to update.")
            LOCATIONS_EXPORT, ROUTING_EXPORT, DIAGNOSTICS_EXPORT ->
                if ("--output" !in options) return invalid("An output destination is required.")
            SOURCE_SET -> {
                val source = normalizedPositionals.first()
                if (source !in setOf("current-locations", "subscription", "all") ||
                    normalizedPositionals.size != if (source == "subscription") 2 else 1) return invalid("Invalid source selection.")
            }
            ROUTING_SET -> if (normalizedPositionals.first() !in setOf("ignore-rules", "direct-domains", "block-quic-udp443")) {
                return invalid("Unknown routing setting.")
            }
            else -> Unit
        }
        return ControlCliParseResult.Invocation(descriptor.id, client, normalizedPositionals, options, flags)
    }

    private fun invalid(reason: String) = ControlCliParseResult.Invalid(reason)
}
