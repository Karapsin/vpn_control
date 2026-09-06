package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlValue

/** Reuse command grammar for typed requests; `input` is content, never a server path. */
object ControlCommandArguments {
    fun decode(command: ControlCommand): ControlCliParseResult.Invocation? {
        val schema = ControlCliParser.schema(command.operation)
        val optionNames = schema.valuedOptions.associateBy { it.removePrefix("--") }
        if (command.arguments.keys.any { it !in schema.positional && it !in optionNames } ||
            command.arguments.values.any { it !is ControlValue.Text }) return null
        val values = command.arguments.mapValues { (it.value as ControlValue.Text).value }
        val positionals = schema.positional.mapNotNull { values[it] }
        // Optional positional holes must not shift later values into another argument.
        if (schema.positional.take(positionals.size).any { it !in values }) return null
        val options = values.filterKeys { it in optionNames }.mapKeys { optionNames.getValue(it.key) }
        val tokens = command.operation.wireName.split('.') + options.flatMap { (name, value) ->
            listOf(name, if (name == "--input") "-" else value)
        } + listOf("--") + positionals
        val parsed = ControlCliParser.parse(tokens) as? ControlCliParseResult.Invocation ?: return null
        return parsed.copy(options = options)
    }
}
