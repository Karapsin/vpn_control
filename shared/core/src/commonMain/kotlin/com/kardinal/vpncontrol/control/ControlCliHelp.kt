package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlOperationId

/** Help is derived from the same registry that accepts public commands. */
object ControlCliHelp {
    fun render(executable: String, operation: ControlOperationId? = null): String = buildString {
        appendLine("Usage: $executable [options] <command>")
        appendLine()
        val descriptors = operation?.let { listOf(ControlOperationRegistry[it]) } ?: ControlOperationRegistry.operations
        for (descriptor in descriptors) {
            appendLine("  $executable ${descriptor.grammar}")
            if (descriptor.aliases.isNotEmpty()) appendLine("    Aliases: ${descriptor.aliases.joinToString()}")
        }
        appendLine()
        appendLine("Options: --help, --version, --json, --async, --timeout-seconds N (default 600; 0 unlimited)")
        appendLine("  --controller-id ID --if-revision N (from the same observed controller)")
        appendLine("  --state-dir PATH (desktop); --android [--serial SERIAL] [--interactive]")
        appendLine("GUI startup: --autostart, --tray, --minimized")
        append("Use capabilities to inspect platform support. A wait timeout does not cancel accepted work.")
    }
}
