package com.kardinal.vpncontrol.desktop

internal fun desktopAppChildProcess(command: List<String>, environment: Map<String, String> = System.getenv()): ProcessBuilder =
    ProcessBuilder(command).apply {
        environment().clear()
        environment().putAll(environment)
        val executable = command.first().replace('\\', '/').substringAfterLast('/').lowercase(java.util.Locale.ROOT)
        if (executable !in setOf("java", "java.exe", "javaw.exe")) {
            // jpackage's private marker describes the current launcher's internal re-exec only.
            // Inheriting it makes a new packaged launcher parse app arguments as JVM options.
            environment().remove("_JPACKAGE_LAUNCHER")
        }
    }
