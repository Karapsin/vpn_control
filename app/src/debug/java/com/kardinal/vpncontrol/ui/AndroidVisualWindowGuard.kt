package com.kardinal.vpncontrol.ui

/** Rejects an Android system ANR alert before it can contaminate a visual capture. */
internal object AndroidVisualWindowGuard {
    private val windowRecord = Regex(
        """(?ms)^\s*(?:Window #\d+\s+)?Window\{(?<record>.*?)(?=^\s*(?:Window #\d+\s+)?Window\{|\z)""",
    )

    fun requireNoPrimaryAnr(dumpsysWindowWindows: String) {
        val primaryAnr = windowRecord.findAll(dumpsysWindowWindows)
            .map { it.groups["record"]?.value.orEmpty() }
            .firstOrNull { record ->
                "Application Not Responding:" in record &&
                    Regex("""\bmDisplayId=0\b""").containsMatchIn(record)
            }
        check(primaryAnr == null) {
            "Android visual capture blocked by a primary-display ANR window. " +
                "Preserved dumpsys window windows output:\n$dumpsysWindowWindows"
        }
    }
}
