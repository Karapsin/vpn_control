package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.ImportPreference

object MainActivityTestBridge {
    fun clearImportOverrides() {
        ImportTestHooks.clear()
    }

    fun setClipboardOverride(value: String?) {
        ImportTestHooks.clipboardTextOverride = value
    }

    fun invokeImportFromClipboard(activity: MainActivity, preference: ImportPreference) {
        activity.invokePrivate("importClipboardAs", preference)
    }

    fun invokePasteSubscriptionFromClipboard(activity: MainActivity) {
        activity.invokePrivate("pasteSubscriptionFromClipboard")
    }

    fun invokeImportFile(
        activity: MainActivity,
        preference: ImportPreference,
        raw: String,
    ) {
        activity.invokePrivate("handleImportedFileContent", raw, preference)
    }

    fun invokeSubscriptionQrImport(activity: MainActivity, raw: String) {
        activity.setQrImportMode("SUBSCRIPTION")
        activity.invokePrivate("handleQrImportResult", raw)
    }

    fun invokeLocationQrImport(activity: MainActivity, raw: String) {
        activity.setQrImportMode("LOCATION")
        activity.invokePrivate("handleQrImportResult", raw)
    }

    fun invokeRoutingRulesQrImport(activity: MainActivity, raw: String) {
        activity.setQrImportMode("ROUTING_RULES")
        activity.invokePrivate("handleQrImportResult", raw)
    }

    private fun MainActivity.setQrImportMode(name: String) {
        val field = MainActivity::class.java.getDeclaredField("pendingQrImportMode")
        field.isAccessible = true
        val constants = requireNotNull(field.type.enumConstants)
        val value = constants.first { (it as Enum<*>).name == name }
        field.set(this, value)
    }

    private fun MainActivity.invokePrivate(name: String, vararg args: Any) {
        val argTypes = args.map { it.javaClass }.toTypedArray()
        val method = MainActivity::class.java.getDeclaredMethod(name, *argTypes)
        method.isAccessible = true
        method.invoke(this, *args)
    }
}
