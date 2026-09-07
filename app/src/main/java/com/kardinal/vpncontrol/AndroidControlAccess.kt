package com.kardinal.vpncontrol

internal object AndroidControlAccess {
    fun authorize(callingUid: Int, appUid: Int, hasDumpPermission: Boolean) {
        if (callingUid != appUid && (callingUid != 2000 || !hasDumpPermission)) {
            throw SecurityException("PERMISSION_DENIED")
        }
    }

    fun opaqueId(value: String): String {
        require(value.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))) {
            "INVALID_ARGUMENT"
        }
        return value
    }

    fun parseUri(value: String, authority: String): Pair<String, String> {
        val match = Regex("content://${Regex.escape(authority)}/(requests|results)/([0-9a-f-]+)")
            .matchEntire(value) ?: throw IllegalArgumentException("INVALID_ARGUMENT")
        return match.groupValues[1] to opaqueId(match.groupValues[2])
    }

    fun parseDocumentUpload(value: String, authority: String): Pair<String, Long> {
        val match = Regex("content://${Regex.escape(authority)}/document-uploads/([0-9a-f-]+)/(0|[1-9][0-9]*)")
            .matchEntire(value) ?: throw IllegalArgumentException("INVALID_ARGUMENT")
        return opaqueId(match.groupValues[1]) to
            (match.groupValues[2].toLongOrNull() ?: throw IllegalArgumentException("INVALID_ARGUMENT"))
    }
}
