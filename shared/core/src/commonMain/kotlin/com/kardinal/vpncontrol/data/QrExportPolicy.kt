package com.kardinal.vpncontrol.data

/** Shared product limit, independent of a barcode library or platform image API. */
object QrExportPolicy {
    const val MAX_UTF8_BYTES = 1600

    fun byteCount(payload: String): Int = payload.encodeToByteArray().size

    fun fits(payload: String): Boolean = byteCount(payload) <= MAX_UTF8_BYTES

    fun validate(payload: String): Result<String> = runCatching {
        require(payload.isNotEmpty()) { "INVALID_ARGUMENT" }
        // Do not silently replace malformed surrogate sequences in exported configuration.
        payload.encodeToByteArray(throwOnInvalidSequence = true)
        require(fits(payload)) { "QR_TOO_LARGE" }
        payload
    }
}
