package com.kardinal.vpncontrol.model

object ControlTransferLimits {
    const val CHUNK_BYTES = 65_536
    const val FRAME_BYTES = 100_000
}

enum class ControlTransferPurpose(val wireName: String) {
    LOCATIONS_INPUT("locations.input"), ROUTING_INPUT("routing.input"), SETTINGS_INPUT("settings.input"),
    SSH_KEY_INPUT("ssh-key.input"), LOCATIONS_EXPORT("locations.export"), ROUTING_EXPORT("routing.export"),
    DIAGNOSTICS_EXPORT("diagnostics.export"),
}

/** Supplied by the authenticated adapter, never trusted from a request body. */
data class ControlTransferBinding(val ownerId: String, val principal: String, val purpose: ControlTransferPurpose) {
    override fun toString() = "ControlTransferBinding(<redacted>)"
}

data class ControlTransferManifest(val id: String, val byteCount: Long, val sha256: String?, val chunkBytes: Int = ControlTransferLimits.CHUNK_BYTES) {
    override fun toString() = "ControlTransferManifest(byteCount=$byteCount, sealed=${sha256 != null})"
}

class ControlTransferChunk(val id: String, val offset: Long, val bytes: ByteArray) {
    override fun toString() = "ControlTransferChunk(<redacted>)"
}

sealed interface ControlTransferCommand {
    data class Begin(val requestId: String) : ControlTransferCommand
    class Append(val id: String, val offset: Long, val bytes: ByteArray) : ControlTransferCommand {
        override fun toString() = "Append(<redacted>)"
    }
    data class Seal(val id: String, val byteCount: Long, val sha256: String) : ControlTransferCommand {
        override fun toString() = "Seal(<redacted>)"
    }
    data class Read(val id: String, val offset: Long, val length: Int) : ControlTransferCommand
    data class Discard(val id: String) : ControlTransferCommand
}
