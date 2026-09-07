package com.kardinal.vpncontrol

/** Private application/service bridge. Never starts an Android component or grants OS permission. */
internal interface AndroidRetainedRuntimeSession {
    suspend fun dispatch(action: AndroidRuntimeAction, commandId: String, preparedId: String? = null)
    suspend fun release(): Result<Unit>
}

/** Service-local identity; caller holds the service command mutex around effects. */
internal class AndroidRuntimeRetentionGate {
    private var token: String? = null
    val occupied: Boolean get() = token != null
    fun acquire(expected: AndroidRuntimeObservation, actual: AndroidRuntimeObservation, available: Boolean): String? {
        if (occupied || !available || expected.knowledge != AndroidRuntimeKnowledge.RUNNING || expected != actual) return null
        return java.util.UUID.randomUUID().toString().also { token = it }
    }
    fun checkCurrent(candidate: String, available: Boolean = true) { check(available && token == candidate) { "RUNTIME_COMMAND_STALE" } }
    fun release(candidate: String) { checkCurrent(candidate); token = null }
}

internal class AndroidRetainedRuntimeServices {
    internal interface Host { suspend fun acquire(expected: AndroidRuntimeObservation): AndroidRetainedRuntimeSession? }
    @Volatile private var host: Host? = null
    @Synchronized fun register(value: Host) { host = value }
    @Synchronized fun unregister(value: Host) { if (host === value) host = null }
    suspend fun acquire(expected: AndroidRuntimeObservation): AndroidRetainedRuntimeSession? =
        host?.takeIf { expected.knowledge == AndroidRuntimeKnowledge.RUNNING }?.acquire(expected)
}
