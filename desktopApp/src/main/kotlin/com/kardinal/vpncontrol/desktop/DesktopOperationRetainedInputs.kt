package com.kardinal.vpncontrol.desktop

import java.util.IdentityHashMap

/** Exact in-memory cleanup owners. No entry is a command or a request to replay an operation. */
internal class DesktopOperationRetainedInputs {
    private enum class State { RETAINED, RELEASING, RELEASED }
    private class Entry(val input: AutoCloseable, var state: State = State.RETAINED)

    private val guard = Any()
    private val entries = IdentityHashMap<AutoCloseable, Entry>()
    private var terminal = false

    val hasRetainedInputs: Boolean
        get() = synchronized(guard) { entries.values.any { it.state != State.RELEASED } }

    fun retain(input: AutoCloseable) = synchronized(guard) {
        check(!terminal) { "CONFLICT" }
        val previous = entries[input]
        check(previous == null || previous.state == State.RETAINED) { "CONFLICT" }
        if (previous == null) entries[input] = Entry(input)
    }

    fun release(input: AutoCloseable): Result<Unit> {
        val entry = synchronized(guard) {
            val found = entries[input] ?: return Result.failure(IllegalStateException("CONFLICT"))
            when (found.state) {
                State.RELEASED -> return Result.success(Unit)
                State.RELEASING -> return Result.failure(IllegalStateException("UNAVAILABLE"))
                State.RETAINED -> found.state = State.RELEASING
            }
            found
        }
        var released = false
        return try {
            entry.input.close()
            released = true
            Result.success(Unit)
        } catch (failure: Exception) {
            Result.failure(failure)
        } finally {
            // A failed release, including a VM error, leaves the exact owner available.
            synchronized(guard) { entry.state = if (released) State.RELEASED else State.RETAINED }
        }
    }

    /** Called only after the operation's native outcome and enclosing decision are both known. */
    fun releaseAllTerminal(): Result<Unit> {
        val inputs = synchronized(guard) {
            terminal = true
            entries.values.filter { it.state != State.RELEASED }.map { it.input }
        }
        var failure: Throwable? = null
        for (input in inputs) {
            release(input).exceptionOrNull()?.let { error ->
                if (failure == null) failure = error
                else if (failure !== error) failure?.addSuppressed(error)
            }
        }
        return failure?.let { Result.failure(it) } ?: Result.success(Unit)
    }

    override fun toString() = "DesktopOperationRetainedInputs(<redacted>)"
}
