package com.kardinal.vpncontrol

import java.util.IdentityHashMap

/** Message-free, bounded diagnostic shape for failures that may contain secrets. */
internal object AndroidFailureTrace {
    private const val MAX_CAUSES = 4
    private const val MAX_FRAMES_PER_CAUSE = 12

    fun format(stage: String, failure: Throwable): String = buildString {
        append("stage=").append(stage)
        val seen = IdentityHashMap<Throwable, Unit>()
        var current: Throwable? = failure
        var cause = 0
        while (current != null && cause < MAX_CAUSES && seen.put(current, Unit) == null) {
            append(" cause[").append(cause).append("]=")
            append(current.javaClass.name)
            current.stackTrace.take(MAX_FRAMES_PER_CAUSE).forEach { frame ->
                append(" @").append(frame.className).append('#').append(frame.methodName)
                    .append(':').append(frame.lineNumber)
            }
            current = current.cause
            cause++
        }
        if (current != null) append(if (seen.containsKey(current)) " cause_cycle" else " cause_limit")
    }
}

/** A completed search had no candidate that passed active verification. */
internal class AndroidFindBestNoVerifiedCandidateException : IllegalStateException()
