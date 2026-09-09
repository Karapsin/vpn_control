package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.shared.storageapi.RuntimeConfigStore
import java.util.IdentityHashMap
import java.util.concurrent.TimeUnit
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** One owner retains every native child until its exit is established, including response loss. */
internal class DesktopRuntimeTransition(
    private val store: RuntimeConfigStore,
    private val prepare: suspend (DesktopRuntimeLaunch, CoroutineContext) -> DesktopPreparedRuntimeProcess,
    private val ready: suspend (DesktopRuntimeProcess, DesktopRuntimeLaunch) -> Boolean,
    private val publish: (DesktopRuntimeLaunch?, DesktopRuntimeProcess?) -> Unit,
    private val retire: (DesktopRuntimeLaunch) -> Unit,
) {
    private val mutex = Mutex()
    private val retentionLock = Any()
    private var active: Pair<DesktopRuntimeLaunch, DesktopRuntimeProcess>? = null
    private val retainedDisposals = mutableSetOf<DesktopRuntimeProcess>()
    private val retainedAdmissions = mutableSetOf<AutoCloseable>()
    private val retiredInputs = mutableSetOf<DesktopRuntimeLaunch>()
    private val restoreLeaseCounts = IdentityHashMap<DesktopRuntimeLaunch, Int>()
    private val deferredRetirements = java.util.Collections.newSetFromMap(IdentityHashMap<DesktopRuntimeLaunch, Boolean>())

    /** This is deliberately synchronous: callers capture while holding their own state lock. */
    fun captureRestoreLease(): DesktopRuntimeRestoreLease? {
        val launch = synchronized(retentionLock) {
            val captured = active?.takeIf { it.second.isAlive }?.first ?: return null
            restoreLeaseCounts[captured] = (restoreLeaseCounts[captured] ?: 0) + 1
            captured
        }
        return RetainedRestoreLease(launch)
    }

    private inner class RetainedRestoreLease(private val launch: DesktopRuntimeLaunch) : DesktopRuntimeRestoreLease {
        private val lock = Any()
        private var closed = false
        private var restoring = false
        private var released = false

        override suspend fun restore(): Result<DesktopRuntimeSession> {
            synchronized(lock) {
                if (closed || restoring) return Result.failure(IllegalStateException("UNAVAILABLE"))
                restoring = true
            }
            return try {
                restoreRetained(launch, currentCoroutineContext())
            } finally {
                synchronized(lock) { restoring = false }
                val release = releaseIfTerminal()
                // A close racing an await on transition.mutex retains A until preparation or
                // recovery has reached a terminal result.
                if (release) releaseRestoreLease(launch)
            }
        }

        override fun close() {
            synchronized(lock) { closed = true }
            if (releaseIfTerminal()) releaseRestoreLease(launch)
        }

        private fun releaseIfTerminal(): Boolean = synchronized(lock) {
            if (closed && !restoring && !released) {
                released = true
                true
            } else false
        }
    }

    private fun releaseRestoreLease(launch: DesktopRuntimeLaunch) {
        val retire = synchronized(retentionLock) {
            val remaining = (restoreLeaseCounts[launch] ?: return).minus(1)
            if (remaining > 0) {
                restoreLeaseCounts[launch] = remaining
                false
            } else {
                restoreLeaseCounts.remove(launch)
                deferredRetirements.remove(launch) && active?.first !== launch
            }
        }
        if (retire) retireWhenPossible(launch)
    }

    private fun publishActive(value: Pair<DesktopRuntimeLaunch, DesktopRuntimeProcess>?) = synchronized(retentionLock) {
        active = value
        value?.first?.let {
            // A reactivated retained A is live again; its deferred retirement is obsolete.
            deferredRetirements.remove(it)
            retiredInputs.remove(it)
        }
    }

    private fun activeSnapshot(): Pair<DesktopRuntimeLaunch, DesktopRuntimeProcess>? = synchronized(retentionLock) { active }

    private fun activeSession(launch: DesktopRuntimeLaunch): DesktopRuntimeSession? = synchronized(retentionLock) {
        active?.takeIf { (activeLaunch, child) -> activeLaunch === launch && child.isAlive }
            ?.let { (activeLaunch, child) -> activeLaunch.session(child) }
    }

    private suspend fun restoreRetained(
        launch: DesktopRuntimeLaunch,
        context: CoroutineContext,
    ): Result<DesktopRuntimeSession> = mutex.withLock {
        activeSession(launch)?.let { Result.success(it) } ?: startLocked(context) { launch }
    }

    suspend fun start(context: CoroutineContext, build: suspend () -> DesktopRuntimeLaunch): Result<DesktopRuntimeSession> =
        mutex.withLock { startLocked(context, build) }

    private suspend fun startLocked(
        context: CoroutineContext,
        build: suspend () -> DesktopRuntimeLaunch,
    ): Result<DesktopRuntimeSession> {
        val former = activeSnapshot()
        val previous = former?.takeIf { it.second.isAlive }
        var candidate: DesktopRuntimeLaunch? = null
        var prepared: DesktopPreparedRuntimeProcess? = null
        var started: DesktopRuntimeProcess? = null
        var previousStopped = false
        val resourceWarnings = mutableListOf<DesktopRuntimeResourceWarning>()
        return try {
            retryRetiredInputs()
            check(synchronized(retentionLock) { retiredInputs.size < 4 }) { "UNAVAILABLE" }
            context.ensureActive()
            val requested = build()
            candidate = requested
            val authorization = prepare(requested, context)
            prepared = authorization
            context.ensureActive()
            // Authorization and preparation have completed with actual A still untouched.
            withContext(NonCancellable) {
                activeSnapshot()?.let { (_, child) -> resourceWarnings += dispose(child) }
                publishActive(null)
                publish(null, null)
                previousStopped = true
                if (resourceWarnings.any { it.disposition == DesktopRuntimeResourceDisposition.PENDING_PUBLICATION })
                    throw DesktopRuntimeResourcePublicationFailure(resourceWarnings)
            }
            context.ensureActive()
            val child = authorization.commit()
            started = child
            authorization.close()
            prepared = null
            val running = withContext(context[kotlinx.coroutines.Job] ?: NonCancellable) { ready(child, requested) }
            if (!running) throw DesktopWindowsRuntimeFailure("RUNTIME_FAILED")
            context.ensureActive()
            store.writeRuntimeConfig(requested.configJson)
            val session = requested.session(child).let { it.copy(resourceWarnings = resourceWarnings + it.resourceWarnings) }
            publishActive(requested to child)
            publish(requested, child)
            former?.first?.let(::retireWhenPossible)
            desktopControlConfirmOutcome()
            Result.success(session)
        } catch (failure: Exception) {
            withContext(NonCancellable) {
                // A lost native reply never releases the retained ownership supplied by the broker.
                (failure as? DesktopWindowsRuntimeFailure)?.unresolvedRuntime?.let { resourceWarnings += dispose(it) }
                (failure as? DesktopWindowsRuntimeFailure)?.retainedAdmission?.let { disposeAdmission(it) }
                started?.let { resourceWarnings += dispose(it) }
                prepared?.let { disposePrepared(it) }
                var recovered: DesktopRuntimeSession? = null
                var recoveryFailed = false
                if (previousStopped) {
                    if (previous != null) {
                        // A pending publication retains the newest owned cache bytes. Until that
                        // lease is admitted for recovery, opening the old user path would lose them.
                        // Production scoped resources remain gated while that admission is wired.
                        if (resourceWarnings.none { it.disposition == DesktopRuntimeResourceDisposition.PENDING_PUBLICATION })
                            recovered = recover(previous.first)
                        recoveryFailed = recovered == null
                    } else {
                        runCatching { store.clearRuntimeConfig() }
                    }
                }
                candidate?.let(::retireWhenPossible)
                if (recoveryFailed) previous?.first?.let(::retireWhenPossible)
                desktopControlConfirmOutcome()
                val observedCode = failureCode(failure)
                val code = if (failure is CancellationException || context[kotlinx.coroutines.Job]?.isActive == false)
                    ControlCode.CANCELLED else when (observedCode) {
                        // The control transport is healthy. Native disposal has now established
                        // failure; transport-class codes would keep the public ledger nonterminal.
                        ControlCode.OUTCOME_UNKNOWN, ControlCode.UNAVAILABLE, ControlCode.TIMEOUT,
                        ControlCode.INCOMPATIBLE_PROTOCOL -> ControlCode.RUNTIME_FAILED
                        else -> observedCode
                    }
                if (recovered != null || recoveryFailed) {
                    Result.failure(DesktopRuntimeTransitionFailure(code, recovered, recoveryFailed, resourceWarnings.toList()))
                } else if (code == ControlCode.CANCELLED || code != observedCode) {
                    Result.failure(DesktopWindowsRuntimeFailure(code.name))
                } else Result.failure(failure)
            }
        }
    }

    suspend fun stop(): Result<Unit> = mutex.withLock {
        withContext(NonCancellable) {
            runCatching {
                val resourceWarnings = mutableListOf<DesktopRuntimeResourceWarning>()
                activeSnapshot()?.let { (launch, child) ->
                    resourceWarnings += dispose(child)
                    publishActive(null)
                    publish(null, null)
                    retireWhenPossible(launch)
                }
                retainedDisposals.toList().forEach { resourceWarnings += dispose(it) }
                retainedAdmissions.toList().forEach { disposeAdmission(it) }
                store.clearRuntimeConfig()
                retryRetiredInputs()
                desktopControlConfirmOutcome()
                if (resourceWarnings.isNotEmpty()) throw DesktopRuntimeResourcePublicationFailure(resourceWarnings)
            }
        }
    }

    private suspend fun recover(launch: DesktopRuntimeLaunch): DesktopRuntimeSession? {
        var prepared: DesktopPreparedRuntimeProcess? = null
        var child: DesktopRuntimeProcess? = null
        return try {
            // Use the original immutable descriptor and retained captures, never staged settings B.
            val authorization = prepare(launch, currentCoroutineContext())
            prepared = authorization
            val recovered = authorization.commit()
            child = recovered
            authorization.close()
            prepared = null
            if (!ready(recovered, launch)) throw DesktopWindowsRuntimeFailure("RUNTIME_FAILED")
            store.writeRuntimeConfig(launch.configJson)
            publishActive(launch to recovered)
            publish(launch, recovered)
            launch.session(recovered)
        } catch (failure: Exception) {
            (failure as? DesktopWindowsRuntimeFailure)?.unresolvedRuntime?.let { dispose(it) }
            (failure as? DesktopWindowsRuntimeFailure)?.retainedAdmission?.let { disposeAdmission(it) }
            child?.let { dispose(it) }
            prepared?.let { disposePrepared(it) }
            publishActive(null)
            publish(null, null)
            runCatching { store.clearRuntimeConfig() }
            null
        }
    }

    private suspend fun disposePrepared(prepared: DesktopPreparedRuntimeProcess) {
        try { prepared.close() }
        catch (failure: DesktopWindowsRuntimeFailure) {
            if (failure.unresolvedRuntime == null && failure.retainedAdmission == null) throw failure
            failure.unresolvedRuntime?.let { dispose(it) }
            failure.retainedAdmission?.let { disposeAdmission(it) }
        }
    }

    private suspend fun disposeAdmission(admission: AutoCloseable) {
        retainedAdmissions += admission
        while (runCatching { admission.close() }.isFailure) {
            desktopControlReportPendingOutcome()
            delay(250)
        }
        retainedAdmissions -= admission
    }

    private suspend fun dispose(child: DesktopRuntimeProcess): List<DesktopRuntimeResourceWarning> {
        retainedDisposals += child
        while (true) {
            var resourceWarnings = emptyList<DesktopRuntimeResourceWarning>()
            val stopped = runCatching {
                if (child.isAlive) {
                    runCatching { child.destroy() }
                    if (!child.waitFor(2, TimeUnit.SECONDS)) {
                        runCatching { child.destroyForcibly() }
                        if (!child.waitFor(2, TimeUnit.SECONDS)) return@runCatching false
                    }
                }
                try { child.close() }
                catch (publication: DesktopRuntimeResourcePublicationFailure) {
                    // This typed failure guarantees native exit and native-handle disposal. Its
                    // journal owns durable bytes; keeping a fictitious live child would hang quit.
                    resourceWarnings = publication.warnings
                }
                true
            }.getOrDefault(false)
            if (stopped) {
                retainedDisposals -= child
                return resourceWarnings
            }
            desktopControlReportPendingOutcome()
            delay(250)
        }
    }

    private fun retireWhenPossible(launch: DesktopRuntimeLaunch) {
        val mayRetire = synchronized(retentionLock) {
            // A lease pins actual A across a successful B until its owner commits or rolls back.
            // Do not drop immutable files merely because B has already published.
            if (restoreLeaseCounts.containsKey(launch) || active?.first === launch) {
                deferredRetirements += launch
                false
            } else {
                retiredInputs += launch
                true
            }
        }
        if (mayRetire && runCatching { retire(launch) }.isSuccess) synchronized(retentionLock) {
            retiredInputs.remove(launch)
        }
    }

    private fun retryRetiredInputs() = synchronized(retentionLock) { retiredInputs.toList() }.forEach(::retireWhenPossible)

    private fun failureCode(failure: Exception): ControlCode =
        ControlCode.entries.firstOrNull { it.name == failure.message } ?: when (failure) {
            is IllegalArgumentException -> ControlCode.INVALID_ARGUMENT
            is DesktopPersistenceException -> ControlCode.PERSISTENCE_FAILED
            else -> ControlCode.RUNTIME_FAILED
        }
}
