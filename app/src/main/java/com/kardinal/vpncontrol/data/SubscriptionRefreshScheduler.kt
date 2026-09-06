package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.isAllSubscriptionsGroupActive
import com.kardinal.vpncontrol.shared.storageapi.RefreshScheduler
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executor
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

internal class SubscriptionRefreshScheduler(
    private val workOperations: SubscriptionRefreshWorkOperations,
    private val diagnosticsLogger: (String) -> Unit = {},
    private val latestState: (suspend () -> PersistedState)? = null,
) : RefreshScheduler {
    constructor(context: Context, latestState: suspend () -> PersistedState) : this(
        workOperations = AndroidSubscriptionRefreshWorkOperations(context),
        diagnosticsLogger = { message -> DiagnosticsLogger.append(context, message) },
        latestState = latestState,
    )
    private val scheduling = Mutex()

    override suspend fun sync(state: PersistedState) {
        scheduling.withLock { schedule(latestState?.invoke() ?: state) }
    }

    override suspend fun scheduleNext(state: PersistedState) {
        scheduling.withLock { schedule(latestState?.invoke() ?: state) }
    }

    private suspend fun schedule(state: PersistedState) {
        val intervalMinutes = state.subscriptionRefreshPolicy
            .effectiveIntervalMinutes(state.subscriptionRefreshCustomHours)
        val refreshAll = isAllSubscriptionsGroupActive(state.activeSubscriptionId, state.subscriptions)
        val validSource = if (refreshAll) {
            state.subscriptions.any { subscription ->
                subscription.url.isNotBlank() &&
                    RemoteSourceResolver.validateProfileSource(subscription.url).isSuccess
            }
        } else {
            state.profileUrl.isNotBlank() && RemoteSourceResolver.validateProfileSource(state.profileUrl).isSuccess
        }
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION ||
            intervalMinutes == null ||
            !validSource
        ) {
            workOperations.cancelUniqueWork(WORK_NAME).await()
            diagnosticsLogger(
                "Subscription refresh scheduling canceled: mode=${state.profileSourceMode} activeUrlSet=${state.profileUrl.isNotBlank()} subscriptions=${state.subscriptions.size} policy=${state.subscriptionRefreshPolicy} refreshAll=$refreshAll validSource=$validSource",
            )
            return
        }

        workOperations.enqueueUniqueRefresh(
            workName = WORK_NAME,
            policy = ExistingWorkPolicy.REPLACE,
            intervalMinutes = intervalMinutes,
        ).await()
        diagnosticsLogger(
            "Subscription refresh scheduled: policy=${state.subscriptionRefreshPolicy} refreshAll=$refreshAll intervalMinutes=$intervalMinutes workPolicy=${ExistingWorkPolicy.REPLACE}",
        )
    }

    companion object {
        const val WORK_NAME = "subscription-refresh-work"
    }

    override fun cancel() {
        workOperations.cancelUniqueWork(WORK_NAME)
    }
}

internal interface SubscriptionRefreshWorkOperations {
    fun cancelUniqueWork(workName: String): SubscriptionRefreshCompletion

    fun enqueueUniqueRefresh(
        workName: String,
        policy: ExistingWorkPolicy,
        intervalMinutes: Long,
    ): SubscriptionRefreshCompletion
}

internal fun interface SubscriptionRefreshCompletion { suspend fun await() }

private class AndroidSubscriptionRefreshWorkOperations(
    context: Context,
) : SubscriptionRefreshWorkOperations {
    private val workManager = WorkManager.getInstance(context)

    override fun cancelUniqueWork(workName: String): SubscriptionRefreshCompletion =
        completion(workManager.cancelUniqueWork(workName))

    override fun enqueueUniqueRefresh(
        workName: String,
        policy: ExistingWorkPolicy,
        intervalMinutes: Long,
    ): SubscriptionRefreshCompletion {
        val request = OneTimeWorkRequestBuilder<SubscriptionRefreshWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .setInitialDelay(intervalMinutes, TimeUnit.MINUTES)
            .addTag(workName)
            .build()

        return completion(workManager.enqueueUniqueWork(
            workName,
            policy,
            request,
        ))
    }

    private fun completion(operation: androidx.work.Operation) = SubscriptionRefreshCompletion {
        // Cancelling a wait does not undo WorkManager's already-submitted operation.
        suspendCancellableCoroutine<Unit> { continuation ->
            val future = operation.result
            future.addListener({
                try { future.get(); continuation.resume(Unit) }
                catch (error: Exception) { continuation.resumeWithException(error) }
            }, Executor { it.run() })
        }
    }
}
