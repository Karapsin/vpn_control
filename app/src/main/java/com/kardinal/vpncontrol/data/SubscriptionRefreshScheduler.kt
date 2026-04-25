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

class SubscriptionRefreshScheduler(
    private val context: Context,
) : RefreshScheduler {
    override suspend fun sync(state: PersistedState) {
        schedule(state, appendToCurrentChain = false)
    }

    override suspend fun scheduleNext(state: PersistedState) {
        schedule(state, appendToCurrentChain = true)
    }

    private suspend fun schedule(
        state: PersistedState,
        appendToCurrentChain: Boolean,
    ) {
        val workManager = WorkManager.getInstance(context)
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
            workManager.cancelUniqueWork(WORK_NAME)
            DiagnosticsLogger.append(
                context,
                "Subscription refresh scheduling canceled: mode=${state.profileSourceMode} activeUrlSet=${state.profileUrl.isNotBlank()} subscriptions=${state.subscriptions.size} policy=${state.subscriptionRefreshPolicy} refreshAll=$refreshAll validSource=$validSource",
            )
            return
        }

        val request = OneTimeWorkRequestBuilder<SubscriptionRefreshWorker>()
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .setInitialDelay(intervalMinutes, TimeUnit.MINUTES)
            .addTag(WORK_NAME)
            .build()

        workManager.enqueueUniqueWork(
            WORK_NAME,
            if (appendToCurrentChain) {
                ExistingWorkPolicy.APPEND_OR_REPLACE
            } else {
                ExistingWorkPolicy.REPLACE
            },
            request,
        )
        DiagnosticsLogger.append(
            context,
            "Subscription refresh scheduled: policy=${state.subscriptionRefreshPolicy} refreshAll=$refreshAll intervalMinutes=$intervalMinutes append=$appendToCurrentChain",
        )
    }

    companion object {
        const val WORK_NAME = "subscription-refresh-work"
    }

    override fun cancel() {
        WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
    }
}
