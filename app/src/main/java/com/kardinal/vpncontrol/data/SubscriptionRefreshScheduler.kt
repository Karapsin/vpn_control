package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.kardinal.vpncontrol.model.PersistedState
import com.kardinal.vpncontrol.model.ProfileSourceMode
import java.util.concurrent.TimeUnit

class SubscriptionRefreshScheduler(
    private val context: Context,
) {
    suspend fun sync(state: PersistedState) {
        val workManager = WorkManager.getInstance(context)
        val intervalHours = state.subscriptionRefreshPolicy
            .effectiveIntervalHours(state.subscriptionRefreshCustomHours)
        val validSource =
            state.profileUrl.isBlank() || RemoteSourceResolver.validateProfileSource(state.profileUrl).isSuccess
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION ||
            state.profileUrl.isBlank() ||
            intervalHours == null ||
            !validSource
        ) {
            workManager.cancelUniqueWork(WORK_NAME)
            DiagnosticsLogger.append(
                context,
                "Subscription refresh scheduling canceled: mode=${state.profileSourceMode} urlSet=${state.profileUrl.isNotBlank()} policy=${state.subscriptionRefreshPolicy} validSource=$validSource",
            )
            return
        }

        val request = PeriodicWorkRequestBuilder<SubscriptionRefreshWorker>(
            repeatInterval = intervalHours,
            repeatIntervalTimeUnit = TimeUnit.HOURS,
        )
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .addTag(WORK_NAME)
            .build()

        workManager.enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request,
        )
        DiagnosticsLogger.append(
            context,
            "Subscription refresh scheduled: policy=${state.subscriptionRefreshPolicy} intervalHours=$intervalHours",
        )
    }

    companion object {
        const val WORK_NAME = "subscription-refresh-work"
    }
}
