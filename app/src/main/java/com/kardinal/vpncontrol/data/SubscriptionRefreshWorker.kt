package com.kardinal.vpncontrol.data

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import java.io.IOException

class SubscriptionRefreshWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val storage = ProfileStorage(applicationContext)
        val state = storage.snapshot()
        if (state.profileSourceMode != ProfileSourceMode.SUBSCRIPTION ||
            state.subscriptionRefreshPolicy == SubscriptionRefreshPolicy.OFF ||
            state.profileUrl.isBlank()
        ) {
            DiagnosticsLogger.append(
                applicationContext,
                "Background subscription sync skipped: mode=${state.profileSourceMode} policy=${state.subscriptionRefreshPolicy} urlSet=${state.profileUrl.isNotBlank()}",
            )
            return Result.success()
        }

        val orchestrator = BenchmarkOrchestrator(applicationContext, storage)
        return orchestrator.syncSubscriptionLocations().fold(
            onSuccess = { count ->
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync complete: count=$count",
                )
                Result.success()
            },
            onFailure = { error ->
                DiagnosticsLogger.append(
                    applicationContext,
                    "Background subscription sync failed: ${error.message ?: error::class.java.simpleName}",
                )
                if (error is IOException && runAttemptCount < 3) {
                    Result.retry()
                } else {
                    Result.failure()
                }
            },
        )
    }
}
