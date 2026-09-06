package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.AppRepository

internal fun interface AndroidControllerEffectSink {
    fun handle(effects: List<MainControllerEffect>)
    suspend fun handleWithinMutation(effects: List<MainControllerEffect>) { handle(effects) }
}

internal class AndroidEffectBatchRunner(
    private val launch: (suspend () -> Unit) -> Unit,
    private val launchMutation: (suspend () -> Unit) -> Unit,
    private val execute: suspend (List<MainControllerEffect>) -> Unit,
) : AndroidControllerEffectSink {
    override fun handle(effects: List<MainControllerEffect>) {
        if (effects.isEmpty()) return
        val dispatcher = if (effects.any { it !is MainControllerEffect.UpdateStatus &&
            it != MainControllerEffect.EnsureInstalledAppsLoaded }) launchMutation else launch
        dispatcher { execute(effects) }
    }
    override suspend fun handleWithinMutation(effects: List<MainControllerEffect>) { execute(effects) }
}

internal class AndroidControllerEffectHandler(
    private val repository: AppRepository,
    private val launch: (suspend () -> Unit) -> Unit,
    private val ensureInstalledAppsLoaded: () -> Unit,
    private val importRoutingRules: suspend (String) -> Unit,
    private val launchMutation: (suspend () -> Unit) -> Unit = launch,
) : AndroidControllerEffectSink {
    private val batches = AndroidEffectBatchRunner(launch, launchMutation, ::handleWithinMutation)
    override fun handle(effects: List<MainControllerEffect>) = batches.handle(effects)

    override suspend fun handleWithinMutation(effects: List<MainControllerEffect>) {
        effects.forEach { effect ->
            when (effect) {
                MainControllerEffect.EnsureInstalledAppsLoaded -> ensureInstalledAppsLoaded()
                is MainControllerEffect.UpdateStatus -> {
                    repository.updateStatus(effect.message)
                }
                is MainControllerEffect.UpdateProfileSourceMode -> {
                    repository.updateProfileSourceMode(effect.mode)
                }
                is MainControllerEffect.UpdateAppMode -> {
                    repository.updateAppMode(effect.mode)
                }
                is MainControllerEffect.UpdateAppLanguage -> {
                    repository.updateAppLanguage(effect.language)
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.SelectActiveSubscription -> {
                    repository.selectActiveSubscription(effect.subscriptionId)
                }
                is MainControllerEffect.ImportRoutingRules -> importRoutingRules(effect.raw)
                is MainControllerEffect.SaveProfileSource -> {
                    repository.updateProfileSource(effect.value, effect.mode, effect.normalizedName)
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.DeleteProfileHistoryEntry -> {
                    repository.deleteProfileHistoryEntry(effect.source)
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.SaveProfileHistoryRename -> {
                    repository.updateSubscriptionSource(
                        source = effect.source,
                        newSource = effect.normalizedSource,
                        name = effect.normalizedName,
                    )
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.SaveSubscriptionRefreshPolicy -> {
                    repository.updateSubscriptionRefreshPolicy(
                        policy = effect.policy,
                        customHours = effect.customHours,
                        findBestAfterRefresh = effect.findBestAfterRefresh,
                    )
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.SaveValidationSettings -> {
                    repository.updateValidationSettings(effect.settings)
                    repository.updateStatus(effect.statusMessage)
                }
                is MainControllerEffect.SaveDns -> {
                    repository.updateDns(effect.settings)
                    repository.updateStatus(effect.statusMessage)
                }
            }
        }
    }
}
