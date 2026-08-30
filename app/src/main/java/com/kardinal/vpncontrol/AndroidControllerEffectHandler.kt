package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.data.AppRepository

internal fun interface AndroidControllerEffectSink {
    fun handle(effects: List<MainControllerEffect>)
}

internal class AndroidControllerEffectHandler(
    private val repository: AppRepository,
    private val launch: (suspend () -> Unit) -> Unit,
    private val ensureInstalledAppsLoaded: () -> Unit,
    private val importRoutingRules: (String) -> Unit,
) : AndroidControllerEffectSink {
    override fun handle(effects: List<MainControllerEffect>) {
        if (effects.isEmpty()) return
        effects.forEach { effect ->
            when (effect) {
                MainControllerEffect.EnsureInstalledAppsLoaded -> ensureInstalledAppsLoaded()
                is MainControllerEffect.UpdateStatus -> {
                    launch {
                        repository.updateStatus(effect.message)
                    }
                }
                is MainControllerEffect.UpdateProfileSourceMode -> {
                    launch {
                        repository.updateProfileSourceMode(effect.mode)
                    }
                }
                is MainControllerEffect.UpdateAppMode -> {
                    launch {
                        repository.updateAppMode(effect.mode)
                    }
                }
                is MainControllerEffect.UpdateAppLanguage -> {
                    launch {
                        repository.updateAppLanguage(effect.language)
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.SelectActiveSubscription -> {
                    launch {
                        repository.selectActiveSubscription(effect.subscriptionId)
                    }
                }
                is MainControllerEffect.ImportRoutingRules -> importRoutingRules(effect.raw)
                is MainControllerEffect.SaveProfileSource -> {
                    launch {
                        repository.updateProfileSource(effect.value, effect.mode, effect.normalizedName)
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.DeleteProfileHistoryEntry -> {
                    launch {
                        repository.deleteProfileHistoryEntry(effect.source)
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.SaveProfileHistoryRename -> {
                    launch {
                        repository.updateSubscriptionSource(
                            source = effect.source,
                            newSource = effect.normalizedSource,
                            name = effect.normalizedName,
                        )
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.SaveSubscriptionRefreshPolicy -> {
                    launch {
                        repository.updateSubscriptionRefreshPolicy(
                            policy = effect.policy,
                            customHours = effect.customHours,
                            findBestAfterRefresh = effect.findBestAfterRefresh,
                        )
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.SaveValidationSettings -> {
                    launch {
                        repository.updateValidationSettings(effect.settings)
                        repository.updateStatus(effect.statusMessage)
                    }
                }
                is MainControllerEffect.SaveDns -> {
                    launch {
                        repository.updateDns(effect.settings)
                        repository.updateStatus(effect.statusMessage)
                    }
                }
            }
        }
    }
}
