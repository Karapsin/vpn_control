package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.shared.storageapi.SubscriptionContentFetcher

object DesktopAppServiceFactory {
    fun default(): DesktopAppService {
        val store = DesktopStateStore.default()
        val validationDirectory = store.validationDirectory()
        val runtimeManager = DesktopProxyRuntimeManager(
            runtimeConfigStore = store,
            baseDir = store.runtimeDirectory(),
            directProbeRouting = DesktopDirectProbeRouting.forValidationDirectory(validationDirectory),
        )
        return DesktopAppService(
            desktopStore = store,
            runtimeManager = runtimeManager,
            validationRuntime = DesktopProxyValidationRuntime(baseDir = validationDirectory),
            connectionLifecycle = DesktopConnectionLifecycleService(runtimeManager),
            subscriptionService = DesktopSubscriptionService(DesktopSubscriptionDownloadClient()),
            autostartManager = DesktopAutostartManager.default(),
            autoRefreshBestSelectionAction = { service ->
                service.findBestLocation(refreshSubscriptionsFirst = false)
            },
            initialWorkspace = store.loadWorkspace(defaultDesktopWorkspace()),
        ).installShutdownHook()
    }

    internal fun createForTesting(
        store: DesktopStateStore,
        initialWorkspace: DesktopWorkspace = store.loadWorkspace(defaultDesktopWorkspace()),
        runtimeManager: DesktopProxyRuntimeManager = DesktopProxyRuntimeManager(
            runtimeConfigStore = store,
            baseDir = store.runtimeDirectory(),
            directProbeRouting = DesktopDirectProbeRouting.forValidationDirectory(store.validationDirectory()),
        ),
        validationRuntime: DesktopProxyValidationRuntime = DesktopProxyValidationRuntime(
            baseDir = store.validationDirectory(),
        ),
        subscriptionContentFetcher: SubscriptionContentFetcher = DesktopSubscriptionDownloadClient(),
        autostartManager: DesktopAutostartManager = DesktopAutostartManager.default(),
        autoRefreshBestSelectionAction: suspend (DesktopAppService) -> Unit = { service ->
            service.findBestLocation(refreshSubscriptionsFirst = false)
        },
        forceRunningState: Boolean? = null,
    ): DesktopAppService {
        val service = DesktopAppService(
            desktopStore = store,
            runtimeManager = runtimeManager,
            validationRuntime = validationRuntime,
            connectionLifecycle = DesktopConnectionLifecycleService(runtimeManager),
            subscriptionService = DesktopSubscriptionService(subscriptionContentFetcher),
            autostartManager = autostartManager,
            autoRefreshBestSelectionAction = autoRefreshBestSelectionAction,
            initialWorkspace = initialWorkspace,
        )
        if (forceRunningState != null) {
            service.forceRunningStateForTesting(forceRunningState)
        }
        return service
    }
}
