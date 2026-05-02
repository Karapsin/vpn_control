package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AndroidRoutingActionsServiceTest {
    @Test
    fun saveRoutingRulesPersistsDraftAndNavigatesBack() {
        val controller = MainController(
            MainUiState(
                currentScreen = AppScreen.ROUTING_RULES,
                screenHistory = listOf(AppScreen.MAIN),
                appMode = AppMode.VPN,
                isVpnRunning = true,
                routingProxyPackagesDraft = setOf("org.example.two", "org.example.one"),
                routingNationalDomainsDraft = "ru\nsu",
                routingDirectDomainsDraft = "example.com",
            ),
        )
        val statuses = mutableListOf<String>()
        var savedRules: RoutingRules? = null
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            updateRoutingRules = {
                savedRules = it
                Result.success(Unit)
            },
        )

        service.saveRoutingRules()

        assertEquals(listOf("org.example.one", "org.example.two"), savedRules?.proxyPackages)
        assertEquals(listOf("ru", "su"), savedRules?.nationalDomainSuffixes)
        assertEquals(listOf("example.com"), savedRules?.directDomainSuffixes)
        assertEquals(listOf("Routing rules saved. Restart VPN to apply"), statuses)
        assertEquals(AppScreen.MAIN, controller.currentState().currentScreen)
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun importRoutingRulesSanitizesAndAppliesDrafts() {
        val controller = MainController(MainUiState(isVpnRunning = false))
        val statuses = mutableListOf<String>()
        var savedRules: RoutingRules? = null
        val service = service(
            controller = controller,
            updateStatus = { statuses += it },
            updateRoutingRules = {
                savedRules = it
                Result.success(Unit)
            },
        )

        service.importRoutingRules(
            """
            {
              "ignore_rules": true,
              "proxy_packages": ["org.example.two", "org.example.one", "org.example.one"],
              "national_domain_suffixes": ["ru"],
              "direct_domain_suffixes": ["example.com"]
            }
            """.trimIndent(),
        )

        assertEquals(true, savedRules?.ignoreRules)
        assertEquals(listOf("org.example.one", "org.example.two"), savedRules?.proxyPackages)
        assertEquals("org.example.one\norg.example.two", controller.currentState().routingProxyPackagesDraft.sorted().joinToString("\n"))
        assertEquals("ru", controller.currentState().routingNationalDomainsDraft)
        assertEquals("example.com", controller.currentState().routingDirectDomainsDraft)
        assertEquals(listOf("Routing rules imported"), statuses)
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun selectAllVisibleProxyAppsUsesCurrentSearchFilter() {
        val controller = MainController(
            MainUiState(
                routingAppSearch = "mail",
                installedApps = listOf(
                    InstalledApp("org.example.mail", "Mail", false),
                    InstalledApp("org.example.maps", "Maps", false),
                    InstalledApp("org.example.systemmail", "System Mail", true),
                ),
            ),
        )
        val service = service(controller)

        service.selectAllVisibleProxyApps()

        assertEquals(
            setOf("org.example.mail", "org.example.systemmail"),
            controller.currentState().routingProxyPackagesDraft,
        )
    }

    private fun service(
        controller: MainController,
        updateStatus: suspend (String) -> Unit = {},
        updateRoutingRules: suspend (RoutingRules) -> Result<Unit> = { Result.success(Unit) },
    ): AndroidRoutingActionsService {
        return AndroidRoutingActionsService(
            controller = controller,
            stateProvider = controller::currentState,
            effectSink = AndroidControllerEffectSink { effects ->
                effects.forEach { effect ->
                    if (effect is MainControllerEffect.UpdateStatus) {
                        runBlocking { updateStatus(effect.message) }
                    }
                }
            },
            launch = { block -> runBlocking { block() } },
            setBusy = { busy -> controller.update { it.copy(isBusy = busy) } },
            updateRoutingRules = updateRoutingRules,
            updateStatus = updateStatus,
        )
    }
}
