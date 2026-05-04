package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.RoutingStatusMessages
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.InstalledApp
import com.kardinal.vpncontrol.model.RoutingRules
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AndroidRoutingActionsServiceTest {
    @Test
    fun directDomainDraftChangeAutosavesRulesAndStaysOnScreen() {
        val controller = MainController(
            MainUiState(
                currentScreen = AppScreen.ROUTING_RULES,
                screenHistory = listOf(AppScreen.MAIN),
                appMode = AppMode.VPN,
                isVpnRunning = true,
                routingProxyPackagesDraft = setOf("org.example.two", "org.example.one"),
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

        service.onRoutingDirectDomainsDraftChanged(" *.Example.COM. \nexample.com")

        assertEquals(listOf("org.example.one", "org.example.two"), savedRules?.proxyPackages)
        assertEquals(listOf("example.com"), savedRules?.directDomainSuffixes)
        assertEquals(listOf(RoutingStatusMessages.routingRulesSavedRestartRequired(AppMode.VPN)), statuses)
        assertEquals(AppScreen.ROUTING_RULES, controller.currentState().currentScreen)
        assertFalse(controller.currentState().isBusy)
    }

    @Test
    fun appAssignmentChangeAutosavesRules() {
        val controller = MainController(MainUiState())
        var savedRules: RoutingRules? = null
        val service = service(
            controller = controller,
            updateRoutingRules = {
                savedRules = it
                Result.success(Unit)
            },
        )

        service.toggleProxyRoutingApp("org.example.one")

        assertEquals(listOf("org.example.one"), savedRules?.proxyPackages)
        assertEquals(listOf("org.example.one"), controller.currentState().routingRules.proxyPackages)
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
        assertEquals("example.com", controller.currentState().routingDirectDomainsDraft)
        assertEquals(listOf("example.com"), savedRules?.directDomainSuffixes)
        assertEquals(listOf(RoutingStatusMessages.routingRulesImported()), statuses)
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
        var savedRules: RoutingRules? = null
        val service = service(
            controller = controller,
            updateRoutingRules = {
                savedRules = it
                Result.success(Unit)
            },
        )

        service.selectAllVisibleProxyApps()

        assertEquals(
            setOf("org.example.mail", "org.example.systemmail"),
            controller.currentState().routingProxyPackagesDraft,
        )
        assertEquals(listOf("org.example.mail", "org.example.systemmail"), savedRules?.proxyPackages)
    }

    @Test
    fun exportOmitsLegacyNationalDomainField() {
        val controller = MainController(
            MainUiState(
                routingDirectDomainsDraft = "example.com",
            ),
        )
        val service = service(controller)

        val document = service.buildRoutingRulesExport()

        assertFalse(document.content.contains("national_domain_suffixes"))
        assertEquals(true, document.content.contains("direct_domain_suffixes"))
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
