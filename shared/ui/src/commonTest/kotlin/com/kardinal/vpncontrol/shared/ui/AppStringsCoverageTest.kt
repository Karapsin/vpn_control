package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import kotlin.test.Test
import kotlin.test.assertTrue

class AppStringsCoverageTest {
    @Test
    fun everySupportedLanguageHasEveryUiTextKey() {
        assertTrue(
            missingUiTextLocalizationKeys().isEmpty(),
            "Missing UI text localizations: ${missingUiTextLocalizationKeys()}",
        )
    }

    @Test
    fun generatedJsonCatalogHasEveryUiTextKey() {
        assertTrue(
            missingGeneratedUiTextLocalizationKeys().isEmpty(),
            "Missing generated JSON UI text localizations: ${missingGeneratedUiTextLocalizationKeys()}",
        )
    }

    @Test
    fun appStringsReadsUiTextFromGeneratedCatalog() {
        val russian = AppStrings(AppLanguage.RUSSIAN)
        val expected = generatedUiTextTranslations
            .getValue(AppLanguage.RUSSIAN)
            .getValue(UiText.FIND_BEST)

        assertTrue(russian.get(UiText.FIND_BEST) == expected)
    }

    @Test
    fun remoteSourcePreviewMessagesAreLocalized() {
        val remoteSourceMessages = listOf(
            "Subscription URL",
            "Unreadable subscription URL",
            "Insecure HTTP subscriptions are not supported",
            "Use an https:// subscription URL.",
            "The URL must include a valid HTTPS host",
            "Paste a valid https:// subscription URL.",
            "Direct remote source",
            "sing-box import link",
            "Unreadable sing-box import link",
            "Only valid HTTPS remote URLs are supported",
            "Use a sing-box import link that resolves to a valid https:// URL.",
            "Fetches remote content from the embedded URL",
            "Fetches remote content from connliberty.com",
            "The import link could not be parsed",
            "Paste a valid sing-box remote-profile import link or a direct subscription URL.",
            "VPN import link",
            "Unreadable VPN import link",
            "Unsupported provider import",
            "Amnezia and other vpn:// imports are not supported. Use a normal subscription URL or add locations manually.",
            "The import payload could not be decoded",
            "vpn:// imports are not supported. Use a normal subscription URL or add locations manually.",
        )
        assertMessagesAreLocalized(remoteSourceMessages)
    }

    @Test
    fun statusAndConnectionLogMessagesAreLocalized() {
        val statusMessages = listOf(
            "Applying selected location...",
            "Applying updated selected location...",
            "Best location search timed out; keeping the current connection",
            "Clipboard is empty",
            "Connection log enabled",
            "Connection log hidden",
            "Connection test tools enabled",
            "Connection test tools hidden",
            "Could not open export destination",
            "Could not open selected file",
            "Could not open selected locations file",
            "Could not open selected rules file",
            "Failed to apply updated selected location",
            "Failed to export diagnostics",
            "Failed to export locations",
            "Failed to export routing rules",
            "Failed to find a replacement location",
            "Failed to import file",
            "Failed to open diagnostics destination",
            "Failed to save refresh settings",
            "Failed to update startup setting",
            "Import canceled",
            "Invalid subscription URL",
            "Latency history enabled",
            "Latency history hidden",
            "Live traffic stats enabled",
            "Live traffic stats hidden",
            "Location check cancelled",
            "Location check failed",
            "Locations exported",
            "Locations import canceled",
            "No locations available for benchmarking",
            "No subscriptions to refresh",
            "No suitable location found",
            "Per-profile totals enabled",
            "Per-profile totals hidden",
            "Previous VPN session will be restored",
            "QR scan canceled",
            "Remote source is empty",
            "Routing rules exported",
            "Routing rules import canceled",
            "Saved routing rules",
            "Session stats enabled",
            "Session stats hidden",
            "Shared text is not a supported import payload",
            "Subscription deleted",
            "Subscription refresh finished, but VPN permission is required to switch in background. Previous VPN location kept as a fallback.",
            "Subscription refresh finished. Finding the best location...",
            "Subscription refresh finished. No suitable location found",
        )
        assertMessagesAreLocalized(statusMessages)
    }

    @Test
    fun structuredStatusMessagesAreLocalized() {
        val structuredMessages = listOf(
            StatusMessages.subscriptionAutoRefreshSet(SubscriptionRefreshPolicy.CUSTOM, 0.5),
            StatusMessages.validationSettingsSaved(
                BenchmarkValidationSettings(
                    primaryUrl = "https://www.google.com/generate_204",
                    secondaryUrl = "https://chatgpt.com/",
                    batchSize = 4,
                    retryCount = 2,
                ),
            ),
            StatusMessages.customDnsSaved(enabled = true),
            StatusMessages.findBestStart(ProfileSourceMode.SUBSCRIPTION),
            StatusMessages.startingConnectionWithBestLocation(AppMode.VPN),
            StatusMessages.connectionReadyOnComputer(AppMode.PROXY_ONLY),
            StatusMessages.desktopAppInitialized(),
            StatusMessages.runtimeMode(AppMode.VPN.name),
            StatusMessages.runtimeLog("/tmp/sing-box:a|b.log"),
            StatusMessages.preflightPassed(AppMode.VPN),
            StatusMessages.desktopVpnCapabilityReady(),
        )
        val supportedLanguages = listOf(
            AppLanguage.RUSSIAN,
            AppLanguage.GERMAN,
            AppLanguage.CHINESE,
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH,
        )

        val rawLeaks = supportedLanguages.flatMap { language ->
            val strings = AppStrings(language)
            structuredMessages.mapNotNull { message ->
                val localized = strings.statusMessage(message)
                when {
                    localized == message -> "$language: structured message fell back to raw $message"
                    localized.contains("vpn-control-status") -> "$language: encoded status leaked in $localized"
                    localized.contains("preflight", ignoreCase = true) -> "$language: technical preflight leaked in $localized"
                    else -> null
                }
            }
        }

        assertTrue(rawLeaks.isEmpty(), "Structured status localization leaks: $rawLeaks")
        assertTrue(
            AppStrings(AppLanguage.RUSSIAN)
                .statusMessage(StatusMessages.validationSettingsSaved(BenchmarkValidationSettings(batchSize = 4, retryCount = 2)))
                .contains("группа 4"),
        )
        assertTrue(
            AppStrings(AppLanguage.GERMAN)
                .statusMessage(StatusMessages.subscriptionAutoRefreshSet(SubscriptionRefreshPolicy.CUSTOM, 0.5))
                .contains("alle 30 Min."),
        )
    }

    @Test
    fun desktopProfileShellTextUsesGeneratedLocalizations() {
        val english = AppStrings(AppLanguage.ENGLISH)
        val supportedLanguages = listOf(
            AppLanguage.RUSSIAN,
            AppLanguage.GERMAN,
            AppLanguage.CHINESE,
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH,
        )

        val missing = supportedLanguages.flatMap { language ->
            val strings = AppStrings(language)
            listOf(
                UiText.DESKTOP_SHELL,
                UiText.DESKTOP_SHELL_DESCRIPTION,
                UiText.AUTO_REFRESH_WHILE_OPEN,
                UiText.SUBSCRIPTION_MODE,
                UiText.PROFILE_SOURCE_DESKTOP_USE_SAVED_HINT,
                UiText.PROFILE_SOURCE_DESKTOP_USE_SUBSCRIPTION_HINT,
            ).mapNotNull { key ->
                if (strings.get(key) == english.get(key)) "$language: $key" else null
            }
        }

        assertTrue(
            missing.isEmpty(),
            "Desktop profile shell strings still fall back to English: $missing",
        )
    }

    @Test
    fun customRefreshIntervalDisplayIsLocalized() {
        val german = AppStrings(AppLanguage.GERMAN)

        assertTrue(
            german.refreshPolicyDisplay(
                com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy.CUSTOM,
                0.5,
            ).contains("30 Min."),
        )
        assertTrue(
            !german.refreshPolicyDisplay(
                com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy.CUSTOM,
                0.5,
            ).contains("0.5h"),
        )
        assertTrue(
            german.statusMessage("Subscription auto-refresh set to every 30 minutes")
                .contains("alle 30 Min."),
        )
    }

    @Test
    fun desktopRuntimeDetailsAreLocalized() {
        val runtimeMessages = listOf(
            "Runtime mode: VPN",
            "VPN ready on this computer",
            "Proxy ready on this computer",
            "Desktop app initialized",
            "Local proxy: 127.0.0.1:2080",
            "VPN mode preflight passed",
            "Proxy-only mode preflight passed",
            "VPN mode preflight failed: 2 checks",
            "VPN mode unavailable: CAP_NET_ADMIN missing",
            "Desktop VPN capability: ready",
            "Desktop VPN capability: not ready",
            "Runtime log: /tmp/runtime-sing-box.log",
            "fail TUN device: Linux TUN device is missing at /dev/net/tun. Try: sudo modprobe tun",
            "fail network privileges: Desktop VPN mode needs CAP_NET_ADMIN. Run as root or grant sing-box capabilities: sudo setcap cap_net_admin,cap_net_raw+ep $(command -v sing-box)",
            "fail route/DNS tooling: Windows route/DNS tooling is unavailable. VPN mode needs netsh.exe and DNS client PowerShell cmdlets.",
        )

        assertMessagesAreLocalized(runtimeMessages)
    }

    @Test
    fun benchmarkProgressMessagesAreLocalizedWithoutEnglishFragments() {
        val benchmarkMessages = listOf(
            "Checking 45 locations...",
            "Finding the best location from the subscription... Testing fastest candidates in batches...",
            "Finding the best location from saved locations... Testing fastest candidates in batches...",
            "Best: 🇺🇸США • primary ok • secondary timeout • tcp 50.0ms",
        )
        assertMessagesAreLocalized(benchmarkMessages)

        val forbiddenFragments = listOf(
            "Best:",
            "primary",
            "secondary",
            "Checking",
            "locations...",
            "Finding the best",
            "Testing fastest",
            "candidates",
            "batches",
        )
        val supportedLanguages = listOf(
            AppLanguage.RUSSIAN,
            AppLanguage.GERMAN,
            AppLanguage.CHINESE,
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH,
        )

        val leftovers = supportedLanguages.flatMap { language ->
            val strings = AppStrings(language)
            benchmarkMessages.flatMap { message ->
                val localized = strings.statusMessage(message)
                forbiddenFragments.mapNotNull { fragment ->
                    if (localized.contains(fragment)) "$language: $fragment in $localized" else null
                }
            }
        }

        assertTrue(
            leftovers.isEmpty(),
            "Benchmark status messages still contain English fragments: $leftovers",
        )
    }

    @Test
    fun majorUiStringsAvoidKnownAwkwardFragments() {
        val russian = AppStrings(AppLanguage.RUSSIAN)
        assertNoFragments(
            label = "Russian UI",
            text = listOf(
                UiText.FIND_BEST,
                UiText.DNS_APPLIES_NEW_DESKTOP_SESSIONS,
                UiText.APP_MODE_ANDROID_DESCRIPTION,
                UiText.APP_MODE_DESKTOP_DESCRIPTION,
                UiText.VALIDATION_DESCRIPTION_ALL,
                UiText.VALIDATION_DESCRIPTION_SELECTED,
                UiText.VALIDATION_DESCRIPTION_DESKTOP,
                UiText.BATCH_SIZE,
                UiText.SECONDARY_TEST_SITE,
                UiText.DESKTOP_SUBSCRIPTION_URL_HELP,
                UiText.DESKTOP_SHELL,
                UiText.DESKTOP_SHELL_DESCRIPTION,
                UiText.ROUTING_DESCRIPTION_DESKTOP,
                UiText.ROUTING_DESCRIPTION_VPN,
                UiText.COUNTRY_CODE_DOMAINS,
                UiText.COUNTRY_CODE_DOMAINS_DESCRIPTION,
                UiText.BYPASS_DOMAINS,
                UiText.BYPASS_DOMAINS_DESCRIPTION,
                UiText.DOMAIN_RULE_COUNTS,
                UiText.IGNORE_RULES_ON_PROXY,
                UiText.IGNORE_RULES_ON_APPS,
                UiText.LOCAL_PROXY_DESCRIPTION,
            ).joinToString("\n") { russian.get(it) } + "\n" +
                russian.statusMessage("Runtime mode: VPN") + "\n" +
                russian.statusMessage("Runtime log: /tmp/sing-box.log") + "\n" +
                russian.statusMessage("VPN mode preflight passed") + "\n" +
                russian.statusMessage("Desktop VPN capability: ready") + "\n" +
                russian.statusMessage("Best: 🇩🇪 Германия • primary ok • secondary ok • tcp 50.0ms"),
            fragments = listOf(
                "Find best",
                "desktop",
                "mixed proxy",
                "privileged helper",
                "proxied",
                "All ",
                "top N",
                "пач",
                "вторичный",
                "обход доменов",
                "домены обхода",
                "режим выполнения",
                "журнал выполнения",
                "предпровер",
                "возможность vpn",
                "живого трафика",
                "проксируем",
                "ms",
            ),
        )

        val german = AppStrings(AppLanguage.GERMAN)
        assertNoFragments(
            label = "German UI",
            text = listOf(
                german.get(UiText.FIND_BEST),
                german.get(UiText.BATCH_SIZE),
                german.get(UiText.ROUTING_DESCRIPTION_DESKTOP),
                german.get(UiText.ROUTING_DESCRIPTION_VPN),
                german.get(UiText.APP_MODE_ANDROID_VPN_DETAIL),
                german.get(UiText.COUNTRY_CODE_DOMAINS),
                german.get(UiText.COUNTRY_CODE_DOMAINS_DESCRIPTION),
                german.get(UiText.BYPASS_DOMAINS),
                german.get(UiText.BYPASS_DOMAINS_DESCRIPTION),
                german.get(UiText.DOMAIN_RULE_COUNTS),
                german.get(UiText.IGNORE_RULES_ON_APPS),
                german.statusMessage("Runtime mode: VPN"),
                german.statusMessage("Runtime log: /tmp/sing-box.log"),
                german.statusMessage("VPN mode preflight passed"),
                german.statusMessage("Desktop VPN capability: ready"),
                german.statusMessage("Validation settings saved: google.com • batch 4 • retries 2"),
            ).joinToString("\n"),
            fragments = listOf("Beste finden", "Batch", "Domain-Bypass", "Traffic", "Bypass", "Laufzeit", "Fähigkeit", "Desktop-Shell"),
        )

        listOf(
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH,
        ).forEach { language ->
            val strings = AppStrings(language)
            assertNoFragments(
                label = "$language desktop/proxy UI",
                text = listOf(
                    strings.get(UiText.DESKTOP_SHELL),
                    strings.get(UiText.DESKTOP_SHELL_DESCRIPTION),
                    strings.get(UiText.ROUTING_DESCRIPTION_DESKTOP),
                    strings.get(UiText.COUNTRY_CODE_DOMAINS),
                    strings.get(UiText.COUNTRY_CODE_DOMAINS_DESCRIPTION),
                    strings.get(UiText.BYPASS_DOMAINS),
                    strings.get(UiText.BYPASS_DOMAINS_DESCRIPTION),
                    strings.get(UiText.DOMAIN_RULE_COUNTS),
                    strings.get(UiText.IGNORE_RULES_ON_PROXY),
                    strings.get(UiText.LOCAL_PROXY_DESCRIPTION),
                    strings.statusMessage("Runtime mode: VPN"),
                    strings.statusMessage("Runtime log: /tmp/sing-box.log"),
                    strings.statusMessage("Desktop VPN capability: ready"),
                ).joinToString("\n"),
                fragments = listOf(
                    "Shell desktop",
                    "desktop",
                    "runtime",
                    "enforcement",
                    "proxied",
                    "bypass",
                    "contournement",
                    "de escritorio",
                    "de execução",
                    "d'exécution",
                ),
            )
        }
    }

    private fun assertMessagesAreLocalized(messages: List<String>) {
        val supportedLanguages = listOf(
            AppLanguage.RUSSIAN,
            AppLanguage.GERMAN,
            AppLanguage.CHINESE,
            AppLanguage.SPANISH,
            AppLanguage.PORTUGUESE,
            AppLanguage.FRENCH,
        )

        val missing = supportedLanguages.flatMap { language ->
            val strings = AppStrings(language)
            messages.mapNotNull { message ->
                if (strings.statusMessage(message) == message) "$language: $message" else null
            }
        }

        assertTrue(
            missing.isEmpty(),
            "Messages still fall back to English: $missing",
        )
    }

    private fun assertNoFragments(
        label: String,
        text: String,
        fragments: List<String>,
    ) {
        val found = fragments.filter { fragment ->
            text.contains(fragment, ignoreCase = true)
        }
        assertTrue(
            found.isEmpty(),
            "$label still contains awkward fragments $found in: $text",
        )
    }
}
