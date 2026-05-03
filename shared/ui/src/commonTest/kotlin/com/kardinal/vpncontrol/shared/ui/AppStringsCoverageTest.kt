package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.ProfileSourceMode
import com.kardinal.vpncontrol.model.StatusMessageKey
import com.kardinal.vpncontrol.model.StatusMessages
import com.kardinal.vpncontrol.model.SubscriptionRefreshPolicy
import com.kardinal.vpncontrol.model.UiSettingsStatusItem
import kotlin.test.Test
import kotlin.test.assertTrue

class AppStringsCoverageTest {
    private val nonEnglishLanguages = AppLanguage.entries
        .filter { it != AppLanguage.SYSTEM && it != AppLanguage.ENGLISH }

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
    fun generatedStatusJsonCatalogExistsForEveryLanguage() {
        val supportedLanguages = AppLanguage.entries.filter { it != AppLanguage.SYSTEM }
        val missing = supportedLanguages.filter { language ->
            generatedStatusTranslations[language] == null
        }

        assertTrue(
            missing.isEmpty(),
            "Missing generated status JSON catalogs: $missing",
        )
    }

    @Test
    fun generatedStatusJsonCatalogHasStructuredTemplatesForEveryStatusKey() {
        val englishStructured = generatedStatusTranslations
            .getValue(AppLanguage.ENGLISH)
            .structured
        val missingEnglish = StatusMessageKey.entries.filterNot { key ->
            key.name in englishStructured ||
                englishStructured.keys.any { candidate -> candidate.startsWith("${key.name}.") }
        }
        assertTrue(
            missingEnglish.isEmpty(),
            "English status catalog is missing structured templates for keys: $missingEnglish",
        )

        val requiredKeys = englishStructured.keys
        val missingByLanguage = generatedStatusTranslations.flatMap { (language, catalog) ->
            requiredKeys
                .filterNot { it in catalog.structured }
                .map { "$language: $it" }
        }
        assertTrue(
            missingByLanguage.isEmpty(),
            "Status catalogs are missing structured templates: $missingByLanguage",
        )
    }

    @Test
    fun generatedStatusJsonCatalogHasRequiredBenchmarkKeys() {
        val requiredStatuses = setOf(
            "ok",
            "timeout",
            "error",
            "partial",
            "blocked",
            "challenge",
            "manual",
            "cached",
            "unreachable",
            "validation_timeout",
            "tcp_timeout",
            "tcp_error",
            "custom_config_manual_only",
        )
        val missing = generatedStatusTranslations.flatMap { (language, catalog) ->
            requiredStatuses
                .filterNot { status -> status in catalog.benchmark.statuses }
                .map { status -> "$language: $status" }
        }

        assertTrue(
            missing.isEmpty(),
            "Missing generated benchmark status translations: $missing",
        )
    }

    @Test
    fun generatedStatusJsonCatalogDoesNotUseGenericPlaceholderTargets() {
        val placeholderTargets = mapOf(
            AppLanguage.ARABIC to listOf(
                Regex("^(?:حدث:\\s*)?حالة(?::\\s*بعيد)?$"),
                Regex("^تم تحديث الحالة$"),
            ),
            AppLanguage.BENGALI to listOf(
                Regex("^(?:ঘটনা:\\s*)?অবস্থা(?::\\s*রিমোট)?$"),
                Regex("^স্থিতি আপডেট হয়েছে$"),
            ),
            AppLanguage.PERSIAN to listOf(
                Regex("^(?:رویداد:\\s*)?وضعیت(?::\\s*دور)?$"),
                Regex("^وضعیت به‌روزرسانی شد$"),
            ),
            AppLanguage.INDONESIAN to listOf(
                Regex("^(?:Peristiwa:\\s*)?Status(?::\\s*jarak jauh)?$"),
            ),
            AppLanguage.ITALIAN to listOf(
                Regex("^Stato$"),
            ),
            AppLanguage.GREEK to listOf(
                Regex("^(?:Συμβάν:\\s*)?Κατάσταση$"),
            ),
            AppLanguage.HINDI to listOf(
                Regex("^(?:घटना:\\s*)?स्थिति$"),
            ),
            AppLanguage.JAPANESE to listOf(
                Regex("^(?:イベント:\\s*)?状態$"),
            ),
            AppLanguage.KOREAN to listOf(
                Regex("^(?:이벤트:\\s*)?상태(?::\\s*원격)?$"),
                Regex("^상태를 업데이트했습니다$"),
            ),
            AppLanguage.THAI to listOf(
                Regex("^(?:เหตุการณ์:\\s*)?สถานะ(?::\\s*ระยะไกล)?$"),
                Regex("^อัปเดตสถานะแล้ว$"),
            ),
            AppLanguage.TURKISH to listOf(
                Regex("^(?:Olay:\\s*)?Durum(?::\\s*uzak)?$"),
                Regex("^Durum güncellendi$"),
            ),
        )
        val violations = generatedStatusTranslations.flatMap { (language, catalog) ->
            val patterns = placeholderTargets[language].orEmpty()
            val replacements = catalog.freeformReplacements +
                catalog.legacyReplacements +
                catalog.legacyExact.map { (source, target) -> source to target }
            replacements.mapNotNull { (source, target) ->
                if (patterns.any { it.matches(target.trim()) }) {
                    "$language: $source -> $target"
                } else {
                    null
                }
            }
        }

        assertTrue(
            violations.isEmpty(),
            "Status catalogs still use generic placeholder targets: $violations",
        )
    }

    @Test
    fun generatedUiCatalogDoesNotUseTranslatedTextPlaceholders() {
        val placeholderFragments = mapOf(
            AppLanguage.ARABIC to listOf(Regex("(^|\\s)نص(\\s|$)")),
            AppLanguage.BENGALI to listOf(Regex("পাঠ্য")),
            AppLanguage.PERSIAN to listOf(Regex("(^|\\s)متن(\\s|$)")),
            AppLanguage.INDONESIAN to listOf(Regex("\\bTeks\\b")),
            AppLanguage.KOREAN to listOf(Regex("텍스트")),
            AppLanguage.THAI to listOf(Regex("ข้อความ")),
        )
        val violations = placeholderFragments.flatMap { (language, patterns) ->
            generatedUiTextTranslations.getValue(language).mapNotNull { (key, value) ->
                val pattern = patterns.firstOrNull { it.containsMatchIn(value) }
                if (pattern == null) null else "$language $key contains translated placeholder: $value"
            }
        }

        assertTrue(
            violations.isEmpty(),
            "Generated UI catalogs still contain translated text placeholders: $violations",
        )
    }

    @Test
    fun generatedUiCatalogDoesNotUseScaffoldedKeyPhrases() {
        val generatedLanguages = AppLanguage.entries
            .filter { it != AppLanguage.SYSTEM && it != AppLanguage.ENGLISH }
        val awkwardFragments = listOf(
            "Metin",
            "connect περιγραφή",
            "connect विवरण",
            "connect 説明",
            "mismatch",
            "successful starts",
            "on login",
            "settings enabled",
            "ρυθμίσεις enabled",
            "सेटिंग्स enabled",
            "設定 enabled",
            "applies new desktop",
            "android detail",
            "desktop detail",
            "policy off",
            "policy hourly",
            "interval hours",
            "validation summary",
            "qr too large message",
            "qr generation failed",
            "too large",
            "generation failed",
            "selected none",
            "selected value",
            "rename subscription",
            "subscrição kind",
            "rule counts",
            "ignore rules",
            "merged location",
        )
        val violations = generatedLanguages.flatMap { language ->
            generatedUiTextTranslations.getValue(language).mapNotNull { (key, value) ->
                val fragment = awkwardFragments.firstOrNull { value.contains(it, ignoreCase = true) }
                if (fragment == null) null else "$language $key contains '$fragment': $value"
            }
        }

        assertTrue(
            violations.isEmpty(),
            "Generated UI catalogs still contain scaffolded phrases: $violations",
        )
    }

    @Test
    fun generatedStatusJsonCatalogDoesNotUseBrokenMixedEnglishFragments() {
        val awkwardFragments = listOf(
            Regex("lying", RegexOption.IGNORE_CASE),
            Regex("timed out", RegexOption.IGNORE_CASE),
            Regex("keeping the", RegexOption.IGNORE_CASE),
            Regex("\\bis empty\\b", RegexOption.IGNORE_CASE),
            Regex("Could not", RegexOption.IGNORE_CASE),
            Regex("\\bSet a\\b", RegexOption.IGNORE_CASE),
            Regex("Add at least", RegexOption.IGNORE_CASE),
            Regex("\\bSwitch to\\b", RegexOption.IGNORE_CASE),
            Regex("is no longer", RegexOption.IGNORE_CASE),
            Regex("Auto-[^\\s]*ing", RegexOption.IGNORE_CASE),
            Regex("\\bset to\\b", RegexOption.IGNORE_CASE),
            Regex("\\bwas off\\b", RegexOption.IGNORE_CASE),
            Regex("Review and save", RegexOption.IGNORE_CASE),
            Regex("\\bare read", RegexOption.IGNORE_CASE),
            Regex("could not be", RegexOption.IGNORE_CASE),
            Regex("\\bBest .* and\\b", RegexOption.IGNORE_CASE),
            Regex("yenilemeed", RegexOption.IGNORE_CASE),
            Regex("penyegaraned", RegexOption.IGNORE_CASE),
            Regex("aplikasily", RegexOption.IGNORE_CASE),
            Regex("アプリly", RegexOption.IGNORE_CASE),
            Regex("แอปly", RegexOption.IGNORE_CASE),
            Regex("\\bto\\b", RegexOption.IGNORE_CASE),
            Regex("Re(?:بدء|চালু|شروع|시작|เริ่ม|開始)", RegexOption.IGNORE_CASE),
            Regex("Validation settings", RegexOption.IGNORE_CASE),
            Regex("Desktop VPN", RegexOption.IGNORE_CASE),
            Regex("Desktop Proxy", RegexOption.IGNORE_CASE),
            Regex("route/DNS tooling is", RegexOption.IGNORE_CASE),
            Regex("\\bneeds\\b", RegexOption.IGNORE_CASE),
            Regex("Run as root", RegexOption.IGNORE_CASE),
            Regex("\\bcapabilities\\b", RegexOption.IGNORE_CASE),
            Regex("DNS client PowerShell cmdlets", RegexOption.IGNORE_CASE),
        )
        val violations = generatedStatusTranslations.flatMap { (language, catalog) ->
            if (language == AppLanguage.ENGLISH) {
                emptyList()
            } else {
                val replacements = catalog.freeformReplacements +
                    catalog.legacyReplacements +
                    catalog.legacyExact.map { (source, target) -> source to target }
                replacements.mapNotNull { (source, target) ->
                    val fragment = awkwardFragments.firstOrNull { it.containsMatchIn(target) }
                    if (fragment == null) null else "$language: $source -> $target"
                }
            }
        }

        assertTrue(
            violations.isEmpty(),
            "Status catalogs still contain broken mixed-English fragments: $violations",
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
    fun mainScreenAppTitleIsLocalizedForEveryNonEnglishLanguage() {
        val english = AppStrings(AppLanguage.ENGLISH).get(UiText.APP_TITLE)
        val missing = nonEnglishLanguages.mapNotNull { language ->
            val title = AppStrings(language).get(UiText.APP_TITLE)
            if (title == english) "$language: $title" else null
        }

        assertTrue(
            missing.isEmpty(),
            "Main screen app title still uses English: $missing",
        )
    }

    @Test
    fun languageOptionsAreSortedByVisibleName() {
        val strings = AppStrings(AppLanguage.ENGLISH)
        val options = sortedLanguageOptions(strings, systemLanguageCode = "en")

        assertTrue(options.first() == AppLanguage.SYSTEM)
        val languageNames = options
            .drop(1)
            .map { strings.languageDisplayName(it, systemLanguageCode = "en") }
        assertTrue(
            languageNames == languageNames.sortedBy { it.lowercase() },
            "Language options are not sorted by visible name: $languageNames",
        )
    }

    @Test
    fun compactSubscriptionRefreshButtonLabelsRespectReferenceCharacterBudget() {
        val compactLanguages = setOf(AppLanguage.GERMAN, AppLanguage.OLD_RUSSIAN, AppLanguage.SOVIET)
        val referenceLanguages = AppLanguage.entries
            .filter { it != AppLanguage.SYSTEM && it !in compactLanguages }
        val buttonKeys = listOf(UiText.REFRESH_ACTIVE, UiText.REFRESH_ALL)

        val violations = buttonKeys.flatMap { key ->
            val limit = referenceLanguages.maxOf { language ->
                AppStrings(language).get(key).length
            }
            compactLanguages.mapNotNull { language ->
                val label = AppStrings(language).get(key)
                if (label.length > limit) {
                    "$language $key label '$label' has ${label.length} chars, limit is $limit"
                } else {
                    null
                }
            }
        }

        assertTrue(
            violations.isEmpty(),
            "Compact subscription refresh labels exceed reference character budget: $violations",
        )
    }

    @Test
    fun germanOldRussianAndSovietUseCompactSubscriptionRefreshButtonLabels() {
        val german = AppStrings(AppLanguage.GERMAN)
        val oldRussian = AppStrings(AppLanguage.OLD_RUSSIAN)
        val soviet = AppStrings(AppLanguage.SOVIET)

        assertTrue(german.get(UiText.REFRESH_ACTIVE) == "Aktives neu")
        assertTrue(german.get(UiText.REFRESH_ALL) == "Alle neu")
        assertTrue(oldRussian.get(UiText.REFRESH_ACTIVE) == "Активную")
        assertTrue(oldRussian.get(UiText.REFRESH_ALL) == "Все грамоты")
        assertTrue(soviet.get(UiText.REFRESH_ACTIVE) == "Активную")
        assertTrue(soviet.get(UiText.REFRESH_ALL) == "Все сводки")
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
            "Profile source set to subscription",
            "Profile source set to saved locations",
            "QR scan canceled",
            "Remote source is empty",
            "Routing rules exported",
            "Routing rules import canceled",
            "Saved routing rules",
            "Session stats enabled",
            "Session stats hidden",
            "Shared text is not a supported import payload",
            "Subscription deleted",
            "Connection mode set to VPN",
            "Connection mode set to proxy only",
            "Disconnect first to change connection mode",
            "History entry deleted",
            "Subscription name reset",
            "Subscription name saved",
            "Switch to Saved Locations to add locations manually",
            "Switch to Saved Locations to import locations",
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
            StatusMessages.startingConnection(AppMode.VPN),
            StatusMessages.startingConnection(AppMode.PROXY_ONLY),
            StatusMessages.startingConnectionWithBestLocation(AppMode.VPN),
            StatusMessages.startingConnectionWithBestLocation(AppMode.PROXY_ONLY),
            StatusMessages.connectionReadyOnComputer(AppMode.PROXY_ONLY),
            StatusMessages.desktopAppInitialized(),
            StatusMessages.runtimeMode(AppMode.VPN.name),
            StatusMessages.runtimeLog("/tmp/sing-box:a|b.log"),
            StatusMessages.preflightPassed(AppMode.VPN),
            StatusMessages.desktopVpnCapabilityReady(),
            StatusMessages.noLocationsAvailableForBenchmarking(),
            StatusMessages.bestLocationSearchTimedOut(),
            StatusMessages.retryingBestLocationSearch(attempt = 2, total = 3),
            StatusMessages.locationSearchCancelled(),
            StatusMessages.locationSearchFailed(),
            StatusMessages.locationSearchCancelledStopFailed(AppMode.VPN, "stop failed"),
            StatusMessages.vpnPermissionRequired(),
            StatusMessages.noSuitableLocationFound(),
            StatusMessages.bestLocationNotMapped(),
            StatusMessages.noSubscriptionsSaved(),
            StatusMessages.noRemoteSource(),
            StatusMessages.addSavedLocationFirst(),
            StatusMessages.subscriptionRefreshStart(targetCount = 1),
            StatusMessages.subscriptionRefreshStart(targetCount = 2),
            StatusMessages.subscriptionRefreshStart(targetCount = 1, auto = true),
            StatusMessages.subscriptionRefreshStart(targetCount = 2, auto = true),
            StatusMessages.refreshingSubscriptionNamed("Example"),
            StatusMessages.subscriptionRefreshed(),
            StatusMessages.subscriptionsRefreshed(),
            StatusMessages.subscriptionsRefreshedCount(refreshedCount = 1, totalCount = 2),
            StatusMessages.subscriptionsRefreshedPartial(
                refreshedCount = 1,
                totalCount = 2,
                failedLabel = "Example",
            ),
            StatusMessages.locationsRefreshed(1),
            StatusMessages.locationsRefreshed(2),
            StatusMessages.failedToRefresh("Example"),
            StatusMessages.failedToRefreshActiveSubscription(),
            StatusMessages.failedToRefreshSubscriptions(),
            StatusMessages.noSubscriptionsRefreshed(),
            StatusMessages.noActiveSubscriptionSelected(),
            StatusMessages.loadingSavedLocations(),
            StatusMessages.downloadingRemoteSource(),
            StatusMessages.resolvingRemoteSource("Example"),
            StatusMessages.subscriptionSourceLoadFailed("Example"),
            StatusMessages.noLocationsFoundSelectedSubscription(),
            StatusMessages.noLocationsFoundInSource("Example"),
            StatusMessages.checkingTcpSpeed("Germany"),
            StatusMessages.checkingLocations(12),
            StatusMessages.checkingLocationSource(12, "ALL_SUBSCRIPTIONS"),
            StatusMessages.testingFastestCandidates(),
            StatusMessages.testingLocationsRange(start = 1, end = 3, total = 12),
            StatusMessages.findBestTestingFastest(ProfileSourceMode.SUBSCRIPTION),
            StatusMessages.findBestTestingFastest(ProfileSourceMode.CURRENT_LOCATIONS),
            StatusMessages.bestLocationSummary("Germany", "primary ok"),
            StatusMessages.activatedAllSubscriptions(),
            StatusMessages.activatedSubscription("Example"),
            StatusMessages.profileSourceMode(ProfileSourceMode.SUBSCRIPTION),
            StatusMessages.profileSourceMode(ProfileSourceMode.CURRENT_LOCATIONS),
            StatusMessages.subscriptionNameReset(),
            StatusMessages.subscriptionNameSaved(),
            StatusMessages.subscriptionDeleted(),
            StatusMessages.selectLocationFirst(),
            StatusMessages.checkingLocation("Germany"),
            StatusMessages.testingLocation("Germany"),
            StatusMessages.locationCheckCancelled(),
            StatusMessages.noLocationsToExport(),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, false),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LIVE_TRAFFIC_STATS, true),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.PROFILE_TOTALS, false),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LATENCY_HISTORY, true),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_LOG, false),
            StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.CONNECTION_TEST_TOOLS, true),
            StatusMessages.subscriptionLocationSaveReadOnly(),
            StatusMessages.invalidLocationConfig(),
            StatusMessages.locationAlreadySaved("Germany"),
            StatusMessages.locationEditUnavailable(),
            StatusMessages.locationAdded("Germany"),
            StatusMessages.locationUpdatedAndMerged("Germany"),
            StatusMessages.locationUpdated("Germany"),
            StatusMessages.subscriptionLocationDeleteReadOnly(),
            StatusMessages.selectedLocationRemoved("Germany"),
            StatusMessages.locationRemoved("Germany"),
            StatusMessages.selectedLocationRemovedConnectionStopped(AppMode.VPN, "Germany"),
            StatusMessages.locationRemovalRollbackFailed(AppMode.PROXY_ONLY),
            StatusMessages.importLocationsBlocked(),
            StatusMessages.importLocationsFailed(),
            StatusMessages.locationsImported(removedSelected = false),
            StatusMessages.locationsImported(removedSelected = true),
            StatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.VPN),
            StatusMessages.locationsImportRollbackFailed(AppMode.PROXY_ONLY),
            StatusMessages.clipboardEmpty(),
            StatusMessages.clipboardReadFailed(),
            StatusMessages.subscriptionTextLoadedIntoProfile(),
            StatusMessages.profileSourceSet(ProfileSourceMode.SUBSCRIPTION),
            StatusMessages.profileSourceSet(ProfileSourceMode.CURRENT_LOCATIONS),
            StatusMessages.disconnectFirstChangeConnectionMode(),
            StatusMessages.connectionModeSet(AppMode.VPN),
            StatusMessages.connectionModeSet(AppMode.PROXY_ONLY),
            StatusMessages.ruleSetRemoved(),
            StatusMessages.switchToSavedLocationsToAddLocations(),
            StatusMessages.historyEntryDeleted(),
            StatusMessages.selectedLocationUnchanged("Germany"),
            StatusMessages.selectedLocationSet("Germany"),
            StatusMessages.selectedLocationApplying(),
            StatusMessages.updatedSelectedLocationApplying(),
            StatusMessages.selectedLocationApplyFailed(),
            StatusMessages.selectedLocationSelectFailed(),
            StatusMessages.updatedSelectedLocationApplyFailed(),
            StatusMessages.updatedSelectedLocationSaveFailed(),
            StatusMessages.updatedSelectedLocationAppliedSaveFailed(),
            StatusMessages.connectionStoppedKeepStateConsistent(AppMode.VPN),
            StatusMessages.previousConnectionRestored(AppMode.VPN),
            StatusMessages.previousConnectionRestoredWithReason(AppMode.VPN, "retry failed."),
            StatusMessages.previousConnectionRestoreFailedStopped(AppMode.VPN, "restore failed"),
            StatusMessages.previousConnectionRestoreOrStopFailed(
                AppMode.VPN,
                restoreFailure = "restore failed",
                stopFailure = "stop failed",
            ),
            StatusMessages.locationChecked("Germany"),
            StatusMessages.locationCheckFailed(),
            StatusMessages.locationEdited(12),
            StatusMessages.sampleRuleSetAdded(),
            StatusMessages.ruleSetDeleted("desktop-1"),
            StatusMessages.routingRulesSaved(),
            StatusMessages.routingRulesSavedRestartRequired(AppMode.VPN),
            StatusMessages.routingRulesSaveFailed(),
            StatusMessages.routingRulesImported(),
            StatusMessages.routingRulesImportedRestartRequired(AppMode.VPN),
            StatusMessages.routingRulesImportedRestartRequired(AppMode.PROXY_ONLY),
            StatusMessages.routingRulesImportFailed(),
            StatusMessages.routingRulesCopiedToClipboard(),
            StatusMessages.routingRulesExportCanceled(),
            StatusMessages.routingRulesExportedTo("/tmp/rules.json"),
            StatusMessages.routingRulesExportFailed(),
            StatusMessages.routingRulesFileOpenFailed(),
            StatusMessages.locationsCopiedToClipboard(),
            StatusMessages.locationsExportCanceled(),
            StatusMessages.locationsExportedTo("/tmp/locations.txt"),
            StatusMessages.locationsExportFailed(),
            StatusMessages.locationsFileOpenFailed(),
            StatusMessages.locationsFileReadFailed(),
            StatusMessages.diagnosticsExportCanceled(),
            StatusMessages.diagnosticsExportedTo("/tmp/diagnostics.txt"),
            StatusMessages.diagnosticsExportFailed(),
            StatusMessages.diagnosticsDestinationOpenFailed(),
            StatusMessages.diagnosticsExportOpened(),
            StatusMessages.noSubscriptionsToRefresh(),
            StatusMessages.startOnLoginEnabled(),
            StatusMessages.startOnLoginDisabled(),
            StatusMessages.startupSettingUpdateFailed(),
            StatusMessages.subscriptionHwidCleared(),
            StatusMessages.subscriptionHwidSaved(),
            StatusMessages.refreshSettingsSaveFailed(),
            StatusMessages.appModeChanged(AppMode.PROXY_ONLY),
            StatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY),
            StatusMessages.previousConnectionRestorePending(),
            StatusMessages.previousLocationUnavailable(),
            StatusMessages.restoringPreviousConnection("Germany"),
            StatusMessages.connectionStartedOnTarget(AppMode.VPN, "tun-test"),
            StatusMessages.connectionStartedOnTarget(AppMode.PROXY_ONLY, "127.0.0.1:2080"),
            StatusMessages.connectionStartFailed(AppMode.VPN),
            StatusMessages.connectionStopFailed(AppMode.PROXY_ONLY),
            StatusMessages.connectionStartCancelled(AppMode.VPN),
            StatusMessages.connectionStopCancelled(AppMode.PROXY_ONLY),
            StatusMessages.selectedLocationSaveFailed(),
            StatusMessages.selectedLocationStartedSaveFailed(AppMode.VPN),
            StatusMessages.bestLocationStartFailed(AppMode.PROXY_ONLY),
            StatusMessages.bestLocationSaveFailed(),
            StatusMessages.bestLocationStartedSaveFailed(AppMode.VPN),
            StatusMessages.backgroundRefreshFindingBest(),
            StatusMessages.backgroundVpnPermissionRequiredKeepingPrevious(),
            StatusMessages.appClosedConnectionWasOff(),
            StatusMessages.connectionStoppedReconnectOnNextLaunch(AppMode.VPN),
            StatusMessages.connectionStopBeforeExitFailed(AppMode.VPN),
            StatusMessages.subscriptionReceived(),
            StatusMessages.subscriptionLinkReceived(),
            StatusMessages.locationConfigReceived(),
            StatusMessages.sharedTextUnsupportedImport(),
            StatusMessages.pasteSubscriptionRequired(),
            StatusMessages.subscriptionSaved(),
            StatusMessages.invalidRemoteSource(),
            StatusMessages.invalidRuleSet(),
            StatusMessages.ruleSetAdded(),
            StatusMessages.ruleSetUpdated(),
            StatusMessages.allSubscriptionsSelected(),
            StatusMessages.subscriptionSelected(),
            StatusMessages.invalidSubscriptionUrl(),
            StatusMessages.subscriptionRefreshRemovedSelectedStopped(AppMode.VPN),
            StatusMessages.subscriptionDeleteRemovedSelectedStopped(AppMode.PROXY_ONLY),
            StatusMessages.benchmarkedLocation("Germany", "primary ok", "secondary ok"),
            StatusMessages.benchmarkLocationFailed("Germany"),
            StatusMessages.appsLoadFailed(),
            StatusMessages.backgroundRefreshSwitched(
                AppMode.VPN,
                selectedProfileName = "Germany",
                winnerSource = "Example",
                failedLabel = null,
            ),
            StatusMessages.backgroundRefreshSwitched(
                AppMode.VPN,
                selectedProfileName = "Germany",
                winnerSource = "Example",
                failedLabel = "Example failed",
            ),
            StatusMessages.backgroundRefreshReplacementFailed(
                AppMode.VPN,
                failureMessage = StatusMessages.replacementLocationSearchFailed(),
                failedLabel = "Example failed",
                selectedSourceFailed = true,
                rollbackMessage = StatusMessages.backgroundRefreshPreviousLocationKept(AppMode.VPN),
            ),
            StatusMessages.backgroundRefreshSelectedMissingKept(AppMode.VPN, failedLabel = null),
            StatusMessages.backgroundRefreshSelectedMissingKept(AppMode.VPN, failedLabel = "Example failed"),
            StatusMessages.backgroundRefreshKeptCurrent(AppMode.VPN, failedLabel = null, selectedSourceFailed = false),
            StatusMessages.backgroundRefreshKeptCurrent(
                AppMode.VPN,
                failedLabel = "Example failed",
                selectedSourceFailed = true,
            ),
            StatusMessages.backgroundRefreshReplacementStopped(AppMode.VPN),
            StatusMessages.backgroundRefreshRestoreOrStopFailed(AppMode.VPN, "restore failed"),
            StatusMessages.backgroundRefreshFailed(),
            StatusMessages.replacementLocationSearchFailed(),
            StatusMessages.replacementLocationSaveFailed(),
        )
        val rawLeaks = nonEnglishLanguages.flatMap { language ->
            val strings = AppStrings(language)
            structuredMessages.mapNotNull { message ->
                val localized = strings.statusMessage(message)
                when {
                    localized == message -> "$language: structured message fell back to raw $message"
                    localized.contains("vpn-control-status") -> "$language: encoded status leaked in $localized"
                    localized.contains("preflight", ignoreCase = true) -> "$language: technical preflight leaked in $localized"
                    localized == strings.get(UiText.STATUS) -> "$language: structured message collapsed to generic status for $message"
                    else -> null
                }
            }
        }

        assertTrue(rawLeaks.isEmpty(), "Structured status localization leaks: $rawLeaks")
        val locationStatusEnglishLeaks = nonEnglishLanguages.flatMap { language ->
            val strings = AppStrings(language)
            listOf(
                StatusMessages.selectLocationFirst(),
                StatusMessages.checkingLocation("Germany"),
                StatusMessages.testingLocation("Germany"),
                StatusMessages.locationCheckCancelled(),
                StatusMessages.noLocationsToExport(),
            ).flatMap { message ->
                val localized = strings.statusMessage(message)
                listOf("Select a location", "Checking", "Testing", "Location check", "No locations").mapNotNull { fragment ->
                    if (localized.contains(fragment, ignoreCase = true)) "$language: $fragment in $localized" else null
                }
            }
        }
        assertTrue(
            locationStatusEnglishLeaks.isEmpty(),
            "Structured location status messages still contain English fragments: $locationStatusEnglishLeaks",
        )
        val sharedStatusFallbacks = nonEnglishLanguages.flatMap { language ->
            val english = AppStrings(AppLanguage.ENGLISH)
            val strings = AppStrings(language)
            listOf(
                StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.SESSION_STATS, true),
                StatusMessages.uiSettingVisibilityChanged(UiSettingsStatusItem.LIVE_TRAFFIC_STATS, false),
                StatusMessages.subscriptionLocationSaveReadOnly(),
                StatusMessages.locationAdded("Germany"),
                StatusMessages.locationRemoved("Germany"),
                StatusMessages.selectedLocationRemovedConnectionStopped(AppMode.VPN, "Germany"),
                StatusMessages.importLocationsBlocked(),
                StatusMessages.locationsImported(removedSelected = true),
                StatusMessages.locationsImportedSelectedUnavailableConnectionStopped(AppMode.PROXY_ONLY),
            ).mapNotNull { message ->
                val localized = strings.statusMessage(message)
                val englishText = english.statusMessage(message)
                if (localized == englishText) "$language: $englishText" else null
            }
        }
        assertTrue(
            sharedStatusFallbacks.isEmpty(),
            "Structured shared status messages still fall back to English: $sharedStatusFallbacks",
        )
        val desktopSettingsEnglishLeaks = nonEnglishLanguages.flatMap { language ->
            val strings = AppStrings(language)
            listOf(
                StatusMessages.startOnLoginEnabled(),
                StatusMessages.startOnLoginDisabled(),
                StatusMessages.subscriptionHwidCleared(),
                StatusMessages.subscriptionHwidSaved(),
                StatusMessages.appModeChanged(AppMode.PROXY_ONLY),
                StatusMessages.connectionStoppedForAppMode(AppMode.VPN, AppMode.PROXY_ONLY),
            ).flatMap { message ->
                val localized = strings.statusMessage(message)
                listOf(
                    "App will start",
                    "App startup",
                    "Subscription x-hwid",
                    "App mode",
                    "stopped",
                ).mapNotNull { fragment ->
                    if (localized.contains(fragment, ignoreCase = true)) "$language: $fragment in $localized" else null
                }
            }
        }
        assertTrue(
            desktopSettingsEnglishLeaks.isEmpty(),
            "Structured desktop settings status messages still contain English fragments: $desktopSettingsEnglishLeaks",
        )
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
        val missing = nonEnglishLanguages.flatMap { language ->
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
    fun desktopRefreshAndConnectionLogMessagesAreLocalized() {
        val runtimeMessages = listOf(
            "VPN started on vpn-control",
            "Proxy started on 127.0.0.1:2080",
            "Restoring VPN: 🇭🇺⚡ Венгрия bypass...",
            "VPN stopped. Will reconnect on next launch.",
            "Proxy stopped. Will reconnect on next launch.",
            "Starting VPN...",
            "Starting local proxy...",
            "Starting VPN with the best location...",
            "Starting local proxy with the best location...",
            "Starting VPN with the new best location...",
            "Starting proxy with the new best location...",
            "Profile source mode: SUBSCRIPTION",
            "Profile source mode: CURRENT_LOCATIONS",
            "43 locations refreshed",
            "1 location refreshed",
            "Refreshing VLESS (auto)...",
            "Refreshing Whitelists...",
        )
        assertMessagesAreLocalized(runtimeMessages)

        val forbiddenFragments = listOf(
            "Refreshing ",
            "Starting ",
            "with the best location",
            "new best location",
            "VPN started",
            "Proxy started",
            "Restoring VPN",
            "Will reconnect",
            "Profile source mode",
            "CURRENT_LOCATIONS",
            "SUBSCRIPTION",
            "locations refreshed",
            "location refreshed",
        )
        val leftovers = nonEnglishLanguages.flatMap { language ->
            val strings = AppStrings(language)
            runtimeMessages.flatMap { message ->
                val localized = strings.statusMessage(message)
                forbiddenFragments.mapNotNull { fragment ->
                    if (localized.contains(fragment)) "$language: $fragment in $localized" else null
                }
            }
        }

        assertTrue(
            leftovers.isEmpty(),
            "Desktop runtime/log messages still contain English fragments: $leftovers",
        )
    }

    @Test
    fun benchmarkProgressMessagesAreLocalizedWithoutEnglishFragments() {
        val benchmarkMessages = listOf(
            "Checking 45 locations...",
            "Testing locations 4-6 of 45...",
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
            "Testing locations",
            "Finding the best",
            "Testing fastest",
            "candidates",
            "batches",
        )

        val leftovers = nonEnglishLanguages.flatMap { language ->
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

    @Test
    fun easterEggLanguagesUseThemedVocabulary() {
        val oldRussian = AppStrings(AppLanguage.OLD_RUSSIAN)
        val oldRussianText = easterEggVocabularySample(oldRussian) + "\n" + listOf(
            oldRussian.statusMessage(StatusMessages.languageSet("Древнерусский")),
            oldRussian.statusMessage(StatusMessages.runtimeMode(AppMode.VPN.name)),
            oldRussian.statusMessage(StatusMessages.runtimeMode(AppMode.PROXY_ONLY.name)),
            oldRussian.statusMessage(StatusMessages.preflightPassed(AppMode.VPN)),
            oldRussian.statusMessage("Runtime mode: VPN"),
            oldRussian.statusMessage("Starting VPN..."),
            oldRussian.statusMessage("Starting local proxy..."),
            oldRussian.statusMessage("Profile source mode: SUBSCRIPTION"),
            oldRussian.statusMessage("App initialized"),
            oldRussian.statusMessage("TUN device"),
        ).joinToString("\n")

        assertNoFragments(
            label = "Old Russian easter egg",
            text = oldRussianText,
            fragments = listOf("прокси", "TUN", "Импорт", "Экспорт", "маршрутиза", "домен", "локац", "профил", "прилож", "компьют"),
        )
        assertTrue(oldRussianText.contains("тайная сѣть"))
        assertTrue(oldRussianText.contains("посредник"))
        assertTrue(oldRussianText.contains("сѣтевой ход"))

        val soviet = AppStrings(AppLanguage.SOVIET)
        val sovietText = easterEggVocabularySample(soviet) + "\n" + listOf(
            soviet.statusMessage(StatusMessages.languageSet("Советский")),
            soviet.statusMessage(StatusMessages.runtimeMode(AppMode.VPN.name)),
            soviet.statusMessage(StatusMessages.runtimeMode(AppMode.PROXY_ONLY.name)),
            soviet.statusMessage(StatusMessages.preflightPassed(AppMode.VPN)),
            soviet.statusMessage("Runtime mode: VPN"),
            soviet.statusMessage("Starting VPN..."),
            soviet.statusMessage("Starting local proxy..."),
            soviet.statusMessage("TUN device"),
        ).joinToString("\n")

        assertNoFragments(
            label = "Soviet easter egg",
            text = sovietText,
            fragments = listOf("прокси", "TUN", "Импорт", "Экспорт", "локац"),
        )
        assertTrue(sovietText.contains("спецканал"))
        assertTrue(sovietText.contains("ретранслятор"))
        assertTrue(sovietText.contains("магистраль"))
    }

    private fun easterEggVocabularySample(strings: AppStrings): String =
        listOf(
            UiText.START_VPN,
            UiText.STOP_VPN,
            UiText.START_PROXY,
            UiText.STOP_PROXY,
            UiText.SETTINGS_VPN_PROXY_MODE,
            UiText.SETTINGS_VPN_MODE,
            UiText.PROXY_ONLY,
            UiText.APP_MODE_DESKTOP_DESCRIPTION,
            UiText.APP_MODE_DESKTOP_PROXY_DETAIL,
            UiText.IMPORT,
            UiText.EXPORT,
            UiText.REFRESH_DESCRIPTION_ALL,
            UiText.REFRESH_ACTIVE,
            UiText.REFRESH_ALL,
            UiText.PROFILE_SOURCE,
            UiText.LOCATIONS_EXPORT_TITLE,
            UiText.RULES_EXPORT_TITLE,
            UiText.ROUTING_RULES_TITLE,
            UiText.ROUTING_DESCRIPTION_DESKTOP,
            UiText.ROUTING_DESCRIPTION_VPN,
            UiText.ROUTING_DESCRIPTION_PROXY,
            UiText.APP_ASSIGNMENTS,
            UiText.APP_ASSIGNMENTS_DESCRIPTION_VPN,
            UiText.COUNTRY_CODE_DOMAINS,
            UiText.COUNTRY_CODE_DOMAINS_DESCRIPTION,
            UiText.BYPASS_DOMAINS,
            UiText.BYPASS_DOMAINS_DESCRIPTION,
            UiText.LOCAL_PROXY,
            UiText.LOCAL_PROXY_DESCRIPTION,
            UiText.PROXY_STATUS_RUNNING,
            UiText.PROXY_STATUS_STOPPED,
            UiText.PROXY,
        ).joinToString("\n") { strings.get(it) }

    private fun assertMessagesAreLocalized(messages: List<String>) {
        val missing = nonEnglishLanguages.flatMap { language ->
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
