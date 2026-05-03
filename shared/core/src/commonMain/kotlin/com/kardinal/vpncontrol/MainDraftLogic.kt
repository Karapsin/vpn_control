package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.model.SettingsStatusMessages
import com.kardinal.vpncontrol.data.CompactJson
import com.kardinal.vpncontrol.model.BenchmarkValidationSettings
import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.RoutingRuleSet
import com.kardinal.vpncontrol.model.RoutingRuleSetAction
import com.kardinal.vpncontrol.model.RoutingRuleSetFormat
import com.kardinal.vpncontrol.model.RoutingRuleSetSourceType
import java.net.URI
import kotlin.random.Random
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray

data class DnsSavePlan(
    val dns: String,
    val enabled: Boolean,
    val statusMessage: String,
)

data class ValidationSettingsSavePlan(
    val settings: BenchmarkValidationSettings,
    val statusMessage: String,
)

object MainDraftLogic {
    fun resolveValidationSettingsSave(state: MainUiState): ValidationSettingsSavePlan {
        val batchSize = state.validationBatchSizeDraft.toIntOrNull()
            ?: BenchmarkValidationSettings.DEFAULT_BATCH_SIZE
        val retryCount = state.validationRetryCountDraft.toIntOrNull()
            ?: BenchmarkValidationSettings.DEFAULT_RETRY_COUNT
        val settings = BenchmarkValidationSettings(
            primaryUrl = state.validationPrimaryUrlDraft,
            secondaryUrl = state.validationSecondaryUrlDraft,
            batchSize = batchSize,
            retryCount = retryCount,
        ).normalized()
        return ValidationSettingsSavePlan(
            settings = settings,
            statusMessage = SettingsStatusMessages.validationSettingsSaved(settings),
        )
    }

    fun resolveDnsSave(state: MainUiState): DnsSavePlan {
        val dns = state.customDnsDraft.trim()
        val enabled = state.useCustomDnsDraft && dns.isNotBlank()
        return DnsSavePlan(
            dns = dns,
            enabled = enabled,
            statusMessage = SettingsStatusMessages.customDnsSaved(enabled),
        )
    }

    fun buildEditedRoutingRules(state: MainUiState): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(state.routingProxyPackagesDraft)
        return RoutingRules(
            ignoreRules = state.routingIgnoreRulesDraft,
            proxyPackages = proxyPackages,
            bypassPackages = emptyList(),
            nationalDomainSuffixes = RoutingRules.parseNationalDomainSuffixes(state.routingNationalDomainsDraft),
            directDomainSuffixes = RoutingRules.parseDirectDomainSuffixes(state.routingDirectDomainsDraft),
            ruleSets = emptyList(),
        )
    }

    fun buildRuleSetDraft(state: MainUiState): Result<RoutingRuleSet> = runCatching {
        val name = state.routingRuleSetNameDraft.trim()
        require(name.isNotBlank()) { "Rule-set name is required" }
        val sourceType = state.routingRuleSetSourceTypeDraft
        val source = state.routingRuleSetSourceDraft.trim()
        require(source.isNotBlank()) {
            when (sourceType) {
                RoutingRuleSetSourceType.INLINE -> "Inline rule-set content is required"
                RoutingRuleSetSourceType.REMOTE -> "Remote rule-set URL is required"
            }
        }
        when (sourceType) {
            RoutingRuleSetSourceType.INLINE -> requireInlineRuleSet(source)
            RoutingRuleSetSourceType.REMOTE -> requireRemoteRuleSetUrl(source)
        }
        RoutingRuleSet(
            id = state.editingRuleSetId.takeIf { it.isNotBlank() } ?: Random.nextLong().toString(),
            name = name,
            sourceType = sourceType,
            format = state.routingRuleSetFormatDraft,
            action = state.routingRuleSetActionDraft,
            source = if (sourceType == RoutingRuleSetSourceType.REMOTE) {
                normalizeHttpsUrl(source)
            } else {
                source
            },
            updateIntervalHours = state.routingRuleSetUpdateHoursDraft.toIntOrNull()?.coerceAtLeast(1) ?: 24,
        ).normalized()
    }

    fun sanitizeRoutingRules(rules: RoutingRules): RoutingRules {
        val proxyPackages = RoutingRules.normalizePackageNames(rules.proxyPackages)
        return rules.copy(
            proxyPackages = proxyPackages,
            bypassPackages = emptyList(),
            ruleSets = emptyList(),
        )
    }

    fun applyImportedRoutingRules(state: MainUiState, rules: RoutingRules): MainUiState {
        return state.copy(
            routingIgnoreRulesDraft = rules.ignoreRules,
            routingProxyPackagesDraft = rules.proxyPackages.toSet(),
            routingBypassPackagesDraft = emptySet(),
            routingNationalDomainsDraft = rules.nationalDomainSuffixes.joinToString(separator = "\n"),
            routingDirectDomainsDraft = rules.directDomainSuffixes.joinToString(separator = "\n"),
            routingRuleSetsDraft = emptyList(),
            showRuleSetDialog = false,
            editingRuleSetId = "",
        )
    }

    private fun sanitizeRuleSets(ruleSets: List<RoutingRuleSet>): List<RoutingRuleSet> {
        return ruleSets
            .mapNotNull { ruleSet ->
                runCatching {
                    when (ruleSet.sourceType) {
                        RoutingRuleSetSourceType.INLINE -> requireInlineRuleSet(ruleSet.source)
                        RoutingRuleSetSourceType.REMOTE -> requireRemoteRuleSetUrl(ruleSet.source)
                    }
                    ruleSet.normalized().copy(
                        source = if (ruleSet.sourceType == RoutingRuleSetSourceType.REMOTE) {
                            normalizeHttpsUrl(ruleSet.source)
                        } else {
                            ruleSet.source.trim()
                        },
                    )
                }.getOrNull()
            }
            .distinctBy { it.id }
            .sortedBy { it.name.lowercase() }
    }

    private fun requireRemoteRuleSetUrl(raw: String) {
        val normalized = normalizeHttpsUrl(raw)
        val uri = URI(normalized)
        require(uri.scheme?.lowercase() == "https" && !uri.host.isNullOrBlank()) {
            "Remote rule-set URL must be a valid HTTPS URL"
        }
    }

    private fun normalizeHttpsUrl(raw: String): String {
        val trimmed = raw.trim()
        val withScheme = if (trimmed.contains("://")) trimmed else "https://$trimmed"
        val uri = URI(withScheme)
        require(uri.host?.isNotBlank() == true) { "Remote rule-set URL must include a host" }
        require(uri.scheme.equals("https", ignoreCase = true)) { "Remote rule-set URL must use HTTPS" }
        return buildString {
            append("https://")
            append(uri.host)
            if (uri.port != -1) {
                append(':')
                append(uri.port)
            }
            uri.rawPath?.takeIf { it.isNotBlank() }?.let(::append)
            uri.rawQuery?.let {
                append('?')
                append(it)
            }
            uri.rawFragment?.let {
                append('#')
                append(it)
            }
        }
    }

    private fun requireInlineRuleSet(raw: String) {
        val trimmed = raw.trim()
        require(trimmed.isNotBlank()) { "Inline rule-set content is required" }
        val rules = when (val parsed = CompactJson.parseToJsonElement(trimmed)) {
            is JsonArray -> parsed
            is JsonObject -> parsed["rules"]?.jsonArray
                ?: throw IllegalArgumentException(
                    "Inline rule-set JSON must be a rules array or an object with a rules field",
                )
            else -> throw IllegalArgumentException(
                "Inline rule-set JSON must be a rules array or an object with a rules field",
            )
        }
        require(rules.isNotEmpty()) { "Inline rule-set must contain at least one rule" }
    }
}
