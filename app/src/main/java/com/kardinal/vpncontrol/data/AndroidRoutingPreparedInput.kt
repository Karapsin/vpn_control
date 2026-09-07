package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.MainDraftLogic
import com.kardinal.vpncontrol.model.RoutingRules

/** Single-owner admission payload; parsing must release the source before persistence. */
internal class AndroidRoutingPreparedInput private constructor(private var input: String?,
    private var external: com.kardinal.vpncontrol.AndroidControlInputSpool?) : AutoCloseable {
    constructor(input: String) : this(input, null)
    constructor(input: com.kardinal.vpncontrol.AndroidControlInputSpool) : this(null, input)
    private var existing: RoutingRules? = null
    fun reuseMatchingTokens(rules: RoutingRules) { existing = rules }
    fun prepareForStorage(): AndroidPreparedRouting = AndroidPreparedRouting(prepare())
    fun prepare(): RoutingRules = try {
        MainDraftLogic.sanitizeRoutingRules(external?.let { spool ->
            existing?.let { RoutingRulesTransfer.import(spool.source(), it) } ?: RoutingRulesTransfer.import(spool.source())
        }
            ?: RoutingRulesTransfer.import(requireNotNull(input)))
    } finally { close() }
    override fun close() { input = null; existing = null; external?.close(); external = null }
}

/** Private, single-use copy: source strings can be released as persistence bytes are emitted. */
internal class AndroidPreparedRouting(rules: RoutingRules) {
    private val ignoreRules = rules.ignoreRules
    private val blockQuicUdp443 = rules.blockQuicUdp443
    private val packages = rules.proxyPackages.toTypedArray<String?>()
    private val domains = rules.directDomainSuffixes.toTypedArray<String?>()
    val domainCount: Int get() = domains.size
    private var consumed = false

    fun matches(rules: RoutingRules): Boolean {
        check(!consumed)
        return ignoreRules == rules.ignoreRules && blockQuicUdp443 == rules.blockQuicUdp443 &&
            packages.size == rules.proxyPackages.size && domains.size == rules.directDomainSuffixes.size &&
            packages.indices.all { packages[it] == rules.proxyPackages[it] } &&
            domains.indices.all { domains[it] == rules.directDomainSuffixes[it] }
    }
    fun discard() { consumed = true; packages.fill(null); domains.fill(null) }

    fun consume(spoolFactory: (() -> com.kardinal.vpncontrol.control.ControlTransferSpool)? = null): AndroidRoutingPreferenceValues {
        check(!consumed) { "Routing payload already consumed" }
        consumed = true
        return try {
            AndroidRoutingPreferenceValues(ignoreRules, blockQuicUdp443,
                AndroidStringListCodec.encodeOwned(packages, spoolFactory), AndroidStringListCodec.encodeOwned(domains, spoolFactory))
        } finally { packages.fill(null); domains.fill(null) }
    }
}

internal data class AndroidRoutingPreferenceValues(val ignoreRules: Boolean, val blockQuicUdp443: Boolean,
    val proxyPackages: String, val directDomainSuffixes: String)
