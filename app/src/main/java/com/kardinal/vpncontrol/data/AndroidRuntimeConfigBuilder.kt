package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.RoutingRules

/** The caller transfers a retained lease to prepared runtime ownership, then closes this build. */
internal class BuiltRuntimeConfig(
    val json: String,
    private val directDomains: AndroidDirectDomainRuleSetStore.Lease?,
) : AutoCloseable {
    fun retainDirectDomains(): AndroidDirectDomainRuleSetStore.Lease? = directDomains?.retain()
    override fun close() {
        directDomains?.close()
    }
}

/** Android-generated configurations keep large direct-domain data in a private source rule set. */
internal class AndroidRuntimeConfigBuilder(private val directDomainRuleSets: AndroidDirectDomainRuleSetStore) {
    fun build(
        profile: ProxyProfile,
        dns: DnsSettings,
        routing: RoutingRules,
        mode: AppMode,
        verificationPort: Int?,
        homeRoute: HomeSshRouteRuntimeOptions?,
    ): BuiltRuntimeConfig {
        require(profile.protocol != com.kardinal.vpncontrol.model.ProxyProtocol.CUSTOM) {
            "Custom configurations are transformed separately"
        }
        val lease = directDomainRuleSets.stage(routing)
        try {
            val json = when (mode) {
                AppMode.VPN -> SingBoxConfigFactory.buildTunConfig(
                    profile = profile,
                    dns = dns,
                    routingRules = routing,
                    activeVerificationPort = verificationPort,
                    homeRoute = homeRoute,
                    localDirectDomainRuleSetPath = lease?.path,
                )
                AppMode.PROXY_ONLY -> SingBoxConfigFactory.buildProxyOnlyConfig(
                    profile = profile,
                    dns = dns,
                    routingRules = routing,
                    listenPort = SingBoxConfigFactory.DEFAULT_PROXY_ONLY_PORT,
                    managementProxyPort = verificationPort ?: SingBoxConfigFactory.DEFAULT_VPN_MANAGEMENT_PROXY_PORT,
                    homeRoute = homeRoute,
                    localDirectDomainRuleSetPath = lease?.path,
                )
            }
            return BuiltRuntimeConfig(json, lease)
        } catch (failure: Throwable) {
            lease?.close()
            throw failure
        }
    }
}
