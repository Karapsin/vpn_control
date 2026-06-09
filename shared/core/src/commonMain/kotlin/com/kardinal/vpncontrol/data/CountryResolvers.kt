package com.kardinal.vpncontrol.data

fun interface UserCountryResolver {
    suspend fun resolveUserCountryCode(): String?
}

fun interface CandidateCountryResolver {
    suspend fun resolveCandidateCountryCode(ipAddress: String): String?
}

object NoopUserCountryResolver : UserCountryResolver {
    override suspend fun resolveUserCountryCode(): String? = null
}

object NoopCandidateCountryResolver : CandidateCountryResolver {
    override suspend fun resolveCandidateCountryCode(ipAddress: String): String? = null
}
