package com.kardinal.vpncontrol

import android.content.pm.PackageManager
import org.junit.Assert.*
import org.junit.Test

class AndroidArchiveSigningFlagsTest {
    @Suppress("DEPRECATION")
    @Test fun api29RequestsVerifiedCertificateCollectionAndModernSigningInfoTogether() {
        // AOSP android-10.0.0_r47 PackageManager.getPackageArchiveInfo gates
        // collectCertificates(pkg, false) on GET_SIGNATURES only. generatePackageInfo
        // separately gates SigningInfo creation on GET_SIGNING_CERTIFICATES.
        fun signingInfo(flags: Int, validSignature: Boolean): String? {
            val verified = flags and PackageManager.GET_SIGNATURES != 0 && validSignature
            return if (verified && flags and PackageManager.GET_SIGNING_CERTIFICATES != 0) "verified-current-signers" else null
        }
        assertNull(signingInfo(PackageManager.GET_SIGNING_CERTIFICATES, true))
        assertNull(signingInfo(PackageManager.GET_SIGNATURES, true))
        assertEquals("verified-current-signers", signingInfo(androidArchiveSigningFlags(29), true))
        assertNull(signingInfo(androidArchiveSigningFlags(29), false))
    }

    @Test fun newerPlatformsKeepModernSigningMetadataRequest() {
        for (sdk in 30..35) assertEquals(PackageManager.GET_SIGNING_CERTIFICATES, androidArchiveSigningFlags(sdk))
    }
}
