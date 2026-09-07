package com.kardinal.vpncontrol

import android.content.pm.PackageManager

/** Android 10 only collects/verifies archive certificates when the legacy flag is also present.
 * We still consume SigningInfo.apkContentsSigners, never PackageInfo.signatures.
 * AOSP android-10.0.0_r47 PackageManager.getPackageArchiveInfo and PackageParser.collectCertificates.
 */
@Suppress("DEPRECATION")
internal fun androidArchiveSigningFlags(sdk: Int): Int = PackageManager.GET_SIGNING_CERTIFICATES or
    (if (sdk == 29) PackageManager.GET_SIGNATURES else 0)
