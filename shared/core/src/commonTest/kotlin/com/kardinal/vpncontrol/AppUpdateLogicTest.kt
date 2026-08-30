package com.kardinal.vpncontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AppUpdateLogicTest {
    @Test
    fun parsesAndSelectsPreferredCompatibleAsset() {
        val manifest = AppUpdateLogic.parseManifest(manifestJson())

        assertEquals(138, manifest.buildNumber)
        assertTrue(AppUpdateLogic.isUpdateAvailable(137, manifest))
        assertFalse(AppUpdateLogic.isUpdateAvailable(138, manifest))
        assertEquals(
            UpdatePackageType.DEB,
            AppUpdateLogic.selectAsset(
                manifest = manifest,
                platform = UpdatePlatform.LINUX,
                architectureAliases = setOf("amd64"),
                preferredPackageTypes = listOf(UpdatePackageType.DEB, UpdatePackageType.RPM),
            )?.packageType,
        )
    }

    @Test
    fun returnsNullWhenArchitectureIsUnavailable() {
        val manifest = AppUpdateLogic.parseManifest(manifestJson())

        assertNull(
            AppUpdateLogic.selectAsset(
                manifest = manifest,
                platform = UpdatePlatform.LINUX,
                architectureAliases = setOf("arm64"),
                preferredPackageTypes = listOf(UpdatePackageType.DEB),
            ),
        )
    }

    @Test
    fun rejectsUnknownSchemaAndUntrustedDownload() {
        assertFailsWith<IllegalArgumentException> {
            AppUpdateLogic.parseManifest(manifestJson().replace("\"schemaVersion\": 1", "\"schemaVersion\": 2"))
        }
        assertFailsWith<IllegalArgumentException> {
            AppUpdateLogic.parseManifest(
                manifestJson().replace(
                    "https://github.com/Karapsin/vpn_control/releases/download/v0.1.138/app.deb",
                    "https://example.com/app.deb",
                ),
            )
        }
    }

    private fun manifestJson(): String =
        """
        {
          "schemaVersion": 1,
          "buildNumber": 138,
          "releaseTag": "v0.1.138",
          "releaseNotesUrl": "https://github.com/Karapsin/vpn_control/releases/tag/v0.1.138",
          "assets": [
            {
              "platform": "linux",
              "architecture": "x86_64",
              "packageType": "deb",
              "displayVersion": "0.1.138",
              "fileName": "app.deb",
              "downloadUrl": "https://github.com/Karapsin/vpn_control/releases/download/v0.1.138/app.deb",
              "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              "sizeBytes": 1024
            }
          ]
        }
        """.trimIndent()
}
