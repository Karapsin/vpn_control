package com.kardinal.vpncontrol

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/** A restored installer task must not prevent a newly authorized interaction from gaining focus. */
class AndroidControlInteractionManifestTest {
    private fun interactionActivity(): Element {
        val manifest = listOf(File("src/main/AndroidManifest.xml"), File("app/src/main/AndroidManifest.xml"))
            .first { it.isFile }
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(manifest)
        val activities = document.getElementsByTagName("activity")
        return (0 until activities.length).map { activities.item(it) as Element }.single {
            it.android("name") == ".AndroidControlInteractionActivity"
        }
    }

    @Test fun recoveredInstallerInteractionAlwaysGetsAnIndependentTask() {
        val activity = interactionActivity()
        assertEquals("An older installer task must not consume a fresh interaction launch",
            "always", activity.android("documentLaunchMode"))
        assertTrue(activity.android("launchMode") in setOf("", "standard"))
    }

    @Test fun independentInteractionRemainsProtectedAndAbsentFromRecents() {
        val activity = interactionActivity()
        assertEquals("android.permission.DUMP", activity.android("permission"))
        assertEquals("true", activity.android("excludeFromRecents"))
    }

    private fun Element.android(name: String) = getAttributeNS("http://schemas.android.com/apk/res/android", name)
}
