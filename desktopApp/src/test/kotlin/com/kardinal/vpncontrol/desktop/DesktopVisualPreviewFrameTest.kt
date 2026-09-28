package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopVisualPreviewFrameTest {
    @Test
    fun benchmarkVisualSceneUsesAnAdmittedPublicBenchmarkLabel() {
        val directory = Files.createTempDirectory("vpn-control-visual-benchmark-preview")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            service.replaceStateForVisualCapture(visualState("locations-benchmark"), visualLocations())
            val (_, presentation) = visualPreviewFrame(service, "visual-preview")
            assertTrue(presentation.frontend.locations.first().benchmark.isNotBlank())
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun selectedLocationVisualSceneMarksItsPreviewRowActiveWithoutRunningTheService() {
        val directory = Files.createTempDirectory("vpn-control-visual-location-preview")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            service.replaceStateForVisualCapture(visualState("locations-selected"), visualLocations())
            assertFalse(service.controlSnapshot("visual-preview").runtimeRunning)

            val (runtime, presentation) = visualPreviewFrame(service, "visual-preview")
            assertTrue(runtime.runtimeRunning)
            assertTrue(runtime.activeLocationId != null)
            assertEquals(1, presentation.frontend.locations.count { it.selected && it.active })
            assertFalse(service.controlPresentationSnapshot("visual-preview").locations.any { it.active })
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun connectedVisualSceneHasAConsistentPreviewRuntimeWithoutStartingTheRealRuntime() {
        val directory = Files.createTempDirectory("vpn-control-visual-preview")
        val service = DesktopAppServiceFactory.createForTesting(DesktopStateStore(directory))
        try {
            service.replaceStateForVisualCapture(visualState("main-connected"), visualLocations())
            assertFalse(service.controlSnapshot("visual-preview").runtimeRunning)

            val (runtime, presentation) = visualPreviewFrame(service, "visual-preview")
            assertTrue(runtime.runtimeRunning)
            assertTrue(presentation.frontend.runtime.runtimeRunning)
            assertTrue(presentation.frontend.statistics.running)
            assertEquals(runtime, presentation.frontend.runtime)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
