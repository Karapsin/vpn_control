package com.kardinal.vpncontrol.desktop

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Portable regressions for the Windows region capture (VISUAL-002/VISUAL-004). They model the
 * hosted windows-2025 failures of f31ab987: the taskbar clock and the runner's desktop shortcuts
 * changed outside the product surface, foreground state and a caret changed inside full-screen
 * frames, and a window's translucent 1 px border blends with whatever lies behind it.
 */
class NativeRegionCaptureTest {
    private val screen = RegionRect(0, 0, 1280, 800)
    private val workArea = RegionRect(0, 0, 1280, 752)

    @Test
    fun regionRectanglesTouchingAtAnEdgeDoNotIntersect() {
        val target = RegionRect(100, 100, 200, 200)
        assertTrue(target.intersects(RegionRect(199, 199, 300, 300)))
        assertFalse(target.intersects(RegionRect(200, 100, 300, 200)))
        assertFalse(target.intersects(RegionRect(100, 200, 200, 300)))
        assertFalse(target.intersects(RegionRect(150, 150, 150, 160)))
        assertTrue(screen.contains(target))
        assertFalse(workArea.contains(RegionRect(10, 740, 20, 760)))
        assertEquals(RegionRect(90, 90, 210, 210), target.expanded(10))
    }

    @Test
    fun targetSelectionRequiresExactlyOnePaintingWindowWithTheNativeIdentity() {
        val wizard = nativeWindow(11, pid = 700, className = "MsiDialogCloseClass", title = "vpn-control Setup")
        val preparing = nativeWindow(12, pid = 700, className = "MsiDialogCloseClass", title = "Windows Installer")
        val rule = TargetRule("installer-wizard", processId = 700, titleSuffix = " Setup")
        assertEquals(TargetSelection.Found(wizard), selectTarget(listOf(preparing, wizard), rule))
        assertEquals(
            TargetSelection.Missing(listOf(wizard.copy(cloaked = true))),
            selectTarget(listOf(wizard.copy(cloaked = true)), rule),
        )
        assertTrue(selectTarget(listOf(wizard.copy(minimized = true)), rule) is TargetSelection.Missing)
        assertTrue(selectTarget(listOf(wizard.copy(visible = false)), rule) is TargetSelection.Missing)
        assertTrue(selectTarget(listOf(wizard.copy(processId = 701)), rule) is TargetSelection.Missing)
        assertTrue(selectTarget(listOf(wizard, wizard.copy(handle = 13)), rule) is TargetSelection.Ambiguous)

        val owner = 0x400L
        val dialog = nativeWindow(21, className = "#32770", title = "Import VPN Control configuration", owner = owner)
        val dialogRule = TargetRule("file-dialog", processId = 100, className = "#32770", title = dialog.title, ownerHandle = owner)
        assertEquals(TargetSelection.Found(dialog), selectTarget(listOf(dialog), dialogRule))
        assertTrue(selectTarget(listOf(dialog.copy(ownerHandle = 0x401)), dialogRule) is TargetSelection.Missing)
        assertTrue(selectTarget(listOf(dialog.copy(className = "SunAwtDialog")), dialogRule) is TargetSelection.Missing)
    }

    @Test
    fun targetWaitOutlastsATransientInstallerWindowAndNamesItsRefusal() {
        val wizard = nativeWindow(11, pid = 700, title = "vpn-control Setup")
        val rule = TargetRule("installer-wizard", processId = 700, titleSuffix = " Setup")
        var polls = 0
        val censuses = listOf(emptyList(), listOf(wizard, wizard.copy(handle = 12)), listOf(wizard))
        val found = awaitTarget("windows-msi", rule, 5, { censuses[minOf(polls++, censuses.lastIndex)] }) {}
        assertEquals(wizard, found)
        assertEquals(3, polls)

        val ambiguous = assertFailsWith<RegionCaptureRefusedException> {
            awaitTarget("windows-msi", rule, 3, { listOf(wizard, wizard.copy(handle = 12)) }) {}
        }
        assertEquals(RegionCaptureRefusal.TARGET_AMBIGUOUS, ambiguous.refusal)
        assertTrue(ambiguous.message!!.startsWith("windows-msi: infrastructure failure [target-ambiguous]"))

        var missingPolls = 0
        val missing = assertFailsWith<RegionCaptureRefusedException> {
            awaitTarget("windows-msi", rule, 4, { missingPolls++; listOf(wizard.copy(cloaked = true)) }) {}
        }
        assertEquals(RegionCaptureRefusal.TARGET_MISSING, missing.refusal)
        assertEquals(4, missingPolls)
        assertTrue("hidden matches" in missing.detail)
    }

    @Test
    fun placementCarriesInvisibleResizeBordersOverToTheWindowRectangle() {
        // Windows 10+ window rectangles include 7 px invisible resize borders left, right and below.
        val app = nativeWindow(1, bounds = RegionRect(147, 40, 1133, 753), windowRect = RegionRect(140, 40, 1140, 760))
        val move = planPlacement(app, WindowsRegionScenes.windowFrame)
        assertEquals(RegionRect(140, 16, 1140, 736), move.expectedBounds)
        assertEquals(RegionRect(133, 16, 1147, 743), move.windowRect)

        val wizard = nativeWindow(2, bounds = RegionRect(393, 181, 886, 567))
        val wizardMove = planPlacement(wizard, WindowsRegionScenes.installerWizard)
        assertEquals(RegionRect(160, 60, 653, 446), wizardMove.expectedBounds)
        assertEquals(wizardMove.expectedBounds, wizardMove.windowRect)
    }

    @Test
    fun canonicalPlacementConvergesOrRefusesWithANamedReason() {
        var current = nativeWindow(1, bounds = RegionRect(147, 40, 1133, 753), windowRect = RegionRect(140, 40, 1140, 760))
        val moves = mutableListOf<Pair<PlacementMove, Boolean>>()
        val placed = placeCanonically("windows-window-frame", "application-window", WindowsRegionScenes.windowFrame, workArea,
            read = { current },
            move = { move, resize ->
                moves += move to resize
                val r = move.windowRect
                current = current.copy(windowRect = r, bounds = RegionRect(r.left + 7, r.top, r.right - 7, r.bottom - 7))
            },
            pause = {},
        )
        assertEquals(RegionRect(140, 16, 1140, 736), placed.window.bounds)
        assertEquals(1, placed.moves)
        assertTrue(moves.single().second, "the application window is sized, not only moved")

        // A dialog whose minimum size clamps the request never converges.
        var clamped = nativeWindow(2, bounds = RegionRect(15, 31, 571, 447))
        val notConverged = assertFailsWith<RegionCaptureRefusedException> {
            placeCanonically("windows-open-dialog", "file-dialog", WindowsRegionScenes.fileDialog, workArea,
                read = { clamped },
                move = { move, _ -> clamped = clamped.copy(bounds = RegionRect.sized(move.windowRect.left, move.windowRect.top, 600, 440)) },
                pause = {},
            )
        }
        assertEquals(RegionCaptureRefusal.PLACEMENT_NOT_CONVERGED, notConverged.refusal)

        val tooLarge = assertFailsWith<RegionCaptureRefusedException> {
            placeCanonically("windows-msi", "installer-wizard", WindowsRegionScenes.installerWizard, workArea,
                read = { nativeWindow(3, bounds = RegionRect(0, 0, 1200, 760)) }, move = { _, _ -> error("must not move") }, pause = {},
            )
        }
        assertEquals(RegionCaptureRefusal.OUTSIDE_WORK_AREA, tooLarge.refusal)
    }

    @Test
    fun occlusionGuardRefusesOnlyWindowsAboveTheReferenceThatPaintIntoTheRegion() {
        val region = RegionRect(160, 60, 653, 446)
        val target = nativeWindow(10, bounds = region)
        val backdrop = nativeWindow(11, bounds = region.expanded(16))
        val check = OcclusionCheck("installer-wizard", region, backdrop.handle, setOf(target.handle, backdrop.handle))
        val tooltip = nativeWindow(20, className = "tooltips_class32", bounds = RegionRect(600, 400, 700, 430))
        val elsewhere = nativeWindow(21, bounds = RegionRect(900, 100, 1000, 200))
        val cloaked = nativeWindow(22, bounds = region, cloaked = true)
        val minimized = nativeWindow(23, bounds = region, minimized = true)
        val below = nativeWindow(24, bounds = region)
        assertEquals(listOf(tooltip), findOccluders(listOf(tooltip, elsewhere, cloaked, minimized, target, backdrop, below), check))
        assertEquals(emptyList(), findOccluders(listOf(elsewhere, target, backdrop, below), check))
        // Anything between the target and its backdrop blends into the region as well.
        val between = nativeWindow(25, bounds = RegionRect(100, 50, 300, 200))
        assertEquals(listOf(between), findOccluders(listOf(target, between, backdrop), check))
        assertNull(findOccluders(listOf(target), check))

        val refusal = assertFailsWith<RegionCaptureRefusedException> {
            requireUnoccluded("windows-msi", "before", listOf(tooltip, target, backdrop), listOf(check))
        }
        assertEquals(RegionCaptureRefusal.OCCLUDED, refusal.refusal)
        assertTrue("tooltips_class32" in refusal.detail && "before capture" in refusal.detail)
    }

    @Test
    fun foreignResidueIsDismissedBestEffortAndNeverDecidesByTitleAlone() {
        var dismissals = 0
        var censuses = 0
        val cleared = dismissForeignResidue(20, {
            censuses++
            if (censuses <= 2) listOf("System Properties") else emptyList()
        }, { dismissals++ }) {}
        assertEquals(emptyList(), cleared)
        assertEquals(2, dismissals, "each census that still shows the dialog closes it again")
        assertEquals(4, censuses, "two consecutive clear censuses end the dismissal")

        var persistentDismissals = 0
        val remaining = dismissForeignResidue(20, { listOf("System Properties - Virtual Memory") }, { persistentDismissals++ }) {}
        assertEquals(listOf("System Properties - Virtual Memory"), remaining)
        assertEquals(20, persistentDismissals)
    }

    @Test
    fun aRemainingSystemPropertiesDialogRefusesOnlyWhereItCoversTheRegion() {
        val output = Files.createTempDirectory("vpn-control-region-residue")
        try {
            val covering = FakeDesktop().apply {
                residue = nativeWindow(90, pid = 4, className = "#32770", title = "System Properties", bounds = RegionRect(100, 100, 500, 400))
            }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { covering.captureWizard(output) }
            assertEquals(RegionCaptureRefusal.OCCLUDED, refusal.refusal)
            assertTrue("System Properties" in refusal.detail)
            assertFalse(Files.exists(output.resolve("windows-msi.png")), "an occluded frame is never published")
            assertTrue(Files.exists(output.resolve("windows-msi.frame.png")), "the refused moment stays as diagnostic evidence")
            assertEquals("occluded", Json.parseToJsonElement(Files.readString(output.resolve("windows-msi.refusal.json"))).jsonObject["reason"]!!.jsonPrimitive.content)

            val aside = output.resolve("aside")
            FakeDesktop().apply {
                residue = nativeWindow(90, pid = 4, className = "#32770", title = "System Properties", bounds = RegionRect(900, 100, 1200, 400))
            }.captureWizard(aside)
            assertTrue(Files.exists(aside.resolve("windows-msi.png")))
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aBackdropLeftAboveItsTargetIsRefusedInsteadOfPublishingTheBackdrop() {
        // The occlusion guard trusted that the target lies above its backdrop. When stacking leaves
        // the opaque backdrop on top, every region pixel is the flat #404040 backdrop; that is an
        // occluded target and must never be published as the scene image.
        val output = Files.createTempDirectory("vpn-control-region-buried")
        try {
            val refusal = assertFailsWith<RegionCaptureRefusedException> {
                FakeDesktop().apply { stackingRefused = true }.captureWizard(output)
            }
            assertEquals(RegionCaptureRefusal.OCCLUDED, refusal.refusal)
            assertTrue("backdrop" in refusal.detail)
            assertFalse(Files.exists(output.resolve("windows-msi.png")), "the flat backdrop is never published")
        } finally {
            output.toFile().deleteRecursively()
        }
        val region = RegionRect(160, 60, 653, 446)
        val target = nativeWindow(10, bounds = region)
        val backdrop = nativeWindow(11, title = "backdrop", bounds = region.expanded(16))
        val check = OcclusionCheck("installer-wizard", region, backdrop.handle, setOf(target.handle, backdrop.handle))
        assertEquals(listOf(backdrop), findOccluders(listOf(backdrop, target), check))
        assertNull(findOccluders(listOf(backdrop), check), "a surface missing from the census is never unoccluded")
    }

    @Test
    fun aWindowShownOnlyWhileThePublishedPairIsTakenIsRefused() {
        // The census ran only before the first and after the last capture, so a tooltip or toast
        // that covered the region in both captures of the published pair, and was gone by the
        // final census, was published inside the scene image.
        val output = Files.createTempDirectory("vpn-control-region-transient")
        try {
            val desktop = FakeDesktop().apply { transientDuringStablePair = true }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { desktop.captureWizard(output) }
            assertEquals(RegionCaptureRefusal.OCCLUDED, refusal.refusal)
            assertTrue("tooltips_class32" in refusal.detail)
            assertFalse(Files.exists(output.resolve("windows-msi.png")))
            val frame = ImageIO.read(output.resolve("windows-msi.frame.png").toFile())
            assertEquals(TOOLTIP_RGB, frame.getRGB(250, 110) and 0xFFFFFF, "the kept frame shows the occluder")
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aRefusalBeforeCaptureKeepsTheFrameOfTheRefusedMoment() {
        // Placement refusals propagate through the scene's finally blocks (msiexec killed, dialogs
        // and windows disposed) before the scene loop records them, so the kept "diagnostic" frame
        // showed the torn-down desktop instead of the refused surface.
        val output = Files.createTempDirectory("vpn-control-region-refused-moment")
        try {
            val desktop = FakeDesktop()
            desktop.windows += nativeWindow(0x2A, pid = 700, className = "MsiDialogCloseClass", title = "vpn-control Setup",
                bounds = RegionRect(40, 20, 1240, 740))
            val engine = RegionCaptureEngine(desktop, "windows", buildJsonObject {})
            val refusal = assertFailsWith<RegionCaptureRefusedException> {
                engine.placeWindow(
                    "windows-msi", "installer-wizard",
                    TargetRule("installer-wizard", processId = 700, titleSuffix = WindowsRegionScenes.INSTALLER_TITLE_SUFFIX),
                    WindowsRegionScenes.installerWizard,
                    { _, _, _ -> error("an oversized wizard must not be moved") },
                )
            }
            assertEquals(RegionCaptureRefusal.OUTSIDE_WORK_AREA, refusal.refusal)
            desktop.windows.clear()
            engine.recordRefusal(output, refusal)
            val frame = ImageIO.read(output.resolve("windows-msi.frame.png").toFile())
            assertEquals(WIZARD_RGB, frame.getRGB(600, 400) and 0xFFFFFF, "the kept frame shows the refused wizard")
            val reason = Json.parseToJsonElement(Files.readString(output.resolve("windows-msi.refusal.json"))).jsonObject["reason"]
            assertEquals("outside-work-area", reason!!.jsonPrimitive.content)
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aHungOrSilentTargetIsRefusedInsteadOfPublishingItsLastFrame() {
        // Two identical captures 250 ms apart show a quiet frame, not a ready target: a wizard whose
        // thread is blocked keeps showing its last frame, and that frame was published.
        val output = Files.createTempDirectory("vpn-control-region-hung")
        try {
            val desktop = FakeDesktop().apply { hung += WIZARD }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { desktop.captureWizard(output) }
            assertEquals("target-not-responding", refusal.refusal.reason)
            assertTrue("IsHungAppWindow" in refusal.detail && "before the stable-frame loop" in refusal.detail, refusal.detail)
            assertFalse(Files.exists(output.resolve("windows-msi.png")), "a frozen frame is never published")
            assertEquals("target-not-responding", refusalReason(output, "windows-msi"))
            assertEquals(1, desktop.captures, "no stable-frame capture is taken, only the refused moment's frame")

            val quiet = FakeDesktop().apply { silent += WIZARD }
            val silentRefusal = assertFailsWith<RegionCaptureRefusedException> { quiet.captureWizard(output.resolve("silent")) }
            assertEquals("target-not-responding", silentRefusal.refusal.reason)
            assertTrue("did not answer WM_NULL within 2000 ms" in silentRefusal.detail, silentRefusal.detail)
            assertFalse(Files.exists(output.resolve("silent/windows-msi.png")))
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aTargetThatStopsAnsweringWhileThePairIsTakenIsNotPublished() {
        val output = Files.createTempDirectory("vpn-control-region-hangs-later")
        try {
            val desktop = FakeDesktop().apply { wizardHangsAfterCapture = 1 }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { desktop.captureWizard(output) }
            assertEquals("target-not-responding", refusal.refusal.reason)
            assertTrue("before publishing" in refusal.detail, refusal.detail)
            assertEquals(2, desktop.captures, "the stable pair was taken and then refused before publishing")
            assertFalse(Files.exists(output.resolve("windows-msi.png")))
            assertTrue(Files.exists(output.resolve("windows-msi.frame.png")))
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aTargetThatHasNotPaintedIsNotPublished() {
        // A window that has not handled its first WM_PAINT gives identical captures as well: its
        // region is the flat backdrop beneath it, or DWM's caption above a flat client area.
        val output = Files.createTempDirectory("vpn-control-region-unpainted")
        try {
            val blank = FakeDesktop().apply { wizardPaintsFromCapture = Int.MAX_VALUE }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { blank.captureWizard(output) }
            assertEquals("target-not-painted", refusal.refusal.reason)
            assertTrue("is entirely the capture backdrop colour #404040" in refusal.detail, refusal.detail)
            assertEquals(REGION_STABLE_MAX_ATTEMPTS, blank.captures, "a flat pair keeps the loop capturing")
            assertFalse(Files.exists(output.resolve("windows-msi.png")))

            val frameOnly = FakeDesktop().apply { wizardClientPainted = false }
            val clientRefusal = assertFailsWith<RegionCaptureRefusedException> { frameOnly.captureWizard(output.resolve("client")) }
            assertEquals("target-not-painted", clientRefusal.refusal.reason)
            assertTrue("client area" in clientRefusal.detail && "one colour #FFFFFF" in clientRefusal.detail, clientRefusal.detail)
            assertFalse(Files.exists(output.resolve("client/windows-msi.png")))

            // A target that paints late is waited for, not refused.
            val late = FakeDesktop().apply { wizardPaintsFromCapture = 3 }
            val record = late.captureWizard(output.resolve("late"))
            assertEquals(4, record["stable_frame"]!!.jsonObject["attempts"]!!.jsonPrimitive.int)
            assertEquals(WIZARD_RGB, ImageIO.read(output.resolve("late/windows-msi.png").toFile()).getRGB(10, 10) and 0xFFFFFF)
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aDialogOrWizardWithoutItsExpectedControlsIsNotPublished() {
        val output = Files.createTempDirectory("vpn-control-region-controls")
        try {
            val noCancel = FakeDesktop().apply { children[WIZARD] = WIZARD_BUTTONS.filterNot { it.text == "Cancel" } }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { noCancel.captureWizard(output) }
            assertEquals("target-controls-missing", refusal.refusal.reason)
            assertTrue("cancel-button (Button 'Cancel')" in refusal.detail, refusal.detail)
            assertTrue("Button id=701 '&Next'" in refusal.detail, "the refusal lists the child-window census")
            assertFalse(Files.exists(output.resolve("windows-msi.png")))

            val hiddenNext = FakeDesktop().apply {
                children[WIZARD] = WIZARD_BUTTONS.map { if (it.text == "&Next") it.copy(visible = false) else it }
            }
            val hidden = assertFailsWith<RegionCaptureRefusedException> { hiddenNext.captureWizard(output.resolve("hidden")) }
            assertEquals("target-controls-missing", hidden.refusal.reason)

            val dialog = FakeDesktop().apply { children[DIALOG] = DIALOG_BUTTONS.filterNot { it.controlId == 2 } }
            val dialogRefusal = assertFailsWith<RegionCaptureRefusedException> { dialog.captureDialog(output.resolve("dialog")) }
            assertEquals("target-controls-missing", dialogRefusal.refusal.reason)
            assertTrue("cancel-button (Button id=2)" in dialogRefusal.detail, dialogRefusal.detail)
            assertFalse(Files.exists(output.resolve("dialog/windows-open-dialog.png")))

            val complete = output.resolve("complete")
            FakeDesktop().captureDialog(complete)
            assertTrue(Files.exists(complete.resolve("windows-open-dialog.png")), "a dialog showing IDOK and IDCANCEL is published")
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    private fun refusalReason(output: Path, sceneId: String): String =
        Json.parseToJsonElement(Files.readString(output.resolve("$sceneId.refusal.json"))).jsonObject["reason"]!!.jsonPrimitive.content

    @Test
    fun stableFrameNeedsTwoConsecutiveIdenticalCaptures() {
        var captures = 0
        val frames = listOf("loading", "painted", "painted")
        val stable = awaitStableFrame("windows-msi", 20, { frames[captures++] }, String::equals) {}
        assertEquals("painted", stable.frame)
        assertEquals(3, stable.attempts)

        var unstableCaptures = 0
        val unstable = assertFailsWith<RegionCaptureRefusedException> {
            awaitStableFrame("windows-open-dialog", 20, { unstableCaptures++ }, Int::equals) {}
        }
        assertEquals(RegionCaptureRefusal.UNSTABLE_FRAME, unstable.refusal)
        assertEquals(20, unstableCaptures, "the stable-frame loop is bounded")
    }

    @Test
    fun partsAreStackedInAFixedLayoutAndTheRestIsFill() {
        val layout = stackLayout(listOf(192 to 209, 24 to 40))
        assertEquals(StackLayout(192, 257, listOf(PartOffset(0, 0), PartOffset(0, 217))), layout)

        val frame = BufferedImage(40, 30, BufferedImage.TYPE_INT_RGB)
        for (y in 0 until 30) for (x in 0 until 40) frame.setRGB(x, y, (x shl 16) or (y shl 8) or 7)
        val parts = listOf(RegionRect(2, 3, 6, 5), RegionRect(30, 20, 32, 23))
        val small = stackLayout(parts.map { it.width to it.height }, gap = 1)
        val image = composeRegionImage(frame, RegionRect(0, 0, 40, 30), parts, small)
        assertEquals(4, image.width)
        assertEquals(6, image.height)
        assertEquals(frame.getRGB(2, 3), image.getRGB(0, 0))
        assertEquals(frame.getRGB(5, 4), image.getRGB(3, 1))
        assertEquals(REGION_FILL_RGB, image.getRGB(0, 2) and 0xFFFFFF)
        assertEquals(frame.getRGB(30, 20), image.getRGB(0, 3))
        assertEquals(REGION_FILL_RGB, image.getRGB(2, 3) and 0xFFFFFF)
        assertFailsWith<IllegalArgumentException> {
            composeRegionImage(frame, RegionRect(0, 0, 40, 30), listOf(RegionRect(35, 25, 45, 31)), stackLayout(listOf(10 to 6)))
        }
    }

    @Test
    fun cursorParksInAWorkAreaCornerAwayFromEveryRegion() {
        assertEquals(1279 to 751, cursorParkingPoint(workArea, listOf(RegionRect(160, 60, 653, 446))))
        assertEquals(1279 to 0, cursorParkingPoint(workArea, listOf(RegionRect(1200, 700, 1280, 752))))
        assertNull(cursorParkingPoint(RegionRect(0, 0, 100, 100), listOf(RegionRect(0, 0, 100, 100))))
    }

    @Test
    fun captureSessionVerifiesEverySettingAndRestoresInReverseOrder() {
        val journal = mutableListOf<String>()
        var blink = 530
        var cues = false
        val session = CaptureSessionSettings.applyAll(listOf(
            "caret-blink-ms" to sessionSetting("caret-blink-ms", -1, { blink }) { journal += "blink=$it"; blink = it },
            "keyboard-cues" to sessionSetting("keyboard-cues", true, { cues }) { journal += "cues=$it"; cues = it },
            "already" to sessionSetting("already", 0, { 0 }) { journal += "already=$it" },
        ))
        assertEquals(listOf("blink=-1", "cues=true"), journal)
        assertEquals("530", session.json()["caret-blink-ms"]!!.jsonObject["original"]!!.jsonPrimitive.content)
        session.close()
        assertEquals(listOf("blink=-1", "cues=true", "cues=false", "blink=530"), journal)
        assertEquals(530, blink)

        journal.clear()
        var animation = 1
        val failed = assertFailsWith<RegionCaptureRefusedException> {
            CaptureSessionSettings.applyAll(listOf(
                "window-animation" to sessionSetting("window-animation", 0, { animation }) { journal += "animation=$it"; animation = it },
                "transparency" to sessionSetting("transparency", 0, { 1 }) { journal += "transparency=$it" },
            ))
        }
        assertEquals(RegionCaptureRefusal.SESSION_SETTING_FAILED, failed.refusal)
        assertTrue("transparency reads 1 after setting 0" in failed.detail)
        assertEquals(listOf("animation=0", "transparency=0", "animation=1"), journal, "applied settings are restored")
    }

    @Test
    fun aCaptureSessionThatCannotBeAppliedRefusesEveryRequestedScene() {
        // The session was applied outside the per-scene loop: a failed setting ended the task with
        // only a log line, so no scene had the refusal record and frame the evidence list promises.
        val output = Files.createTempDirectory("vpn-control-region-session")
        try {
            val desktop = FakeDesktop()
            val scenes = listOf("windows-msi", "windows-tray-connected")
            val ran = mutableListOf<String>()
            var animation = 1
            val failure = assertFailsWith<IllegalStateException> {
                runRegionCaptureScenes(desktop, "windows", listOf(
                    "window-animation" to sessionSetting("window-animation", 0, { animation }) { animation = it },
                    "transparency" to sessionSetting("transparency", 0, { 1 }) {},
                ), scenes, output) { _, sceneId -> ran += sceneId }
            }
            assertTrue("session-setting-failed" in failure.message.orEmpty())
            assertEquals(emptyList(), ran, "no scene runs without its capture session")
            assertEquals(1, animation, "the settings applied before the failure are restored")
            for (sceneId in scenes) {
                val path = output.resolve("$sceneId.refusal.json")
                assertTrue(Files.exists(path), "$sceneId is refused like any other scene")
                val refusal = Json.parseToJsonElement(Files.readString(path)).jsonObject
                assertEquals("session-setting-failed", refusal["reason"]!!.jsonPrimitive.content)
                assertTrue("transparency reads 1 after setting 0" in refusal["detail"]!!.jsonPrimitive.content)
                assertEquals("capture-session.frame.png", refusal["frame"]!!.jsonPrimitive.content)
                assertFalse(Files.exists(output.resolve("$sceneId.png")))
            }
            val frame = ImageIO.read(output.resolve("capture-session.frame.png").toFile())
            assertEquals(1280 to 800, frame.width to frame.height)
            assertEquals(1, desktop.captures, "one full frame of the refused session")
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun notifyIconPromotionSelectsOnlyThisExecutablesIcon() {
        val java = "C:\\hostedtoolcache\\windows\\Java_Temurin-Hotspot_jdk\\17.0.16-8\\x64\\bin\\java.exe"
        val entries = listOf(
            NotifyIconEntry("1", java, uid = 2, promoted = null),
            NotifyIconEntry("2", java.uppercase(), uid = 1, promoted = 0),
            NotifyIconEntry("3", java, uid = null, promoted = 0),
            NotifyIconEntry("4", "C:\\Windows\\explorer.exe", uid = 2, promoted = 1),
            NotifyIconEntry("5", "{6D809377-6AF0-444B-8957-A3773F02200E}\\Java\\bin\\java.exe", uid = 2, promoted = null),
        )
        val selected = selectNotifyIconEntries(entries, java, 2) { null }
        assertEquals(listOf("1", "3"), selected.map { it.key })
        val programFiles = selectNotifyIconEntries(entries, "C:\\Program Files\\Java\\bin\\java.exe", 2) { guid ->
            if (guid == "6D809377-6AF0-444B-8957-A3773F02200E") "C:\\Program Files" else null
        }
        assertEquals(listOf("5"), programFiles.map { it.key })
        assertEquals(emptyList(), selectNotifyIconEntries(entries, "", 2) { null })
    }

    @Test
    fun trayIconRectangleMustBeAStableIconInsideTheTaskbar() {
        val taskbar = RegionRect(0, 752, 1280, 800)
        val reads = listOf(null, RegionRect(1060, 752, 1084, 800), RegionRect(1092, 752, 1116, 800), RegionRect(1092, 752, 1116, 800))
        var index = 0
        assertEquals(RegionRect(1092, 752, 1116, 800) to 4, awaitIconRect("windows-tray-connected", 10, taskbar, { reads[index++] }) {})

        val outside = assertFailsWith<RegionCaptureRefusedException> {
            awaitIconRect("windows-tray-connected", 3, taskbar, { RegionRect(1092, 700, 1116, 740) }) {}
        }
        assertEquals(RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE, outside.refusal)
        val whole = assertFailsWith<RegionCaptureRefusedException> {
            awaitIconRect("windows-tray-connected", 3, taskbar, { taskbar }) {}
        }
        assertEquals(RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE, whole.refusal)
    }

    @Test
    fun regionCaptureExcludesTheClockDesktopIconsAndWallpaperFromTheComparedImage() {
        val output = Files.createTempDirectory("vpn-control-region-capture")
        try {
            val desktop = FakeDesktop()
            val record = desktop.captureWizard(output)
            val image = ImageIO.read(output.resolve("windows-msi.png").toFile())
            val frame = ImageIO.read(output.resolve("windows-msi.frame.png").toFile())
            assertEquals(493 to 386, image.width to image.height)
            assertEquals(1280 to 800, frame.width to frame.height)
            // The clock and the desktop shortcut change on every capture, yet the region is stable
            // on the first pair: they lie outside it by construction.
            assertEquals(2, record["stable_frame"]!!.jsonObject["attempts"]!!.jsonPrimitive.int)
            for (y in 0 until image.height) for (x in 0 until image.width) {
                assertEquals(frame.getRGB(160 + x, 60 + y), image.getRGB(x, y))
            }
            assertEquals(WIZARD_RGB, image.getRGB(10, 10) and 0xFFFFFF)
            val part = record["parts"]!!.jsonArray.single().jsonObject
            assertEquals("installer-wizard", part["target"]!!.jsonObject["kind"]!!.jsonPrimitive.content)
            assertEquals("0x2A", part["target"]!!.jsonObject["handle"]!!.jsonPrimitive.content)
            assertEquals(listOf(160, 60, 653, 446), part["rect"]!!.jsonArray.map { it.jsonPrimitive.int })
            assertEquals(listOf(160, 60), part["placement"]!!.jsonObject["canonical"]!!.jsonObject["origin"]!!.jsonArray.map { it.jsonPrimitive.int })
            assertEquals("0x2B", part["placement"]!!.jsonObject["backdrop"]!!.jsonObject["handle"]!!.jsonPrimitive.content)
            assertEquals(listOf(1279, 751), record["cursor"]!!.jsonArray.map { it.jsonPrimitive.int })
            assertTrue(desktop.cuesShown.contains(0x2AL))
            assertEquals(listOf(0x2BL to 0x2AL), desktop.stacked)
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun aTargetThatKeepsChangingIsRefusedAsAnUnstableFrame() {
        val output = Files.createTempDirectory("vpn-control-region-unstable")
        try {
            val desktop = FakeDesktop().apply { blinkingCaret = true }
            val refusal = assertFailsWith<RegionCaptureRefusedException> { desktop.captureWizard(output) }
            assertEquals(RegionCaptureRefusal.UNSTABLE_FRAME, refusal.refusal)
            assertEquals(REGION_STABLE_MAX_ATTEMPTS, desktop.captures)
            assertFalse(Files.exists(output.resolve("windows-msi.png")))
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun foregroundAndFocusMustStayOnTheTarget() {
        val output = Files.createTempDirectory("vpn-control-region-foreground")
        try {
            val refused = assertFailsWith<RegionCaptureRefusedException> {
                FakeDesktop().apply { foregroundRefused = true }.captureWizard(output)
            }
            assertEquals(RegionCaptureRefusal.NOT_FOREGROUND, refused.refusal)
            val unfocused = assertFailsWith<RegionCaptureRefusedException> {
                FakeDesktop().apply { focusInside = false }.captureWizard(output.resolve("focus"))
            }
            assertEquals(RegionCaptureRefusal.NOT_FOREGROUND, unfocused.refusal)
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    @Test
    fun trayRegionRecordMatchesTheSharedGoldenRecord() {
        val output = Files.createTempDirectory("vpn-control-region-tray")
        try {
            val desktop = FakeDesktop()
            val record = desktop.captureTray(output)
            val image = ImageIO.read(output.resolve("windows-tray-connected.png").toFile())
            assertEquals(192 to 257, image.width to image.height)
            assertEquals(MENU_RGB, image.getRGB(5, 5) and 0xFFFFFF)
            assertEquals(REGION_FILL_RGB, image.getRGB(100, 212) and 0xFFFFFF)
            assertEquals(ICON_RGB, image.getRGB(3, 220) and 0xFFFFFF)
            val golden = Json.parseToJsonElement(Files.readString(repositoryRoot().resolve(GOLDEN_TRAY_RECORD)))
            assertEquals(golden, record)
        } finally {
            output.toFile().deleteRecursively()
        }
    }

    private fun repositoryRoot(): Path {
        var directory: Path? = Path.of("").toAbsolutePath()
        while (directory != null && !Files.isRegularFile(directory.resolve("visual-tests/scenes.json"))) directory = directory.parent
        return checkNotNull(directory) { "repository root with visual-tests/scenes.json not found" }
    }

    private fun nativeWindow(
        handle: Long,
        pid: Int = 100,
        className: String = "Window",
        title: String = "",
        bounds: RegionRect = RegionRect(0, 0, 10, 10),
        windowRect: RegionRect = bounds,
        owner: Long = 0,
        cloaked: Boolean = false,
        minimized: Boolean = false,
    ) = NativeWindow(handle, pid, className, title, true, cloaked, minimized, bounds, windowRect, owner)

    /**
     * A 1280x800 desktop whose taskbar clock and desktop shortcut label change on every capture,
     * with a wallpaper gradient and a target window that the capture must find, place and isolate.
     */
    private inner class FakeDesktop : RegionDesktop {
        val windows = mutableListOf<NativeWindow>()
        var residue: NativeWindow? = null
        var blinkingCaret = false
        var foregroundRefused = false
        var focusInside = true
        var stackingRefused = false
        var transientDuringStablePair = false
        val hung = mutableSetOf<Long>()
        val silent = mutableSetOf<Long>()
        /** The wizard's thread stops answering once this many captures were taken. */
        var wizardHangsAfterCapture: Int? = null
        /** The wizard draws nothing before this capture (its region shows what lies beneath it). */
        var wizardPaintsFromCapture = 1
        /** False: DWM draws the wizard's caption, but its client area stays flat white. */
        var wizardClientPainted = true
        val children = mutableMapOf<Long, List<NativeControl>>()
        var captures = 0
        val cuesShown = mutableListOf<Long>()
        val stacked = mutableListOf<Pair<Long, Long>>()
        private var foreground = 0L
        private var transient: NativeWindow? = null

        override fun isHungAppWindow(handle: Long) =
            handle in hung || (handle == WIZARD && wizardHangsAfterCapture?.let { captures >= it } == true)
        override fun answersWithin(handle: Long, timeoutMillis: Int) = handle !in silent && !isHungAppWindow(handle)
        override fun childWindows(handle: Long) = children[handle].orEmpty()
        override fun clientArea(handle: Long): RegionRect? = window(handle)?.let { window ->
            val bounds = window.bounds
            if (window.title in FRAMED_TITLES) RegionRect(bounds.left, bounds.top + CAPTION, bounds.right, bounds.bottom) else bounds
        }

        override fun screen() = screen
        override fun workArea() = workArea
        override fun scale() = 1.0 to 1.0
        override fun census(): List<NativeWindow> = listOfNotNull(transient, residue) + windows
        override fun window(handle: Long) = windows.firstOrNull { it.handle == handle }
        override fun disableTransitions(handle: Long) = true
        override fun showKeyboardCues(handle: Long) {
            cuesShown += handle
        }
        override fun bringToForeground(handle: Long, pause: () -> Unit): Boolean {
            if (!foregroundRefused) foreground = handle
            return !foregroundRefused
        }
        override fun foregroundHandle() = foreground
        override fun focus(handle: Long): JsonObject = buildJsonObject {
            put("focus", hexHandle(handle))
            put("focus_inside_target", focusInside)
        }
        override fun parkCursor(x: Int, y: Int) = true
        override fun dismissHostedSystemProperties(pause: () -> Unit): List<String> = listOfNotNull(residue?.title)
        override fun pause(millis: Long) = Unit

        override fun stackBelow(window: Long, above: Long): Boolean {
            stacked += window to above
            if (stackingRefused) return false
            val moving = windows.first { it.handle == window }
            windows.remove(moving)
            windows.add(windows.indexOfFirst { it.handle == above } + 1, moving)
            return true
        }

        override fun captureScreen(screen: RegionRect): BufferedImage {
            captures++
            // A tooltip shown from the first capture until right after the second one.
            if (transientDuringStablePair && captures == 1) {
                transient = nativeWindow(0x50, pid = 9, className = "tooltips_class32", title = "tooltip",
                    bounds = RegionRect(200, 100, 360, 130))
            }
            val image = BufferedImage(screen.width, screen.height, BufferedImage.TYPE_INT_RGB)
            for (y in 0 until screen.height) for (x in 0 until screen.width) image.setRGB(x, y, (x / 5 shl 16) or (y / 4 shl 8) or 0x80)
            // Desktop shortcut label and taskbar clock: different on every capture (runner drift, real time).
            fill(image, RegionRect(0, 460, 80, 480), 0x111111 * (captures % 15))
            fill(image, RegionRect(1180, 760, 1240, 796), 0x0F0F0F * (captures % 16))
            // Stacked from the bottom: everything below the backdrop is hidden inside the region.
            for (window in census().asReversed()) {
                when (window.title) {
                    "vpn-control Setup" -> paintWizard(image, window.bounds)
                    DIALOG_TITLE -> paintFramed(image, window.bounds, DIALOG_RGB)
                    "backdrop" -> fill(image, window.bounds, WindowsRegionScenes.BACKDROP_RGB)
                    "menu" -> {
                        fill(image, window.bounds, MENU_RGB)
                        fill(image, RegionRect.sized(window.bounds.left + 20, window.bounds.top + 20, 120, 6), TEXT_RGB)
                    }
                    "System Properties" -> fill(image, window.bounds, 0xF0F0F0)
                    "tooltip" -> fill(image, window.bounds, TOOLTIP_RGB)
                }
            }
            if (blinkingCaret) fill(image, RegionRect(200, 100, 201, 116), if (captures % 2 == 0) 0 else 0xFFFFFF)
            if (windows.any { it.title == "taskbar" }) {
                fill(image, ICON_RECT, ICON_RGB)
                fill(image, RegionRect.sized(ICON_RECT.left + 8, ICON_RECT.top + 16, 8, 8), TEXT_RGB)
            }
            if (transientDuringStablePair && captures == 2) transient = null
            return image
        }

        fun captureWizard(output: Path): JsonObject {
            windows += nativeWindow(0x2A, pid = 700, className = "MsiDialogCloseClass", title = "vpn-control Setup",
                bounds = RegionRect(393, 181, 886, 567))
            children.putIfAbsent(WIZARD, WIZARD_BUTTONS)
            val engine = RegionCaptureEngine(this, "windows", sessionJson())
            val part = engine.placeWindow(
                "windows-msi", "installer-wizard",
                TargetRule("installer-wizard", processId = 700, titleSuffix = WindowsRegionScenes.INSTALLER_TITLE_SUFFIX),
                WindowsRegionScenes.installerWizard,
                { handle, move, _ -> moveWindow(handle, move.windowRect) },
            )
            windows.add(0, nativeWindow(0x2B, pid = 100, title = "backdrop", bounds = part.rect.expanded(WindowsRegionScenes.BACKDROP_MARGIN)))
            return engine.capture("windows-msi", output, listOf(part.copy(backdropHandle = 0x2B)), part.targetHandle)
        }

        /** The import dialog of this process, owned by the application window, sized canonically. */
        fun captureDialog(output: Path): JsonObject {
            windows += nativeWindow(DIALOG, className = "#32770", title = DIALOG_TITLE, bounds = RegionRect(15, 31, 571, 447), owner = 0x400)
            children.putIfAbsent(DIALOG, DIALOG_BUTTONS)
            val engine = RegionCaptureEngine(this, "windows", sessionJson())
            val part = engine.placeWindow(
                "windows-open-dialog", "file-dialog",
                TargetRule("file-dialog", processId = 100, className = "#32770", title = DIALOG_TITLE, ownerHandle = 0x400),
                WindowsRegionScenes.fileDialog,
                { handle, move, _ -> moveWindow(handle, move.windowRect) },
            )
            windows.add(0, nativeWindow(0x41, pid = 100, title = "backdrop", bounds = part.rect.expanded(WindowsRegionScenes.BACKDROP_MARGIN)))
            return engine.capture("windows-open-dialog", output, listOf(part.copy(backdropHandle = 0x41)), part.targetHandle)
        }

        private fun paintWizard(image: BufferedImage, bounds: RegionRect) {
            if (captures < wizardPaintsFromCapture) return
            if (wizardClientPainted) {
                paintFramed(image, bounds, WIZARD_RGB)
            } else {
                fill(image, RegionRect(bounds.left, bounds.top, bounds.right, bounds.top + CAPTION), CAPTION_RGB)
                fill(image, RegionRect(bounds.left, bounds.top + CAPTION, bounds.right, bounds.bottom), 0xFFFFFF)
            }
        }

        /** A caption band that DWM draws above a client area showing a line of text. */
        private fun paintFramed(image: BufferedImage, bounds: RegionRect, rgb: Int) {
            fill(image, RegionRect(bounds.left, bounds.top, bounds.right, bounds.top + CAPTION), CAPTION_RGB)
            fill(image, RegionRect(bounds.left, bounds.top + CAPTION, bounds.right, bounds.bottom), rgb)
            fill(image, RegionRect.sized(bounds.left + 40, bounds.top + 30, 120, 6), TEXT_RGB)
        }

        fun captureTray(output: Path): JsonObject {
            windows += nativeWindow(0x30, pid = 100, title = "menu", bounds = RegionRect(544, 168, 736, 377))
            windows += nativeWindow(0x31, pid = 100, title = "helper", bounds = RegionRect(0, 0, 136, 39))
            windows += nativeWindow(0x33, pid = 9, className = WindowsRegionScenes.TASKBAR_CLASS, title = "taskbar", bounds = RegionRect(0, 752, 1280, 800))
            val engine = RegionCaptureEngine(this, "windows", sessionJson())
            val menu = engine.placeWindow(
                "windows-tray-connected", "tray-menu", TargetRule("tray-menu", handle = 0x30, processId = 100),
                WindowsRegionScenes.trayMenu, { handle, move, _ -> moveWindow(handle, move.windowRect) },
            )
            windows.add(windows.indexOfFirst { it.handle == 0x31L }, nativeWindow(0x32, pid = 100, title = "backdrop",
                bounds = menu.rect.expanded(WindowsRegionScenes.BACKDROP_MARGIN)))
            val icon = LocatedPart(
                role = "tray-icon",
                target = buildJsonObject {
                    put("kind", "notification-icon")
                    put("locator", "Shell_NotifyIconGetRect")
                    put("uid", 1)
                },
                rect = ICON_RECT,
                placement = buildJsonObject { put("policy", "shell-placed") },
                targetHandle = 0x33,
                keyboardCues = false,
                current = { ICON_RECT },
            )
            return engine.capture("windows-tray-connected", output, listOf(menu.copy(backdropHandle = 0x32), icon), 0x31)
        }

        private fun moveWindow(handle: Long, rect: RegionRect) {
            val index = windows.indexOfFirst { it.handle == handle }
            windows[index] = windows[index].copy(bounds = rect, windowRect = rect)
        }

        private fun sessionJson() = buildJsonObject {
            put("caret-blink-ms", buildJsonObject {
                put("original", "530")
                put("capture", "-1")
            })
        }

        private fun fill(image: BufferedImage, rect: RegionRect, rgb: Int) {
            for (y in maxOf(rect.top, 0) until minOf(rect.bottom, image.height)) {
                for (x in maxOf(rect.left, 0) until minOf(rect.right, image.width)) image.setRGB(x, y, rgb)
            }
        }
    }

    private companion object {
        const val WIZARD_RGB = 0xF3F3F3
        const val DIALOG_RGB = 0xF5F6F7
        const val CAPTION_RGB = 0xDDE3EA
        const val TEXT_RGB = 0x1B1B1B
        const val MENU_RGB = 0x121F2D
        const val ICON_RGB = 0x2A8FD0
        const val TOOLTIP_RGB = 0xFFFFE1
        const val CAPTION = 8
        const val WIZARD = 0x2AL
        const val DIALOG = 0x40L
        const val DIALOG_TITLE = "Import VPN Control configuration"
        val FRAMED_TITLES = setOf("vpn-control Setup", DIALOG_TITLE)
        val WIZARD_BUTTONS = listOf(
            NativeControl(0x2A01, "Button", "&Back", 700, true),
            NativeControl(0x2A02, "Button", "&Next", 701, true),
            NativeControl(0x2A03, "Button", "Cancel", 702, true),
            NativeControl(0x2A04, "Static", "Welcome to the vpn-control Setup Wizard", 703, true),
        )
        val DIALOG_BUTTONS = listOf(
            NativeControl(0x4001, "Button", "&Open", 1, true),
            NativeControl(0x4002, "Button", "Cancel", 2, true),
            NativeControl(0x4003, "Button", "&Help", 0x40E, false),
            NativeControl(0x4004, "ComboBoxEx32", "", 0x47C, true),
        )
        val ICON_RECT = RegionRect(1092, 756, 1116, 796)
        const val GOLDEN_TRAY_RECORD = "scripts/testdata/visual_region/windows-tray-connected.region.json"
    }
}
