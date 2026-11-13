package com.kardinal.vpncontrol.desktop

import java.awt.image.BufferedImage
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/*
 * Platform-independent decisions of the Windows region capture (VISUAL-002). A Windows OS-owned
 * scene image is the target surface's own region, located by native identity, placed
 * canonically, guarded against occlusion and taken from the first of two consecutive identical
 * captures. The Windows glue only reads native state into these types and applies the plans.
 */

internal const val REGION_RECORD_SCHEMA = 1
internal const val REGION_PART_GAP = 8
internal const val REGION_FILL_RGB = 0x000000
internal const val REGION_STABLE_MAX_ATTEMPTS = 20
internal const val REGION_STABLE_INTERVAL_MILLIS = 250L

/** The full frame of a capture session that could not be applied; every scene's refusal names it. */
internal const val SESSION_REFUSAL_FRAME = "capture-session.frame.png"

/** Readiness checks before the stable-frame loop, [REGION_READY_INTERVAL_MILLIS] apart. */
internal const val REGION_READY_MAX_POLLS = 12
internal const val REGION_READY_INTERVAL_MILLIS = 250L

/** Bound of the WM_NULL round trip that shows a target window's thread is answering. */
internal const val REGION_RESPONSE_TIMEOUT_MILLIS = 2_000

/** Reads, 250 ms apart, of NotifyIconSettings (Explorer records a new icon's entry asynchronously). */
internal const val NOTIFY_ICON_ENTRY_POLLS = 20

/** Reads, 250 ms apart, of the promoted icon's rectangle. */
internal const val NOTIFY_ICON_RECT_POLLS = 40

/** Named infrastructure-failure reasons of a refused region capture. */
internal enum class RegionCaptureRefusal(val reason: String) {
    NON_CANONICAL_DISPLAY("non-canonical-display"),
    TARGET_MISSING("target-missing"),
    TARGET_AMBIGUOUS("target-ambiguous"),
    PLACEMENT_NOT_CONVERGED("placement-not-converged"),
    OUTSIDE_WORK_AREA("outside-work-area"),
    NOT_FOREGROUND("target-not-foreground"),
    CURSOR_NOT_PARKED("cursor-not-parked"),
    OCCLUDED("occluded"),
    TARGET_MOVED("target-moved"),
    UNSTABLE_FRAME("unstable-frame"),
    TARGET_NOT_RESPONDING("target-not-responding"),
    TARGET_NOT_PAINTED("target-not-painted"),
    CONTROLS_MISSING("target-controls-missing"),
    TRAY_ICON_UNAVAILABLE("tray-icon-unavailable"),
    TRAY_ICON_NOT_PROMOTED("tray-icon-not-promoted"),
    SESSION_SETTING_FAILED("session-setting-failed"),
    SECURE_DESKTOP("secure-desktop-not-capturable"),
}

internal class RegionCaptureRefusedException(
    val sceneId: String,
    val refusal: RegionCaptureRefusal,
    val detail: String,
) : IllegalStateException("$sceneId: infrastructure failure [${refusal.reason}]: $detail") {
    /** Full screen of the refused moment, taken before the scene closes its surfaces. */
    var frame: BufferedImage? = null
}

internal fun refuseRegion(sceneId: String, refusal: RegionCaptureRefusal, detail: String): Nothing =
    throw RegionCaptureRefusedException(sceneId, refusal, detail)

internal data class RegionRect(val left: Int, val top: Int, val right: Int, val bottom: Int) {
    val width: Int get() = right - left
    val height: Int get() = bottom - top
    val isEmpty: Boolean get() = width <= 0 || height <= 0

    fun intersects(other: RegionRect): Boolean =
        !isEmpty && !other.isEmpty &&
            left < other.right && other.left < right && top < other.bottom && other.top < bottom

    fun contains(other: RegionRect): Boolean =
        !other.isEmpty && other.left >= left && other.top >= top && other.right <= right && other.bottom <= bottom

    fun contains(x: Int, y: Int): Boolean = x >= left && x < right && y >= top && y < bottom

    fun expanded(margin: Int): RegionRect = RegionRect(left - margin, top - margin, right + margin, bottom + margin)

    /** The overlap of both rectangles; empty when they do not intersect. */
    fun intersect(other: RegionRect): RegionRect =
        RegionRect(maxOf(left, other.left), maxOf(top, other.top), minOf(right, other.right), minOf(bottom, other.bottom))

    fun json(): JsonArray = JsonArray(listOf(left, top, right, bottom).map { JsonPrimitive(it) })

    override fun toString(): String = "[$left,$top,$right,$bottom]"

    companion object {
        fun sized(x: Int, y: Int, width: Int, height: Int): RegionRect = RegionRect(x, y, x + width, y + height)
    }
}

internal fun hexHandle(handle: Long): String = "0x" + java.lang.Long.toHexString(handle).uppercase()

/** One top-level window of a census taken in z-order, topmost first. */
internal data class NativeWindow(
    val handle: Long,
    val processId: Int,
    val className: String,
    val title: String,
    val visible: Boolean,
    val cloaked: Boolean,
    val minimized: Boolean,
    /** Visible frame: DWM extended frame bounds without shadow, else the window rectangle. */
    val bounds: RegionRect,
    /** GetWindowRect, which on Windows 10+ includes the invisible resize borders. */
    val windowRect: RegionRect = bounds,
    val ownerHandle: Long = 0,
    val boundsSource: String = "dwm-extended-frame-bounds",
) {
    val paints: Boolean get() = visible && !cloaked && !minimized && !bounds.isEmpty

    fun describe(): String = "${className.ifEmpty { "?" }} '$title' pid=$processId handle=${hexHandle(handle)} rect=$bounds"

    fun identity(kind: String, locator: String): JsonObject = buildJsonObject {
        put("kind", kind)
        put("locator", locator)
        put("handle", hexHandle(handle))
        put("process_id", processId)
        put("class", className)
        put("title", title)
        put("owner", hexHandle(ownerHandle))
        put("bounds_source", boundsSource)
    }
}

/** Native identity a target surface must have; every non-null field must match. */
internal data class TargetRule(
    val kind: String,
    val handle: Long? = null,
    val processId: Int? = null,
    val className: String? = null,
    val title: String? = null,
    val titleSuffix: String? = null,
    val ownerHandle: Long? = null,
) {
    fun matches(window: NativeWindow): Boolean =
        (handle == null || window.handle == handle) &&
            (processId == null || window.processId == processId) &&
            (className == null || window.className == className) &&
            (title == null || window.title == title) &&
            (titleSuffix == null || window.title.endsWith(titleSuffix)) &&
            (ownerHandle == null || window.ownerHandle == ownerHandle)

    fun locator(): String = buildList {
        handle?.let { add("handle=${hexHandle(it)}") }
        processId?.let { add("pid=$it") }
        className?.let { add("class=$it") }
        title?.let { add("title='$it'") }
        titleSuffix?.let { add("title-suffix='$it'") }
        ownerHandle?.let { add("owner=${hexHandle(it)}") }
    }.joinToString(" ")
}

internal sealed interface TargetSelection {
    data class Found(val window: NativeWindow) : TargetSelection
    data class Missing(val nonPainting: List<NativeWindow>) : TargetSelection
    data class Ambiguous(val candidates: List<NativeWindow>) : TargetSelection
}

internal fun selectTarget(census: List<NativeWindow>, rule: TargetRule): TargetSelection {
    val matching = census.filter(rule::matches)
    val painting = matching.filter(NativeWindow::paints)
    return when (painting.size) {
        1 -> TargetSelection.Found(painting.single())
        0 -> TargetSelection.Missing(matching)
        else -> TargetSelection.Ambiguous(painting)
    }
}

/** Polls censuses until exactly one painting window has the rule's identity. */
internal fun awaitTarget(
    sceneId: String,
    rule: TargetRule,
    maxPolls: Int,
    census: () -> List<NativeWindow>,
    pause: () -> Unit,
): NativeWindow {
    require(maxPolls >= 1)
    var last: TargetSelection = TargetSelection.Missing(emptyList())
    for (poll in 1..maxPolls) {
        last = selectTarget(census(), rule)
        if (last is TargetSelection.Found) return last.window
        if (poll < maxPolls) pause()
    }
    when (val outcome = last) {
        is TargetSelection.Ambiguous -> refuseRegion(
            sceneId,
            RegionCaptureRefusal.TARGET_AMBIGUOUS,
            "${rule.kind} (${rule.locator()}) matched ${outcome.candidates.size} windows after $maxPolls censuses: " +
                outcome.candidates.joinToString("; ") { it.describe() },
        )
        is TargetSelection.Missing -> refuseRegion(
            sceneId,
            RegionCaptureRefusal.TARGET_MISSING,
            "${rule.kind} (${rule.locator()}) matched no visible window after $maxPolls censuses" +
                outcome.nonPainting.takeIf { it.isNotEmpty() }
                    ?.joinToString("; ", prefix = "; hidden matches: ") { it.describe() }.orEmpty(),
        )
        is TargetSelection.Found -> error("unreachable")
    }
}

/** Canonical visible-frame origin, and size for surfaces the capture owns; null keeps the intrinsic size. */
internal data class CanonicalPlacement(val x: Int, val y: Int, val width: Int? = null, val height: Int? = null) {
    init {
        require((width == null) == (height == null)) { "canonical size needs both dimensions" }
        require(width == null || (width > 0 && height!! > 0)) { "canonical size must be positive" }
    }

    val resizes: Boolean get() = width != null

    fun json(): JsonObject = buildJsonObject {
        put("origin", JsonArray(listOf(JsonPrimitive(x), JsonPrimitive(y))))
        put("size", if (width == null) JsonNull else JsonArray(listOf(JsonPrimitive(width), JsonPrimitive(height!!))))
    }
}

/** SetWindowPos rectangle that puts the visible frame exactly on [expectedBounds]. */
internal data class PlacementMove(val windowRect: RegionRect, val expectedBounds: RegionRect)

internal fun planPlacement(window: NativeWindow, canonical: CanonicalPlacement): PlacementMove {
    // DWM reports the visible frame; SetWindowPos takes the window rectangle with its invisible
    // resize borders. Carry those borders over so the visible frame lands on the canonical one.
    val insetLeft = (window.bounds.left - window.windowRect.left).coerceAtLeast(0)
    val insetTop = (window.bounds.top - window.windowRect.top).coerceAtLeast(0)
    val insetRight = (window.windowRect.right - window.bounds.right).coerceAtLeast(0)
    val insetBottom = (window.windowRect.bottom - window.bounds.bottom).coerceAtLeast(0)
    val expected = RegionRect.sized(
        canonical.x,
        canonical.y,
        canonical.width ?: window.bounds.width,
        canonical.height ?: window.bounds.height,
    )
    return PlacementMove(
        RegionRect(expected.left - insetLeft, expected.top - insetTop, expected.right + insetRight, expected.bottom + insetBottom),
        expected,
    )
}

internal data class PlacementResult(val window: NativeWindow, val expected: RegionRect, val moves: Int)

/** Moves (and for owned surfaces sizes) the target until its visible frame is canonical. */
internal fun placeCanonically(
    sceneId: String,
    label: String,
    canonical: CanonicalPlacement,
    workArea: RegionRect,
    read: () -> NativeWindow,
    move: (PlacementMove, Boolean) -> Unit,
    pause: () -> Unit,
    maxMoves: Int = 3,
): PlacementResult {
    val first = read()
    val expected = planPlacement(first, canonical).expectedBounds
    if (!workArea.contains(expected)) {
        refuseRegion(
            sceneId,
            RegionCaptureRefusal.OUTSIDE_WORK_AREA,
            "$label canonical frame $expected does not fit the work area $workArea",
        )
    }
    var current = first
    var moves = 0
    while (current.bounds != expected && moves < maxMoves) {
        move(planPlacement(current, canonical), canonical.resizes)
        moves++
        pause()
        current = read()
    }
    if (current.bounds != expected) {
        refuseRegion(
            sceneId,
            RegionCaptureRefusal.PLACEMENT_NOT_CONVERGED,
            "$label frame is ${current.bounds} after $moves moves; canonical frame is $expected",
        )
    }
    return PlacementResult(current, expected, moves)
}

/** A region that must be free of foreign windows, and the window whose z-position bounds "above". */
internal data class OcclusionCheck(
    val label: String,
    val region: RegionRect,
    val referenceHandle: Long,
    val surfaceHandles: Set<Long>,
)

/**
 * Windows above [OcclusionCheck.referenceHandle] in z-order that paint into the region. The
 * reference is the target itself for opaque surfaces and the capture's own backdrop for a
 * translucent surface, whose pixels blend with everything stacked above that backdrop. Every
 * surface paints the region from above the reference: a target stacked beneath its backdrop is
 * hidden by it, so the reference itself is then an occluder. Null when the reference or a
 * surface is absent from the census.
 */
internal fun findOccluders(census: List<NativeWindow>, check: OcclusionCheck): List<NativeWindow>? {
    val reference = census.indexOfFirst { it.handle == check.referenceHandle }
    if (reference < 0) return null
    val surfaces = check.surfaceHandles.map { handle -> census.indexOfFirst { it.handle == handle } }
    if (surfaces.any { it < 0 }) return null
    val above = census.subList(0, reference).filter { window ->
        window.handle !in check.surfaceHandles && window.paints && window.bounds.intersects(check.region)
    }
    return if (surfaces.any { it > reference }) above + census[reference] else above
}

internal fun requireUnoccluded(sceneId: String, phase: String, census: List<NativeWindow>, checks: List<OcclusionCheck>) {
    for (check in checks) {
        val occluders = findOccluders(census, check) ?: refuseRegion(
            sceneId,
            RegionCaptureRefusal.TARGET_MISSING,
            "${check.label} reference window ${hexHandle(check.referenceHandle)} or one of its surfaces " +
                "${check.surfaceHandles.map(::hexHandle)} is absent $phase capture",
        )
        if (occluders.isNotEmpty()) {
            refuseRegion(
                sceneId,
                RegionCaptureRefusal.OCCLUDED,
                "${check.label} region ${check.region} is covered $phase capture by " +
                    occluders.joinToString("; ") { it.describe() },
            )
        }
    }
}

internal class StableFrame<T>(val frame: T, val attempts: Int)

/**
 * Captures until two consecutive captures are identical and the later one has painted
 * ([unpainted] returns null); that later capture is published. An identical pair that has not
 * painted keeps the loop capturing, and is refused as target-not-painted if the loop ends on one.
 */
internal fun <T> awaitStableFrame(
    sceneId: String,
    maxAttempts: Int,
    capture: () -> T,
    identical: (T, T) -> Boolean,
    unpainted: (T) -> String? = { null },
    pause: () -> Unit,
): StableFrame<T> {
    require(maxAttempts >= 2) { "a stable frame needs at least two captures" }
    var previous = capture()
    var flat: String? = null
    for (attempt in 2..maxAttempts) {
        pause()
        val current = capture()
        if (identical(previous, current)) {
            flat = unpainted(current) ?: return StableFrame(current, attempt)
        } else {
            flat = null
        }
        previous = current
    }
    flat?.let { refuseRegion(sceneId, RegionCaptureRefusal.TARGET_NOT_PAINTED, "$it in all $maxAttempts captures") }
    refuseRegion(
        sceneId,
        RegionCaptureRefusal.UNSTABLE_FRAME,
        "no two consecutive region captures were identical in $maxAttempts attempts",
    )
}

/** The single colour of [rect] in [frame], or null when the rectangle shows more than one colour. */
internal fun flatColour(frame: BufferedImage, screen: RegionRect, rect: RegionRect): Int? {
    require(screen.contains(rect)) { "rect $rect lies outside the captured screen $screen" }
    val pixels = frame.getRGB(rect.left - screen.left, rect.top - screen.top, rect.width, rect.height, null, 0, rect.width)
    val first = pixels[0] and 0xFFFFFF
    return if (pixels.all { (it and 0xFFFFFF) == first }) first else null
}

internal fun rgbHex(rgb: Int): String = "#%06X".format(rgb and 0xFFFFFF)

/** One descendant window of a target, from its native child-window census. */
internal data class NativeControl(
    val handle: Long,
    val className: String,
    val text: String,
    val controlId: Int,
    val visible: Boolean,
) {
    fun describe(): String = "$className id=$controlId '$text'" + if (visible) "" else " (hidden)"
}

/** A visible child control a dialog must show: its window class plus its control ID or caption. */
internal data class ControlRule(
    val label: String,
    val className: String,
    val controlId: Int? = null,
    val caption: String? = null,
) {
    init {
        require((controlId == null) != (caption == null)) { "a control rule names either a control ID or a caption" }
    }

    /** Captions compare without their access-key ampersand ("&Next" is Next). */
    fun matches(control: NativeControl): Boolean =
        control.visible && control.className.equals(className, ignoreCase = true) &&
            (controlId == null || control.controlId == controlId) &&
            (caption == null || control.text.replace("&", "").trim().equals(caption, ignoreCase = true))

    fun describe(): String = "$label ($className ${controlId?.let { "id=$it" } ?: "'$caption'"})"
}

/**
 * What must hold for a part before the stable-frame loop and again before its image is published.
 * Two identical captures show only that nothing changed, not that the target is ready.
 */
internal data class PartReadiness(
    /** The window's thread answers: IsHungAppWindow is false and WM_NULL returns within the bound. */
    val responsive: Boolean = true,
    /** The window's client area, not only the frame DWM draws around it, shows more than one colour. */
    val clientPainted: Boolean = true,
    /** Visible child controls the native child-window census must show. */
    val controls: List<ControlRule> = emptyList(),
    /** A notification icon, which must lie in the visible notification area (notifyIconPlacementFailure). */
    val notificationIcon: Boolean = false,
)

internal data class PartOffset(val x: Int, val y: Int) {
    fun json(): JsonArray = JsonArray(listOf(JsonPrimitive(x), JsonPrimitive(y)))
}

internal data class StackLayout(val width: Int, val height: Int, val offsets: List<PartOffset>)

/** Parts are stacked top to bottom, left-aligned, [gap] pixels apart; the rest is fill. */
internal fun stackLayout(sizes: List<Pair<Int, Int>>, gap: Int = REGION_PART_GAP): StackLayout {
    require(sizes.isNotEmpty() && sizes.all { (width, height) -> width > 0 && height > 0 }) { "parts need a positive size" }
    var y = 0
    val offsets = sizes.mapIndexed { index, (_, height) ->
        if (index > 0) y += gap
        PartOffset(0, y).also { y += height }
    }
    return StackLayout(sizes.maxOf { it.first }, y, offsets)
}

/** Composes the scene image from [frame]; every part must lie inside the captured [screen]. */
internal fun composeRegionImage(
    frame: BufferedImage,
    screen: RegionRect,
    parts: List<RegionRect>,
    layout: StackLayout,
    fillRgb: Int = REGION_FILL_RGB,
): BufferedImage {
    require(parts.size == layout.offsets.size) { "every part needs a layout offset" }
    require(frame.width == screen.width && frame.height == screen.height) { "frame does not match the screen" }
    val image = BufferedImage(layout.width, layout.height, BufferedImage.TYPE_INT_RGB)
    val fill = IntArray(layout.width * layout.height) { fillRgb }
    image.setRGB(0, 0, layout.width, layout.height, fill, 0, layout.width)
    parts.forEachIndexed { index, rect ->
        require(screen.contains(rect)) { "part $rect lies outside the captured screen $screen" }
        val pixels = frame.getRGB(rect.left - screen.left, rect.top - screen.top, rect.width, rect.height, null, 0, rect.width)
        val offset = layout.offsets[index]
        image.setRGB(offset.x, offset.y, rect.width, rect.height, pixels, 0, rect.width)
    }
    return image
}

internal fun rgbPixels(image: BufferedImage): IntArray =
    image.getRGB(0, 0, image.width, image.height, null, 0, image.width).also { pixels ->
        for (index in pixels.indices) pixels[index] = pixels[index] and 0xFFFFFF
    }

/** A point in the work area away from every region, so nothing in a region is hovered. */
internal fun cursorParkingPoint(workArea: RegionRect, regions: List<RegionRect>, margin: Int = 24): Pair<Int, Int>? =
    listOf(
        workArea.right - 1 to workArea.bottom - 1,
        workArea.right - 1 to workArea.top,
        workArea.left to workArea.bottom - 1,
        workArea.left to workArea.top,
    ).firstOrNull { (x, y) -> regions.none { it.expanded(margin).contains(x, y) } }

/** One HKCU\Control Panel\NotifyIconSettings entry (Windows 11 notification-icon promotion). */
internal data class NotifyIconEntry(val key: String, val executablePath: String, val uid: Int?, val promoted: Int?)

/** Entries of this executable's icon; a recorded UID must equal the icon's uID. */
internal fun selectNotifyIconEntries(
    entries: List<NotifyIconEntry>,
    executable: String,
    uid: Int,
    knownFolder: (String) -> String?,
): List<NotifyIconEntry> {
    if (executable.isBlank()) return emptyList()
    val wanted = normalizeWindowsPath(executable)
    return entries.filter { entry ->
        val path = resolveKnownFolderPath(entry.executablePath, knownFolder)
        path != null && normalizeWindowsPath(path) == wanted && (entry.uid == null || entry.uid == uid)
    }
}

private val KNOWN_FOLDER_PREFIX = Regex("""^\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}(\\.*)?$""")

/** Explorer records paths under a known folder as "{FOLDERID}\rest". */
internal fun resolveKnownFolderPath(raw: String, knownFolder: (String) -> String?): String? {
    val match = KNOWN_FOLDER_PREFIX.matchEntire(raw) ?: return raw
    val base = knownFolder(match.groupValues[1].uppercase()) ?: return null
    return base.trimEnd('\\') + match.groupValues[2]
}

internal fun normalizeWindowsPath(path: String): String = path.replace('/', '\\').trimEnd('\\').lowercase()

/** Shell_NotifyIconGetRect for this process's notification icon, with the identity it was asked for. */
internal data class NotifyIconLocation(val rect: RegionRect?, val identity: JsonObject)

/** The taskbar's notification area as the shell exposes it in native windows. */
internal data class NotificationArea(
    val taskbar: NativeWindow,
    /** Where promoted icons show; null when the shell exposes no such visible window. */
    val visible: RegionRect?,
    /** How [visible] was located, or what the taskbar showed instead. */
    val source: String,
    /** The overflow chevron, when the shell exposes it as a visible window. */
    val chevron: RegionRect?,
    /** True when [visible] is the promoted-icon area itself, which never holds the chevron. */
    val excludesChevron: Boolean,
    /** Open overflow flyout windows. */
    val overflow: List<NativeWindow> = emptyList(),
) {
    fun json(): JsonObject = buildJsonObject {
        put("taskbar", hexHandle(taskbar.handle))
        put("taskbar_rect", taskbar.bounds.json())
        put("visible", visible?.json() ?: JsonNull)
        put("source", source)
        put("chevron", chevron?.json() ?: JsonNull)
        put("excludes_chevron", excludesChevron)
        put("overflow", JsonArray(overflow.map { JsonPrimitive(it.describe()) }))
    }
}

/**
 * Why [icon] is not a promoted notification icon on the taskbar, or null when it is: inside the
 * visible notification area, off the overflow chevron and outside any open overflow flyout. An
 * area or a chevron the shell does not expose as a window refuses rather than passes, because
 * Shell_NotifyIconGetRect reports the chevron's rectangle for an icon left in the overflow.
 */
internal fun notifyIconPlacementFailure(icon: RegionRect, area: NotificationArea?): String? = when {
    area == null -> "no visible ${WindowsRegionScenes.TASKBAR_CLASS} holds the icon rect $icon"
    area.overflow.any { it.bounds.intersects(icon) } ->
        "icon rect $icon lies in the overflow flyout ${area.overflow.joinToString("; ") { it.describe() }}"
    !area.taskbar.bounds.contains(icon) -> "icon rect $icon lies outside the taskbar ${area.taskbar.bounds}"
    area.chevron != null && area.chevron.intersects(icon) -> "icon rect $icon is the overflow chevron ${area.chevron}"
    area.visible == null -> "the visible notification area was not located: ${area.source}"
    !area.visible.contains(icon) -> "icon rect $icon lies outside the visible notification area ${area.visible} (${area.source})"
    area.chevron == null && !area.excludesChevron ->
        "the overflow chevron was not located, so icon rect $icon in ${area.source} ${area.visible} cannot be told apart from it"
    else -> null
}

/**
 * Waits for the notification icon's own rectangle: inside the taskbar, of icon size and equal on
 * two consecutive reads. The clock and other icons are outside this rectangle by construction.
 */
internal fun awaitIconRect(
    sceneId: String,
    maxPolls: Int,
    taskbar: RegionRect,
    read: () -> RegionRect?,
    pause: () -> Unit,
): Pair<RegionRect, Int> {
    require(maxPolls >= 2)
    var previous: RegionRect? = null
    var last: RegionRect? = null
    for (poll in 1..maxPolls) {
        val current = read()
        last = current
        val usable = current != null && taskbar.contains(current) &&
            current.width in 8..96 && current.height in 8..96
        if (usable && current == previous) return current!! to poll
        previous = if (usable) current else null
        if (poll < maxPolls) pause()
    }
    refuseRegion(
        sceneId,
        RegionCaptureRefusal.TRAY_ICON_UNAVAILABLE,
        "notification icon rectangle ${last ?: "unavailable"} was not a stable icon inside the taskbar $taskbar " +
            "after $maxPolls reads",
    )
}

/** Leftover foreign dialogs are closed best effort; the occlusion guard decides whether they matter. */
internal fun dismissForeignResidue(
    maxAttempts: Int,
    residue: () -> List<String>,
    dismiss: () -> Unit,
    pause: () -> Unit,
): List<String> {
    var clearCensuses = 0
    var remaining = residue()
    for (attempt in 1..maxAttempts) {
        if (remaining.isEmpty()) {
            clearCensuses++
            if (clearCensuses >= 2) return emptyList()
        } else {
            clearCensuses = 0
            dismiss()
        }
        pause()
        remaining = residue()
    }
    return remaining
}

/** One applied session setting and how to restore it. */
internal class AppliedSessionSetting(
    val name: String,
    val original: String,
    val capture: String,
    val restore: () -> Unit,
)

internal fun interface SessionSetting {
    fun apply(): AppliedSessionSetting
}

/** Applies [capture] when it differs, verifies it by reading it back, and restores the original. */
internal fun <T> sessionSetting(name: String, capture: T, read: () -> T, write: (T) -> Unit): SessionSetting =
    SessionSetting {
        val original = read()
        if (original != capture) write(capture)
        val applied = read()
        check(applied == capture) { "$name reads $applied after setting $capture" }
        AppliedSessionSetting(name, original.toString(), capture.toString()) {
            if (original != capture) write(original)
        }
    }

/** Capture-session settings; applied in order and restored in reverse order on close. */
internal class CaptureSessionSettings private constructor(
    private val applied: List<AppliedSessionSetting>,
) : AutoCloseable {
    fun json(): JsonObject = buildJsonObject {
        applied.forEach { setting ->
            put(setting.name, buildJsonObject {
                put("original", setting.original)
                put("capture", setting.capture)
            })
        }
    }

    override fun close() {
        val failure = restoreAll(applied)
        if (failure != null) throw failure
    }

    companion object {
        fun applyAll(settings: List<Pair<String, SessionSetting>>): CaptureSessionSettings {
            val applied = mutableListOf<AppliedSessionSetting>()
            for ((name, setting) in settings) {
                try {
                    applied += setting.apply()
                } catch (error: Exception) {
                    val refused = RegionCaptureRefusedException(
                        "capture-session",
                        RegionCaptureRefusal.SESSION_SETTING_FAILED,
                        "$name: ${error.message}",
                    )
                    refused.addSuppressed(error)
                    restoreAll(applied)?.let(refused::addSuppressed)
                    throw refused
                }
            }
            return CaptureSessionSettings(applied)
        }

        private fun restoreAll(applied: List<AppliedSessionSetting>): IllegalStateException? {
            val failures = applied.asReversed().mapNotNull { setting ->
                runCatching(setting.restore).exceptionOrNull()?.let { setting.name to it }
            }
            if (failures.isEmpty()) return null
            return IllegalStateException(
                "capture-session settings were not restored: " + failures.joinToString { (name, error) -> "$name (${error.message})" },
            ).apply { failures.forEach { addSuppressed(it.second) } }
        }
    }
}

/** One captured part of a scene: its native identity, screen rectangle and image offset. */
internal data class RegionPart(
    val role: String,
    val target: JsonObject,
    val rect: RegionRect,
    val offset: PartOffset,
    val placement: JsonObject,
)

internal fun regionImageName(sceneId: String): String = "$sceneId.png"
internal fun regionFrameName(sceneId: String): String = "$sceneId.frame.png"
internal fun regionRecordName(sceneId: String): String = "$sceneId.region.json"

/** Region provenance, validated by scripts/visual_region.py and embedded by capture stamping. */
internal fun regionRecord(
    platform: String,
    sceneId: String,
    imageWidth: Int,
    imageHeight: Int,
    screen: RegionRect,
    workArea: RegionRect,
    parts: List<RegionPart>,
    stableAttempts: Int,
    maxAttempts: Int,
    intervalMillis: Long,
    occlusion: JsonObject,
    readiness: JsonObject,
    cursor: Pair<Int, Int>,
    foreground: JsonObject,
    session: JsonObject,
): JsonObject = buildJsonObject {
    put("schema_version", REGION_RECORD_SCHEMA)
    put("platform", platform)
    put("scene", sceneId)
    put("image", regionImageName(sceneId))
    put("image_size", sizeJson(imageWidth, imageHeight))
    put("frame", regionFrameName(sceneId))
    put("frame_size", sizeJson(screen.width, screen.height))
    put("screen", screen.json())
    put("work_area", workArea.json())
    put("fill_rgb", buildJsonArray {
        add(JsonPrimitive(REGION_FILL_RGB shr 16 and 0xFF))
        add(JsonPrimitive(REGION_FILL_RGB shr 8 and 0xFF))
        add(JsonPrimitive(REGION_FILL_RGB and 0xFF))
    })
    put("parts", JsonArray(parts.map { part ->
        buildJsonObject {
            put("role", part.role)
            put("target", part.target)
            put("rect", part.rect.json())
            put("offset", part.offset.json())
            put("placement", part.placement)
        }
    }))
    put("stable_frame", buildJsonObject {
        put("attempts", stableAttempts)
        put("max_attempts", maxAttempts)
        put("interval_ms", intervalMillis)
    })
    put("occlusion", occlusion)
    put("readiness", readiness)
    put("cursor", sizeJson(cursor.first, cursor.second))
    put("foreground", foreground)
    put("session", session)
}

private fun sizeJson(first: Int, second: Int): JsonArray = JsonArray(listOf(JsonPrimitive(first), JsonPrimitive(second)))

internal fun occlusionJson(checks: List<OcclusionCheck>): JsonObject = buildJsonObject {
    put("phases", JsonArray(listOf(JsonPrimitive("before"), JsonPrimitive("during"), JsonPrimitive("after"))))
    put("checks", JsonArray(checks.map { check ->
        buildJsonObject {
            put("label", check.label)
            put("region", check.region.json())
            put("reference", hexHandle(check.referenceHandle))
            put("occluders", JsonArray(emptyList<JsonElement>()))
        }
    }))
}

/** Canonical Windows region-capture policy for each OS-owned scene. */
internal object WindowsRegionScenes {
    /** The application's own window, frame included, with its visible frame at a fixed size. */
    val windowFrame = CanonicalPlacement(140, 16, 1000, 720)

    /** Common file dialogs are resizable; a fixed size removes any remembered dialog size. */
    val fileDialog = CanonicalPlacement(160, 60, 640, 460)

    /** The MSI wizard is a fixed-size dialog: it is moved, never resized. */
    val installerWizard = CanonicalPlacement(160, 60)

    /** The tray popup sizes itself to its rows: it is moved, never resized. */
    val trayMenu = CanonicalPlacement(320, 160)

    /** Opaque capture backdrop beneath every window part: borders and translucent pixels blend with it. */
    const val BACKDROP_MARGIN = 16
    const val BACKDROP_RGB = 0x404040

    /** The common file dialog's Open or Save button (IDOK) and its Cancel button (IDCANCEL). */
    val fileDialogControls = listOf(
        ControlRule("ok-button", "Button", controlId = 1),
        ControlRule("cancel-button", "Button", controlId = 2),
    )

    /** WixUI's welcome page offers Next and Cancel; MSI assigns no fixed control IDs. */
    val installerWizardControls = listOf(
        ControlRule("next-button", "Button", caption = "Next"),
        ControlRule("cancel-button", "Button", caption = "Cancel"),
    )

    /** Readiness each part role must show before its region is captured and again before it is published. */
    fun readiness(role: String): PartReadiness = when (role) {
        "file-dialog" -> PartReadiness(controls = fileDialogControls)
        "installer-wizard" -> PartReadiness(controls = installerWizardControls)
        // The icon's window is the taskbar: its thread must answer, but its client area is the whole bar.
        "tray-icon" -> PartReadiness(clientPainted = false, notificationIcon = true)
        else -> PartReadiness()
    }

    /** WixUI titles every wizard page "[ProductName] Setup". */
    const val INSTALLER_TITLE_SUFFIX = " Setup"
    const val FILE_DIALOG_CLASS = "#32770"
    const val AWT_TRAY_MESSAGE_WINDOW_CLASS = "SunAwtTrayIcon"
    const val TASKBAR_CLASS = "Shell_TrayWnd"

    /** HKCU key whose entries Windows 11 keeps per notification icon, with IsPromoted. */
    const val NOTIFY_ICON_SETTINGS = "Control Panel\\NotifyIconSettings"

    /** Overflow flyouts of the Windows 10 and the Windows 11 notification area. */
    val NOTIFY_ICON_OVERFLOW_CLASSES = setOf("NotifyIconOverflowWindow", "TopLevelWindowForOverflowXamlIsland")

    fun isRegionCaptured(sceneId: String): Boolean = sceneId.startsWith("windows-")
}
