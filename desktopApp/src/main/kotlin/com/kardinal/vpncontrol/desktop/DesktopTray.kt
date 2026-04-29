package com.kardinal.vpncontrol.desktop

import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import java.awt.BasicStroke
import java.awt.Color as AwtColor
import java.awt.Cursor
import java.awt.GradientPaint
import java.awt.GraphicsEnvironment
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Image
import java.awt.MouseInfo
import java.awt.Point
import java.awt.Polygon
import java.awt.RenderingHints
import java.awt.SystemTray
import java.awt.TrayIcon
import java.awt.Window
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.awt.image.BufferedImage
import javax.imageio.ImageIO
import javax.swing.BorderFactory
import javax.swing.BoxLayout
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSeparator
import javax.swing.JWindow
import javax.swing.SwingUtilities
import javax.swing.Timer
import kotlin.math.roundToInt

@Composable
internal fun DesktopTrayIcon(
    connectionActionLabel: String,
    findBestLabel: String,
    showWindowLabel: String,
    hideWindowLabel: String,
    exitLabel: String,
    connectionActionEnabled: Boolean,
    findBestEnabled: Boolean,
    onToggleConnection: () -> Unit,
    onFindBest: () -> Unit,
    onShowWindow: () -> Unit,
    onHideWindow: () -> Unit,
    onExit: () -> Unit,
) {
    DisposableEffect(connectionActionLabel, connectionActionEnabled, findBestEnabled) {
        val popup = TrayPopupController()
        val trayIcon = installTrayIcon(
            connectionActionLabel = connectionActionLabel,
            findBestLabel = findBestLabel,
            showWindowLabel = showWindowLabel,
            hideWindowLabel = hideWindowLabel,
            exitLabel = exitLabel,
            connectionActionEnabled = connectionActionEnabled,
            findBestEnabled = findBestEnabled,
            onToggleConnection = onToggleConnection,
            onFindBest = onFindBest,
            onShowWindow = onShowWindow,
            onHideWindow = onHideWindow,
            onExit = onExit,
            popup = popup,
        )
        onDispose {
            popup.dismiss()
            trayIcon?.let { icon ->
                runCatching { SystemTray.getSystemTray().remove(icon) }
            }
        }
    }
}

internal fun isDesktopTraySupported(): Boolean {
    return runCatching {
        !GraphicsEnvironment.isHeadless() && SystemTray.isSupported()
    }.getOrDefault(false)
}

private fun installTrayIcon(
    connectionActionLabel: String,
    findBestLabel: String,
    showWindowLabel: String,
    hideWindowLabel: String,
    exitLabel: String,
    connectionActionEnabled: Boolean,
    findBestEnabled: Boolean,
    onToggleConnection: () -> Unit,
    onFindBest: () -> Unit,
    onShowWindow: () -> Unit,
    onHideWindow: () -> Unit,
    onExit: () -> Unit,
    popup: TrayPopupController,
): TrayIcon? {
    if (!isDesktopTraySupported()) return null

    fun toggleMenu() {
        val anchor = MouseInfo.getPointerInfo()?.location ?: Point(0, 0)
        popup.toggle(
            anchor = anchor,
            connectionActionLabel = connectionActionLabel,
            findBestLabel = findBestLabel,
            showWindowLabel = showWindowLabel,
            hideWindowLabel = hideWindowLabel,
            exitLabel = exitLabel,
            connectionActionEnabled = connectionActionEnabled,
            findBestEnabled = findBestEnabled,
            onToggleConnection = onToggleConnection,
            onFindBest = onFindBest,
            onShowWindow = onShowWindow,
            onHideWindow = onHideWindow,
            onExit = onExit,
        )
    }

    val tray = SystemTray.getSystemTray()
    val iconSize = maxOf(tray.trayIconSize.width, tray.trayIconSize.height, 22)
        .coerceAtMost(128)
    val trayIcon = TrayIcon(createTrayImage(iconSize), "VPN Control Desktop").apply {
        isImageAutoSize = true
        addActionListener { toggleMenu() }
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(event: MouseEvent) {
                    if (event.button == MouseEvent.BUTTON1) {
                        toggleMenu()
                    }
                }

                override fun mouseReleased(event: MouseEvent) {
                    if (event.isPopupTrigger || event.button == MouseEvent.BUTTON3) {
                        toggleMenu()
                    }
                }
            },
        )
    }

    return runCatching {
        tray.add(trayIcon)
        trayIcon
    }.getOrNull()
}

private fun createTrayImage(size: Int): Image {
    loadDesktopIconImage()?.let { return scaleDesktopIconForTray(it, size) }
    return createFallbackTrayImage(size)
}

private fun loadDesktopIconImage(): BufferedImage? {
    val classLoader = Thread.currentThread().contextClassLoader ?: ClassLoader.getSystemClassLoader()
    return listOf("tray_icon.png", "gen_icon.png")
        .firstNotNullOfOrNull { resource ->
            runCatching {
                classLoader.getResourceAsStream(resource)?.use(ImageIO::read)
            }.getOrNull()
        }
}

private fun scaleDesktopIconForTray(source: BufferedImage, size: Int): Image {
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
    val graphics = image.createGraphics()
    graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC)
    graphics.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY)
    val background = averageCornerRgb(source)
    graphics.color = AwtColor(background)
    graphics.fillRect(0, 0, size, size)
    val bounds = findIconContentBounds(source, background)
    val visualBounds = findBrightContentBounds(source) ?: bounds
    val maxDrawSize = (size * 0.82).coerceAtLeast(1.0)
    val scale = maxDrawSize / maxOf(bounds.width, bounds.height)
    val drawWidth = (bounds.width * scale).roundToInt().coerceIn(1, size)
    val drawHeight = (bounds.height * scale).roundToInt().coerceIn(1, size)
    val offsetX = (size / 2.0 - (visualBounds.centerX - bounds.x) * scale)
        .roundToInt()
        .coerceIn(0, size - drawWidth)
    val offsetY = (size / 2.0 - (visualBounds.centerY - bounds.y) * scale)
        .roundToInt()
        .coerceIn(0, size - drawHeight)
    graphics.drawImage(
        source,
        offsetX,
        offsetY,
        offsetX + drawWidth,
        offsetY + drawHeight,
        bounds.x,
        bounds.y,
        bounds.x + bounds.width,
        bounds.y + bounds.height,
        null,
    )
    graphics.dispose()
    return image
}

private data class IconContentBounds(
    val x: Int,
    val y: Int,
    val width: Int,
    val height: Int,
) {
    val centerX: Double
        get() = x + (width - 1) / 2.0
    val centerY: Double
        get() = y + (height - 1) / 2.0
}

private fun findIconContentBounds(source: BufferedImage, background: Int): IconContentBounds {
    var minX = source.width
    var minY = source.height
    var maxX = -1
    var maxY = -1
    for (y in 0 until source.height) {
        for (x in 0 until source.width) {
            if (!isCloseToBackground(source.getRGB(x, y), background)) {
                if (x < minX) minX = x
                if (y < minY) minY = y
                if (x > maxX) maxX = x
                if (y > maxY) maxY = y
            }
        }
    }
    if (maxX < minX || maxY < minY) {
        return IconContentBounds(0, 0, source.width, source.height)
    }
    val padding = maxOf(source.width, source.height) / 64
    minX = (minX - padding).coerceAtLeast(0)
    minY = (minY - padding).coerceAtLeast(0)
    maxX = (maxX + padding).coerceAtMost(source.width - 1)
    maxY = (maxY + padding).coerceAtMost(source.height - 1)
    return IconContentBounds(
        x = minX,
        y = minY,
        width = maxX - minX + 1,
        height = maxY - minY + 1,
    )
}

private fun averageCornerRgb(source: BufferedImage): Int {
    val colors = intArrayOf(
        source.getRGB(0, 0),
        source.getRGB(source.width - 1, 0),
        source.getRGB(0, source.height - 1),
        source.getRGB(source.width - 1, source.height - 1),
    )
    val red = colors.sumOf { it shr 16 and 0xff } / colors.size
    val green = colors.sumOf { it shr 8 and 0xff } / colors.size
    val blue = colors.sumOf { it and 0xff } / colors.size
    return AwtColor(red, green, blue).rgb
}

private fun findBrightContentBounds(source: BufferedImage): IconContentBounds? {
    var minX = source.width
    var minY = source.height
    var maxX = -1
    var maxY = -1
    var brightPixels = 0
    for (y in 0 until source.height) {
        for (x in 0 until source.width) {
            val rgb = source.getRGB(x, y)
            val red = rgb shr 16 and 0xff
            val green = rgb shr 8 and 0xff
            val blue = rgb and 0xff
            if (red >= 218 && green >= 218 && blue >= 218) {
                brightPixels += 1
                if (x < minX) minX = x
                if (y < minY) minY = y
                if (x > maxX) maxX = x
                if (y > maxY) maxY = y
            }
        }
    }
    if (brightPixels < source.width * source.height / 200 || maxX < minX || maxY < minY) {
        return null
    }
    return IconContentBounds(
        x = minX,
        y = minY,
        width = maxX - minX + 1,
        height = maxY - minY + 1,
    )
}

private fun isCloseToBackground(rgb: Int, background: Int): Boolean {
    val tolerance = 28
    return kotlin.math.abs((rgb shr 16 and 0xff) - (background shr 16 and 0xff)) <= tolerance &&
        kotlin.math.abs((rgb shr 8 and 0xff) - (background shr 8 and 0xff)) <= tolerance &&
        kotlin.math.abs((rgb and 0xff) - (background and 0xff)) <= tolerance
}

private fun createFallbackTrayImage(size: Int): Image {
    val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
    val graphics = image.createGraphics()
    graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
    graphics.scale(size / 64.0, size / 64.0)

    // AWT/XEmbed tray hosts may flatten transparent pixels to white/black.
    // Use a self-contained badge so the icon is portable across tray themes.
    graphics.paint = GradientPaint(
        0f,
        0f,
        AwtColor(13, 25, 56),
        64f,
        64f,
        AwtColor(16, 92, 206),
    )
    graphics.fillRect(0, 0, 64, 64)

    graphics.paint = GradientPaint(
        7f,
        8f,
        AwtColor(43, 128, 236),
        59f,
        60f,
        AwtColor(255, 128, 31),
    )
    graphics.fillOval(4, 4, 56, 56)

    graphics.paint = GradientPaint(
        11f,
        9f,
        AwtColor(17, 165, 246),
        54f,
        58f,
        AwtColor(0, 36, 142),
    )
    graphics.fillOval(8, 8, 48, 48)

    val innerShield = Polygon(
        intArrayOf(32, 45, 44, 39, 32, 25, 20, 19),
        intArrayOf(16, 23, 36, 46, 53, 46, 36, 23),
        8,
    )
    graphics.paint = GradientPaint(
        20f,
        16f,
        AwtColor(255, 255, 255),
        44f,
        53f,
        AwtColor(200, 221, 246),
    )
    graphics.fillPolygon(innerShield)

    graphics.color = AwtColor(72, 107, 171)
    graphics.stroke = BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
    graphics.drawPolygon(innerShield)

    graphics.paint = GradientPaint(
        22f,
        24f,
        AwtColor(0, 204, 238),
        43f,
        47f,
        AwtColor(0, 63, 184),
    )
    val inner = Polygon(
        intArrayOf(32, 40, 39, 36, 32, 28, 25, 24),
        intArrayOf(24, 28, 36, 42, 46, 42, 36, 28),
        8,
    )
    graphics.fillPolygon(inner)

    graphics.color = AwtColor.WHITE
    graphics.stroke = BasicStroke(5.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND)
    graphics.drawLine(24, 34, 30, 40)
    graphics.drawLine(30, 40, 42, 27)

    graphics.color = AwtColor(255, 184, 69)
    graphics.fillOval(50, 36, 4, 4)
    graphics.fillOval(47, 47, 3, 3)
    graphics.dispose()
    return image
}

private class TrayPopupController {
    private var window: JWindow? = null
    private var hideTimer: Timer? = null

    fun toggle(
        anchor: Point,
        connectionActionLabel: String,
        findBestLabel: String,
        showWindowLabel: String,
        hideWindowLabel: String,
        exitLabel: String,
        connectionActionEnabled: Boolean,
        findBestEnabled: Boolean,
        onToggleConnection: () -> Unit,
        onFindBest: () -> Unit,
        onShowWindow: () -> Unit,
        onHideWindow: () -> Unit,
        onExit: () -> Unit,
    ) {
        SwingUtilities.invokeLater {
            if (window?.isVisible == true) {
                dismissNow()
                return@invokeLater
            }
            dismissNow()
            val popup = JWindow().apply {
                name = "vpn-control-tray-menu"
                setType(Window.Type.POPUP)
                isAlwaysOnTop = true
                focusableWindowState = false
                background = AwtColor(0, 0, 0, 0)
                contentPane = TrayMenuPanel(
                    connectionActionLabel = connectionActionLabel,
                    findBestLabel = findBestLabel,
                    showWindowLabel = showWindowLabel,
                    hideWindowLabel = hideWindowLabel,
                    exitLabel = exitLabel,
                    connectionActionEnabled = connectionActionEnabled,
                    findBestEnabled = findBestEnabled,
                    onToggleConnection = {
                        dismiss()
                        onToggleConnection()
                    },
                    onFindBest = {
                        dismiss()
                        onFindBest()
                    },
                    onShowWindow = {
                        dismiss()
                        onShowWindow()
                    },
                    onHideWindow = {
                        dismiss()
                        onHideWindow()
                    },
                    onExit = {
                        dismiss()
                        onExit()
                    },
                )
            }
            popup.pack()
            val bounds = GraphicsEnvironment
                .getLocalGraphicsEnvironment()
                .defaultScreenDevice
                .defaultConfiguration
                .bounds
            val x = (anchor.x - popup.width / 2)
                .coerceIn(bounds.x + 8, bounds.x + bounds.width - popup.width - 8)
            val preferredY = anchor.y - popup.height - 22
            val y = if (preferredY >= bounds.y + 8) {
                preferredY
            } else {
                (anchor.y + 22).coerceAtMost(bounds.y + bounds.height - popup.height - 8)
            }
            popup.setLocation(x, y)
            popup.isVisible = true
            popup.toFront()
            window = popup
            scheduleAutoHide()
        }
    }

    fun dismiss() {
        if (SwingUtilities.isEventDispatchThread()) {
            dismissNow()
        } else {
            SwingUtilities.invokeLater {
                dismissNow()
            }
        }
    }

    private fun dismissNow() {
        hideTimer?.stop()
        hideTimer = null
        window?.dispose()
        window = null
    }

    private fun scheduleAutoHide() {
        hideTimer?.stop()
        hideTimer = Timer(6_000) { dismiss() }.apply {
            isRepeats = false
            start()
        }
    }
}

private class TrayMenuPanel(
    connectionActionLabel: String,
    findBestLabel: String,
    showWindowLabel: String,
    hideWindowLabel: String,
    exitLabel: String,
    connectionActionEnabled: Boolean,
    findBestEnabled: Boolean,
    onToggleConnection: () -> Unit,
    onFindBest: () -> Unit,
    onShowWindow: () -> Unit,
    onHideWindow: () -> Unit,
    onExit: () -> Unit,
) : RoundedPanel() {
    init {
        layout = BoxLayout(this, BoxLayout.Y_AXIS)
        border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        add(row(showWindowLabel, true, onShowWindow))
        add(row(hideWindowLabel, true, onHideWindow))
        add(separator())
        add(row(connectionActionLabel, connectionActionEnabled, onToggleConnection))
        add(row(findBestLabel, findBestEnabled, onFindBest))
        add(separator())
        add(row(exitLabel, true, onExit))
    }

    private fun separator(): JSeparator {
        return JSeparator().apply {
            foreground = AwtColor(80, 112, 140)
            background = AwtColor(42, 58, 76)
            border = BorderFactory.createEmptyBorder(7, 0, 7, 0)
            alignmentX = LEFT_ALIGNMENT
        }
    }

    private fun row(
        title: String,
        enabled: Boolean,
        action: () -> Unit,
    ): JPanel {
        return TrayMenuRow(title, enabled, action).apply {
            alignmentX = LEFT_ALIGNMENT
        }
    }
}

private open class RoundedPanel : JPanel() {
    init {
        isOpaque = false
    }

    override fun paintComponent(graphics: Graphics) {
        val g = graphics.create() as Graphics2D
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g.paint = GradientPaint(
            0f,
            0f,
            AwtColor(18, 31, 45, 248),
            0f,
            height.toFloat(),
            AwtColor(7, 16, 30, 248),
        )
        g.fillRoundRect(0, 0, width - 1, height - 1, 18, 18)
        g.color = AwtColor(118, 162, 225, 130)
        g.stroke = BasicStroke(1.2f)
        g.drawRoundRect(0, 0, width - 1, height - 1, 18, 18)
        g.dispose()
        super.paintComponent(graphics)
    }
}

private class TrayMenuRow(
    title: String,
    enabled: Boolean,
    private val action: () -> Unit,
) : JPanel() {
    private var hovered = false

    init {
        isOpaque = false
        layout = BoxLayout(this, BoxLayout.X_AXIS)
        border = BorderFactory.createEmptyBorder(9, 12, 9, 12)
        preferredSize = java.awt.Dimension(176, 38)
        maximumSize = java.awt.Dimension(176, 38)
        cursor = if (enabled) Cursor.getPredefinedCursor(Cursor.HAND_CURSOR) else Cursor.getDefaultCursor()

        add(JLabel(title).apply {
            foreground = if (enabled) AwtColor.WHITE else AwtColor(122, 139, 154)
            font = font.deriveFont(java.awt.Font.BOLD, 13f)
        })

        addMouseListener(
            object : MouseAdapter() {
                override fun mouseEntered(event: MouseEvent) {
                    if (enabled) {
                        hovered = true
                        repaint()
                    }
                }

                override fun mouseExited(event: MouseEvent) {
                    hovered = false
                    repaint()
                }

                override fun mouseReleased(event: MouseEvent) {
                    if (enabled) {
                        action()
                    }
                }
            },
        )
    }

    override fun paintComponent(graphics: Graphics) {
        val g = graphics.create() as Graphics2D
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        if (hovered) {
            g.color = AwtColor(72, 123, 181, 92)
            g.fillRoundRect(0, 3, width, height - 6, 14, 14)
        }
        g.dispose()
        super.paintComponent(graphics)
    }
}
