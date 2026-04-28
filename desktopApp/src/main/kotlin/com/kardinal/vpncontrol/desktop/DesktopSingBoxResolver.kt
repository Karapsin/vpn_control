package com.kardinal.vpncontrol.desktop

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

data class DesktopSingBoxExecutable(
    val path: Path,
    val source: String,
)

class DesktopSingBoxResolver(
    private val toolsDir: Path,
    private val classLoader: ClassLoader = DesktopSingBoxResolver::class.java.classLoader,
    private val osNameOverride: String? = null,
    private val osArchOverride: String? = null,
) {
    fun resolve(): DesktopSingBoxExecutable? {
        envOverride()?.let { return it }
        bundledExecutable()?.let { return it }
        pathExecutable()?.let { return it }
        return null
    }

    fun missingMessage(): String {
        return "sing-box is not available. Rebuild the desktop package with bundled sing-box, " +
            "set VPN_CONTROL_SING_BOX to sing-box executable path, or add sing-box to PATH."
    }

    private fun envOverride(): DesktopSingBoxExecutable? {
        val raw = System.getenv("VPN_CONTROL_SING_BOX")
            ?.trim()
            ?.trim('"')
            ?.takeIf(String::isNotBlank)
            ?: return null
        val path = Path.of(raw)
        return if (isUsableExecutable(path)) {
            DesktopSingBoxExecutable(path, "VPN_CONTROL_SING_BOX")
        } else {
            null
        }
    }

    private fun bundledExecutable(): DesktopSingBoxExecutable? {
        val resource = bundledResourcePath() ?: return null
        val bytes = classLoader.getResourceAsStream(resource)?.use { it.readBytes() } ?: return null
        Files.createDirectories(toolsDir)
        val executable = toolsDir.resolve(resource.substringAfterLast('/'))
        if (!Files.exists(executable) || Files.size(executable) != bytes.size.toLong()) {
            Files.write(
                executable,
                bytes,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            )
        }
        if (!isWindows()) {
            executable.toFile().setExecutable(true, true)
        }
        return if (isUsableExecutable(executable)) {
            DesktopSingBoxExecutable(executable, "bundled $resource")
        } else {
            null
        }
    }

    private fun pathExecutable(): DesktopSingBoxExecutable? {
        val executableNames = if (isWindows()) {
            listOf("sing-box.exe", "sing-box")
        } else {
            listOf("sing-box")
        }
        return System.getenv("PATH")
            .orEmpty()
            .split(File.pathSeparator)
            .asSequence()
            .filter(String::isNotBlank)
            .flatMap { directory -> executableNames.asSequence().map { Path.of(directory).resolve(it) } }
            .firstOrNull(::isUsableExecutable)
            ?.let { DesktopSingBoxExecutable(it, "PATH") }
    }

    private fun bundledResourcePath(): String? {
        val os = when {
            isWindows() -> "windows"
            isLinux() -> "linux"
            isMacOs() -> "darwin"
            else -> return null
        }
        val arch = when (osArch()) {
            "amd64", "x86_64" -> "amd64"
            "aarch64", "arm64" -> "arm64"
            else -> return null
        }
        val suffix = if (os == "windows") ".exe" else ""
        return "bin/$os-$arch/sing-box$suffix"
    }

    private fun isUsableExecutable(path: Path): Boolean {
        return Files.isRegularFile(path) && (isWindows() || Files.isExecutable(path))
    }

    private fun isWindows(): Boolean {
        return osName().contains("windows")
    }

    private fun isLinux(): Boolean {
        return osName().contains("linux")
    }

    private fun isMacOs(): Boolean {
        val name = osName()
        return name.contains("mac") || name.contains("darwin")
    }

    private fun osName(): String {
        return (osNameOverride ?: System.getProperty("os.name")).lowercase()
    }

    private fun osArch(): String {
        return (osArchOverride ?: System.getProperty("os.arch")).lowercase()
    }
}
