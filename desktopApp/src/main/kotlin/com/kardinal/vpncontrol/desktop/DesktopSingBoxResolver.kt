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
            else -> return null
        }
        val arch = when (System.getProperty("os.arch").lowercase()) {
            "amd64", "x86_64" -> "amd64"
            else -> return null
        }
        val suffix = if (os == "windows") ".exe" else ""
        return "bin/$os-$arch/sing-box$suffix"
    }

    private fun isUsableExecutable(path: Path): Boolean {
        return Files.isRegularFile(path) && (isWindows() || Files.isExecutable(path))
    }

    private fun isWindows(): Boolean {
        return System.getProperty("os.name").lowercase().contains("windows")
    }

    private fun isLinux(): Boolean {
        return System.getProperty("os.name").lowercase().contains("linux")
    }
}
