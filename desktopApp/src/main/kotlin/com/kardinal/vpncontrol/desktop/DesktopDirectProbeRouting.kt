package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption

data class DesktopDirectProbeRouting(
    val processNames: List<String> = emptyList(),
    val processPaths: List<String> = emptyList(),
) {
    companion object {
        @Suppress("UNUSED_PARAMETER")
        fun forValidationDirectory(
            validationDirectory: Path,
            currentProcessCommand: String? = ProcessHandle.current().info().command().orElse(null),
            osName: String = System.getProperty("os.name"),
        ): DesktopDirectProbeRouting {
            val probePath = probeSingBoxExecutable(validationDirectory, osName)
                .toAbsolutePath()
                .normalize()
                .toString()
            return DesktopDirectProbeRouting(
                processNames = defaultProcessNames(),
                processPaths = listOf(probePath),
            )
        }

        fun probeSingBoxExecutable(
            validationDirectory: Path,
            osName: String = System.getProperty("os.name"),
        ): Path {
            val suffix = if (osName.lowercase().contains("windows")) ".exe" else ""
            return validationDirectory.resolve("$PROBE_SING_BOX_BASENAME$suffix")
        }

        fun defaultProcessNames(): List<String> {
            return listOf(
                PROBE_SING_BOX_BASENAME,
                "$PROBE_SING_BOX_BASENAME.exe",
            )
        }

        const val PROBE_SING_BOX_BASENAME = "vpn-control-probe-sing-box"
    }
}

internal fun prepareDirectProbeSingBoxExecutable(
    source: Path,
    validationDirectory: Path,
    osName: String = System.getProperty("os.name"),
): Path {
    val target = DesktopDirectProbeRouting.probeSingBoxExecutable(validationDirectory, osName)
        .toAbsolutePath()
        .normalize()
    val normalizedSource = source.toAbsolutePath().normalize()
    if (normalizedSource == target) {
        return target
    }

    Files.createDirectories(target.parent)
    if (shouldRefreshProbeBinary(source = normalizedSource, target = target)) {
        runCatching {
            Files.copy(normalizedSource, target, StandardCopyOption.REPLACE_EXISTING)
        }.getOrElse {
            if (!Files.isRegularFile(target)) {
                throw it
            }
        }
    }
    if (!osName.lowercase().contains("windows")) {
        target.toFile().setExecutable(true, true)
    }
    return target
}

private fun shouldRefreshProbeBinary(source: Path, target: Path): Boolean {
    if (!Files.isRegularFile(target)) {
        return true
    }
    return runCatching {
        Files.size(source) != Files.size(target) ||
            Files.getLastModifiedTime(source) > Files.getLastModifiedTime(target)
    }.getOrDefault(true)
}
