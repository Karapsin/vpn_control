package com.kardinal.vpncontrol.desktop

import androidx.compose.ui.awt.ComposeWindow
import java.awt.FileDialog
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection
import java.nio.file.Files
import java.nio.file.Path

object DesktopTextTransfer {
    fun readClipboardText(): Result<String> = runCatching {
        val clipboard = Toolkit.getDefaultToolkit().systemClipboard
        val contents = clipboard.getContents(null)
        require(contents != null && contents.isDataFlavorSupported(DataFlavor.stringFlavor)) {
            "Clipboard does not contain text"
        }
        contents.getTransferData(DataFlavor.stringFlavor)
            ?.toString()
            ?.trim()
            ?.takeIf(String::isNotBlank)
            ?: error("Clipboard is empty")
    }

    fun writeClipboardText(text: String): Result<Unit> = runCatching {
        Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null)
    }

    fun chooseOpenFile(window: ComposeWindow, title: String): Result<Path?> = runCatching {
        val dialog = FileDialog(window, title, FileDialog.LOAD)
        dialog.isVisible = true
        val file = dialog.file ?: return@runCatching null
        val directory = dialog.directory ?: return@runCatching null
        Path.of(directory, file)
    }

    fun chooseSaveFile(
        window: ComposeWindow,
        title: String,
        suggestedFileName: String,
    ): Result<Path?> = runCatching {
        val dialog = FileDialog(window, title, FileDialog.SAVE)
        dialog.file = suggestedFileName
        dialog.isVisible = true
        val file = dialog.file ?: return@runCatching null
        val directory = dialog.directory ?: return@runCatching null
        Path.of(directory, file)
    }

    fun readTextFile(path: Path): Result<String> = runCatching {
        Files.readString(path)
    }

    fun writeTextFile(path: Path, content: String): Result<Path> = runCatching {
        path.parent?.let(Files::createDirectories)
        Files.writeString(path, content)
        path
    }

    fun openTextFile(window: ComposeWindow, title: String): Result<String?> = runCatching {
        val selected = chooseOpenFile(window, title).getOrThrow() ?: return@runCatching null
        readTextFile(selected).getOrThrow()
    }

    fun saveTextFile(
        window: ComposeWindow,
        title: String,
        suggestedFileName: String,
        content: String,
    ): Result<Path?> = runCatching {
        val selected = chooseSaveFile(window, title, suggestedFileName).getOrThrow() ?: return@runCatching null
        writeTextFile(selected, content).getOrThrow()
    }
}
