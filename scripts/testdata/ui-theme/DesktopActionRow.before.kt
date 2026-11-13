@Composable
private fun DesktopActionRow(
    visualScope: String,
    onImportFile: () -> Unit,
    onImportClipboard: () -> Unit,
    onExportFile: () -> Unit,
    onExportClipboard: () -> Unit,
) {
    val strings = LocalAppStrings.current
    var showImportMenu by remember { mutableStateOf(false) }
    var showExportMenu by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box {
            OutlinedButton(
                onClick = { showImportMenu = true },
                modifier = Modifier.heightIn(min = 48.dp).testTag("$visualScope-import-menu"),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.IMPORT))
            }
            DropdownMenu(
                expanded = showImportMenu,
                onDismissRequest = { showImportMenu = false },
            ) {
                DropdownMenuItem(
                    modifier = Modifier.testTag("import-file"),
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showImportMenu = false
                        onImportFile()
                    },
                )
                DropdownMenuItem(
                    modifier = Modifier.testTag("import-clipboard"),
                    text = { Text(strings.get(UiText.CLIPBOARD)) },
                    onClick = {
                        showImportMenu = false
                        onImportClipboard()
                    },
                )
            }
        }
        Box {
            OutlinedButton(
                onClick = { showExportMenu = true },
                modifier = Modifier.heightIn(min = 48.dp).testTag("$visualScope-export-menu"),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
            ) {
                Text(strings.get(UiText.EXPORT))
            }
            DropdownMenu(
                expanded = showExportMenu,
                onDismissRequest = { showExportMenu = false },
            ) {
                DropdownMenuItem(
                    modifier = Modifier.testTag("export-file"),
                    text = { Text(strings.get(UiText.FILE)) },
                    onClick = {
                        showExportMenu = false
                        onExportFile()
                    },
                )
                DropdownMenuItem(
                    modifier = Modifier.testTag("export-clipboard"),
                    text = { Text(strings.get(UiText.CLIPBOARD)) },
                    onClick = {
                        showExportMenu = false
                        onExportClipboard()
                    },
                )
            }
        }
    }
}
