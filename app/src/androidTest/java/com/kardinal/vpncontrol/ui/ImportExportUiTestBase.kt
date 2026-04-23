package com.kardinal.vpncontrol.ui

import android.content.ClipboardManager
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.MainActivityTestBridge
import com.kardinal.vpncontrol.MainActivity
import com.kardinal.vpncontrol.MainViewModel
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule

abstract class ImportExportUiTestBase {
    @get:Rule
    val composeRule = createAndroidComposeRule<MainActivity>()

    protected lateinit var viewModel: MainViewModel

    @Before
    fun setUpBase() {
        viewModel = ViewModelProvider(
            composeRule.activity,
            MainViewModel.factory(composeRule.activity.applicationContext),
        )[MainViewModel::class.java]
        runOnUiThread {
            MainActivityTestBridge.clearImportOverrides()
        }
    }

    @After
    fun tearDownBase() {
        runOnUiThread {
            MainActivityTestBridge.clearImportOverrides()
        }
    }

    protected fun runOnUiThread(action: () -> Unit) {
        composeRule.activity.runOnUiThread(action)
        composeRule.waitForIdle()
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    protected fun waitForText(text: String) {
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty()
        }
    }

    protected fun clickText(text: String, index: Int = 0) {
        composeRule.onAllNodesWithText(text)[index].performClick()
    }

    protected fun clickTag(tag: String) {
        composeRule.onNodeWithTag(tag, useUnmergedTree = true).performClick()
    }

    protected fun assertTextExists(text: String) {
        assertTrue(
            "Expected text to exist: $text",
            composeRule.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty(),
        )
    }

    protected fun assertTextDoesNotExist(text: String) {
        assertTrue(
            "Expected text to be absent: $text",
            composeRule.onAllNodesWithText(text).fetchSemanticsNodes().isEmpty(),
        )
    }

    protected fun waitUntil(condition: () -> Boolean) {
        composeRule.waitUntil(timeoutMillis = 5_000, condition = condition)
    }

    protected fun readClipboardText(): String {
        val clipboardManager = composeRule.activity.getSystemService(ClipboardManager::class.java)
        return clipboardManager?.primaryClip
            ?.getItemAt(0)
            ?.coerceToText(composeRule.activity)
            ?.toString()
            .orEmpty()
    }
}
