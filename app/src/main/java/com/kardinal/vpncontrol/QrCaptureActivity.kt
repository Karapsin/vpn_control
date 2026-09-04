package com.kardinal.vpncontrol

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import com.journeyapps.barcodescanner.CaptureActivity
import com.journeyapps.barcodescanner.DecoratedBarcodeView

class QrCaptureActivity : CaptureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (isVisualCapture) {
            enforceVisualCaptureFullscreen()
            scheduleVisualCaptureFullscreenConvergence()
            findViewById<DecoratedBarcodeView>(R.id.zxing_barcode_scanner).visibility = View.INVISIBLE
        }
    }

    override fun onResume() {
        super.onResume()
        if (isVisualCapture) {
            enforceVisualCaptureFullscreen()
            scheduleVisualCaptureFullscreenConvergence()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && isVisualCapture) {
            enforceVisualCaptureFullscreen()
            scheduleVisualCaptureFullscreenConvergence()
        }
    }

    override fun onDestroy() {
        window.decorView.removeCallbacks(fullscreenReassertion)
        super.onDestroy()
    }

    private val isVisualCapture: Boolean
        get() = intent.getBooleanExtra(EXTRA_VISUAL_CAPTURE, false)

    private val fullscreenReassertion = Runnable {
        if (!isFinishing && !isDestroyed && isVisualCapture) enforceVisualCaptureFullscreen()
    }

    private fun scheduleVisualCaptureFullscreenConvergence() {
        window.decorView.removeCallbacks(fullscreenReassertion)
        FULLSCREEN_REASSERT_DELAYS_MILLIS.forEach { delayMillis ->
            window.decorView.postDelayed(fullscreenReassertion, delayMillis)
        }
    }

    @Suppress("DEPRECATION")
    private fun enforceVisualCaptureFullscreen() {
        // SystemUI demo-mode resets between native visual scenes can transiently restore the
        // status bar even though zxing_CaptureTheme is fullscreen. Reassert the production
        // theme's contract through both modern and legacy APIs until the window converges.
        window.addFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN)
        window.decorView.systemUiVisibility =
            window.decorView.systemUiVisibility or
            View.SYSTEM_UI_FLAG_FULLSCREEN or
            View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
            View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
            View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false)
            window.insetsController?.hide(WindowInsets.Type.statusBars())
        }
    }

    companion object {
        const val EXTRA_VISUAL_CAPTURE = "com.kardinal.vpncontrol.extra.VISUAL_CAPTURE"
        private val FULLSCREEN_REASSERT_DELAYS_MILLIS = longArrayOf(100L, 500L, 1_500L, 4_000L)
    }
}
