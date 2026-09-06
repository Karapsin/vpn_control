package com.kardinal.vpncontrol

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.os.Bundle
import android.os.PowerManager
import java.util.Collections
import java.util.IdentityHashMap

/** Conservative positive evidence, never shell/permission inference. */
internal class AndroidForegroundState(private val application: Application) : Application.ActivityLifecycleCallbacks {
    private val resumed = Collections.newSetFromMap(IdentityHashMap<Activity, Boolean>())
    init { application.registerActivityLifecycleCallbacks(this) }
    @Synchronized fun ready(): Boolean = resumed.isNotEmpty() &&
        !application.getSystemService(KeyguardManager::class.java).isDeviceLocked &&
        application.getSystemService(PowerManager::class.java).isInteractive
    @Synchronized override fun onActivityResumed(activity: Activity) { resumed.add(activity) }
    @Synchronized override fun onActivityPaused(activity: Activity) { resumed.remove(activity) }
    @Synchronized override fun onActivityDestroyed(activity: Activity) { resumed.remove(activity) }
    override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
    override fun onActivityStarted(activity: Activity) = Unit
    override fun onActivityStopped(activity: Activity) = Unit
    override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
}
