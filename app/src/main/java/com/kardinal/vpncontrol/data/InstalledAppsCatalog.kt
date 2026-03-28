package com.kardinal.vpncontrol.data

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.kardinal.vpncontrol.model.InstalledApp
import java.util.Locale
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class InstalledAppsCatalog(
    private val context: Context,
) {
    suspend fun load(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val packageManager = context.packageManager
        val visibleApps = linkedMapOf<String, InstalledApp>()

        launcherApps(packageManager).forEach { app ->
            visibleApps[app.packageName] = app
        }

        installedApplications(packageManager)
            .filter { !it.isSystemApp }
            .forEach { app ->
                visibleApps.putIfAbsent(app.packageName, app)
            }

        visibleApps.values
            .sortedWith(
                compareBy<InstalledApp>(
                    { it.isSystemApp },
                    { it.label.lowercase(Locale.ROOT) },
                    { it.packageName },
                ),
            )
    }

    private fun launcherApps(packageManager: PackageManager): List<InstalledApp> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }

        val resolveInfos = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.queryIntentActivities(
                launcherIntent,
                PackageManager.ResolveInfoFlags.of(0),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.queryIntentActivities(launcherIntent, 0)
        }

        return resolveInfos
            .asSequence()
            .mapNotNull { info ->
                val appInfo = info.activityInfo?.applicationInfo ?: return@mapNotNull null
                val packageName = appInfo.packageName
                if (packageName == context.packageName) return@mapNotNull null

                InstalledApp(
                    packageName = packageName,
                    label = info.loadLabel(packageManager)?.toString()?.ifBlank { packageName } ?: packageName,
                    isSystemApp = isSystemApp(appInfo),
                )
            }
            .distinctBy { it.packageName }
            .toList()
    }

    private fun installedApplications(packageManager: PackageManager): List<InstalledApp> {
        val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(
                PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
        }

        return applications
            .asSequence()
            .filter { it.packageName != context.packageName }
            .map { app ->
                InstalledApp(
                    packageName = app.packageName,
                    label = app.loadLabel(packageManager)?.toString()?.ifBlank { app.packageName } ?: app.packageName,
                    isSystemApp = isSystemApp(app),
                )
            }
            .toList()
    }

    private fun isSystemApp(app: ApplicationInfo): Boolean {
        val flags = app.flags
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
            flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }
}
