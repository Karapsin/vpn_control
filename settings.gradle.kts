pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "vpn_control_android"
include(":app")
include(":shared:model")
include(":shared:core")
include(":shared:storage-api")
include(":shared:ui")
include(":desktopApp")
