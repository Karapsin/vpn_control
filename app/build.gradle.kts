plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun parseCanonicalVersion(value: String): List<Int> {
    val parts = value.trim().split('.').map { it.toIntOrNull() }
    require(parts.size == 3 && parts.all { it != null && it in 0..19 } && requireNotNull(parts[0]) > 0) {
        "vpnControlVersion must have three components; major is 1..19 and others are 0..19"
    }
    return parts.map { requireNotNull(it) }
}

val canonicalVersion = providers.gradleProperty("vpnControlVersion")
val canonicalVersionCode = canonicalVersion.map { version ->
    parseCanonicalVersion(version).fold(0) { value, component -> value * 20 + component }
        .times(20)
        .also { require(it > 0) { "vpnControlVersion must produce a positive build number" } }
}
val generatedVersionCode = canonicalVersionCode
val generatedVersionName = canonicalVersion
val releaseKeystorePath = providers.environmentVariable("VPN_CONTROL_ANDROID_KEYSTORE_PATH").orNull
val releaseStorePassword = providers.environmentVariable("VPN_CONTROL_ANDROID_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("VPN_CONTROL_ANDROID_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("VPN_CONTROL_ANDROID_KEY_PASSWORD").orNull
val hasReleaseSigning = listOf(
    releaseKeystorePath,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword,
).all { !it.isNullOrBlank() }

android {
    namespace = "com.kardinal.vpncontrol"
    compileSdk = 35
    buildToolsVersion = "35.0.0"
    ndkVersion = "28.2.13676358"

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    defaultConfig {
        applicationId = "com.kardinal.vpncontrol"
        minSdk = 29
        targetSdk = 35
        versionCode = generatedVersionCode.get()
        versionName = generatedVersionName.get()

        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("stableRelease") {
                storeFile = file(requireNotNull(releaseKeystorePath))
                storePassword = releaseStorePassword
                keyAlias = releaseKeyAlias
                keyPassword = releaseKeyPassword
            }
        }
    }

    buildTypes {
        debug {
            ndk {
                abiFilters += listOf("arm64-v8a", "x86_64")
            }
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            signingConfig = if (hasReleaseSigning) {
                signingConfigs.getByName("stableRelease")
            } else {
                signingConfigs.getByName("debug")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    sourceSets.getByName("androidTest").assets.srcDir(rootProject.file("visual-tests"))
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.02.00")

    implementation(project(":shared:model"))
    implementation(project(":shared:core"))
    implementation(project(":shared:storage-api"))
    implementation(project(":shared:ui"))
    implementation(files("libs/libbox.aar"))
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.navigation:navigation-compose:2.8.9")
    implementation("androidx.datastore:datastore-preferences:1.1.2")
    // Same-version runtime artifacts exposed for the compatible exact-allocation serializer.
    implementation("androidx.datastore:datastore-preferences-proto:1.1.2")
    implementation("androidx.datastore:datastore-preferences-external-protobuf:1.1.2")
    implementation("androidx.work:work-runtime-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")

    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3:1.3.1")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}

// Exercise the production JNI implementation in the ordinary fast unit tier,
// including child JVMs that enforce the Android-sized Java heap.
val nativeStringHostDirectory = layout.buildDirectory.dir("native-string-host")
val hostWindows = System.getProperty("os.name").startsWith("Windows")
val hostJniPlatform = when {
    hostWindows -> "win32"
    System.getProperty("os.name").startsWith("Mac") -> "darwin"
    else -> "linux"
}
val nativeStringCmakeBin = providers.provider { android.sdkDirectory.resolve("cmake/3.22.1/bin") }
val configureNativeStringHost by tasks.registering(Exec::class) {
    inputs.files(fileTree("src/main/cpp"), fileTree("src/test/cpp"))
    inputs.property("jniHome", System.getProperty("java.home"))
    outputs.file(nativeStringHostDirectory.map { it.file("CMakeCache.txt") })
    doFirst {
        val output = nativeStringHostDirectory.get().asFile
        val cmakeBin = nativeStringCmakeBin.get()
        commandLine(
            cmakeBin.resolve(if (hostWindows) "cmake.exe" else "cmake"),
            "-S", file("src/main/cpp"), "-B", output, "-G", "Ninja",
            "-DCMAKE_MAKE_PROGRAM=${cmakeBin.resolve(if (hostWindows) "ninja.exe" else "ninja")}",
            "-DCMAKE_BUILD_TYPE=Release",
            "-DVPN_CONTROL_JNI_INCLUDE_DIR=${System.getProperty("java.home")}/include",
            "-DVPN_CONTROL_JNI_PLATFORM_DIR=${System.getProperty("java.home")}/include/$hostJniPlatform",
            "-DVPN_CONTROL_HOST_TESTS=ON",
            "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=${output.resolve("lib")}",
            "-DCMAKE_RUNTIME_OUTPUT_DIRECTORY=${output.resolve("lib")}",
        )
    }
}
val buildNativeStringHost by tasks.registering(Exec::class) {
    dependsOn(configureNativeStringHost)
    inputs.files(fileTree("src/main/cpp"), fileTree("src/test/cpp"))
    outputs.dir(nativeStringHostDirectory.map { it.dir("lib") })
    doFirst {
        commandLine(
            nativeStringCmakeBin.get().resolve(if (hostWindows) "cmake.exe" else "cmake"),
            "--build", nativeStringHostDirectory.get().asFile,
        )
    }
}

tasks.withType<Test>().configureEach {
    dependsOn(buildNativeStringHost)
    doFirst {
        systemProperty("vpnControl.test.runtimeClasspath", classpath.asPath)
        systemProperty("java.library.path", nativeStringHostDirectory.get().dir("lib").asFile.absolutePath)
    }
}
