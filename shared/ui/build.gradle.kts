import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import groovy.json.JsonSlurper

plugins {
    id("com.android.library")
    id("org.jetbrains.compose")
    id("org.jetbrains.kotlin.multiplatform")
    id("org.jetbrains.kotlin.plugin.compose")
}

val generatedI18nCatalogDir = layout.buildDirectory.dir("generated/source/i18nCatalog/commonMain/kotlin")
val i18nCatalogDir = layout.projectDirectory.dir("src/commonMain/resources/i18n")

val generateI18nCatalog by tasks.registering {
    val outputDir = generatedI18nCatalogDir
    inputs.dir(i18nCatalogDir)
    outputs.dir(outputDir)

    doLast {
        val jsonFiles = i18nCatalogDir.asFile
            .listFiles { file -> file.isFile && file.extension == "json" }
            ?.sortedBy { it.name }
            .orEmpty()
        require(jsonFiles.isNotEmpty()) {
            "No i18n JSON files found in ${i18nCatalogDir.asFile}"
        }

        val parser = JsonSlurper()
        val targetFile = outputDir.get().file(
            "com/kardinal/vpncontrol/shared/ui/GeneratedI18nCatalog.kt",
        ).asFile
        targetFile.parentFile.mkdirs()

        fun String.kotlinLiteral(): String = buildString {
            append('"')
            this@kotlinLiteral.forEach { char ->
                when (char) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '$' -> append("\\$")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(char)
                }
            }
            append('"')
        }

        targetFile.writeText(
            buildString {
                appendLine("package com.kardinal.vpncontrol.shared.ui")
                appendLine()
                appendLine("import com.kardinal.vpncontrol.model.AppLanguage")
                appendLine()
                appendLine("// Generated from shared/ui/src/commonMain/resources/i18n/*.json.")
                appendLine("internal val generatedUiTextTranslations: Map<AppLanguage, Map<UiText, String>> = buildMap {")
                jsonFiles.forEach { file ->
                    val code = file.nameWithoutExtension
                    @Suppress("UNCHECKED_CAST")
                    val entries = parser.parse(file) as Map<String, Any?>
                    appendLine("    run {")
                    appendLine("        val language = requireNotNull(AppLanguage.entries.firstOrNull { it.code == ${code.kotlinLiteral()} }) {")
                    appendLine("            \"No AppLanguage entry exists for i18n catalog ${code}\"")
                    appendLine("        }")
                    appendLine("        put(language, mapOf(")
                    entries.forEach { (key, value) ->
                        appendLine("            UiText.$key to ${value.toString().kotlinLiteral()},")
                    }
                    appendLine("        ))")
                    appendLine("    }")
                }
                appendLine("}")
            },
            Charsets.UTF_8,
        )
    }
}

kotlin {
    androidTarget {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    jvm("desktop") {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_17)
        }
    }

    sourceSets {
        commonMain {
            kotlin.srcDir(generatedI18nCatalogDir)
        }
        commonMain.dependencies {
            implementation(project(":shared:model"))
            implementation(project(":shared:core"))
            implementation(compose.runtime)
            implementation(compose.foundation)
            implementation(compose.material3)
            implementation(compose.ui)
            implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

tasks.matching { task ->
    task.name.startsWith("compile") && task.name.contains("Kotlin")
}.configureEach {
    dependsOn(generateI18nCatalog)
}

android {
    namespace = "com.kardinal.vpncontrol.shared.ui"
    compileSdk = 35
    buildToolsVersion = "35.0.0"

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}
