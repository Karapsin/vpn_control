import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import groovy.json.JsonSlurper

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.multiplatform")
}

val generatedLanguageDir = layout.buildDirectory.dir("generated/source/languages/commonMain/kotlin")
val languageManifest = layout.projectDirectory.file("src/commonMain/resources/languages.json")

val generateAppLanguages by tasks.registering {
    val outputDir = generatedLanguageDir
    inputs.file(languageManifest)
    outputs.dir(outputDir)

    doLast {
        val parser = JsonSlurper()
        val entries = parser.parse(languageManifest.asFile) as? List<*>
            ?: error("Expected a JSON array in ${languageManifest.asFile}")
        require(entries.isNotEmpty()) {
            "Language manifest must contain at least SYSTEM and ENGLISH"
        }

        val languages = entries.mapIndexed { index, raw ->
            val item = raw as? Map<*, *>
                ?: error("Language entry $index must be an object")
            val enumName = item["enumName"] as? String
                ?: error("Language entry $index is missing enumName")
            val code = item["code"] as? String
                ?: error("Language entry $index is missing code")
            val nativeName = item["nativeName"] as? String
                ?: error("Language entry $index is missing nativeName")
            require(enumName.matches(Regex("[A-Z][A-Z0-9_]*"))) {
                "Invalid AppLanguage enumName '$enumName'"
            }
            require(code.isEmpty() || code.matches(Regex("[a-z]{2,3}"))) {
                "Invalid AppLanguage code '$code' for $enumName"
            }
            Triple(enumName, code, nativeName)
        }

        require(languages.first().first == "SYSTEM" && languages.first().second.isEmpty()) {
            "First language entry must be SYSTEM with an empty code"
        }
        require(languages.any { it.first == "ENGLISH" && it.second == "en" }) {
            "Language manifest must include ENGLISH with code en"
        }
        require(languages.map { it.first }.distinct().size == languages.size) {
            "Language manifest contains duplicate enumName values"
        }
        require(languages.map { it.second }.distinct().size == languages.size) {
            "Language manifest contains duplicate code values"
        }

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

        val targetFile = outputDir.get().file(
            "com/kardinal/vpncontrol/model/AppLanguage.kt",
        ).asFile
        targetFile.parentFile.mkdirs()
        targetFile.writeText(
            buildString {
                appendLine("package com.kardinal.vpncontrol.model")
                appendLine()
                appendLine("// Generated from shared/model/src/commonMain/resources/languages.json.")
                appendLine("enum class AppLanguage(")
                appendLine("    val code: String,")
                appendLine("    val nativeName: String,")
                appendLine(") {")
                languages.forEachIndexed { index, language ->
                    val suffix = if (index == languages.lastIndex) ";" else ","
                    appendLine(
                        "    ${language.first}(code = ${language.second.kotlinLiteral()}, " +
                            "nativeName = ${language.third.kotlinLiteral()})$suffix",
                    )
                }
                appendLine()
                appendLine("    companion object {")
                appendLine("        val selectable: List<AppLanguage> = entries")
                appendLine()
                appendLine("        fun fromStoredName(raw: String?): AppLanguage {")
                appendLine("            val normalized = raw.orEmpty().trim()")
                appendLine("            return entries.firstOrNull { it.name.equals(normalized, ignoreCase = true) } ?: SYSTEM")
                appendLine("        }")
                appendLine()
                appendLine("        fun fromSystemLanguageCode(raw: String?): AppLanguage {")
                appendLine("            val normalized = raw.orEmpty().substringBefore('-').substringBefore('_').lowercase()")
                appendLine("            return entries.firstOrNull { it != SYSTEM && it.code == normalized } ?: ENGLISH")
                appendLine("        }")
                appendLine("    }")
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
            kotlin.srcDir(generatedLanguageDir)
        }
        commonMain.dependencies {
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
    }
}

tasks.matching { task ->
    task.name.startsWith("compile") && task.name.contains("Kotlin")
}.configureEach {
    dependsOn(generateAppLanguages)
}

android {
    namespace = "com.kardinal.vpncontrol.shared.model"
    compileSdk = 35
    buildToolsVersion = "35.0.0"

    defaultConfig {
        minSdk = 29
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
