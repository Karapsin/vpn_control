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
val i18nStatusCatalogDir = layout.projectDirectory.dir("src/commonMain/resources/i18n-status")

val generateI18nCatalog by tasks.registering {
    val outputDir = generatedI18nCatalogDir
    inputs.dir(i18nCatalogDir)
    inputs.dir(i18nStatusCatalogDir)
    outputs.dir(outputDir)

    doLast {
        val jsonFiles = i18nCatalogDir.asFile
            .listFiles { file -> file.isFile && file.extension == "json" }
            ?.sortedBy { it.name }
            .orEmpty()
        require(jsonFiles.isNotEmpty()) {
            "No i18n JSON files found in ${i18nCatalogDir.asFile}"
        }
        val statusJsonFiles = i18nStatusCatalogDir.asFile
            .listFiles { file -> file.isFile && file.extension == "json" }
            ?.sortedBy { it.name }
            .orEmpty()
        require(statusJsonFiles.isNotEmpty()) {
            "No status i18n JSON files found in ${i18nStatusCatalogDir.asFile}"
        }
        require(jsonFiles.map { it.nameWithoutExtension }.toSet() == statusJsonFiles.map { it.nameWithoutExtension }.toSet()) {
            "UI and status i18n catalogs must use the same language codes"
        }

        val parser = JsonSlurper()
        val packageDir = outputDir.get().dir("com/kardinal/vpncontrol/shared/ui").asFile
        packageDir.deleteRecursively()
        packageDir.mkdirs()

        fun generatedFile(name: String): java.io.File = packageDir.resolve(name)

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

        fun parseObject(file: java.io.File): Map<*, *> {
            return parser.parse(file) as? Map<*, *>
                ?: error("Expected a JSON object in ${file.path}")
        }

        fun Map<*, *>.objectValue(key: String, file: java.io.File): Map<*, *> {
            return this[key] as? Map<*, *>
                ?: error("Missing object '$key' in ${file.path}")
        }

        fun Map<*, *>.stringValue(key: String, file: java.io.File): String {
            return this[key] as? String
                ?: error("Missing string '$key' in ${file.path}")
        }

        fun Map<*, *>.pairsValue(key: String, file: java.io.File): List<Pair<String, String>> {
            val entries = this[key] as? List<*>
                ?: error("Missing replacement list '$key' in ${file.path}")
            return entries.mapIndexed { index, entry ->
                val map = entry as? Map<*, *>
                    ?: error("Entry $index in '$key' must be an object in ${file.path}")
                val source = map["source"] as? String
                    ?: error("Entry $index in '$key' is missing source in ${file.path}")
                val target = map["target"] as? String
                    ?: error("Entry $index in '$key' is missing target in ${file.path}")
                source to target
            }
        }

        fun Map<*, *>.stringMapValue(key: String, file: java.io.File): Map<String, String> {
            val entries = this[key] as? Map<*, *>
                ?: error("Missing string map '$key' in ${file.path}")
            return entries.map { (source, target) ->
                val sourceText = source as? String
                    ?: error("Map '$key' contains a non-string key in ${file.path}")
                val targetText = target as? String
                    ?: error("Map '$key' contains a non-string value for '$sourceText' in ${file.path}")
                sourceText to targetText
            }.toMap()
        }

        fun StringBuilder.appendPairList(entries: List<Pair<String, String>>, indent: String) {
            appendLine("listOf(")
            entries.forEach { (source, target) ->
                appendLine("$indent    ${source.kotlinLiteral()} to ${target.kotlinLiteral()},")
            }
            append("$indent)")
        }

        fun StringBuilder.appendStringMap(entries: Map<String, String>, indent: String) {
            appendLine("mapOf(")
            entries.forEach { (source, target) ->
                appendLine("$indent    ${source.kotlinLiteral()} to ${target.kotlinLiteral()},")
            }
            append("$indent)")
        }

        fun String.catalogFunctionSuffix(): String {
            return replace(Regex("[^A-Za-z0-9]"), "_")
        }

        generatedFile("GeneratedI18nTypes.kt").writeText(
            buildString {
                appendLine("package com.kardinal.vpncontrol.shared.ui")
                appendLine()
                appendLine("import com.kardinal.vpncontrol.model.AppLanguage")
                appendLine()
                appendLine("// Generated from shared/ui/src/commonMain/resources/i18n/*.json.")
                appendLine("// Generated from shared/ui/src/commonMain/resources/i18n-status/*.json.")
                appendLine("internal data class GeneratedDynamicStatusWords(")
                appendLine("    val findingSubscription: String,")
                appendLine("    val findingSaved: String,")
                appendLine("    val testingFastestCandidates: String,")
                appendLine("    val checkingLocations: String,")
                appendLine("    val testingLocationsRange: String,")
                appendLine("    val selectLocationFirst: String,")
                appendLine("    val checkingLocation: String,")
                appendLine("    val testingLocation: String,")
                appendLine("    val locationCheckCancelled: String,")
                appendLine("    val noLocationsToExport: String,")
                appendLine("    val refreshIntervalMinutes: String,")
                appendLine("    val refreshIntervalHours: String,")
                appendLine("    val refreshIntervalHoursMinutes: String,")
                appendLine("    val refreshIntervalEvery: String,")
                appendLine("    val refreshIntervalEveryHour: String,")
                appendLine(")")
                appendLine()
                appendLine("internal data class GeneratedBenchmarkWords(")
                appendLine("    val best: String,")
                appendLine("    val test: String,")
                appendLine("    val primary: String,")
                appendLine("    val secondary: String,")
                appendLine("    val tcp: String,")
                appendLine("    val millisUnit: String,")
                appendLine("    val statuses: Map<String, String>,")
                appendLine(")")
                appendLine()
                appendLine("internal data class GeneratedStatusTranslations(")
                appendLine("    val dynamic: GeneratedDynamicStatusWords,")
                appendLine("    val benchmark: GeneratedBenchmarkWords,")
                appendLine("    val structured: Map<String, String>,")
                appendLine("    val freeformReplacements: List<Pair<String, String>>,")
                appendLine("    val legacyExact: Map<String, String>,")
                appendLine("    val legacyReplacements: List<Pair<String, String>>,")
                appendLine(")")
                appendLine()
                appendLine("internal fun appLanguageForGeneratedCatalog(code: String, catalog: String): AppLanguage {")
                appendLine("    return requireNotNull(AppLanguage.entries.firstOrNull { it.code == code }) {")
                appendLine("        \"No AppLanguage entry exists for i18n catalog \$catalog\"")
                appendLine("    }")
                appendLine("}")
                appendLine()
            },
            Charsets.UTF_8,
        )

        jsonFiles.forEach { file ->
            val code = file.nameWithoutExtension
            @Suppress("UNCHECKED_CAST")
            val entries = parser.parse(file) as Map<String, Any?>
            generatedFile("GeneratedUiText_${code.catalogFunctionSuffix()}.kt").writeText(
                buildString {
                    appendLine("package com.kardinal.vpncontrol.shared.ui")
                    appendLine()
                    appendLine("internal fun uiTextTranslations_${code.catalogFunctionSuffix()}(): Map<UiText, String> = mapOf(")
                    entries.forEach { (key, value) ->
                        appendLine("    UiText.$key to ${value.toString().kotlinLiteral()},")
                    }
                    appendLine(")")
                },
                Charsets.UTF_8,
            )
        }

        statusJsonFiles.forEach { file ->
            val code = file.nameWithoutExtension
            val root = parseObject(file)
            val dynamic = root.objectValue("dynamic", file)
            val benchmark = root.objectValue("benchmark", file)
            val statuses = benchmark.stringMapValue("statuses", file)
            val structured = root.stringMapValue("structured", file)
            val freeformReplacements = root.pairsValue("freeformReplacements", file)
                .sortedByDescending { it.first.length }
            val legacyExact = root.pairsValue("legacyExact", file).toMap()
            val legacyReplacements = root.pairsValue("legacyReplacements", file)
                .sortedByDescending { it.first.length }
            generatedFile("GeneratedStatus_${code.catalogFunctionSuffix()}.kt").writeText(
                buildString {
                    appendLine("package com.kardinal.vpncontrol.shared.ui")
                    appendLine()
                    appendLine("internal fun statusTranslations_${code.catalogFunctionSuffix()}(): GeneratedStatusTranslations = GeneratedStatusTranslations(")
                    appendLine("    dynamic = GeneratedDynamicStatusWords(")
                    appendLine("        findingSubscription = ${dynamic.stringValue("findingSubscription", file).kotlinLiteral()},")
                    appendLine("        findingSaved = ${dynamic.stringValue("findingSaved", file).kotlinLiteral()},")
                    appendLine("        testingFastestCandidates = ${dynamic.stringValue("testingFastestCandidates", file).kotlinLiteral()},")
                    appendLine("        checkingLocations = ${dynamic.stringValue("checkingLocations", file).kotlinLiteral()},")
                    appendLine("        testingLocationsRange = ${dynamic.stringValue("testingLocationsRange", file).kotlinLiteral()},")
                    appendLine("        selectLocationFirst = ${dynamic.stringValue("selectLocationFirst", file).kotlinLiteral()},")
                    appendLine("        checkingLocation = ${dynamic.stringValue("checkingLocation", file).kotlinLiteral()},")
                    appendLine("        testingLocation = ${dynamic.stringValue("testingLocation", file).kotlinLiteral()},")
                    appendLine("        locationCheckCancelled = ${dynamic.stringValue("locationCheckCancelled", file).kotlinLiteral()},")
                    appendLine("        noLocationsToExport = ${dynamic.stringValue("noLocationsToExport", file).kotlinLiteral()},")
                    appendLine("        refreshIntervalMinutes = ${dynamic.stringValue("refreshIntervalMinutes", file).kotlinLiteral()},")
                    appendLine("        refreshIntervalHours = ${dynamic.stringValue("refreshIntervalHours", file).kotlinLiteral()},")
                    appendLine("        refreshIntervalHoursMinutes = ${dynamic.stringValue("refreshIntervalHoursMinutes", file).kotlinLiteral()},")
                    appendLine("        refreshIntervalEvery = ${dynamic.stringValue("refreshIntervalEvery", file).kotlinLiteral()},")
                    appendLine("        refreshIntervalEveryHour = ${dynamic.stringValue("refreshIntervalEveryHour", file).kotlinLiteral()},")
                    appendLine("    ),")
                    appendLine("    benchmark = GeneratedBenchmarkWords(")
                    appendLine("        best = ${benchmark.stringValue("best", file).kotlinLiteral()},")
                    appendLine("        test = ${benchmark.stringValue("test", file).kotlinLiteral()},")
                    appendLine("        primary = ${benchmark.stringValue("primary", file).kotlinLiteral()},")
                    appendLine("        secondary = ${benchmark.stringValue("secondary", file).kotlinLiteral()},")
                    appendLine("        tcp = ${benchmark.stringValue("tcp", file).kotlinLiteral()},")
                    appendLine("        millisUnit = ${benchmark.stringValue("millisUnit", file).kotlinLiteral()},")
                    append("        statuses = ")
                    appendStringMap(statuses, "        ")
                    appendLine(",")
                    appendLine("    ),")
                    append("    structured = ")
                    appendStringMap(structured, "    ")
                    appendLine(",")
                    append("    freeformReplacements = ")
                    appendPairList(freeformReplacements, "    ")
                    appendLine(",")
                    append("    legacyExact = ")
                    appendStringMap(legacyExact, "    ")
                    appendLine(",")
                    append("    legacyReplacements = ")
                    appendPairList(legacyReplacements, "    ")
                    appendLine(",")
                    appendLine(")")
                    appendLine()
                },
                Charsets.UTF_8,
            )
        }

        generatedFile("GeneratedI18nCatalog.kt").writeText(
            buildString {
                appendLine("package com.kardinal.vpncontrol.shared.ui")
                appendLine()
                appendLine("import com.kardinal.vpncontrol.model.AppLanguage")
                appendLine()
                appendLine("internal val generatedStatusTranslations: Map<AppLanguage, GeneratedStatusTranslations> = mapOf(")
                statusJsonFiles.forEach { file ->
                    val code = file.nameWithoutExtension
                    appendLine(
                        "    appLanguageForGeneratedCatalog(${code.kotlinLiteral()}, \"status ${code}\") " +
                            "to statusTranslations_${code.catalogFunctionSuffix()}(),",
                    )
                }
                appendLine(")")
                appendLine()
                appendLine("internal val generatedUiTextTranslations: Map<AppLanguage, Map<UiText, String>> = mapOf(")
                jsonFiles.forEach { file ->
                    val code = file.nameWithoutExtension
                    appendLine(
                        "    appLanguageForGeneratedCatalog(${code.kotlinLiteral()}, \"UI ${code}\") " +
                            "to uiTextTranslations_${code.catalogFunctionSuffix()}(),",
                    )
                }
                appendLine(")")
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
