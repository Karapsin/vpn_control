package com.kardinal.vpncontrol.shared.ui

import com.kardinal.vpncontrol.model.AppLanguage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Catalog copy that the visual review of f31ab987 found wrong on screen.
 *
 * STATE-005: saving a mode change while connected keeps the live runtime and leaves a restart
 * pending. `DesktopPendingConnectionCliTest.liveModeSaveKeepsTheSessionAndTheWarningSaysSo`
 * pins this text to that behavior; this class keeps every catalog on the corrected meaning.
 */
class CatalogCopyRegressionTest {
    @Test
    fun modeChangeWarningSaysTheSessionContinuesUntilARestart() {
        val warning = AppStrings(AppLanguage.ENGLISH).get(UiText.APP_MODE_DESKTOP_CHANGE_WARNING)
        assertFalse(warning.contains("stops the current session"), warning)
        assertTrue(warning.contains("does not stop the current session"), warning)
        assertTrue(warning.contains("Restart the connection"), warning)
    }

    @Test
    fun noCatalogKeepsItsRetiredModeChangeWarning() {
        assertEquals(
            generatedUiTextTranslations.keys.map(AppLanguage::code).toSet(),
            retiredModeChangeWarnings.keys,
            "Every catalog needs its retired sentence here",
        )
        val stale = generatedUiTextTranslations.filter { (language, texts) ->
            texts[UiText.APP_MODE_DESKTOP_CHANGE_WARNING] == retiredModeChangeWarnings[language.code]
        }.keys.map(AppLanguage::code)
        assertTrue(stale.isEmpty(), "Catalogs still say that changing mode stops the session: $stale")
    }

    @Test
    fun noCatalogContainsTheDirectDomainExampleTypo() {
        val typo = "some_stie"
        val ui = generatedUiTextTranslations.flatMap { (language, texts) ->
            texts.filterValues { typo in it }.keys.map { key -> "${language.code}.$key" }
        }
        val status = generatedStatusTranslations.filterValues { typo in it.toString() }.keys.map { "${it.code} status" }
        assertTrue((ui + status).isEmpty(), "Catalog entries with the '$typo' typo: ${ui + status}")
        assertTrue(
            AppStrings(AppLanguage.ENGLISH).get(UiText.BYPASS_DOMAINS_DESCRIPTION).endsWith("some_site.com"),
            AppStrings(AppLanguage.ENGLISH).get(UiText.BYPASS_DOMAINS_DESCRIPTION),
        )
    }
}

/** The sentence each catalog showed until 529cc610: "Changing mode while connected stops the current session first." */
private val retiredModeChangeWarnings: Map<String, String> = mapOf(
    "ar" to "تغيير الوضع أثناء الاتصال يوقف الجلسة الحالية أولًا.",
    "az" to "Qoşulu olarkən rejimi dəyişmək əvvəlcə cari sessiyanı dayandırır.",
    "be" to "Змена рэжыму пры актыўным падключэнні спачатку спыніць бягучы сеанс.",
    "bg" to "Промяната на режима при активна връзка първо спира текущата сесия.",
    "bn" to "সংযুক্ত থাকা অবস্থায় মোড বদলালে বর্তমান সেশন আগে বন্ধ হবে।",
    "bs" to "Promjena načina dok je veza aktivna prvo zaustavlja trenutnu sesiju.",
    "cs" to "Změna režimu během připojení nejprve zastaví aktuální relaci.",
    "da" to "Hvis tilstanden ændres, mens der er forbindelse, stoppes den aktuelle session først.",
    "de" to "Eine Modusänderung bei aktiver Verbindung stoppt zuerst die aktuelle Sitzung.",
    "el" to "Η αλλαγή λειτουργίας ενώ υπάρχει σύνδεση σταματά πρώτα την τρέχουσα συνεδρία.",
    "en" to "Changing mode while connected stops the current session first.",
    "es" to "Cambiar el modo mientras está conectado detiene primero la sesión actual.",
    "et" to "Režiimi muutmine ühenduse ajal peatab esmalt praeguse seansi.",
    "fa" to "تغییر حالت در زمان اتصال، ابتدا نشست فعلی را متوقف می‌کند.",
    "fi" to "Tilan vaihtaminen yhteyden aikana pysäyttää ensin nykyisen istunnon.",
    "fil" to "Kapag binago ang mode habang nakakonekta, ihihinto muna ang kasalukuyang session.",
    "fr" to "Changer de mode pendant une connexion arrête d'abord la session actuelle.",
    "he" to "שינוי מצב בזמן חיבור עוצר תחילה את ההפעלה הנוכחית.",
    "hi" to "कनेक्शन चालू रहते मोड बदलने पर पहले वर्तमान सत्र रुकता है।",
    "hr" to "Promjena načina dok je veza aktivna prvo zaustavlja trenutnu sesiju.",
    "hu" to "Ha kapcsolódás közben módot váltasz, az aktuális munkamenet előbb leáll.",
    "hy" to "Միացված վիճակում ռեժիմը փոխելիս ընթացիկ սեսիան նախ կանգնեցվում է։",
    "id" to "Mengubah mode saat tersambung akan menghentikan sesi saat ini lebih dulu.",
    "it" to "Cambiare modalità durante la connessione arresta prima la sessione corrente.",
    "ja" to "接続中にモードを変更すると、現在のセッションを先に停止します。",
    "ka" to "კავშირისას რეჟიმის შეცვლა ჯერ მიმდინარე სესიას აჩერებს.",
    "kk" to "Қосылып тұрған кезде режимді өзгерту алдымен ағымдағы сеансты тоқтатады.",
    "km" to "ការប្តូររបៀបនៅពេលកំពុងភ្ជាប់ នឹងបញ្ឈប់សម័យបច្ចុប្បន្នជាមុន។",
    "ko" to "연결 중 모드를 변경하면 현재 세션이 먼저 중지됩니다.",
    "ku" to "Guhertina modê dema girêdayî yî pêşî danişîna niha rawestîne.",
    "ky" to "Туташып турганда режимди өзгөртүү адегенде учурдагы сессияны токтотот.",
    "lo" to "ການປ່ຽນໂໝດຂະນະເຊື່ອມຕໍ່ຢູ່ຈະຢຸດເຊດຊັນປັດຈຸບັນກ່ອນ.",
    "lt" to "Keičiant režimą aktyvaus ryšio metu pirmiausia sustabdomas dabartinis seansas.",
    "lv" to "Mainot režīmu aktīva savienojuma laikā, vispirms tiek apturēta pašreizējā sesija.",
    "mk" to "Промената на режимот додека сте поврзани прво ја запира тековната сесија.",
    "mr" to "कनेक्ट असताना मोड बदलल्यास आधी चालू सेशन थांबवले जाते.",
    "ms" to "Menukar mod semasa bersambung akan menghentikan sesi semasa terlebih dahulu.",
    "my" to "ချိတ်ဆက်ထားချိန်တွင် မုဒ်ပြောင်းပါက လက်ရှိ session ကို အရင် ရပ်ပါမည်။",
    "nb" to "Hvis du endrer modus mens du er tilkoblet, stoppes gjeldende økt først.",
    "ne" to "जडान भएको बेला मोड परिवर्तन गर्दा पहिले हालको सत्र रोकिन्छ।",
    "nl" to "Als u de modus wijzigt terwijl er verbinding is, wordt de huidige sessie eerst gestopt.",
    "orv" to "Смена режима при активномъ подключении сначала остановитъ текущую сессию.",
    "pa" to "ਕਨੈਕਟ ਹੋਣ ਦੌਰਾਨ ਮੋਡ ਬਦਲਣ ਨਾਲ ਪਹਿਲਾਂ ਮੌਜੂਦਾ ਸੈਸ਼ਨ ਰੁਕ ਜਾਂਦਾ ਹੈ।",
    "pl" to "Zmiana trybu podczas połączenia najpierw zatrzyma bieżącą sesję.",
    "ps" to "د نښلونې پر مهال د حالت بدلول لومړی اوسنۍ ناسته دروي.",
    "pt" to "Alterar o modo enquanto conectado para primeiro a sessão atual.",
    "ro" to "Schimbarea modului în timp ce ești conectat oprește mai întâi sesiunea curentă.",
    "ru" to "Смена режима при активном подключении сначала остановит текущую сессию.",
    "si" to "සම්බන්ධ වී සිටියදී ප්‍රකාරය වෙනස් කිරීම වත්මන් සැසිය මුලින් නවත්වයි.",
    "sk" to "Zmena režimu počas pripojenia najprv zastaví aktuálnu reláciu.",
    "sl" to "Spreminjanje načina med povezavo najprej ustavi trenutno sejo.",
    "sov" to "Смена режима при активном подключении сначала остановит текущую смену.",
    "sq" to "Ndryshimi i modalitetit gjatë lidhjes ndalon fillimisht sesionin aktual.",
    "sr" to "Промена режима док је веза активна прво зауставља тренутну сесију.",
    "sv" to "Om läget ändras medan du är ansluten stoppas den aktuella sessionen först.",
    "ta" to "இணைந்திருக்கும் போது முறையை மாற்றினால் தற்போதைய அமர்வு முதலில் நிறுத்தப்படும்.",
    "te" to "కనెక్ట్ అయి ఉన్నప్పుడు మోడ్ మార్చితే ముందుగా ప్రస్తుత సెషన్ ఆగుతుంది.",
    "tg" to "Иваз кардани реҷа ҳангоми пайвастӣ аввал сеанси ҷориро қатъ мекунад.",
    "th" to "การเปลี่ยนโหมดขณะเชื่อมต่อจะหยุดเซสชันปัจจุบันก่อน",
    "tk" to "Birikdirilen wagty tertibi üýtgetmek ilki häzirki sessiýany duruzýar.",
    "tr" to "Bağlıyken modu değiştirmek önce geçerli oturumu durdurur.",
    "uk" to "Зміна режиму під час підключення спершу зупинить поточний сеанс.",
    "ur" to "کنیکٹ ہونے کے دوران موڈ بدلنے سے پہلے موجودہ سیشن بند ہو جاتا ہے۔",
    "uz" to "Ulangan paytda rejimni oʻzgartirish avval joriy seansni toʻxtatadi.",
    "vi" to "Đổi chế độ khi đang kết nối sẽ dừng phiên hiện tại trước.",
    "zh" to "连接时更改模式会先停止当前会话。",
)
