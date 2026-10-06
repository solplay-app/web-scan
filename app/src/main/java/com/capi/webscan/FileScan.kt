package com.capi.webscan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.time.Instant

sealed class VtFile {
    object NotFound : VtFile()
    data class Err(val msg: String) : VtFile()
    data class Found(
        val flagged: Int, val total: Int, val threatLabel: String?, val threatNames: List<String>,
        val categories: List<String>, val type: String?, val tags: List<String>,
        val detections: List<VtDetection>, val firstSeen: String?
    ) : VtFile()
}
data class PermInfo(val label: String, val level: Int, val why: String)   // level 2 = élevé, 1 = sensible
data class FileThreat(val title: String, val summary: String, val capabilities: List<String>)
data class FileReport(
    val name: String, val size: Long, val sha256: String, val pkg: String?, val perms: List<PermInfo>,
    val vt: VtFile?, val noKey: Boolean, val error: String?
) { val link: String get() = "https://www.virustotal.com/gui/file/$sha256" }

/** Recherche de l'empreinte SHA-256 sur VirusTotal (le fichier lui-même n'est JAMAIS envoyé). */
fun Net.virusTotalFile(sha: String, key: String): VtFile {
    val r = get("https://www.virustotal.com/api/v3/files/$sha", mapOf("x-apikey" to key.trim()))
        ?: return VtFile.Err("Pas de réponse de VirusTotal (réseau).")
    return when (r.status) {
        200 -> try {
            val a = JSONObject(r.body).getJSONObject("data").getJSONObject("attributes")
            val s = a.optJSONObject("last_analysis_stats")
            val mal = s?.optInt("malicious") ?: 0; val sus = s?.optInt("suspicious") ?: 0
            val total = mal + sus + (s?.optInt("harmless") ?: 0) + (s?.optInt("undetected") ?: 0)
            val dets = mutableListOf<VtDetection>()
            a.optJSONObject("last_analysis_results")?.let { res ->
                res.keys().forEach { k ->
                    val o = res.optJSONObject(k) ?: return@forEach
                    val cat = o.optString("category")
                    if (cat == "malicious" || cat == "suspicious")
                        dets.add(VtDetection(o.optString("engine_name", k), cat, o.optString("result")))
                }
            }
            fun values(arr: JSONArray?) = (0 until (arr?.length() ?: 0)).mapNotNull { arr!!.optJSONObject(it)?.optString("value") }
            val ptc = a.optJSONObject("popular_threat_classification")
            val tagsArr = a.optJSONArray("tags")
            VtFile.Found(
                flagged = mal + sus, total = total,
                threatLabel = ptc?.optString("suggested_threat_label")?.takeIf { it.isNotBlank() },
                threatNames = values(ptc?.optJSONArray("popular_threat_name")),
                categories = values(ptc?.optJSONArray("popular_threat_category")),
                type = a.optString("type_description").takeIf { it.isNotBlank() },
                tags = (0 until (tagsArr?.length() ?: 0)).map { tagsArr!!.optString(it) },
                detections = dets,
                firstSeen = if (a.has("first_submission_date")) Instant.ofEpochSecond(a.getLong("first_submission_date")).toString().take(10) else null
            )
        } catch (_: Exception) { VtFile.Err("Réponse VirusTotal illisible.") }
        404 -> VtFile.NotFound
        401, 403 -> VtFile.Err("Clé VirusTotal refusée.")
        429 -> VtFile.Err("Quota VirusTotal atteint : réessayez dans une minute.")
        else -> VtFile.Err("VirusTotal a répondu HTTP ${r.status}.")
    }
}

private val FILE_THREATS: List<Pair<List<String>, FileThreat>> = listOf(
    listOf("ransom", "ransomware", "filecoder") to FileThreat("Rançongiciel",
        "Chiffre vos fichiers puis réclame de l'argent pour les rendre.",
        listOf("Rendre photos et documents illisibles", "Afficher une demande de rançon", "Voler les données avant de les chiffrer")),
    listOf("banker", "banking", "bank") to FileThreat("Cheval de Troie bancaire",
        "Vise vos comptes bancaires et applis de paiement.",
        listOf("Superposer de faux écrans de connexion bancaire", "Lire vos SMS pour intercepter les codes de validation",
            "Utiliser l'accessibilité pour agir à votre place", "Effectuer des virements à votre insu")),
    listOf("spy", "spyware", "stalkerware", "stealer", "infostealer", "keylogger", "monitor") to FileThreat("Logiciel espion / voleur de données",
        "Surveille votre appareil et exfiltre vos informations.",
        listOf("Enregistrer frappes, messages et appels", "Voler mots de passe, cookies et portefeuilles crypto",
            "Activer micro et caméra", "Suivre votre position")),
    listOf("backdoor", "rat", "remote", "botnet") to FileThreat("Accès à distance / porte dérobée",
        "Permet à un pirate de contrôler l'appareil à distance.",
        listOf("Exécuter des commandes à votre insu", "Accéder à vos fichiers", "Enrôler l'appareil dans un botnet")),
    listOf("dropper", "downloader", "loader") to FileThreat("Dropper / téléchargeur",
        "Sert à installer discrètement d'autres logiciels malveillants.",
        listOf("Télécharger et installer d'autres malwares", "Contourner les protections en s'installant en deux temps")),
    listOf("trojan") to FileThreat("Cheval de Troie",
        "Se fait passer pour une appli ou un fichier légitime.",
        listOf("Ouvrir une porte dérobée", "Voler des données", "Télécharger d'autres malwares")),
    listOf("worm") to FileThreat("Ver",
        "Se propage tout seul vers d'autres appareils ou contacts.",
        listOf("Envoyer le malware à vos contacts", "Se copier sur le réseau ou les supports USB")),
    listOf("miner", "coinminer", "cryptominer", "xmrig") to FileThreat("Cryptomineur",
        "Utilise votre appareil pour miner de la cryptomonnaie.",
        listOf("Saturer le processeur", "Vider la batterie et faire chauffer l'appareil")),
    listOf("exploit") to FileThreat("Exploit",
        "Tente d'abuser d'une faille de sécurité.",
        listOf("Prendre le contrôle via une vulnérabilité", "Élever ses privilèges")),
    listOf("adware", "adload", "hiddenads") to FileThreat("Publicitaire (adware)",
        "Affiche des pubs intrusives et suit vos habitudes.",
        listOf("Pubs plein écran et redirections", "Collecte de données de navigation")),
    listOf("riskware", "pua", "pup", "unwanted", "hacktool") to FileThreat("Logiciel risqué / indésirable",
        "Pas forcément un virus, mais potentiellement dangereux ou abusif.",
        listOf("Comportements intrusifs", "Outil pouvant être détourné"))
)

fun matchFileThreats(f: VtFile.Found): List<FileThreat> {
    val text = (listOfNotNull(f.threatLabel) + f.threatNames + f.categories + f.detections.map { it.result }).joinToString(" ").lowercase()
    val tokens = text.split(Regex("[^a-z0-9]+")).filter { it.isNotEmpty() }
    fun has(kw: String) = tokens.any { t -> t == kw || (kw.length >= 5 && t.contains(kw)) }
    return FILE_THREATS.filter { (kws, _) -> kws.any { has(it) } }.map { it.second }.take(4)
}

private data class PDef(val key: String, val label: String, val level: Int, val why: String)
private val PERMS = listOf(
    PDef("READ_SMS", "Lire vos SMS", 2, "Peut lire vos SMS, y compris les codes de vérification."),
    PDef("RECEIVE_SMS", "Intercepter les SMS reçus", 2, "Peut capter les codes envoyés par votre banque ou vos comptes."),
    PDef("SEND_SMS", "Envoyer des SMS", 2, "Peut envoyer des SMS à votre insu (numéros surtaxés)."),
    PDef("BIND_ACCESSIBILITY_SERVICE", "Service d'accessibilité", 2, "Peut lire l'écran et agir à votre place : technique courante des chevaux de Troie bancaires."),
    PDef("SYSTEM_ALERT_WINDOW", "Affichage par-dessus les autres applis", 2, "Peut afficher de faux écrans de connexion devant de vraies applis."),
    PDef("REQUEST_INSTALL_PACKAGES", "Installer d'autres applis", 2, "Peut installer d'autres applications (comportement de dropper)."),
    PDef("BIND_DEVICE_ADMIN", "Administrateur de l'appareil", 2, "Peut compliquer la désinstallation et verrouiller l'appareil."),
    PDef("BIND_NOTIFICATION_LISTENER_SERVICE", "Lire vos notifications", 2, "Peut lire vos notifications, codes de vérification compris."),
    PDef("MANAGE_EXTERNAL_STORAGE", "Accès à tous vos fichiers", 1, "Peut lire et modifier tous les fichiers du téléphone."),
    PDef("READ_CONTACTS", "Lire vos contacts", 1, "Peut copier votre carnet d'adresses."),
    PDef("READ_CALL_LOG", "Lire le journal d'appels", 1, "Peut consulter qui vous appelez ou qui vous appelle."),
    PDef("RECORD_AUDIO", "Utiliser le micro", 1, "Peut enregistrer le son."),
    PDef("CAMERA", "Utiliser la caméra", 1, "Peut prendre des photos ou filmer."),
    PDef("ACCESS_FINE_LOCATION", "Position précise", 1, "Peut suivre vos déplacements."),
    PDef("ACCESS_BACKGROUND_LOCATION", "Position en arrière-plan", 1, "Peut vous suivre même appli fermée."),
    PDef("READ_PHONE_STATE", "Identifiants du téléphone", 1, "Peut lire des identifiants et l'état des appels."),
    PDef("CALL_PHONE", "Passer des appels", 1, "Peut lancer des appels sans passer par vous."),
    PDef("QUERY_ALL_PACKAGES", "Voir toutes vos applis", 1, "Peut dresser la liste des applis installées."),
    PDef("WRITE_SETTINGS", "Modifier les réglages système", 1, "Peut changer des réglages de l'appareil.")
)

object FileScanner {
    suspend fun scan(ctx: Context, uri: Uri, key: String, step: (String) -> Unit): FileReport = withContext(Dispatchers.IO) {
        var name = "fichier"; var size = -1L
        try {
            ctx.contentResolver.query(uri, null, null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val ni = c.getColumnIndex(OpenableColumns.DISPLAY_NAME); val si = c.getColumnIndex(OpenableColumns.SIZE)
                    if (ni >= 0) name = c.getString(ni) ?: name
                    if (si >= 0 && !c.isNull(si)) size = c.getLong(si)
                }
            }
            val isApk = name.lowercase().endsWith(".apk")
            val tmp = if (isApk) File(ctx.cacheDir, "scan.apk") else null
            step("Calcul de l'empreinte SHA-256 (sur l'appareil)…")
            val md = MessageDigest.getInstance("SHA-256")
            var total = 0L
            (ctx.contentResolver.openInputStream(uri) ?: throw IllegalStateException("Fichier illisible")).use { ins ->
                val out = tmp?.outputStream()
                try {
                    val buf = ByteArray(65536)
                    while (true) {
                        val n = ins.read(buf); if (n < 0) break
                        md.update(buf, 0, n); out?.write(buf, 0, n); total += n
                    }
                } finally { out?.close() }
            }
            if (size < 0) size = total
            val sha = md.digest().joinToString("") { "%02x".format(it) }

            var pkg: String? = null; var perms = emptyList<PermInfo>()
            if (tmp != null) {
                step("Lecture des permissions de l'APK…")
                @Suppress("DEPRECATION")
                val info = ctx.packageManager.getPackageArchiveInfo(tmp.absolutePath, PackageManager.GET_PERMISSIONS)
                pkg = info?.packageName
                val req = info?.requestedPermissions?.map { it.substringAfterLast('.') }.orEmpty().toSet()
                perms = PERMS.filter { it.key in req }.map { PermInfo(it.label, it.level, it.why) }.sortedByDescending { it.level }
                tmp.delete()
            }

            if (key.isBlank()) return@withContext FileReport(name, size, sha, pkg, perms, null, true, null)
            step("Recherche de l'empreinte sur VirusTotal…")
            FileReport(name, size, sha, pkg, perms, Net.virusTotalFile(sha, key), false, null)
        } catch (e: Exception) {
            FileReport(name, size, "", null, emptyList(), null, false, e.message ?: "Erreur de lecture du fichier")
        }
    }
}


data class InstalledApp(val label: String, val pkg: String, val perms: List<PermInfo>, val outsidePlay: Boolean, val risk: Int) // 2 élevé, 1 moyen

/** Analyse locale des applis installées : permissions sensibles déclarées + origine d'installation. Aucun envoi réseau. */
object InstalledScanner {
    @Suppress("DEPRECATION")
    fun scan(ctx: Context): List<InstalledApp> {
        val pm = ctx.packageManager
        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).mapNotNull { p ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || p.packageName == ctx.packageName) return@mapNotNull null
            val req = p.requestedPermissions?.map { it.substringAfterLast('.') }.orEmpty().toSet()
            val found = PERMS.filter { it.key in req }.map { PermInfo(it.label, it.level, it.why) }.sortedByDescending { it.level }
            val high = found.count { it.level == 2 }
            if (high == 0) return@mapNotNull null
            val installer = try {
                if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(p.packageName).installingPackageName else pm.getInstallerPackageName(p.packageName)
            } catch (_: Exception) { null }
            val outside = installer != "com.android.vending"
            val base = if (high >= 3) 2 else 1
            val risk = if (outside && base == 1) 2 else base
            InstalledApp(ai.loadLabel(pm).toString(), p.packageName, found, outside, risk)
        }.sortedWith(compareByDescending<InstalledApp> { it.risk }.thenByDescending { it.perms.count { x -> x.level == 2 } })
    }
}
