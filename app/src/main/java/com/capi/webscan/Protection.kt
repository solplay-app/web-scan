package com.capi.webscan

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.telephony.TelephonyManager
import android.util.Base64
import android.view.accessibility.AccessibilityManager
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class ProtEvent(val time: String, val title: String, val detail: String, val severity: Int) // 2 = alerte, 1 = info, 0 = état

object ProtectionState {
    val active = MutableStateFlow(false)
    val events = MutableStateFlow<List<ProtEvent>>(emptyList())
    fun log(e: ProtEvent) { events.value = (listOf(e) + events.value).take(50) }
}

enum class Status { OK, WARN, INFO }
data class AuditItem(val title: String, val status: Status, val detail: String, val actionLabel: String? = null, val action: String? = null)
data class AppAccess(val label: String, val pkg: String, val camera: Boolean, val mic: Boolean)

object DeviceAudit {
    fun run(ctx: Context): List<AuditItem> {
        val items = mutableListOf<AuditItem>()
        val cr = ctx.contentResolver; val pm = ctx.packageManager

        val kg = ctx.getSystemService(KeyguardManager::class.java)
        items.add(if (kg.isDeviceSecure) AuditItem("Verrouillage de l'écran", Status.OK, "Un code, schéma ou la biométrie protège l'appareil.")
        else AuditItem("Verrouillage de l'écran", Status.WARN, "Aucun verrouillage : quiconque prend le téléphone a accès à tout.", "Régler", Settings.ACTION_SECURITY_SETTINGS))

        val dpm = ctx.getSystemService(DevicePolicyManager::class.java)
        val enc = dpm.storageEncryptionStatus
        items.add(if (enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER || enc == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY)
            AuditItem("Chiffrement du stockage", Status.OK, "Le stockage est chiffré par Android. La clé VirusTotal saisie dans Web Scan est en plus chiffrée par le Keystore.")
        else AuditItem("Chiffrement du stockage", Status.WARN, "Le stockage ne semble pas chiffré.", "Sécurité", Settings.ACTION_SECURITY_SETTINGS))

        try {
            val am = ctx.getSystemService(AccessibilityManager::class.java)
            val acc = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).map { it.resolveInfo.loadLabel(pm).toString() }
            items.add(if (acc.isEmpty()) AuditItem("Services d'accessibilité", Status.OK, "Aucun service d'accessibilité actif.")
            else AuditItem("Services d'accessibilité", Status.WARN,
                "Actifs : ${acc.joinToString(", ")}. Légitime pour un lecteur d'écran ou un gestionnaire de mots de passe ; suspect sinon (les chevaux de Troie bancaires s'en servent pour lire l'écran).",
                "Vérifier", Settings.ACTION_ACCESSIBILITY_SETTINGS))
        } catch (_: Exception) {}

        val admins = dpm.activeAdmins?.map { it.packageName }.orEmpty()
        items.add(if (admins.isEmpty()) AuditItem("Administrateurs de l'appareil", Status.OK, "Aucune appli administratrice.")
        else AuditItem("Administrateurs de l'appareil", Status.WARN, "Actifs : ${admins.joinToString(", ")}. Ils peuvent verrouiller l'appareil et gêner la désinstallation.", "Vérifier", Settings.ACTION_SECURITY_SETTINGS))

        val listeners = Settings.Secure.getString(cr, "enabled_notification_listeners").orEmpty().split(":")
            .map { it.substringBefore("/") }.filter { it.isNotBlank() && it != ctx.packageName }
        items.add(if (listeners.isEmpty()) AuditItem("Lecture des notifications", Status.OK, "Aucune appli ne lit vos notifications.")
        else AuditItem("Lecture des notifications", Status.WARN, "Applis autorisées : ${listeners.joinToString(", ")}. Elles peuvent lire vos codes de vérification.",
            "Vérifier", "android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))

        val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        items.add(if (!adb) AuditItem("Débogage USB", Status.OK, "Désactivé.")
        else AuditItem("Débogage USB", Status.WARN, "Activé : un ordinateur branché peut accéder à l'appareil.", "Désactiver", Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS))

        try {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            val userCas = ks.aliases().toList().count { it.startsWith("user:") }
            items.add(if (userCas == 0) AuditItem("Certificats installés par l'utilisateur", Status.OK, "Aucun : pas d'interception HTTPS locale connue.")
            else AuditItem("Certificats installés par l'utilisateur", Status.WARN, "$userCas certificat(s) ajouté(s) : ils permettent d'intercepter le trafic chiffré s'ils viennent d'une source non fiable.", "Vérifier", Settings.ACTION_SECURITY_SETTINGS))
        } catch (_: Exception) {}

        try {
            val cm = ctx.getSystemService(ConnectivityManager::class.java)
            val vpn = cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            val proxy = !System.getProperty("http.proxyHost").isNullOrBlank()
            items.add(when {
                proxy -> AuditItem("VPN / proxy", Status.WARN, "Un proxy est configuré : votre trafic passe par un tiers.", "Vérifier", Settings.ACTION_WIRELESS_SETTINGS)
                vpn -> AuditItem("VPN / proxy", Status.INFO, "Un VPN est actif. Normal si c'est le vôtre ; sinon vérifiez qui le fournit.", "Vérifier", Settings.ACTION_VPN_SETTINGS)
                else -> AuditItem("VPN / proxy", Status.OK, "Ni VPN ni proxy détecté.")
            })
        } catch (_: Exception) {}

        val rooted = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/system/app/Superuser.apk").any { File(it).exists() } ||
            (Build.TAGS?.contains("test-keys") == true)
        items.add(if (!rooted) AuditItem("Appareil modifié (root)", Status.OK, "Aucun signe de root.")
        else AuditItem("Appareil modifié (root)", Status.WARN, "Signes de root : les protections d'Android sont affaiblies."))

        val displays = ctx.getSystemService(DisplayManager::class.java).displays.size
        items.add(if (displays <= 1) AuditItem("Écran externe / diffusion", Status.OK, "Aucun écran externe détecté.")
        else AuditItem("Écran externe / diffusion", Status.WARN, "$displays affichages : l'écran est peut-être diffusé ou mis en miroir."))
        return items
    }

    /** Applis installées (hors système) qui ont déjà reçu l'accès caméra ou micro. */
    @Suppress("DEPRECATION")
    fun appsWithAccess(ctx: Context): List<AppAccess> {
        val pm = ctx.packageManager
        return pm.getInstalledPackages(PackageManager.GET_PERMISSIONS).mapNotNull { p: PackageInfo ->
            val ai = p.applicationInfo ?: return@mapNotNull null
            if ((ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 || p.packageName == ctx.packageName) return@mapNotNull null
            val req = p.requestedPermissions ?: return@mapNotNull null
            val fl = p.requestedPermissionsFlags ?: return@mapNotNull null
            fun granted(n: String) = req.indices.any { req[it] == n && (fl[it] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0 }
            val cam = granted("android.permission.CAMERA"); val mic = granted("android.permission.RECORD_AUDIO")
            if (cam || mic) AppAccess(ai.loadLabel(pm).toString(), p.packageName, cam, mic) else null
        }.sortedBy { it.label.lowercase() }
    }
}

object CallForward {
    /** Interroge le réseau (*#21#). Résultat variable selon l'opérateur. Nécessite la permission CALL_PHONE. */
    fun check(ctx: Context, onResult: (String) -> Unit) {
        try {
            val tm = ctx.getSystemService(TelephonyManager::class.java)
            tm.sendUssdRequest("*#21#", object : TelephonyManager.UssdResponseCallback() {
                override fun onReceiveUssdResponse(t: TelephonyManager, request: String, response: CharSequence) { onResult(response.toString()) }
                override fun onReceiveUssdResponseFailed(t: TelephonyManager, request: String, failureCode: Int) {
                    onResult("Le réseau n'a pas répondu (code $failureCode). Composez *#21# depuis le clavier téléphone.")
                }
            }, Handler(Looper.getMainLooper()))
        } catch (_: SecurityException) { onResult("Permission d'appel refusée.") }
        catch (e: Exception) { onResult("Vérification impossible sur cet appareil : ${e.message}") }
    }
}

/** Chiffrement AES-256-GCM avec une clé non exportable du Keystore Android. */
object SecureStore {
    private const val ALIAS = "webscan_key"
    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256).build())
        return g.generateKey()
    }
    fun put(ctx: Context, name: String, value: String) {
        val prefs = ctx.getSharedPreferences("secure", Context.MODE_PRIVATE)
        if (value.isEmpty()) { prefs.edit().remove(name).apply(); return }
        try {
            val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
            val data = c.iv + c.doFinal(value.toByteArray())
            prefs.edit().putString(name, Base64.encodeToString(data, Base64.NO_WRAP)).apply()
        } catch (_: Exception) {}
    }
    fun get(ctx: Context, name: String): String? = try {
        val raw = Base64.decode(ctx.getSharedPreferences("secure", Context.MODE_PRIVATE).getString(name, null) ?: return null, Base64.NO_WRAP)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, raw.copyOfRange(0, 12))) }
        String(c.doFinal(raw.copyOfRange(12, raw.size)))
    } catch (_: Exception) { null }
}
