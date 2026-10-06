package com.capi.webscan

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.hardware.camera2.CameraManager
import android.hardware.display.DisplayManager
import android.media.AudioManager
import android.media.AudioRecordingConfiguration
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Protection active : notification permanente avec l'icône clé dans la barre d'état + surveillance. */
class ProtectionService : Service() {
    companion object { const val CH_PERM = "protection"; const val CH_ALERT = "alerts"; const val ID = 1; const val STOP = "STOP" }

    private val handler = Handler(Looper.getMainLooper())
    private var scope: CoroutineScope? = null
    private var registeredAt = 0L
    private var lastRec = 0
    private fun now() = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
    private fun grace() = System.currentTimeMillis() - registeredAt < 3000

    private val camCb = object : CameraManager.AvailabilityCallback() {
        override fun onCameraUnavailable(cameraId: String) {
            if (!grace()) alert("Caméra activée", "Une application utilise la caméra (vous, si vous venez de l'ouvrir).")
        }
    }
    private val recCb = object : AudioManager.AudioRecordingCallback() {
        override fun onRecordingConfigChanged(configs: MutableList<AudioRecordingConfiguration>) {
            val n = configs.size
            if (n > lastRec && !grace()) alert("Micro activé", "Un enregistrement audio vient de démarrer (appel, dictée ou autre appli).")
            lastRec = n
        }
    }
    private val dispCb = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) { if (!grace()) alert("Nouvel écran détecté", "Diffusion ou mise en miroir de l'écran possible.", true) }
        override fun onDisplayRemoved(displayId: Int) {}
        override fun onDisplayChanged(displayId: Int) {}
    }

    private fun alert(title: String, detail: String, force: Boolean = false) {
        val screenOff = !getSystemService(PowerManager::class.java).isInteractive
        val sev = if (screenOff || force) 2 else 1
        val full = if (screenOff) "$detail ÉCRAN ÉTEINT : si ce n'est pas vous, vérifiez les applis ayant accès au micro/caméra." else detail
        ProtectionState.log(ProtEvent(now(), title, full, sev))
        if (sev == 2) {
            val n = Notification.Builder(this, CH_ALERT).setSmallIcon(R.drawable.ic_key).setContentTitle("⚠️ $title")
                .setContentText(full).setStyle(Notification.BigTextStyle().bigText(full)).setAutoCancel(true)
                .setContentIntent(openApp()).build()
            getSystemService(NotificationManager::class.java).notify((System.currentTimeMillis() % 100000).toInt() + 10, n)
        }
    }

    private fun openApp() = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)

    private fun buildNotification(): Notification {
        val stop = PendingIntent.getService(this, 1, Intent(this, ProtectionService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, CH_PERM).setSmallIcon(R.drawable.ic_key)
            .setContentTitle("Protection Web Scan active")
            .setContentText("Surveillance caméra, micro, écrans et réglages sensibles")
            .setOngoing(true).setContentIntent(openApp())
            .addAction(Notification.Action.Builder(null, "Désactiver", stop).build()).build()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { stopSelf(); return START_NOT_STICKY }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CH_PERM, "Protection active", NotificationManager.IMPORTANCE_LOW))
        nm.createNotificationChannel(NotificationChannel(CH_ALERT, "Alertes de sécurité", NotificationManager.IMPORTANCE_HIGH))
        val n = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE) else startForeground(ID, n)

        if (scope == null) {
            registeredAt = System.currentTimeMillis()
            getSystemService(CameraManager::class.java).registerAvailabilityCallback(camCb, handler)
            val am = getSystemService(AudioManager::class.java)
            lastRec = am.activeRecordingConfigurations.size
            am.registerAudioRecordingCallback(recCb, handler)
            getSystemService(DisplayManager::class.java).registerDisplayListener(dispCb, handler)
            scope = CoroutineScope(SupervisorJob() + Dispatchers.Default).also { s -> s.launch { auditLoop() } }
            ProtectionState.active.value = true
            ProtectionState.log(ProtEvent(now(), "Protection activée", "Surveillance caméra, micro, écrans et réglages sensibles.", 0))
        }
        return START_STICKY
    }

    private suspend fun auditLoop() {
        var last = DeviceAudit.run(this).filter { it.status == Status.WARN }.map { it.title }.toSet()
        while (true) {
            delay(60_000)
            val cur = DeviceAudit.run(this).filter { it.status == Status.WARN }.map { it.title }.toSet()
            (cur - last).forEach { alert("Nouveau risque : $it", "Ce réglage est passé à risque pendant la protection.", true) }
            last = cur
        }
    }

    override fun onDestroy() {
        try {
            getSystemService(CameraManager::class.java).unregisterAvailabilityCallback(camCb)
            getSystemService(AudioManager::class.java).unregisterAudioRecordingCallback(recCb)
            getSystemService(DisplayManager::class.java).unregisterDisplayListener(dispCb)
        } catch (_: Exception) {}
        scope?.cancel(); scope = null
        ProtectionState.active.value = false
        ProtectionState.log(ProtEvent(now(), "Protection désactivée", "La surveillance est arrêtée.", 0))
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
