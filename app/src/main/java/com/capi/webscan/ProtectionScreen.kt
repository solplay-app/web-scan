package com.capi.webscan

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun open(ctx: Context, i: Intent) { try { ctx.startActivity(i) } catch (_: Exception) {} }

@Composable
fun ProtectionScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val active by ProtectionState.active.collectAsState()
    val events by ProtectionState.events.collectAsState()
    var audit by remember { mutableStateOf<List<AuditItem>?>(null) }
    var apps by remember { mutableStateOf<List<AppAccess>?>(null) }
    var fwd by remember { mutableStateOf<String?>(null) }
    var installed by remember { mutableStateOf<List<InstalledApp>?>(null) }
    var scanning by remember { mutableStateOf(false) }

    fun refresh() = scope.launch {
        audit = withContext(Dispatchers.Default) { DeviceAudit.run(ctx) }
        apps = withContext(Dispatchers.Default) { DeviceAudit.appsWithAccess(ctx) }
    }
    LaunchedEffect(Unit) { refresh() }
    LaunchedEffect(active) { refresh() }

    fun start() { ctx.startForegroundService(Intent(ctx, ProtectionService::class.java)) }
    val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { start() }
    val phonePerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        if (ok) CallForward.check(ctx) { fwd = it } else fwd = "Permission d'appel refusée : utilisez le bouton « Ouvrir le composeur »."
    }

    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = if (active) Color(0xFFE8F5E9) else MaterialTheme.colorScheme.surfaceVariant)) {
                Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (active) Icon(painterResource(R.drawable.ic_key), null, Modifier.size(48.dp), tint = Color(0xFF2E7D32))
                    else Image(painterResource(R.drawable.ic_shield), null, Modifier.size(56.dp))
                    Text(if (active) "Protection ACTIVE" else "Protection désactivée", fontWeight = FontWeight.Bold, fontSize = 20.sp,
                        color = if (active) Color(0xFF2E7D32) else Color.DarkGray)
                    Text(if (active) "Une clé s'affiche dans la barre d'état. Captures d'écran de Web Scan bloquées. Caméra, micro, écrans et réglages sensibles surveillés."
                        else "Active la surveillance en temps réel : alertes si le micro ou la caméra s'allument, si un écran est diffusé, ou si un réglage dangereux apparaît.",
                        fontSize = 13.sp)
                    Button(onClick = {
                        if (active) ctx.stopService(Intent(ctx, ProtectionService::class.java))
                        else if (Build.VERSION.SDK_INT >= 33 && ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                            notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
                        else start()
                    }, Modifier.fillMaxWidth()) { Text(if (active) "Désactiver la protection" else "Activer la protection") }
                }
            }
        }

        item { Text("Alertes en temps réel", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
        if (events.isEmpty()) item { Text("Aucun événement pour l'instant.", color = Color.Gray) }
        items(events.take(15)) { e ->
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = when (e.severity) { 2 -> Color(0xFFFDECEA); 1 -> Color(0xFFFFF8E1); else -> MaterialTheme.colorScheme.surfaceVariant })) {
                Column(Modifier.padding(12.dp)) {
                    Text("${e.time}  ${e.title}", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(e.detail, fontSize = 12.sp)
                }
            }
        }

        item { Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Contrôle de l'appareil", fontWeight = FontWeight.Bold, fontSize = 18.sp, modifier = Modifier.weight(1f))
            TextButton(onClick = { refresh() }) { Text("Actualiser") }
        } }
        val a = audit
        if (a == null) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
        else items(a) { it ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                    Text(when (it.status) { Status.OK -> "✅"; Status.WARN -> "⚠️"; Status.INFO -> "ℹ️" }, modifier = Modifier.width(32.dp))
                    Column(Modifier.weight(1f)) {
                        Text(it.title, fontWeight = FontWeight.Medium)
                        Text(it.detail, fontSize = 12.sp, color = Color.DarkGray)
                        if (it.action != null) TextButton(onClick = { open(ctx, Intent(it.action)) }) { Text(it.actionLabel ?: "Ouvrir") }
                    }
                }
            }
        }

        item { Text("Accès caméra et micro", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
        item {
            Text("Applis installées qui ont déjà reçu l'accès. Retirez-le à celles dont vous n'avez pas besoin.", fontSize = 13.sp, color = Color.DarkGray)
        }
        item {
            OutlinedButton(onClick = { open(ctx, Intent(Settings.ACTION_PRIVACY_SETTINGS)) }, Modifier.fillMaxWidth()) {
                Text("Réglages confidentialité (interrupteurs caméra/micro)")
            }
        }
        val ap = apps
        if (ap == null) item { LinearProgressIndicator(Modifier.fillMaxWidth()) }
        else if (ap.isEmpty()) item { Text("Aucune appli tierce n'a l'accès caméra ou micro.", color = Color(0xFF2E7D32)) }
        else items(ap.take(40)) { app ->
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(app.label, fontWeight = FontWeight.Medium)
                        Text(listOfNotNull(if (app.camera) "📷 Caméra" else null, if (app.mic) "🎤 Micro" else null).joinToString("  "), fontSize = 12.sp)
                    }
                    TextButton(onClick = { open(ctx, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.pkg}"))) }) { Text("Gérer") }
                }
            }
        }

        item { Text("Applis installées à vérifier", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Repère les applis qui demandent des permissions typiques des malwares (SMS, superposition, installation d'applis, notifications…) et celles installées hors Play Store. Analyse locale, rien n'est envoyé.", fontSize = 13.sp)
                    Button(onClick = { scanning = true; scope.launch { installed = withContext(Dispatchers.Default) { InstalledScanner.scan(ctx) }; scanning = false } },
                        Modifier.fillMaxWidth(), enabled = !scanning) { Text(if (scanning) "Analyse…" else "Analyser mes applis") }
                    installed?.let { if (it.isEmpty()) Text("Aucune appli installée ne demande de permission à haut risque.", fontSize = 13.sp, color = Color(0xFF2E7D32)) }
                }
            }
        }
        items(installed.orEmpty()) { a ->
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = if (a.risk == 2) Color(0xFFFDECEA) else Color(0xFFFFF8E1))) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(a.label, fontWeight = FontWeight.Bold)
                            Text((if (a.risk == 2) "Profil élevé" else "Profil moyen") + if (a.outsidePlay) " · hors Play Store" else "", fontSize = 12.sp, color = Color.DarkGray)
                        }
                        TextButton(onClick = { open(ctx, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${a.pkg}"))) }) { Text("Gérer") }
                    }
                    a.perms.filter { it.level == 2 }.forEach { Text("• ${it.label}", fontSize = 12.sp) }
                    Text("Ces permissions montrent ce que l'appli peut faire, pas ce qu'elle fait : une messagerie légitime en demande aussi.", fontSize = 11.sp, color = Color.Gray)
                }
            }
        }

        item { Text("Renvoi d'appel", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Un renvoi d'appel peut détourner vos appels et codes vocaux vers un tiers.", fontSize = 13.sp)
                    Button(onClick = {
                        if (ctx.checkSelfPermission(Manifest.permission.CALL_PHONE) == PackageManager.PERMISSION_GRANTED) CallForward.check(ctx) { fwd = it }
                        else phonePerm.launch(Manifest.permission.CALL_PHONE)
                    }, Modifier.fillMaxWidth()) { Text("Vérifier auprès du réseau") }
                    fwd?.let { Text("Réponse de l'opérateur : $it", fontSize = 13.sp, fontWeight = FontWeight.Medium) }
                    OutlinedButton(onClick = { open(ctx, Intent(Intent.ACTION_DIAL, Uri.parse("tel:" + Uri.encode("##002#")))) }, Modifier.fillMaxWidth()) {
                        Text("Désactiver tous les renvois (ouvre le composeur)")
                    }
                    Text("La réponse dépend de l'opérateur. Vous validez vous-même l'appel dans le composeur.", fontSize = 11.sp, color = Color.Gray)
                }
            }
        }

        item {
            Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF8E1))) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Ce que Web Scan ne peut pas faire", fontWeight = FontWeight.Bold)
                    Text("• Empêcher une écoute au niveau de l'opérateur (fausse antenne, failles du réseau) : aucune appli ne le peut. Pour vos conversations sensibles, utilisez des appels chiffrés de bout en bout (Signal, WhatsApp).", fontSize = 12.sp)
                    Text("• Bloquer les captures d'écran du système : seules les fenêtres de Web Scan sont protégées.", fontSize = 12.sp)
                    Text("• Couper la caméra ou le micro des autres applis : Web Scan détecte et alerte. Pour les couper, utilisez les interrupteurs Android 12+ ou retirez les permissions.", fontSize = 12.sp)
                    Text("• Chiffrer tout le téléphone : Android chiffre déjà le stockage (voir le contrôle). Web Scan chiffre ses propres données sensibles (clé VirusTotal).", fontSize = 12.sp)
                }
            }
        }
    }
}
