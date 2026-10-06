package com.capi.webscan

import android.app.Activity
import android.content.Intent
import android.view.WindowManager
import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private fun handleShare(i: Intent?) {
        if (i?.action != Intent.ACTION_SEND) return
        val txt = i.getStringExtra(Intent.EXTRA_TEXT) ?: return
        Regex("""https?://\S+""").find(txt)?.value?.let { Incoming.url.value = it.trimEnd('.', ',', ')', ';') }
    }
    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handleShare(intent) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleShare(intent)
        setContent { MaterialTheme(colorScheme = lightColorScheme()) { Surface(Modifier.fillMaxSize()) { AppRoot() } } }
    }
}

@Composable
fun ScannerScreen(vtKey: String, onVtKey: (String) -> Unit, report: Report?, onReport: (Report?) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var url by rememberSaveable { mutableStateOf("") }
    var deep by rememberSaveable { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var stepText by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val incoming by Incoming.url.collectAsState()
    val hist by History.items.collectAsState()
    remember { History.load(ctx) }

    fun startScan() {
        error = null; onReport(null); busy = true
        scope.launch {
            try {
                val rep = Analyzer.analyze(ctx, url, deep, vtKey) { stepText = it }
                onReport(rep)
                History.add(ctx, "site", rep.target, "${rep.level.label} · ${rep.score}/100")
            } catch (e: Exception) { error = e.message ?: "Erreur d'analyse" }
            busy = false
        }
    }
    LaunchedEffect(incoming) {
        incoming?.let { url = it; Incoming.url.value = null; if (!busy) startScan() }
    }

    LazyColumn(
        Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item { Text("Web Scan", fontSize = 26.sp, fontWeight = FontWeight.Bold) }
        item {
            OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("URL du site à analyser") }, placeholder = { Text("https://exemple.com") })
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Switch(deep, { deep = it })
                Spacer(Modifier.width(8.dp))
                Column {
                    Text("Analyse approfondie", fontWeight = FontWeight.Medium)
                    Text(if (deep) "Charge la page dans une WebView isolée (JS exécuté)" else "Lit seulement le HTML, sans l'exécuter (plus sûr)",
                        fontSize = 12.sp, color = Color.Gray)
                }
            }
        }
        item {
            OutlinedTextField(vtKey, { onVtKey(it) }, Modifier.fillMaxWidth(), singleLine = true,
                label = { Text("Clé VirusTotal (optionnel)") }, visualTransformation = PasswordVisualTransformation())
        }
        item {
            Button(
                onClick = { startScan() },
                enabled = !busy && url.isNotBlank(), modifier = Modifier.fillMaxWidth()
            ) { Text(if (busy) "Analyse en cours…" else "Analyser") }
        }
        if (busy) item { Column { LinearProgressIndicator(Modifier.fillMaxWidth()); Text(stepText, fontSize = 12.sp, color = Color.Gray) } }
        error?.let { e -> item { Text(e, color = Color(0xFFC62828)) } }

        if (report == null && !busy && hist.isNotEmpty()) {
            item { Text("Historique (chiffré)", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
            items(hist.take(15)) { h ->
                Card(Modifier.fillMaxWidth().clickable(enabled = h.kind == "site") { url = h.title }) {
                    Column(Modifier.padding(12.dp)) {
                        Text((if (h.kind == "site") "🌐 " else "📄 ") + h.title, fontWeight = FontWeight.Medium, fontSize = 14.sp, maxLines = 1)
                        Text("${h.time} · ${h.summary}", fontSize = 12.sp, color = Color.Gray)
                    }
                }
            }
            item { TextButton(onClick = { History.clear(ctx) }) { Text("Effacer l'historique") } }
        }

        report?.let { r ->
            val c = Color(r.level.color)
            item { ScoreCard(r, c) }
            item {
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("En clair", fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        Text(r.headline)
                        Text("Que faire ?", fontWeight = FontWeight.Medium, modifier = Modifier.padding(top = 6.dp))
                        r.advice.forEach { Text("• $it") }
                        val bctx = LocalContext.current
                        val dom = Blocker.clean(if (r.tech.shared) r.tech.host else r.tech.registrable)
                        var siteBlocked by remember { mutableStateOf(false) }
                        if (dom != null) OutlinedButton(onClick = { Blocker.update(bctx) { it.copy(custom = it.custom + dom) }; siteBlocked = true },
                            Modifier.fillMaxWidth(), enabled = !siteBlocked) {
                            Text(if (siteBlocked) "$dom ajouté à la liste (activez le blocage)" else "Bloquer $dom")
                        }
                    }
                }
            }
            item { Text("Signaux détectés (${r.findings.size})", fontWeight = FontWeight.Bold, fontSize = 18.sp) }
            if (r.findings.isEmpty()) item { Text("Aucun signal détecté.") }
            items(r.findings) { f ->
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(
                    containerColor = if (f.strong) Color(0xFFFDECEA) else MaterialTheme.colorScheme.surfaceVariant)) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
                        Text("+${f.points}", fontWeight = FontWeight.Bold, color = if (f.strong) Color(0xFFC62828) else Color.DarkGray,
                            modifier = Modifier.width(44.dp))
                        Column {
                            if (f.strong) Text("★ SIGNAL FORT", fontSize = 11.sp, color = Color(0xFFC62828), fontWeight = FontWeight.Bold)
                            Text(f.message)
                        }
                    }
                }
            }
            if (r.capped) item { Text("Score brut ${r.raw} plafonné à 39 : aucun signal fort ★, donc pas de verdict élevé.", fontSize = 12.sp, color = Color.Gray) }
            item { ThreatsCard(r, vtKey.isBlank()) { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it))) } }
            item { TechCard(r.tech) }
            item {
                OutlinedButton(onClick = {
                    ctx.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                        type = "text/plain"; putExtra(Intent.EXTRA_TEXT, r.shareText())
                    }, "Partager le rapport"))
                }, Modifier.fillMaxWidth()) { Text("Partager le rapport") }
            }
            item { Text("Score indicatif : ce n'est pas une preuve. Vérifiez toujours manuellement.", fontSize = 12.sp, color = Color.Gray) }
        }
    }
}

@Composable
fun ScoreCard(r: Report, c: Color) {
    Card(Modifier.fillMaxWidth()) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.size(110.dp), contentAlignment = Alignment.Center) {
                Canvas(Modifier.fillMaxSize()) {
                    val s = Stroke(14.dp.toPx(), cap = StrokeCap.Round); val pad = 7.dp.toPx()
                    val sz = Size(size.width - 2 * pad, size.height - 2 * pad)
                    drawArc(Color(0x22000000), 135f, 270f, false, Offset(pad, pad), sz, style = s)
                    drawArc(c, 135f, 270f * r.score / 100f, false, Offset(pad, pad), sz, style = s)
                }
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("${r.score}", fontSize = 30.sp, fontWeight = FontWeight.Bold, color = c); Text("/100", fontSize = 12.sp)
                }
            }
            Spacer(Modifier.width(16.dp))
            Column {
                Text(r.level.label, fontWeight = FontWeight.Bold, fontSize = 18.sp, color = c)
                Text(r.tech.registrable, fontSize = 13.sp, color = Color.Gray)
            }
        }
    }
}

@Composable
fun TechCard(t: Tech) {
    fun row(k: String, v: String?) = v?.let { k to it }
    val rows = listOfNotNull(
        row("Domaine", t.registrable),
        row("Mode", if (t.deep) "Approfondi (WebView)" else "HTML seul"),
        row("Titre de la page", t.title?.takeIf { it.isNotBlank() }),
        row("URL finale", t.finalUrl),
        row("Enregistré le", t.domain?.registered?.take(10)),
        row("Âge du domaine", t.domain?.let { "${it.ageDays} jours" }),
        row("Expire le", t.domain?.expiry?.take(10)),
        row("Registrar", t.domain?.registrar),
        row("Certificat", t.cert?.let { "${it.issuer} — émis il y a ${it.ageDays} j (durée ${it.lifetimeDays} j)" }),
        row("Domaines tiers inconnus", t.unknownThirdParties?.toString()),
        row("VirusTotal", t.vt?.let { "${it.flagged} détection(s) sur ${it.total} moteurs" })
    )
    Card(Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Détails techniques", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            rows.forEach { (k, v) -> Row { Text(k, Modifier.width(130.dp), color = Color.Gray, fontSize = 13.sp); Text(v, fontSize = 13.sp) } }
        }
    }
}

@Composable
fun ThreatsCard(r: Report, noKey: Boolean, openLink: (String) -> Unit) {
    val vt = r.tech.vt
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Menaces détectées (VirusTotal)", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            when {
                vt == null && noKey -> Text("Ajoutez une clé VirusTotal pour voir quelles menaces sont signalées et ce qu'elles peuvent faire.", color = Color.Gray)
                vt == null -> Text("VirusTotal n'a pas répondu (clé invalide, quota atteint ou domaine inconnu).", color = Color.Gray)
                vt.flagged == 0 -> Text("0 détection sur ${vt.total} moteurs.", color = Color(0xFF2E7D32))
                else -> {
                    Text("${vt.flagged} moteur(s) sur ${vt.total} signalent ce site.", fontWeight = FontWeight.Medium)
                    r.threats.forEach { g ->
                        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFFDECEA)), modifier = Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(g.info.title, fontWeight = FontWeight.Bold, color = Color(0xFFC62828))
                                Text(g.info.summary, fontSize = 14.sp)
                                Text("Ce que ça peut faire :", fontWeight = FontWeight.Medium, fontSize = 13.sp)
                                g.info.capabilities.forEach { Text("• $it", fontSize = 13.sp) }
                                Text("Que faire : ${g.info.advice}", fontSize = 13.sp)
                                Text("Signalé par : ${g.engines.joinToString(", ")}", fontSize = 12.sp, color = Color.Gray)
                            }
                        }
                    }
                    Text("Ces explications décrivent le type de menace signalé, pas un fichier précis analysé.", fontSize = 12.sp, color = Color.Gray)
                    OutlinedButton(onClick = { openLink(vt.link) }, Modifier.fillMaxWidth()) { Text("Voir le détail sur VirusTotal") }
                }
            }
            if (r.tech.shared) Text("Site sur plateforme gratuite : le rapport VirusTotal concerne ce sous-domaine précis.", fontSize = 12.sp, color = Color.Gray)
        }
    }
}

@Composable
fun AppRoot() {
    val ctx = LocalContext.current
    val act = ctx as Activity
    var tab by rememberSaveable { mutableStateOf(0) }
    var vtKey by remember { mutableStateOf(SecureStore.get(ctx, "vt") ?: "") }   // clé chiffrée par le Keystore
    val setKey: (String) -> Unit = { vtKey = it; SecureStore.put(ctx, "vt", it) }
    var siteReport by remember { mutableStateOf<Report?>(null) }
    var fileReport by remember { mutableStateOf<FileReport?>(null) }
    val active by ProtectionState.active.collectAsState()
    val shared by Incoming.url.collectAsState()
    LaunchedEffect(shared) { if (shared != null) tab = 0 }
    // Protection active : captures d'écran et enregistrement d'écran bloqués pour Web Scan
    LaunchedEffect(active) {
        if (active) act.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else act.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
    Column(Modifier.fillMaxSize().systemBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.ic_shield), null, Modifier.size(28.dp))
            Spacer(Modifier.width(8.dp))
            Text("Web Scan", fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Spacer(Modifier.weight(1f))
            if (active) {
                Icon(painterResource(R.drawable.ic_key), null, Modifier.size(22.dp), tint = Color(0xFF2E7D32))
                Spacer(Modifier.width(4.dp)); Text("Protégé", color = Color(0xFF2E7D32), fontSize = 12.sp, fontWeight = FontWeight.Bold)
            }
        }
        TabRow(selectedTabIndex = tab) {
            Tab(tab == 0, { tab = 0 }, text = { Text("Site", fontSize = 12.sp) })
            Tab(tab == 1, { tab = 1 }, text = { Text("Fichier", fontSize = 12.sp) })
            Tab(tab == 2, { tab = 2 }, text = { Text("Protection", fontSize = 12.sp) })
            Tab(tab == 3, { tab = 3 }, text = { Text("Blocage", fontSize = 12.sp) })
        }
        Box(Modifier.weight(1f)) {
            when (tab) {
                0 -> ScannerScreen(vtKey, setKey, siteReport) { siteReport = it }
                1 -> FileScanScreen(vtKey, setKey, fileReport) { fileReport = it }
                2 -> ProtectionScreen()
                else -> BlockScreen()
            }
        }
    }
}
