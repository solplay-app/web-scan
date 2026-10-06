package com.capi.webscan

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
private fun SwitchRow(title: String, sub: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Bold)
            Text(sub, fontSize = 12.sp, color = Color.Gray)
        }
        Switch(checked, onChange)
    }
}

@Composable
fun BlockScreen() {
    val ctx = LocalContext.current
    remember { Blocker.load(ctx) }
    val cfg by Blocker.settings.collectAsState()
    val active by BlockState.active.collectAsState()
    val blocked by BlockState.blocked.collectAsState()
    val total by BlockState.total.collectAsState()
    val recent by BlockState.recent.collectAsState()
    var input by remember { mutableStateOf("") }
    var err by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val listInfo by Blocker.remoteInfo.collectAsState()
    var updating by remember { mutableStateOf(false) }
    var updMsg by remember { mutableStateOf<String?>(null) }

    val startIntent = Intent(ctx, BlockService::class.java)
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { r ->
        if (r.resultCode == Activity.RESULT_OK) ctx.startService(startIntent)
    }
    fun toggle() {
        if (active) { ctx.startService(Intent(ctx, BlockService::class.java).setAction(BlockService.STOP)); return }
        val i = VpnService.prepare(ctx)
        if (i != null) launcher.launch(i) else ctx.startService(startIntent)
    }

    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(if (active) "Blocage actif" else "Blocage désactivé", fontWeight = FontWeight.Bold, fontSize = 18.sp,
                        color = if (active) Color(0xFF2E7D32) else Color.Gray)
                    Text("Bloque les publicités, les traceurs et les sites de votre choix pour toutes les applis et tous les navigateurs, en filtrant les noms de domaine sur le téléphone. Android affichera l'icône de VPN : c'est normal, aucun trafic n'est envoyé à un serveur Web Scan.", fontSize = 13.sp)
                    Button(onClick = { toggle() }, Modifier.fillMaxWidth()) { Text(if (active) "Désactiver le blocage" else "Activer le blocage") }
                    if (total > 0) Text("$blocked bloquées sur $total requêtes depuis l'activation", fontSize = 12.sp, color = Color.Gray)
                }
            }
        }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    SwitchRow("Publicités", "Régies publicitaires courantes (liste intégrée)", cfg.ads) { v -> Blocker.update(ctx) { it.copy(ads = v) } }
                    Text(listInfo, fontSize = 12.sp, color = Color.Gray)
                    OutlinedButton(onClick = {
                        updating = true; updMsg = null
                        scope.launch {
                            val n = withContext(Dispatchers.IO) { Blocker.refresh(ctx) }
                            updating = false
                            updMsg = if (n == null) "Échec : vérifiez la connexion (le téléchargement se fait hors VPN de blocage si besoin)." else "$n domaines publicitaires ajoutés."
                        }
                    }, Modifier.fillMaxWidth(), enabled = !updating) { Text(if (updating) "Téléchargement…" else "Mettre à jour la liste de publicités") }
                    updMsg?.let { Text(it, fontSize = 12.sp) }
                    SwitchRow("Traceurs", "Mesure d'audience et suivi entre applis", cfg.trackers) { v -> Blocker.update(ctx) { it.copy(trackers = v) } }
                }
            }
        }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Text("Filtre de sécurité", fontWeight = FontWeight.Bold)
                    Text("Appliqué par le DNS Cloudflare : il tient sa propre liste à jour.", fontSize = 12.sp, color = Color.Gray)
                    val opts = listOf("Standard" to "Aucun filtre supplémentaire", "Malware et phishing" to "Sites piégés connus (recommandé)", "Malware, phishing et adulte" to "Ajoute le contenu pour adultes")
                    opts.forEachIndexed { i, (t, s) ->
                        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(cfg.level == i, { Blocker.update(ctx) { it.copy(level = i) } })
                            Column { Text(t, fontSize = 14.sp); Text(s, fontSize = 11.sp, color = Color.Gray) }
                        }
                    }
                }
            }
        }
        item {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Sites bloqués par vous", fontWeight = FontWeight.Bold)
                    OutlinedTextField(input, { input = it; err = null }, Modifier.fillMaxWidth(), singleLine = true,
                        label = { Text("ex. exemple.com") }, isError = err != null, supportingText = { err?.let { Text(it) } })
                    Button(onClick = {
                        val d = Blocker.clean(input)
                        if (d == null) err = "Adresse invalide"
                        else { Blocker.update(ctx) { it.copy(custom = it.custom + d) }; input = "" }
                    }, Modifier.fillMaxWidth()) { Text("Bloquer ce site") }
                    Text("Le site et tous ses sous-domaines sont bloqués.", fontSize = 12.sp, color = Color.Gray)
                    if (cfg.custom.isEmpty()) Text("Aucun site ajouté.", fontSize = 13.sp)
                }
            }
        }
        items(cfg.custom.sorted()) { d ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(d, Modifier.weight(1f))
                TextButton(onClick = { Blocker.update(ctx) { it.copy(custom = it.custom - d) } }) { Text("Retirer") }
            }
        }
        if (recent.isNotEmpty()) {
            item { Text("Dernières requêtes bloquées", fontWeight = FontWeight.Bold) }
            items(recent) { n -> Text(n, fontSize = 12.sp, color = Color.Gray) }
        }
        item {
            Text("Limites : si votre navigateur utilise un DNS chiffré (« DNS sécurisé » de Chrome) ou si le « DNS privé » d'Android est réglé sur un fournisseur, ces requêtes contournent le filtre : désactivez-les pour que le blocage s'applique. Les pubs servies depuis le même domaine que le contenu (ex. dans YouTube) ne peuvent pas être bloquées par ce moyen.", fontSize = 12.sp, color = Color.Gray)
        }
    }
}
