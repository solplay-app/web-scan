package com.capi.webscan

import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Bitmap
import android.net.http.SslError
import android.os.Message
import android.webkit.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.json.JSONTokener
import java.util.Collections
import kotlin.coroutines.resume

data class FormInfo(val action: String, val sensitive: Boolean)
data class Rendered(
    val html: String, val title: String, val finalUrl: String, val forms: List<FormInfo>,
    val hosts: Set<String>, val dialogs: Int, val popups: Int, val sslError: Boolean
)

private const val EXTRACT_JS = """(function(){
 var f=[].map.call(document.querySelectorAll('form'),function(x){return {a:x.action||'',
  s:!!x.querySelector('input[type=password]')||/(password|mot de passe|card number|numéro de carte|cvv|iban|seed phrase|private key|clé privée)/i.test(x.innerText+' '+x.innerHTML)}});
 return JSON.stringify({h:document.documentElement.outerHTML.slice(0,1500000),t:document.title,u:location.href,f:f});
})()"""

/** WebView isolée : pas de cookies persistants, pas de téléchargement, schémas non-http bloqués. */
@SuppressLint("SetJavaScriptEnabled")
suspend fun renderPage(ctx: Context, url: String): Rendered? = withContext(Dispatchers.Main) {
    withTimeoutOrNull(35_000) {
        suspendCancellableCoroutine<Rendered?> { cont ->
            val wv = WebView(ctx.applicationContext)
            val hosts = Collections.synchronizedSet(mutableSetOf<String>())
            var dialogs = 0; var popups = 0; var sslError = false; var done = false

            fun finish(r: Rendered?) {
                if (done) return
                done = true
                wv.removeCallbacks(null)
                wv.stopLoading(); wv.destroy()
                CookieManager.getInstance().removeAllCookies(null)
                if (cont.isActive) cont.resume(r)
            }

            wv.settings.apply {
                javaScriptEnabled = true; domStorageEnabled = true
                setSupportMultipleWindows(true); javaScriptCanOpenWindowsAutomatically = true
                allowFileAccess = false; allowContentAccess = false
                saveFormData = false
            }

            val extract = Runnable {
                wv.evaluateJavascript(EXTRACT_JS) { value ->
                    try {
                        val j = JSONObject(JSONTokener(value).nextValue() as String)
                        val fa = j.getJSONArray("f")
                        val forms = (0 until fa.length()).map { fa.getJSONObject(it).let { o -> FormInfo(o.getString("a"), o.getBoolean("s")) } }
                        finish(Rendered(j.getString("h"), j.getString("t"), j.getString("u"), forms, hosts.toSet(), dialogs, popups, sslError))
                    } catch (_: Exception) { finish(null) }
                }
            }

            wv.webChromeClient = object : WebChromeClient() {
                override fun onJsAlert(v: WebView?, u: String?, m: String?, r: JsResult): Boolean { dialogs++; r.cancel(); return true }
                override fun onJsConfirm(v: WebView?, u: String?, m: String?, r: JsResult): Boolean { dialogs++; r.cancel(); return true }
                override fun onJsPrompt(v: WebView?, u: String?, m: String?, d: String?, r: JsPromptResult): Boolean { dialogs++; r.cancel(); return true }
                override fun onCreateWindow(v: WebView?, d: Boolean, g: Boolean, msg: Message?): Boolean { popups++; return false }
            }
            wv.webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(v: WebView, r: WebResourceRequest): Boolean =
                    r.url.scheme !in listOf("http", "https") // bloque intent://, market://, tel:…
                override fun shouldInterceptRequest(v: WebView, r: WebResourceRequest): WebResourceResponse? {
                    r.url.host?.let { hosts.add(it.lowercase()) }; return null
                }
                override fun onPageFinished(v: WebView, u: String) { v.removeCallbacks(extract); v.postDelayed(extract, 4000) }
                override fun onReceivedSslError(v: WebView, h: SslErrorHandler, e: SslError) { sslError = true; h.proceed() }
                override fun onReceivedError(v: WebView, r: WebResourceRequest, e: WebResourceError) {
                    if (r.isForMainFrame) finish(null)
                }
            }
            cont.invokeOnCancellation { wv.post { try { wv.destroy() } catch (_: Exception) {} } }
            wv.loadUrl(url)
        }
    }
}
