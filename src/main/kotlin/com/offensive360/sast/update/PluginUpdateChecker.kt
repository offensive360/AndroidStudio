package com.offensive360.sast.update

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Plugin update notifier — checks the GitHub Releases API for newer versions.
 * Fire-and-forget, throttled (24h cache), silent on any failure.
 */
object PluginUpdateChecker {
    private const val CURRENT_VERSION = "1.1.18"
    private const val RELEASES_API_URL = "https://api.github.com/repos/offensive360/AndroidStudio/releases/latest"
    private const val USER_AGENT = "Offensive360-AS-Plugin/$CURRENT_VERSION"
    private const val CACHE_TTL_MS = 24L * 60 * 60 * 1000
    private val lastCheckMs = AtomicLong(0)
    private val notifiedThisSession = AtomicBoolean(false)

    /**
     * Manual check — bypasses throttle. Shows "up to date" if no update.
     */
    fun forceCheckAsync(project: Project) {
        lastCheckMs.set(0)
        notifiedThisSession.set(false)
        _forceShowUpToDate = true
        checkAsync(project)
    }

    @Volatile
    private var _forceShowUpToDate = false

    /**
     * Fire-and-forget. Never throws. Never blocks the scan.
     */
    fun checkAsync(project: Project) {
        if (notifiedThisSession.get() && !_forceShowUpToDate) return
        val now = System.currentTimeMillis()
        if (now - lastCheckMs.get() < CACHE_TTL_MS && !_forceShowUpToDate) return
        lastCheckMs.set(now)

        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val connection = (URL(RELEASES_API_URL).openConnection() as HttpURLConnection).apply {
                    requestMethod = "GET"
                    connectTimeout = 5000
                    readTimeout = 10000
                    setRequestProperty("User-Agent", USER_AGENT)
                    setRequestProperty("Accept", "application/vnd.github+json")
                }

                val code = connection.responseCode
                if (code !in 200..299) return@executeOnPooledThread
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                if (body.isBlank()) return@executeOnPooledThread

                val json = JSONObject(body)
                if (json.optBoolean("draft", false) || json.optBoolean("prerelease", false)) return@executeOnPooledThread
                val tag = json.optString("tag_name", "")
                if (tag.isBlank()) return@executeOnPooledThread

                val latestVersion = tag.trimStart('v', 'V')
                if (!isNewer(latestVersion, CURRENT_VERSION)) {
                    if (_forceShowUpToDate) {
                        _forceShowUpToDate = false
                        ApplicationManager.getApplication().invokeLater {
                            javax.swing.JOptionPane.showMessageDialog(
                                null,
                                "You're up to date! You have the latest version (v$CURRENT_VERSION).",
                                "Offensive 360",
                                javax.swing.JOptionPane.INFORMATION_MESSAGE)
                        }
                    }
                    return@executeOnPooledThread
                }
                _forceShowUpToDate = false

                // Find the .zip asset (first one ending in .zip wins)
                var downloadUrl = json.optString("html_url", "")
                val assets = json.optJSONArray("assets")
                if (assets != null) {
                    for (i in 0 until assets.length()) {
                        val a = assets.getJSONObject(i)
                        val name = a.optString("name", "")
                        if (name.endsWith(".zip", ignoreCase = true)) {
                            downloadUrl = a.optString("browser_download_url", downloadUrl)
                            break
                        }
                    }
                }

                val notes = truncateNotes(json.optString("body", ""))

                notifiedThisSession.set(true)
                showNotification(project, latestVersion, downloadUrl, notes)
            } catch (_: Exception) {
                // Silent: update notifications must NEVER block scans or surface errors.
            }
        }
    }

    private fun truncateNotes(body: String): String {
        if (body.isBlank()) return ""
        // Strip any trailing footer
        var trimmed = body
        for (footer in listOf("---\n")) {
            val idx = trimmed.indexOf(footer)
            if (idx > 0) { trimmed = trimmed.substring(0, idx); break }
        }
        trimmed = trimmed.trim()
        if (trimmed.length > 600) trimmed = trimmed.substring(0, 600).trimEnd() + "…"
        return trimmed
    }

    private fun isNewer(server: String, current: String): Boolean {
        return try {
            val a = parseVersion(server)
            val b = parseVersion(current)
            var result = false
            var decided = false
            for (i in 0 until 4) {
                if (!decided && a[i] != b[i]) {
                    result = a[i] > b[i]
                    decided = true
                }
            }
            result
        } catch (_: Exception) {
            false
        }
    }

    private fun parseVersion(v: String): IntArray {
        val parts = v.split(".")
        val r = IntArray(4)
        for (i in 0 until minOf(4, parts.size)) {
            r[i] = parts[i].toIntOrNull() ?: 0
        }
        return r
    }

    private fun showNotification(project: Project, latest: String, downloadUrl: String, notes: String) {
        ApplicationManager.getApplication().invokeLater {
            try {
                val dialog = UpdateDialog(project, CURRENT_VERSION, latest, notes, downloadUrl)
                dialog.show()
            } catch (_: Exception) {
                // Fallback to balloon notification if dialog fails
                val notification = NotificationGroupManager.getInstance()
                    .getNotificationGroup("O360 SAST")
                    .createNotification("O360 SAST: update available",
                        "v$latest is available (you have v$CURRENT_VERSION)",
                        NotificationType.INFORMATION)
                if (downloadUrl.isNotBlank()) {
                    notification.addAction(NotificationAction.createSimple("Open download page") {
                        try { BrowserUtil.browse(downloadUrl) } catch (_: Exception) {}
                    })
                }
                notification.notify(project)
            }
        }
    }
}
