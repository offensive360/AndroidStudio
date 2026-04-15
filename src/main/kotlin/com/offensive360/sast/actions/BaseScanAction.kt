package com.offensive360.sast.actions

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindowManager
import com.offensive360.sast.api.O360ApiClient
import com.offensive360.sast.settings.O360Settings
import com.offensive360.sast.toolwindow.SecurityFindingsService
import com.offensive360.sast.update.PluginUpdateChecker
import com.offensive360.sast.util.ScanCache
import java.io.File
import java.net.SocketTimeoutException
import java.net.UnknownHostException

abstract class BaseScanAction : AnAction() {

    abstract fun getFiles(e: AnActionEvent): List<File>
    abstract fun getScanLabel(e: AnActionEvent): String

    companion object {
        private val activeScans = java.util.concurrent.ConcurrentHashMap<String, Boolean>()

        fun isScanInProgress(project: Project): Boolean =
            activeScans[project.basePath ?: ""] == true

        fun setScanInProgress(project: Project, value: Boolean) {
            val key = project.basePath ?: ""
            if (value) activeScans[key] = true else activeScans.remove(key)
        }
    }

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val settings = O360Settings.getInstance()

        if (!settings.isConfigured) {
            notify(project, "O360 SAST: Please configure endpoint and access token in File \u2192 Settings \u2192 Tools \u2192 O360 SAST", NotificationType.WARNING)
            return
        }

        if (isScanInProgress(project)) {
            notify(project, "O360 SAST: A scan is already in progress for this project. Please wait for it to finish.", NotificationType.WARNING)
            return
        }

        // Option D — fire-and-forget plugin-update check (silent if server lacks endpoint)
        try { PluginUpdateChecker.checkAsync(project) } catch (_: Exception) {}

        val files = getFiles(e)
        if (files.isEmpty()) {
            notify(project, "O360 SAST: No scannable files found", NotificationType.INFORMATION)
            return
        }

        val label = getScanLabel(e)
        val service = SecurityFindingsService.getInstance(project)
        val projectBasePath = project.basePath

        // Open the tool window
        ApplicationManager.getApplication().invokeLater {
            ToolWindowManager.getInstance(project).getToolWindow("O360 Security Findings")?.show()
        }

        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "O360 SAST: Scanning $label\u2026", true) {
            override fun run(indicator: ProgressIndicator) {
                setScanInProgress(project, true)
                try {
                    indicator.isIndeterminate = false
                    indicator.fraction = 0.0

                    // Incremental scanning: check if files changed since last scan
                    indicator.text = "Computing file hashes\u2026"
                    service.setStatus("Computing file hashes\u2026")
                    val currentHashes = ScanCache.computeFileHashes(files)

                    if (projectBasePath != null) {
                        val cached = ScanCache.load(projectBasePath)
                        if (cached != null && !ScanCache.hasFilesChanged(currentHashes, cached.fileHashes)) {
                            // No files changed — use cached results
                            service.showFindings(cached.findings)
                            val count = cached.findings.size
                            val msg = "No files changed since last scan. Showing $count cached finding${if (count != 1) "s" else ""}"
                            notify(project, msg, NotificationType.INFORMATION)
                            service.setStatus(msg)
                            return
                        }
                    }

                    indicator.fraction = 0.1
                    indicator.text = "Scanning $label\u2026"
                    service.setStatus("Scanning $label\u2026")

                    val result = O360ApiClient.instance.scan(files, label) { msg ->
                        indicator.text = msg
                        service.setStatus(msg)
                    }

                    service.showFindings(result.findings)

                    // Save results to cache
                    if (projectBasePath != null) {
                        try {
                            ScanCache.save(projectBasePath, result.findings, currentHashes, result.findings.size)
                        } catch (_: Exception) {
                            // Cache save failure is non-fatal
                        }
                    }

                    val count = result.findings.size
                    val msg = if (count == 0) "No findings in $label" else "Found $count finding${if (count != 1) "s" else ""} in $label"
                    notify(project, msg, if (count == 0) NotificationType.INFORMATION else NotificationType.WARNING)

                } catch (ex: Exception) {
                    val userMessage = when (ex) {
                        is SocketTimeoutException ->
                            "Connection timed out. Check your server URL and network."
                        is UnknownHostException ->
                            "Cannot reach server. Check your endpoint URL."
                        else -> {
                            // Sanitize: strip raw exception class names, show only the message
                            val raw = ex.message ?: "An unexpected error occurred"
                            raw.replace(Regex("^[a-zA-Z_.]+Exception:\\s*"), "")
                        }
                    }
                    service.setStatus("Scan failed: $userMessage")
                    notify(project, "O360 SAST scan failed: $userMessage", NotificationType.ERROR)
                } finally {
                    setScanInProgress(project, false)
                }
            }
        })
    }

    override fun getActionUpdateThread(): com.intellij.openapi.actionSystem.ActionUpdateThread {
        return com.intellij.openapi.actionSystem.ActionUpdateThread.BGT
    }

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.project != null
    }

    private fun notify(project: Project, message: String, type: NotificationType) {
        NotificationGroupManager.getInstance()
            .getNotificationGroup("O360 SAST")
            .createNotification(message, type)
            .notify(project)
    }
}
