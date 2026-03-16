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
import java.io.File

abstract class BaseScanAction : AnAction() {

    abstract fun getFiles(e: AnActionEvent): List<File>
    abstract fun getScanLabel(e: AnActionEvent): String

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val settings = O360Settings.getInstance()

        if (!settings.isConfigured) {
            notify(project, "O360 SAST: Please configure endpoint and access token in File → Settings → Tools → O360 SAST", NotificationType.WARNING)
            return
        }

        val files = getFiles(e)
        if (files.isEmpty()) {
            notify(project, "O360 SAST: No scannable files found", NotificationType.INFORMATION)
            return
        }

        val label = getScanLabel(e)
        val service = SecurityFindingsService.getInstance(project)

        // Open the tool window
        ApplicationManager.getApplication().invokeLater {
            ToolWindowManager.getInstance(project).getToolWindow("O360 Security Findings")?.show()
        }

        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "O360 SAST: Scanning $label…", true) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = true
                service.setStatus("Scanning $label…")

                try {
                    val result = O360ApiClient.instance.scan(files, label) { msg ->
                        indicator.text = msg
                        service.setStatus(msg)
                    }

                    service.showFindings(result.findings)

                    val count = result.findings.size
                    val msg = if (count == 0) "No findings in $label" else "Found $count finding${if (count != 1) "s" else ""} in $label"
                    notify(project, msg, if (count == 0) NotificationType.INFORMATION else NotificationType.WARNING)

                } catch (ex: Exception) {
                    service.setStatus("Scan failed: ${ex.message}")
                    notify(project, "O360 SAST scan failed: ${ex.message}", NotificationType.ERROR)
                }
            }
        })
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
