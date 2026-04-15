package com.offensive360.sast.actions

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.offensive360.sast.update.PluginUpdateChecker

class CheckUpdateAction : AnAction("Check for Updates", "Check for Offensive 360 plugin updates", null) {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        // Force check by resetting the throttle
        PluginUpdateChecker.forceCheckAsync(project)
    }

    override fun getActionUpdateThread() = com.intellij.openapi.actionSystem.ActionUpdateThread.BGT
}
