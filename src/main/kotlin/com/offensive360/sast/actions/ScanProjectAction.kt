package com.offensive360.sast.actions

import com.intellij.openapi.actionSystem.AnActionEvent
import com.offensive360.sast.util.FileCollector
import java.io.File

class ScanProjectAction : BaseScanAction() {
    override fun getFiles(e: AnActionEvent): List<File> {
        val project = e.project ?: return emptyList()
        return FileCollector.collectProjectFiles(project)
    }

    override fun getScanLabel(e: AnActionEvent): String =
        e.project?.name ?: "Project"
}
