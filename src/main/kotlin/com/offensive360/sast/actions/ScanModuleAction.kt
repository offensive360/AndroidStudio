package com.offensive360.sast.actions

import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.module.ModuleUtil
import com.offensive360.sast.util.FileCollector
import java.io.File

class ScanModuleAction : BaseScanAction() {
    override fun getFiles(e: AnActionEvent): List<File> {
        val project = e.project ?: return emptyList()
        val vf = e.getData(com.intellij.openapi.actionSystem.CommonDataKeys.VIRTUAL_FILE)
        val module = (if (vf != null) ModuleUtil.findModuleForFile(vf, project) else null)
            ?: return FileCollector.collectProjectFiles(project)
        return FileCollector.collectModuleFiles(module)
    }

    override fun getScanLabel(e: AnActionEvent): String {
        val project = e.project ?: return "Module"
        val vf = e.getData(com.intellij.openapi.actionSystem.CommonDataKeys.VIRTUAL_FILE) ?: return "Module"
        return ModuleUtil.findModuleForFile(vf, project)?.name ?: "Module"
    }
}
