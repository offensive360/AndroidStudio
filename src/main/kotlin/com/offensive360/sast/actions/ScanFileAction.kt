package com.offensive360.sast.actions

import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.offensive360.sast.util.FileCollector
import java.io.File

class ScanFileAction : BaseScanAction() {
    override fun getFiles(e: AnActionEvent): List<File> {
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE) ?: return emptyList()
        return FileCollector.collectSingleFile(vf)
    }

    override fun getScanLabel(e: AnActionEvent): String =
        e.getData(CommonDataKeys.VIRTUAL_FILE)?.name ?: "File"

    override fun update(e: AnActionEvent) {
        val vf = e.getData(CommonDataKeys.VIRTUAL_FILE)
        e.presentation.isEnabledAndVisible = e.project != null && vf != null && !vf.isDirectory
    }
}
