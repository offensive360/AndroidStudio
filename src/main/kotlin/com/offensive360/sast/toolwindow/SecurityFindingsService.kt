package com.offensive360.sast.toolwindow

import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import com.offensive360.sast.models.Finding

@Service(Service.Level.PROJECT)
class SecurityFindingsService(private val project: Project) {

    var toolWindowPanel: SecurityFindingsPanel? = null

    fun showFindings(findings: List<Finding>) {
        toolWindowPanel?.showFindings(findings)
    }

    fun clearFindings() {
        toolWindowPanel?.clearFindings()
    }

    fun setStatus(message: String) {
        toolWindowPanel?.setStatus(message)
    }

    companion object {
        fun getInstance(project: Project): SecurityFindingsService =
            project.getService(SecurityFindingsService::class.java)
    }
}
