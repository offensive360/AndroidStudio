package com.offensive360.sast.toolwindow

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import com.intellij.util.ui.JBUI
import com.offensive360.sast.models.Finding
import com.offensive360.sast.models.Severity
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

class SecurityFindingsPanel(private val project: Project) {

    val component: JComponent = buildUI()
    private lateinit var table: JBTable
    private lateinit var tableModel: FindingsTableModel
    private lateinit var statusLabel: JBLabel
    private lateinit var detailPanel: JPanel
    private lateinit var detailTitle: JLabel
    private lateinit var detailBody: JTextArea
    private var currentFindings: List<Finding> = emptyList()

    private fun buildUI(): JComponent {
        val root = JPanel(BorderLayout())
        root.background = JBColor.background()

        // Status bar at top
        statusLabel = JBLabel("No findings — run a scan to get started")
        statusLabel.border = JBUI.Borders.empty(4, 8)
        root.add(statusLabel, BorderLayout.NORTH)

        // Main split pane: table on left, details on right
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.resizeWeight = 0.6

        // Findings table
        tableModel = FindingsTableModel()
        table = JBTable(tableModel)
        table.setDefaultRenderer(Object::class.java, FindingsCellRenderer())
        table.tableHeader.reorderingAllowed = false
        table.columnModel.getColumn(0).preferredWidth = 80   // Severity
        table.columnModel.getColumn(1).preferredWidth = 300  // Title
        table.columnModel.getColumn(2).preferredWidth = 250  // File
        table.columnModel.getColumn(3).preferredWidth = 60   // Line
        table.selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION

        table.selectionModel.addListSelectionListener {
            val row = table.selectedRow
            if (row >= 0 && row < currentFindings.size) {
                showDetail(currentFindings[row])
            }
        }

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val row = table.rowAtPoint(e.point)
                    if (row >= 0 && row < currentFindings.size) {
                        navigateToFinding(currentFindings[row])
                    }
                }
            }
        })

        splitPane.topComponent = JBScrollPane(table)

        // Detail panel
        detailPanel = JPanel(BorderLayout())
        detailPanel.border = JBUI.Borders.empty(8)
        detailTitle = JLabel("Select a finding for details")
        detailTitle.font = detailTitle.font.deriveFont(Font.BOLD, 13f)
        detailBody = JTextArea()
        detailBody.isEditable = false
        detailBody.lineWrap = true
        detailBody.wrapStyleWord = true
        detailBody.background = JBColor.background()
        detailBody.border = JBUI.Borders.empty(4, 0)
        detailPanel.add(detailTitle, BorderLayout.NORTH)
        detailPanel.add(JBScrollPane(detailBody), BorderLayout.CENTER)
        splitPane.bottomComponent = detailPanel

        root.add(splitPane, BorderLayout.CENTER)
        return root
    }

    fun showFindings(findings: List<Finding>) {
        ApplicationManager.getApplication().invokeLater {
            currentFindings = findings
            tableModel.setFindings(findings)
            val critical = findings.count { it.severity == Severity.CRITICAL }
            val high = findings.count { it.severity == Severity.HIGH }
            val medium = findings.count { it.severity == Severity.MEDIUM }
            val low = findings.count { it.severity == Severity.LOW }
            statusLabel.text = if (findings.isEmpty()) {
                "No findings"
            } else {
                "${findings.size} findings — Critical: $critical  High: $high  Medium: $medium  Low: $low"
            }
            if (findings.isNotEmpty()) table.setRowSelectionInterval(0, 0)
        }
    }

    fun clearFindings() {
        ApplicationManager.getApplication().invokeLater {
            currentFindings = emptyList()
            tableModel.setFindings(emptyList())
            statusLabel.text = "No findings"
            detailTitle.text = "Select a finding for details"
            detailBody.text = ""
        }
    }

    fun setStatus(message: String) {
        ApplicationManager.getApplication().invokeLater {
            statusLabel.text = message
        }
    }

    private fun showDetail(finding: Finding) {
        detailTitle.text = "[${finding.severity.label}] ${finding.title}"
        val sb = StringBuilder()
        sb.appendLine("File: ${finding.fileName}  Line: ${finding.line}")
        sb.appendLine()
        if (finding.vulnerability.isNotBlank()) {
            sb.appendLine(finding.vulnerability)
            sb.appendLine()
        }
        if (!finding.effect.isNullOrBlank()) {
            sb.appendLine("Impact:")
            sb.appendLine(finding.effect)
            sb.appendLine()
        }
        if (!finding.recommendation.isNullOrBlank()) {
            sb.appendLine("Recommendation:")
            sb.appendLine(finding.recommendation)
            sb.appendLine()
        }
        if (!finding.codeSnippet.isNullOrBlank()) {
            sb.appendLine("Code:")
            sb.appendLine(finding.codeSnippet)
        }
        detailBody.text = sb.toString()
        detailBody.caretPosition = 0
    }

    private fun navigateToFinding(finding: Finding) {
        ApplicationManager.getApplication().invokeLater {
            val vf: VirtualFile? = findVirtualFile(finding)
            if (vf != null) {
                val fileEditorManager = FileEditorManager.getInstance(project)
                fileEditorManager.openFile(vf, true)
                val editor = fileEditorManager.selectedTextEditor ?: return@invokeLater
                val line = (finding.line - 1).coerceAtLeast(0)
                val doc = editor.document
                if (line < doc.lineCount) {
                    val offset = doc.getLineStartOffset(line)
                    editor.caretModel.moveToOffset(offset)
                    editor.scrollingModel.scrollToCaret(com.intellij.openapi.editor.ScrollType.CENTER)
                }
            }
        }
    }

    private fun findVirtualFile(finding: Finding): VirtualFile? {
        // Try full path first
        if (finding.filePath.isNotBlank()) {
            LocalFileSystem.getInstance().findFileByPath(finding.filePath)?.let { return it }
        }
        // Search by file name in project
        val roots = com.intellij.openapi.roots.ProjectRootManager.getInstance(project).contentRoots
        for (root in roots) {
            val found = findInTree(root, finding.fileName)
            if (found != null) return found
        }
        return null
    }

    private fun findInTree(dir: VirtualFile, name: String): VirtualFile? {
        if (!dir.isDirectory) return null
        for (child in dir.children) {
            if (child.isDirectory) findInTree(child, name)?.let { return it }
            else if (child.name == name) return child
        }
        return null
    }

    inner class FindingsTableModel : AbstractTableModel() {
        private val columns = arrayOf("Severity", "Title", "File", "Line")
        private var findings: List<Finding> = emptyList()

        fun setFindings(f: List<Finding>) {
            findings = f.sortedWith(compareByDescending { it.riskLevel })
            fireTableDataChanged()
        }

        override fun getRowCount() = findings.size
        override fun getColumnCount() = columns.size
        override fun getColumnName(col: Int) = columns[col]

        override fun getValueAt(row: Int, col: Int): Any {
            val f = findings[row]
            return when (col) {
                0 -> f.severity.label
                1 -> f.title
                2 -> f.fileName
                3 -> f.line.toString()
                else -> ""
            }
        }

        fun getFinding(row: Int): Finding = findings[row]
    }

    inner class FindingsCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable, value: Any?, isSelected: Boolean,
            hasFocus: Boolean, row: Int, column: Int
        ): Component {
            val comp = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            if (column == 0 && !isSelected) {
                val finding = tableModel.getFinding(row)
                background = Color.decode(finding.severity.color).let {
                    Color(it.red, it.green, it.blue, 60)
                }
            }
            return comp
        }
    }
}
