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
import com.offensive360.sast.knowledge.VulnerabilityKnowledgeBase
import com.offensive360.sast.models.Finding
import com.offensive360.sast.models.Severity
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.net.URI
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
    private lateinit var tabbedPane: JTabbedPane

    // Detail tab components
    private lateinit var severityBadge: JLabel
    private lateinit var descriptionArea: JTextArea
    private lateinit var impactArea: JTextArea
    private lateinit var detailCodeArea: JTextArea
    private lateinit var detailFileLabel: JLabel

    // Fix tab components
    private lateinit var recommendationArea: JTextArea
    private lateinit var vulnerableCodeArea: JTextArea
    private lateinit var secureCodeArea: JTextArea

    // References tab components
    private lateinit var referencesPanel: JPanel

    private var currentFindings: List<Finding> = emptyList()

    companion object {
        private val SEVERITY_CRITICAL = JBColor(Color.decode("#FF3B3B"), Color.decode("#FF3B3B"))
        private val SEVERITY_HIGH = JBColor(Color.decode("#FF8C00"), Color.decode("#FF8C00"))
        private val SEVERITY_MEDIUM = JBColor(Color.decode("#FFD700"), Color.decode("#FFD700"))
        private val SEVERITY_LOW = JBColor(Color.decode("#4FC3F7"), Color.decode("#4FC3F7"))
        private val SEVERITY_INFO = JBColor(Color.decode("#90A4AE"), Color.decode("#90A4AE"))

        private val CODE_BG = JBColor(Color(40, 42, 48), Color(40, 42, 48))
        private val CODE_FG = JBColor(Color(212, 212, 212), Color(212, 212, 212))
        private val FIX_BG = JBColor(Color(30, 50, 80), Color(30, 50, 80))
        private val VULN_CODE_BG = JBColor(Color(60, 30, 30), Color(60, 30, 30))
        private val SECURE_CODE_BG = JBColor(Color(30, 60, 35), Color(30, 60, 35))

        private val MONO_FONT = Font("Consolas", Font.PLAIN, 12).let { f ->
            if (f.family == "Consolas") f else Font(Font.MONOSPACED, Font.PLAIN, 12)
        }
    }

    private fun buildUI(): JComponent {
        val root = JPanel(BorderLayout())
        root.background = JBColor.background()

        // Status bar at top
        statusLabel = JBLabel("No findings \u2014 run a scan to get started")
        statusLabel.border = JBUI.Borders.empty(4, 8)
        root.add(statusLabel, BorderLayout.NORTH)

        // Main split pane: table on top, details on bottom
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.resizeWeight = 0.45

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
            val viewRow = table.selectedRow
            if (viewRow >= 0) {
                val modelRow = table.convertRowIndexToModel(viewRow)
                if (modelRow >= 0 && modelRow < currentFindings.size) {
                    showDetail(tableModel.getFinding(modelRow))
                }
            }
        }

        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2) {
                    val viewRow = table.rowAtPoint(e.point)
                    if (viewRow >= 0) {
                        val modelRow = table.convertRowIndexToModel(viewRow)
                        if (modelRow >= 0 && modelRow < currentFindings.size) {
                            navigateToFinding(tableModel.getFinding(modelRow))
                        }
                    }
                }
            }
        })

        // Enter key listener for keyboard navigation
        table.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER) {
                    val viewRow = table.selectedRow
                    if (viewRow >= 0) {
                        val modelRow = table.convertRowIndexToModel(viewRow)
                        if (modelRow >= 0 && modelRow < currentFindings.size) {
                            navigateToFinding(tableModel.getFinding(modelRow))
                        }
                    }
                    e.consume()
                }
            }
        })

        splitPane.topComponent = JBScrollPane(table)

        // Detail panel with tabbed interface
        detailPanel = JPanel(BorderLayout())
        detailPanel.border = JBUI.Borders.empty(4)

        detailTitle = JLabel("Select a finding for details")
        detailTitle.font = detailTitle.font.deriveFont(Font.BOLD, 14f)
        detailTitle.border = JBUI.Borders.empty(4, 4, 8, 4)
        detailPanel.add(detailTitle, BorderLayout.NORTH)

        tabbedPane = JTabbedPane(JTabbedPane.TOP)
        tabbedPane.tabLayoutPolicy = JTabbedPane.SCROLL_TAB_LAYOUT

        // --- Details Tab ---
        tabbedPane.addTab("Details", buildDetailsTab())

        // --- How to Fix Tab ---
        tabbedPane.addTab("How to Fix", buildFixTab())

        // --- References Tab ---
        tabbedPane.addTab("References", buildReferencesTab())

        detailPanel.add(tabbedPane, BorderLayout.CENTER)
        splitPane.bottomComponent = detailPanel

        root.add(splitPane, BorderLayout.CENTER)
        return root
    }

    private fun buildDetailsTab(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.background = JBColor.background()
        panel.border = JBUI.Borders.empty(8)

        // Severity badge + file info row
        val headerRow = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        headerRow.isOpaque = false
        headerRow.alignmentX = Component.LEFT_ALIGNMENT
        headerRow.maximumSize = Dimension(Int.MAX_VALUE, 30)

        severityBadge = JLabel()
        severityBadge.isOpaque = true
        severityBadge.font = severityBadge.font.deriveFont(Font.BOLD, 11f)
        severityBadge.foreground = Color.WHITE
        severityBadge.border = JBUI.Borders.empty(2, 8, 2, 8)
        headerRow.add(severityBadge)

        detailFileLabel = JLabel()
        detailFileLabel.foreground = JBColor.GRAY
        detailFileLabel.font = detailFileLabel.font.deriveFont(Font.PLAIN, 11f)
        headerRow.add(detailFileLabel)

        panel.add(headerRow)
        panel.add(Box.createVerticalStrut(10))

        // Description section
        val descLabel = createSectionLabel("Description")
        descLabel.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(descLabel)
        panel.add(Box.createVerticalStrut(4))

        descriptionArea = createReadOnlyTextArea()
        descriptionArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(descriptionArea)
        panel.add(Box.createVerticalStrut(12))

        // Impact section
        val impactLabel = createSectionLabel("Impact")
        impactLabel.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(impactLabel)
        panel.add(Box.createVerticalStrut(4))

        impactArea = createReadOnlyTextArea()
        impactArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(impactArea)
        panel.add(Box.createVerticalStrut(12))

        // Affected code section
        val codeLabel = createSectionLabel("Affected Code")
        codeLabel.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(codeLabel)
        panel.add(Box.createVerticalStrut(4))

        detailCodeArea = createCodeArea(CODE_BG, CODE_FG)
        detailCodeArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(wrapCodeArea(detailCodeArea, CODE_BG))
        panel.add(Box.createVerticalStrut(8))

        // Glue at bottom
        panel.add(Box.createVerticalGlue())

        val scroll = JBScrollPane(panel)
        scroll.border = JBUI.Borders.empty()
        scroll.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
        return scroll
    }

    private fun buildFixTab(): JComponent {
        val panel = JPanel()
        panel.layout = BoxLayout(panel, BoxLayout.Y_AXIS)
        panel.background = JBColor.background()
        panel.border = JBUI.Borders.empty(8)

        // Recommendation section with blue-tinted highlight
        val recLabel = createSectionLabel("Recommendation")
        recLabel.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(recLabel)
        panel.add(Box.createVerticalStrut(4))

        recommendationArea = createReadOnlyTextArea()
        recommendationArea.background = FIX_BG
        recommendationArea.foreground = JBColor(Color(180, 210, 255), Color(180, 210, 255))
        recommendationArea.border = BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 3, 0, 0, JBColor(Color(80, 140, 220), Color(80, 140, 220))),
            JBUI.Borders.empty(8, 10)
        )
        recommendationArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(recommendationArea)
        panel.add(Box.createVerticalStrut(16))

        // Vulnerable code section
        val vulnHeader = createSectionWithCopyButton("Vulnerable Code", "Copy Vulnerable Code") {
            copyToClipboard(vulnerableCodeArea.text)
        }
        vulnHeader.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(vulnHeader)
        panel.add(Box.createVerticalStrut(4))

        vulnerableCodeArea = createCodeArea(VULN_CODE_BG, JBColor(Color(255, 180, 180), Color(255, 180, 180)))
        vulnerableCodeArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(wrapCodeArea(vulnerableCodeArea, VULN_CODE_BG))
        panel.add(Box.createVerticalStrut(16))

        // Secure code section (shows recommendation as secure pattern)
        val secureHeader = createSectionWithCopyButton("Secure Code Pattern", "Copy Secure Code") {
            copyToClipboard(secureCodeArea.text)
        }
        secureHeader.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(secureHeader)
        panel.add(Box.createVerticalStrut(4))

        secureCodeArea = createCodeArea(SECURE_CODE_BG, JBColor(Color(180, 255, 180), Color(180, 255, 180)))
        secureCodeArea.alignmentX = Component.LEFT_ALIGNMENT
        panel.add(wrapCodeArea(secureCodeArea, SECURE_CODE_BG))
        panel.add(Box.createVerticalStrut(8))

        panel.add(Box.createVerticalGlue())

        val scroll = JBScrollPane(panel)
        scroll.border = JBUI.Borders.empty()
        scroll.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
        return scroll
    }

    private fun buildReferencesTab(): JComponent {
        referencesPanel = JPanel()
        referencesPanel.layout = BoxLayout(referencesPanel, BoxLayout.Y_AXIS)
        referencesPanel.background = JBColor.background()
        referencesPanel.border = JBUI.Borders.empty(8)

        val scroll = JBScrollPane(referencesPanel)
        scroll.border = JBUI.Borders.empty()
        scroll.horizontalScrollBarPolicy = ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER
        return scroll
    }

    // --- Helper UI builders ---

    private fun createSectionLabel(text: String): JLabel {
        val label = JLabel(text)
        label.font = label.font.deriveFont(Font.BOLD, 12f)
        label.foreground = JBColor(Color(180, 180, 180), Color(180, 180, 180))
        label.border = JBUI.Borders.empty(0, 0, 2, 0)
        return label
    }

    private fun createReadOnlyTextArea(): JTextArea {
        val area = JTextArea()
        area.isEditable = false
        area.lineWrap = true
        area.wrapStyleWord = true
        area.background = JBColor.background()
        area.foreground = JBColor.foreground()
        area.font = area.font.deriveFont(Font.PLAIN, 12f)
        area.border = JBUI.Borders.empty(4, 4)
        area.maximumSize = Dimension(Int.MAX_VALUE, Int.MAX_VALUE)
        return area
    }

    private fun createCodeArea(bg: Color, fg: Color): JTextArea {
        val area = JTextArea()
        area.isEditable = false
        area.lineWrap = false
        area.font = MONO_FONT
        area.background = bg
        area.foreground = fg
        area.border = JBUI.Borders.empty(8)
        area.maximumSize = Dimension(Int.MAX_VALUE, Int.MAX_VALUE)
        return area
    }

    private fun wrapCodeArea(codeArea: JTextArea, bg: Color): JComponent {
        val wrapper = JPanel(BorderLayout())
        wrapper.background = bg
        wrapper.border = BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(JBColor(Color(60, 63, 70), Color(60, 63, 70)), 1),
            JBUI.Borders.empty()
        )
        val scroll = JBScrollPane(codeArea)
        scroll.border = JBUI.Borders.empty()
        scroll.preferredSize = Dimension(0, 120)
        scroll.maximumSize = Dimension(Int.MAX_VALUE, 200)
        wrapper.add(scroll, BorderLayout.CENTER)
        wrapper.alignmentX = Component.LEFT_ALIGNMENT
        wrapper.maximumSize = Dimension(Int.MAX_VALUE, 200)
        return wrapper
    }

    private fun createSectionWithCopyButton(title: String, buttonText: String, action: () -> Unit): JPanel {
        val row = JPanel(BorderLayout())
        row.isOpaque = false
        row.maximumSize = Dimension(Int.MAX_VALUE, 24)

        val label = createSectionLabel(title)
        row.add(label, BorderLayout.WEST)

        val copyBtn = JButton(buttonText)
        copyBtn.font = copyBtn.font.deriveFont(Font.PLAIN, 10f)
        copyBtn.margin = JBUI.insets(1, 6, 1, 6)
        copyBtn.isFocusable = false
        copyBtn.addActionListener { action() }
        val btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0))
        btnPanel.isOpaque = false
        btnPanel.add(copyBtn)
        row.add(btnPanel, BorderLayout.EAST)

        return row
    }

    private fun copyToClipboard(text: String) {
        if (text.isNotBlank()) {
            val selection = StringSelection(text)
            Toolkit.getDefaultToolkit().systemClipboard.setContents(selection, null)
        }
    }

    private fun severityColor(severity: Severity): Color = when (severity) {
        Severity.CRITICAL -> SEVERITY_CRITICAL
        Severity.HIGH -> SEVERITY_HIGH
        Severity.MEDIUM -> SEVERITY_MEDIUM
        Severity.LOW -> SEVERITY_LOW
        Severity.INFO -> SEVERITY_INFO
    }

    private fun createClickableLink(text: String, url: String): JLabel {
        val link = JLabel("<html><a href='$url' style='color:#589df6;'>$text</a></html>")
        link.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        link.alignmentX = Component.LEFT_ALIGNMENT
        link.border = JBUI.Borders.empty(2, 0)
        link.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                try {
                    Desktop.getDesktop().browse(URI(url))
                } catch (_: Exception) {
                    // Silently fail if browser cannot be opened
                }
            }
        })
        return link
    }

    // --- Core logic ---

    fun showFindings(findings: List<Finding>) {
        ApplicationManager.getApplication().invokeLater {
            // RECONCILIATION CONTRACT (2026-04-08):
            //   The tool window shows EXACTLY what the server returned — no filtering,
            //   no dedup, no client-side drops. UI count == server count, always.
            //   The post-render assertion below logs a warning if drift ever occurs.
            //
            // Wipe first so stale rows from a previous scan can never leak through.
            tableModel.setFindings(emptyList())
            currentFindings = emptyList()

            // Replace the entire list with the server response as-is. No filter.
            currentFindings = findings
            tableModel.setFindings(findings)

            val critical = findings.count { it.severity == Severity.CRITICAL }
            val high = findings.count { it.severity == Severity.HIGH }
            val medium = findings.count { it.severity == Severity.MEDIUM }
            val low = findings.count { it.severity == Severity.LOW }

            // Reconciliation assertion: the UI table must now contain exactly findings.size rows.
            val uiCount = tableModel.rowCount
            if (uiCount != findings.size) {
                statusLabel.text = "WARN: count drift - server=${findings.size}, ui=$uiCount"
            } else {
                statusLabel.text = if (findings.isEmpty()) {
                    "No findings"
                } else {
                    "${findings.size} findings \u2014 Critical: $critical  High: $high  Medium: $medium  Low: $low"
                }
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
            clearDetailTabs()
        }
    }

    fun setStatus(message: String) {
        ApplicationManager.getApplication().invokeLater {
            statusLabel.text = message
        }
    }

    private fun clearDetailTabs() {
        severityBadge.text = ""
        severityBadge.isVisible = false
        detailFileLabel.text = ""
        descriptionArea.text = ""
        impactArea.text = ""
        detailCodeArea.text = ""
        recommendationArea.text = ""
        vulnerableCodeArea.text = ""
        secureCodeArea.text = ""
        referencesPanel.removeAll()
        referencesPanel.revalidate()
        referencesPanel.repaint()
    }

    private fun showDetail(finding: Finding) {
        detailTitle.text = finding.title

        // --- Details Tab ---
        severityBadge.text = " ${finding.severity.label} "
        severityBadge.background = severityColor(finding.severity)
        severityBadge.isVisible = true

        detailFileLabel.text = "${finding.fileName} : ${finding.line}"

        // Look up offline KB for fallback content
        val kbEntry = VulnerabilityKnowledgeBase.lookup(finding.type)
                   ?: VulnerabilityKnowledgeBase.lookup(finding.title)

        val description = finding.vulnerability.takeIf { it.isNotBlank() }
            ?: kbEntry?.description?.takeIf { it.isNotBlank() }
        val impact = finding.effect?.takeIf { it.isNotBlank() }
            ?: kbEntry?.impact?.takeIf { it.isNotBlank() }
        val howToFix = finding.recommendation?.takeIf { it.isNotBlank() }
            ?: kbEntry?.howToFix?.takeIf { it.isNotBlank() }

        descriptionArea.text = description ?: "Loading description..."
        descriptionArea.caretPosition = 0

        impactArea.text = impact ?: "Loading impact information..."
        impactArea.caretPosition = 0

        detailCodeArea.text = finding.codeSnippet ?: "No code snippet available."
        detailCodeArea.caretPosition = 0

        // --- Fix Tab ---
        recommendationArea.text = howToFix ?: "Loading fix recommendations..."
        recommendationArea.caretPosition = 0

        // Trigger internet fetch if offline KB didn't cover this vulnerability
        if (description == null || howToFix == null) {
            fetchOnlineKBAsync(finding.type.ifBlank { finding.title })
        }

        vulnerableCodeArea.text = finding.codeSnippet ?: "No vulnerable code snippet available."
        vulnerableCodeArea.caretPosition = 0

        // Derive a secure code hint from the recommendation
        secureCodeArea.text = if (!finding.recommendation.isNullOrBlank()) {
            "// Secure pattern based on recommendation:\n// ${finding.recommendation!!.replace("\n", "\n// ")}"
        } else {
            "// No secure code pattern available."
        }
        secureCodeArea.caretPosition = 0

        // --- References Tab ---
        referencesPanel.removeAll()

        val refTitle = createSectionLabel("Related References")
        refTitle.alignmentX = Component.LEFT_ALIGNMENT
        referencesPanel.add(refTitle)
        referencesPanel.add(Box.createVerticalStrut(8))

        // Extract CWE references from vulnerability type/text
        val cwePattern = Regex("CWE-\\d+", RegexOption.IGNORE_CASE)
        val cweMatches = mutableSetOf<String>()
        cweMatches.addAll(cwePattern.findAll(finding.vulnerability).map { it.value.uppercase() })
        cweMatches.addAll(cwePattern.findAll(finding.title).map { it.value.uppercase() })
        cweMatches.addAll(cwePattern.findAll(finding.type).map { it.value.uppercase() })
        if (!finding.effect.isNullOrBlank()) {
            cweMatches.addAll(cwePattern.findAll(finding.effect!!).map { it.value.uppercase() })
        }
        if (!finding.recommendation.isNullOrBlank()) {
            cweMatches.addAll(cwePattern.findAll(finding.recommendation!!).map { it.value.uppercase() })
        }

        // Map common vulnerability types to CWE if none found
        if (cweMatches.isEmpty()) {
            val typeLower = finding.type.lowercase()
            val titleLower = finding.title.lowercase()
            val vulnLower = finding.vulnerability.lowercase()
            val combined = "$typeLower $titleLower $vulnLower"

            val cweMap = mapOf(
                "sql injection" to "CWE-89",
                "sqli" to "CWE-89",
                "xss" to "CWE-79",
                "cross-site scripting" to "CWE-79",
                "command injection" to "CWE-78",
                "os command" to "CWE-78",
                "path traversal" to "CWE-22",
                "directory traversal" to "CWE-22",
                "hardcoded" to "CWE-798",
                "hard-coded" to "CWE-798",
                "insecure deserialization" to "CWE-502",
                "deseriali" to "CWE-502",
                "xxe" to "CWE-611",
                "xml external" to "CWE-611",
                "ssrf" to "CWE-918",
                "server-side request" to "CWE-918",
                "open redirect" to "CWE-601",
                "csrf" to "CWE-352",
                "cross-site request" to "CWE-352",
                "buffer overflow" to "CWE-120",
                "overflow" to "CWE-120",
                "weak crypto" to "CWE-327",
                "weak hash" to "CWE-328",
                "information disclosure" to "CWE-200",
                "info leak" to "CWE-200",
                "broken auth" to "CWE-287",
                "authentication" to "CWE-287",
                "insecure random" to "CWE-330",
                "predictable" to "CWE-330",
                "race condition" to "CWE-362",
                "null pointer" to "CWE-476",
                "null dereference" to "CWE-476",
                "log injection" to "CWE-117",
                "ldap injection" to "CWE-90",
                "xpath injection" to "CWE-643",
                "missing encryption" to "CWE-311",
                "cleartext" to "CWE-319",
                "insecure storage" to "CWE-922"
            )

            for ((keyword, cwe) in cweMap) {
                if (combined.contains(keyword)) {
                    cweMatches.add(cwe)
                    break
                }
            }
        }

        if (cweMatches.isNotEmpty()) {
            for (cwe in cweMatches.sorted()) {
                val cweId = cwe.removePrefix("CWE-")
                val link = createClickableLink(
                    "$cwe - MITRE",
                    "https://cwe.mitre.org/data/definitions/$cweId.html"
                )
                referencesPanel.add(link)
                referencesPanel.add(Box.createVerticalStrut(4))
            }
            referencesPanel.add(Box.createVerticalStrut(8))
        }

        // Collect all reference URLs, deduplicate by URL (case-insensitive)
        val allRefs = mutableListOf<Pair<String, String>>() // label -> url
        val seenUrls = mutableSetOf<String>()

        // Add KB references first (from VulnerabilityInfo.json - authoritative URLs)
        if (!kbEntry?.references.isNullOrBlank()) {
            kbEntry!!.references.split("\n").map { it.trim() }.filter { it.startsWith("http") }.forEach { ref ->
                val normalized = ref.trimEnd('/')
                if (seenUrls.add(normalized.lowercase())) {
                    val label = when {
                        ref.contains("owasp.org") -> "OWASP Reference"
                        ref.contains("cwe.mitre.org") -> "MITRE CWE Reference"
                        ref.contains("knowledge-base.offensive360.com") -> "O360 Knowledge Base"
                        else -> try { java.net.URL(ref).host } catch (_: Exception) { ref }
                    }
                    allRefs.add(label to ref)
                }
            }
        }

        // Only show KB links that actually exist in VulnerabilityInfo.json references
        // Never auto-generate KB URLs from titles (they may not exist on the website)

        // Render deduplicated references
        for ((label, url) in allRefs) {
            referencesPanel.add(createClickableLink(label, url))
            referencesPanel.add(Box.createVerticalStrut(4))
        }

        // General search link
        val searchLink = createClickableLink(
            "Search: ${finding.title} vulnerability fix",
            "https://www.google.com/search?q=${java.net.URLEncoder.encode("${finding.title} vulnerability fix", "UTF-8")}"
        )
        referencesPanel.add(searchLink)

        referencesPanel.add(Box.createVerticalGlue())
        referencesPanel.revalidate()
        referencesPanel.repaint()

        // Switch to Details tab
        tabbedPane.selectedIndex = 0
    }

    private val onlineKbCache = mutableMapOf<String, Map<String, String>>()

    private fun fetchOnlineKBAsync(vulnType: String) {
        if (vulnType.isBlank()) return
        val cacheKey = vulnType.lowercase().replace(Regex("[^a-z0-9]"), "-")
        if (onlineKbCache.containsKey(cacheKey)) {
            applyOnlineKB(onlineKbCache[cacheKey]!!)
            return
        }
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val slug = cacheKey.trim('-')
                val urls = listOf(
                    "https://knowledge-base.offensive360.com/api/vulnerabilities/$slug"
                )
                for (url in urls) {
                    try {
                        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                        conn.connectTimeout = 5000
                        conn.readTimeout = 5000
                        conn.setRequestProperty("Accept", "application/json,text/html")
                        if (conn.responseCode == 200) {
                            val body = conn.inputStream.bufferedReader().readText()
                            val result = mutableMapOf<String, String>()
                            // Try JSON parse first
                            try {
                                val json = org.json.JSONObject(body)
                                result["description"] = json.optString("description").ifBlank { json.optString("info") }
                                result["impact"] = json.optString("impact").ifBlank { json.optString("effect") }
                                result["howToFix"] = json.optString("recommendation").ifBlank { json.optString("howToFix") }
                            } catch (_: Exception) {
                                // HTML page — extract first paragraph as description
                                val para = Regex("<p[^>]*>(.*?)</p>", RegexOption.DOT_MATCHES_ALL)
                                    .find(body)?.groupValues?.get(1)
                                    ?.replace(Regex("<[^>]+>"), "")?.trim()
                                if (!para.isNullOrBlank()) result["description"] = para
                            }
                            if (result.isNotEmpty()) {
                                onlineKbCache[cacheKey] = result
                                ApplicationManager.getApplication().invokeLater { applyOnlineKB(result) }
                                break
                            }
                        }
                    } catch (_: Exception) {}
                }
            } catch (_: Exception) {}
        }
    }

    private fun applyOnlineKB(data: Map<String, String>) {
        val desc = data["description"]?.takeIf { it.isNotBlank() }
        val impact = data["impact"]?.takeIf { it.isNotBlank() }
        val fix = data["howToFix"]?.takeIf { it.isNotBlank() }

        if (desc != null && descriptionArea.text.startsWith("Loading")) {
            descriptionArea.text = desc
            descriptionArea.caretPosition = 0
        }
        if (impact != null && impactArea.text.startsWith("Loading")) {
            impactArea.text = impact
            impactArea.caretPosition = 0
        }
        if (fix != null && recommendationArea.text.startsWith("Loading")) {
            recommendationArea.text = fix
            recommendationArea.caretPosition = 0
        }
    }

    private fun navigateToFinding(finding: Finding) {
        ApplicationManager.getApplication().invokeLater {
            val vf: VirtualFile? = findVirtualFile(finding)
            if (vf == null) {
                javax.swing.JOptionPane.showMessageDialog(
                    null as java.awt.Component?,
                    "Could not locate the source file for this finding in the current project.\n\n" +
                    "File: ${if (finding.filePath.isNotBlank()) finding.filePath else finding.fileName}\n" +
                    "Line: ${finding.line}\n\n" +
                    "This finding may have come from a dashboard project uploaded from a different folder\n" +
                    "layout. Open the matching source file manually, or re-scan this project from the IDE\n" +
                    "so paths match your local layout.",
                    "Offensive 360 — Navigation",
                    javax.swing.JOptionPane.INFORMATION_MESSAGE
                )
                return@invokeLater
            }
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

    private fun findVirtualFile(finding: Finding): VirtualFile? {
        val lfs = LocalFileSystem.getInstance()
        // 1) Try the raw filePath as-is (absolute local path).
        if (finding.filePath.isNotBlank()) {
            lfs.findFileByPath(finding.filePath)?.let { return it }
        }

        val roots = com.intellij.openapi.roots.ProjectRootManager.getInstance(project).contentRoots
        val rel = finding.filePath.replace('\\', '/').trimStart('/')

        // 2) Try relative path under each content root, stripping zip-prefix segments.
        //    Project-agnostic: no hardcoded project name.
        if (rel.isNotBlank()) {
            val parts = rel.split('/')
            for (root in roots) {
                val rootPath = root.path.trimEnd('/')
                // Full relative first
                lfs.findFileByPath("$rootPath/$rel")?.let { return it }
                // Then progressively strip leading segments (handles "Foo-master/src/..." prefixes).
                for (start in 1 until parts.size) {
                    val sub = parts.subList(start, parts.size).joinToString("/")
                    lfs.findFileByPath("$rootPath/$sub")?.let { return it }
                }
            }
        }

        // 3) Final fallback: recursive basename search.
        val basename = if (finding.fileName.isNotBlank()) finding.fileName
                       else rel.substringAfterLast('/')
        if (basename.isNotBlank()) {
            for (root in roots) {
                val found = findInTree(root, basename)
                if (found != null) return found
            }
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
            findings = f.sortedWith(
                compareByDescending<Finding> { it.riskLevel }
                    .thenBy { it.line }
            )
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
                val modelRow = table.convertRowIndexToModel(row)
                if (modelRow in 0 until tableModel.rowCount) {
                    val finding = tableModel.getFinding(modelRow)
                    background = Color.decode(finding.severity.color).let {
                        Color(it.red, it.green, it.blue, 60)
                    }
                }
            }
            return comp
        }
    }
}
