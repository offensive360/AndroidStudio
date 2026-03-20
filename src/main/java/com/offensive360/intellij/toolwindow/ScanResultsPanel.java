package com.offensive360.intellij.toolwindow;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileEditor.OpenFileDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.ui.table.JBTable;
import com.offensive360.intellij.kb.VulnerabilityKnowledgeBase;
import com.offensive360.intellij.models.DepVulnerability;
import com.offensive360.intellij.models.LangVulnerability;
import com.offensive360.intellij.models.LicenseIssue;
import com.offensive360.intellij.models.MalwareResult;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.Collections;
import java.util.List;

/**
 * Main panel for displaying Offensive360 scan results in the IDE tool window.
 * Contains four tabs: Language Vulnerabilities, Dependencies, Malware, Licenses.
 */
public class ScanResultsPanel extends JPanel implements ScanResultsService.ChangeListener {

    private final Project project;
    private final JBTabbedPane tabbedPane;
    private final CardLayout cardLayout;
    private final JPanel cardPanel;

    private static final String CARD_EMPTY = "empty";
    private static final String CARD_RESULTS = "results";

    // Tables
    private final JBTable langTable;
    private final JBTable depTable;
    private final JBTable malwareTable;
    private final JBTable licenseTable;

    // Models
    private final LangTableModel langModel;
    private final DepTableModel depModel;
    private final MalwareTableModel malwareModel;
    private final LicenseTableModel licenseModel;

    public ScanResultsPanel(Project project) {
        super(new BorderLayout());
        this.project = project;

        // Card layout: empty state vs results
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);

        // ── Empty state ───────────────────────────────────────────────
        JPanel emptyPanel = new JPanel(new GridBagLayout());
        JBLabel emptyLabel = new JBLabel("Run a scan to see results here");
        emptyLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        emptyPanel.add(emptyLabel);
        cardPanel.add(emptyPanel, CARD_EMPTY);

        // ── Tabbed results ────────────────────────────────────────────
        tabbedPane = new JBTabbedPane();

        langModel = new LangTableModel();
        langTable = createTable(langModel);
        addDoubleClickNavigation(langTable, this::navigateToLangVuln);
        addContextMenu(langTable, this::showLangFixGuidance);
        tabbedPane.addTab("Language Vulnerabilities", new JScrollPane(langTable));

        depModel = new DepTableModel();
        depTable = createTable(depModel);
        addContextMenu(depTable, this::showDepFixGuidance);
        tabbedPane.addTab("Dependencies", new JScrollPane(depTable));

        malwareModel = new MalwareTableModel();
        malwareTable = createTable(malwareModel);
        addContextMenu(malwareTable, null);
        tabbedPane.addTab("Malware", new JScrollPane(malwareTable));

        licenseModel = new LicenseTableModel();
        licenseTable = createTable(licenseModel);
        addContextMenu(licenseTable, null);
        tabbedPane.addTab("Licenses", new JScrollPane(licenseTable));

        cardPanel.add(tabbedPane, CARD_RESULTS);
        add(cardPanel, BorderLayout.CENTER);

        // Start with empty state
        cardLayout.show(cardPanel, CARD_EMPTY);

        // Listen for result changes
        ScanResultsService service = ScanResultsService.getInstance(project);
        service.addChangeListener(this);
        refreshFromService(service);
    }

    @Override
    public void onResultsChanged() {
        ApplicationManager.getApplication().invokeLater(() -> {
            ScanResultsService service = ScanResultsService.getInstance(project);
            refreshFromService(service);
        });
    }

    private void refreshFromService(ScanResultsService service) {
        langModel.setData(service.getLangVulnerabilities());
        depModel.setData(service.getDepVulnerabilities());
        malwareModel.setData(service.getMalwareResults());
        licenseModel.setData(service.getLicenseIssues());

        if (service.getTotalCount() > 0) {
            cardLayout.show(cardPanel, CARD_RESULTS);
        } else {
            cardLayout.show(cardPanel, CARD_EMPTY);
        }
    }

    // ── Table helpers ─────────────────────────────────────────────────

    private JBTable createTable(AbstractTableModel model) {
        JBTable table = new JBTable(model);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.setRowHeight(24);
        table.setShowGrid(false);
        table.setIntercellSpacing(new Dimension(0, 0));
        table.getTableHeader().setReorderingAllowed(false);

        // Severity column renderer (first column)
        table.getColumnModel().getColumn(0).setCellRenderer(new SeverityRenderer());
        table.getColumnModel().getColumn(0).setMaxWidth(80);
        table.getColumnModel().getColumn(0).setMinWidth(60);

        return table;
    }

    private void addDoubleClickNavigation(JBTable table, Runnable navigator) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
                    navigator.run();
                }
            }
        });
    }

    private void addContextMenu(JBTable table, Runnable fixGuidanceAction) {
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) { handlePopup(e); }
            @Override
            public void mouseReleased(MouseEvent e) { handlePopup(e); }

            private void handlePopup(MouseEvent e) {
                if (!e.isPopupTrigger()) return;
                int row = table.rowAtPoint(e.getPoint());
                if (row < 0) return;
                table.setRowSelectionInterval(row, row);

                JPopupMenu menu = new JPopupMenu();
                if (fixGuidanceAction != null) {
                    JMenuItem fixItem = new JMenuItem("View Fix Guidance");
                    fixItem.addActionListener(ev -> fixGuidanceAction.run());
                    menu.add(fixItem);
                }
                JMenuItem copyItem = new JMenuItem("Copy Row");
                copyItem.addActionListener(ev -> copyRowToClipboard(table, row));
                menu.add(copyItem);

                menu.show(table, e.getX(), e.getY());
            }
        });
    }

    private void copyRowToClipboard(JBTable table, int row) {
        StringBuilder sb = new StringBuilder();
        for (int col = 0; col < table.getColumnCount(); col++) {
            if (col > 0) sb.append("\t");
            Object val = table.getValueAt(row, col);
            sb.append(val != null ? val.toString() : "");
        }
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(sb.toString());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
    }

    // ── Navigation ────────────────────────────────────────────────────

    private void navigateToLangVuln() {
        int row = langTable.getSelectedRow();
        if (row < 0) return;

        LangVulnerability vuln = langModel.getRow(row);
        if (vuln == null || vuln.getFilePath() == null) return;

        String basePath = project.getBasePath();
        String filePath = vuln.getFilePath();

        // Try absolute path first, then relative to project
        VirtualFile vf = LocalFileSystem.getInstance().findFileByPath(filePath);
        if (vf == null && basePath != null) {
            String fullPath = basePath + File.separator + filePath;
            vf = LocalFileSystem.getInstance().findFileByPath(fullPath.replace('\\', '/'));
        }
        if (vf == null && basePath != null) {
            // Try matching by file name within project
            String fileName = vuln.getFileName();
            if (fileName != null) {
                String fullPath = basePath + File.separator + fileName;
                vf = LocalFileSystem.getInstance().findFileByPath(fullPath.replace('\\', '/'));
            }
        }

        if (vf != null) {
            int line = Math.max(0, vuln.getLineNo() - 1);
            int col = Math.max(0, vuln.getColumnNo());
            new OpenFileDescriptor(project, vf, line, col).navigate(true);
        } else {
            Messages.showWarningDialog(project,
                "Could not locate file: " + filePath,
                "Offensive360 SAST for Android Studio");
        }
    }

    // ── Fix guidance dialogs ──────────────────────────────────────────

    private void showLangFixGuidance() {
        int row = langTable.getSelectedRow();
        if (row < 0) return;
        LangVulnerability vuln = langModel.getRow(row);
        if (vuln == null) return;

        String type = vuln.getType() != null ? vuln.getType() : vuln.getVulnerability();
        String help = VulnerabilityKnowledgeBase.getFullHelp(type != null ? type : "");

        JTextArea textArea = new JTextArea(help);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(600, 400));

        JOptionPane.showMessageDialog(this, scrollPane,
            "Fix Guidance - " + (vuln.getType() != null ? vuln.getType() : "Vulnerability"),
            JOptionPane.INFORMATION_MESSAGE);
    }

    private void showDepFixGuidance() {
        int row = depTable.getSelectedRow();
        if (row < 0) return;
        DepVulnerability vuln = depModel.getRow(row);
        if (vuln == null) return;

        String desc = vuln.getDescription() != null ? vuln.getDescription() : "";
        String cve = vuln.getCveId() != null ? vuln.getCveId() : "N/A";
        String msg = "CVE: " + cve + "\n\n" + desc + "\n\nUpdate the affected dependency to a patched version.";

        JTextArea textArea = new JTextArea(msg);
        textArea.setEditable(false);
        textArea.setLineWrap(true);
        textArea.setWrapStyleWord(true);
        textArea.setCaretPosition(0);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(600, 300));

        JOptionPane.showMessageDialog(this, scrollPane,
            "Dependency Vulnerability - " + vuln.getFileName(),
            JOptionPane.INFORMATION_MESSAGE);
    }

    // ── Severity renderer ─────────────────────────────────────────────

    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, column);
            label.setHorizontalAlignment(SwingConstants.CENTER);

            if (!isSelected && value != null) {
                String sev = value.toString().toLowerCase();
                switch (sev) {
                    case "critical":
                        label.setForeground(new Color(180, 0, 0));
                        label.setFont(label.getFont().deriveFont(Font.BOLD));
                        break;
                    case "high":
                        label.setForeground(new Color(220, 80, 0));
                        label.setFont(label.getFont().deriveFont(Font.BOLD));
                        break;
                    case "medium":
                        label.setForeground(new Color(0, 120, 200));
                        label.setFont(label.getFont().deriveFont(Font.PLAIN));
                        break;
                    case "low":
                        label.setForeground(new Color(0, 140, 0));
                        label.setFont(label.getFont().deriveFont(Font.PLAIN));
                        break;
                    default:
                        label.setForeground(table.getForeground());
                        label.setFont(label.getFont().deriveFont(Font.PLAIN));
                        break;
                }
            }
            return label;
        }
    }

    // ── Table Models ──────────────────────────────────────────────────

    private static class LangTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Severity", "Type", "File", "Line", "Description"};
        private List<LangVulnerability> data = Collections.emptyList();

        void setData(List<LangVulnerability> data) {
            this.data = data != null ? data : Collections.emptyList();
            fireTableDataChanged();
        }

        LangVulnerability getRow(int row) {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int row, int col) {
            LangVulnerability v = data.get(row);
            switch (col) {
                case 0: return v.getRiskLevel() != null ? v.getRiskLevel() : "Medium";
                case 1: return v.getType() != null ? v.getType() : v.getVulnerability();
                case 2: return v.getFileName() != null ? v.getFileName() : v.getFilePath();
                case 3: return v.getLineNo();
                case 4: return v.getVulnerability() != null ? v.getVulnerability() : v.getCodeSnippet();
                default: return "";
            }
        }
    }

    private static class DepTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Severity", "CVE", "File", "Description"};
        private List<DepVulnerability> data = Collections.emptyList();

        void setData(List<DepVulnerability> data) {
            this.data = data != null ? data : Collections.emptyList();
            fireTableDataChanged();
        }

        DepVulnerability getRow(int row) {
            return row >= 0 && row < data.size() ? data.get(row) : null;
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int row, int col) {
            DepVulnerability v = data.get(row);
            switch (col) {
                case 0: return v.getSeverity() != null ? v.getSeverity() : "Medium";
                case 1: return v.getCveId() != null ? v.getCveId() : "N/A";
                case 2: return v.getFileName();
                case 3: return v.getDescription();
                default: return "";
            }
        }
    }

    private static class MalwareTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Severity", "Rule", "File", "Description"};
        private List<MalwareResult> data = Collections.emptyList();

        void setData(List<MalwareResult> data) {
            this.data = data != null ? data : Collections.emptyList();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int row, int col) {
            MalwareResult v = data.get(row);
            switch (col) {
                case 0: return v.getSeverity() != null ? v.getSeverity() : "High";
                case 1: return v.getRuleName();
                case 2: return v.getFileName();
                case 3: return v.getDescription();
                default: return "";
            }
        }
    }

    private static class LicenseTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {"Risk", "License", "File", "Type"};
        private List<LicenseIssue> data = Collections.emptyList();

        void setData(List<LicenseIssue> data) {
            this.data = data != null ? data : Collections.emptyList();
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return data.size(); }
        @Override public int getColumnCount() { return COLUMNS.length; }
        @Override public String getColumnName(int column) { return COLUMNS[column]; }

        @Override
        public Object getValueAt(int row, int col) {
            LicenseIssue v = data.get(row);
            switch (col) {
                case 0: return v.getRiskLevel() != null ? v.getRiskLevel() : "Low";
                case 1: return v.getLicenseName();
                case 2: return v.getFileName();
                case 3: return v.getLicenseType();
                default: return "";
            }
        }
    }
}
