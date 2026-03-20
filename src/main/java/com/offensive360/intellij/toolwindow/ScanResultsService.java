package com.offensive360.intellij.toolwindow;

import com.intellij.openapi.components.Service;
import com.intellij.openapi.project.Project;
import com.offensive360.intellij.models.DepVulnerability;
import com.offensive360.intellij.models.LangVulnerability;
import com.offensive360.intellij.models.LicenseIssue;
import com.offensive360.intellij.models.MalwareResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Project-level service that holds the latest scan results and notifies
 * registered listeners when the data changes.
 */
@Service(Service.Level.PROJECT)
public final class ScanResultsService {

    public interface ChangeListener {
        void onResultsChanged();
    }

    private List<LangVulnerability> langVulnerabilities = Collections.emptyList();
    private List<DepVulnerability> depVulnerabilities = Collections.emptyList();
    private List<MalwareResult> malwareResults = Collections.emptyList();
    private List<LicenseIssue> licenseIssues = Collections.emptyList();

    private final List<ChangeListener> listeners = new CopyOnWriteArrayList<>();

    public static ScanResultsService getInstance(Project project) {
        return project.getService(ScanResultsService.class);
    }

    // ── Setters ───────────────────────────────────────────────────────

    public void setResults(List<LangVulnerability> lang,
                           List<DepVulnerability> dep,
                           List<MalwareResult> malware,
                           List<LicenseIssue> license) {
        this.langVulnerabilities = lang != null ? new ArrayList<>(lang) : Collections.emptyList();
        this.depVulnerabilities = dep != null ? new ArrayList<>(dep) : Collections.emptyList();
        this.malwareResults = malware != null ? new ArrayList<>(malware) : Collections.emptyList();
        this.licenseIssues = license != null ? new ArrayList<>(license) : Collections.emptyList();
        fireChanged();
    }

    // ── Getters ───────────────────────────────────────────────────────

    public List<LangVulnerability> getLangVulnerabilities() {
        return Collections.unmodifiableList(langVulnerabilities);
    }

    public List<DepVulnerability> getDepVulnerabilities() {
        return Collections.unmodifiableList(depVulnerabilities);
    }

    public List<MalwareResult> getMalwareResults() {
        return Collections.unmodifiableList(malwareResults);
    }

    public List<LicenseIssue> getLicenseIssues() {
        return Collections.unmodifiableList(licenseIssues);
    }

    public int getTotalCount() {
        return langVulnerabilities.size() + depVulnerabilities.size()
             + malwareResults.size() + licenseIssues.size();
    }

    // ── Listeners ─────────────────────────────────────────────────────

    public void addChangeListener(ChangeListener listener) {
        listeners.add(listener);
    }

    public void removeChangeListener(ChangeListener listener) {
        listeners.remove(listener);
    }

    private void fireChanged() {
        for (ChangeListener l : listeners) {
            l.onResultsChanged();
        }
    }
}
