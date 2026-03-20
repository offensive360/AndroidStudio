package com.offensive360.intellij.actions;

import com.intellij.notification.Notification;
import com.intellij.notification.NotificationType;
import com.intellij.notification.Notifications;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.options.ShowSettingsUtil;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.offensive360.intellij.api.SastClient;
import com.offensive360.intellij.kb.VulnerabilityKnowledgeBase;
import com.offensive360.intellij.settings.PluginSettings;
import com.offensive360.intellij.settings.SettingsConfigurable;
import com.offensive360.intellij.toolwindow.ScanResultsService;
import org.jetbrains.annotations.NotNull;

/**
 * Action to scan the current project for vulnerabilities.
 */
public class ScanProjectAction extends AnAction {
    private static final Logger logger = Logger.getInstance(ScanProjectAction.class);

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        PluginSettings settings = PluginSettings.getInstance(project);

        // Check if configured
        if (!settings.isConfigured()) {
            int result = showConfigurationDialog(project);
            if (result != 0) return; // User cancelled
        }

        // Run scan in background (non-modal)
        new Task.Backgroundable(project, "Scanning with Offensive360 SAST for Android Studio...", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                performScan(project, settings, indicator);
            }
        }.queue();
    }

    private void performScan(Project project, PluginSettings settings, ProgressIndicator progress) {
        try {
            String projectName = project.getName();
            String projectPath = project.getBasePath();

            if (projectPath == null) {
                showError("Project path is null");
                return;
            }

            SastClient client = new SastClient(settings.getEndpoint(), settings.getAccessToken());

            // Verify token with typed result
            progress.setText("Verifying authentication...");
            SastClient.TokenVerifyResult tokenResult = client.verifyTokenTyped();
            if (!tokenResult.valid) {
                String errorMsg = VulnerabilityKnowledgeBase.getAuthErrorMessage(
                    tokenResult.statusCode, tokenResult.networkError);
                showError(errorMsg);
                return;
            }

            // Perform scan — results are fetched immediately on completion
            // (before server deletes the ephemeral project)
            progress.setText("Scanning project: " + projectName);
            SastClient.ScanResult result = client.scanProject(
                new java.io.File(projectPath),
                projectName,
                progress
            );

            int totalVulns = result.getTotalCount();

            // Store results in the project service
            ScanResultsService service = ScanResultsService.getInstance(project);
            service.setResults(
                result.languageVulnerabilities,
                result.dependencyVulnerabilities,
                result.malwareResults,
                result.licenseIssues
            );

            // Open the results tool window on the EDT
            ApplicationManager.getApplication().invokeLater(() -> {
                ToolWindow tw = ToolWindowManager.getInstance(project).getToolWindow("Offensive360 Results");
                if (tw != null) {
                    tw.show();
                }
            });

            if (totalVulns > 0) {
                showNotification(
                    "Scan completed. Found " + totalVulns + " issues. See the Offensive360 Results panel.",
                    NotificationType.WARNING
                );
            } else {
                showNotification(
                    "Scan completed. No issues found.",
                    NotificationType.INFORMATION
                );
            }

        } catch (InterruptedException ex) {
            showNotification("Scan cancelled.", NotificationType.INFORMATION);
        } catch (Exception ex) {
            logger.error("Scan failed", ex);
            showError("Scan failed: " + ex.getMessage());
        }
    }

    private int showConfigurationDialog(Project project) {
        ShowSettingsUtil.getInstance().showSettingsDialog(project, SettingsConfigurable.class);
        PluginSettings settings = PluginSettings.getInstance(project);
        return settings.isConfigured() ? 0 : 1;
    }

    private void showNotification(String message, NotificationType type) {
        Notification notification = new Notification(
            "Offensive360",
            "Offensive360 SAST for Android Studio",
            message,
            type
        );
        Notifications.Bus.notify(notification);
    }

    private void showError(String message) {
        showNotification(message, NotificationType.ERROR);
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        e.getPresentation().setEnabled(e.getProject() != null);
    }
}
