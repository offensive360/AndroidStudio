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
import com.intellij.openapi.ui.InputValidator;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.offensive360.intellij.api.SastClient;
import com.offensive360.intellij.kb.VulnerabilityKnowledgeBase;
import com.offensive360.intellij.settings.PluginSettings;
import com.offensive360.intellij.settings.SettingsConfigurable;
import com.offensive360.intellij.toolwindow.ScanResultsService;
import org.jetbrains.annotations.NotNull;

/**
 * Action to scan a remote Git repository for vulnerabilities.
 */
public class ScanGitRepoAction extends AnAction {
    private static final Logger logger = Logger.getInstance(ScanGitRepoAction.class);

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        PluginSettings settings = PluginSettings.getInstance(project);

        // Check if configured
        if (!settings.isConfigured()) {
            ShowSettingsUtil.getInstance().showSettingsDialog(project, SettingsConfigurable.class);
            if (!settings.isConfigured()) return;
        }

        // Prompt for Git repo URL
        String repoUrl = Messages.showInputDialog(
            project,
            "Enter Git Repository URL:",
            "Offensive360 SAST for Android Studio - Scan Git Repository",
            Messages.getQuestionIcon(),
            "",
            new InputValidator() {
                @Override
                public boolean checkInput(String inputString) {
                    return !inputString.trim().isEmpty() && inputString.contains("://");
                }

                @Override
                public boolean canClose(String inputString) {
                    return checkInput(inputString);
                }
            }
        );

        if (repoUrl == null || repoUrl.trim().isEmpty()) return;

        // Prompt for branch
        String branch = Messages.showInputDialog(
            project,
            "Enter branch name:",
            "Offensive360 SAST for Android Studio - Branch",
            Messages.getQuestionIcon(),
            "main",
            null
        );

        if (branch == null || branch.trim().isEmpty()) {
            branch = "main";
        }

        final String finalRepoUrl = repoUrl.trim();
        final String finalBranch = branch.trim();

        // Run scan in background
        new Task.Backgroundable(project, "Scanning Git repository with Offensive360 SAST...", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                performGitScan(project, settings, finalRepoUrl, finalBranch, indicator);
            }
        }.queue();
    }

    private void performGitScan(Project project, PluginSettings settings,
                                String repoUrl, String branch, ProgressIndicator progress) {
        try {
            SastClient client = new SastClient(settings.getEndpoint(), settings.getAccessToken());

            // Verify token
            progress.setText("Verifying authentication...");
            SastClient.TokenVerifyResult tokenResult = client.verifyTokenTyped();
            if (!tokenResult.valid) {
                String errorMsg = VulnerabilityKnowledgeBase.getAuthErrorMessage(
                    tokenResult.statusCode, tokenResult.networkError);
                showError(errorMsg);
                return;
            }

            // Submit git repo scan — results are fetched immediately on completion
            SastClient.ScanResult result = client.scanGitRepo(repoUrl, branch, progress);

            int totalVulns = result.getTotalCount();

            // Store results
            ScanResultsService service = ScanResultsService.getInstance(project);
            service.setResults(
                result.languageVulnerabilities,
                result.dependencyVulnerabilities,
                result.malwareResults,
                result.licenseIssues
            );

            // Open the results tool window
            ApplicationManager.getApplication().invokeLater(() -> {
                ToolWindow tw = ToolWindowManager.getInstance(project).getToolWindow("Offensive360 Results");
                if (tw != null) {
                    tw.show();
                }
            });

            if (totalVulns > 0) {
                showNotification(
                    "Git scan completed. Found " + totalVulns + " issues. See the Offensive360 Results panel.",
                    NotificationType.WARNING
                );
            } else {
                showNotification(
                    "Git scan completed. No issues found.",
                    NotificationType.INFORMATION
                );
            }

        } catch (InterruptedException ex) {
            showNotification("Scan cancelled.", NotificationType.INFORMATION);
        } catch (Exception ex) {
            logger.error("Git repo scan failed", ex);
            showError("Git repo scan failed: " + ex.getMessage());
        }
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
