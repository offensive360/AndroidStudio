package com.offensive360.intellij.settings;

import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.options.ConfigurationException;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

/**
 * Settings UI for configuring Offensive360 SAST plugin.
 */
public class SettingsConfigurable implements Configurable {
    private SettingsPanel settingsPanel;
    private final Project project;
    private final PluginSettings settings;

    public SettingsConfigurable(Project project) {
        this.project = project;
        this.settings = PluginSettings.getInstance(project);
    }

    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "Offensive360 SAST";
    }

    @Nullable
    @Override
    public JComponent createComponent() {
        settingsPanel = new SettingsPanel();
        return settingsPanel.getPanel();
    }

    @Override
    public boolean isModified() {
        return settingsPanel != null && (
            !settingsPanel.getEndpoint().equals(settings.getEndpoint()) ||
            !settingsPanel.getAccessToken().equals(settings.getAccessToken())
        );
    }

    @Override
    public void apply() throws ConfigurationException {
        if (settingsPanel == null) return;

        String endpoint = settingsPanel.getEndpoint().trim();
        String accessToken = settingsPanel.getAccessToken().trim();

        if (endpoint.isEmpty()) {
            throw new ConfigurationException("O360 Server Endpoint cannot be empty");
        }

        if (accessToken.isEmpty() || !accessToken.startsWith("ey")) {
            throw new ConfigurationException("Access Token must be a valid JWT token starting with 'ey'");
        }

        settings.setEndpoint(endpoint);
        settings.setAccessToken(accessToken);
    }

    @Override
    public void reset() {
        if (settingsPanel != null) {
            settingsPanel.setEndpoint(settings.getEndpoint());
            settingsPanel.setAccessToken(settings.getAccessToken());
        }
    }

    @Override
    public void disposeUIResources() {
        settingsPanel = null;
    }
}
