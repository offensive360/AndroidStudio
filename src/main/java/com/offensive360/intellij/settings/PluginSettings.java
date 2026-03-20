package com.offensive360.intellij.settings;

import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.openapi.project.Project;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Settings service for Offensive360 SAST plugin.
 * Persists server endpoint and API token configuration.
 */
@Service(Service.Level.PROJECT)
@State(
    name = "Offensive360Settings",
    storages = @Storage("offensive360.xml")
)
public final class PluginSettings implements PersistentStateComponent<PluginSettings> {
    public String endpoint = "https://sast.offensive360.com";
    public String accessToken = "";

    public static PluginSettings getInstance(@NotNull Project project) {
        return project.getService(PluginSettings.class);
    }

    @Nullable
    @Override
    public PluginSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull PluginSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }

    public String getEndpoint() {
        return endpoint != null ? endpoint : "https://sast.offensive360.com";
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getAccessToken() {
        return accessToken != null ? accessToken : "";
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public boolean isConfigured() {
        return getAccessToken() != null && !getAccessToken().isEmpty()
            && getAccessToken().startsWith("ey");
    }
}
