package com.offensive360.sast.update

import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.StartupActivity

/**
 * Fires once per project on IDE start to check the GitHub release feed for
 * a newer plugin version. Throttled and silent on failure (see PluginUpdateChecker).
 */
class PluginUpdateStartupActivity : StartupActivity.DumbAware {
    override fun runActivity(project: Project) {
        try {
            PluginUpdateChecker.checkAsync(project)
        } catch (_: Exception) {
            // Update notifications must never break IDE startup.
        }
    }
}
