package com.offensive360.sast.update

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBScrollPane
import java.awt.*
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import javax.swing.*

class UpdateDialog(
    private val project: Project,
    private val currentVersion: String,
    private val newVersion: String,
    private val releaseNotes: String,
    private val downloadUrl: String
) : DialogWrapper(project, true) {

    private val progressBar = JProgressBar(0, 100).apply {
        isStringPainted = true
        string = ""
        preferredSize = Dimension(460, 24)
    }
    private val statusLabel = JLabel("Click Update to download and install the latest version.").apply {
        foreground = Color(153, 153, 153)
        font = font.deriveFont(11f)
    }
    private var updateButton: JButton? = null

    init {
        title = "Offensive 360 — Update Available"
        setOKButtonText("Update Now")
        setCancelButtonText("Skip")
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(GridBagLayout())
        panel.preferredSize = Dimension(500, 360)
        val gbc = GridBagConstraints().apply {
            gridx = 0; fill = GridBagConstraints.HORIZONTAL; weightx = 1.0
            insets = Insets(4, 0, 4, 0)
        }

        // Header
        gbc.gridy = 0
        val header = JLabel("A new version of Offensive 360 is available")
        header.font = header.font.deriveFont(Font.BOLD, 16f)
        panel.add(header, gbc)

        // Version info
        gbc.gridy = 1
        val versionLabel = JLabel("<html>Installed: <b style='color:#FF8C00'>v$currentVersion</b> &nbsp;&nbsp;→&nbsp;&nbsp; <b style='color:#4EC9B0'>v$newVersion</b></html>")
        versionLabel.font = versionLabel.font.deriveFont(13f)
        panel.add(versionLabel, gbc)

        // Release notes
        gbc.gridy = 2
        gbc.fill = GridBagConstraints.BOTH
        gbc.weighty = 1.0
        val notesArea = JTextArea(releaseNotes.ifBlank { "No release notes available." })
        notesArea.isEditable = false
        notesArea.lineWrap = true
        notesArea.wrapStyleWord = true
        notesArea.font = Font("Segoe UI", Font.PLAIN, 12)
        notesArea.margin = Insets(8, 8, 8, 8)
        val scrollPane = JBScrollPane(notesArea)
        scrollPane.preferredSize = Dimension(460, 180)
        panel.add(scrollPane, gbc)

        // Progress bar
        gbc.gridy = 3
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weighty = 0.0
        panel.add(progressBar, gbc)

        // Status
        gbc.gridy = 4
        panel.add(statusLabel, gbc)

        return panel
    }

    override fun doOKAction() {
        if (downloadUrl.isBlank()) {
            statusLabel.text = "No download URL available."
            return
        }

        // Disable OK button during download
        updateButton = getButton(okAction)
        updateButton?.isEnabled = false
        updateButton?.text = "Downloading..."

        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Downloading Offensive 360 update...", true) {
            override fun run(indicator: ProgressIndicator) {
                try {
                    indicator.isIndeterminate = false
                    val tempDir = File(System.getProperty("java.io.tmpdir"), "Offensive360Update")
                    tempDir.mkdirs()
                    val zipPath = File(tempDir, "o360-sast-v$newVersion.zip")

                    val connection = (URL(downloadUrl).openConnection() as HttpURLConnection).apply {
                        connectTimeout = 30000
                        readTimeout = 600000
                        setRequestProperty("User-Agent", "Offensive360-AS-Plugin/$currentVersion")
                        instanceFollowRedirects = true
                    }

                    // Follow redirects (GitHub redirects to CDN)
                    var finalConnection = connection
                    val responseCode = connection.responseCode
                    if (responseCode in 301..302) {
                        val redirectUrl = connection.getHeaderField("Location")
                        finalConnection = (URL(redirectUrl).openConnection() as HttpURLConnection).apply {
                            connectTimeout = 30000
                            readTimeout = 600000
                        }
                    }

                    val totalBytes = finalConnection.contentLengthLong
                    var receivedBytes = 0L

                    finalConnection.inputStream.use { input ->
                        FileOutputStream(zipPath).use { output ->
                            val buffer = ByteArray(8192)
                            var bytesRead: Int
                            while (input.read(buffer).also { bytesRead = it } != -1) {
                                if (indicator.isCanceled) {
                                    zipPath.delete()
                                    return
                                }
                                output.write(buffer, 0, bytesRead)
                                receivedBytes += bytesRead
                                if (totalBytes > 0) {
                                    val percent = (receivedBytes * 100 / totalBytes).toInt()
                                    indicator.fraction = percent / 100.0
                                    val sizeMb = receivedBytes / (1024.0 * 1024.0)
                                    val totalMb = totalBytes / (1024.0 * 1024.0)
                                    indicator.text = "Downloading: %.1f / %.1f MB".format(sizeMb, totalMb)
                                    ApplicationManager.getApplication().invokeLater {
                                        progressBar.value = percent
                                        progressBar.string = "$percent%"
                                        statusLabel.text = "Downloading: %.1f / %.1f MB".format(sizeMb, totalMb)
                                    }
                                }
                            }
                        }
                    }

                    ApplicationManager.getApplication().invokeLater {
                        progressBar.value = 100
                        progressBar.string = "100%"
                        statusLabel.text = "Download complete: ${zipPath.absolutePath}"
                        updateButton?.text = "Done"

                        // Open the folder containing the zip
                        try {
                            Desktop.getDesktop().open(tempDir)
                        } catch (_: Exception) {}

                        JOptionPane.showMessageDialog(
                            null,
                            "Update downloaded to:\n${zipPath.absolutePath}\n\n" +
                            "To install:\n" +
                            "1. Close Android Studio\n" +
                            "2. Extract the zip to your plugins folder\n" +
                            "3. Restart Android Studio",
                            "Offensive 360 — Update Downloaded",
                            JOptionPane.INFORMATION_MESSAGE
                        )
                    }
                } catch (e: Exception) {
                    ApplicationManager.getApplication().invokeLater {
                        progressBar.value = 0
                        progressBar.string = ""
                        statusLabel.text = "Download failed: ${e.message}"
                        updateButton?.text = "Retry"
                        updateButton?.isEnabled = true
                    }
                }
            }
        })
    }
}
