package com.offensive360.sast.settings

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.ui.Messages
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel

class O360Configurable : Configurable {

    private val endpointField = JBTextField()
    private val tokenField = JBPasswordField()
    private val allowSelfSignedCheckbox = JBCheckBox("Allow self-signed SSL certificates (for on-premise instances)")
    private val testConnectionButton = JButton("Test Connection")

    private var panel: JPanel? = null

    override fun getDisplayName(): String = "O360 SAST"

    override fun createComponent(): JComponent {
        testConnectionButton.addActionListener { testConnection() }

        panel = FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Endpoint:"), endpointField, 1, false)
            .addTooltip("O360 SAST server URL (e.g. https://your-server.com:1800)")
            .addLabeledComponent(JBLabel("Access Token:"), tokenField, 1, false)
            .addTooltip("Generated from O360 dashboard \u2192 Settings \u2192 Access Tokens")
            .addSeparator()
            .addComponent(allowSelfSignedCheckbox, 1)
            .addComponent(testConnectionButton, 1)
            .addComponentFillVertically(JPanel(), 0)
            .panel
        return panel!!
    }

    override fun isModified(): Boolean {
        val s = O360Settings.getInstance()
        return endpointField.text != s.endpoint ||
                String(tokenField.password) != s.accessToken ||
                allowSelfSignedCheckbox.isSelected != s.allowSelfSignedCerts
    }

    override fun apply() {
        val endpoint = endpointField.text.trim().trimEnd('/')
        val token = String(tokenField.password).trim()

        // Validate endpoint is a valid URL
        if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
            Messages.showErrorDialog(
                "Endpoint must be a valid URL starting with http:// or https://",
                "O360 SAST: Invalid Endpoint"
            )
            return
        }

        // Validate token is not empty
        if (token.isEmpty()) {
            Messages.showErrorDialog(
                "Access Token cannot be empty.",
                "O360 SAST: Missing Token"
            )
            return
        }

        val s = O360Settings.getInstance()
        s.endpoint = endpoint
        s.accessToken = token
        s.allowSelfSignedCerts = allowSelfSignedCheckbox.isSelected
    }

    override fun reset() {
        val s = O360Settings.getInstance()
        endpointField.text = s.endpoint
        tokenField.text = s.accessToken
        allowSelfSignedCheckbox.isSelected = s.allowSelfSignedCerts
    }

    private fun testConnection() {
        val endpoint = endpointField.text.trim().trimEnd('/')
        val token = String(tokenField.password).trim()

        if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
            Messages.showErrorDialog(
                "Endpoint must be a valid URL starting with http:// or https://",
                "O360 SAST: Invalid Endpoint"
            )
            return
        }
        if (token.isEmpty()) {
            Messages.showErrorDialog(
                "Access Token cannot be empty.",
                "O360 SAST: Missing Token"
            )
            return
        }

        val allowSelfSigned = allowSelfSignedCheckbox.isSelected
        // Use ExternalScan endpoint for validation — HealthCheck returns 403 for External tokens
        val healthUrl = "$endpoint/app/api/ExternalScan/scanQueuePosition"

        testConnectionButton.isEnabled = false
        testConnectionButton.text = "Testing\u2026"

        Thread {
            try {
                val (code, _) = doHealthCheckGet(healthUrl, token, allowSelfSigned)
                javax.swing.SwingUtilities.invokeLater {
                    testConnectionButton.isEnabled = true
                    testConnectionButton.text = "Test Connection"
                    if (code in 200..299) {
                        Messages.showInfoMessage(
                            "Connection successful! Server returned HTTP $code.",
                            "O360 SAST: Connection Test"
                        )
                    } else {
                        Messages.showErrorDialog(
                            "Server returned HTTP $code. Check your endpoint and token.",
                            "O360 SAST: Connection Test Failed"
                        )
                    }
                }
            } catch (ex: Exception) {
                javax.swing.SwingUtilities.invokeLater {
                    testConnectionButton.isEnabled = true
                    testConnectionButton.text = "Test Connection"
                    val message = when (ex) {
                        is SocketTimeoutException -> "Connection timed out. Check your server URL and network."
                        is UnknownHostException -> "Cannot reach server. Check your endpoint URL."
                        else -> "Connection failed: ${ex.message ?: "Unknown error"}"
                    }
                    Messages.showErrorDialog(message, "O360 SAST: Connection Test Failed")
                }
            }
        }.start()
    }

    /**
     * Perform a GET to the HealthCheck endpoint.
     * Uses curl when self-signed certs are enabled (same approach as O360ApiClient)
     * to avoid Java SSL issues with certain server configurations.
     */
    private fun doHealthCheckGet(urlStr: String, token: String, allowSelfSigned: Boolean): Pair<Int, String> {
        if (allowSelfSigned) {
            return doHealthCheckViaCurl(urlStr, token)
        }
        // Standard Java HTTP for non-self-signed
        val connection = URL(urlStr).openConnection() as HttpURLConnection
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("Authorization", "Bearer $token")

        val code = connection.responseCode
        val body = try {
            connection.inputStream?.bufferedReader()?.use { it.readText() } ?: ""
        } catch (_: IOException) {
            connection.errorStream?.bufferedReader()?.use { it.readText() } ?: ""
        }
        connection.disconnect()
        return Pair(code, body)
    }

    private fun doHealthCheckViaCurl(urlStr: String, token: String): Pair<Int, String> {
        val curlPath = findCurl()
        val cmd = mutableListOf(
            curlPath, "-sk", "--max-time", "15",
            "-w", "|||HTTP_CODE:%{http_code}",
            "-H", "Authorization: Bearer $token",
            urlStr
        )

        val process = ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        if (exitCode != 0) {
            throw IOException("curl failed (exit $exitCode): $output")
        }

        val marker = "|||HTTP_CODE:"
        val markerIdx = output.lastIndexOf(marker)
        val httpCode: Int
        val body: String
        if (markerIdx >= 0) {
            httpCode = output.substring(markerIdx + marker.length).trim().toIntOrNull() ?: 0
            body = output.substring(0, markerIdx)
        } else {
            httpCode = 0
            body = output
        }
        return Pair(httpCode, body)
    }

    /** Find curl executable — prefer Git's curl (OpenSSL) over Windows system curl (SChannel) */
    private fun findCurl(): String {
        val gitCurlPaths = listOf(
            "C:\\Program Files\\Git\\mingw64\\bin\\curl.exe",
            "C:\\Program Files (x86)\\Git\\mingw64\\bin\\curl.exe"
        )
        for (path in gitCurlPaths) {
            if (File(path).exists()) return path
        }
        return "curl"
    }
}
