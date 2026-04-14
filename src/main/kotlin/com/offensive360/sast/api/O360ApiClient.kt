package com.offensive360.sast.api

import com.offensive360.sast.models.Finding
import com.offensive360.sast.models.ScanResult
import com.offensive360.sast.settings.O360Settings
import org.json.JSONObject
import java.io.*
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class O360ApiClient {

    companion object {
        val instance = O360ApiClient()
        private const val MAX_ZIP_SIZE_BYTES = 100L * 1024 * 1024 // 100 MB
        private const val CONNECT_TIMEOUT_MS = 30 * 1000
        private const val READ_TIMEOUT_MS = 600 * 1000

        /** Find curl executable — prefer Git's curl (OpenSSL) over Windows system curl (SChannel) */
        private fun findCurl(): String {
            // Check common Git installation paths first
            val gitCurlPaths = listOf(
                "C:\\Program Files\\Git\\mingw64\\bin\\curl.exe",
                "C:\\Program Files (x86)\\Git\\mingw64\\bin\\curl.exe"
            )
            for (path in gitCurlPaths) {
                if (File(path).exists()) return path
            }
            // Fall back to system curl
            return "curl"
        }
    }

    private fun configureSsl(connection: HttpURLConnection) {
        if (connection is HttpsURLConnection) {
            val settings = O360Settings.getInstance()
            if (settings.allowSelfSignedCerts) {
                val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                })
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, trustAllCerts, SecureRandom())
                connection.sslSocketFactory = sslContext.socketFactory
                connection.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
            }
        }
    }

    private fun openConnection(urlStr: String): HttpURLConnection {
        val connection = URL(urlStr).openConnection() as HttpURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        configureSsl(connection)
        return connection
    }

    private fun readResponseBody(connection: HttpURLConnection): String {
        val stream = try {
            connection.inputStream
        } catch (_: IOException) {
            connection.errorStream
        }
        return stream?.bufferedReader()?.use { it.readText() } ?: ""
    }

    /**
     * POST multipart/form-data using curl via ProcessBuilder.
     * Java's SSL stack (HttpsURLConnection / OkHttp) fails on POST requests to
     * nginx servers that perform SSL renegotiation ("SSLHandshakeException:
     * Remote host terminated the handshake"). curl handles this correctly.
     */
    private fun postMultipart(
        urlStr: String,
        token: String,
        textParts: Map<String, String>,
        fileFieldName: String,
        file: File,
        fileMimeType: String = "application/zip"
    ): Pair<Int, String> {
        // Use Git's curl which has better SSL compatibility on Windows
        val curlPath = findCurl()
        val cmd = mutableListOf(curlPath, "-sk", "--max-time", "900", "-w", "|||HTTP_CODE:%{http_code}")
        cmd.addAll(listOf("-H", "Authorization: Bearer $token"))

        for ((name, value) in textParts) {
            cmd.addAll(listOf("-F", "$name=$value"))
        }
        cmd.addAll(listOf("-F", "$fileFieldName=@${file.absolutePath};type=$fileMimeType"))
        cmd.add(urlStr)

        val process = ProcessBuilder(cmd)
            .redirectErrorStream(true)
            .start()

        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        if (exitCode != 0) {
            throw IOException("curl failed with exit code $exitCode: $output")
        }

        // Parse response — HTTP code is after |||HTTP_CODE: marker
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

    /**
     * Simple GET request returning (statusCode, body).
     */
    private fun doGet(urlStr: String, token: String): Pair<Int, String> {
        val connection = openConnection(urlStr)
        connection.requestMethod = "GET"
        connection.setRequestProperty("Authorization", "Bearer $token")

        val code = connection.responseCode
        val body = readResponseBody(connection)
        connection.disconnect()
        return Pair(code, body)
    }

    /**
     * Simple DELETE request returning status code.
     */
    private fun doDelete(urlStr: String, token: String): Int {
        val connection = openConnection(urlStr)
        connection.requestMethod = "DELETE"
        connection.setRequestProperty("Authorization", "Bearer $token")

        val code = connection.responseCode
        connection.disconnect()
        return code
    }

    fun scan(files: List<File>, projectName: String, progressCallback: (String) -> Unit): ScanResult {
        val settings = O360Settings.getInstance()
        val endpoint = settings.endpoint.trimEnd('/')
        val token = settings.accessToken

        progressCallback("Zipping ${files.size} files\u2026")
        val zipFile = createZip(files, projectName)

        try {
            // Warn if zip is very large
            if (zipFile.length() > MAX_ZIP_SIZE_BYTES) {
                val sizeMb = zipFile.length() / (1024 * 1024)
                progressCallback("Warning: Upload size is ${sizeMb}MB. This may take a while\u2026")
            }

            // Use scanProjectFile + polling (same as working VSCode v1.0.4 plugin).
            // Falls back to ExternalScan only for External tokens that get 403.
            progressCallback("Uploading to O360 SAST\u2026")

            val textParts = linkedMapOf(
                "Name" to projectName,
                "ExternalScanSourceType" to "IntelijExtension"
            )

            var projectId: String? = null

            try {
                val (code, body) = postMultipart(
                    "$endpoint/app/api/Project/scanProjectFile",
                    token,
                    textParts,
                    "FileSource",
                    zipFile
                )

                if (code == 403) {
                    throw ForbiddenException()
                }
                if (code == 401) {
                    throw RuntimeException("Your access token is invalid or expired (HTTP 401).\n\nPlease ask your O360 administrator to generate a new token from Dashboard > Settings > Tokens.")
                }
                if (code !in 200..299) {
                    throw RuntimeException("Upload failed (HTTP $code)")
                }
                projectId = body.trim().trim('"')
            } catch (_: ForbiddenException) {
                // External token — fall back to ExternalScan with retry (handles intermittent 500s)
                val maxRetries = 3
                var lastError = ""
                for (attempt in 1..maxRetries) {
                    try {
                        if (attempt > 1) {
                            progressCallback("Retrying scan (attempt $attempt/$maxRetries)...")
                            Thread.sleep(5000L * attempt)
                        }
                        return scanViaExternalScan(zipFile, projectName, endpoint, token, settings, progressCallback)
                    } catch (e: ServerErrorException) {
                        lastError = e.message ?: "Server error"
                        if (attempt < maxRetries) progressCallback("Server error, retrying in ${5 * attempt}s (attempt $attempt/$maxRetries)...")
                    } catch (e: SocketTimeoutException) {
                        lastError = "Connection timed out"
                        if (attempt < maxRetries) progressCallback("Timed out, retrying...")
                    } catch (e: IOException) {
                        lastError = e.message ?: "Connection error"
                        if (attempt < maxRetries) progressCallback("Connection error, retrying...")
                    }
                }
                throw RuntimeException(lastError.ifBlank { "Scan failed after $maxRetries attempts. The server may be temporarily overloaded — please try again in a moment." })
            }

            if (projectId.isNullOrBlank()) {
                throw RuntimeException("No project ID returned from server")
            }

            // Poll for scan completion
            progressCallback("Scan queued, waiting for results...")
            val result = pollAndFetchResults(endpoint, token, projectId!!, progressCallback)

            // Clean up: delete the project from server dashboard
            deleteProject(endpoint, token, projectId!!)

            return result
        } finally {
            zipFile.delete()
        }
    }

    private class ForbiddenException : Exception()
    private class ServerErrorException(message: String) : Exception(message)

    private fun scanViaExternalScan(
        zipFile: File,
        projectName: String,
        endpoint: String,
        token: String,
        settings: O360Settings,
        progressCallback: (String) -> Unit
    ): ScanResult {
        progressCallback("Scanning (ExternalScan)...")

        val textParts = linkedMapOf(
            "Name" to projectName,
            "ExternalScanSourceType" to "IntelijExtension",
            "KeepInvisibleAndDeletePostScan" to "True"
        )

        val (code, responseBody) = postMultipart(
            "$endpoint/app/api/ExternalScan",
            token,
            textParts,
            "FileSource",
            zipFile
        )

        if (code >= 500) {
            throw ServerErrorException("Server returned HTTP $code. The server may be temporarily overloaded — please try again.")
        }
        if (code !in 200..299) {
            throw RuntimeException("Scan failed (HTTP $code)")
        }

        val json = JSONObject(responseBody)
        val vulnerabilities = json.optJSONArray("vulnerabilities")
        val findings = mutableListOf<Finding>()

        if (vulnerabilities != null) {
            for (i in 0 until vulnerabilities.length()) {
                findings.add(Finding.fromJson(vulnerabilities.getJSONObject(i)))
            }
        }

        val externalProjectId = json.optString("projectId", "")

        // Clean up: delete the project from server to leave no dashboard traces
        if (externalProjectId.isNotBlank()) {
            deleteProject(endpoint, token, externalProjectId)
        }

        return ScanResult(
            findings = findings,
            projectId = externalProjectId
        )
    }

    private fun pollAndFetchResults(
        endpoint: String,
        token: String,
        projectId: String,
        progressCallback: (String) -> Unit
    ): ScanResult {
        val maxWaitMs = 60 * 60 * 1000L // 60 minutes
        val pollIntervalMs = 10_000L
        val startTime = System.currentTimeMillis()
        var firstPoll = true

        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            Thread.sleep(if (firstPoll) 3000L else pollIntervalMs)
            firstPoll = false

            val (code, body) = doGet("$endpoint/app/api/Project/$projectId", token)

            if (code == 404) {
                throw RuntimeException("Project not found (404). The scan may have been deleted by the server.")
            }
            if (code in 200..299) {
                val json = JSONObject(body)
                when (val status = json.optInt("status", -1)) {
                    2, 4 -> { // Succeeded or Partial Failed
                        progressCallback("Retrieving scan results...")
                        return fetchLangResults(endpoint, token, projectId)
                    }
                    3 -> throw RuntimeException("Scan failed on server")
                    5 -> throw RuntimeException("Scan was skipped by server")
                    else -> {
                        val statusText = when (status) { 0 -> "queued"; 1 -> "in progress"; else -> "status $status" }
                        progressCallback("Scan $statusText...")
                    }
                }
            }
        }

        throw RuntimeException("Scan timed out after 60 minutes")
    }

    private fun fetchLangResults(endpoint: String, token: String, projectId: String): ScanResult {
        // Note: API has "Langauge" misspelled
        val (code, body) = doGet("$endpoint/app/api/Project/$projectId/LangaugeScanResult", token)

        if (code !in 200..299) {
            return ScanResult(findings = emptyList(), projectId = projectId)
        }

        val findings = mutableListOf<Finding>()

        try {
            val items = if (body.trimStart().startsWith("[")) {
                org.json.JSONArray(body)
            } else {
                val obj = JSONObject(body)
                obj.optJSONArray("pageItems") ?: org.json.JSONArray()
            }

            for (i in 0 until items.length()) {
                val item = items.getJSONObject(i)
                findings.add(Finding(
                    id = item.optString("id", ""),
                    title = item.optString("type", ""),
                    type = item.optString("type", ""),
                    riskLevel = item.optInt("riskLevel", 2),
                    fileName = item.optString("fileName", ""),
                    filePath = item.optString("filePath", ""),
                    lineNumber = "${item.optInt("lineNo", 0)},${item.optInt("columnNo", 0)}",
                    vulnerability = item.optString("vulnerability", ""),
                    codeSnippet = item.optString("codeSnippet", ""),
                    effect = item.optString("effect", ""),
                    recommendation = item.optString("recommendation", "")
                ))
            }
        } catch (_: Exception) {
            // Parse error -- return empty
        }

        return ScanResult(findings = findings, projectId = projectId)
    }

    private fun deleteProject(endpoint: String, token: String, projectId: String) {
        try {
            doDelete("$endpoint/app/api/Project/$projectId", token)
        } catch (_: Exception) {
            // best-effort cleanup
        }
    }

    private fun createZip(files: List<File>, projectName: String): File {
        val maxFileSize = 50L * 1024 * 1024 // 50 MB per file — skip larger files
        val zipFile = File(System.getProperty("java.io.tmpdir"), "o360_scan_${UUID.randomUUID()}.zip")
        // Find common parent directory for relative paths
        val commonParent = files.mapNotNull { it.parentFile?.absolutePath }
            .minByOrNull { it.length } ?: ""
        var skippedCount = 0
        ZipOutputStream(FileOutputStream(zipFile)).use { zos ->
            for (file in files) {
                if (!file.exists() || !file.isFile) continue
                if (file.length() > maxFileSize) {
                    skippedCount++
                    continue // Skip files larger than 50MB
                }
                // Use relative path from common parent, or just filename
                val entryName = if (commonParent.isNotEmpty() && file.absolutePath.startsWith(commonParent)) {
                    file.absolutePath.removePrefix(commonParent).trimStart('/', '\\').replace('\\', '/')
                } else {
                    file.name
                }
                try {
                    zos.putNextEntry(ZipEntry(entryName))
                    file.inputStream().use { it.copyTo(zos) }
                    zos.closeEntry()
                } catch (_: Exception) {
                    // Skip files we can't read (permissions, locks, etc.)
                }
            }
        }
        if (skippedCount > 0) {
            System.err.println("O360 SAST: Skipped $skippedCount file(s) exceeding 50MB limit")
        }
        return zipFile
    }

}
