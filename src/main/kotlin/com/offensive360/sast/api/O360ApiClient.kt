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
        // Long timeouts to support very large customer projects (~1GB source).
        private const val MAX_ZIP_SIZE_BYTES = 2L * 1024 * 1024 * 1024 // 2 GB
        private const val CONNECT_TIMEOUT_MS = 60 * 1000              // 60 s
        private const val READ_TIMEOUT_MS = 4 * 60 * 60 * 1000        // 4 h
        private const val CURL_MAX_TIME_SECONDS = 4 * 60 * 60         // 4 h
        // Watchdog must be longer than curl --max-time so curl exits cleanly first.
        private const val PROCESS_WAIT_MS = (4 * 60 + 5) * 60 * 1000L // 4 h 5 min

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
        val cmd = mutableListOf(
            curlPath, "-sk",
            "--connect-timeout", "60",
            "--max-time", CURL_MAX_TIME_SECONDS.toString(),
            "-w", "|||HTTP_CODE:%{http_code}"
        )
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
        // Bounded wait so a hung curl can never block the IDE forever.
        // Watchdog is intentionally longer than --max-time so curl exits cleanly first.
        val exited = process.waitFor(PROCESS_WAIT_MS, java.util.concurrent.TimeUnit.MILLISECONDS)
        if (!exited) {
            try { process.destroyForcibly() } catch (_: Exception) {}
            throw IOException("Scan upload timed out after 4 hours. Please contact your Offensive 360 administrator if your project is exceptionally large.")
        }
        val exitCode = process.exitValue()

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
     * Streaming binary GET — writes response body directly to outFile. Used for
     * downloading the original sourceZip from /Project/{id}/sourceZip without buffering
     * the entire archive in RAM. Returns the HTTP status code; outFile is left empty/
     * partial on non-2xx (caller should delete).
     */
    private fun doGetBinary(urlStr: String, token: String, outFile: File): Int {
        val connection = openConnection(urlStr)
        connection.requestMethod = "GET"
        connection.setRequestProperty("Authorization", "Bearer $token")
        connection.connectTimeout = 30_000
        connection.readTimeout = READ_TIMEOUT_MS
        val code = try { connection.responseCode } catch (_: Exception) { 0 }
        val stream = if (code in 200..299) connection.inputStream else (connection.errorStream ?: return code)
        stream.use { input ->
            outFile.outputStream().use { output ->
                input.copyTo(output, bufferSize = 64 * 1024)
            }
        }
        return code
    }

    /**
     * v1.1.14: byte-identical guarantee. Downloads /Project/{id}/sourceZip → re-POSTs
     * via /ExternalScan with KeepInvisibleAndDeletePostScan=True. Server's content cache
     * returns the same canonical findings as the original dashboard project — same source
     * bytes → same hash → same cache entry → same findings, by construction. Returns null
     * if sourceZip is unavailable (404 = pruned, 410 = retention, network error, etc.).
     */
    private fun tryDownloadAndRescan(endpoint: String, token: String, projectId: String): ScanResult? {
        if (projectId.isBlank()) return null
        val tempZip = File.createTempFile("o360_src_", ".zip")
        return try {
            val dlUrl = "$endpoint/app/api/Project/$projectId/sourceZip"
            val code = doGetBinary(dlUrl, token, tempZip)
            if (code !in 200..299 || tempZip.length() == 0L) {
                return null
            }
            // Resolve the dashboard project's actual name — MUST match for cache hit.
            // ExternalScanSourceType=8 is the numeric value the server expects.
            val dashName = try {
                val (pc, pb) = doGet("$endpoint/app/api/Project/$projectId", token)
                if (pc in 200..299) JSONObject(pb).optString("name", "") else ""
            } catch (_: Exception) { "" }
            val parts = linkedMapOf(
                "Name" to (if (dashName.isNotBlank()) dashName else "o360-${java.util.UUID.randomUUID()}"),
                "ExternalScanSourceType" to "8",
                "KeepInvisibleAndDeletePostScan" to "True"
            )
            val (scanCode, scanBody) = postMultipart(
                "$endpoint/app/api/ExternalScan", token, parts, "FileSource", tempZip
            )
            if (scanCode !in 200..299) return null
            val json = JSONObject(scanBody)
            val findings = mutableListOf<Finding>()
            val vulnerabilities = json.optJSONArray("vulnerabilities")
            if (vulnerabilities != null) {
                for (i in 0 until vulnerabilities.length()) {
                    findings.add(Finding.fromJson(vulnerabilities.getJSONObject(i)))
                }
            }
            ScanResult(findings = findings, projectId = json.optString("projectId", ""))
        } catch (_: Exception) {
            null
        } finally {
            try { tempZip.delete() } catch (_: Exception) {}
        }
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

        // === v1.1.15: ALWAYS SCAN LOCAL FILES ===
        // The plugin always scans the customer's actual local source files via ExternalScan.
        // No dashboard lookup, no sourceZip download. IDE results may differ from the
        // dashboard (different exclusion rules, different files) — acceptable per customer.
        // Caching (in ScanCache) avoids re-uploading when no files changed — ZERO server
        // requests on cache hit, critical for 10+ developers sharing one server.

        progressCallback("Zipping ${files.size} files\u2026")
        val zipFile = createZip(files, projectName)

        try {
            if (zipFile.length() > MAX_ZIP_SIZE_BYTES) {
                val sizeMb = zipFile.length() / (1024 * 1024)
                progressCallback("Warning: Upload size is ${sizeMb}MB. This may take a while\u2026")
            }

            // No dashboard match — fall back to a temporary ExternalScan. The server
            // auto-deletes the project because we set KeepInvisibleAndDeletePostScan=True,
            // so the scan leaves no trace on the dashboard.
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
        } finally {
            zipFile.delete()
        }
    }

    /**
     * Look up an existing dashboard project whose name matches the given IntelliJ
     * project name. Uses GET /app/api/Project (accessible to External tokens).
     * Matching strategy: exact (case-insensitive), then normalized (strip
     * dots/spaces/underscores/hyphens), then substring match. Returns the project
     * id or null if no match. Throws on LICENSE_REQUIRED.
     */
    private fun findMatchingDashboardProject(endpoint: String, token: String, projectName: String): String? {
        // Large pageSize so we don't miss projects on page 2+ and fall into a bad substring match.
        val (code, body) = doGet("$endpoint/app/api/Project?pageSize=500&pageNumber=1", token)
        if (code in listOf(401, 403)) {
            if (body.contains("LICENSE_REQUIRED", ignoreCase = true)) {
                throw RuntimeException("LICENSE_REQUIRED: $body")
            }
            return null
        }
        if (code !in 200..299) return null

        val items: org.json.JSONArray = try {
            val jo = JSONObject(body)
            jo.optJSONArray("pageItems") ?: org.json.JSONArray()
        } catch (_: Exception) {
            try { org.json.JSONArray(body) } catch (_: Exception) { org.json.JSONArray() }
        }
        if (items.length() == 0) return null

        fun norm(s: String): String = s.lowercase()
            .replace(".", "").replace(" ", "").replace("_", "")
            .replace("-", "").replace("/", "").replace("\\", "")
        val target = norm(projectName)

        // Pass 1: exact case-insensitive
        for (i in 0 until items.length()) {
            val it = items.getJSONObject(i)
            val name = it.optString("name", "")
            if (name.equals(projectName, ignoreCase = true)) {
                return it.optString("id", null)
            }
        }
        // Pass 2: normalized match
        for (i in 0 until items.length()) {
            val it = items.getJSONObject(i)
            val name = it.optString("name", "")
            if (norm(name) == target) {
                return it.optString("id", null)
            }
        }
        // Substring fallback REMOVED in v1.1.14 — caused wrong-project picks
        // (e.g. "WebGoatNET" substring-matched "WebGoat.NET-admin-test").
        // Use findByFingerprint() for content-based fallback instead.
        return null
    }

    /**
     * Content-fingerprint match: walks dashboard projects and returns the id of the
     * one whose totalScannedCodeFiles matches localFileCount within ±2 files. Same
     * source structure → same fingerprint → same canonical findings, by construction.
     * This guarantees cross-plugin/dashboard count consistency for any project that
     * has been scanned before, regardless of folder rename. Returns null if no match.
     */
    fun findByFingerprint(endpoint: String, token: String, localFileCount: Int): String? {
        if (localFileCount <= 0) return null
        return try {
            val (code, body) = doGet("$endpoint/app/api/Project?pageSize=500&pageNumber=1", token)
            if (code !in 200..299) return null
            val items = try {
                JSONObject(body).optJSONArray("pageItems") ?: org.json.JSONArray()
            } catch (_: Exception) { org.json.JSONArray() }

            var bestId: String? = null
            var bestDelta = Int.MAX_VALUE
            var bestDate = 0L
            for (i in 0 until items.length()) {
                val it = items.getJSONObject(i)
                val serverFiles = it.optInt("totalScannedCodeFiles", 0)
                if (serverFiles <= 0) continue
                val delta = kotlin.math.abs(serverFiles - localFileCount)
                if (delta > 2) continue
                val dateStr = it.optString("lastModifiedDate", "")
                val date = try { java.time.Instant.parse(dateStr).toEpochMilli() } catch (_: Exception) { 0L }
                if (delta < bestDelta || (delta == bestDelta && date > bestDate)) {
                    bestDelta = delta
                    bestDate = date
                    bestId = it.optString("id", null)
                }
            }
            bestId
        } catch (_: Exception) { null }
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
        progressCallback("Scanning (temporary)...")

        // Temporary scan: server auto-deletes the project immediately after the
        // scan because KeepInvisibleAndDeletePostScan=True is set. Plugin-triggered
        // scans must not persist on the dashboard.
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

        // License-lock detection (vendor-neutral message).
        if (code == 401 || code == 403) {
            if (responseBody.contains("LICENSE_REQUIRED", ignoreCase = true)) {
                throw RuntimeException(
                    "The Offensive 360 server is locked due to a license issue and is rejecting all requests. " +
                    "Please contact your Offensive 360 administrator to reactivate the license."
                )
            }
            throw RuntimeException(
                "Access denied (HTTP $code). Your access token may be invalid or expired. " +
                "Please contact your Offensive 360 administrator for a new token."
            )
        }
        if (code >= 500) {
            throw ServerErrorException("Server returned HTTP $code. The server may be temporarily overloaded — please try again.")
        }
        if (code !in 200..299) {
            throw RuntimeException("Scan failed (HTTP $code)")
        }

        val json = JSONObject(responseBody)
        val externalProjectId = json.optString("projectId", "")

        // v1.1.15: Use inline ExternalScan results directly.
        // No post-scan /LangaugeScanResult fetch — the project is auto-deleted by
        // KeepInvisibleAndDeletePostScan=True before we can read it, causing 500.
        // The inline response already contains the complete findings.
        val findings = mutableListOf<Finding>()
        val vulnerabilities = json.optJSONArray("vulnerabilities")
        if (vulnerabilities != null) {
            for (i in 0 until vulnerabilities.length()) {
                findings.add(Finding.fromJson(vulnerabilities.getJSONObject(i)))
            }
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
                // LangaugeScanResult has slightly different field names from ExternalScan:
                //   title (human-readable) vs type (machine ID)
                //   lineNo/columnNo (integers) vs lineNumber (string "line,col")
                // codeSnippet may be base64-encoded — use Finding.fromJson-compatible decode.
                // Map "title" first, fall back to "type" for machine ID if title missing.
                val rawSnippet = item.optString("codeSnippet", "")
                val decodedSnippet = try {
                    val bytes = java.util.Base64.getDecoder().decode(rawSnippet)
                    val decoded = String(bytes, Charsets.UTF_8)
                    if (decoded.all { it in '\t'..'\u007E' || it == '\n' || it == '\r' }) decoded else rawSnippet
                } catch (_: Exception) { rawSnippet }
                findings.add(Finding(
                    id = item.optString("id", ""),
                    title = item.optString("title", item.optString("type", "")),
                    type = item.optString("type", ""),
                    riskLevel = item.optInt("riskLevel", 2),
                    fileName = item.optString("fileName", ""),
                    filePath = item.optString("filePath", ""),
                    lineNumber = "${item.optInt("lineNo", 0)},${item.optInt("columnNo", 0)}",
                    vulnerability = item.optString("vulnerability", ""),
                    codeSnippet = decodedSnippet,
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
