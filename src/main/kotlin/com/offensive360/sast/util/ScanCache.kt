package com.offensive360.sast.util

import com.offensive360.sast.models.Finding
import com.offensive360.sast.models.ScanResult
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

object ScanCache {

    private const val CACHE_DIR = ".SASTO360"
    private const val CACHE_FILE = "lastScanResults.json"
    // Schema version is now derived from the plugin descriptor version. Every new
    // plugin install/upgrade automatically invalidates any prior cache for the project,
    // while user settings (token, URL, ignore lists — stored in o360sast.xml) remain
    // untouched. Customers no longer need to manually clear cache after upgrading.
    private val CACHE_SCHEMA_VERSION: String by lazy {
        try {
            val pid = com.intellij.openapi.extensions.PluginId.getId("com.offensive360.sast")
            val v = com.intellij.ide.plugins.PluginManagerCore.getPlugin(pid)?.version ?: "unknown"
            "plugin-$v"
        } catch (_: Throwable) {
            "plugin-unknown"
        }
    }
    private const val SCHEMA_MARKER_FILE = "schema.version"

    /**
     * Wipes any cache from a prior plugin version on first load after upgrade.
     * Idempotent: writes a schema-version marker so this only runs once per upgrade.
     */
    private fun ensureFreshSchema(projectBasePath: String) {
        try {
            val cacheDir = File(projectBasePath, CACHE_DIR)
            if (!cacheDir.exists()) return
            val markerFile = File(cacheDir, SCHEMA_MARKER_FILE)
            val existing = if (markerFile.exists()) markerFile.readText().trim() else ""
            if (existing == CACHE_SCHEMA_VERSION) return
            // Schema mismatch (or first run after upgrade) — delete stale cache
            File(cacheDir, CACHE_FILE).takeIf { it.exists() }?.delete()
            markerFile.writeText(CACHE_SCHEMA_VERSION)
        } catch (_: Exception) {
            // best-effort cleanup
        }
    }

    /**
     * Compute MD5 hash of a file's contents.
     */
    fun md5(file: File): String {
        val digest = MessageDigest.getInstance("MD5")
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (input.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Compute MD5 hashes for all files in the list.
     */
    fun computeFileHashes(files: List<File>): Map<String, String> {
        val hashes = mutableMapOf<String, String>()
        for (file in files) {
            if (file.exists() && file.isFile) {
                try {
                    hashes[file.absolutePath] = md5(file)
                } catch (_: Exception) {
                    // Skip files we cannot read
                }
            }
        }
        return hashes
    }

    /**
     * Save scan results and file hashes to cache file.
     * serverTotal is the server-reported totalVulnerabilities count (persisted so we
     * can detect cache tampering / drift on load).
     */
    fun save(projectBasePath: String, findings: List<Finding>, fileHashes: Map<String, String>, serverTotal: Int? = null) {
        val cacheDir = File(projectBasePath, CACHE_DIR)
        if (!cacheDir.exists()) {
            cacheDir.mkdirs()
        }

        val json = JSONObject()
        json.put("timestamp", System.currentTimeMillis())
        json.put("totalVulnerabilities", serverTotal ?: findings.size)

        val hashesObj = JSONObject()
        for ((path, hash) in fileHashes) {
            hashesObj.put(path, hash)
        }
        json.put("fileHashes", hashesObj)

        val findingsArray = JSONArray()
        for (finding in findings) {
            val fObj = JSONObject()
            fObj.put("id", finding.id)
            fObj.put("title", finding.title)
            fObj.put("type", finding.type)
            fObj.put("riskLevel", finding.riskLevel)
            fObj.put("fileName", finding.fileName)
            fObj.put("filePath", finding.filePath)
            fObj.put("lineNumber", finding.lineNumber)
            fObj.put("vulnerability", finding.vulnerability)
            fObj.put("codeSnippet", finding.codeSnippet ?: "")
            fObj.put("effect", finding.effect ?: "")
            fObj.put("recommendation", finding.recommendation ?: "")
            findingsArray.put(fObj)
        }
        json.put("findings", findingsArray)

        File(cacheDir, CACHE_FILE).writeText(json.toString(2))
    }

    /**
     * Load cached scan results. Returns null if cache does not exist, is unreadable,
     * or fails the integrity check (stored totalVulnerabilities != findings array length).
     */
    fun load(projectBasePath: String): CachedScanData? {
        ensureFreshSchema(projectBasePath)
        val cacheFile = File(projectBasePath, "$CACHE_DIR/$CACHE_FILE")
        if (!cacheFile.exists()) return null

        return try {
            val json = JSONObject(cacheFile.readText())
            val timestamp = json.optLong("timestamp", 0L)
            val storedTotal = if (json.has("totalVulnerabilities")) json.optInt("totalVulnerabilities", -1) else -1

            val hashesObj = json.optJSONObject("fileHashes") ?: JSONObject()
            val fileHashes = mutableMapOf<String, String>()
            for (key in hashesObj.keys()) {
                fileHashes[key] = hashesObj.getString(key)
            }

            val findingsArray = json.optJSONArray("findings") ?: JSONArray()
            val findings = mutableListOf<Finding>()
            for (i in 0 until findingsArray.length()) {
                val fObj = findingsArray.getJSONObject(i)
                findings.add(Finding(
                    id = fObj.optString("id", ""),
                    title = fObj.optString("title", ""),
                    type = fObj.optString("type", ""),
                    riskLevel = fObj.optInt("riskLevel", 0),
                    fileName = fObj.optString("fileName", ""),
                    filePath = fObj.optString("filePath", ""),
                    lineNumber = fObj.optString("lineNumber", "1"),
                    vulnerability = fObj.optString("vulnerability", ""),
                    codeSnippet = fObj.optString("codeSnippet").takeIf { it.isNotBlank() },
                    effect = fObj.optString("effect").takeIf { it.isNotBlank() },
                    recommendation = fObj.optString("recommendation").takeIf { it.isNotBlank() }
                ))
            }

            // Integrity check: if we have a server-reported total, it MUST match the
            // cached array length. Any drift = stale/corrupted cache → discard.
            if (storedTotal >= 0 && storedTotal != findings.size) {
                try { cacheFile.delete() } catch (_: Exception) {}
                return null
            }

            CachedScanData(timestamp, fileHashes, findings)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Check whether any files have changed compared to cached hashes.
     * Returns true if files have changed or cache is missing.
     */
    fun hasFilesChanged(currentHashes: Map<String, String>, cachedHashes: Map<String, String>): Boolean {
        if (currentHashes.size != cachedHashes.size) return true
        for ((path, hash) in currentHashes) {
            if (cachedHashes[path] != hash) return true
        }
        return false
    }

    data class CachedScanData(
        val timestamp: Long,
        val fileHashes: Map<String, String>,
        val findings: List<Finding>
    )
}
