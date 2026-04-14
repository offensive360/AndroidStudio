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
     */
    fun save(projectBasePath: String, findings: List<Finding>, fileHashes: Map<String, String>) {
        val cacheDir = File(projectBasePath, CACHE_DIR)
        if (!cacheDir.exists()) {
            cacheDir.mkdirs()
        }

        val json = JSONObject()
        json.put("timestamp", System.currentTimeMillis())

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
     * Load cached scan results. Returns null if cache does not exist or is unreadable.
     */
    fun load(projectBasePath: String): CachedScanData? {
        val cacheFile = File(projectBasePath, "$CACHE_DIR/$CACHE_FILE")
        if (!cacheFile.exists()) return null

        return try {
            val json = JSONObject(cacheFile.readText())
            val timestamp = json.optLong("timestamp", 0L)

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
