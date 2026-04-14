package com.offensive360.sast.models

import org.json.JSONObject

data class Finding(
    val id: String,
    val title: String,
    val type: String,
    val riskLevel: Int,
    val fileName: String,
    val filePath: String,
    val lineNumber: String,
    val vulnerability: String,
    val codeSnippet: String?,
    val effect: String?,
    val recommendation: String?
) {
    val severity: Severity get() = when (riskLevel) {
        4 -> Severity.CRITICAL
        3 -> Severity.HIGH
        2 -> Severity.MEDIUM
        1 -> Severity.LOW
        else -> Severity.INFO
    }

    val line: Int get() = lineNumber.substringBefore(",").toIntOrNull() ?: 1

    companion object {
        fun fromJson(obj: JSONObject): Finding = Finding(
            id = obj.optString("id"),
            title = obj.optString("title"),
            type = obj.optString("type"),
            riskLevel = obj.optInt("riskLevel", 0),
            fileName = obj.optString("fileName"),
            filePath = obj.optString("filePath"),
            lineNumber = obj.optString("lineNumber", "1"),
            vulnerability = obj.optString("vulnerability"),
            codeSnippet = decodeIfBase64(obj.optString("codeSnippet")),
            effect = obj.optString("effect").takeIf { it.isNotBlank() },
            recommendation = obj.optString("recommendation").takeIf { it.isNotBlank() }
        )

        /** Server sometimes returns base64-encoded code snippets (from AI engine). Detect and decode. */
        private fun decodeIfBase64(value: String?): String? {
            if (value.isNullOrBlank()) return null
            // If it looks like plain code (has spaces, operators, quotes), return as-is
            if (value.contains(' ') || value.contains('(') || value.contains('"') || value.contains('=') && value.contains(';'))
                return value
            // Try base64 decode
            return try {
                val decoded = String(java.util.Base64.getDecoder().decode(value), Charsets.UTF_8)
                // Verify decoded looks like code (printable chars)
                if (decoded.all { it.code in 9..126 }) decoded else value
            } catch (_: Exception) {
                value
            }
        }
    }
}

enum class Severity(val label: String, val color: String) {
    CRITICAL("Critical", "#FF3B3B"),
    HIGH("High", "#FF8C00"),
    MEDIUM("Medium", "#FFD700"),
    LOW("Low", "#4FC3F7"),
    INFO("Info", "#90A4AE")
}

data class ScanResult(
    val findings: List<Finding>,
    val projectId: String
)
