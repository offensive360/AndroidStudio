package com.offensive360.sast.api

import com.offensive360.sast.models.Finding
import com.offensive360.sast.models.ScanResult
import com.offensive360.sast.settings.O360Settings
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.asRequestBody
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class O360ApiClient {

    private val client = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(300, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .build()

    fun scan(files: List<File>, projectName: String, progressCallback: (String) -> Unit): ScanResult {
        val settings = O360Settings.getInstance()
        val endpoint = settings.endpoint.trimEnd('/')
        val token = settings.accessToken

        progressCallback("Zipping files…")
        val zipFile = createZip(files, projectName)

        try {
            progressCallback("Uploading to O360 SAST…")

            val body = MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("name", projectName)
                .addFormDataPart("externalScanSourceType", "IntelijExtension")
                .addFormDataPart("allowDependencyScan", settings.scanDependencies.toString())
                .addFormDataPart("allowLicenseScan", settings.scanLicenses.toString())
                .addFormDataPart("allowMalwareScan", settings.scanMalware.toString())
                .addFormDataPart(
                    "fileSource",
                    zipFile.name,
                    zipFile.asRequestBody("application/zip".toMediaType())
                )
                .build()

            val request = Request.Builder()
                .url("$endpoint/app/api/ExternalScan")
                .addHeader("Authorization", "Bearer $token")
                .post(body)
                .build()

            progressCallback("Scanning…")

            client.newCall(request).execute().use { response ->
                val responseBody = response.body?.string() ?: ""

                if (!response.isSuccessful) {
                    throw RuntimeException("Scan failed (HTTP ${response.code}): $responseBody")
                }

                val json = JSONObject(responseBody)
                val vulnerabilities = json.optJSONArray("vulnerabilities")
                val findings = mutableListOf<Finding>()

                if (vulnerabilities != null) {
                    for (i in 0 until vulnerabilities.length()) {
                        findings.add(Finding.fromJson(vulnerabilities.getJSONObject(i)))
                    }
                }

                return ScanResult(
                    findings = findings,
                    projectId = json.optString("projectId", "")
                )
            }
        } finally {
            zipFile.delete()
        }
    }

    private fun createZip(files: List<File>, projectName: String): File {
        val zipFile = File(System.getProperty("java.io.tmpdir"), "o360_scan_${UUID.randomUUID()}.zip")
        ZipOutputStream(FileOutputStream(zipFile)).use { zos ->
            for (file in files) {
                if (!file.exists() || !file.isFile) continue
                // Use relative path as entry name
                zos.putNextEntry(ZipEntry(file.name))
                file.inputStream().use { it.copyTo(zos) }
                zos.closeEntry()
            }
        }
        return zipFile
    }

    companion object {
        val instance = O360ApiClient()
    }
}
