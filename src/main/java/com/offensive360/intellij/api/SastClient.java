package com.offensive360.intellij.api;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import com.intellij.openapi.progress.ProgressIndicator;
import com.offensive360.intellij.models.DepVulnerability;
import com.offensive360.intellij.models.LangVulnerability;
import com.offensive360.intellij.models.LicenseIssue;
import com.offensive360.intellij.models.MalwareResult;
import okhttp3.*;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonDeserializationContext;

/**
 * HTTP client for Offensive360 SAST API.
 * Handles authentication, scanning, and result retrieval.
 */
public class SastClient {
    private static final String SCAN_FILE_ENDPOINT = "/app/api/Project/scanProjectFile";
    private static final String PROJECT_ENDPOINT = "/app/api/Project";
    private static final String GIT_REPO_SCAN_ENDPOINT = "/app/api/Project/scanGitRepo";
    private static final int POLL_INTERVAL_SECONDS = 10;
    private static final int MAX_WAIT_MINUTES = 60;

    private final String endpoint;
    private final String accessToken;
    private final OkHttpClient httpClient;
    private final Gson gson;

    public SastClient(String endpoint, String accessToken) {
        this.endpoint = endpoint.replaceAll("/$", "");
        this.accessToken = accessToken;
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(60, TimeUnit.SECONDS)
            .readTimeout(600, TimeUnit.SECONDS)
            .writeTimeout(600, TimeUnit.SECONDS)
            .build();
        // Custom deserializer: handles List<String> fields that the server
        // may return as either a JSON array OR a plain string.
        this.gson = new GsonBuilder()
            .registerTypeAdapter(
                new TypeToken<List<String>>() {}.getType(),
                (JsonDeserializer<List<String>>) (json, typeOfT, context) -> {
                    List<String> list = new ArrayList<>();
                    if (json.isJsonArray()) {
                        for (JsonElement el : json.getAsJsonArray()) {
                            if (!el.isJsonNull()) list.add(el.getAsString());
                        }
                    } else if (json.isJsonPrimitive()) {
                        String val = json.getAsString();
                        if (val != null && !val.isEmpty()) {
                            list.add(val);
                        }
                    }
                    return list;
                })
            .create();
    }

    // ── Token verification ────────────────────────────────────────────

    /**
     * Typed result from token verification, carrying the HTTP status code.
     */
    public static class TokenVerifyResult {
        public final boolean valid;
        public final int statusCode;
        public final boolean networkError;

        public TokenVerifyResult(boolean valid, int statusCode, boolean networkError) {
            this.valid = valid;
            this.statusCode = statusCode;
            this.networkError = networkError;
        }
    }

    /**
     * Verify that the API token is valid. Returns a typed result with status code.
     */
    public TokenVerifyResult verifyTokenTyped() {
        String url = endpoint + PROJECT_ENDPOINT + "?page=1&pageSize=1";
        Request request = new Request.Builder()
            .url(url)
            .addHeader("Authorization", "Bearer " + accessToken)
            .get()
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            return new TokenVerifyResult(response.isSuccessful(), response.code(), false);
        } catch (IOException e) {
            return new TokenVerifyResult(false, 0, true);
        }
    }

    /**
     * Legacy boolean verify method for backward compatibility.
     */
    public boolean verifyToken() throws IOException {
        TokenVerifyResult result = verifyTokenTyped();
        if (result.networkError) {
            throw new IOException("Network error while verifying token");
        }
        return result.valid;
    }

    // ── Project scan (zip upload) ─────────────────────────────────────

    /**
     * Scan a directory or project. Uses temp-file-based zip.
     * Returns a ScanResult with pre-fetched results (fetched immediately on completion,
     * before the server deletes the ephemeral project).
     */
    public ScanResult scanProject(File projectDir, String projectName, ProgressIndicator progress) throws IOException, InterruptedException {
        progress.setText("Creating project archive...");
        File zipFile = ProjectZipper.zipProjectToFile(projectDir);
        try {
            progress.setFraction(0.3);
            progress.setText("Uploading to SAST server...");
            String scanUrl = endpoint + SCAN_FILE_ENDPOINT;

            MultipartBody.Builder multipartBuilder = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("FileSource", projectName + ".zip",
                    RequestBody.create(zipFile, MediaType.parse("application/zip")))
                .addFormDataPart("Name", projectName)
                .addFormDataPart("ExternalScanSourceType", "IntellijExtension");
                // KeepInvisibleAndDeletePostScan disabled until server-side delayed deletion is fixed
                // .addFormDataPart("KeepInvisibleAndDeletePostScan", "True");

            Request request = new Request.Builder()
                .url(scanUrl)
                .addHeader("Authorization", "Bearer " + accessToken)
                .post(multipartBuilder.build())
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("Scan upload failed: " + response.code() + " " + response.message());
                }

                String body = response.body().string();
                String projectId = null;
                try {
                    JsonElement parsed = JsonParser.parseString(body);
                    if (parsed.isJsonObject()) {
                        JsonObject result = parsed.getAsJsonObject();
                        projectId = result.has("id") ? result.get("id").getAsString()
                            : result.has("projectId") ? result.get("projectId").getAsString() : null;
                    } else if (parsed.isJsonPrimitive()) {
                        projectId = parsed.getAsString();
                    }
                } catch (Exception e) {
                    // Response might be a raw string
                    projectId = body.trim().replace("\"", "");
                }

                if (projectId == null || projectId.isEmpty()) {
                    throw new IOException("No project ID in response: " + body);
                }

                progress.setFraction(0.5);
                // Wait for completion AND fetch results immediately (before server deletes ephemeral project)
                return waitForScanAndFetchResults(projectId, projectName, progress);
            }
        } finally {
            // Clean up temp file
            if (zipFile.exists()) {
                zipFile.delete();
            }
        }
    }

    // ── Git repo scan ─────────────────────────────────────────────────

    /**
     * Scan a remote Git repository by URL and branch.
     * Returns a ScanResult with pre-fetched results.
     */
    public ScanResult scanGitRepo(String repoUrl, String branch, ProgressIndicator progress) throws IOException, InterruptedException {
        progress.setText("Submitting Git repository for scanning...");

        JsonObject payload = new JsonObject();
        payload.addProperty("gitRepoUrl", repoUrl);
        payload.addProperty("branch", branch);

        RequestBody body = RequestBody.create(
            gson.toJson(payload), MediaType.parse("application/json"));

        Request request = new Request.Builder()
            .url(endpoint + GIT_REPO_SCAN_ENDPOINT)
            .addHeader("Authorization", "Bearer " + accessToken)
            .post(body)
            .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException("Git repo scan failed: " + response.code() + " " + response.message());
            }

            String respBody = response.body().string();
            String projectId = null;
            try {
                JsonElement parsed = JsonParser.parseString(respBody);
                if (parsed.isJsonObject()) {
                    JsonObject result = parsed.getAsJsonObject();
                    projectId = result.has("id") ? result.get("id").getAsString()
                        : result.has("projectId") ? result.get("projectId").getAsString() : null;
                } else if (parsed.isJsonPrimitive()) {
                    projectId = parsed.getAsString();
                }
            } catch (Exception e) {
                projectId = respBody.trim().replace("\"", "");
            }

            if (projectId == null || projectId.isEmpty()) {
                throw new IOException("No project ID in response: " + respBody);
            }

            progress.setFraction(0.4);

            // Derive a project name from the repo URL for queue polling
            String projectName = repoUrl;
            int lastSlash = repoUrl.lastIndexOf('/');
            if (lastSlash >= 0) {
                projectName = repoUrl.substring(lastSlash + 1).replace(".git", "");
            }

            return waitForScanAndFetchResults(projectId, projectName, progress);
        }
    }

    // ── Poll for completion + immediate result fetch ──────────────────

    /**
     * Polls until scan completes, then immediately fetches results before the
     * server can delete the ephemeral project (KeepInvisibleAndDeletePostScan).
     */
    private ScanResult waitForScanAndFetchResults(String projectId, String projectName, ProgressIndicator progress) throws IOException, InterruptedException {
        long startTime = System.currentTimeMillis();
        long maxWaitMs = MAX_WAIT_MINUTES * 60 * 1000L;
        boolean firstPoll = true;

        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (progress.isCanceled()) {
                throw new InterruptedException("Scan cancelled by user");
            }

            // Short initial delay (3s), then standard interval — avoids missing fast scans
            Thread.sleep(firstPoll ? 3000L : POLL_INTERVAL_SECONDS * 1000L);
            firstPoll = false;

            String statusUrl = endpoint + PROJECT_ENDPOINT + "/" + projectId;
            Request request = new Request.Builder()
                .url(statusUrl)
                .addHeader("Authorization", "Bearer " + accessToken)
                .get()
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.code() == 404) {
                    // Project not found — may have been deleted or ID is invalid
                    throw new IOException("Project not found (404). The scan may have been deleted by the server.");
                }
                if (response.isSuccessful()) {
                    String body = response.body().string();
                    JsonObject project = gson.fromJson(body, JsonObject.class);
                    int status = project.has("status") ? project.get("status").getAsInt() : -1;

                    switch (status) {
                        case 2: // Succeeded
                        case 4: // Partial Failed — some results may be available
                            progress.setFraction(0.9);
                            progress.setText("Retrieving scan results...");
                            // Fetch results IMMEDIATELY before server deletes the ephemeral project
                            return getScanResults(projectId);
                        case 3: // Failed
                            throw new IOException("Scan failed on server");
                        case 5: // Skipped
                            throw new IOException("Scan was skipped by server");
                        default: // 0=Queued, 1=InProgress
                            String statusText = status == 0 ? "Queued" : status == 1 ? "In Progress" : "Status: " + status;
                            progress.setText("Scan " + statusText + "...");
                            progress.setFraction(0.5 + (0.4 * (System.currentTimeMillis() - startTime) / maxWaitMs));
                            break;
                    }
                }
            }
        }

        throw new IOException("Scan timed out after " + MAX_WAIT_MINUTES + " minutes");
    }

    // ── Typed result retrieval ────────────────────────────────────────

    /**
     * Typed result holder using model classes instead of raw JsonArray.
     */
    public static class ScanResult {
        public String projectId;
        public List<LangVulnerability> languageVulnerabilities = Collections.emptyList();
        public List<DepVulnerability> dependencyVulnerabilities = Collections.emptyList();
        public List<MalwareResult> malwareResults = Collections.emptyList();
        public List<LicenseIssue> licenseIssues = Collections.emptyList();

        public int getTotalCount() {
            return languageVulnerabilities.size() + dependencyVulnerabilities.size()
                 + malwareResults.size() + licenseIssues.size();
        }
    }

    /**
     * Get scan results parsed into typed models.
     * Called immediately after scan completion — must be fast before server deletes ephemeral project.
     */
    private ScanResult getScanResults(String projectId) throws IOException {
        ScanResult results = new ScanResult();
        results.projectId = projectId;
        results.languageVulnerabilities = getTypedResults(projectId, "/LangaugeScanResult",
            new TypeToken<List<LangVulnerability>>() {}.getType());
        results.dependencyVulnerabilities = getTypedResults(projectId, "/DependencyScanResult",
            new TypeToken<List<DepVulnerability>>() {}.getType());
        results.malwareResults = getTypedResults(projectId, "/MalwareScanResult",
            new TypeToken<List<MalwareResult>>() {}.getType());
        results.licenseIssues = getTypedResults(projectId, "/LicenseScanResult",
            new TypeToken<List<LicenseIssue>>() {}.getType());
        return results;
    }

    /**
     * Fetch and parse a paginated result endpoint into a typed list.
     */
    private <T> List<T> getTypedResults(String projectId, String path, Type listType) throws IOException {
        List<T> allItems = new ArrayList<>();
        int page = 1;
        int pageSize = 100;

        while (true) {
            String url = endpoint + "/app/api/Project/" + projectId + path
                + "?page=" + page + "&pageSize=" + pageSize;

            Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + accessToken)
                .get()
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new IOException("Failed to fetch results from " + path + ": HTTP " + response.code());
                }

                String body = response.body().string();
                if (body == null || body.isEmpty()) break;

                JsonElement rootElement = JsonParser.parseString(body);

                JsonArray itemsArray = null;

                if (rootElement.isJsonObject()) {
                    JsonObject jsonObj = rootElement.getAsJsonObject();
                    // Handle paginated responses
                    if (jsonObj.has("pageItems")) {
                        itemsArray = jsonObj.get("pageItems").getAsJsonArray();
                    } else if (jsonObj.has("items")) {
                        itemsArray = jsonObj.get("items").getAsJsonArray();
                    } else if (jsonObj.has("data")) {
                        JsonElement dataEl = jsonObj.get("data");
                        if (dataEl.isJsonArray()) {
                            itemsArray = dataEl.getAsJsonArray();
                        }
                    }
                } else if (rootElement.isJsonArray()) {
                    itemsArray = rootElement.getAsJsonArray();
                }

                if (itemsArray == null || itemsArray.size() == 0) {
                    break;
                }

                List<T> pageItems = gson.fromJson(itemsArray, listType);
                if (pageItems != null) {
                    allItems.addAll(pageItems);
                }

                // If fewer items than page size, we've reached the last page
                if (itemsArray.size() < pageSize) {
                    break;
                }

                page++;
            }
        }

        return allItems;
    }
}
