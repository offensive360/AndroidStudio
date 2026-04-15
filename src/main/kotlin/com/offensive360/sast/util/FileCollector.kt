package com.offensive360.sast.util

import com.intellij.openapi.module.Module
import com.intellij.openapi.project.Project
import com.intellij.openapi.roots.ModuleRootManager
import com.intellij.openapi.roots.ProjectRootManager
import com.intellij.openapi.vfs.VirtualFile
import java.io.File

object FileCollector {

    private const val MAX_FILE_COUNT = 50_000
    private const val FILE_COUNT_WARNING_THRESHOLD = 10_000
    private const val MAX_FILE_SIZE_BYTES = 50L * 1024 * 1024

    // BLACKLIST approach (matches VS plugin's ScanCache.ExcludeExts exactly).
    // Any file whose extension is NOT in this set is considered scannable.
    // This is a superset of the old WHITELIST (which missed .aspx/.sql/.config/
    // .html/.master/.ascx/.asax/.cshtml/.razor and caused VS vs AS count drift).
    // Keep in lockstep with VS plugin's ExcludeExts in ScanCache.cs — any change
    // here MUST be mirrored in the other plugin.
    private val EXCLUDE_EXTS = setOf(
        ".zip", ".dll", ".pdf", ".exe", ".ds_store", ".bak", ".tmp",
        ".mp3", ".mp4", ".wav", ".avi", ".mov", ".wmv", ".flv",
        ".bmp", ".gif", ".jpg", ".jpeg", ".png", ".psd", ".tif", ".tiff", ".ico", ".svg",
        ".jar", ".rar", ".7z", ".gz", ".tar", ".war", ".ear",
        ".pdb", ".class", ".iml", ".nupkg", ".vsix", ".aar",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".db", ".sqlite", ".mdb", ".lock",
        ".sln", ".csproj", ".vbproj", ".vcxproj", ".fsproj", ".proj",
        ".suo", ".user", ".cache", ".snk", ".pfx", ".p12"
    )

    // Folders to skip during file collection. Must match VS plugin's
    // ScanCache.ExcludeFolders exactly to guarantee VS + AS upload identical
    // file sets for the same project (so finding counts match).
    // NOTE: backup<N> folders are matched by isExcludedFolder() pattern below,
    // not by this literal set, so don't bother adding backup4/5/etc here.
    private val SKIP_DIRS = setOf(
        ".vs", "cvs", ".svn", ".hg", ".git", ".bzr", "bin", "obj",
        ".idea", ".vscode", "node_modules", "packages",
        "dist", "build", "out", "target", ".gradle", "__pycache__",
        ".sasto360", "testresults", "test-results", ".nuget",
        ".node_modules", ".pytest_cache", ".next", "coverage"
    )

    /**
     * True if the given single-segment folder name should be skipped.
     * Combines a literal-set lookup with a pattern match for backup folders so
     * that VS migration's auto-created Backup4/Backup5 (and any future variant)
     * is automatically excluded without having to update the literal list every
     * time. Pattern: "backup", "backups", "backup1", "backup12", etc — any folder
     * whose lowercase name is "backup"/"backups" or starts with "backup" followed
     * only by digits.
     */
    private fun isExcludedFolder(segmentName: String): Boolean {
        if (segmentName.isEmpty()) return false
        val lower = segmentName.lowercase()
        if (lower in SKIP_DIRS) return true
        if (lower == "backup" || lower == "backups") return true
        if (lower.startsWith("backup") && lower.length > 6) {
            return lower.substring(6).all { it in '0'..'9' }
        }
        return false
    }

    fun collectProjectFiles(project: Project): List<File> {
        val files = mutableListOf<File>()
        val contentRoots = ProjectRootManager.getInstance(project).contentRoots
        if (contentRoots.isNotEmpty()) {
            contentRoots.forEach { root -> collectFrom(root, files) }
        } else {
            // Fallback: use project base path for non-Java/non-Android projects
            val basePath = project.basePath
            if (basePath != null) {
                val baseDir = com.intellij.openapi.vfs.LocalFileSystem.getInstance().findFileByPath(basePath)
                if (baseDir != null) {
                    collectFrom(baseDir, files)
                }
            }
        }
        checkFileCount(files)
        return files
    }

    fun collectModuleFiles(module: Module): List<File> {
        val files = mutableListOf<File>()
        ModuleRootManager.getInstance(module).contentRoots.forEach { root ->
            collectFrom(root, files)
        }
        checkFileCount(files)
        return files
    }

    fun collectSingleFile(virtualFile: VirtualFile): List<File> {
        val file = File(virtualFile.path)
        return if (file.exists() && isScannable(virtualFile.name)) listOf(file) else emptyList()
    }

    private fun collectFrom(vf: VirtualFile, out: MutableList<File>) {
        if (vf.isDirectory) {
            // Case-insensitive directory skip (Backup1 == backup1 == BACKUP1).
            // Also matches backup<N> via isExcludedFolder pattern.
            if (isExcludedFolder(vf.name)) return
            vf.children.forEach { collectFrom(it, out) }
        } else {
            if (isScannable(vf)) {
                out.add(File(vf.path))
            }
        }
    }

    /**
     * Blacklist-based scan check (matches VS plugin behaviour):
     *   - Extension must NOT be in EXCLUDE_EXTS
     *   - File size must be under 50MB (skip huge blobs the server would reject)
     */
    private fun isScannable(vf: VirtualFile): Boolean {
        val name = vf.name
        if (name.isBlank()) return false
        val dotIdx = name.lastIndexOf('.')
        val ext = if (dotIdx >= 0) name.substring(dotIdx).lowercase() else ""
        if (ext in EXCLUDE_EXTS) return false
        try {
            if (vf.length > MAX_FILE_SIZE_BYTES) return false
        } catch (_: Exception) { /* best-effort size check */ }
        return true
    }

    private fun isScannable(name: String): Boolean {
        val dotIdx = name.lastIndexOf('.')
        val ext = if (dotIdx >= 0) name.substring(dotIdx).lowercase() else ""
        return ext !in EXCLUDE_EXTS
    }

    private fun checkFileCount(files: List<File>) {
        if (files.size > MAX_FILE_COUNT) {
            throw IllegalStateException(
                "Too many files to scan (${files.size}). Maximum supported is $MAX_FILE_COUNT. " +
                "Consider scanning individual modules instead."
            )
        }
        if (files.size > FILE_COUNT_WARNING_THRESHOLD) {
            // Log a warning — callers can check this via the file count
            System.err.println("O360 SAST: Large codebase detected (${files.size} files). Scan may take longer.")
        }
    }

    /**
     * Returns the number of files that would be collected, useful for pre-checks.
     */
    fun getFileCount(project: Project): Int {
        return collectProjectFiles(project).size
    }
}
