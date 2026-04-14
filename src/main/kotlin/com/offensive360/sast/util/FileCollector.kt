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

    private val SCANNABLE_EXTENSIONS = setOf(
        "cs", "java", "kt", "kts", "js", "ts", "jsx", "tsx",
        "py", "php", "rb", "go", "swift", "m", "mm", "cpp", "c", "h",
        "dart", "scala", "groovy", "apex", "cls", "trigger",
        "xml", "yaml", "yml", "json", "tf", "dockerfile"
    )

    private val SKIP_DIRS = setOf(
        ".git", ".idea", ".gradle", "build", "out", "target",
        "node_modules", ".node_modules", "__pycache__", ".pytest_cache",
        "bin", "obj", ".vs", ".vscode", "dist", ".next", "coverage",
        ".sasto360", ".SASTO360"
    )

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
            if (vf.name in SKIP_DIRS) return
            vf.children.forEach { collectFrom(it, out) }
        } else {
            if (isScannable(vf.name)) {
                out.add(File(vf.path))
            }
        }
    }

    private fun isScannable(name: String): Boolean {
        val ext = name.substringAfterLast('.', "").lowercase()
        return ext in SCANNABLE_EXTENSIONS
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
