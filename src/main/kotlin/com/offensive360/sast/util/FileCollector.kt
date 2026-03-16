package com.offensive360.sast.util

import com.intellij.openapi.module.Module
import com.intellij.openapi.project.Project
import com.intellij.openapi.roots.ModuleRootManager
import com.intellij.openapi.roots.ProjectRootManager
import com.intellij.openapi.vfs.VirtualFile
import java.io.File

object FileCollector {

    private val SCANNABLE_EXTENSIONS = setOf(
        "cs", "java", "kt", "kts", "js", "ts", "jsx", "tsx",
        "py", "php", "rb", "go", "swift", "m", "mm", "cpp", "c", "h",
        "dart", "scala", "groovy", "apex", "cls", "trigger",
        "xml", "yaml", "yml", "json", "tf", "dockerfile"
    )

    private val SKIP_DIRS = setOf(
        ".git", ".idea", ".gradle", "build", "out", "target",
        "node_modules", ".node_modules", "__pycache__", ".pytest_cache",
        "bin", "obj", ".vs", ".vscode", "dist", ".next", "coverage"
    )

    fun collectProjectFiles(project: Project): List<File> {
        val files = mutableListOf<File>()
        ProjectRootManager.getInstance(project).contentRoots.forEach { root ->
            collectFrom(root, files)
        }
        return files
    }

    fun collectModuleFiles(module: Module): List<File> {
        val files = mutableListOf<File>()
        ModuleRootManager.getInstance(module).contentRoots.forEach { root ->
            collectFrom(root, files)
        }
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
}
