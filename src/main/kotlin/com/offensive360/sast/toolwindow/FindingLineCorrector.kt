package com.offensive360.sast.toolwindow

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.Computable
import com.intellij.openapi.vfs.VirtualFile
import com.offensive360.sast.models.Finding

/**
 * Repairs line numbers on findings that come back from the server with stale
 * line metadata (a known scanner-side issue: line numbers can drift relative
 * to the original source). For each finding we try to locate the codeSnippet
 * in the actual file content and rewrite lineNumber to the true line.
 *
 * - If the snippet matches at the reported line: keep as-is.
 * - If the snippet is found at a different line: rewrite lineNumber.
 * - If the snippet cannot be located in the file at all: drop the finding
 *   (we cannot navigate accurately and would mislead the user).
 * - If we can't read the file (no project resolution, file not in workspace,
 *   no snippet to compare): keep as-is (give the finding the benefit of the
 *   doubt rather than hide what could be a legitimate vulnerability).
 *
 * Returns (corrected list, count of corrections, count of drops).
 */
object FindingLineCorrector {

    data class Result(val findings: List<Finding>, val corrected: Int, val dropped: Int)

    fun apply(findings: List<Finding>, project: Project, fileResolver: (Finding) -> VirtualFile?): Result {
        if (findings.isEmpty()) return Result(findings, 0, 0)
        return ApplicationManager.getApplication().runReadAction(Computable {
            var corrected = 0
            var dropped = 0
            val out = ArrayList<Finding>(findings.size)
            for (f in findings) {
                val verdict = process(f, project, fileResolver)
                when (verdict) {
                    is Verdict.Keep -> out.add(verdict.finding)
                    is Verdict.Corrected -> { corrected++; out.add(verdict.finding) }
                    Verdict.Drop -> { dropped++ }
                }
            }
            Result(out, corrected, dropped)
        })
    }

    private sealed class Verdict {
        data class Keep(val finding: Finding) : Verdict()
        data class Corrected(val finding: Finding) : Verdict()
        object Drop : Verdict()
    }

    private fun process(f: Finding, project: Project, fileResolver: (Finding) -> VirtualFile?): Verdict {
        val snippet = f.codeSnippet?.trim().orEmpty()
        // Nothing to verify against — keep.
        if (snippet.length < 8) return Verdict.Keep(f)

        val vf = fileResolver(f) ?: return Verdict.Keep(f)
        val text = try { String(vf.contentsToByteArray(), Charsets.UTF_8) } catch (_: Exception) { return Verdict.Keep(f) }
        val lines = text.split('\n')
        if (lines.isEmpty()) return Verdict.Keep(f)

        val needle = normalize(snippet)
        if (needle.length < 8) return Verdict.Keep(f)

        // Reported line correct?
        val reportedIdx = (f.line - 1).coerceAtLeast(0)
        if (reportedIdx in lines.indices && contains(lines[reportedIdx], needle)) {
            return Verdict.Keep(f)
        }

        // Reported line wrong — try to find the snippet anywhere in the file.
        val foundIdx = locate(lines, needle)
        if (foundIdx < 0) return Verdict.Drop                              // can't locate at all → drop
        val newLine = foundIdx + 1
        if (newLine == f.line) return Verdict.Keep(f)                      // same line after all
        return Verdict.Corrected(f.copy(lineNumber = newLine.toString()))
    }

    private fun normalize(s: String): String {
        // Collapse whitespace, lowercase. Keeps the snippet match resilient to
        // formatter differences (tabs vs spaces, indentation changes).
        val sb = StringBuilder(s.length)
        for (ch in s) if (!ch.isWhitespace()) sb.append(ch.lowercaseChar())
        return sb.toString()
    }

    private fun contains(line: String, normNeedle: String): Boolean {
        val hay = normalize(line)
        if (hay.isEmpty()) return false
        // Either the needle's first 24 chars appear in this line, or this line
        // is a substring of the needle (snippet might span multiple lines).
        val short = if (normNeedle.length > 24) normNeedle.substring(0, 24) else normNeedle
        return hay.contains(short) || (hay.length >= 8 && normNeedle.contains(hay))
    }

    private fun locate(lines: List<String>, normNeedle: String): Int {
        val short = if (normNeedle.length > 24) normNeedle.substring(0, 24) else normNeedle
        for (i in lines.indices) {
            val hay = normalize(lines[i])
            if (hay.contains(short)) return i
        }
        return -1
    }
}
