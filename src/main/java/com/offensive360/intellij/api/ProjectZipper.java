package com.offensive360.intellij.api;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Utility for zipping project directories for scanning.
 * Uses a temporary file on disk instead of in-memory buffers to support
 * large codebases (1 GB+).
 */
public class ProjectZipper {
    private static final Set<String> EXCLUDED_EXTENSIONS = new HashSet<>(Arrays.asList(
        ".zip", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
        ".exe", ".jar", ".war", ".ear",
        ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wmv", ".flv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdb", ".nupkg", ".vsix", ".aar"
    ));

    private static final Set<String> EXCLUDED_FOLDERS = new HashSet<>(Arrays.asList(
        ".git", ".svn", ".hg", ".bzr", "cvs",
        "bin", "obj", ".vs", ".idea", ".vscode",
        "__pycache__", ".pytest_cache", ".tox",
        "vendor", "packages", "dist", "build", "out", "target",
        ".next", ".nuxt", "coverage", "node_modules",
        ".gradle", "gradle", ".m2",
        ".DS_Store"
    ));

    /**
     * Zip a project directory to a temporary file on disk.
     * The caller is responsible for deleting the returned file when done.
     *
     * @param projectDir root directory to zip
     * @return a temporary {@link File} containing the zip archive
     * @throws IOException on I/O errors
     */
    public static File zipProjectToFile(File projectDir) throws IOException {
        File tempFile = File.createTempFile("o360_scan_", ".zip");
        tempFile.deleteOnExit(); // safety net

        try (FileOutputStream fos = new FileOutputStream(tempFile);
             BufferedOutputStream bos = new BufferedOutputStream(fos, 64 * 1024);
             ZipOutputStream zipOut = new ZipOutputStream(bos)) {

            Files.walkFileTree(projectDir.toPath(), new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    String folderName = dir.getFileName().toString().toLowerCase();
                    if (EXCLUDED_FOLDERS.contains(folderName)) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    String fileName = file.getFileName().toString().toLowerCase();
                    String extension = getFileExtension(file);

                    // Skip excluded extensions
                    if (EXCLUDED_EXTENSIONS.contains(extension.toLowerCase())) {
                        return FileVisitResult.CONTINUE;
                    }

                    // Skip hidden and temporary files
                    if (fileName.startsWith(".") || fileName.endsWith(".tmp") || fileName.endsWith(".bak")) {
                        return FileVisitResult.CONTINUE;
                    }

                    Path relPath = projectDir.toPath().relativize(file);
                    ZipEntry entry = new ZipEntry(relPath.toString().replace("\\", "/"));
                    zipOut.putNextEntry(entry);
                    Files.copy(file, zipOut);
                    zipOut.closeEntry();

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Skip files we cannot read
                    return FileVisitResult.CONTINUE;
                }
            });
        }

        return tempFile;
    }

    /**
     * Legacy in-memory method retained for backward compatibility with small projects.
     * Prefer {@link #zipProjectToFile(File)} for production use.
     */
    public static byte[] zipProject(File projectDir) throws IOException {
        File tempFile = zipProjectToFile(projectDir);
        try {
            return Files.readAllBytes(tempFile.toPath());
        } finally {
            tempFile.delete();
        }
    }

    private static String getFileExtension(Path path) {
        String fileName = path.getFileName().toString();
        int lastDot = fileName.lastIndexOf('.');
        return lastDot > 0 ? fileName.substring(lastDot) : "";
    }
}
