package utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/** 输出文件工具：统一处理父目录创建、无父目录边界、写 jar。 */
public final class PocIO {

    private PocIO() {}

    /** 确保 path 的父目录存在；无父目录（如 "x.jar"）时跳过，不会 NPE */
    public static void ensureParent(String path) throws IOException {
        Path parent = Paths.get(path).toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }

    /** 把单个 class 字节码打包成 jar 文件（自动创建父目录） */
    public static void writeJar(String path, String entryName, byte[] classBytes) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(entryName, classBytes);
        writeJar(path, entries);
    }

    /** 把多个 entry（entryName -> class 字节码）打包成 jar 文件（自动创建父目录） */
    public static void writeJar(String path, Map<String, byte[]> entries) throws IOException {
        ensureParent(path);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(Paths.get(path)))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                jos.putNextEntry(new JarEntry(e.getKey()));
                jos.write(e.getValue());
                jos.closeEntry();
            }
        }
    }

    /** 写文本文件（UTF-8，自动创建父目录） */
    public static void writeText(String path, String text) throws IOException {
        ensureParent(path);
        Files.write(Paths.get(path), text.getBytes(StandardCharsets.UTF_8));
    }
}
