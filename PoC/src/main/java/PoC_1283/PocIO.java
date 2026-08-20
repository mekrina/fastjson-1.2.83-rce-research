package PoC_1283;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
        ensureParent(path);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(Paths.get(path)))) {
            jos.putNextEntry(new JarEntry(entryName));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }
}
