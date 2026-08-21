package utils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 从 code_to_run.txt 读取要执行的代码，并包裹 try-catch 兜底 Throwable（含 Error），
 * 避免 <clinit> 抛异常导致类加载失败。
 *
 * 文件查找顺序：当前目录 -> poc/ 子目录（即从 fastjson 项目根 或 poc/ 目录运行均可）。
 */
public final class CodeLoader {

    private static final String[] CANDIDATES = {"code_to_run.txt", "poc/code_to_run.txt"};

    private CodeLoader() {}

    /** 读取代码并生成最终 static{} 方法体（已 try-catch 包裹） */
    public static String loadBody() throws IOException {
        Path found = null;
        for (String candidate : CANDIDATES) {
            Path p = Paths.get(candidate);
            if (Files.exists(p)) {
                found = p;
                break;
            }
        }
        if (found == null) {
            throw new IOException("code_to_run.txt not found (tried: "
                    + String.join(", ", CANDIDATES)
                    + "). Run from project root or poc/ dir.");
        }

        String code = new String(Files.readAllBytes(found), StandardCharsets.UTF_8);
        return "try { " + code + " } catch (Throwable t) {}";
    }
}
