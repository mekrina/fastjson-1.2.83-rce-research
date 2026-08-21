package utils;

import java.util.Locale;

/** JSON 输出工具（payload / metadata 生成用）。 */
public final class JsonUtil {

    private JsonUtil() {}

    /** 生成 JSON 字符串字面量（ASCII 转义非可见字符） */
    public static String quote(String value) {
        StringBuilder json = new StringBuilder(value.length() + 8);
        json.append('"');
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '\\':
                    json.append("\\\\");
                    break;
                case '"':
                    json.append("\\\"");
                    break;
                case '\b':
                    json.append("\\b");
                    break;
                case '\f':
                    json.append("\\f");
                    break;
                case '\n':
                    json.append("\\n");
                    break;
                case '\r':
                    json.append("\\r");
                    break;
                case '\t':
                    json.append("\\t");
                    break;
                default:
                    if (ch < 0x20 || ch > 0x7E) {
                        json.append('\\').append(String.format(Locale.ROOT, "u%04X", (int) ch));
                    } else {
                        json.append(ch);
                    }
            }
        }
        return json.append('"').toString();
    }

    public static String hex(long value) {
        return String.format(Locale.ROOT, "0x%016X", value);
    }

    /** int 数组 → JSON 数组文本 */
    public static String intArray(int[] values) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(values[i]);
        }
        return json.append(']').toString();
    }

    /** code units → Unicode 转义文本 */
    public static String escapeCodeUnits(int[] values) {
        StringBuilder escaped = new StringBuilder();
        for (int value : values) {
            escaped.append('\\').append(String.format(Locale.ROOT, "u%04X", value));
        }
        return escaped.toString();
    }
}
