package poc_2062;

/** FNV-1a-64 哈希（fastjson 白名单哈希算法，用于构造碰撞验证）。 */
public final class Fnv {

    public static final long OFFSET_BASIS = 0xCBF29CE484222325L;
    public static final long PRIME = 0x100000001B3L;

    private Fnv() {}

    public static long hashCode64(String value) {
        long hash = OFFSET_BASIS;
        for (int i = 0; i < value.length(); i++) {
            hash = (hash ^ value.charAt(i)) * PRIME;
        }
        return hash;
    }
}
