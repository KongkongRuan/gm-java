package com.yxj.gm.util.JNI;

/**
 * SM2 P-256-V1 原生加速。
 *
 * 提供三个层级的加速接口：
 *   1. 域运算：nativeMulMod / nativeSqrMod / nativeInv
 *   2. 标量乘法：nativeFixedBaseMul / nativeFieldMul / nativeShamirMul
 *   3. 向后兼容：nativeMulCore / nativeSqrCore / nativeReduce
 *
 * 加载失败或调用异常时自动回退到纯 Java 实现。
 */
public class Nat256Native {

    private static volatile boolean loaded = false;
    private static volatile boolean available = false;

    static {
        try {
            NativeLoader.load();
            loaded = true;
            available = true;
        } catch (Throwable t) {
            loaded = true;
            available = false;
        }
    }

    /* ========== 向后兼容：域运算原始接口 ========== */
    public static native void nativeMulCore(int[] a, int[] b, int[] ext);
    public static native void nativeSqrCore(int[] a, int[] ext);
    public static native void nativeReduce(int[] ext, int[] r);
    public static native void nativeInv(int[] a, int[] r);

    /* ========== 融合域运算（mul+reduce 一次 JNI 调用） ========== */
    public static native void nativeMulMod(int[] a, int[] b, int[] r);
    public static native void nativeSqrMod(int[] a, int[] r);

    /* ========== 完整标量乘法（整个 wNAF 循环在 C 中完成） ========== */

    /** [k]G — 基点标量乘法。k[8] 小端 256 位标量，outXY[16] = {x[8], y[8]} 仿射结果 */
    public static native void nativeFixedBaseMul(int[] k, int[] outXY);

    /** [k]P — 任意点标量乘法。px/py[8] 仿射坐标，k[8] 标量，outXY[16] 结果 */
    public static native void nativeFieldMul(int[] px, int[] py, int[] k, int[] outXY);

    /** [s]G + [t]P — Shamir's trick。s[8], px/py[8], t[8], outXY[16] */
    public static native void nativeShamirMul(int[] s, int[] px, int[] py, int[] t, int[] outXY);

    /** [k]G — Comb 固定基点乘法（d=32, t=8, 255 条目预计算表）。比 wNAF 快 ~3x */
    public static native void nativeCombFixedBaseMul(int[] k, int[] outXY);

    /* ========== 字节数组级完整 SM2 操作（消除 BigInteger 开销） ========== */

    /** 密钥生成：random[32] → out[96] = prikey[32] + pubX[32] + pubY[32]，返回 1=成功 0=k 越界需重试 */
    public static native int nativeKeyGen(byte[] random32, byte[] out96);

    /** 签名核心：e[32] + d[32] + daInv[32] + k[32] → outRS[64] = r[32] + s[32]，返回 1=成功 0=需重试 */
    public static native int nativeSignCore(byte[] e32, byte[] d32, byte[] daInv32, byte[] k32, byte[] outRS64);

    /** 验签核心：e[32] + r[32] + s[32] + pubXY[64] → true/false */
    public static native boolean nativeVerifyCore(byte[] e32, byte[] r32, byte[] s32, byte[] pubXY64);

    public static boolean isAvailable() {
        return available;
    }

    public static void markUnavailable() {
        available = false;
    }

    public static void main(String[] args) {
        System.out.println("Nat256Native available: " + isAvailable());
        if (isAvailable()) {
            int[] a = {0x12345678, 0x9ABCDEF0, 1, 2, 3, 4, 5, 6};
            int[] b = {0xFEDCBA98, 0x76543210, 7, 8, 9, 10, 11, 12};
            int[] ext = new int[16];
            nativeMulCore(a, b, ext);
            System.out.println("ext[0]=" + Integer.toHexString(ext[0]) + " ext[1]=" + Integer.toHexString(ext[1]));
        }
    }
}
