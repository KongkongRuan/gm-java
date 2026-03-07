package com.yxj.gm.util;

import java.math.BigInteger;

/**
 * SM2 P-256-V1 有限域快速算术
 *
 * 利用 SM2 素数 p = 2^256 - 2^224 - 2^96 + 2^64 - 1 的 Solinas 结构,
 * 用移位和加减法替代通用除法取模, 消除 BigInteger 对象分配.
 *
 * 内部表示: int[8] 小端序 (word[0] = bits 0-31, word[7] = bits 224-255)
 */
public final class SM2P256V1Field {

    private static final long M = 0xFFFFFFFFL;

    static final int[] P = {
            0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
    };

    // ======================== 模加 / 模减 ========================

    public static void add(int[] a, int[] b, int[] r) {
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += (a[i] & M) + (b[i] & M);
            r[i] = (int) cc;
            cc >>>= 32;
        }
        if (cc != 0) {
            addR(r);
        }
        subPCond(r);
    }

    public static void sub(int[] a, int[] b, int[] r) {
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += (a[i] & M) - (b[i] & M);
            r[i] = (int) cc;
            cc >>= 32;
        }
        if (cc != 0) {
            addP(r);
        }
    }

    public static void neg(int[] a, int[] r) {
        if (isZero(a)) {
            System.arraycopy(a, 0, r, 0, 8);
            return;
        }
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += (P[i] & M) - (a[i] & M);
            r[i] = (int) cc;
            cc >>= 32;
        }
    }

    // ======================== 模乘 / 模平方 ========================

    public static void mul(int[] a, int[] b, int[] r) {
        int[] ext = new int[16];
        for (int i = 0; i < 8; i++) {
            long ai = a[i] & M;
            long carry = 0;
            for (int j = 0; j < 8; j++) {
                carry += ai * (b[j] & M) + (ext[i + j] & M);
                ext[i + j] = (int) carry;
                carry >>>= 32;
            }
            ext[i + 8] = (int) carry;
        }
        reduce(ext, r);
    }

    public static void sqr(int[] a, int[] r) {
        int[] ext = new int[16];

        for (int i = 0; i < 7; i++) {
            long ai = a[i] & M;
            long carry = 0;
            for (int j = i + 1; j < 8; j++) {
                carry += ai * (a[j] & M) + (ext[i + j] & M);
                ext[i + j] = (int) carry;
                carry >>>= 32;
            }
            ext[i + 8] = (int) carry;
        }

        long cc = 0;
        for (int i = 1; i < 15; i++) {
            cc += (ext[i] & M) << 1;
            ext[i] = (int) cc;
            cc >>>= 32;
        }
        ext[15] = (int) cc;

        cc = 0;
        for (int i = 0; i < 8; i++) {
            long ai = a[i] & M;
            cc += ai * ai + (ext[2 * i] & M);
            ext[2 * i] = (int) cc;
            cc >>>= 32;
            cc += (ext[2 * i + 1] & M);
            ext[2 * i + 1] = (int) cc;
            cc >>>= 32;
        }

        reduce(ext, r);
    }

    // ======================== 乘以小常数 ========================

    public static void twice(int[] a, int[] r) {
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += (a[i] & M) << 1;
            r[i] = (int) cc;
            cc >>>= 32;
        }
        if (cc != 0) {
            addR(r);
        }
        subPCond(r);
    }

    public static void thrice(int[] a, int[] r) {
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += 3L * (a[i] & M);
            r[i] = (int) cc;
            cc >>>= 32;
        }
        // cc is 0, 1, or 2. Add cc * R = cc * (1, 0, -1, 1, 0, 0, 0, 1) in LE
        if (cc != 0) {
            long c = (r[0] & M) + cc;  r[0] = (int) c; c >>= 32;
            c += (r[1] & M);           r[1] = (int) c; c >>= 32;
            c += (r[2] & M) - cc;      r[2] = (int) c; c >>= 32;
            c += (r[3] & M) + cc;      r[3] = (int) c; c >>= 32;
            c += (r[4] & M);           r[4] = (int) c; c >>= 32;
            c += (r[5] & M);           r[5] = (int) c; c >>= 32;
            c += (r[6] & M);           r[6] = (int) c; c >>= 32;
            c += (r[7] & M) + cc;      r[7] = (int) c;
        }
        subPCond(r);
    }

    // ======================== SM2 快速模归约 ========================

    /**
     * 将 512 位乘积 (int[16] 小端) 归约到 256 位 (mod p).
     *
     * 利用 2^256 ≡ 2^224 + 2^96 - 2^64 + 1 (mod p) 将高 256 位折叠.
     * 所有系数通过代数推导, 对 x[8]..x[15] 的每个贡献直接累加到 r[0..7].
     */
    public static void reduce(int[] ext, int[] r) {
        long x0 = ext[0] & M, x1 = ext[1] & M, x2 = ext[2] & M, x3 = ext[3] & M;
        long x4 = ext[4] & M, x5 = ext[5] & M, x6 = ext[6] & M, x7 = ext[7] & M;
        long x8 = ext[8] & M, x9 = ext[9] & M, x10 = ext[10] & M, x11 = ext[11] & M;
        long x12 = ext[12] & M, x13 = ext[13] & M, x14 = ext[14] & M, x15 = ext[15] & M;

        long s0 = x0 + x8 + x9 + x10 + x11 + x12 + 2 * x13 + 2 * x14 + 2 * x15;
        long s1 = x1 + x9 + x10 + x11 + x12 + x13 + 2 * x14 + 2 * x15;
        long s2 = x2 - x8 - x9 - x13 - x14;
        long s3 = x3 + x8 + x11 + x12 + 2 * x13 + x14 + x15;
        long s4 = x4 + x9 + x12 + x13 + 2 * x14 + x15;
        long s5 = x5 + x10 + x13 + x14 + 2 * x15;
        long s6 = x6 + x11 + x14 + x15;
        long s7 = x7 + x8 + x9 + x10 + x11 + 2 * x12 + 2 * x13 + 2 * x14 + 3 * x15;

        long cc;

        // 第 1 轮: carry 传播
        cc = s0 >> 32; s0 &= M;
        s1 += cc; cc = s1 >> 32; s1 &= M;
        s2 += cc; cc = s2 >> 32; s2 &= M;
        s3 += cc; cc = s3 >> 32; s3 &= M;
        s4 += cc; cc = s4 >> 32; s4 &= M;
        s5 += cc; cc = s5 >> 32; s5 &= M;
        s6 += cc; cc = s6 >> 32; s6 &= M;
        s7 += cc; cc = s7 >> 32; s7 &= M;

        // R-reduce carry (cc ≈ 0..15)
        s0 += cc; s2 -= cc; s3 += cc; s7 += cc;

        // 第 2 轮: carry 传播
        cc = s0 >> 32; s0 &= M;
        s1 += cc; cc = s1 >> 32; s1 &= M;
        s2 += cc; cc = s2 >> 32; s2 &= M;
        s3 += cc; cc = s3 >> 32; s3 &= M;
        s4 += cc; cc = s4 >> 32; s4 &= M;
        s5 += cc; cc = s5 >> 32; s5 &= M;
        s6 += cc; cc = s6 >> 32; s6 &= M;
        s7 += cc; cc = s7 >> 32; s7 &= M;

        // R-reduce carry (cc = 0 or 1)
        s0 += cc; s2 -= cc; s3 += cc; s7 += cc;

        // 第 3 轮: final carry 传播
        cc = s0 >> 32; s0 &= M;
        s1 += cc; cc = s1 >> 32; s1 &= M;
        s2 += cc; cc = s2 >> 32; s2 &= M;
        s3 += cc; cc = s3 >> 32; s3 &= M;
        s4 += cc; cc = s4 >> 32; s4 &= M;
        s5 += cc; cc = s5 >> 32; s5 &= M;
        s6 += cc; cc = s6 >> 32; s6 &= M;
        s7 += cc;

        r[0] = (int) s0; r[1] = (int) s1; r[2] = (int) s2; r[3] = (int) s3;
        r[4] = (int) s4; r[5] = (int) s5; r[6] = (int) s6; r[7] = (int) s7;

        subPCond(r);
    }

    // ======================== 内部辅助 ========================

    /**
     * 如果 r >= p 则减去 p (常量时间)
     */
    private static void subPCond(int[] r) {
        long borrow = 0;
        int[] d = new int[8];
        for (int i = 0; i < 8; i++) {
            borrow += (r[i] & M) - (P[i] & M);
            d[i] = (int) borrow;
            borrow >>= 32;
        }
        int mask = (int) borrow; // 0 if r >= p, -1 if r < p
        for (int i = 0; i < 8; i++) {
            r[i] = (d[i] & ~mask) | (r[i] & mask);
        }
    }

    /** 加 p, 用于 sub 结果为负时 */
    private static void addP(int[] r) {
        long cc = 0;
        for (int i = 0; i < 8; i++) {
            cc += (r[i] & M) + (P[i] & M);
            r[i] = (int) cc;
            cc >>>= 32;
        }
    }

    /**
     * 加 R = 2^224 + 2^96 - 2^64 + 1 (= 2^256 mod p)
     * LE signed: [+1, 0, -1, +1, 0, 0, 0, +1]
     */
    private static void addR(int[] r) {
        long cc = (r[0] & M) + 1; r[0] = (int) cc; cc >>= 32;
        cc += (r[1] & M); r[1] = (int) cc; cc >>= 32;
        cc += (r[2] & M) - 1; r[2] = (int) cc; cc >>= 32;
        cc += (r[3] & M) + 1; r[3] = (int) cc; cc >>= 32;
        cc += (r[4] & M); r[4] = (int) cc; cc >>= 32;
        cc += (r[5] & M); r[5] = (int) cc; cc >>= 32;
        cc += (r[6] & M); r[6] = (int) cc; cc >>= 32;
        cc += (r[7] & M) + 1; r[7] = (int) cc;
    }

    /** addR 并返回 carry */
    private static long addRCarry(int[] r) {
        long cc = (r[0] & M) + 1; r[0] = (int) cc; cc >>= 32;
        cc += (r[1] & M); r[1] = (int) cc; cc >>= 32;
        cc += (r[2] & M) - 1; r[2] = (int) cc; cc >>= 32;
        cc += (r[3] & M) + 1; r[3] = (int) cc; cc >>= 32;
        cc += (r[4] & M); r[4] = (int) cc; cc >>= 32;
        cc += (r[5] & M); r[5] = (int) cc; cc >>= 32;
        cc += (r[6] & M); r[6] = (int) cc; cc >>= 32;
        cc += (r[7] & M) + 1; r[7] = (int) cc;
        return cc >> 32;
    }

    // ======================== 工具方法 ========================

    public static boolean isZero(int[] a) {
        return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0;
    }

    public static int[] fromBigInteger(BigInteger x) {
        int[] r = new int[8];
        for (int i = 0; i < 8; i++) {
            r[i] = x.intValue();
            x = x.shiftRight(32);
        }
        return r;
    }

    public static BigInteger toBigInteger(int[] a) {
        byte[] b = new byte[33];
        for (int i = 0; i < 8; i++) {
            int v = a[i];
            int off = 29 - 4 * i;
            b[off] = (byte) (v >>> 24);
            b[off + 1] = (byte) (v >>> 16);
            b[off + 2] = (byte) (v >>> 8);
            b[off + 3] = (byte) v;
        }
        b[0] = 0;
        return new BigInteger(b);
    }
}
