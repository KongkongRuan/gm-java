package com.yxj.gm.SM3;

import java.io.ByteArrayOutputStream;

/**
 * SM3 哈希算法
 *
 * 性能优化：压缩函数使用 int 寄存器运算，消除 byte[]/int 反复转换，
 *          消息扩展使用 int 数组，update 使用 ByteArrayOutputStream 避免 O(n²) 拼接
 */
public class SM3Digest {

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private static final int T_0_15 = 0x79cc4519;
    private static final int T_16_63 = 0x7a879d8a;

    private ByteArrayOutputStream msgBuffer = new ByteArrayOutputStream();

    private static int bytesToIntBE(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) |
                ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }

    private static void intToBytesBE(int val, byte[] b, int off) {
        b[off] = (byte) (val >>> 24);
        b[off + 1] = (byte) (val >>> 16);
        b[off + 2] = (byte) (val >>> 8);
        b[off + 3] = (byte) val;
    }

    private static int FF1(int X, int Y, int Z) { return X ^ Y ^ Z; }
    private static int FF2(int X, int Y, int Z) { return (X & Y) | (X & Z) | (Y & Z); }
    private static int GG1(int X, int Y, int Z) { return X ^ Y ^ Z; }
    private static int GG2(int X, int Y, int Z) { return (X & Y) | (~X & Z); }
    private static int P0(int X) { return X ^ Integer.rotateLeft(X, 9) ^ Integer.rotateLeft(X, 17); }
    private static int P1(int X) { return X ^ Integer.rotateLeft(X, 15) ^ Integer.rotateLeft(X, 23); }

    private static byte[] pad(byte[] m) {
        long bitLen = m.length * 8L;
        long k = 448 - ((bitLen + 1) % 512);
        if (k < 0) k += 512;
        int totalBytes = (int) ((bitLen + 1 + k + 64) / 8);
        byte[] result = new byte[totalBytes];
        System.arraycopy(m, 0, result, 0, m.length);
        result[m.length] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            result[totalBytes - 1 - i] = (byte) (bitLen >>> (i * 8));
        }
        return result;
    }

    /**
     * 压缩函数 - 全 int 运算
     */
    private static int[] CF(int[] V, byte[] block) {
        int[] W = new int[68];
        int[] W1 = new int[64];

        for (int i = 0; i < 16; i++) {
            W[i] = bytesToIntBE(block, i * 4);
        }
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ Integer.rotateLeft(W[j - 3], 15))
                    ^ Integer.rotateLeft(W[j - 13], 7) ^ W[j - 6];
        }
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        int A = V[0], B = V[1], C = V[2], D = V[3];
        int E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            int T = (j < 16) ? T_0_15 : T_16_63;
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + Integer.rotateLeft(T, j % 32), 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1, TT2;
            if (j < 16) {
                TT1 = FF1(A, B, C) + D + SS2 + W1[j];
                TT2 = GG1(E, F, G) + H + SS1 + W[j];
            } else {
                TT1 = FF2(A, B, C) + D + SS2 + W1[j];
                TT2 = GG2(E, F, G) + H + SS1 + W[j];
            }
            D = C;
            C = Integer.rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = Integer.rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        return new int[]{A ^ V[0], B ^ V[1], C ^ V[2], D ^ V[3],
                E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]};
    }

    private byte[] computeHash(byte[] msgAll) {
        byte[] padded = pad(msgAll);
        int n = padded.length / 64;
        int[] v = IV.clone();
        byte[] block = new byte[64];
        for (int i = 0; i < n; i++) {
            System.arraycopy(padded, i * 64, block, 0, 64);
            v = CF(v, block);
        }
        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++) {
            intToBytesBE(v[i], result, i * 4);
        }
        return result;
    }

    public void update(byte[] msg) {
        msgBuffer.write(msg, 0, msg.length);
    }

    public byte[] doFinal() {
        byte[] data = msgBuffer.toByteArray();
        msgBuffer.reset();
        if (data.length == 0) {
            throw new RuntimeException("请添加要计算的值");
        }
        return computeHash(data);
    }

    public byte[] doFinal(byte[] msg) {
        msgBuffer.reset();
        return computeHash(msg);
    }

    public void msgAllReset() {
        msgBuffer.reset();
    }
}
