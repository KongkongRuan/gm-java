package com.yxj.gm.SM3;

import java.io.ByteArrayOutputStream;

/**
 * SM3 哈希算法
 *
 * 性能优化：
 * - 压缩函数使用 int 寄存器运算，消除 byte[]/int 反复转换
 * - 消息扩展使用 int 数组，update 使用 ByteArrayOutputStream 避免 O(n²) 拼接
 * - 对象复用：W/W1/state 数组复用，减少 GC
 * - 预计算 T 的循环移位，消除重复计算
 * - 主循环拆分为 0-15 和 16-63，减少分支预测失败
 * - CF 直接读取 padded 的 offset，消除 block 拷贝
 */
public class SM3Digest {

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private static final int T_0_15 = 0x79cc4519;
    private static final int T_16_63 = 0x7a879d8a;

    /** 预计算 T 的循环移位，避免主循环中重复计算 */
    private static final int[] T_ROTATED = new int[64];
    static {
        for (int j = 0; j < 64; j++) {
            int T = (j < 16) ? T_0_15 : T_16_63;
            T_ROTATED[j] = Integer.rotateLeft(T, j % 32);
        }
    }

    private ByteArrayOutputStream msgBuffer = new ByteArrayOutputStream();

    /** 复用的工作数组，避免每次 CF 分配 */
    private final int[] W = new int[68];
    private final int[] W1 = new int[64];
    private final int[] stateA = new int[8];
    private final int[] stateB = new int[8];

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

    private static int P1(int X) {
        return X ^ Integer.rotateLeft(X, 15) ^ Integer.rotateLeft(X, 23);
    }

    private static int P0(int X) {
        return X ^ Integer.rotateLeft(X, 9) ^ Integer.rotateLeft(X, 17);
    }

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
     * 压缩函数 - 直接读取 padded[offset..]，结果写入 out，无额外分配
     */
    private void CF(int[] V, byte[] padded, int offset, int[] out) {
        for (int i = 0; i < 16; i++) {
            W[i] = bytesToIntBE(padded, offset + i * 4);
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

        // 0-15 轮：FF1, GG1
        for (int j = 0; j < 16; j++) {
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j], 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
            int TT2 = (E ^ F ^ G) + H + SS1 + W[j];
            D = C;
            C = Integer.rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = Integer.rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }
        // 16-63 轮：FF2, GG2
        for (int j = 16; j < 64; j++) {
            int SS1 = Integer.rotateLeft(Integer.rotateLeft(A, 12) + E + T_ROTATED[j], 7);
            int SS2 = SS1 ^ Integer.rotateLeft(A, 12);
            int TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
            int TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j];
            D = C;
            C = Integer.rotateLeft(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = Integer.rotateLeft(F, 19);
            F = E;
            E = P0(TT2);
        }

        out[0] = A ^ V[0];
        out[1] = B ^ V[1];
        out[2] = C ^ V[2];
        out[3] = D ^ V[3];
        out[4] = E ^ V[4];
        out[5] = F ^ V[5];
        out[6] = G ^ V[6];
        out[7] = H ^ V[7];
    }

    private byte[] computeHash(byte[] msgAll) {
        byte[] padded = pad(msgAll);
        int n = padded.length / 64;

        System.arraycopy(IV, 0, stateA, 0, 8);
        int[] inState = stateA;
        int[] outState = stateB;

        for (int i = 0; i < n; i++) {
            CF(inState, padded, i * 64, outState);
            int[] tmp = inState;
            inState = outState;
            outState = tmp;
        }

        byte[] result = new byte[32];
        for (int i = 0; i < 8; i++) {
            intToBytesBE(inState[i], result, i * 4);
        }
        return result;
    }

    public void update(byte[] msg) {
        msgBuffer.write(msg, 0, msg.length);
    }

    public void update(byte[] msg, int offset, int len) {
        msgBuffer.write(msg, offset, len);
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
