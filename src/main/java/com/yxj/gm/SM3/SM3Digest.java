package com.yxj.gm.SM3;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.LongAdder;

/**
 * SM3 哈希算法
 *
 * 性能优化：
 * - Streaming update：在 update 阶段直接消化完整 64 字节分组，避免先把全部数据缓存到大数组
 * - 压缩函数使用 int 寄存器运算
 * - 消息扩展使用 int 数组复用
 * - 预计算 T 的循环移位
 * - 主循环拆分 0-15 和 16-63 减少分支
 * - 仅保留 64 字节内部缓冲 + 128 字节最终填充缓冲
 */
public class SM3Digest {

    private static final boolean DEBUG = Boolean.getBoolean("sm3.debug");
    private static final LongAdder debugTotalNs = new LongAdder();
    private static final LongAdder debugFullBlockNs = new LongAdder();
    private static final LongAdder debugFinalBlockNs = new LongAdder();
    private static final LongAdder debugCalls = new LongAdder();

    static {
        if (DEBUG) {
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                long calls = debugCalls.sum();
                if (calls == 0) return;
                long total = debugTotalNs.sum();
                long full = debugFullBlockNs.sum();
                long fin = debugFinalBlockNs.sum();
                System.err.printf("[SM3 DEBUG] calls=%d total=%.3fs fullBlocks=%.3fs(%.1f%%) finalBlocks=%.3fs(%.1f%%)%n",
                        calls, total / 1e9, full / 1e9, full * 100.0 / total,
                        fin / 1e9, fin * 100.0 / total);
            }, "sm3-debug"));
        }
    }

    /**
     * JDK 9+ 时使用 VarHandle 做 byte[] 与大端 int 之间的零开销转换；
     * JDK 8 运行时自动降级为手动移位。
     */
    private static final class FastIntView {
        static final boolean AVAILABLE;
        private static final MethodHandle GET;
        private static final MethodHandle SET;

        static {
            MethodHandle get = null, set = null;
            try {
                Class<?> vhClass = Class.forName("java.lang.invoke.VarHandle");
                MethodHandles.Lookup lookup = MethodHandles.publicLookup();
                MethodHandle factory = lookup.findStatic(
                        MethodHandles.class, "byteArrayViewVarHandle",
                        MethodType.methodType(vhClass, Class.class, ByteOrder.class));
                Object vh = factory.invoke(int[].class, ByteOrder.BIG_ENDIAN);
                get = lookup.findVirtual(vhClass, "get", MethodType.methodType(int.class, byte[].class, int.class)).bindTo(vh);
                set = lookup.findVirtual(vhClass, "set", MethodType.methodType(void.class, byte[].class, int.class, int.class)).bindTo(vh);
            } catch (Throwable ignored) {
            }
            GET = get;
            SET = set;
            AVAILABLE = get != null;
        }

        static int get(byte[] b, int off) {
            try {
                return (int) GET.invokeExact(b, off);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }

        static void set(byte[] b, int off, int v) {
            try {
                SET.invokeExact(b, off, v);
            } catch (Throwable t) {
                throw new RuntimeException(t);
            }
        }
    }

    private static final int[] IV = {
            0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
            0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    private static final int T_0_15 = 0x79cc4519;
    private static final int T_16_63 = 0x7a879d8a;

    private static final int[] T_ROTATED = new int[64];
    static {
        for (int j = 0; j < 64; j++) {
            int T = (j < 16) ? T_0_15 : T_16_63;
            T_ROTATED[j] = Integer.rotateLeft(T, j % 32);
        }
    }

    // streaming 状态
    private final byte[] buffer = new byte[64];
    private int bufferLen = 0;
    private long totalBytes = 0;

    private final int[] W = new int[68];
    private final int[] W1 = new int[64];
    private final int[] stateA = new int[8];
    private final int[] stateB = new int[8];
    private int[] inState;
    private int[] outState;

    public SM3Digest() {
        resetState();
    }

    private void resetState() {
        System.arraycopy(IV, 0, stateA, 0, 8);
        inState = stateA;
        outState = stateB;
        bufferLen = 0;
        totalBytes = 0;
    }

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

    private void processBlock(byte[] data, int offset) {
        CF(inState, data, offset, outState, W, W1);
        int[] tmp = inState;
        inState = outState;
        outState = tmp;
    }

    private static void CF(int[] V, byte[] padded, int offset, int[] out, int[] W, int[] W1) {
        if (FastIntView.AVAILABLE) {
            for (int i = 0; i < 16; i++) {
                W[i] = FastIntView.get(padded, offset + i * 4);
            }
        } else {
            for (int i = 0; i < 16; i++) {
                W[i] = bytesToIntBE(padded, offset + i * 4);
            }
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

    public void update(byte[] msg) {
        update(msg, 0, msg.length);
    }

    public void update(byte[] msg, int offset, int len) {
        totalBytes += len;
        int pos = offset;
        int remaining = len;

        // 先把内部 buffer 填满
        if (bufferLen > 0) {
            int need = 64 - bufferLen;
            int copy = Math.min(need, remaining);
            System.arraycopy(msg, pos, buffer, bufferLen, copy);
            bufferLen += copy;
            pos += copy;
            remaining -= copy;
            if (bufferLen == 64) {
                processBlock(buffer, 0);
                bufferLen = 0;
            }
        }

        // 直接处理 msg 中的完整 64 字节分组
        while (remaining >= 64) {
            processBlock(msg, pos);
            pos += 64;
            remaining -= 64;
        }

        // 剩余不足 64 字节的缓存起来
        if (remaining > 0) {
            System.arraycopy(msg, pos, buffer, 0, remaining);
            bufferLen = remaining;
        }
    }

    public byte[] doFinal() {
        long t0 = DEBUG ? System.nanoTime() : 0L;
        long bitLen = totalBytes * 8L;
        int remainder = bufferLen;

        // 最后一个（或两个）填充分组，最多分配 128 字节
        byte[] finalBlock = new byte[remainder <= 55 ? 64 : 128];
        System.arraycopy(buffer, 0, finalBlock, 0, remainder);
        finalBlock[remainder] = (byte) 0x80;
        for (int i = 0; i < 8; i++) {
            finalBlock[finalBlock.length - 1 - i] = (byte) (bitLen >>> (i * 8));
        }

        long tFinal0 = DEBUG ? System.nanoTime() : 0L;
        int finalBlocks = finalBlock.length >>> 6;
        for (int i = 0; i < finalBlocks; i++) {
            CF(inState, finalBlock, i << 6, outState, W, W1);
            int[] tmp = inState;
            inState = outState;
            outState = tmp;
        }
        long tFinal1 = DEBUG ? System.nanoTime() : 0L;

        byte[] result = new byte[32];
        if (FastIntView.AVAILABLE) {
            for (int i = 0; i < 8; i++) {
                FastIntView.set(result, i * 4, inState[i]);
            }
        } else {
            for (int i = 0; i < 8; i++) {
                intToBytesBE(inState[i], result, i * 4);
            }
        }

        if (DEBUG) {
            long total = System.nanoTime() - t0;
            debugTotalNs.add(total);
            debugFullBlockNs.add(total - (tFinal1 - tFinal0));
            debugFinalBlockNs.add(tFinal1 - tFinal0);
            debugCalls.increment();
        }

        resetState();
        return result;
    }

    public byte[] doFinal(byte[] msg) {
        resetState();
        update(msg);
        return doFinal();
    }

    public void msgAllReset() {
        resetState();
    }

    /**
     * 返回性能调试统计信息（仅在 -Dsm3.debug=true 时有意义）。
     * 格式：calls=... total=...s fullBlocks=...s(...) finalBlocks=...s(...)
     */
    public static String getDebugSummary() {
        long calls = debugCalls.sum();
        if (calls == 0) return "[SM3 DEBUG] no data";
        long total = debugTotalNs.sum();
        long full = debugFullBlockNs.sum();
        long fin = debugFinalBlockNs.sum();
        return String.format("[SM3 DEBUG] calls=%d total=%.3fs fullBlocks=%.3fs(%.1f%%) finalBlocks=%.3fs(%.1f%%)",
                calls, total / 1e9, full / 1e9, full * 100.0 / total,
                fin / 1e9, fin * 100.0 / total);
    }
}
