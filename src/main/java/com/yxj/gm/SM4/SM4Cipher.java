package com.yxj.gm.SM4;

import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.constant.SM4Constant;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.JNI.SM4GCMNative;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.*;

import static com.yxj.gm.enums.ModeEnum.CTR;

/**
 * 国密SM4对称加密算法
 *      默认为CTR模式
 *      PKCS7填充
 *
 * 性能优化：核心运算使用 int 寄存器，S-Box 使用位运算索引，
 *          CTR 计数器使用直接字节操作，线程池全局复用
 */
public class SM4Cipher {

    private final int processorCount = 2 * Runtime.getRuntime().availableProcessors() + 1;

    /**
     * 内部并行化总开关。
     * 默认开启（大分组数时自动使用多线程）；业务层若希望自己管理线程池，
     * 可添加 -Dgm.sm4.parallel=false 强制走单线程路径。
     */
    private static final boolean PARALLEL_ENABLED =
            Boolean.parseBoolean(System.getProperty("gm.sm4.parallel", "true"));

    /**
     * 懒加载的线程池：仅在真正进入并行路径时才创建，避免禁用并行时仍占用线程资源。
     */
    private static final class LazyThreadPool {
        static final ExecutorService INSTANCE = Executors.newFixedThreadPool(
                Math.max(2, Runtime.getRuntime().availableProcessors()),
                r -> {
                    Thread t = new Thread(r);
                    t.setDaemon(true);
                    return t;
                }
        );
    }

    private static ExecutorService getThreadPool() {
        return LazyThreadPool.INSTANCE;
    }

    private ModeEnum Mode = CTR;
    private byte[][] VBox = new byte[129][16];
    private PaddingEnum Padding = PaddingEnum.Pkcs7;
    // 调试开关：运行时加 -Dgm.debug 打印调试信息，-Dgm.time 打印分相位耗时（关闭时零开销）
    private static final boolean DEBUG = Boolean.getBoolean("gm.debug");
    private static final boolean TIME = Boolean.getBoolean("gm.time");

    public ModeEnum getMode() { return Mode; }
    public void setMode(ModeEnum mode) { Mode = mode; }
    public PaddingEnum getPadding() { return Padding; }
    public void setPadding(PaddingEnum padding) { Padding = padding; }

    public SM4Cipher() {}
    public SM4Cipher(PaddingEnum padding, ModeEnum mode) { this.Padding = padding; this.Mode = mode; }
    public SM4Cipher(PaddingEnum padding) { this.Padding = padding; }
    public SM4Cipher(ModeEnum mode) { this.Mode = mode; }

    // ==================== 优化后的 int 运算核心 ====================

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

    private static int tauInt(int A) {
        return ((SM4Constant.SboxTable[(A >>> 24) & 0xFF] & 0xFF) << 24) |
                ((SM4Constant.SboxTable[(A >>> 16) & 0xFF] & 0xFF) << 16) |
                ((SM4Constant.SboxTable[(A >>> 8) & 0xFF] & 0xFF) << 8) |
                (SM4Constant.SboxTable[A & 0xFF] & 0xFF);
    }

    private static int lInt(int B) {
        return B ^ Integer.rotateLeft(B, 2) ^ Integer.rotateLeft(B, 10) ^
                Integer.rotateLeft(B, 18) ^ Integer.rotateLeft(B, 24);
    }

    private static int lPrimeInt(int B) {
        return B ^ Integer.rotateLeft(B, 13) ^ Integer.rotateLeft(B, 23);
    }

    private static int tInt(int A) {
        return SM4Constant.T0[(A >>> 24) & 0xFF] ^ SM4Constant.T1[(A >>> 16) & 0xFF]
                ^ SM4Constant.T2[(A >>> 8) & 0xFF] ^ SM4Constant.T3[A & 0xFF];
    }
    private static int tPrimeInt(int A) { return lPrimeInt(tauInt(A)); }

    /**
     * 性能调试：按相位（填充分配 / 核心轮运算 / 结果拷贝 / 去填充）聚合耗时。
     * 仅当 -Dgm.time=true 时生效，并通过 JVM 关闭钩子打印汇总。
     * 用途：配合性能测试类定位 SM4 各模式的慢点（例如 ECB/CBC 串行时核心相位占 95%+）。
     */
    private static final class Timing {
        static final boolean ON = TIME;
        static final java.util.concurrent.atomic.LongAdder padNs = new java.util.concurrent.atomic.LongAdder();
        static final java.util.concurrent.atomic.LongAdder coreNs = new java.util.concurrent.atomic.LongAdder();
        static final java.util.concurrent.atomic.LongAdder copyNs = new java.util.concurrent.atomic.LongAdder();
        static final java.util.concurrent.atomic.LongAdder unpadNs = new java.util.concurrent.atomic.LongAdder();
        static final java.util.concurrent.atomic.LongAdder calls = new java.util.concurrent.atomic.LongAdder();
        static {
            if (ON) {
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    long c = calls.sum();
                    if (c == 0) return;
                    long pad = padNs.sum(), core = coreNs.sum(), copy = copyNs.sum(), unpad = unpadNs.sum();
                    long total = pad + core + copy + unpad;
                    if (total == 0) return;
                    System.err.printf("[SM4 TIME] calls=%d total=%.2fs pad=%.1f%% core=%.1f%% copy=%.1f%% unpad=%.1f%%%n",
                            c, total / 1e9,
                            pad * 100.0 / total, core * 100.0 / total,
                            copy * 100.0 / total, unpad * 100.0 / total);
                }, "sm4-time"));
            }
        }
        static long t0() { return ON ? System.nanoTime() : 0L; }
        static void acc(java.util.concurrent.atomic.LongAdder a, long s) { if (ON) a.add(System.nanoTime() - s); }
    }

    // 并行化阈值：分组数小于该值时不值得线程调度开销，走串行
    private static final int PARALLEL_THRESHOLD = 256;

    /**
     * 轮密钥扩展（int 版本）
     */
    public int[] extKeyInt(byte[] key) {
        if (key.length != 16) throw new RuntimeException("KEY length!=16");
        int[] K = new int[36];
        K[0] = bytesToIntBE(key, 0) ^ SM4Constant.FK[0];
        K[1] = bytesToIntBE(key, 4) ^ SM4Constant.FK[1];
        K[2] = bytesToIntBE(key, 8) ^ SM4Constant.FK[2];
        K[3] = bytesToIntBE(key, 12) ^ SM4Constant.FK[3];
        int[] rk = new int[32];
        for (int i = 0; i < 32; i++) {
            rk[i] = K[i + 4] = K[i] ^ tPrimeInt(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4Constant.CK[i]);
        }
        return rk;
    }

    /**
     * 轮密钥扩展（byte[][] 版本，向后兼容）
     */
    public byte[][] ext_key_L(byte[] in) {
        int[] rk = extKeyInt(in);
        byte[][] result = new byte[32][4];
        for (int i = 0; i < 32; i++) {
            result[i] = new byte[4];
            intToBytesBE(rk[i], result[i], 0);
        }
        return result;
    }

    private static int[] toIntKeys(byte[][] rks) {
        int[] rk = new int[32];
        for (int i = 0; i < 32; i++) {
            rk[i] = bytesToIntBE(rks[i], 0);
        }
        return rk;
    }

    private byte[] cipherCore(byte[] in, int[] rk) {
        byte[] out = new byte[16];
        cipherCoreOff(in, 0, out, 0, rk);
        return out;
    }

    private byte[] decryptCore(byte[] in, int[] rk) {
        byte[] out = new byte[16];
        decryptCoreOff(in, 0, out, 0, rk);
        return out;
    }

    private static void cipherCoreOff(byte[] in, int inOff, byte[] out, int outOff, int[] rk) {
        int x0 = bytesToIntBE(in, inOff), x1 = bytesToIntBE(in, inOff + 4);
        int x2 = bytesToIntBE(in, inOff + 8), x3 = bytesToIntBE(in, inOff + 12);
        for (int i = 0; i < 32; i++) {
            int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[i]);
            x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
        }
        intToBytesBE(x3, out, outOff);
        intToBytesBE(x2, out, outOff + 4);
        intToBytesBE(x1, out, outOff + 8);
        intToBytesBE(x0, out, outOff + 12);
    }

    private static void decryptCoreOff(byte[] in, int inOff, byte[] out, int outOff, int[] rk) {
        int x0 = bytesToIntBE(in, inOff), x1 = bytesToIntBE(in, inOff + 4);
        int x2 = bytesToIntBE(in, inOff + 8), x3 = bytesToIntBE(in, inOff + 12);
        for (int i = 31; i >= 0; i--) {
            int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[i]);
            x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
        }
        intToBytesBE(x3, out, outOff);
        intToBytesBE(x2, out, outOff + 4);
        intToBytesBE(x1, out, outOff + 8);
        intToBytesBE(x0, out, outOff + 12);
    }

    // ==================== CTR 计数器直接操作 ====================

    private static void incrementCounter(byte[] counter) {
        for (int i = counter.length - 1; i >= 0; i--) {
            if (++counter[i] != 0) break;
        }
    }

    private static byte[] addToCounter(byte[] counter, long value) {
        byte[] result = counter.clone();
        long carry = value;
        for (int i = result.length - 1; i >= 0 && carry > 0; i--) {
            carry += (result[i] & 0xFFL);
            result[i] = (byte) carry;
            carry >>>= 8;
        }
        return result;
    }

    // ==================== 公开 API ====================

    public byte[] cipherEncrypt(byte[] key, byte[] ming, byte[] iv) {
        int[] rk = extKeyInt(key);
        byte[] result = null;
        switch (Mode) {
            case ECB: result = blockEncryptECBInt(ming, rk); break;
            case CBC: result = blockEncryptCBCInt(ming, iv, rk); break;
            case CFB: result = blockEncryptCFBInt(ming, iv, rk); break;
            case OFB: result = blockEncryptOFBInt(ming, iv, rk); break;
            case CTR: result = blockEncryptCTRInt(ming, iv, rk); break;
            default: throw new RuntimeException("加密模式错误：" + Mode);
        }
        return result;
    }

    public byte[] cipherDecrypt(byte[] key, byte[] mi, byte[] iv) {
        if (iv == null) iv = "1234567812345678".getBytes();
        int[] rk = extKeyInt(key);
        byte[] result = null;
        switch (Mode) {
            case ECB: result = blockDecryptECBInt(mi, rk); break;
            case CBC: result = blockDecryptCBCInt(mi, iv, rk); break;
            case CFB: result = blockDecryptCFBInt(mi, iv, rk); break;
            case OFB: result = blockEncryptOFBInt(mi, iv, rk); break;
            case CTR: result = blockEncryptCTRInt(mi, iv, rk); break;
            default: throw new RuntimeException("解密模式错误：" + Mode);
        }
        return result;
    }

    /**
     * 无分配 in-place 加密。输入数组 data 直接被密文覆盖。
     * 仅支持 NoPadding 且长度为 16 的倍数。
     * 适用场景：高频、大内存、已预先知道数据长度的调用方，可消除 padding()/result[] 的分配与拷贝。
     */
    public byte[] cipherEncryptNoAlloc(byte[] key, byte[] data, byte[] iv) {
        if (iv == null && Mode != ModeEnum.ECB) iv = "1234567812345678".getBytes();
        if (Padding != PaddingEnum.NoPadding) {
            throw new RuntimeException("cipherEncryptNoAlloc 只支持 NoPadding 模式");
        }
        if (data.length % 16 != 0) {
            throw new RuntimeException("NoPadding 模式下输入长度必须是16的倍数");
        }
        int[] rk = extKeyInt(key);
        switch (Mode) {
            case ECB: blockEncryptECBNoAlloc(data, rk); break;
            case CBC: blockEncryptCBCNoAlloc(data, iv, rk); break;
            default: throw new RuntimeException("当前模式不支持 in-place 加密：" + Mode);
        }
        return data;
    }

    /**
     * 无分配 in-place 解密。输入数组 data 直接被明文覆盖。
     * 仅支持 NoPadding 且长度为 16 的倍数。
     */
    public byte[] cipherDecryptNoAlloc(byte[] key, byte[] data, byte[] iv) {
        if (iv == null && Mode != ModeEnum.ECB) iv = "1234567812345678".getBytes();
        if (Padding != PaddingEnum.NoPadding) {
            throw new RuntimeException("cipherDecryptNoAlloc 只支持 NoPadding 模式");
        }
        if (data.length % 16 != 0) {
            throw new RuntimeException("NoPadding 模式下输入长度必须是16的倍数");
        }
        int[] rk = extKeyInt(key);
        switch (Mode) {
            case ECB: blockDecryptECBNoAlloc(data, rk); break;
            // CBC 解密 in-place 必须串行从后向前，会丢失现有并行优势，实测比分配 result[] 更慢，故不提供。
            default: throw new RuntimeException("当前模式不支持 in-place 解密：" + Mode);
        }
        return data;
    }

    // ==================== 向后兼容的 byte[][] 版本 ====================

    public byte[] blockEncryptECB(byte[] m, byte[][] rks) {
        return blockEncryptECBInt(m, toIntKeys(rks));
    }

    public byte[] blockEncryptCBC(byte[] m, byte[] iv, byte[][] rks) {
        return blockEncryptCBCInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockEncryptCTR(byte[] m, byte[] iv, byte[][] rks) {
        return blockEncryptCTRInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockEncryptCFB(byte[] m, byte[] iv, byte[][] rks) {
        return blockEncryptCFBInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockEncryptOFB(byte[] m, byte[] iv, byte[][] rks) {
        return blockEncryptOFBInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockDecryptECB(byte[] m, byte[][] rks) {
        return blockDecryptECBInt(m, toIntKeys(rks));
    }

    public byte[] blockDecryptCBC(byte[] m, byte[] iv, byte[][] rks) {
        return blockDecryptCBCInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockDecryptCFB(byte[] m, byte[] iv, byte[][] rks) {
        return blockDecryptCFBInt(m, iv, toIntKeys(rks));
    }

    public byte[] blockDecryptOFB(byte[] m, byte[] iv, byte[][] rks) {
        return blockEncryptOFBInt(m, iv, toIntKeys(rks));
    }

    // ==================== int 轮密钥版本的分组加解密 ====================

    /**
     * ECB 加密：各分组相互独立，可并行。
     */
    private byte[] blockEncryptECBInt(byte[] m, int[] rk) {
        Timing.calls.increment();
        long s = Timing.t0();
        byte[] padded = padding(m);
        Timing.acc(Timing.padNs, s);
        int blocks = padded.length / 16;
        byte[] result = new byte[padded.length];
        if (PARALLEL_ENABLED && blocks >= PARALLEL_THRESHOLD) {
            parallelCore(padded, result, rk, true);
        } else {
            long c = Timing.t0();
            for (int i = 0; i < blocks; i++) {
                cipherCoreOff(padded, i * 16, result, i * 16, rk);
            }
            Timing.acc(Timing.coreNs, c);
        }
        return result;
    }

    /**
     * 分块并行执行 SM4 核心轮运算（ECB 用）。
     */
    private void parallelCore(byte[] in, byte[] out, int[] rk, boolean encrypt) {
        int blocks = in.length / 16;
        int procs = Math.min(processorCount, blocks);
        long size = blocks / procs;
        long remainder = blocks % procs;
        CountDownLatch latch = new CountDownLatch(procs);
        long s = Timing.t0();
        for (int j = 0; j < procs; j++) {
            long start = j * size;
            long end = (j == procs - 1) ? start + size + remainder : (j + 1) * size;
            long fs = start, fe = end;
            getThreadPool().execute(() -> {
                if (encrypt) {
                    for (int i = (int) fs; i < fe; i++) {
                        cipherCoreOff(in, i * 16, out, i * 16, rk);
                    }
                } else {
                    for (int i = (int) fs; i < fe; i++) {
                        decryptCoreOff(in, i * 16, out, i * 16, rk);
                    }
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        Timing.acc(Timing.coreNs, s);
    }

    /**
     * CBC 加密：第 i 个密文分组依赖 C(i-1)，是链式串行，无法简单并行化（保留串行）。
     * 优化点：NoPadding 且长度对齐时复用输入数组；CBC 异或与 SM4 轮函数在 int 寄存器内融合，
     * 避免中间字节缓冲的反复读写。
     */
    private byte[] blockEncryptCBCInt(byte[] m, byte[] iv, int[] rk) {
        Timing.calls.increment();
        long s = Timing.t0();
        // NoPadding 且长度合法时直接复用输入数组，避免 10MB 级的 Arrays.copyOf
        byte[] padded = (Padding == PaddingEnum.NoPadding && m.length % 16 == 0) ? m : padding(m);
        Timing.acc(Timing.padNs, s);
        int blocks = padded.length / 16;
        byte[] result = new byte[padded.length];
        // 空输入（NoPadding + 0 字节）没有数据块，直接返回空结果，避免对空数组做首块异或越界
        if (blocks > 0) {
            long c = Timing.t0();
            // --- opt: fused int-level XOR + inline SM4 core ---
            int x0 = bytesToIntBE(padded, 0) ^ bytesToIntBE(iv, 0);
            int x1 = bytesToIntBE(padded, 4) ^ bytesToIntBE(iv, 4);
            int x2 = bytesToIntBE(padded, 8) ^ bytesToIntBE(iv, 8);
            int x3 = bytesToIntBE(padded, 12) ^ bytesToIntBE(iv, 12);
            for (int r = 0; r < 32; r++) {
                int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[r]);
                x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
            }
            intToBytesBE(x3, result, 0);
            intToBytesBE(x2, result, 4);
            intToBytesBE(x1, result, 8);
            intToBytesBE(x0, result, 12);
            for (int i = 1; i < blocks; i++) {
                int off = i * 16;
                x0 = bytesToIntBE(padded, off) ^ bytesToIntBE(result, off - 16);
                x1 = bytesToIntBE(padded, off + 4) ^ bytesToIntBE(result, off - 12);
                x2 = bytesToIntBE(padded, off + 8) ^ bytesToIntBE(result, off - 8);
                x3 = bytesToIntBE(padded, off + 12) ^ bytesToIntBE(result, off - 4);
                for (int r = 0; r < 32; r++) {
                    int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[r]);
                    x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
                }
                intToBytesBE(x3, result, off);
                intToBytesBE(x2, result, off + 4);
                intToBytesBE(x1, result, off + 8);
                intToBytesBE(x0, result, off + 12);
            }
            Timing.acc(Timing.coreNs, c);
        }
        return result;
    }

    private byte[] blockEncryptCTRInt(byte[] m, byte[] iv, int[] rk) {
        Timing.calls.increment();
        checkIvLength(iv);
        int totalBlocks = (m.length + 15) / 16;
        byte[] result = new byte[m.length];
        if (!PARALLEL_ENABLED || totalBlocks < PARALLEL_THRESHOLD) {
            // 单线程路径：避免线程调度与同步开销，也响应 -Dgm.sm4.parallel=false
            byte[] counter = iv.clone();
            byte[] cipherBuf = new byte[16];
            for (int i = 0; i < totalBlocks; i++) {
                cipherCoreOff(counter, 0, cipherBuf, 0, rk);
                int off = i * 16;
                int len = Math.min(16, m.length - off);
                for (int b = 0; b < len; b++) result[off + b] = (byte) (m[off + b] ^ cipherBuf[b]);
                incrementCounter(counter);
            }
            return result;
        }

        int procs = Math.min(processorCount, totalBlocks);
        long size = totalBlocks / procs;
        long remainder = totalBlocks % procs;
        CountDownLatch latch = new CountDownLatch(procs);

        for (int j = 0; j < procs; j++) {
            long start = j * size;
            long end = (j == procs - 1) ? (j * size + size + remainder) : ((j + 1) * size);
            byte[] threadIv = (j == 0) ? iv.clone() : addToCounter(iv, j * size);
            long finalEnd = end;
            long finalStart = start;
            getThreadPool().execute(() -> {
                byte[] curIv = threadIv;
                byte[] cipherBuf = new byte[16];
                for (int i = (int) finalStart; i < finalEnd; i++) {
                    cipherCoreOff(curIv, 0, cipherBuf, 0, rk);
                    int off = i * 16;
                    int len = Math.min(16, m.length - off);
                    for (int b = 0; b < len; b++) result[off + b] = (byte)(m[off + b] ^ cipherBuf[b]);
                    incrementCounter(curIv);
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return result;
    }

    private byte[] blockEncryptCFBInt(byte[] m, byte[] iv, int[] rk) {
        checkIvLength(iv);
        byte[] result = new byte[m.length];
        byte[] feedback = iv.clone();
        byte[] keystream = new byte[16];
        for (int off = 0; off < m.length; off += 16) {
            int len = Math.min(16, m.length - off);
            cipherCoreOff(feedback, 0, keystream, 0, rk);
            for (int i = 0; i < len; i++) {
                result[off + i] = (byte) (m[off + i] ^ keystream[i]);
            }
            updateShiftRegister(feedback, result, off, len);
        }
        return result;
    }

    private byte[] blockDecryptCFBInt(byte[] m, byte[] iv, int[] rk) {
        checkIvLength(iv);
        byte[] result = new byte[m.length];
        byte[] feedback = iv.clone();
        byte[] keystream = new byte[16];
        for (int off = 0; off < m.length; off += 16) {
            int len = Math.min(16, m.length - off);
            cipherCoreOff(feedback, 0, keystream, 0, rk);
            for (int i = 0; i < len; i++) {
                result[off + i] = (byte) (m[off + i] ^ keystream[i]);
            }
            updateShiftRegister(feedback, m, off, len);
        }
        return result;
    }

    private byte[] blockEncryptOFBInt(byte[] m, byte[] iv, int[] rk) {
        checkIvLength(iv);
        byte[] result = new byte[m.length];
        byte[] feedback = iv.clone();
        for (int off = 0; off < m.length; off += 16) {
            int len = Math.min(16, m.length - off);
            feedback = cipherCore(feedback, rk);
            for (int i = 0; i < len; i++) {
                result[off + i] = (byte) (m[off + i] ^ feedback[i]);
            }
        }
        return result;
    }

    /**
     * ECB 解密：各分组相互独立，可并行。
     */
    private byte[] blockDecryptECBInt(byte[] m, int[] rk) {
        Timing.calls.increment();
        int blocks = m.length / 16;
        byte[] result = new byte[m.length];
        if (PARALLEL_ENABLED && blocks >= PARALLEL_THRESHOLD) {
            parallelCore(m, result, rk, false);
        } else {
            long c = Timing.t0();
            for (int i = 0; i < blocks; i++) {
                decryptCoreOff(m, i * 16, result, i * 16, rk);
            }
            Timing.acc(Timing.coreNs, c);
        }
        long u = Timing.t0();
        result = unPadding(result);
        Timing.acc(Timing.unpadNs, u);
        return result;
    }

    /**
     * CBC 解密：第 i 个明文分组 = 解密(Ci) XOR C(i-1)，C(i-1) 来自输入密文（已知），
     * 因此各分组相互独立，可并行（与 CTR 同理）。
     */
    private byte[] blockDecryptCBCInt(byte[] m, byte[] iv, int[] rk) {
        Timing.calls.increment();
        int blocks = m.length / 16;
        byte[] result = new byte[m.length];
        if (PARALLEL_ENABLED && blocks >= PARALLEL_THRESHOLD) {
            parallelCbcDecrypt(m, iv, result, rk);
        } else {
            long c = Timing.t0();
            for (int i = 0; i < blocks; i++) {
                int off = i * 16;
                decryptCoreOff(m, off, result, off, rk);
                byte[] xorWith = (i == 0) ? iv : m;
                int xorOff = (i == 0) ? 0 : off - 16;
                for (int j = 0; j < 16; j++) result[off + j] ^= xorWith[xorOff + j];
            }
            Timing.acc(Timing.coreNs, c);
        }
        long u = Timing.t0();
        result = unPadding(result);
        Timing.acc(Timing.unpadNs, u);
        return result;
    }

    private void parallelCbcDecrypt(byte[] m, byte[] iv, byte[] result, int[] rk) {
        int blocks = m.length / 16;
        int procs = Math.min(processorCount, blocks);
        long size = blocks / procs;
        long remainder = blocks % procs;
        CountDownLatch latch = new CountDownLatch(procs);
        long s = Timing.t0();
        for (int j = 0; j < procs; j++) {
            long start = j * size;
            long end = (j == procs - 1) ? start + size + remainder : (j + 1) * size;
            long fs = start, fe = end;
            getThreadPool().execute(() -> {
                for (int i = (int) fs; i < fe; i++) {
                    int off = i * 16;
                    decryptCoreOff(m, off, result, off, rk);
                    byte[] xorWith = (i == 0) ? iv : m;
                    int xorOff = (i == 0) ? 0 : off - 16;
                    for (int j2 = 0; j2 < 16; j2++) result[off + j2] ^= xorWith[xorOff + j2];
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        Timing.acc(Timing.coreNs, s);
    }

    // ==================== in-place / no-alloc 版本 ====================

    /**
     * ECB 加密 in-place。data 既是输入也是输出，避免 result[] 分配。
     * 大分组数时仍走并行，线程范围互不重叠，in==out 安全（仅块边界有轻微 false sharing）。
     */
    private void blockEncryptECBNoAlloc(byte[] data, int[] rk) {
        int blocks = data.length / 16;
        if (PARALLEL_ENABLED && blocks >= PARALLEL_THRESHOLD) {
            parallelCore(data, data, rk, true);
        } else {
            for (int i = 0; i < blocks; i++) {
                cipherCoreOff(data, i * 16, data, i * 16, rk);
            }
        }
    }

    /**
     * ECB 解密 in-place。
     */
    private void blockDecryptECBNoAlloc(byte[] data, int[] rk) {
        int blocks = data.length / 16;
        if (PARALLEL_ENABLED && blocks >= PARALLEL_THRESHOLD) {
            parallelCore(data, data, rk, false);
        } else {
            for (int i = 0; i < blocks; i++) {
                decryptCoreOff(data, i * 16, data, i * 16, rk);
            }
        }
    }

    /**
     * CBC 加密 in-place。第 i 块密文写入 data[i*16..]，并与下一块明文异或。
     */
    private void blockEncryptCBCNoAlloc(byte[] data, byte[] iv, int[] rk) {
        int blocks = data.length / 16;
        if (blocks == 0) return;
        int x0 = bytesToIntBE(data, 0) ^ bytesToIntBE(iv, 0);
        int x1 = bytesToIntBE(data, 4) ^ bytesToIntBE(iv, 4);
        int x2 = bytesToIntBE(data, 8) ^ bytesToIntBE(iv, 8);
        int x3 = bytesToIntBE(data, 12) ^ bytesToIntBE(iv, 12);
        for (int r = 0; r < 32; r++) {
            int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[r]);
            x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
        }
        intToBytesBE(x3, data, 0);
        intToBytesBE(x2, data, 4);
        intToBytesBE(x1, data, 8);
        intToBytesBE(x0, data, 12);
        for (int i = 1; i < blocks; i++) {
            int off = i * 16;
            x0 = bytesToIntBE(data, off) ^ bytesToIntBE(data, off - 16);
            x1 = bytesToIntBE(data, off + 4) ^ bytesToIntBE(data, off - 12);
            x2 = bytesToIntBE(data, off + 8) ^ bytesToIntBE(data, off - 8);
            x3 = bytesToIntBE(data, off + 12) ^ bytesToIntBE(data, off - 4);
            for (int r = 0; r < 32; r++) {
                int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[r]);
                x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
            }
            intToBytesBE(x3, data, off);
            intToBytesBE(x2, data, off + 4);
            intToBytesBE(x1, data, off + 8);
            intToBytesBE(x0, data, off + 12);
        }
    }

    // ==================== 内部工具方法 ====================

    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private static void xorBytesInPlace(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] ^= b[i];
        }
    }

    private byte[] padding(byte[] m) {
        if (Padding == PaddingEnum.NoPadding) {
            if (m.length % 16 != 0) {
                throw new RuntimeException("NoPadding 模式下输入长度必须是16的倍数");
            }
            return Arrays.copyOf(m, m.length);
        }
        int blockLength;
        if (Padding == PaddingEnum.Pkcs7) {
            blockLength = 16;
        } else if (Padding == PaddingEnum.Pkcs5) {
            blockLength = 8;
        } else {
            throw new RuntimeException("未识别的填充算法");
        }
        int t = blockLength - (m.length % blockLength);
        byte[] result = new byte[m.length + t];
        System.arraycopy(m, 0, result, 0, m.length);
        Arrays.fill(result, m.length, result.length, (byte) t);
        return result;
    }

    private byte[] unPadding(byte[] m) {
        if (Padding == PaddingEnum.NoPadding) {
            return Arrays.copyOf(m, m.length);
        }
        int count = m[m.length - 1] & 0xFF;
        byte[] result = new byte[m.length - count];
        System.arraycopy(m, 0, result, 0, result.length);
        return result;
    }

    private static void updateShiftRegister(byte[] feedback, byte[] input, int off, int len) {
        if (len == feedback.length) {
            System.arraycopy(input, off, feedback, 0, feedback.length);
            return;
        }
        System.arraycopy(feedback, len, feedback, 0, feedback.length - len);
        System.arraycopy(input, off, feedback, feedback.length - len, len);
    }

    private static void checkIvLength(byte[] iv) {
        if (iv == null) {
            throw new RuntimeException("iv 不能为空");
        }
        if (iv.length != 16) {
            throw new RuntimeException("iv 长度错误 iv len=" + iv.length);
        }
    }

    private byte[][] block(byte[] m) {
        int count = m.length / 16;
        int last = m.length % 16;
        if (last != 0) count++;
        byte[][] result = new byte[count][];
        for (int i = 0; i < count; i++) {
            int len = (i == count - 1 && last != 0) ? last : 16;
            result[i] = new byte[len];
            System.arraycopy(m, i * 16, result[i], 0, len);
        }
        return result;
    }

    private byte[] merge(byte[][] ms) {
        int len = (ms.length - 1) * 16 + ms[ms.length - 1].length;
        byte[] result = new byte[len];
        for (int i = 0; i < ms.length; i++) {
            System.arraycopy(ms[i], 0, result, i * 16, ms[i].length);
        }
        return result;
    }

    // ==================== GCM 相关代码 ====================

    private static byte[] shiftRight1(byte[] in) {
        byte[] out = new byte[in.length];
        int carry = 0;
        for (int i = 0; i < in.length; i++) {
            int b = in[i] & 0xFF;
            out[i] = (byte) ((b >>> 1) | carry);
            carry = (b & 1) << 7;
        }
        return out;
    }

    private void initVBox(byte[] H) {
        byte[] R = new byte[16];
        R[0] = (byte) 0xE1;
        VBox[0] = H.clone();
        for (int i = 0; i < 128; i++) {
            boolean lsb = (VBox[i][15] & 1) == 1;
            VBox[i + 1] = shiftRight1(VBox[i]);
            if (lsb) {
                xorBytesInPlace(VBox[i + 1], R);
            }
        }
    }

    private byte[] byteArrayMultiplePoint(byte[] X) {
        byte[] Y0 = new byte[16];
        for (int i = 0; i < 128; i++) {
            if (((X[i / 8] >> (7 - i % 8)) & 0x1) == 1) {
                xorBytesInPlace(Y0, VBox[i]);
            }
        }
        return Y0;
    }

    private byte[] GHASH(byte[] X, byte[] H) {
        if (X.length % 16 != 0) {
            throw new RuntimeException("X.length%16!=0");
        }
        byte[][] blockX = block(X);
        long m = X.length / 16;
        byte[] Y0 = new byte[16];
        for (int i = 1; i <= m; i++) {
            xorBytesInPlace(Y0, blockX[i - 1]);
            Y0 = byteArrayMultiplePoint(Y0);
        }
        return Y0;
    }

    /**
     * GHASH via native CLMUL/PCLMULQDQ when available.
     * Falls back to the Java table implementation otherwise.
     */
    private byte[] GHASHFast(byte[] X, byte[] H) {
        if (SM4GCMNative.isAvailable()) {
            try {
                byte[] out = new byte[16];
                SM4GCMNative.ghash(X, H, out);
                return out;
            } catch (Throwable t) {
                SM4GCMNative.markUnavailable();
            }
        }
        return GHASH(X, H);
    }

    private byte[] GCTR(byte[] ICB, byte[] X, int[] rk) {
        if (X == null) return null;
        long n = X.length / 16;
        if (X.length % 16 != 0) n++;
        byte[][] blockX = block(X);
        byte[][] YArray = new byte[(int) n][16];

        if (!PARALLEL_ENABLED || blockX.length < PARALLEL_THRESHOLD) {
            // 单线程路径，响应 -Dgm.sm4.parallel=false
            byte[] curIv = ICB.clone();
            for (int i = 0; i < blockX.length; i++) {
                byte[] cipher = cipherCore(curIv, rk);
                if (blockX[i].length != cipher.length) {
                    byte[] tempCipher = new byte[blockX[i].length];
                    System.arraycopy(cipher, 0, tempCipher, 0, blockX[i].length);
                    cipher = tempCipher;
                }
                YArray[i] = xorBytes(blockX[i], cipher);
                incrementCounter(curIv);
            }
            return DataConvertUtil.byteArrAdd(YArray);
        }

        int procs = Math.min(processorCount, blockX.length);
        long size = blockX.length / procs;
        long remainder = blockX.length % procs;
        CountDownLatch latch = new CountDownLatch(procs);

        for (int j = 0; j < procs; j++) {
            long start = j * size;
            long end = (j == procs - 1) ? (j * size + size + remainder) : ((j + 1) * size);
            byte[] threadIv = addToCounter(ICB, start);
            long finalEnd = end;
            long finalStart = start;
            getThreadPool().execute(() -> {
                byte[] curIv = threadIv;
                for (int i = (int) finalStart; i < finalEnd; i++) {
                    byte[] cipher = cipherCore(curIv, rk);
                    if (blockX[i].length != cipher.length) {
                        byte[] tempCipher = new byte[blockX[i].length];
                        System.arraycopy(cipher, 0, tempCipher, 0, blockX[i].length);
                        cipher = tempCipher;
                    }
                    YArray[i] = xorBytes(blockX[i], cipher);
                    curIv = curIv.clone();
                    incrementCounter(curIv);
                }
                latch.countDown();
            });
        }
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        return DataConvertUtil.byteArrAdd(YArray);
    }

    public AEADExecution cipherEncryptGCM(byte[] key, byte[] ming, byte[] iv, byte[] aad, int tagLen) {
        long l = System.currentTimeMillis();
        int[] rk = extKeyInt(key);
        if (TIME) {
            System.out.println("ext_key_L:" + (System.currentTimeMillis() - l));
            l = System.currentTimeMillis();
        }
        byte[] H = cipherCore(new byte[16], rk);
        if (DEBUG) System.out.println("H:" + Hex.toHexString(H));
        if (TIME) {
            System.out.println("generateH:" + (System.currentTimeMillis() - l));
            l = System.currentTimeMillis();
        }
        initVBox(H);
        if (TIME) {
            System.out.println("initVBox:" + (System.currentTimeMillis() - l));
        }

        byte[] J0;
        if (iv.length == 12) {
            J0 = new byte[16];
            System.arraycopy(iv, 0, J0, 0, 12);
            J0[15] = 0x01;
        } else {
            long s1 = iv.length / 16;
            if (iv.length % 16 != 0) s1++;
            long s = 16 * s1 - iv.length;
            byte[] lenBytes = new byte[8];
            int ivLen = iv.length;
            lenBytes[4] = (byte) (ivLen >>> 24);
            lenBytes[5] = (byte) (ivLen >>> 16);
            lenBytes[6] = (byte) (ivLen >>> 8);
            lenBytes[7] = (byte) ivLen;
            J0 = GHASHFast(DataConvertUtil.byteArrAdd(iv, new byte[(int) s + 8], lenBytes), H);
        }

        l = System.currentTimeMillis();
        byte[] incJ0 = addToCounter(J0, 1);
        byte[] C = GCTR(incJ0, ming, rk);
        if (DEBUG) System.out.println("C hex:" + Hex.toHexString(C));
        if (TIME) {
            System.out.println("GCTR C:" + (System.currentTimeMillis() - l));
            l = System.currentTimeMillis();
        }

        int ceilC = (int) Math.ceil(C.length / 16.0);
        int ceilAad = (int) Math.ceil(aad.length / 16.0);
        byte[] u = 16 * ceilC - C.length == 0 ? null : new byte[16 * ceilC - C.length];
        byte[] v = 16 * ceilAad - aad.length == 0 ? null : new byte[16 * ceilAad - aad.length];

        byte[] aadLenBytes = new byte[8];
        int aadBitLen = 8 * aad.length;
        aadLenBytes[4] = (byte) (aadBitLen >>> 24);
        aadLenBytes[5] = (byte) (aadBitLen >>> 16);
        aadLenBytes[6] = (byte) (aadBitLen >>> 8);
        aadLenBytes[7] = (byte) aadBitLen;

        byte[] cLenBytes = new byte[8];
        int cBitLen = 8 * C.length;
        cLenBytes[4] = (byte) (cBitLen >>> 24);
        cLenBytes[5] = (byte) (cBitLen >>> 16);
        cLenBytes[6] = (byte) (cBitLen >>> 8);
        cLenBytes[7] = (byte) cBitLen;

        byte[] S = GHASHFast(DataConvertUtil.byteArrAdd(aad, v, C, u, aadLenBytes, cLenBytes), H);

        if (TIME) {
            System.out.println("GHASH S:" + (System.currentTimeMillis() - l));
            l = System.currentTimeMillis();
        }

        byte[] T = new byte[tagLen];
        System.arraycopy(GCTR(J0, S, rk), 0, T, 0, tagLen);

        if (TIME) {
            System.out.println("GCTR T:" + (System.currentTimeMillis() - l));
        }

        return new AEADExecution(C, T);
    }

    public byte[] cipherDecryptGCM(byte[] key, byte[] mi, byte[] iv, byte[] aad, byte[] tag) {
        int[] rk = extKeyInt(key);
        byte[] H = cipherCore(new byte[16], rk);
        initVBox(H);

        byte[] J0;
        if (iv.length == 12) {
            J0 = new byte[16];
            System.arraycopy(iv, 0, J0, 0, 12);
            J0[15] = 0x01;
        } else {
            long s1 = iv.length / 16;
            if (iv.length % 16 != 0) s1++;
            long s = 16 * s1 - iv.length;
            byte[] lenBytes = new byte[8];
            int ivLen = iv.length;
            lenBytes[4] = (byte) (ivLen >>> 24);
            lenBytes[5] = (byte) (ivLen >>> 16);
            lenBytes[6] = (byte) (ivLen >>> 8);
            lenBytes[7] = (byte) ivLen;
            J0 = GHASHFast(DataConvertUtil.byteArrAdd(iv, new byte[(int) s + 8], lenBytes), H);
        }

        byte[] incJ0 = addToCounter(J0, 1);
        byte[] P = GCTR(incJ0, mi, rk);

        int ceilC = (int) Math.ceil(mi.length / 16.0);
        int ceilAad = (int) Math.ceil(aad.length / 16.0);
        byte[] u = 16 * ceilC - mi.length == 0 ? null : new byte[16 * ceilC - mi.length];
        byte[] v = 16 * ceilAad - aad.length == 0 ? null : new byte[16 * ceilAad - aad.length];

        byte[] aadLenBytes = new byte[8];
        int aadBitLen = 8 * aad.length;
        aadLenBytes[4] = (byte) (aadBitLen >>> 24);
        aadLenBytes[5] = (byte) (aadBitLen >>> 16);
        aadLenBytes[6] = (byte) (aadBitLen >>> 8);
        aadLenBytes[7] = (byte) aadBitLen;

        byte[] cLenBytes = new byte[8];
        int cBitLen = 8 * mi.length;
        cLenBytes[4] = (byte) (cBitLen >>> 24);
        cLenBytes[5] = (byte) (cBitLen >>> 16);
        cLenBytes[6] = (byte) (cBitLen >>> 8);
        cLenBytes[7] = (byte) cBitLen;

        byte[] S = GHASHFast(DataConvertUtil.byteArrAdd(aad, v, mi, u, aadLenBytes, cLenBytes), H);
        byte[] T = new byte[tag.length];
        System.arraycopy(GCTR(J0, S, rk), 0, T, 0, tag.length);
        if (!Arrays.equals(T, tag)) {
            throw new RuntimeException("tag不匹配");
        }
        return P;
    }
}
