package com.yxj.gm.SM4;

import com.yxj.gm.SM4.dto.AEADExecution;
import com.yxj.gm.constant.SM4Constant;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.enums.PaddingEnum;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
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

    private static final ExecutorService THREAD_POOL = Executors.newFixedThreadPool(
            Math.max(2, Runtime.getRuntime().availableProcessors()),
            r -> {
                Thread t = new Thread(r);
                t.setDaemon(true);
                return t;
            }
    );

    private ModeEnum Mode = CTR;
    private byte[][] VBox = new byte[129][16];
    private PaddingEnum Padding = PaddingEnum.Pkcs7;
    private boolean DEBUG = false;
    private boolean TIME = false;

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

    private static int tInt(int A) { return lInt(tauInt(A)); }
    private static int tPrimeInt(int A) { return lPrimeInt(tauInt(A)); }

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

    /**
     * 单 block 加密（int 轮密钥）
     */
    private byte[] cipherCore(byte[] in, int[] rk) {
        int x0 = bytesToIntBE(in, 0), x1 = bytesToIntBE(in, 4);
        int x2 = bytesToIntBE(in, 8), x3 = bytesToIntBE(in, 12);
        for (int i = 0; i < 32; i++) {
            int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[i]);
            x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
        }
        byte[] out = new byte[16];
        intToBytesBE(x3, out, 0);
        intToBytesBE(x2, out, 4);
        intToBytesBE(x1, out, 8);
        intToBytesBE(x0, out, 12);
        return out;
    }

    /**
     * 单 block 解密（int 轮密钥）
     */
    private byte[] decryptCore(byte[] in, int[] rk) {
        int x0 = bytesToIntBE(in, 0), x1 = bytesToIntBE(in, 4);
        int x2 = bytesToIntBE(in, 8), x3 = bytesToIntBE(in, 12);
        for (int i = 31; i >= 0; i--) {
            int tmp = x0 ^ tInt(x1 ^ x2 ^ x3 ^ rk[i]);
            x0 = x1; x1 = x2; x2 = x3; x3 = tmp;
        }
        byte[] out = new byte[16];
        intToBytesBE(x3, out, 0);
        intToBytesBE(x2, out, 4);
        intToBytesBE(x1, out, 8);
        intToBytesBE(x0, out, 12);
        return out;
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
            case CTR: result = blockEncryptCTRInt(mi, iv, rk); break;
            default: throw new RuntimeException("解密模式错误：" + Mode);
        }
        return result;
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

    public byte[] blockDecryptECB(byte[] m, byte[][] rks) {
        return blockDecryptECBInt(m, toIntKeys(rks));
    }

    public byte[] blockDecryptCBC(byte[] m, byte[] iv, byte[][] rks) {
        return blockDecryptCBCInt(m, iv, toIntKeys(rks));
    }

    // ==================== int 轮密钥版本的分组加解密 ====================

    private byte[] blockEncryptECBInt(byte[] m, int[] rk) {
        m = padding(m);
        byte[][] block = block(m);
        byte[][] result = new byte[block.length][16];
        for (int i = 0; i < block.length; i++) {
            result[i] = cipherCore(block[i], rk);
        }
        return merge(result);
    }

    private byte[] blockEncryptCBCInt(byte[] m, byte[] iv, int[] rk) {
        m = padding(m);
        byte[][] block = block(m);
        byte[][] result = new byte[block.length][16];
        byte[] xorTemp = iv;
        for (int i = 0; i < block.length; i++) {
            result[i] = cipherCore(xorBytes(block[i], xorTemp), rk);
            xorTemp = result[i];
        }
        return merge(result);
    }

    private byte[] blockEncryptCTRInt(byte[] m, byte[] iv, int[] rk) {
        if (iv.length != 16) {
            throw new RuntimeException("iv 长度错误 iv len=" + iv.length);
        }
        byte[][] blocks = block(m);
        byte[][] mis = new byte[blocks.length][16];
        int procs = Math.min(processorCount, blocks.length);

        long size = blocks.length / procs;
        long remainder = blocks.length % procs;
        CountDownLatch latch = new CountDownLatch(procs);

        for (int j = 0; j < procs; j++) {
            long start = j * size;
            long end = (j == procs - 1) ? (j * size + size + remainder) : ((j + 1) * size);
            byte[] threadIv = (j == 0) ? iv.clone() : addToCounter(iv, j * size);
            long finalEnd = end;
            long finalStart = start;
            THREAD_POOL.execute(() -> {
                byte[] curIv = threadIv;
                for (int i = (int) finalStart; i < finalEnd; i++) {
                    byte[] cipher = cipherCore(curIv, rk);
                    if (blocks[i].length != cipher.length) {
                        byte[] tempCipher = new byte[blocks[i].length];
                        System.arraycopy(cipher, 0, tempCipher, 0, blocks[i].length);
                        cipher = tempCipher;
                    }
                    mis[i] = xorBytes(blocks[i], cipher);
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
        return merge(mis);
    }

    private byte[] blockDecryptECBInt(byte[] m, int[] rk) {
        byte[][] block = block(m);
        byte[][] result = new byte[block.length][16];
        for (int i = 0; i < block.length; i++) {
            result[i] = decryptCore(block[i], rk);
        }
        byte[] merged = merge(result);
        return unPadding(merged);
    }

    private byte[] blockDecryptCBCInt(byte[] m, byte[] iv, int[] rk) {
        byte[][] block = block(m);
        byte[][] result = new byte[block.length][16];
        byte[] xorTemp = iv;
        for (int i = 0; i < block.length; i++) {
            result[i] = xorBytes(decryptCore(block[i], rk), xorTemp);
            xorTemp = block[i];
        }
        byte[] merged = merge(result);
        return unPadding(merged);
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
        int count = m[m.length - 1] & 0xFF;
        byte[] result = new byte[m.length - count];
        System.arraycopy(m, 0, result, 0, result.length);
        return result;
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

    private byte[] GCTR(byte[] ICB, byte[] X, int[] rk) {
        if (X == null) return null;
        long n = X.length / 16;
        if (X.length % 16 != 0) n++;
        byte[][] blockX = block(X);
        byte[][] YArray = new byte[(int) n][16];

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
            THREAD_POOL.execute(() -> {
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
            J0 = GHASH(DataConvertUtil.byteArrAdd(iv, new byte[(int) s + 8], lenBytes), H);
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

        byte[] S = GHASH(DataConvertUtil.byteArrAdd(aad, v, C, u, aadLenBytes, cLenBytes), H);

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
            J0 = GHASH(DataConvertUtil.byteArrAdd(iv, new byte[(int) s + 8], lenBytes), H);
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

        byte[] S = GHASH(DataConvertUtil.byteArrAdd(aad, v, mi, u, aadLenBytes, cLenBytes), H);
        byte[] T = new byte[tag.length];
        System.arraycopy(GCTR(J0, S, rk), 0, T, 0, tag.length);
        if (!Arrays.equals(T, tag)) {
            throw new RuntimeException("tag不匹配");
        }
        return P;
    }
}
