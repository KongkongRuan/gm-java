package com.yxj.gm.SM2.Signature;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.JNI.Nat256Native;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SM2 签名/验签
 *
 * 优化：
 * 1. 签名使用 fixedBaseMultiply 直接计算 [k]G，跳过完整的密钥对生成和公钥校验
 * 2. 验签使用 Shamir's Trick 将两次独立标量乘法合并为一次遍历
 * 3. 提供接受公钥参数的签名重载，避免从私钥推导公钥的额外标量乘法
 */
public class SM2Signature {

    private static final boolean DEBUG = Boolean.getBoolean("gm.debug");

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger N_MINUS_2 = SM2Constant.getBigN().subtract(TWO);
    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    private static final ThreadLocal<byte[]> cachedPriKey = new ThreadLocal<>();
    private static final ThreadLocal<BigInteger> cachedDaInverse = new ThreadLocal<>();
    private static final ThreadLocal<byte[]> cachedDaInvBytes = new ThreadLocal<>();

    private byte[][] internalSignature(byte[] msg, byte[] dA, byte[] Za) {
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(Za);
        sm3Digest.update(msg);
        byte[] e = sm3Digest.doFinal();

        SecureRandom secureRandom = SECURE_RANDOM.get();
        BigInteger bigN = SM2Constant.getBigN();

        BigInteger bigDa = new BigInteger(1, dA);
        byte[] daInvBytes;
        byte[] cached = cachedPriKey.get();
        if (cached != null && java.util.Arrays.equals(cached, dA)) {
            daInvBytes = cachedDaInvBytes.get();
        } else {
            BigInteger daInv = bigDa.add(BigInteger.ONE).modInverse(bigN);
            daInvBytes = SM2Util.toFixedBytes(daInv, 32);
            cachedPriKey.set(dA.clone());
            cachedDaInvBytes.set(daInvBytes);
            cachedDaInverse.set(daInv);
        }

        if (Nat256Native.isAvailable()) {
            try {
                byte[] kBytes = new byte[32];
                byte[] outRS = new byte[64];
                while (true) {
                    secureRandom.nextBytes(kBytes);
                    if (Nat256Native.nativeSignCore(e, dA, daInvBytes, kBytes, outRS) == 1) {
                        byte[][] result = new byte[2][32];
                        System.arraycopy(outRS, 0, result[0], 0, 32);
                        System.arraycopy(outRS, 32, result[1], 0, 32);
                        return result;
                    }
                }
            } catch (Throwable t) {
                Nat256Native.markUnavailable();
            }
        }

        BigInteger daInv = cachedDaInverse.get();
        BigInteger bigE = new BigInteger(1, e);
        BigInteger r, bigK;
        do {
            byte[] kBytes = new byte[32];
            do {
                secureRandom.nextBytes(kBytes);
                bigK = new BigInteger(1, kBytes);
            } while (bigK.compareTo(BigInteger.ONE) < 0 || bigK.compareTo(N_MINUS_2) > 0);

            BigInteger[] kG = SM2Util.fixedBaseMultiply(bigK);
            r = bigE.add(kG[0]).mod(bigN);
        } while (r.signum() == 0 || r.add(bigK).equals(bigN));

        BigInteger s = daInv
                .multiply(bigK.subtract(r.multiply(bigDa)).mod(bigN)).mod(bigN);

        byte[][] result = new byte[2][32];
        result[0] = SM2Util.toFixedBytes(r, 32);
        result[1] = SM2Util.toFixedBytes(s, 32);
        return result;
    }

    private boolean internalVerify(byte[] M, byte[][] rs, byte[] Za, byte[] pubKey) {
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(Za);
        sm3Digest.update(M);
        byte[] e = sm3Digest.doFinal();

        if (Nat256Native.isAvailable()) {
            try {
                return Nat256Native.nativeVerifyCore(e, rs[0], rs[1], pubKey);
            } catch (Throwable t) {
                Nat256Native.markUnavailable();
            }
        }

        BigInteger bigE = new BigInteger(1, e);
        BigInteger bigR = new BigInteger(1, rs[0]);
        BigInteger bigS = new BigInteger(1, rs[1]);
        BigInteger bigN = SM2Constant.getBigN();
        BigInteger bigT = bigR.add(bigS).mod(bigN);
        if (bigT.equals(BigInteger.ZERO)) {
            return false;
        }

        byte[] Xa = new byte[32];
        byte[] Ya = new byte[32];
        System.arraycopy(pubKey, 0, Xa, 0, 32);
        System.arraycopy(pubKey, 32, Ya, 0, 32);
        BigInteger px = new BigInteger(1, Xa);
        BigInteger py = new BigInteger(1, Ya);

        BigInteger[] point = SM2Util.shamirMultiply(bigS, px, py, bigT);
        BigInteger R = bigE.add(point[0]).mod(bigN);
        return R.equals(bigR);
    }

    /**
     * 签名（传入公钥避免额外的标量乘法）
     */
    public byte[] signature(byte[] msg, byte[] id, byte[] priKey, byte[] pubKey) {
        long t = DEBUG ? System.nanoTime() : 0L;
        byte[] za = SM2Util.initZa(id, pubKey);
        byte[][] bytes = internalSignature(msg, priKey, za);
        byte[] temp = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, temp, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, temp, bytes[0].length, bytes[1].length);
        if (DEBUG) System.err.printf("[SM2 SIGN] %.2f ms%n", (System.nanoTime() - t) / 1e6);
        return temp;
    }

    /**
     * 签名（向后兼容，从私钥推导公钥）
     */
    public byte[] signature(byte[] msg, byte[] id, byte[] priKey) {
        byte[] pub = SM2Util.generatePubKeyByPriKey(priKey);
        return signature(msg, id, priKey, pub);
    }

    public byte[] signatureByHSM(byte[] msg, int index) {
        return new byte[0];
    }

    public boolean verify(byte[] msg, byte[] id, byte[] signature, byte[] pubKey) {
        long t = DEBUG ? System.nanoTime() : 0L;
        byte[] Za = SM2Util.initZa(id, pubKey);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        boolean ok = internalVerify(msg, new byte[][]{r, s}, Za, pubKey);
        if (DEBUG) System.err.printf("[SM2 VERIFY] %.2f ms%n", (System.nanoTime() - t) / 1e6);
        return ok;
    }

    /**
     * 验签 int[] 版本：把 byte[] 公钥/签名直接转成 int[8]，跳过 BigInteger。
     * 用于 A/B 测试 int[] 边界是否比 byte[] 更快。
     */
    public boolean verifyInt(byte[] msg, byte[] id, byte[] signature, byte[] pubKey) {
        if (!Nat256Native.isAvailable()) {
            return verify(msg, id, signature, pubKey);
        }
        byte[] Za = SM2Util.initZa(id, pubKey);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(Za);
        sm3Digest.update(msg);
        byte[] e = sm3Digest.doFinal();
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        return Nat256Native.nativeVerifyCoreInt(
                beBytesToLeInt8(e, 0),
                beBytesToLeInt8(r, 0),
                beBytesToLeInt8(s, 0),
                beBytesToLeInt8(pubKey, 0),
                beBytesToLeInt8(pubKey, 32));
    }

    /**
     * 全 native 验签：Java 只算 Za，C 端完成 SM3(Za||msg) + Shamir + compare。
     */
    public boolean verifyFull(byte[] msg, byte[] id, byte[] signature, byte[] pubKey) {
        if (!Nat256Native.isAvailable()) {
            return verify(msg, id, signature, pubKey);
        }
        byte[] Za = SM2Util.initZa(id, pubKey);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        return Nat256Native.nativeVerifyFull(Za, msg, msg.length, r, s, pubKey);
    }

    /**
     * 批量验签：n 个签名一次 JNI 往返，减少边界切换和线程本地缓存抖动。
     */
    public boolean[] verifyBatch(byte[][] msgs, byte[][] sigs, byte[][] pubKeys, byte[] id) {
        int n = msgs.length;
        if (!Nat256Native.isAvailable()) {
            boolean[] out = new boolean[n];
            for (int i = 0; i < n; i++) {
                out[i] = verify(msgs[i], id, sigs[i], pubKeys[i]);
            }
            return out;
        }
        byte[][] zas = new byte[n][];
        int totalMsgLen = 0;
        for (int i = 0; i < n; i++) {
            zas[i] = SM2Util.initZa(id, pubKeys[i]);
            totalMsgLen += msgs[i].length;
        }
        byte[] zaFlat = new byte[n * 32];
        byte[] msgFlat = new byte[totalMsgLen];
        int[] msgLens = new int[n];
        byte[] rsFlat = new byte[n * 64];
        byte[] pubFlat = new byte[n * 64];
        boolean[] out = new boolean[n];
        int msgOff = 0;
        for (int i = 0; i < n; i++) {
            System.arraycopy(zas[i], 0, zaFlat, i * 32, 32);
            System.arraycopy(msgs[i], 0, msgFlat, msgOff, msgs[i].length);
            msgLens[i] = msgs[i].length;
            msgOff += msgs[i].length;
            System.arraycopy(sigs[i], 0, rsFlat, i * 64, 64);
            System.arraycopy(pubKeys[i], 0, pubFlat, i * 64, 64);
        }
        Nat256Native.nativeVerifyBatch(zaFlat, msgFlat, msgLens, rsFlat, pubFlat, n, out);
        return out;
    }

    private static int[] beBytesToLeInt8(byte[] b, int off) {
        int[] r = new int[8];
        for (int i = 0; i < 8; i++) {
            int j = off + 28 - 4 * i;
            r[i] = ((b[j] & 0xFF) << 24) |
                   ((b[j + 1] & 0xFF) << 16) |
                   ((b[j + 2] & 0xFF) << 8) |
                   (b[j + 3] & 0xFF);
        }
        return r;
    }
}
