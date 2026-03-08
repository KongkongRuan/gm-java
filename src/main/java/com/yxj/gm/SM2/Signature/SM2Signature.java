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
        byte[] za = SM2Util.initZa(id, pubKey);
        byte[][] bytes = internalSignature(msg, priKey, za);
        byte[] temp = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, temp, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, temp, bytes[0].length, bytes[1].length);
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
        byte[] Za = SM2Util.initZa(id, pubKey);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        return internalVerify(msg, new byte[][]{r, s}, Za, pubKey);
    }
}
