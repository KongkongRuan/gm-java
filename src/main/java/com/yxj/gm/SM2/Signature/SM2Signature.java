package com.yxj.gm.SM2.Signature;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
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

    private byte[][] internalSignature(byte[] msg, byte[] dA, byte[] Za) {
        byte[] M_ = new byte[Za.length + msg.length];
        System.arraycopy(Za, 0, M_, 0, Za.length);
        System.arraycopy(msg, 0, M_, Za.length, msg.length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(M_);
        byte[] e = sm3Digest.doFinal();

        BigInteger bigE = new BigInteger(1, e);
        BigInteger bigN = SM2Constant.getBigN();
        BigInteger nMinus2 = bigN.subtract(TWO);
        SecureRandom secureRandom = new SecureRandom();

        BigInteger r, bigK;
        do {
            byte[] kBytes = new byte[32];
            do {
                secureRandom.nextBytes(kBytes);
                bigK = new BigInteger(1, kBytes);
            } while (bigK.compareTo(BigInteger.ONE) < 0 || bigK.compareTo(nMinus2) > 0);

            BigInteger[] kG = SM2Util.fixedBaseMultiply(bigK);
            r = bigE.add(kG[0]).mod(bigN);
        } while (r.signum() == 0 || r.add(bigK).equals(bigN));

        BigInteger bigDa = new BigInteger(1, dA);
        BigInteger s = bigDa.add(BigInteger.ONE).modInverse(bigN)
                .multiply(bigK.subtract(r.multiply(bigDa)).mod(bigN)).mod(bigN);

        byte[][] result = new byte[2][32];
        result[0] = SM2Util.toFixedBytes(r, 32);
        result[1] = SM2Util.toFixedBytes(s, 32);
        return result;
    }

    private boolean internalVerify(byte[] M, byte[][] rs, byte[] Za, byte[] pubKey) {
        byte[] Xa = new byte[32];
        byte[] Ya = new byte[32];
        System.arraycopy(pubKey, 0, Xa, 0, 32);
        System.arraycopy(pubKey, 32, Ya, 0, 32);

        byte[] M_ = new byte[Za.length + M.length];
        System.arraycopy(Za, 0, M_, 0, Za.length);
        System.arraycopy(M, 0, M_, Za.length, M.length);

        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(M_);
        byte[] e = sm3Digest.doFinal();

        BigInteger bigE = new BigInteger(1, e);
        BigInteger bigR = new BigInteger(1, rs[0]);
        BigInteger bigS = new BigInteger(1, rs[1]);
        BigInteger bigN = SM2Constant.getBigN();
        BigInteger bigT = bigR.add(bigS).mod(bigN);
        if (bigT.equals(BigInteger.ZERO)) {
            return false;
        }

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
