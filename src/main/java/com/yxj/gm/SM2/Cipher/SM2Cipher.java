package com.yxj.gm.SM2.Cipher;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.security.SecureRandom;
import java.util.Arrays;

public class SM2Cipher {

    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public byte[] SM2CipherEncrypt(byte[] M, byte[] pubKey) {
        byte[] Xb = new byte[32];
        byte[] Yb = new byte[32];
        System.arraycopy(pubKey, 0, Xb, 0, 32);
        System.arraycopy(pubKey, 32, Yb, 0, 32);

        byte[] k = new byte[32];
        SECURE_RANDOM.get().nextBytes(k);
        byte[][] C1Point = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), k, SM2Constant.getA(), SM2Constant.getP());
        byte[] C1 = new byte[C1Point[0].length + C1Point[1].length + 1];
        byte[] PC = new byte[]{(byte) 0x04};
        System.arraycopy(PC, 0, C1, 0, PC.length);
        System.arraycopy(C1Point[0], 0, C1, PC.length, C1Point[0].length);
        System.arraycopy(C1Point[1], 0, C1, PC.length + C1Point[0].length, C1Point[1].length);

        byte[][] bytes = SM2Util.MultiplePointOperation(Xb, Yb, k, SM2Constant.getA(), SM2Constant.getP());

        byte[] x2y2 = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, x2y2, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, x2y2, bytes[0].length, bytes[1].length);

        byte[] T = SM2_KDF(x2y2, M.length);
        byte[] C2 = DataConvertUtil.byteArrayXOR(M, T);
        byte[] x2My2 = new byte[bytes[0].length + M.length + bytes[1].length];
        System.arraycopy(bytes[0], 0, x2My2, 0, bytes[0].length);
        System.arraycopy(M, 0, x2My2, bytes[0].length, M.length);
        System.arraycopy(bytes[1], 0, x2My2, bytes[0].length + M.length, bytes[1].length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(x2My2);
        byte[] C3 = sm3Digest.doFinal();
        byte[] MI = new byte[C1.length + C2.length + C3.length];
        System.arraycopy(C1, 0, MI, 0, C1.length);
        System.arraycopy(C3, 0, MI, C1.length, C3.length);
        System.arraycopy(C2, 0, MI, C1.length + C3.length, C2.length);
        return MI;
    }

    public byte[] SM2CipherDecrypt(byte[] M, byte[] priKey) {
        byte[] C1 = new byte[65];
        byte[] C3 = new byte[32];
        int kLen = M.length - 65 - 32;
        byte[] C2 = new byte[kLen];
        byte[] PC = new byte[1];
        byte[] C1x = new byte[32];
        byte[] C1y = new byte[32];
        System.arraycopy(M, 0, C1, 0, 65);
        System.arraycopy(M, 65, C3, 0, 32);
        System.arraycopy(M, 65 + 32, C2, 0, kLen);
        System.arraycopy(C1, 0, PC, 0, 1);
        System.arraycopy(C1, 1, C1x, 0, 32);
        System.arraycopy(C1, 1 + 32, C1y, 0, 32);

        if (PC[0] != 4) {
            throw new RuntimeException("无法解密压缩C1");
        }
        if (!SM2Util.checkPubKey(new byte[][]{C1x, C1y})) {
            throw new RuntimeException("C1验证未通过");
        }

        byte[][] bytes = SM2Util.MultiplePointOperation(C1x, C1y, priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] x2y2 = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, x2y2, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, x2y2, bytes[0].length, bytes[1].length);
        byte[] T = SM2_KDF(x2y2, kLen);
        byte[] ming = DataConvertUtil.byteArrayXOR(C2, T);

        byte[] x2My2 = new byte[bytes[0].length + ming.length + bytes[1].length];
        System.arraycopy(bytes[0], 0, x2My2, 0, bytes[0].length);
        System.arraycopy(ming, 0, x2My2, bytes[0].length, ming.length);
        System.arraycopy(bytes[1], 0, x2My2, bytes[0].length + ming.length, bytes[1].length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(x2My2);
        byte[] u = sm3Digest.doFinal();
        if (!Arrays.equals(u, C3)) {
            throw new RuntimeException("C3验证未通过");
        }
        return ming;
    }

    /**
     * KDF 密钥派生函数 - 直接写入结果数组，避免反复拼接
     */
    private byte[] SM2_KDF(byte[] Z, int kLen) {
        int v = 32;
        int n = (int) Math.ceil((double) kLen / v);
        byte[] K = new byte[kLen];
        int offset = 0;
        for (int i = 1; i <= n; i++) {
            byte[] hash = paddConnHash(Z, i);
            int copyLen = Math.min(v, kLen - offset);
            System.arraycopy(hash, 0, K, offset, copyLen);
            offset += copyLen;
        }
        return K;
    }

    /**
     * 使用 int 计数器，避免 BigInteger 创建
     */
    private byte[] paddConnHash(byte[] z, int ct) {
        byte[] ctBytes = new byte[4];
        ctBytes[0] = (byte) (ct >>> 24);
        ctBytes[1] = (byte) (ct >>> 16);
        ctBytes[2] = (byte) (ct >>> 8);
        ctBytes[3] = (byte) ct;

        byte[] connect = new byte[z.length + 4];
        System.arraycopy(z, 0, connect, 0, z.length);
        System.arraycopy(ctBytes, 0, connect, z.length, 4);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(connect);
        return sm3Digest.doFinal();
    }
}
