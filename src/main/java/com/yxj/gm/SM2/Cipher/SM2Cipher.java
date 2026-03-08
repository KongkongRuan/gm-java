package com.yxj.gm.SM2.Cipher;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SM2Cipher {

    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    public byte[] SM2CipherEncrypt(byte[] M, byte[] pubKey) {
        byte[] k = new byte[32];
        SECURE_RANDOM.get().nextBytes(k);
        BigInteger bigK = new BigInteger(1, k);

        BigInteger[] c1Pt = SM2Util.fixedBaseMultiply(bigK);
        byte[] c1x = SM2Util.toFixedBytes(c1Pt[0], 32);
        byte[] c1y = SM2Util.toFixedBytes(c1Pt[1], 32);

        byte[] Xb = new byte[32];
        byte[] Yb = new byte[32];
        System.arraycopy(pubKey, 0, Xb, 0, 32);
        System.arraycopy(pubKey, 32, Yb, 0, 32);
        BigInteger[] kpPt = SM2Util.fieldMultiply(
                new BigInteger(1, Xb), new BigInteger(1, Yb), bigK);
        byte[] x2 = SM2Util.toFixedBytes(kpPt[0], 32);
        byte[] y2 = SM2Util.toFixedBytes(kpPt[1], 32);

        byte[] T = SM2_KDF(x2, y2, M.length);
        byte[] C2 = DataConvertUtil.byteArrayXOR(M, T);

        SM3Digest digest = new SM3Digest();
        digest.update(x2);
        digest.update(M);
        digest.update(y2);
        byte[] C3 = digest.doFinal();

        byte[] result = new byte[65 + 32 + M.length];
        result[0] = 0x04;
        System.arraycopy(c1x, 0, result, 1, 32);
        System.arraycopy(c1y, 0, result, 33, 32);
        System.arraycopy(C3, 0, result, 65, 32);
        System.arraycopy(C2, 0, result, 97, M.length);
        return result;
    }

    public byte[] SM2CipherDecrypt(byte[] M, byte[] priKey) {
        if (M[0] != 0x04) {
            throw new RuntimeException("无法解密压缩C1");
        }
        int kLen = M.length - 97;

        byte[] C1x = new byte[32];
        byte[] C1y = new byte[32];
        System.arraycopy(M, 1, C1x, 0, 32);
        System.arraycopy(M, 33, C1y, 0, 32);

        if (!SM2Util.checkPubKey(new byte[][]{C1x, C1y})) {
            throw new RuntimeException("C1验证未通过");
        }

        BigInteger[] pt = SM2Util.fieldMultiply(
                new BigInteger(1, C1x), new BigInteger(1, C1y), new BigInteger(1, priKey));
        byte[] x2 = SM2Util.toFixedBytes(pt[0], 32);
        byte[] y2 = SM2Util.toFixedBytes(pt[1], 32);

        byte[] T = SM2_KDF(x2, y2, kLen);
        byte[] C2 = new byte[kLen];
        System.arraycopy(M, 97, C2, 0, kLen);
        byte[] ming = DataConvertUtil.byteArrayXOR(C2, T);

        SM3Digest digest = new SM3Digest();
        digest.update(x2);
        digest.update(ming);
        digest.update(y2);
        byte[] u = digest.doFinal();

        byte[] C3 = new byte[32];
        System.arraycopy(M, 65, C3, 0, 32);
        if (!Arrays.equals(u, C3)) {
            throw new RuntimeException("C3验证未通过");
        }
        return ming;
    }

    /**
     * KDF 密钥派生函数 - 接受 x2/y2 分离输入，复用 SM3Digest 实例
     */
    private byte[] SM2_KDF(byte[] x2, byte[] y2, int kLen) {
        int n = (kLen + 31) / 32;
        byte[] K = new byte[kLen];
        byte[] ctBytes = new byte[4];
        SM3Digest digest = new SM3Digest();
        int offset = 0;
        for (int i = 1; i <= n; i++) {
            ctBytes[0] = (byte) (i >>> 24);
            ctBytes[1] = (byte) (i >>> 16);
            ctBytes[2] = (byte) (i >>> 8);
            ctBytes[3] = (byte) i;
            digest.update(x2);
            digest.update(y2);
            digest.update(ctBytes);
            byte[] hash = digest.doFinal();
            int copyLen = Math.min(32, kLen - offset);
            System.arraycopy(hash, 0, K, offset, copyLen);
            offset += copyLen;
        }
        return K;
    }
}
