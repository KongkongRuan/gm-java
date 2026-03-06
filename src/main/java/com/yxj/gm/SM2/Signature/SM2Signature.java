package com.yxj.gm.SM2.Signature;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;

/**
 * SM2 签名/验签
 *
 * 优化：使用 BigInteger.modInverse() 替代自实现的扩展欧几里得算法，
 *      使用缓存的 BigInteger 曲线参数
 */
public class SM2Signature {

    private byte[][] internalSignature(byte[] msg, byte[] dA, byte[] Za) {
        byte[] M_ = new byte[Za.length + msg.length];
        System.arraycopy(Za, 0, M_, 0, Za.length);
        System.arraycopy(msg, 0, M_, Za.length, msg.length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(M_);
        byte[] e = sm3Digest.doFinal();

        BigInteger bigE = new BigInteger(1, e);
        BigInteger bigN = SM2Constant.getBigN();
        BigInteger r = BigInteger.ZERO;
        byte[] kBytes = new byte[32];

        while (r.equals(BigInteger.ZERO) || bigN.equals(r.add(new BigInteger(1, kBytes)))) {
            byte[][] keyPairBytes = SM2Util.generatePubKey();
            kBytes = keyPairBytes[0];
            BigInteger bigx1 = new BigInteger(1, keyPairBytes[1]);
            r = bigE.add(bigx1).mod(bigN);
        }

        BigInteger bigK = new BigInteger(1, kBytes);
        BigInteger bigDa = new BigInteger(1, dA);
        BigInteger ts0 = BigInteger.ONE.add(bigDa).mod(bigN);
        BigInteger ts1 = ts0.modInverse(bigN);

        BigInteger ts2 = r.multiply(bigDa).mod(bigN);
        BigInteger ts3 = bigK.subtract(ts2).mod(bigN);
        BigInteger s = ts1.multiply(ts3).mod(bigN);

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

        byte[] sBytes = SM2Util.toFixedBytes(bigS, 32);
        byte[] tBytes = SM2Util.toFixedBytes(bigT, 32);

        byte[][] temp1 = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), sBytes, SM2Constant.getA(), SM2Constant.getP());
        byte[][] temp2 = SM2Util.MultiplePointOperation(
                DataConvertUtil.oneAdd(Xa), DataConvertUtil.oneAdd(Ya),
                tBytes, SM2Constant.getA(), SM2Constant.getP());

        byte[][] temp3 = SM2Util.PointAdditionOperation(
                DataConvertUtil.oneAdd(temp1[0]), DataConvertUtil.oneAdd(temp1[1]),
                DataConvertUtil.oneAdd(temp2[0]), DataConvertUtil.oneAdd(temp2[1]),
                SM2Constant.getA(), SM2Constant.getP());

        BigInteger bigX1 = new BigInteger(1, temp3[0]);
        BigInteger R = bigE.add(bigX1).mod(bigN);
        return R.equals(bigR);
    }

    public byte[] signature(byte[] msg, byte[] id, byte[] priKey) {
        byte[][] puba = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] za = SM2Util.initZa(id, DataConvertUtil.byteArrAdd(puba[0], puba[1]));
        byte[][] bytes = internalSignature(msg, priKey, za);
        byte[] temp = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, temp, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, temp, bytes[0].length, bytes[1].length);
        return temp;
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
