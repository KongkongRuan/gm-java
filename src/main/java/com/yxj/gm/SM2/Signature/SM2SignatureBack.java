package com.yxj.gm.SM2.Signature;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * SM2 签名/验签（备份版本）
 *
 * 优化同 SM2Signature：fixedBaseMultiply + Shamir's Trick
 */
public class SM2SignatureBack {

    private static final BigInteger TWO = BigInteger.valueOf(2);

    byte[] Za;
    byte[] Xa;
    byte[] Ya;

    private void initXaYa(byte[] pubKey) {
        Xa = new byte[32];
        Ya = new byte[32];
        System.arraycopy(pubKey, 0, Xa, 0, 32);
        System.arraycopy(pubKey, 32, Ya, 0, 32);
    }

    private void initZa(byte[] IDa) {
        if (IDa == null) {
            IDa = "1234567812345678".getBytes();
        }
        short ENTLa = (short) (IDa.length * 8);
        byte[] ENTLaBytes = DataConvertUtil.shortToBytes(new short[]{ENTLa});

        byte[] ta = DataConvertUtil.oneDel(SM2Constant.getA());
        byte[] tb = DataConvertUtil.oneDel(SM2Constant.getB());
        byte[] txg = DataConvertUtil.oneDel(SM2Constant.getXG());
        byte[] tyg = DataConvertUtil.oneDel(SM2Constant.getYG());

        byte[] ZaMsg = new byte[ENTLaBytes.length + IDa.length + ta.length + tb.length + txg.length + tyg.length + Xa.length + Ya.length];
        byte[][] ZaByteS = new byte[][]{ENTLaBytes, IDa, ta, tb, txg, tyg, Xa, Ya};
        int index = 0;
        for (byte[] zaByte : ZaByteS) {
            System.arraycopy(zaByte, 0, ZaMsg, index, zaByte.length);
            index += zaByte.length;
        }
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(ZaMsg);
        Za = sm3Digest.doFinal();
    }

    private byte[][] internalSignature(byte[] msg, byte[] dA) {
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

    private boolean internalVerify(byte[] M, byte[][] rs) {
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

    public byte[] signature(byte[] msg, byte[] id, byte[] priKey) {
        byte[] pub = SM2Util.generatePubKeyByPriKey(priKey);
        Xa = new byte[32];
        Ya = new byte[32];
        System.arraycopy(pub, 0, Xa, 0, 32);
        System.arraycopy(pub, 32, Ya, 0, 32);
        initZa(id);
        byte[][] bytes = internalSignature(msg, priKey);
        byte[] temp = new byte[bytes[0].length + bytes[1].length];
        System.arraycopy(bytes[0], 0, temp, 0, bytes[0].length);
        System.arraycopy(bytes[1], 0, temp, bytes[0].length, bytes[1].length);
        return temp;
    }

    public byte[] signatureByHSM(byte[] msg, int index) {
        return new byte[0];
    }

    public boolean verify(byte[] msg, byte[] id, byte[] signature, byte[] pubKey) {
        initXaYa(pubKey);
        initZa(id);
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature, 0, r, 0, 32);
        System.arraycopy(signature, 32, s, 0, 32);
        return internalVerify(msg, new byte[][]{r, s});
    }
}
