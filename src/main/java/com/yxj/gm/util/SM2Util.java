package com.yxj.gm.util;

import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.*;

/**
 * SM2 椭圆曲线工具类
 *
 * 性能优化：
 * 1. 使用雅可比坐标（Jacobian coordinates）进行点运算，整个标量乘法只需 1 次模逆
 * 2. 内部运算全部使用 BigInteger，只在输入/输出处转换 byte[]
 * 3. 对 a = p - 3 情况使用优化的倍点公式
 * 4. 使用 BigInteger.modInverse() 替代自实现的扩展欧几里得
 * 5. 缓存曲线参数的 BigInteger 形式
 */
public class SM2Util {
    public static final ECDomainParameters SM2_DOMAIN_PARAMS = SM2Util.toDomainParams(GMNamedCurves.getByName("sm2p256v1"));
    public static final AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    // ==================== 公开接口（保持向后兼容） ====================

    public static byte[] generatePubKeyByPriKey(byte[] priKey) {
        byte[][] puba = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] pub = new byte[64];
        System.arraycopy(puba[0], 0, pub, 0, 32);
        System.arraycopy(puba[1], 0, pub, 32, 32);
        return pub;
    }

    public static byte[][] generatePubKey() {
        byte[][] result = new byte[3][32];
        SecureRandom secureRandom = new SecureRandom();
        BigInteger bigN = SM2Constant.getBigN();
        BigInteger nMinus2 = bigN.subtract(TWO);

        while (true) {
            byte[] random = new byte[32];
            secureRandom.nextBytes(random);
            BigInteger bigD = new BigInteger(1, random);
            if (bigD.compareTo(BigInteger.ONE) < 0 || bigD.compareTo(nMinus2) > 0) {
                continue;
            }
            byte[][] bytes = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), random, SM2Constant.getA(), SM2Constant.getP());
            if (checkPubKey(bytes)) {
                result[0] = toFixedBytes(bigD, 32);
                result[1] = bytes[0];
                result[2] = bytes[1];
                return result;
            }
        }
    }

    public static byte[] KeyExchange(byte[] peerPubKey, byte[] priKey, int len) {
        byte[] random = Hex.decode("dffcd0d719295a37b9bc19eed2f9923a");
        byte[] PX = new byte[32];
        byte[] PY = new byte[32];
        System.arraycopy(peerPubKey, 0, PX, 0, 32);
        System.arraycopy(peerPubKey, 32, PY, 0, 32);

        byte[][] bytes = MultiplePointOperation(PX, PY, priKey, SM2Constant.getA(), SM2Constant.getP());
        try {
            MessageDigest xaMd = MessageDigest.getInstance("SM3", "XaProvider");
            return TLSUtil.prf(xaMd, random, bytes[0], bytes[1], len);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 生成Za
     */
    public static byte[] initZa(byte[] IDa, byte[] pubKey) {
        byte[] Xa = new byte[32];
        byte[] Ya = new byte[32];
        System.arraycopy(pubKey, 0, Xa, 0, 32);
        System.arraycopy(pubKey, 32, Ya, 0, 32);

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
        return sm3Digest.doFinal();
    }

    public static ECDomainParameters toDomainParams(X9ECParameters x9ECParameters) {
        return new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
    }

    // ==================== 核心点运算（雅可比坐标） ====================

    /**
     * 标量乘法：Q = [k]P
     * 使用雅可比坐标 + 二进制展开法，整个过程只需 1 次模逆
     */
    public static byte[][] MultiplePointOperation(byte[] XG, byte[] YG, byte[] k, byte[] a, byte[] p) {
        BigInteger bigP = toBigIntUnsigned(p);
        BigInteger bigA = toBigIntUnsigned(a);
        BigInteger bigK = toBigIntUnsigned(k);
        BigInteger gx = toBigIntUnsigned(XG);
        BigInteger gy = toBigIntUnsigned(YG);

        boolean aIsMinusThree = bigA.add(THREE).equals(bigP);

        // 雅可比坐标标量乘法
        BigInteger[] Q = jacobianMultiply(gx, gy, bigK, bigA, bigP, aIsMinusThree);

        // 转回仿射坐标（只需 1 次模逆）
        if (Q[2].signum() == 0) {
            return new byte[2][32];
        }
        BigInteger zInv = Q[2].modInverse(bigP);
        BigInteger zInv2 = zInv.multiply(zInv).mod(bigP);
        BigInteger zInv3 = zInv2.multiply(zInv).mod(bigP);
        BigInteger rx = Q[0].multiply(zInv2).mod(bigP);
        BigInteger ry = Q[1].multiply(zInv3).mod(bigP);

        byte[][] result = new byte[2][32];
        result[0] = toFixedBytes(rx, 32);
        result[1] = toFixedBytes(ry, 32);
        return result;
    }

    /**
     * 仿射坐标两点相加（向后兼容，使用 modInverse 替代自实现的扩展欧几里得）
     */
    public static byte[][] PointAdditionOperation(byte[] X1, byte[] Y1, byte[] X2, byte[] Y2, byte[] a, byte[] p) {
        BigInteger x1 = toBigIntUnsigned(X1);
        BigInteger y1 = toBigIntUnsigned(Y1);
        BigInteger x2 = toBigIntUnsigned(X2);
        BigInteger y2 = toBigIntUnsigned(Y2);
        BigInteger bigA = toBigIntUnsigned(a);
        BigInteger bigP = toBigIntUnsigned(p);

        if (x1.signum() == 0 && y1.signum() == 0) {
            return toPointResult(x2, y2);
        }
        if (x2.signum() == 0 && y2.signum() == 0) {
            return toPointResult(x1, y1);
        }

        BigInteger lambda;
        if (!x1.equals(x2)) {
            BigInteger dy = y2.subtract(y1).mod(bigP);
            BigInteger dx = x2.subtract(x1).mod(bigP);
            lambda = dy.multiply(dx.modInverse(bigP)).mod(bigP);
        } else {
            BigInteger num = x1.multiply(x1).mod(bigP).multiply(THREE).add(bigA).mod(bigP);
            BigInteger den = y1.add(y1).mod(bigP);
            lambda = num.multiply(den.modInverse(bigP)).mod(bigP);
        }

        BigInteger x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(bigP);
        BigInteger y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(bigP);

        return toPointResult(x3, y3);
    }

    public static boolean checkPubKey(byte[][] pubKey) {
        BigInteger bigX = toBigIntUnsigned(pubKey[0]);
        BigInteger bigY = toBigIntUnsigned(pubKey[1]);
        BigInteger bigP = SM2Constant.getBigP();
        BigInteger bigA = SM2Constant.getBigA();
        BigInteger bigB = SM2Constant.getBigB();
        BigInteger pMinus1 = bigP.subtract(BigInteger.ONE);

        if (bigX.compareTo(pMinus1) > 0 || bigY.compareTo(pMinus1) > 0) {
            return false;
        }

        BigInteger left = bigY.multiply(bigY).mod(bigP);
        BigInteger right = bigX.multiply(bigX).mod(bigP).multiply(bigX).mod(bigP)
                .add(bigA.multiply(bigX).mod(bigP))
                .add(bigB)
                .mod(bigP);

        return left.equals(right);
    }

    // ==================== 雅可比坐标内部实现 ====================

    /**
     * 雅可比坐标标量乘法：Q = [k]P，P 为仿射坐标
     * 使用 left-to-right 二进制展开 + 混合加法（基点为仿射）
     */
    private static BigInteger[] jacobianMultiply(BigInteger gx, BigInteger gy, BigInteger k,
                                                  BigInteger a, BigInteger p, boolean aIsMinusThree) {
        BigInteger QX = BigInteger.ONE, QY = BigInteger.ONE, QZ = BigInteger.ZERO;

        int bitLength = k.bitLength();
        for (int i = bitLength - 1; i >= 0; i--) {
            BigInteger[] doubled = jacobianDouble(QX, QY, QZ, a, p, aIsMinusThree);
            QX = doubled[0]; QY = doubled[1]; QZ = doubled[2];

            if (k.testBit(i)) {
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, gx, gy, a, p, aIsMinusThree);
                QX = added[0]; QY = added[1]; QZ = added[2];
            }
        }
        return new BigInteger[]{QX, QY, QZ};
    }

    /**
     * 雅可比坐标倍点：2P
     * 当 a = p - 3 时使用优化公式：M = 3*(X - Z²)*(X + Z²)
     */
    private static BigInteger[] jacobianDouble(BigInteger X1, BigInteger Y1, BigInteger Z1,
                                                BigInteger a, BigInteger p, boolean aIsMinusThree) {
        if (Z1.signum() == 0) {
            return new BigInteger[]{BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger Z1sq = Z1.multiply(Z1).mod(p);
        BigInteger M;
        if (aIsMinusThree) {
            BigInteger t1 = X1.subtract(Z1sq).mod(p);
            BigInteger t2 = X1.add(Z1sq).mod(p);
            M = THREE.multiply(t1).multiply(t2).mod(p);
        } else {
            BigInteger Z1_4 = Z1sq.multiply(Z1sq).mod(p);
            M = THREE.multiply(X1.multiply(X1)).add(a.multiply(Z1_4)).mod(p);
        }

        BigInteger Y1sq = Y1.multiply(Y1).mod(p);
        BigInteger S = FOUR.multiply(X1).multiply(Y1sq).mod(p);
        BigInteger X3 = M.multiply(M).subtract(TWO.multiply(S)).mod(p);
        BigInteger Y1_4 = Y1sq.multiply(Y1sq).mod(p);
        BigInteger Y3 = M.multiply(S.subtract(X3)).subtract(EIGHT.multiply(Y1_4)).mod(p);
        BigInteger Z3 = TWO.multiply(Y1).multiply(Z1).mod(p);

        return new BigInteger[]{X3, Y3, Z3};
    }

    /**
     * 雅可比-仿射混合加法：P1(Jacobian) + P2(affine)
     * 由于基点 P2 始终是仿射坐标（Z=1），省去了 Z2 的运算
     */
    private static BigInteger[] jacobianAddMixed(BigInteger X1, BigInteger Y1, BigInteger Z1,
                                                  BigInteger x2, BigInteger y2,
                                                  BigInteger a, BigInteger p, boolean aIsMinusThree) {
        if (Z1.signum() == 0) {
            return new BigInteger[]{x2, y2, BigInteger.ONE};
        }

        BigInteger Z1sq = Z1.multiply(Z1).mod(p);
        BigInteger Z1cu = Z1sq.multiply(Z1).mod(p);
        BigInteger U2 = x2.multiply(Z1sq).mod(p);
        BigInteger S2 = y2.multiply(Z1cu).mod(p);

        BigInteger H = U2.subtract(X1).mod(p);
        BigInteger R = S2.subtract(Y1).mod(p);

        if (H.signum() == 0) {
            if (R.signum() == 0) {
                return jacobianDouble(X1, Y1, Z1, a, p, aIsMinusThree);
            }
            return new BigInteger[]{BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        }

        BigInteger H2 = H.multiply(H).mod(p);
        BigInteger H3 = H2.multiply(H).mod(p);
        BigInteger X1H2 = X1.multiply(H2).mod(p);

        BigInteger X3 = R.multiply(R).subtract(H3).subtract(TWO.multiply(X1H2)).mod(p);
        BigInteger Y3 = R.multiply(X1H2.subtract(X3)).subtract(Y1.multiply(H3)).mod(p);
        BigInteger Z3 = Z1.multiply(H).mod(p);

        return new BigInteger[]{X3, Y3, Z3};
    }

    // ==================== 工具方法 ====================

    /**
     * 将 byte[] 解释为无符号正整数
     * 处理各种长度（32字节无符号、33字节带符号前缀等）
     */
    private static BigInteger toBigIntUnsigned(byte[] b) {
        return new BigInteger(1, b);
    }

    /**
     * BigInteger 转固定长度 byte[]
     */
    public static byte[] toFixedBytes(BigInteger val, int len) {
        byte[] b = val.toByteArray();
        if (b.length == len) return b;
        byte[] result = new byte[len];
        if (b.length > len) {
            System.arraycopy(b, b.length - len, result, 0, len);
        } else {
            System.arraycopy(b, 0, result, len - b.length, b.length);
        }
        return result;
    }

    private static byte[][] toPointResult(BigInteger x, BigInteger y) {
        byte[][] result = new byte[2][32];
        result[0] = toFixedBytes(x, 32);
        result[1] = toFixedBytes(y, 32);
        return result;
    }

    private static BigInteger mod(BigInteger value, BigInteger mod) {
        return value.mod(mod);
    }
}
