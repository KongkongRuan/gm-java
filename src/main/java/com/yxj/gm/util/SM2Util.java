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
import java.util.Arrays;

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

    private static final int WNAF_WIDTH = 7;
    private static final int PRECOMP_SIZE = 1 << (WNAF_WIDTH - 2); // 32 个预计算点

    /** 基点 G 的 wNAF 预计算表（延迟初始化），存储仿射坐标 int[PRECOMP_SIZE][2][8] */
    private static volatile int[][][] basePointTableF;

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
        BigInteger bigK = toBigIntUnsigned(k);
        BigInteger gx = toBigIntUnsigned(XG);
        BigInteger gy = toBigIntUnsigned(YG);

        if (gx.equals(SM2Constant.getBigGX()) && gy.equals(SM2Constant.getBigGY())) {
            BigInteger[] pt = fixedBaseMultiply(bigK);
            return toPointResult(pt[0], pt[1]);
        }

        BigInteger bigP = toBigIntUnsigned(p);
        if (bigP.equals(SM2Constant.getBigP())) {
            BigInteger[] pt = fieldMultiply(gx, gy, bigK);
            return toPointResult(pt[0], pt[1]);
        }

        BigInteger bigA = toBigIntUnsigned(a);
        boolean aIsMinusThree = bigA.add(THREE).equals(bigP);
        BigInteger[] Q = jacobianMultiply(gx, gy, bigK, bigA, bigP, aIsMinusThree);
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

    /**
     * 基点标量乘法 [k]G，使用 wNAF(w=7) + 延迟预计算表 + SM2 域快速算术
     * @return 仿射坐标 [x, y]
     */
    public static BigInteger[] fixedBaseMultiply(BigInteger k) {
        int[][][] table = getBasePointTableF();
        int[] wnaf = toWNAF(k, WNAF_WIDTH);

        int[] QX = new int[8], QY = new int[8], QZ = new int[8];
        int[] tX = new int[8], tY = new int[8], tZ = new int[8];
        int[] py = new int[8];

        for (int i = wnaf.length - 1; i >= 0; i--) {
            jacobianDoubleF(QX, QY, QZ, tX, tY, tZ);
            System.arraycopy(tX, 0, QX, 0, 8);
            System.arraycopy(tY, 0, QY, 0, 8);
            System.arraycopy(tZ, 0, QZ, 0, 8);

            if (wnaf[i] != 0) {
                int idx = (Math.abs(wnaf[i]) - 1) >> 1;
                int[] px = table[idx][0];
                if (wnaf[i] > 0) {
                    System.arraycopy(table[idx][1], 0, py, 0, 8);
                } else {
                    SM2P256V1Field.neg(table[idx][1], py);
                }
                jacobianAddMixedF(QX, QY, QZ, px, py, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            }
        }
        return jacobianToAffine(QX, QY, QZ);
    }

    /**
     * SM2 曲线上任意点的标量乘法 [k]P，使用 NAF + SM2 域快速算术
     */
    private static BigInteger[] fieldMultiply(BigInteger gx, BigInteger gy, BigInteger k) {
        int[] naf = toNAF(k);
        int[] Gx = SM2P256V1Field.fromBigInteger(gx);
        int[] Gy = SM2P256V1Field.fromBigInteger(gy);
        int[] negGy = new int[8];
        SM2P256V1Field.neg(Gy, negGy);

        int[] QX = new int[8], QY = new int[8], QZ = new int[8];
        int[] tX = new int[8], tY = new int[8], tZ = new int[8];

        for (int i = naf.length - 1; i >= 0; i--) {
            jacobianDoubleF(QX, QY, QZ, tX, tY, tZ);
            System.arraycopy(tX, 0, QX, 0, 8);
            System.arraycopy(tY, 0, QY, 0, 8);
            System.arraycopy(tZ, 0, QZ, 0, 8);

            if (naf[i] == 1) {
                jacobianAddMixedF(QX, QY, QZ, Gx, Gy, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            } else if (naf[i] == -1) {
                jacobianAddMixedF(QX, QY, QZ, Gx, negGy, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            }
        }
        return jacobianToAffine(QX, QY, QZ);
    }

    /**
     * Shamir's Trick：单次遍历计算 [s]G + [t]P
     * G 分量使用 wNAF + 预计算表，P 分量使用 NAF，全部使用 SM2 域算术
     */
    public static BigInteger[] shamirMultiply(BigInteger s, BigInteger px, BigInteger py, BigInteger t) {
        int[][][] gTable = getBasePointTableF();
        int[] wNafS = toWNAF(s, WNAF_WIDTH);
        int[] nafT = toNAF(t);

        int[] Px = SM2P256V1Field.fromBigInteger(px);
        int[] Py = SM2P256V1Field.fromBigInteger(py);
        int[] negPy = new int[8];
        SM2P256V1Field.neg(Py, negPy);

        int maxLen = Math.max(wNafS.length, nafT.length);
        int[] QX = new int[8], QY = new int[8], QZ = new int[8];
        int[] tX = new int[8], tY = new int[8], tZ = new int[8];
        int[] gy = new int[8];

        for (int i = maxLen - 1; i >= 0; i--) {
            jacobianDoubleF(QX, QY, QZ, tX, tY, tZ);
            System.arraycopy(tX, 0, QX, 0, 8);
            System.arraycopy(tY, 0, QY, 0, 8);
            System.arraycopy(tZ, 0, QZ, 0, 8);

            int si = (i < wNafS.length) ? wNafS[i] : 0;
            int ti = (i < nafT.length) ? nafT[i] : 0;

            if (si != 0) {
                int idx = (Math.abs(si) - 1) >> 1;
                int[] gx = gTable[idx][0];
                if (si > 0) {
                    System.arraycopy(gTable[idx][1], 0, gy, 0, 8);
                } else {
                    SM2P256V1Field.neg(gTable[idx][1], gy);
                }
                jacobianAddMixedF(QX, QY, QZ, gx, gy, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            }

            if (ti == 1) {
                jacobianAddMixedF(QX, QY, QZ, Px, Py, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            } else if (ti == -1) {
                jacobianAddMixedF(QX, QY, QZ, Px, negPy, tX, tY, tZ);
                System.arraycopy(tX, 0, QX, 0, 8);
                System.arraycopy(tY, 0, QY, 0, 8);
                System.arraycopy(tZ, 0, QZ, 0, 8);
            }
        }
        return jacobianToAffine(QX, QY, QZ);
    }

    /** 雅可比坐标 → 仿射坐标（使用 BigInteger modInverse，每次标量乘法仅调用 1 次） */
    private static BigInteger[] jacobianToAffine(int[] X, int[] Y, int[] Z) {
        if (SM2P256V1Field.isZero(Z)) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        }
        BigInteger bigP = SM2Constant.getBigP();
        BigInteger zBI = SM2P256V1Field.toBigInteger(Z);
        BigInteger zInv = zBI.modInverse(bigP);
        int[] zi = SM2P256V1Field.fromBigInteger(zInv);
        int[] zi2 = new int[8], zi3 = new int[8], rx = new int[8], ry = new int[8];
        SM2P256V1Field.sqr(zi, zi2);
        SM2P256V1Field.mul(zi2, zi, zi3);
        SM2P256V1Field.mul(X, zi2, rx);
        SM2P256V1Field.mul(Y, zi3, ry);
        return new BigInteger[]{SM2P256V1Field.toBigInteger(rx), SM2P256V1Field.toBigInteger(ry)};
    }

    // ==================== SM2 域雅可比坐标运算 ====================

    /**
     * 域雅可比倍点 2P（SM2 曲线 a = p - 3 优化公式）
     * M = 3*(X - Z²)*(X + Z²)
     */
    private static void jacobianDoubleF(int[] X1, int[] Y1, int[] Z1,
                                         int[] X3, int[] Y3, int[] Z3) {
        if (SM2P256V1Field.isZero(Z1)) {
            System.arraycopy(X1, 0, X3, 0, 8);
            System.arraycopy(Y1, 0, Y3, 0, 8);
            Arrays.fill(Z3, 0);
            return;
        }
        int[] Z1sq = new int[8], t1 = new int[8], t2 = new int[8];
        int[] M = new int[8], Y1sq = new int[8], S = new int[8];
        int[] Y1_4 = new int[8], tmp = new int[8];

        SM2P256V1Field.sqr(Z1, Z1sq);
        SM2P256V1Field.sub(X1, Z1sq, t1);
        SM2P256V1Field.add(X1, Z1sq, t2);
        SM2P256V1Field.mul(t1, t2, M);
        SM2P256V1Field.thrice(M, M);

        SM2P256V1Field.sqr(Y1, Y1sq);
        SM2P256V1Field.mul(X1, Y1sq, S);
        SM2P256V1Field.twice(S, S);
        SM2P256V1Field.twice(S, S);

        SM2P256V1Field.sqr(M, X3);
        SM2P256V1Field.sub(X3, S, X3);
        SM2P256V1Field.sub(X3, S, X3);

        SM2P256V1Field.sqr(Y1sq, Y1_4);
        SM2P256V1Field.twice(Y1_4, Y1_4);
        SM2P256V1Field.twice(Y1_4, Y1_4);
        SM2P256V1Field.twice(Y1_4, Y1_4);

        SM2P256V1Field.sub(S, X3, tmp);
        SM2P256V1Field.mul(M, tmp, Y3);
        SM2P256V1Field.sub(Y3, Y1_4, Y3);

        SM2P256V1Field.mul(Y1, Z1, Z3);
        SM2P256V1Field.twice(Z3, Z3);
    }

    /**
     * 域雅可比-仿射混合加法 P1(Jacobian) + P2(affine)
     */
    private static void jacobianAddMixedF(int[] X1, int[] Y1, int[] Z1,
                                           int[] x2, int[] y2,
                                           int[] X3, int[] Y3, int[] Z3) {
        if (SM2P256V1Field.isZero(Z1)) {
            System.arraycopy(x2, 0, X3, 0, 8);
            System.arraycopy(y2, 0, Y3, 0, 8);
            X3[0] = x2[0]; Y3[0] = y2[0]; // already copied
            Z3[0] = 1; for (int i = 1; i < 8; i++) Z3[i] = 0;
            return;
        }
        int[] Z1sq = new int[8], Z1cu = new int[8];
        int[] U2 = new int[8], S2 = new int[8];
        int[] H = new int[8], R = new int[8];
        int[] H2 = new int[8], H3 = new int[8], X1H2 = new int[8], tmp = new int[8];

        SM2P256V1Field.sqr(Z1, Z1sq);
        SM2P256V1Field.mul(Z1sq, Z1, Z1cu);
        SM2P256V1Field.mul(x2, Z1sq, U2);
        SM2P256V1Field.mul(y2, Z1cu, S2);

        SM2P256V1Field.sub(U2, X1, H);
        SM2P256V1Field.sub(S2, Y1, R);

        if (SM2P256V1Field.isZero(H)) {
            if (SM2P256V1Field.isZero(R)) {
                jacobianDoubleF(X1, Y1, Z1, X3, Y3, Z3);
                return;
            }
            Arrays.fill(X3, 0); Arrays.fill(Y3, 0); Arrays.fill(Z3, 0);
            return;
        }

        SM2P256V1Field.sqr(H, H2);
        SM2P256V1Field.mul(H2, H, H3);
        SM2P256V1Field.mul(X1, H2, X1H2);

        SM2P256V1Field.sqr(R, X3);
        SM2P256V1Field.sub(X3, H3, X3);
        SM2P256V1Field.sub(X3, X1H2, X3);
        SM2P256V1Field.sub(X3, X1H2, X3);

        SM2P256V1Field.sub(X1H2, X3, tmp);
        SM2P256V1Field.mul(R, tmp, Y3);
        SM2P256V1Field.mul(Y1, H3, tmp);
        SM2P256V1Field.sub(Y3, tmp, Y3);

        SM2P256V1Field.mul(Z1, H, Z3);
    }

    // ==================== NAF / wNAF 表示 ====================

    private static int[] toNAF(BigInteger k) {
        int[] naf = new int[k.bitLength() + 1];
        int len = 0;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                if ((k.intValue() & 3) == 3) {
                    naf[len] = -1;
                    k = k.add(BigInteger.ONE);
                } else {
                    naf[len] = 1;
                    k = k.subtract(BigInteger.ONE);
                }
            }
            k = k.shiftRight(1);
            len++;
        }
        return Arrays.copyOf(naf, len);
    }

    private static int[] toWNAF(BigInteger k, int w) {
        int[] wnaf = new int[k.bitLength() + 1];
        int len = 0;
        int pow2w = 1 << w;
        int halfPow2w = 1 << (w - 1);
        int mask = pow2w - 1;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                int digit = k.intValue() & mask;
                if (digit >= halfPow2w) { digit -= pow2w; }
                wnaf[len] = digit;
                k = k.subtract(BigInteger.valueOf(digit));
            }
            k = k.shiftRight(1);
            len++;
        }
        return Arrays.copyOf(wnaf, len);
    }

    // ==================== 基点预计算表（延迟初始化，域元素版本） ====================

    private static int[][][] getBasePointTableF() {
        int[][][] table = basePointTableF;
        if (table == null) {
            synchronized (SM2Util.class) {
                table = basePointTableF;
                if (table == null) {
                    table = buildBasePointTableF();
                    basePointTableF = table;
                }
            }
        }
        return table;
    }

    private static int[][][] buildBasePointTableF() {
        int[] gx = SM2P256V1Field.fromBigInteger(SM2Constant.getBigGX());
        int[] gy = SM2P256V1Field.fromBigInteger(SM2Constant.getBigGY());

        int[] dblX = new int[8], dblY = new int[8], dblZ = new int[8];
        jacobianDoubleF(gx, gy, new int[]{1,0,0,0,0,0,0,0}, dblX, dblY, dblZ);
        BigInteger zInv = SM2P256V1Field.toBigInteger(dblZ).modInverse(SM2Constant.getBigP());
        int[] zi = SM2P256V1Field.fromBigInteger(zInv);
        int[] zi2 = new int[8], zi3 = new int[8];
        SM2P256V1Field.sqr(zi, zi2);
        SM2P256V1Field.mul(zi2, zi, zi3);
        int[] dAX = new int[8], dAY = new int[8];
        SM2P256V1Field.mul(dblX, zi2, dAX);
        SM2P256V1Field.mul(dblY, zi3, dAY);

        int[][] jacX = new int[PRECOMP_SIZE][8];
        int[][] jacY = new int[PRECOMP_SIZE][8];
        int[][] jacZ = new int[PRECOMP_SIZE][8];
        System.arraycopy(gx, 0, jacX[0], 0, 8);
        System.arraycopy(gy, 0, jacY[0], 0, 8);
        jacZ[0][0] = 1;

        for (int i = 1; i < PRECOMP_SIZE; i++) {
            jacobianAddMixedF(jacX[i-1], jacY[i-1], jacZ[i-1],
                    dAX, dAY, jacX[i], jacY[i], jacZ[i]);
        }

        return batchToAffineF(jacX, jacY, jacZ);
    }

    private static int[][][] batchToAffineF(int[][] jX, int[][] jY, int[][] jZ) {
        int n = jX.length;
        BigInteger bigP = SM2Constant.getBigP();

        int[][] cumZ = new int[n][8];
        System.arraycopy(jZ[0], 0, cumZ[0], 0, 8);
        for (int i = 1; i < n; i++) {
            SM2P256V1Field.mul(cumZ[i-1], jZ[i], cumZ[i]);
        }

        BigInteger inv = SM2P256V1Field.toBigInteger(cumZ[n-1]).modInverse(bigP);
        int[] invF = SM2P256V1Field.fromBigInteger(inv);

        int[][] zInvs = new int[n][8];
        int[] tmp = new int[8];
        for (int i = n - 1; i > 0; i--) {
            SM2P256V1Field.mul(cumZ[i-1], invF, zInvs[i]);
            SM2P256V1Field.mul(jZ[i], invF, tmp);
            System.arraycopy(tmp, 0, invF, 0, 8);
        }
        System.arraycopy(invF, 0, zInvs[0], 0, 8);

        int[][][] result = new int[n][2][8];
        int[] zi2 = new int[8], zi3 = new int[8];
        for (int i = 0; i < n; i++) {
            SM2P256V1Field.sqr(zInvs[i], zi2);
            SM2P256V1Field.mul(zi2, zInvs[i], zi3);
            SM2P256V1Field.mul(jX[i], zi2, result[i][0]);
            SM2P256V1Field.mul(jY[i], zi3, result[i][1]);
        }
        return result;
    }

    // ==================== BigInteger 版本（仅用于非 SM2 曲线的后备路径） ====================

    private static BigInteger[] jacobianMultiply(BigInteger gx, BigInteger gy, BigInteger k,
                                                  BigInteger a, BigInteger p, boolean aIsMinusThree) {
        if (k.signum() == 0) {
            return new BigInteger[]{BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        }
        int[] naf = toNAF(k);
        BigInteger negGy = p.subtract(gy);
        BigInteger QX = BigInteger.ONE, QY = BigInteger.ONE, QZ = BigInteger.ZERO;
        for (int i = naf.length - 1; i >= 0; i--) {
            BigInteger[] doubled = jacobianDouble(QX, QY, QZ, a, p, aIsMinusThree);
            QX = doubled[0]; QY = doubled[1]; QZ = doubled[2];
            if (naf[i] == 1) {
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, gx, gy, a, p, aIsMinusThree);
                QX = added[0]; QY = added[1]; QZ = added[2];
            } else if (naf[i] == -1) {
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, gx, negGy, a, p, aIsMinusThree);
                QX = added[0]; QY = added[1]; QZ = added[2];
            }
        }
        return new BigInteger[]{QX, QY, QZ};
    }

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

    private static BigInteger[] jacobianAddMixed(BigInteger X1, BigInteger Y1, BigInteger Z1,
                                                  BigInteger x2, BigInteger y2,
                                                  BigInteger a, BigInteger p, boolean aIsMinusThree) {
        if (Z1.signum() == 0) { return new BigInteger[]{x2, y2, BigInteger.ONE}; }
        BigInteger Z1sq = Z1.multiply(Z1).mod(p);
        BigInteger Z1cu = Z1sq.multiply(Z1).mod(p);
        BigInteger U2 = x2.multiply(Z1sq).mod(p);
        BigInteger S2 = y2.multiply(Z1cu).mod(p);
        BigInteger H = U2.subtract(X1).mod(p);
        BigInteger R = S2.subtract(Y1).mod(p);
        if (H.signum() == 0) {
            if (R.signum() == 0) { return jacobianDouble(X1, Y1, Z1, a, p, aIsMinusThree); }
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
