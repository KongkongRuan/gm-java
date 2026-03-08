package com.yxj.gm.util;

import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.util.JNI.Nat256Native;
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
 * 1. 雅可比坐标点运算，整个标量乘法只需 1 次模逆
 * 2. SM2P256V1Field int[8] 域运算，无 BigInteger
 * 3. wNAF 标量分解使用 int[] 位操作，零 BigInteger 分配
 * 4. 预分配 scratch 缓冲区 + 引用交换，热路径零堆分配
 * 5. a = p - 3 优化的倍点公式
 * 6. 基点延迟预计算表 + 批量模逆仿射化
 */
public class SM2Util {
    static {
        Nat256Native.isAvailable();
    }

    public static final ECDomainParameters SM2_DOMAIN_PARAMS = SM2Util.toDomainParams(GMNamedCurves.getByName("sm2p256v1"));
    public static final AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    private static final int WNAF_WIDTH = 7;
    private static final int PRECOMP_SIZE = 1 << (WNAF_WIDTH - 2);

    private static final int FIELD_WNAF_WIDTH = 6;
    private static final int FIELD_PRECOMP_SIZE = 1 << (FIELD_WNAF_WIDTH - 2);

    private static volatile int[][][] basePointTableF;

    private static final ThreadLocal<SecureRandom> SECURE_RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    private static final byte[] ZA_A = DataConvertUtil.oneDel(SM2Constant.getA());
    private static final byte[] ZA_B = DataConvertUtil.oneDel(SM2Constant.getB());
    private static final byte[] ZA_XG = DataConvertUtil.oneDel(SM2Constant.getXG());
    private static final byte[] ZA_YG = DataConvertUtil.oneDel(SM2Constant.getYG());
    private static final byte[] DEFAULT_ID = "1234567812345678".getBytes();

    private static final long UINT = 0xFFFFFFFFL;

    // ==================== 公开接口（保持向后兼容） ====================

    public static byte[] generatePubKeyByPriKey(byte[] priKey) {
        byte[][] puba = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] pub = new byte[64];
        System.arraycopy(puba[0], 0, pub, 0, 32);
        System.arraycopy(puba[1], 0, pub, 32, 32);
        return pub;
    }

    private static final BigInteger N_MINUS_2 = SM2Constant.getBigN().subtract(TWO);

    public static byte[][] generatePubKey() {
        byte[][] result = new byte[3][32];
        SecureRandom secureRandom = SECURE_RANDOM.get();
        byte[] random = new byte[32];

        if (Nat256Native.isAvailable()) {
            byte[] out = new byte[96];
            while (true) {
                secureRandom.nextBytes(random);
                try {
                    if (Nat256Native.nativeKeyGen(random, out) == 1) {
                        System.arraycopy(out, 0, result[0], 0, 32);
                        System.arraycopy(out, 32, result[1], 0, 32);
                        System.arraycopy(out, 64, result[2], 0, 32);
                        return result;
                    }
                } catch (Throwable t) {
                    Nat256Native.markUnavailable();
                    break;
                }
            }
        }

        while (true) {
            secureRandom.nextBytes(random);
            BigInteger bigD = new BigInteger(1, random);
            if (bigD.compareTo(BigInteger.ONE) < 0 || bigD.compareTo(N_MINUS_2) > 0) {
                continue;
            }
            BigInteger[] pt = fixedBaseMultiplyJava(bigD);
            if (pt[0].signum() == 0 && pt[1].signum() == 0) continue;
            result[0] = toFixedBytes(bigD, 32);
            result[1] = toFixedBytes(pt[0], 32);
            result[2] = toFixedBytes(pt[1], 32);
            return result;
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

    public static byte[] initZa(byte[] IDa, byte[] pubKey) {
        if (IDa == null) {
            IDa = DEFAULT_ID;
        }
        short ENTLa = (short) (IDa.length * 8);
        SM3Digest digest = new SM3Digest();
        digest.update(new byte[]{(byte) (ENTLa >>> 8), (byte) ENTLa});
        digest.update(IDa);
        digest.update(ZA_A);
        digest.update(ZA_B);
        digest.update(ZA_XG);
        digest.update(ZA_YG);
        digest.update(pubKey, 0, 32);
        digest.update(pubKey, 32, 32);
        return digest.doFinal();
    }

    public static ECDomainParameters toDomainParams(X9ECParameters x9ECParameters) {
        return new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
    }

    // ==================== 核心点运算（雅可比坐标） ====================

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

    // ==================== 优化标量乘法（零分配热路径） ====================

    /**
     * 基点标量乘法 [k]G，wNAF(w=7) + 预计算表 + 引用交换
     * 优先使用 native 实现（单次 JNI 调用完成整个 wNAF 循环）
     */
    public static BigInteger[] fixedBaseMultiply(BigInteger k) {
        if (Nat256Native.isAvailable()) {
            try {
                int[] kArr = SM2P256V1Field.fromBigInteger(k);
                int[] outXY = new int[16];
                Nat256Native.nativeCombFixedBaseMul(kArr, outXY);
                int[] rx = new int[8], ry = new int[8];
                System.arraycopy(outXY, 0, rx, 0, 8);
                System.arraycopy(outXY, 8, ry, 0, 8);
                return new BigInteger[]{SM2P256V1Field.toBigInteger(rx), SM2P256V1Field.toBigInteger(ry)};
            } catch (Throwable t) {
                Nat256Native.markUnavailable();
            }
        }
        return fixedBaseMultiplyJava(k);
    }

    private static BigInteger[] fixedBaseMultiplyJava(BigInteger k) {
        int[][][] table = getBasePointTableF();
        int[] wnaf = toWNAF(k, WNAF_WIDTH);

        int[] ext = new int[16];
        int[][] s = allocScratch();

        int[] AX = new int[8], AY = new int[8], AZ = new int[8];
        int[] BX = new int[8], BY = new int[8], BZ = new int[8];
        int[] py = new int[8];
        int[] tmp;

        for (int i = wnaf.length - 1; i >= 0; i--) {
            jacobianDoubleF(AX, AY, AZ, BX, BY, BZ, s, ext);
            tmp = AX; AX = BX; BX = tmp;
            tmp = AY; AY = BY; BY = tmp;
            tmp = AZ; AZ = BZ; BZ = tmp;

            if (wnaf[i] != 0) {
                int idx = (Math.abs(wnaf[i]) - 1) >> 1;
                int[] px = table[idx][0];
                if (wnaf[i] > 0) {
                    System.arraycopy(table[idx][1], 0, py, 0, 8);
                } else {
                    SM2P256V1Field.neg(table[idx][1], py);
                }
                jacobianAddMixedF(AX, AY, AZ, px, py, BX, BY, BZ, s, ext);
                tmp = AX; AX = BX; BX = tmp;
                tmp = AY; AY = BY; BY = tmp;
                tmp = AZ; AZ = BZ; BZ = tmp;
            }
        }
        return jacobianToAffine(AX, AY, AZ, ext);
    }

    /**
     * SM2 曲线任意点标量乘法 [k]P，wNAF(w=5) + 即时预计算 + 引用交换
     * 优先使用 native 实现
     */
    public static BigInteger[] fieldMultiply(BigInteger gx, BigInteger gy, BigInteger k) {
        if (Nat256Native.isAvailable()) {
            try {
                int[] pxArr = SM2P256V1Field.fromBigInteger(gx);
                int[] pyArr = SM2P256V1Field.fromBigInteger(gy);
                int[] kArr = SM2P256V1Field.fromBigInteger(k);
                int[] outXY = new int[16];
                Nat256Native.nativeFieldMul(pxArr, pyArr, kArr, outXY);
                int[] rx = new int[8], ry = new int[8];
                System.arraycopy(outXY, 0, rx, 0, 8);
                System.arraycopy(outXY, 8, ry, 0, 8);
                return new BigInteger[]{SM2P256V1Field.toBigInteger(rx), SM2P256V1Field.toBigInteger(ry)};
            } catch (Throwable t) {
                Nat256Native.markUnavailable();
            }
        }
        return fieldMultiplyJava(gx, gy, k);
    }

    private static BigInteger[] fieldMultiplyJava(BigInteger gx, BigInteger gy, BigInteger k) {
        int[] ext = new int[16];
        int[][] s = allocScratch();

        int[] Gx = SM2P256V1Field.fromBigInteger(gx);
        int[] Gy = SM2P256V1Field.fromBigInteger(gy);
        int[][][] table = buildPointTableF(Gx, Gy, FIELD_PRECOMP_SIZE, s, ext);
        int[] wnaf = toWNAF(k, FIELD_WNAF_WIDTH);

        int[] AX = new int[8], AY = new int[8], AZ = new int[8];
        int[] BX = new int[8], BY = new int[8], BZ = new int[8];
        int[] py = new int[8];
        int[] tmp;

        for (int i = wnaf.length - 1; i >= 0; i--) {
            jacobianDoubleF(AX, AY, AZ, BX, BY, BZ, s, ext);
            tmp = AX; AX = BX; BX = tmp;
            tmp = AY; AY = BY; BY = tmp;
            tmp = AZ; AZ = BZ; BZ = tmp;

            if (wnaf[i] != 0) {
                int idx = (Math.abs(wnaf[i]) - 1) >> 1;
                int[] px = table[idx][0];
                if (wnaf[i] > 0) {
                    System.arraycopy(table[idx][1], 0, py, 0, 8);
                } else {
                    SM2P256V1Field.neg(table[idx][1], py);
                }
                jacobianAddMixedF(AX, AY, AZ, px, py, BX, BY, BZ, s, ext);
                tmp = AX; AX = BX; BX = tmp;
                tmp = AY; AY = BY; BY = tmp;
                tmp = AZ; AZ = BZ; BZ = tmp;
            }
        }
        return jacobianToAffine(AX, AY, AZ, ext);
    }

    /**
     * Shamir's Trick：[s]G + [t]P 单次遍历
     * 优先使用 native 实现
     */
    public static BigInteger[] shamirMultiply(BigInteger sVal, BigInteger px, BigInteger py, BigInteger t) {
        if (Nat256Native.isAvailable()) {
            try {
                int[] sArr = SM2P256V1Field.fromBigInteger(sVal);
                int[] pxArr = SM2P256V1Field.fromBigInteger(px);
                int[] pyArr = SM2P256V1Field.fromBigInteger(py);
                int[] tArr = SM2P256V1Field.fromBigInteger(t);
                int[] outXY = new int[16];
                Nat256Native.nativeShamirMul(sArr, pxArr, pyArr, tArr, outXY);
                int[] rx = new int[8], ry = new int[8];
                System.arraycopy(outXY, 0, rx, 0, 8);
                System.arraycopy(outXY, 8, ry, 0, 8);
                return new BigInteger[]{SM2P256V1Field.toBigInteger(rx), SM2P256V1Field.toBigInteger(ry)};
            } catch (Throwable t2) {
                Nat256Native.markUnavailable();
            }
        }
        return shamirMultiplyJava(sVal, px, py, t);
    }

    private static BigInteger[] shamirMultiplyJava(BigInteger sVal, BigInteger px, BigInteger py, BigInteger t) {
        int[] ext = new int[16];
        int[][] scratch = allocScratch();

        int[][][] gTable = getBasePointTableF();
        int[] wNafS = toWNAF(sVal, WNAF_WIDTH);

        int[] Px = SM2P256V1Field.fromBigInteger(px);
        int[] Py = SM2P256V1Field.fromBigInteger(py);
        int[][][] pTable = buildPointTableF(Px, Py, FIELD_PRECOMP_SIZE, scratch, ext);
        int[] wNafT = toWNAF(t, FIELD_WNAF_WIDTH);

        int maxLen = Math.max(wNafS.length, wNafT.length);
        int[] AX = new int[8], AY = new int[8], AZ = new int[8];
        int[] BX = new int[8], BY = new int[8], BZ = new int[8];
        int[] tmpY = new int[8];
        int[] tmp;

        for (int i = maxLen - 1; i >= 0; i--) {
            jacobianDoubleF(AX, AY, AZ, BX, BY, BZ, scratch, ext);
            tmp = AX; AX = BX; BX = tmp;
            tmp = AY; AY = BY; BY = tmp;
            tmp = AZ; AZ = BZ; BZ = tmp;

            int si = (i < wNafS.length) ? wNafS[i] : 0;
            int ti = (i < wNafT.length) ? wNafT[i] : 0;

            if (si != 0) {
                int idx = (Math.abs(si) - 1) >> 1;
                int[] gx = gTable[idx][0];
                if (si > 0) {
                    System.arraycopy(gTable[idx][1], 0, tmpY, 0, 8);
                } else {
                    SM2P256V1Field.neg(gTable[idx][1], tmpY);
                }
                jacobianAddMixedF(AX, AY, AZ, gx, tmpY, BX, BY, BZ, scratch, ext);
                tmp = AX; AX = BX; BX = tmp;
                tmp = AY; AY = BY; BY = tmp;
                tmp = AZ; AZ = BZ; BZ = tmp;
            }

            if (ti != 0) {
                int idx = (Math.abs(ti) - 1) >> 1;
                int[] ppx = pTable[idx][0];
                if (ti > 0) {
                    System.arraycopy(pTable[idx][1], 0, tmpY, 0, 8);
                } else {
                    SM2P256V1Field.neg(pTable[idx][1], tmpY);
                }
                jacobianAddMixedF(AX, AY, AZ, ppx, tmpY, BX, BY, BZ, scratch, ext);
                tmp = AX; AX = BX; BX = tmp;
                tmp = AY; AY = BY; BY = tmp;
                tmp = AZ; AZ = BZ; BZ = tmp;
            }
        }
        return jacobianToAffine(AX, AY, AZ, ext);
    }

    private static BigInteger[] jacobianToAffine(int[] X, int[] Y, int[] Z, int[] ext) {
        if (SM2P256V1Field.isZero(Z)) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        }
        int[] zi = new int[8];
        SM2P256V1Field.inv(Z, zi, ext);
        int[] zi2 = new int[8], zi3 = new int[8], rx = new int[8], ry = new int[8];
        SM2P256V1Field.sqr(zi, zi2, ext);
        SM2P256V1Field.mul(zi2, zi, zi3, ext);
        SM2P256V1Field.mul(X, zi2, rx, ext);
        SM2P256V1Field.mul(Y, zi3, ry, ext);
        return new BigInteger[]{SM2P256V1Field.toBigInteger(rx), SM2P256V1Field.toBigInteger(ry)};
    }

    // ==================== SM2 域雅可比坐标运算（共享 scratch） ====================

    private static int[][] allocScratch() {
        int[][] s = new int[6][];
        for (int i = 0; i < 6; i++) s[i] = new int[8];
        return s;
    }

    /**
     * 域雅可比倍点 2P（a = p - 3 优化, 使用共享 scratch, 零堆分配）
     */
    private static void jacobianDoubleF(int[] X1, int[] Y1, int[] Z1,
                                         int[] X3, int[] Y3, int[] Z3,
                                         int[][] s, int[] ext) {
        if (SM2P256V1Field.isZero(Z1)) {
            System.arraycopy(X1, 0, X3, 0, 8);
            System.arraycopy(Y1, 0, Y3, 0, 8);
            Arrays.fill(Z3, 0);
            return;
        }
        // s[0]=Z1sq→tmp, s[1]=t1→S, s[2]=t2→Y1_4, s[3]=M, s[4]=Y1sq
        SM2P256V1Field.sqr(Z1, s[0], ext);
        SM2P256V1Field.sub(X1, s[0], s[1]);
        SM2P256V1Field.add(X1, s[0], s[2]);
        SM2P256V1Field.mul(s[1], s[2], s[3], ext);
        SM2P256V1Field.thrice(s[3], s[3]);

        SM2P256V1Field.sqr(Y1, s[4], ext);
        SM2P256V1Field.mul(X1, s[4], s[0], ext);
        SM2P256V1Field.twice(s[0], s[0]);
        SM2P256V1Field.twice(s[0], s[0]);

        SM2P256V1Field.sqr(s[3], X3, ext);
        SM2P256V1Field.sub(X3, s[0], X3);
        SM2P256V1Field.sub(X3, s[0], X3);

        SM2P256V1Field.sqr(s[4], s[1], ext);
        SM2P256V1Field.twice(s[1], s[1]);
        SM2P256V1Field.twice(s[1], s[1]);
        SM2P256V1Field.twice(s[1], s[1]);

        SM2P256V1Field.sub(s[0], X3, s[2]);
        SM2P256V1Field.mul(s[3], s[2], Y3, ext);
        SM2P256V1Field.sub(Y3, s[1], Y3);

        SM2P256V1Field.mul(Y1, Z1, Z3, ext);
        SM2P256V1Field.twice(Z3, Z3);
    }

    /**
     * 域雅可比-仿射混合加法（共享 scratch, 零堆分配）
     */
    private static void jacobianAddMixedF(int[] X1, int[] Y1, int[] Z1,
                                           int[] x2, int[] y2,
                                           int[] X3, int[] Y3, int[] Z3,
                                           int[][] s, int[] ext) {
        if (SM2P256V1Field.isZero(Z1)) {
            System.arraycopy(x2, 0, X3, 0, 8);
            System.arraycopy(y2, 0, Y3, 0, 8);
            Z3[0] = 1; for (int i = 1; i < 8; i++) Z3[i] = 0;
            return;
        }
        // s[0]=Z1sq→X1H2→tmp, s[1]=Z1cu, s[2]=U2→H, s[3]=S2→R, s[4]=H2→tmp2, s[5]=H3
        SM2P256V1Field.sqr(Z1, s[0], ext);
        SM2P256V1Field.mul(s[0], Z1, s[1], ext);
        SM2P256V1Field.mul(x2, s[0], s[2], ext);
        SM2P256V1Field.mul(y2, s[1], s[3], ext);

        SM2P256V1Field.sub(s[2], X1, s[2]);
        SM2P256V1Field.sub(s[3], Y1, s[3]);

        if (SM2P256V1Field.isZero(s[2])) {
            if (SM2P256V1Field.isZero(s[3])) {
                jacobianDoubleF(X1, Y1, Z1, X3, Y3, Z3, s, ext);
                return;
            }
            Arrays.fill(X3, 0); Arrays.fill(Y3, 0); Arrays.fill(Z3, 0);
            return;
        }

        SM2P256V1Field.sqr(s[2], s[4], ext);
        SM2P256V1Field.mul(s[4], s[2], s[5], ext);
        SM2P256V1Field.mul(X1, s[4], s[0], ext);

        SM2P256V1Field.sqr(s[3], X3, ext);
        SM2P256V1Field.sub(X3, s[5], X3);
        SM2P256V1Field.sub(X3, s[0], X3);
        SM2P256V1Field.sub(X3, s[0], X3);

        SM2P256V1Field.sub(s[0], X3, s[4]);
        SM2P256V1Field.mul(s[3], s[4], Y3, ext);
        SM2P256V1Field.mul(Y1, s[5], s[0], ext);
        SM2P256V1Field.sub(Y3, s[0], Y3);

        SM2P256V1Field.mul(Z1, s[2], Z3, ext);
    }

    // ==================== wNAF（int[] 位操作，零 BigInteger 分配） ====================

    private static int[] toWNAF(BigInteger k, int w) {
        if (k.signum() == 0) return new int[0];

        int bits = k.bitLength();
        int[] wnaf = new int[bits + 1];
        int len = 0;
        int pow2w = 1 << w;
        int halfPow2w = 1 << (w - 1);
        int mask = pow2w - 1;

        byte[] kb = k.toByteArray();
        int words = (bits + 31) >> 5;
        int[] d = new int[words + 1];
        for (int i = kb.length - 1, bi = 0; i >= 0; i--, bi++) {
            d[bi >> 2] |= (kb[i] & 0xFF) << ((bi & 3) << 3);
        }
        int dLen = words + 1;
        while (dLen > 0 && d[dLen - 1] == 0) dLen--;

        while (dLen > 0) {
            if ((d[0] & 1) != 0) {
                int digit = d[0] & mask;
                if (digit >= halfPow2w) digit -= pow2w;
                wnaf[len] = digit;
                long val = (d[0] & UINT) - digit;
                d[0] = (int) val;
                long carry = val >>> 32;
                for (int j = 1; carry != 0 && j < dLen; j++) {
                    carry += (d[j] & UINT);
                    d[j] = (int) carry;
                    carry >>>= 32;
                }
            }
            for (int j = 0; j < dLen - 1; j++) {
                d[j] = (d[j] >>> 1) | (d[j + 1] << 31);
            }
            if (dLen > 0) {
                d[dLen - 1] >>>= 1;
                if (d[dLen - 1] == 0) dLen--;
            }
            len++;
        }
        return Arrays.copyOf(wnaf, len);
    }

    // ==================== 基点预计算表（延迟初始化） ====================

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
        int[] ext = new int[16];
        int[][] s = allocScratch();
        return buildPointTableF(gx, gy, PRECOMP_SIZE, s, ext);
    }

    /**
     * 构建 wNAF 预计算表 P, 3P, 5P, ..., (2*size-1)*P
     * 使用共享 scratch 和 ext, 批量模逆仿射化
     */
    private static int[][][] buildPointTableF(int[] gx, int[] gy, int size, int[][] s, int[] ext) {
        int[] dblX = new int[8], dblY = new int[8], dblZ = new int[8];
        int[] oneZ = {1, 0, 0, 0, 0, 0, 0, 0};
        jacobianDoubleF(gx, gy, oneZ, dblX, dblY, dblZ, s, ext);
        int[] zi = new int[8];
        SM2P256V1Field.inv(dblZ, zi, ext);
        int[] zi2 = new int[8], zi3 = new int[8];
        SM2P256V1Field.sqr(zi, zi2, ext);
        SM2P256V1Field.mul(zi2, zi, zi3, ext);
        int[] dAX = new int[8], dAY = new int[8];
        SM2P256V1Field.mul(dblX, zi2, dAX, ext);
        SM2P256V1Field.mul(dblY, zi3, dAY, ext);

        int[][] jacX = new int[size][8];
        int[][] jacY = new int[size][8];
        int[][] jacZ = new int[size][8];
        System.arraycopy(gx, 0, jacX[0], 0, 8);
        System.arraycopy(gy, 0, jacY[0], 0, 8);
        jacZ[0][0] = 1;

        for (int i = 1; i < size; i++) {
            jacobianAddMixedF(jacX[i-1], jacY[i-1], jacZ[i-1],
                    dAX, dAY, jacX[i], jacY[i], jacZ[i], s, ext);
        }

        return batchToAffineF(jacX, jacY, jacZ, ext);
    }

    private static int[][][] batchToAffineF(int[][] jX, int[][] jY, int[][] jZ, int[] ext) {
        int n = jX.length;

        int[][] cumZ = new int[n][8];
        System.arraycopy(jZ[0], 0, cumZ[0], 0, 8);
        for (int i = 1; i < n; i++) {
            SM2P256V1Field.mul(cumZ[i-1], jZ[i], cumZ[i], ext);
        }

        int[] invF = new int[8];
        SM2P256V1Field.inv(cumZ[n-1], invF, ext);

        int[][] zInvs = new int[n][8];
        int[] tmp = new int[8];
        for (int i = n - 1; i > 0; i--) {
            SM2P256V1Field.mul(cumZ[i-1], invF, zInvs[i], ext);
            SM2P256V1Field.mul(jZ[i], invF, tmp, ext);
            System.arraycopy(tmp, 0, invF, 0, 8);
        }
        System.arraycopy(invF, 0, zInvs[0], 0, 8);

        int[][][] result = new int[n][2][8];
        int[] zi2 = new int[8], zi3 = new int[8];
        for (int i = 0; i < n; i++) {
            SM2P256V1Field.sqr(zInvs[i], zi2, ext);
            SM2P256V1Field.mul(zi2, zInvs[i], zi3, ext);
            SM2P256V1Field.mul(jX[i], zi2, result[i][0], ext);
            SM2P256V1Field.mul(jY[i], zi3, result[i][1], ext);
        }
        return result;
    }

    // ==================== NAF (BigInteger 后备路径) ====================

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

    // ==================== BigInteger 版本（非 SM2 曲线后备路径） ====================

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

    private static BigInteger toBigIntUnsigned(byte[] b) {
        return new BigInteger(1, b);
    }

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
