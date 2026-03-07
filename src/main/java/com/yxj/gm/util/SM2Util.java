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

    private static final int WNAF_WIDTH = 6;
    private static final int PRECOMP_SIZE = 1 << (WNAF_WIDTH - 2); // 16 个预计算点

    /** 基点 G 的 wNAF 预计算表（延迟初始化），存储 [1]G, [3]G, [5]G, ..., [31]G 的仿射坐标 */
    private static volatile BigInteger[][] basePointTable;

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
     * 基点标量乘法 [k]G，使用 wNAF(w=6) + 延迟预计算表
     * 首次调用触发预计算（~1ms），后续调用直接复用缓存
     * 点加法次数从 NAF 的 ~85 降至 ~37（256位标量）
     * @return 仿射坐标 [x, y]
     */
    public static BigInteger[] fixedBaseMultiply(BigInteger k) {
        BigInteger bigP = SM2Constant.getBigP();
        BigInteger bigA = SM2Constant.getBigA();
        boolean aIsM3 = bigA.add(THREE).equals(bigP);

        BigInteger[][] table = getBasePointTable();
        int[] wnaf = toWNAF(k, WNAF_WIDTH);

        BigInteger QX = BigInteger.ONE, QY = BigInteger.ONE, QZ = BigInteger.ZERO;

        for (int i = wnaf.length - 1; i >= 0; i--) {
            BigInteger[] doubled = jacobianDouble(QX, QY, QZ, bigA, bigP, aIsM3);
            QX = doubled[0]; QY = doubled[1]; QZ = doubled[2];

            if (wnaf[i] != 0) {
                int idx = (Math.abs(wnaf[i]) - 1) >> 1;
                BigInteger px = table[idx][0];
                BigInteger py = (wnaf[i] > 0) ? table[idx][1] : bigP.subtract(table[idx][1]);
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, px, py, bigA, bigP, aIsM3);
                QX = added[0]; QY = added[1]; QZ = added[2];
            }
        }

        if (QZ.signum() == 0) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        }
        BigInteger zInv = QZ.modInverse(bigP);
        BigInteger zInv2 = zInv.multiply(zInv).mod(bigP);
        BigInteger zInv3 = zInv2.multiply(zInv).mod(bigP);
        return new BigInteger[]{QX.multiply(zInv2).mod(bigP), QY.multiply(zInv3).mod(bigP)};
    }

    /**
     * Shamir's Trick：单次遍历计算 [s]G + [t]P
     * G 分量使用 wNAF + 预计算表（~37 次加法），P 分量使用 NAF（~85 次加法）
     */
    public static BigInteger[] shamirMultiply(BigInteger s, BigInteger px, BigInteger py, BigInteger t) {
        BigInteger bigP = SM2Constant.getBigP();
        BigInteger bigA = SM2Constant.getBigA();
        boolean aIsM3 = bigA.add(THREE).equals(bigP);

        BigInteger[][] gTable = getBasePointTable();
        int[] wNafS = toWNAF(s, WNAF_WIDTH);
        int[] nafT = toNAF(t);
        BigInteger negPy = bigP.subtract(py);

        int maxLen = Math.max(wNafS.length, nafT.length);
        BigInteger QX = BigInteger.ONE, QY = BigInteger.ONE, QZ = BigInteger.ZERO;

        for (int i = maxLen - 1; i >= 0; i--) {
            BigInteger[] doubled = jacobianDouble(QX, QY, QZ, bigA, bigP, aIsM3);
            QX = doubled[0]; QY = doubled[1]; QZ = doubled[2];

            int si = (i < wNafS.length) ? wNafS[i] : 0;
            int ti = (i < nafT.length) ? nafT[i] : 0;

            if (si != 0) {
                int idx = (Math.abs(si) - 1) >> 1;
                BigInteger gx = gTable[idx][0];
                BigInteger gy = (si > 0) ? gTable[idx][1] : bigP.subtract(gTable[idx][1]);
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, gx, gy, bigA, bigP, aIsM3);
                QX = added[0]; QY = added[1]; QZ = added[2];
            }

            if (ti == 1) {
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, px, py, bigA, bigP, aIsM3);
                QX = added[0]; QY = added[1]; QZ = added[2];
            } else if (ti == -1) {
                BigInteger[] added = jacobianAddMixed(QX, QY, QZ, px, negPy, bigA, bigP, aIsM3);
                QX = added[0]; QY = added[1]; QZ = added[2];
            }
        }

        if (QZ.signum() == 0) {
            return new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO};
        }
        BigInteger zInv = QZ.modInverse(bigP);
        BigInteger zInv2 = zInv.multiply(zInv).mod(bigP);
        BigInteger zInv3 = zInv2.multiply(zInv).mod(bigP);
        return new BigInteger[]{QX.multiply(zInv2).mod(bigP), QY.multiply(zInv3).mod(bigP)};
    }

    // ==================== 雅可比坐标内部实现 ====================

    /**
     * 将标量 k 转换为 NAF（Non-Adjacent Form）表示
     * NAF 保证不存在连续的非零位，使点加法次数从 ~n/2 降至 ~n/3
     * 返回数组下标 0 为最低位
     */
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

    /**
     * wNAF 表示：窗口宽度 w 的非相邻形式
     * 非零位间隔至少 w 位，使点加法次数降至 ~256/(w+1)
     * 非零值范围：奇数 ±1, ±3, ..., ±(2^(w-1)-1)
     */
    private static int[] toWNAF(BigInteger k, int w) {
        int[] wnaf = new int[k.bitLength() + 1];
        int len = 0;
        int pow2w = 1 << w;
        int halfPow2w = 1 << (w - 1);
        int mask = pow2w - 1;

        while (k.signum() > 0) {
            if (k.testBit(0)) {
                int digit = k.intValue() & mask;
                if (digit >= halfPow2w) {
                    digit -= pow2w;
                }
                wnaf[len] = digit;
                k = k.subtract(BigInteger.valueOf(digit));
            }
            k = k.shiftRight(1);
            len++;
        }
        return Arrays.copyOf(wnaf, len);
    }

    // ==================== 基点预计算表（延迟初始化） ====================

    private static BigInteger[][] getBasePointTable() {
        BigInteger[][] table = basePointTable;
        if (table == null) {
            synchronized (SM2Util.class) {
                table = basePointTable;
                if (table == null) {
                    table = buildBasePointTable();
                    basePointTable = table;
                }
            }
        }
        return table;
    }

    /**
     * 构建基点 G 的 wNAF 预计算表：[1]G, [3]G, [5]G, ..., [2*PRECOMP_SIZE-1]G
     * 全部存储为仿射坐标，用于后续 mixed addition
     * 使用 Montgomery 批量求逆，整个过程仅需 2 次 modInverse
     */
    private static BigInteger[][] buildBasePointTable() {
        BigInteger gx = SM2Constant.getBigGX();
        BigInteger gy = SM2Constant.getBigGY();
        BigInteger bigP = SM2Constant.getBigP();
        BigInteger bigA = SM2Constant.getBigA();
        boolean aIsM3 = bigA.add(THREE).equals(bigP);

        // [2]G → 仿射坐标（1 次 modInverse）
        BigInteger[] dblJ = jacobianDouble(gx, gy, BigInteger.ONE, bigA, bigP, aIsM3);
        BigInteger zInv = dblJ[2].modInverse(bigP);
        BigInteger zi2 = zInv.multiply(zInv).mod(bigP);
        BigInteger zi3 = zi2.multiply(zInv).mod(bigP);
        BigInteger dblX = dblJ[0].multiply(zi2).mod(bigP);
        BigInteger dblY = dblJ[1].multiply(zi3).mod(bigP);

        // 递推计算奇数倍点（雅可比坐标），每步 mixed add [2]G（仿射）
        BigInteger[][] jacPts = new BigInteger[PRECOMP_SIZE][];
        jacPts[0] = new BigInteger[]{gx, gy, BigInteger.ONE};
        for (int i = 1; i < PRECOMP_SIZE; i++) {
            jacPts[i] = jacobianAddMixed(
                    jacPts[i - 1][0], jacPts[i - 1][1], jacPts[i - 1][2],
                    dblX, dblY, bigA, bigP, aIsM3);
        }

        // Montgomery 批量求逆 → 仿射坐标（1 次 modInverse）
        return batchToAffine(jacPts, bigP);
    }

    /**
     * Montgomery 批量求逆：将 n 个雅可比坐标点转为仿射坐标
     * 仅需 1 次 modInverse + O(n) 次乘法，替代 n 次独立 modInverse
     */
    private static BigInteger[][] batchToAffine(BigInteger[][] jacPts, BigInteger p) {
        int n = jacPts.length;

        BigInteger[] cumZ = new BigInteger[n];
        cumZ[0] = jacPts[0][2];
        for (int i = 1; i < n; i++) {
            cumZ[i] = cumZ[i - 1].multiply(jacPts[i][2]).mod(p);
        }

        BigInteger inv = cumZ[n - 1].modInverse(p);

        BigInteger[] zInvs = new BigInteger[n];
        for (int i = n - 1; i > 0; i--) {
            zInvs[i] = cumZ[i - 1].multiply(inv).mod(p);
            inv = jacPts[i][2].multiply(inv).mod(p);
        }
        zInvs[0] = inv;

        BigInteger[][] result = new BigInteger[n][2];
        for (int i = 0; i < n; i++) {
            BigInteger zi2 = zInvs[i].multiply(zInvs[i]).mod(p);
            BigInteger zi3 = zi2.multiply(zInvs[i]).mod(p);
            result[i] = new BigInteger[]{
                    jacPts[i][0].multiply(zi2).mod(p),
                    jacPts[i][1].multiply(zi3).mod(p)
            };
        }
        return result;
    }

    /**
     * 雅可比坐标标量乘法：Q = [k]P，P 为仿射坐标
     * 使用 NAF + left-to-right 遍历 + 混合加法
     * 用于非基点的任意点乘法
     */
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
