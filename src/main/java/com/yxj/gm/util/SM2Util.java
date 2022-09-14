package com.yxj.gm.util;

import com.yxj.gm.constant.SM2Constant;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2Util {
    public static final ECDomainParameters SM2_DOMAIN_PARAMS = SM2Util.toDomainParams(GMNamedCurves.getByName("sm2p256v1"));


    public static final AlgorithmIdentifier sigAlgId = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.156.10197.1.501"));




    public static byte[][] generatePubKey(){
        byte[][] bytes;
        byte[][] result =new byte[3][32];
        SecureRandom secureRandom = new SecureRandom();
        byte[] random;
        while (true){
            random = new byte[32];
            secureRandom.nextBytes(random);
            random=DataConvertUtil.oneAdd(random);
            //判断D是否在1到N-2之间
            BigInteger bigD = new BigInteger(random);
            if(bigD.compareTo(new BigInteger("1"))<0){
                System.err.println("D小于1"+ Hex.toHexString(random));
                continue;
            }
            BigInteger bigN = new BigInteger(SM2Constant.getN());
            if(bigD.compareTo(bigN.subtract(new BigInteger("2"))) > 0){
                System.err.println("D大于N-2"+Hex.toHexString(random));
                continue;
            }
            //倍点运算
            bytes = MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), random, SM2Constant.getA(), SM2Constant.getP());
            if(SM2Util.checkPubKey(bytes)){
                random=DataConvertUtil.byteToN(random,32);
                result[0]=random;
                result[1]=bytes[0];
                result[2]=bytes[1];
                return result;
            }
            System.err.println("公钥验证失败："+Hex.toHexString(random));
        }
    }
    public static ECDomainParameters toDomainParams(X9ECParameters x9ECParameters) {
        return new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
    }
    /**
     * 二进制展开法倍点运算
     * 输人 :点 P,l比特的整数k=  ∈ (0,1)。
     * 输出:Q=[k]P。
     *   a) 置 Q=O;
     *   b) J从 l-1下 降到 0执 行 :
     *     b.1) Q=[2]Q;
     *     b.2) 若 kj=1 则 Q=Q+P;
     *   c) 输出 Q。
     * @param XG 基点X
     * @param YG 基点Y
     * @param k  k倍点
     * @param a  曲线参数a
     * @param p  有限域大小
     * @return 公钥坐标
     */
    public  static byte[][] MultiplePointOperation(byte[] XG, byte[] YG, byte[] k,byte[] a,byte[] p) {
        //第一个字节补0
        //Biginteger会转换成有符号数造成精度丢失
        k=DataConvertUtil.byteToN(k,32);
        k=DataConvertUtil.oneAdd(k);
        byte[] XQ = new byte[32];
        byte[] YQ = new byte[32];
        String s = new BigInteger(k).toString(2);
        char[] chars = s.toCharArray();
        for (char c : chars) {
            //Q=[2]Q 先计算Q+Q
            byte[][] Q1bytes = PointAdditionOperation(XQ, YQ, XQ, YQ, a, p);
            XQ=Q1bytes[0];
            YQ=Q1bytes[1];
            if (c == '1') {
                //Q=Q+P 如果二进制展开后等于1则加P
                byte[][] Q2bytes = PointAdditionOperation(XQ, YQ, XG, YG, a, p);
                XQ=Q2bytes[0];
                YQ=Q2bytes[1];
            }
        }
        XQ=DataConvertUtil.byteToN(XQ,32);
        YQ=DataConvertUtil.byteToN(YQ,32);

        byte[][] Q = new byte[2][32];
        Q[0]=XQ;
        Q[1]=YQ;
        return Q;
    }


    /**
     *仿射点计算两点相加
     * @param X1 X1
     * @param Y1 Y1
     * @param X2 X2
     * @param Y2 Y2
     * @param a 曲线参数a
     * @param p 有限域大小
     * @return 结果点坐标
     */
    public  static byte[][] PointAdditionOperation(byte[] X1, byte[] Y1, byte[] X2, byte[] Y2, byte[] a, byte[] p) {
        X1=DataConvertUtil.byteToN(X1,32);
        Y1=DataConvertUtil.byteToN(Y1,32);
        X2=DataConvertUtil.byteToN(X2,32);
        Y2=DataConvertUtil.byteToN(Y2,32);
        X1=DataConvertUtil.oneAdd(X1);
        Y1=DataConvertUtil.oneAdd(Y1);
        X2=DataConvertUtil.oneAdd(X2);
        Y2=DataConvertUtil.oneAdd(Y2);
        BigInteger bigIntegerX1 = new BigInteger(X1);
        BigInteger bigIntegerY1 = new BigInteger(Y1);
        BigInteger bigIntegerX2 = new BigInteger(X2);
        BigInteger bigIntegerY2 = new BigInteger(Y2);
        BigInteger bigIntegera = new BigInteger(a);
        BigInteger bigIntegerp = new BigInteger(p);
        BigInteger bigIntegerzero = new BigInteger("0");

        //判断是否是0，0
        if (bigIntegerX1.equals(bigIntegerzero) && bigIntegerY1.equals(bigIntegerzero)) {
            byte[][] bytes = new byte[2][33];
            bytes[0] = X2;
            bytes[1] = Y2;
            return bytes;
        }
        if (bigIntegerX2.equals(bigIntegerzero) && bigIntegerY2.equals(bigIntegerzero)) {
            byte[][] bytes = new byte[2][33];
            bytes[0] = X1;
            bytes[1] = Y1;
            return bytes;
        }

        BigInteger k;
        //计算k
        if (!bigIntegerX1.equals(bigIntegerX2)) {
            // 所有中间运算都要进行模运算
            BigInteger tk1 = bigIntegerY2.subtract(bigIntegerY1);
            tk1 = mod(tk1, bigIntegerp);
            BigInteger tk2 = bigIntegerX2.subtract(bigIntegerX1);
            tk2 = mod(tk2, bigIntegerp);
            /*
             * 群里面没有除法运算
             * 除以一个数相当于乘以这个数的逆元
             * 逆元使用扩展欧几里得算法计算
             */
            BigInteger tk3 = tk1.multiply(DataConvertUtil.ex_gcd_ny(tk2, bigIntegerp));
            k = mod(tk3, bigIntegerp);
            //TODO P2 != -P1
        } else  {
            // 所有中间运算都要进行模运算
            BigInteger tk4 = bigIntegerX1.multiply(bigIntegerX1);
            tk4 = mod(tk4, bigIntegerp);
            BigInteger tk5 = new BigInteger("3").multiply(tk4);
            tk5 = mod(tk5, bigIntegerp);
            BigInteger tk6 = tk5.add(bigIntegera);
            tk6 = mod(tk6, bigIntegerp);
            BigInteger tk7 = new BigInteger("2").multiply(bigIntegerY1);
            tk7 = mod(tk7, bigIntegerp);
            BigInteger tk8 = tk6.multiply(DataConvertUtil.ex_gcd_ny(tk7, bigIntegerp));
            k = mod(tk8, bigIntegerp);
        }

        BigInteger bigIntegerX3;
        BigInteger bigIntegerY3;
        // 所有中间运算都要进行模运算（计算X）
        BigInteger tx1 = k.multiply(k);
        tx1 = mod(tx1, bigIntegerp);
        BigInteger tx2 = tx1.subtract(bigIntegerX1);
        tx2 = mod(tx2, bigIntegerp);
        BigInteger tx3 = tx2.subtract(bigIntegerX2);
        bigIntegerX3 = mod(tx3, bigIntegerp);
        //所有中间运算都要进行模运算（计算Y）
        BigInteger ty1 = bigIntegerX1.subtract(bigIntegerX3);
        ty1 = mod(ty1, bigIntegerp);
        BigInteger ty2 = k.multiply(ty1);
        ty2 = mod(ty2, bigIntegerp);
        BigInteger ty3 = ty2.subtract(bigIntegerY1);
        bigIntegerY3 = mod(ty3, bigIntegerp);
        byte[][] bytes = new byte[2][32];
        byte[] X3 = bigIntegerX3.toByteArray();
        byte[] Y3 = bigIntegerY3.toByteArray();
        X3 = DataConvertUtil.byteToN(X3, 32);
        Y3 = DataConvertUtil.byteToN(Y3, 32);
        bytes[0] = X3;
        bytes[1] = Y3;
        return bytes;

    }


    public static boolean checkPubKey(byte[][] pubKey){
        byte[] txa=DataConvertUtil.oneAdd(pubKey[0]);
        byte[] tya=DataConvertUtil.oneAdd(pubKey[1]);
        BigInteger bigTxa = new BigInteger(txa);
        BigInteger bigTya = new BigInteger(tya);
        BigInteger tempP1 = new BigInteger(SM2Constant.getP()).subtract(new BigInteger("1"));
        if(bigTxa.compareTo(tempP1)>0||bigTya.compareTo(tempP1)>0){
//            System.err.println("XY大于P-1"+Hex.toHexString(random));
            return false;
        }
        BigInteger bigP = new BigInteger(SM2Constant.getP());
        BigInteger bigA = new BigInteger(SM2Constant.getA());
        BigInteger bigB = new BigInteger(SM2Constant.getB());
        BigInteger bigYp2 = bigTya.multiply(bigTya);
        bigYp2=bigYp2.mod(bigP);
        BigInteger bigXp2 = bigTxa.multiply(bigTxa);
        bigXp2=bigXp2.mod(bigP);
        BigInteger bigXp3 = bigXp2.multiply(bigTxa);
        bigXp3=bigXp3.mod(bigP);
        BigInteger bigAxP = bigA.multiply(bigTxa);
        bigAxP=bigAxP.mod(bigP);
        bigB=bigB.mod(bigP);
        BigInteger bigxp3_axp = bigXp3.add(bigAxP);
        bigxp3_axp=bigxp3_axp.mod(bigP);
        BigInteger bigxp3_axp_b = bigxp3_axp.add(bigB);
        bigxp3_axp_b=bigxp3_axp_b.mod(bigP);
        return bigYp2.compareTo(bigxp3_axp_b) == 0;
    }
    private  static BigInteger mod(BigInteger value,BigInteger mod){
        return value.mod(mod);
    }
}
