package com.yxj.gm;

import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;

import java.security.KeyPair;


public class TestSM2 {
    public static void main(String[] args) {

//  BigInteger bigInteger = new BigInteger(XG);
//  byte[] testbigbarr= new byte[]{(byte)0x15,(byte)0xCE,(byte)0x7B,(byte)0xC3,(byte)0x2D,(byte)0x29};
//  BigInteger bigInteger1 = new BigInteger(testbigbarr);
//  System.out.println(bigInteger1);
//  BigInteger multiply = bigInteger.multiply(bigInteger);
//  System.out.println(multiply);
//        BigInteger bigInteger = new BigInteger(new byte[]{(byte) 0x9});
//        String s = bigInteger.toString(2);
//        System.out.println(s);
//        char[] chars = s.toCharArray();
//        for (char c : chars) {
//            //Q=[2]Q
//
//            if (c == '1') {
//                //Q=Q+P
//                System.out.println("1");
//            }
//        }
//        BigInteger bigInteger1 = new BigInteger("-4");
//        BigInteger mod = bigInteger1.mod(new BigInteger("19"));
//        System.out.println(mod);
//
//        BigInteger bigInteger2 = new BigInteger(new byte[32]);
//        System.out.println(bigInteger2);

        //TODO---------------AddTest----------
//        byte[] P1X=new byte[]{(byte)0x00,(byte)0xA};
//        byte[] P1Y=new byte[]{(byte)0x00,(byte)0x2};
//
//        byte[] P2X=new byte[]{(byte)0x00,(byte)0x9};
//        byte[] P2Y=new byte[]{(byte)0x00,(byte)0x6};
//
//        byte[] a = new byte[]{(byte)0x00,(byte)0x1};
//        byte[] p = new byte[]{(byte)0x00,(byte)0x13};
//
//        byte[][] bytes = PointAdditionOperation(P1X, P1Y, P2X, P2Y, a, p);
//        BigInteger bigInteger3X = new BigInteger(bytes[0]);
//        BigInteger bigInteger3Y = new BigInteger(bytes[1]);
//        System.out.println("ADD------------------");
//        System.out.println(bigInteger3X);
//        System.out.println(bigInteger3Y);


        //TODO----------------------扩展欧几里得求逆元
//        BigInteger bigInteger = ex_gcd_ny(new BigInteger("-1"), new BigInteger("19"));
//        System.out.println(bigInteger);


//        byte[][] bytes1 = MultiplePointOperation(P1X, P1Y, new BigInteger("2").toByteArray(), a, p);
//        BigInteger bigInteger3X = new BigInteger(bytes1[0]);
//        BigInteger bigInteger3Y = new BigInteger(bytes1[1]);
//        System.out.println("Multiple------------------15-16");
//        System.out.println(bigInteger3X);
//        System.out.println(bigInteger3Y);
//
//        System.out.println("aaaaaaaaaaaaaaaaaaaaaaaaaaa");
//        BigInteger b10=new BigInteger("10");
//        BigInteger mod = b10.multiply(b10).mod(new BigInteger("19"));
//        System.out.println(mod);


//        //TODO---------------生成---------------------------------

//        System.out.println("-------------------p");
//        System.out.println(new BigInteger(p));
//        System.out.println("-------------------a");
//        System.out.println(new BigInteger(a));
//        System.out.println("-------------------b");
//        System.out.println(new BigInteger(b));
//        System.out.println("-------------------XG");
//        System.out.println(new BigInteger(XG));
//        System.out.println("-------------------YG");
//        System.out.println(new BigInteger(YG));
//        System.out.println("-------------------n");
//        System.out.println(new BigInteger(n));

        long l = System.currentTimeMillis();
        String msg = "test";

        for(int i=0;i<10;i++){
//            System.out.println(i);
            KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
//            byte[] sm2s = useKey.cipherEncryptKeyPair("com.yxj.gm.sm2.SM2", keyPair.getPublic(), msg.getBytes());
//            byte[] sm2s1 = useKey.cipherDecrypeKeyPair("com.yxj.gm.sm2.SM2", keyPair.getPrivate(), sm2s);

//            if(new String(sm2s1).equals(msg)){
//                System.out.println("##########################验证通过###########################################");
//            }else {
//                System.err.println("##########################验证失败###########################################");
//            }
        }
        System.out.println("JAVA:");
        long java = System.currentTimeMillis() - l;
        System.out.println(java);

//        long l2 = System.currentTimeMillis();

//        for(int i=0;i<1;i++){
//            System.out.println(i);
//            KeyPair keyPair = useKey.keyPairGenerator("com.yxj.gm.sm2.SM2");
//            byte[] sm2s = useKey.cipherEncryptKeyPair("com.yxj.gm.sm2.SM2", keyPair.getPublic(), msg.getBytes());
//            byte[] sm2s1 = useKey.cipherDecrypeKeyPair("com.yxj.gm.sm2.SM2", keyPair.getPrivate(), sm2s);

//            if(new String(sm2s1).equals(msg)){
//                System.out.println("##########################验证通过###########################################");
//            }else {
//                System.err.println("##########################验证失败###########################################");
//            }
//        }
//        System.out.println("组件化:");
//        long zjh = System.currentTimeMillis() - l2;
//        System.out.println(zjh);
//        System.out.println("倍率");
//        System.out.println(java/zjh);
//        System.out.println(Hex.toHexString(keyPair.getPublic().getEncoded()));
//        System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));


    }
}
