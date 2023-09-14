package com.yxj.gm;

import com.kms.jca.UseKey;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.asn1.ca.sm2.ASN1SM2Signature;
import com.yxj.gm.asn1.ca.util.ASN1Util;
import com.yxj.gm.util.SM2Util;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.KeyPair;
import java.util.Base64;


public class TestSM2 {
    public static void main1(String[] args) {

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

    public static void main2(String[] args) throws IOException {
        byte[] pubKey = Hex.decode("E543ABCEBA68AAD81F31FB92A81D84EEBB0A7A0737F73399515274F07D085BB951C7E1DE565BB992C69F195C24F8AFDABE74DEAF61942207ABF4CAB62F133B00");
//        byte[] msg = Hex.decode("80206ab8ff860ecdd73bdc236194a95279bb885f34406395caac075545282c053085");
//        byte[] signature = Hex.decode("880dc422466fefa738b6659731bc204984b108abdaf4efebe2dce339a523374d311a6bfddafea6b80fa671d3b6b79bba993dbe210a72763b08135396542cd6f8");
//        SM2Signature sm2Signature = new SM2Signature();
//        boolean verify = sm2Signature.verify(msg, null, signature, pubKey);
//        System.out.println(verify);
//
//
//        SM4Cipher sm4Cipher = new SM4Cipher(ModeEnum.CTR);
//        SecureRandom secureRandom = new SecureRandom();
//        UseKey useKey = new UseKey();
//        byte[] key = new byte[16];
//        byte[] testMsg = FileUtils.readFileToByteArray(new File("D:\\GMT正式标准\\GMT 0028-2014 密码模块安全技术要求.PDF"));
//        secureRandom.nextBytes(key);
//
//        long l = System.currentTimeMillis();
//        sm4Cipher.cipherEncrypt(key,testMsg,new byte[16]);
////        useKey.cipherEncrypt("SM4",new ZyxxSecretKey(key),testMsg);
//        System.out.println(System.currentTimeMillis()-l);
        /**
         * 公钥数据转换为pem格式
         */
        Base64.Encoder encoder = Base64.getEncoder();
        String pem = "-----BEGIN PUBLIC KEY-----\r"+encoder.encodeToString(pubKey)+"\r-----END PUBLIC KEY-----";
        System.out.println(pem);


        SM2Signature sm2Signature = new SM2Signature();
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        byte[] signature = sm2Signature.signature("123".getBytes(), null, keyPair.getPrivate().getEncoded());
        System.out.println(Hex.toHexString(signature));


    }

    public static void main3(String[] args) throws IOException {

        byte[] pubKey = Hex.decode("815cdb69ed648bb27deffca2ad8b1d42a44be9f4f26eaacd6b42e0c62c1de290fe7c84527af1e6a7bffed018a62aed9aa04bff01e6adb36c084c5b917efa34d1");
        System.out.println(pubKey.length);
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        System.arraycopy(pubKey,0,x,0,32);
        System.arraycopy(pubKey,32,y,0,32);

        boolean b = SM2Util.checkPubKey(new byte[][]{x, y});
        System.out.println(b);
        ASN1SM2Signature asn1SM2Signature1 = ASN1Util.SM2SignatureToASN1SM2Signature(pubKey);

        System.out.println(Hex.toHexString(asn1SM2Signature1.getEncoded()));

        byte[] sm2Signature = ASN1Util.asn1SignatureToSM2Signature(asn1SM2Signature1.getEncoded());
        System.out.println(Hex.toHexString(sm2Signature));
    }

    public static void main(String[] args) {
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        String msg = "xdyg";
        UseKey useKey = new UseKey();
        byte[] signature = useKey.signature(keyPair, msg.getBytes());
        SM2Signature sm2Signature   = new SM2Signature();
        signature[0]=0;
        boolean verify = sm2Signature.verify(msg.getBytes(), null, signature, keyPair.getPublic().getEncoded());
        System.out.println(verify);
    }
}
