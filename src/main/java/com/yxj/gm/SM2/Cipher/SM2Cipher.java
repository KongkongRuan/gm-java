package com.yxj.gm.SM2.Cipher;


import com.kms.jca.UseKey;
import com.kms.provider.keyPair.ZyxxPrivateKey;
import com.kms.provider.keyPair.ZyxxPublicKey;
import com.yxj.gm.SM2.Key.SM2;
import com.yxj.gm.SM3.SM3;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.SQLOutput;

public class SM2Cipher {
    public static void main(String[] args) {
        UseKey useKey = new UseKey();

//        byte[] pubKey = new byte[64];
//        System.arraycopy(DataConvertUtil.oneDel(SM2Constant.getxB()),0,pubKey,0,32);
//        System.arraycopy(DataConvertUtil.oneDel(SM2Constant.getyB()),0,pubKey,32,32);
        // System.out.println("pubKey:"+Hex.toHexString(pubKey));
        // System.out.println("pubKeylen:"+pubKey.length);
        String msg = "encryption standard";
        System.out.println("msg HEX:");
        System.out.println(Hex.toHexString(msg.getBytes()));
        byte[] prikey = Hex.decode("07DF3A29105359F16BBF8EA753319F4ECC085F8A71BD473DAA05282309D10E71");
        byte[] pubkey = Hex.decode("08B1E2B7E03B3B522C3064EB211B00123ADB81102F12C5F547F7AA3F7C8BE5614904A2CFF9715B85237E8AE62C5DD55297719270E6EC20B3D80E2BC2BC7F2856");
        SM2Cipher sm2Cipher = new SM2Cipher();
//        byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), pubkey);
        byte[] mi = useKey.cipherEncryptKeyPair("SM2",new ZyxxPublicKey(pubkey),msg.getBytes());
//        mi = Hex.decode("A23927CFF6C13927D68D65ECAB086E2B255FC787ACB1D789EF3DF0B7AE8C034690A2A0C5D228CE239E9F8BD068500A1EE23168FE8C2B50F8AC0737D1A3EE4C3173482B6B6DCBFCC032D51A61A66C1256D061334C01A656498676CF3F391232D7ADD9BE1DB13CD57A620CF53BD18275D1C823DD");
        System.out.println("组件化加密密文：");
        System.out.println(Hex.toHexString(mi));
        System.out.println(Hex.toHexString(mi).length());
        byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, prikey);
        System.out.println(Hex.toHexString(ming));
        System.out.println(new String(ming));
        byte[] ming_cs = useKey.cipherDecrypeKeyPair("SM2", new ZyxxPrivateKey(prikey), mi);
        System.out.println(Hex.toHexString(ming_cs));
        System.out.println(new String(ming_cs));

    }
    public byte[] SM2CipherEncrypt(byte[] M,byte[] pubKey){
        // System.out.println("M:"+Hex.toHexString(M));
        byte[] Xb = new byte[32];
        byte[] Yb = new byte[32];
        System.arraycopy(pubKey,0,Xb,0,32);
        System.arraycopy(pubKey,32,Yb,0,32);

        byte[] k = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(k);
//        byte[] k = SM2Constant.getK();
        byte[][] C1Point = SM2.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), k, SM2Constant.getA(), SM2Constant.getP());
        byte[] C1 = new byte[C1Point[0].length+C1Point[1].length+1];
        byte[] PC = new byte[]{(byte) 0x04};
        System.arraycopy(PC,0,C1,0,PC.length);
        System.arraycopy(C1Point[0],0,C1,PC.length,C1Point[0].length);
        System.arraycopy(C1Point[1],0,C1,PC.length+C1Point[0].length,C1Point[1].length);
        // System.out.println("C1:"+Hex.toHexString(C1));
        //S=H*PB 如果S是无穷远点就报错退出
//        byte[][] check = SM2.MultiplePointOperation(Xb, Yb, h, SM2Constant.getA(), SM2Constant.getP());

        byte[][] bytes = SM2.MultiplePointOperation(Xb, Yb, k, SM2Constant.getA(), SM2Constant.getP());

        byte[] x2y2 = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2y2,0,bytes[0].length);
        System.arraycopy(bytes[1],0,x2y2,bytes[0].length,bytes[1].length);

//        Short Klen  = (short) (M.length*8);
//        byte[] KlenBytes = DataConvertUtil.shortToBytes(new short[]{Klen});
        // System.out.println("x2y2:"+Hex.toHexString(x2y2));
        // System.out.println("M.length:"+M.length);
        byte[] T = SM2_KDF(x2y2, M.length);
        // System.out.println("T:"+Hex.toHexString(T));
        byte[] C2 = DataConvertUtil.byteArrayXOR(M,T);
        // System.out.println("C2:"+Hex.toHexString(C2));
        byte[] x2My2 = new byte[bytes[0].length+M.length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2My2,0,bytes[0].length);
        System.arraycopy(M,0,x2My2,bytes[0].length,M.length);
        System.arraycopy(bytes[1],0,x2My2,bytes[0].length+M.length,bytes[1].length);
        SM3 sm3 = new SM3();
        sm3.update(x2My2);
        byte[] C3=sm3.doFinal();
        // System.out.println("C3:"+Hex.toHexString(C3));
        byte[] MI = new byte[C1.length+C2.length+C3.length];
        System.arraycopy(C1,0,MI,0,C1.length);
        System.arraycopy(C3,0,MI,C1.length,C3.length);
        System.arraycopy(C2,0,MI,C1.length+C3.length,C2.length);
        return MI;
    }
    public byte[] SM2CipherDecrypt(byte[] M,byte[] priKey){
        byte[] C1 = new  byte[65];
        byte[] C3 = new  byte[32];
        int kLen = M.length-65-32;
        byte[] C2 = new  byte[kLen];
        byte[] PC = new byte[1];
        byte[] C1x = new byte[32];
        byte[] C1y = new byte[32];
        System.arraycopy(M,0,C1,0,65);
        System.arraycopy(M,65,C3,0,32);
        System.arraycopy(M,65+32,C2,0,kLen);
        // System.out.println(Hex.toHexString(C1));
        // System.out.println(Hex.toHexString(C2));
        // System.out.println(Hex.toHexString(C3));
        System.arraycopy(C1,0,PC,0,1);
        System.arraycopy(C1,1,C1x,0,32);
        System.arraycopy(C1,1+32,C1y,0,32);

        // System.out.println(Hex.toHexString(PC));
        // System.out.println(Hex.toHexString(C1x));
        // System.out.println(Hex.toHexString(C1y));
        if(PC[0]!=4){
            throw new RuntimeException("无法解密压缩C1");
        }
        //验证C1x和C1y
        if(!SM2.checkPubKey(new byte[][]{C1x,C1y})){
            throw new RuntimeException("C1验证未通过");
        }
        //TODO 未作[h]*C1 校验无穷远点
        byte[][] bytes = SM2.MultiplePointOperation(DataConvertUtil.oneAdd(C1x), DataConvertUtil.oneAdd(C1y), priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] x2y2 = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2y2,0,bytes[0].length);
        System.arraycopy(bytes[1],0,x2y2,bytes[0].length,bytes[1].length);
        byte[] T = SM2_KDF(x2y2, kLen);
        byte[] ming = DataConvertUtil.byteArrayXOR(C2,T);

        byte[] x2My2 = new byte[bytes[0].length+ming.length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2My2,0,bytes[0].length);
        System.arraycopy(ming,0,x2My2,bytes[0].length,ming.length);
        System.arraycopy(bytes[1],0,x2My2,bytes[0].length+ming.length,bytes[1].length);
        SM3 sm3 = new SM3();
        sm3.update(x2My2);
        byte[] u=sm3.doFinal();
        if(new BigInteger(u).compareTo(new BigInteger(C3))!=0){
            throw new RuntimeException("C3验证未通过");
        }
        return ming;
    }


    public  byte[] SM2_KDF(byte[] Z,int kLen){
        int v = 32;
        double dkLen = kLen;
        double dV = v;
        double dn=dkLen/dV;
        int n = (int)Math.ceil(dn);
        int downN = kLen/v;
        int m = kLen%v;
//        byte[] ct = new byte[]{(byte) 0x00,(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01};
        BigInteger ct = new BigInteger("1");
        byte[][] HA = new byte[n+1][32];
        for (int i = 1; i <= n; i++) {
            HA[i]= paddConnHash(Z,ct);
            ct =ct.add(new BigInteger("1"));
        }
        byte[] HAt ;
        if(m==0){
            HAt=HA[n];
        }else {
            int choseLen = kLen-(v*downN);
            HAt=new byte[choseLen];
            System.arraycopy(HA[n],0,HAt,0,choseLen);
        }
        byte[] K =null ;
        for (int i = 1; i <= n; i++) {
            if(i==n){
                K=conn(K,HAt);
            }else {
                K=conn(K,HA[i]);
            }
        }
        return K;
    }
    public byte[] conn(byte[] k,byte[] han){
        if(k==null){
            return han;
        }
        byte[] temp = new byte[k.length+han.length];
        System.arraycopy(k,0,temp,0,k.length);
        System.arraycopy(han,0,temp,k.length,han.length);
        return temp;
    }
    public  byte[] paddConnHash(byte[] z,BigInteger bigCt){
        byte[] ct = bigCt.toByteArray();
        //Padding
        byte[] ctPadd = new byte[4];
        System.arraycopy(ct,0,ctPadd,ctPadd.length-ct.length,ct.length);
        //Connect
        byte[] connect = new byte[z.length+ctPadd.length];
        System.arraycopy(z,0,connect,0,z.length);
        System.arraycopy(ctPadd,0,connect,z.length,ctPadd.length);
        //Hash256
        SM3 sm3 = new SM3();
        sm3.update(connect);
        byte[] bytes = sm3.doFinal();
        return bytes;
    }


}
