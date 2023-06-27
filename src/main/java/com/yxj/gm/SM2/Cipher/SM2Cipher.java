package com.yxj.gm.SM2.Cipher;


import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2Cipher {

    public byte[] SM2CipherEncrypt(byte[] M,byte[] pubKey){
        byte[] Xb = new byte[32];
        byte[] Yb = new byte[32];
        System.arraycopy(pubKey,0,Xb,0,32);
        System.arraycopy(pubKey,32,Yb,0,32);

        byte[] k = new byte[32];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(k);
        byte[][] C1Point = SM2Util.MultiplePointOperation(SM2Constant.getXG(), SM2Constant.getYG(), k, SM2Constant.getA(), SM2Constant.getP());
        byte[] C1 = new byte[C1Point[0].length+C1Point[1].length+1];
        byte[] PC = new byte[]{(byte) 0x04};
        System.arraycopy(PC,0,C1,0,PC.length);
        System.arraycopy(C1Point[0],0,C1,PC.length,C1Point[0].length);
        System.arraycopy(C1Point[1],0,C1,PC.length+C1Point[0].length,C1Point[1].length);
        //S=H*PB 如果S是无穷远点就报错退出
        byte[][] bytes = SM2Util.MultiplePointOperation(Xb, Yb, k, SM2Constant.getA(), SM2Constant.getP());

        byte[] x2y2 = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2y2,0,bytes[0].length);
        System.arraycopy(bytes[1],0,x2y2,bytes[0].length,bytes[1].length);

        byte[] T = SM2_KDF(x2y2, M.length);
        byte[] C2 = DataConvertUtil.byteArrayXOR(M,T);
        byte[] x2My2 = new byte[bytes[0].length+M.length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2My2,0,bytes[0].length);
        System.arraycopy(M,0,x2My2,bytes[0].length,M.length);
        System.arraycopy(bytes[1],0,x2My2,bytes[0].length+M.length,bytes[1].length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(x2My2);
        byte[] C3= sm3Digest.doFinal();
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
        System.arraycopy(C1,0,PC,0,1);
        System.arraycopy(C1,1,C1x,0,32);
        System.arraycopy(C1,1+32,C1y,0,32);

        if(PC[0]!=4){
            throw new RuntimeException("无法解密压缩C1");
        }
        //验证C1x和C1y
        if(!SM2Util.checkPubKey(new byte[][]{C1x,C1y})){
            throw new RuntimeException("C1验证未通过");
        }
        //TODO 未作[h]*C1 校验无穷远点
        byte[][] bytes = SM2Util.MultiplePointOperation(DataConvertUtil.oneAdd(C1x), DataConvertUtil.oneAdd(C1y), priKey, SM2Constant.getA(), SM2Constant.getP());
        byte[] x2y2 = new byte[bytes[0].length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2y2,0,bytes[0].length);
        System.arraycopy(bytes[1],0,x2y2,bytes[0].length,bytes[1].length);
        byte[] T = SM2_KDF(x2y2, kLen);
        byte[] ming = DataConvertUtil.byteArrayXOR(C2,T);

        byte[] x2My2 = new byte[bytes[0].length+ming.length+bytes[1].length];
        System.arraycopy(bytes[0],0,x2My2,0,bytes[0].length);
        System.arraycopy(ming,0,x2My2,bytes[0].length,ming.length);
        System.arraycopy(bytes[1],0,x2My2,bytes[0].length+ming.length,bytes[1].length);
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(x2My2);
        byte[] u= sm3Digest.doFinal();
        if(new BigInteger(u).compareTo(new BigInteger(C3))!=0){
            throw new RuntimeException("C3验证未通过");
        }
        return ming;
    }


    private   byte[] SM2_KDF(byte[] Z,int kLen){
        int v = 32;
        double dn= (double) kLen / (double) v;
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
    private byte[] conn(byte[] k,byte[] han){
        if(k==null){
            return han;
        }
        byte[] temp = new byte[k.length+han.length];
        System.arraycopy(k,0,temp,0,k.length);
        System.arraycopy(han,0,temp,k.length,han.length);
        return temp;
    }
    private   byte[] paddConnHash(byte[] z,BigInteger bigCt){
        byte[] ct = bigCt.toByteArray();
        //Padding
        byte[] ctPadd = new byte[4];
        System.arraycopy(ct,0,ctPadd,ctPadd.length-ct.length,ct.length);
        //Connect
        byte[] connect = new byte[z.length+ctPadd.length];
        System.arraycopy(z,0,connect,0,z.length);
        System.arraycopy(ctPadd,0,connect,z.length,ctPadd.length);
        //Hash256
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(connect);
        return sm3Digest.doFinal();
    }


}
