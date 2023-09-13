package com.yxj.gm.SM2.KeyExchange;

import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.constant.SM2Constant;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;

public class KeyExchange {
    public static void main(String[] args) {
        KeyPair keyPairA = SM2KeyPairGenerate.generateSM2KeyPair();
        KeyPair keyPairB = SM2KeyPairGenerate.generateSM2KeyPair();

        byte[] PAX = new byte[32];
        byte[] PAY = new byte[32];
        System.arraycopy(keyPairA.getPublic().getEncoded(),0,PAX,0,32);
        System.arraycopy(keyPairA.getPublic().getEncoded(),32,PAY,0,32);

        byte[] PBX = new byte[32];
        byte[] PBY = new byte[32];
        System.arraycopy(keyPairB.getPublic().getEncoded(),0,PBX,0,32);
        System.arraycopy(keyPairB.getPublic().getEncoded(),32,PBY,0,32);


        byte[][] A = SM2Util.MultiplePointOperation(PBX, PBY, keyPairA.getPrivate().getEncoded(), SM2Constant.getA(), SM2Constant.getP());
        byte[][] B = SM2Util.MultiplePointOperation(PAX, PAY, keyPairB.getPrivate().getEncoded(), SM2Constant.getA(), SM2Constant.getP());
        System.out.println("A1:"+ Hex.toHexString(A[0]));
        System.out.println("A2:"+ Hex.toHexString(A[1]));
        System.out.println("B1:"+ Hex.toHexString(B[0]));
        System.out.println("B2:"+ Hex.toHexString(B[1]));


    }
}
