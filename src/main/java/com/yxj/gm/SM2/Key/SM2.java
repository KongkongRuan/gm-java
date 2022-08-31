package com.yxj.gm.SM2.Key;


import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.SM2Util;

import java.security.KeyPair;

public class SM2 {




    public static KeyPair generateSM2KeyPair(){

        byte[][] bytes =new byte[2][32];

        byte[][] keyPairBytes = SM2Util.generatePubKey();
        byte[] random = keyPairBytes[0];
        bytes[0]=keyPairBytes[1];
        bytes[1]=keyPairBytes[2];
        random= DataConvertUtil.byteToN(random,32);

        //计算后的点组成公钥
        byte[] pubkey = new byte[64];
        System.arraycopy(bytes[0],0,pubkey,0,32);
        System.arraycopy(bytes[1],0,pubkey,32,32);
        return new KeyPair(new SM2PublicKey(pubkey),new SM2PrivateKey(random));
    }






}
