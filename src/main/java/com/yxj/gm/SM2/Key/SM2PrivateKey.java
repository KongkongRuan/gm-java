package com.yxj.gm.SM2.Key;

import java.security.PrivateKey;

public class SM2PrivateKey implements PrivateKey {
    private final byte[] encoded ;
    public SM2PrivateKey(byte[] encoded){
        this.encoded=encoded;
    }
    public String getAlgorithm() {
        return "SM2";
    }

    public String getFormat() {
        return null;
    }

    public byte[] getEncoded() {
        return encoded;
    }
}
