package com.yxj.gm.SM2.Key;

import java.security.PublicKey;

public class SM2PublicKey implements PublicKey {
    private final byte[] encoded;
    public SM2PublicKey(byte[] encoded){
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
