package com.yxj.gm.provider.key;

import javax.crypto.SecretKey;
import java.io.Serializable;

public class XaSecretKey implements SecretKey, Serializable {

    public XaSecretKey(){}
    public XaSecretKey(byte[] bytes){
        this.bytes=bytes;
    }
    private byte[] bytes;
    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return bytes;
    }
}
