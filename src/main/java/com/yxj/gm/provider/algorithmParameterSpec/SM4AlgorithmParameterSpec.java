package com.yxj.gm.provider.algorithmParameterSpec;

import java.security.spec.AlgorithmParameterSpec;

public class SM4AlgorithmParameterSpec implements AlgorithmParameterSpec {

    public SM4AlgorithmParameterSpec(){}
    public SM4AlgorithmParameterSpec(byte[] iv){this.iv=iv;}
    private byte[] iv;

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }
}
