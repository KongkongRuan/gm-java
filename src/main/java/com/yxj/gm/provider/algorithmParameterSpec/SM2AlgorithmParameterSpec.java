package com.yxj.gm.provider.algorithmParameterSpec;

import java.security.spec.AlgorithmParameterSpec;

public class SM2AlgorithmParameterSpec implements AlgorithmParameterSpec {

    public SM2AlgorithmParameterSpec(){}
    public SM2AlgorithmParameterSpec(byte[] id){this.id=id;}
    private byte[] id;

    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }
}
