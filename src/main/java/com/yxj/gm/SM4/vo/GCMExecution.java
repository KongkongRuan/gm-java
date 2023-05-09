package com.yxj.gm.SM4.vo;

public class GCMExecution {

    private byte[] cipherText;
    private byte[] tag;

    public GCMExecution() {
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public byte[] getTag() {
        return tag;
    }

    public GCMExecution(byte[] cipherText, byte[] tag) {
        this.cipherText = cipherText;
        this.tag = tag;
    }

}
