package com.yxj.gm.SM4.dto;



public class AEADExecution {
    private byte[] cipherText;
    private byte[] tag;
    public AEADExecution(){};
    public AEADExecution(byte[] cipherText, byte[] tag){
        this.cipherText=cipherText;
        this.tag=tag;
    }

    public byte[] getCipherText() {
        return cipherText;
    }

    public void setCipherText(byte[] cipherText) {
        this.cipherText = cipherText;
    }

    public byte[] getTag() {
        return tag;
    }

    public void setTag(byte[] tag) {
        this.tag = tag;
    }
}
