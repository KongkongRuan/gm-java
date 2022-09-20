package com.yxj.gm.cert;

import java.util.Arrays;

public class CertParseVo {
    //版本
    private String version;
    //序列号
    private byte[] serial;
    //签名算法
    private String signatureAlgorithm;
    //颁发者信息
    private  String issuerSubject;
    //有效期开始时间
    private  String startTime;
    //有效期结束时间
    private   String endTime;
    //使用者信息
    private  String ownerSubject;
    //是否为CA证书
    private  boolean isCa;
    //最大签发长度
    private  int sigMaxLength;
    //密钥用途
    private  String keyUsage;
    //签名数据
    private  byte[] tbsCert;
    //公钥
    private  byte[] pubKey;
    //公钥参数
    private String publicKeyInfo;
    //签名值
    private  byte[] signature;


    public String getVersion() {
        return version;
    }

    public String getPublicKeyInfo() {
        return publicKeyInfo;
    }

    public void setPublicKeyInfo(String publicKeyInfo) {
        this.publicKeyInfo = publicKeyInfo;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public byte[] getSerial() {
        return serial;
    }

    public void setSerial(byte[] serial) {
        this.serial = serial;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getIssuerSubject() {
        return issuerSubject;
    }

    public void setIssuerSubject(String issuerSubject) {
        this.issuerSubject = issuerSubject;
    }

    public String getStartTime() {
        return startTime;
    }

    public void setStartTime(String startTime) {
        this.startTime = startTime;
    }

    public String getEndTime() {
        return endTime;
    }

    public void setEndTime(String endTime) {
        this.endTime = endTime;
    }

    public String getOwnerSubject() {
        return ownerSubject;
    }

    public void setOwnerSubject(String ownerSubject) {
        this.ownerSubject = ownerSubject;
    }

    public boolean isCa() {
        return isCa;
    }

    public void setIsCa(boolean ca) {
        isCa = ca;
    }

    public int getSigMaxLength() {
        return sigMaxLength;
    }

    public void setSigMaxLength(int sigMaxLength) {
        this.sigMaxLength = sigMaxLength;
    }

    public String getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(String keyUsage) {
        this.keyUsage = keyUsage;
    }

    public byte[] getTbsCert() {
        return tbsCert;
    }

    public void setTbsCert(byte[] tbsCert) {
        this.tbsCert = tbsCert;
    }

    public byte[] getPubKey() {
        return pubKey;
    }

    public void setPubKey(byte[] pubKey) {
        this.pubKey = pubKey;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    @Override
    public String toString() {
        return "CertParseVo{" +
                "version='" + version + '\'' +
                ", serial=" + Arrays.toString(serial) +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", issuerSubject='" + issuerSubject + '\'' +
                ", startTime='" + startTime + '\'' +
                ", endTime='" + endTime + '\'' +
                ", ownerSubject='" + ownerSubject + '\'' +
                ", isCa=" + isCa +
                ", sigMaxLength=" + sigMaxLength +
                ", keyUsage='" + keyUsage + '\'' +
                ", tbsCert=" + Arrays.toString(tbsCert) +
                ", pubKey=" + Arrays.toString(pubKey) +
                ", publicKeyInfo='" + publicKeyInfo + '\'' +
                ", signature=" + Arrays.toString(signature) +
                '}';
    }
}
