package com.yxj.gm.cert;

import org.bouncycastle.util.encoders.Hex;

public class CertParseVo {
    //版本
    private String version;
    //序列号
    private byte[] serial;
    //签名算法
    private String signature;
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
    //证书签发机构签发该证书所使用的密码算法的标识符
    private String signatureAlgorithm;
    //签名值
    private  byte[] signatureValue;
    //SHA1 指纹
    private byte[] SHA1Thumbprint;


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

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }

    public byte[] getSHA1Thumbprint() {
        return SHA1Thumbprint;
    }

    public void setSHA1Thumbprint(byte[] SHA1Thumbprint) {
        this.SHA1Thumbprint = SHA1Thumbprint;
    }


    @Override
    public String toString() {
        return "CertParseVo{" +
                "version='" + version + '\'' +
                ", serial=" + Hex.toHexString(serial) +
                ", signature='" + signature + '\'' +
                ", issuerSubject='" + issuerSubject + '\'' +
                ", startTime='" + startTime + '\'' +
                ", endTime='" + endTime + '\'' +
                ", ownerSubject='" + ownerSubject + '\'' +
                ", isCa=" + isCa +
                ", sigMaxLength=" + sigMaxLength +
                ", keyUsage='" + keyUsage + '\'' +
                ", publicKeyInfo='" + publicKeyInfo + '\'' +
                ", pubKey=" + Hex.toHexString(pubKey) +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", signatureValue=" + Hex.toHexString(signatureValue) +
                ", SHA1Thumbprint=" + Hex.toHexString(SHA1Thumbprint) +
                ", tbsCert=" + Hex.toHexString(tbsCert) +
                '}';
    }
}
