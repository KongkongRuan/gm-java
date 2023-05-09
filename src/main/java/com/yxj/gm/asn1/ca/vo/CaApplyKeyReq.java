package com.yxj.gm.asn1.ca.vo;

import com.yxj.gm.asn1.ca.enums.ApplyTypeEnum;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.Date;

public class CaApplyKeyReq {
    ApplyTypeEnum applyType;

    Integer version;

    String requestTime;

    Integer taskNo;
    //签名算法
    String signatureAlgorithm;

    //申请者公钥HASH的HASH算法
    String hashAlgorithm;

    //申请者的唯一名称
    String entName;

    //申请者公钥HASH
    byte[] entPubKeyHash;

    //申请者证书序列号
    BigInteger serialNumber;

    /**密钥请求*/
    //申请密钥类型
    String appKeyType;
    //申请密钥长度
    Integer appKeyLen;
    //返回的非对称算法类型
    String retAsymAlg;
    //返回的对称算法类型
    String retSymAlg;
    //返回的哈希算法类型
    String retHashAlg;
        /**AppUserInfo*/
        //终端用户加密证书序列号
        BigInteger userCertNo;
        //终端用户保护公钥类型
        String userPubKeyType;
        //终端用户保护公钥
        byte[] userPubKey;
        //密钥有效起始时间
        Date notBefore;
        //密钥截止时间
        Date notAfter;
        //用户姓名
        String userName;
        //地区代码
        String dsCode;
        //扩展信息
        String extendInfo;

        byte[] sigBody;

    @Override
    public String toString() {
        return "CaApplyKeyReq{" +
                "applyType="+applyType+
                ", version=" + version +
                ", requestTime='" + requestTime + '\'' +
                ", taskNo=" + taskNo +
                ", signatureAlgorithm='" + signatureAlgorithm + '\'' +
                ", hashAlgorithm='" + hashAlgorithm + '\'' +
                ", entName='" + entName + '\'' +
                ", entPubKeyHash=" + Hex.toHexString(entPubKeyHash==null?new byte[]{}:entPubKeyHash) +
                ", serialNumber=" + serialNumber +
                ", appKeyType='" + appKeyType + '\'' +
                ", appKeyLen=" + appKeyLen +
                ", retAsymAlg='" + retAsymAlg + '\'' +
                ", retSymAlg='" + retSymAlg + '\'' +
                ", retHashAlg='" + retHashAlg + '\'' +
                ", userCertNo=" + userCertNo +
                ", userPubKeyType='" + userPubKeyType + '\'' +
                ", userPubKey=" + Hex.toHexString(userPubKey==null?new byte[]{}:userPubKey) +
                ", notBefore='" + notBefore + '\'' +
                ", notAfter='" + notAfter + '\'' +
                ", userName='" + userName + '\'' +
                ", dsCode='" + dsCode + '\'' +
                ", extendInfo='" + extendInfo + '\'' +
                ", signatureValue=" + Hex.toHexString(signatureValue==null?new byte[]{}:signatureValue) +
                '}';
    }

    public byte[] getSigBody() {
        return sigBody;
    }

    public void setSigBody(byte[] sigBody) {
        this.sigBody = sigBody;
    }

    public ApplyTypeEnum getApplyType() {
        return applyType;
    }

    public void setApplyType(ApplyTypeEnum applyType) {
        this.applyType = applyType;
    }

    /**密钥恢复*/

    
    
    public String getAppKeyType() {
        return appKeyType;
    }

    public String getUserPubKeyType() {
        return userPubKeyType;
    }

    public void setUserPubKeyType(String userPubKeyType) {
        this.userPubKeyType = userPubKeyType;
    }

    public void setAppKeyType(String appKeyType) {
        this.appKeyType = appKeyType;
    }

    public Integer getAppKeyLen() {
        return appKeyLen;
    }

    public void setAppKeyLen(Integer appKeyLen) {
        this.appKeyLen = appKeyLen;
    }

    public String getRetAsymAlg() {
        return retAsymAlg;
    }

    public void setRetAsymAlg(String retAsymAlg) {
        this.retAsymAlg = retAsymAlg;
    }

    public String getRetSymAlg() {
        return retSymAlg;
    }

    public void setRetSymAlg(String retSymAlg) {
        this.retSymAlg = retSymAlg;
    }

    public String getRetHashAlg() {
        return retHashAlg;
    }

    public void setRetHashAlg(String retHashAlg) {
        this.retHashAlg = retHashAlg;
    }

    public BigInteger getUserCertNo() {
        return userCertNo;
    }

    public void setUserCertNo(BigInteger userCertNo) {
        this.userCertNo = userCertNo;
    }

    public byte[] getUserPubKey() {
        return userPubKey;
    }

    public void setUserPubKey(byte[] userPubKey) {
        this.userPubKey = userPubKey;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getDsCode() {
        return dsCode;
    }

    public void setDsCode(String dsCode) {
        this.dsCode = dsCode;
    }

    public String getExtendInfo() {
        return extendInfo;
    }

    public void setExtendInfo(String extendInfo) {
        this.extendInfo = extendInfo;
    }

    /**密钥撤销*/


    public String getEntName() {
        return entName;
    }

    public void setEntName(String entName) {
        this.entName = entName;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public byte[] getEntPubKeyHash() {
        return entPubKeyHash;
    }

    public void setEntPubKeyHash(byte[] entPubKeyHash) {
        this.entPubKeyHash = entPubKeyHash;
    }

    public String getRequestTime() {
        return requestTime;
    }

    public void setRequestTime(String requestTime) {
        this.requestTime = requestTime;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    //签名值
    byte[] signatureValue;

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(byte[] signatureValue) {
        this.signatureValue = signatureValue;
    }

    public Integer getTaskNo() {
        return taskNo;
    }

    public void setTaskNo(Integer taskNo) {
        this.taskNo = taskNo;
    }
    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }
}
