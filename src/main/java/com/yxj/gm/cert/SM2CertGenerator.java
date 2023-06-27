package com.yxj.gm.cert;

import com.yxj.gm.SM2.Key.SM2PrivateKey;
import com.yxj.gm.SM2.Key.SM2PublicKey;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.util.FileUtils;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.X509Util;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;

public class SM2CertGenerator {
    V3TBSCertificateGenerator tbsGen;
    ExtensionsGenerator extGenerator;


    public byte[] generatorCert(String issuerSubject, long validity, String ownerSubject, KeyUsage keyUsage,boolean isCa,byte[] issuerPriKey,byte[] ownerPubKey,boolean useHSM,int hsmSigPriIndex){
        PublicKey publicKey = new SM2PublicKey(ownerPubKey);
        PrivateKey privateKey = new SM2PrivateKey(issuerPriKey);
        //颁发者信息
        X500Name issuer = new X500Name(issuerSubject);
        //证书序列号
        ASN1Integer serial = new ASN1Integer(UUID.randomUUID().getMostSignificantBits()&Long.MAX_VALUE);
        //生效时间
        Date notBefore = new Date();
        //过期时间
        Date notAfter = new Date(System.currentTimeMillis()+ validity * 24 * 60 * 60 * 1000);
        //使用者信息
        X500Name subject = new X500Name(ownerSubject);
        //获取ecc公钥参数
        ECPublicKeyParameters bcecPublicKey = X509Util.createECPublicKeyParameters(publicKey.getEncoded());
        //转换成ASN.1 SubjectPublicKeyInfo
        SubjectPublicKeyInfo info =X509Util.createSubjectECPublicKeyInfo(bcecPublicKey);
        //初始化 tbsGen  V3证书生成器
        try {
            X509v3CertificateInit(issuer, serial,new Time(notBefore),new Time(notAfter),subject,info,keyUsage,isCa);
        } catch (IOException e) {
            throw new RuntimeException("初始化tbsGen V3证书生成器失败："+e);
        }
        //生成证书体
        TBSCertificate tbsCert = tbsGen.generateTBSCertificate();
        SM2Signature signature = new SM2Signature();
        byte[] certMsg  ;
        try {
            certMsg = tbsCert.getEncoded();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        //组合证书体，算法以及签名值
        X509CertificateHolder certificateHolder ;
        try {
            if(useHSM){
                certificateHolder = new X509CertificateHolder(X509Util.generateStructure(tbsCert, SM2Util.sigAlgId,signature.signatureByHSM(certMsg, hsmSigPriIndex ) ));
            }else {
                certificateHolder = new X509CertificateHolder(X509Util.generateStructure(tbsCert, SM2Util.sigAlgId,signature.signature(certMsg,null, privateKey.getEncoded()) ));
            }
        } catch (IOException e) {
            throw new RuntimeException("组合证书体失败："+e);
        }
        Certificate certificate = certificateHolder.toASN1Structure();
        //ASN.1转pem
        try {
            return FileUtils.ASN1ToPemByteArray(certificate.getEncoded()).getBytes();
        } catch (IOException e) {
            throw new RuntimeException("ASN.1到pem格式转换失败："+e);
        }
    }
    private void X509v3CertificateInit(X500Name issuer, ASN1Integer serial, Time notBefore, Time notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo, KeyUsage keyUsage, boolean isCa) throws IOException {
        tbsGen = new V3TBSCertificateGenerator();
        tbsGen.setSerialNumber(serial);
        tbsGen.setSignature(SM2Util.sigAlgId);

        tbsGen.setIssuer(issuer);
        tbsGen.setStartDate(notBefore);
        tbsGen.setEndDate(notAfter);
        tbsGen.setSubject(subject);
        tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
        extGenerator = new ExtensionsGenerator();
        if(isCa) {

            ASN1EncodableVector aev = new ASN1EncodableVector();
            aev.add(ASN1Boolean.getInstance(true));// ca cert
            aev.add(new ASN1Integer(255));//Path Length Constraint
            DERSequence basicConstraintsSeq = new DERSequence(aev);
            extGenerator.addExtension(Extension.basicConstraints, false, basicConstraintsSeq);
        }
        extGenerator.addExtension(Extension.keyUsage, true, keyUsage);
//        extGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
//        extGenerator.addExtension(Extension.subjectKeyIdentifier,false,extUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo));
//        extGenerator.addExtension(Extension.authorityKeyIdentifier,false,extUtils.createAuthorityKeyIdentifier(subjectPublicKeyInfo));
        tbsGen.setExtensions(extGenerator.generate());
    }
}
