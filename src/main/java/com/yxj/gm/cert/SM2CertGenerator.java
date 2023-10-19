//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.yxj.gm.cert;

import com.yxj.gm.SM2.Key.SM2PrivateKey;
import com.yxj.gm.SM2.Key.SM2PublicKey;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.util.FileUtils;
import com.yxj.gm.util.SM2Util;
import com.yxj.gm.util.X509Util;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public class SM2CertGenerator {
    V3TBSCertificateGenerator tbsGen;
    ExtensionsGenerator extGenerator;

    public SM2CertGenerator() {
    }

    public byte[] generatorCert(String issuerSubject, long validity, String ownerSubject, KeyUsage keyUsage, boolean isCa, byte[] issuerPriKey, byte[] ownerPubKey) {
        PublicKey publicKey = new SM2PublicKey(ownerPubKey);
        PrivateKey privateKey = new SM2PrivateKey(issuerPriKey);
        X500Name issuer = new X500Name(issuerSubject);
        ASN1Integer serial = new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + validity * 24L * 60L * 60L * 1000L);
        X500Name subject = new X500Name(ownerSubject);
        ECPublicKeyParameters bcecPublicKey = X509Util.createECPublicKeyParameters(publicKey.getEncoded());
        SubjectPublicKeyInfo info = X509Util.createSubjectECPublicKeyInfo(bcecPublicKey);

        try {
            this.X509v3CertificateInit(issuer, serial, new Time(notBefore), new Time(notAfter), subject, info, keyUsage, isCa);
        } catch (IOException var27) {
            throw new RuntimeException("初始化tbsGen V3证书生成器失败：" + var27);
        }

        TBSCertificate tbsCert = this.tbsGen.generateTBSCertificate();
        SM2Signature signature = new SM2Signature();

        byte[] certMsg;
        try {
            certMsg = tbsCert.getEncoded();
        } catch (IOException var26) {
            throw new RuntimeException(var26);
        }

        X509CertificateHolder certificateHolder;
        try {
            certificateHolder = new X509CertificateHolder(X509Util.generateStructure(tbsCert, SM2Util.sigAlgId, signature.signature(certMsg, (byte[])null, privateKey.getEncoded())));
        } catch (IOException var25) {
            throw new RuntimeException("组合证书体失败：" + var25);
        }

        Certificate certificate = certificateHolder.toASN1Structure();

        try {
            return FileUtils.ASN1ToPemByteArray(certificate.getEncoded()).getBytes();
        } catch (IOException var24) {
            throw new RuntimeException("ASN.1到pem格式转换失败：" + var24);
        }
    }

    public TBSCertificate generatorCertByHsmStep1GetTbs(String issuerSubject, long validity, String ownerSubject, KeyUsage keyUsage, boolean isCa, byte[] ownerPubKey) {
        PublicKey publicKey = new SM2PublicKey(ownerPubKey);
        X500Name issuer = new X500Name(issuerSubject);
        ASN1Integer serial = new ASN1Integer(UUID.randomUUID().getMostSignificantBits() & Long.MAX_VALUE);
        Date notBefore = new Date();
        Date notAfter = new Date(System.currentTimeMillis() + validity * 24L * 60L * 60L * 1000L);
        X500Name subject = new X500Name(ownerSubject);
        ECPublicKeyParameters bcecPublicKey = X509Util.createECPublicKeyParameters(publicKey.getEncoded());
        SubjectPublicKeyInfo info = X509Util.createSubjectECPublicKeyInfo(bcecPublicKey);

        try {
            this.X509v3CertificateInit(issuer, serial, new Time(notBefore), new Time(notAfter), subject, info, keyUsage, isCa);
        } catch (IOException var17) {
            throw new RuntimeException("初始化tbsGen V3证书生成器失败：" + var17);
        }

        return this.tbsGen.generateTBSCertificate();
    }

    public byte[] generatorCertByHsmStep2GetCert(TBSCertificate tbs, byte[] signatureValue) {
        X509CertificateHolder certificateHolder;
        try {
            certificateHolder = new X509CertificateHolder(X509Util.generateStructure(tbs, SM2Util.sigAlgId, signatureValue));
        } catch (IOException var7) {
            throw new RuntimeException("组合证书体失败：" + var7);
        }

        Certificate certificate = certificateHolder.toASN1Structure();

        try {
            return FileUtils.ASN1ToPemByteArray(certificate.getEncoded()).getBytes();
        } catch (IOException var6) {
            throw new RuntimeException("ASN.1到pem格式转换失败：" + var6);
        }
    }

    private void X509v3CertificateInit(X500Name issuer, ASN1Integer serial, Time notBefore, Time notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo, KeyUsage keyUsage, boolean isCa) throws IOException {
        this.tbsGen = new V3TBSCertificateGenerator();
        this.tbsGen.setSerialNumber(serial);
        this.tbsGen.setSignature(SM2Util.sigAlgId);
        this.tbsGen.setIssuer(issuer);
        this.tbsGen.setStartDate(notBefore);
        this.tbsGen.setEndDate(notAfter);
        this.tbsGen.setSubject(subject);
        this.tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
        this.extGenerator = new ExtensionsGenerator();
        if (isCa) {
            ASN1EncodableVector aev = new ASN1EncodableVector();
            aev.add(ASN1Boolean.getInstance(true));
            aev.add(new ASN1Integer(255L));
            DERSequence basicConstraintsSeq = new DERSequence(aev);
            this.extGenerator.addExtension(Extension.basicConstraints, false, basicConstraintsSeq);
        }

        this.extGenerator.addExtension(Extension.keyUsage, true, keyUsage);
        this.tbsGen.setExtensions(this.extGenerator.generate());
    }
}
