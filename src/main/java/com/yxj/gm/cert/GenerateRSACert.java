package com.yxj.gm.cert;

import com.yxj.gm.util.FileUtils;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * @author YXJ
 * @date 2023/3/31 13:54
 */
public class GenerateRSACert {
    public static void main(String[] args) throws Exception {
        KeyPair rootKeyPair = generateRSAKeyPair();
        X509Certificate rootCert = generateRootCert(rootKeyPair);
        String pemRootCert = FileUtils.ASN1ToPemByteArray(rootCert.getEncoded());
//        KeyStore rootKeyStore = createKeyStore("root", "123456", rootKeyPair.getPrivate(), rootCert);
//        rootKeyStore.store(new FileOutputStream("D:\\certtest\\rsa\\rootCert.jks"),"123456".toCharArray());
        FileUtils.writeStringToFile(new File("D:\\certtest\\rsa\\rootCert.pem"),pemRootCert,"utf8");

        KeyPair subCAPair = generateRSAKeyPair();
        X509Certificate subCaCert = generateSubCaCert(subCAPair.getPublic(),rootKeyPair.getPrivate(),rootCert);
        String pemSubCaCert = FileUtils.ASN1ToPemByteArray(subCaCert.getEncoded());
        KeyStore subCaStore = createKeyStore("subCa", "123456", subCAPair.getPrivate(), subCaCert,rootCert);
        subCaStore.store(new FileOutputStream("D:\\certtest\\rsa\\subCaCert.jks"),"123456".toCharArray());
        FileUtils.writeStringToFile(new File("D:\\certtest\\rsa\\subCaCert.pem"),pemSubCaCert,"utf8");


        KeyPair terminalPair = generateRSAKeyPair();
        X509Certificate terminalCert = generateTerminalCert(terminalPair.getPublic(),subCAPair.getPrivate(),subCaCert);
        String pemTerminalCert = FileUtils.ASN1ToPemByteArray(terminalCert.getEncoded());
        KeyStore terminalStore = createKeyStore("terminal", "123456", terminalPair.getPrivate(), terminalCert,terminalCert);
        terminalStore.store(new FileOutputStream("D:\\certtest\\rsa\\terminalCert.jks"),"123456".toCharArray());
        FileUtils.writeStringToFile(new File("D:\\certtest\\rsa\\terminalCert.pem"),pemTerminalCert,"utf8");


    }
    private static KeyPair generateRSAKeyPair()throws Exception{
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048,new SecureRandom());
        return rsa.generateKeyPair();
    }
    private static X509Certificate generateRootCert(KeyPair keyPair)throws Exception{
        X500Name subject = new X500Name("C=CN,CN=Root");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime()+365*24*60*60*1000L);
        JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ASN1EncodableVector aev = new ASN1EncodableVector();
        aev.add(ASN1Boolean.getInstance(true));// ca cert
        aev.add(new ASN1Integer(255));//Path Length Constraint
        DERSequence basicConstraintsSeq = new DERSequence(aev);
        jcaX509v3CertificateBuilder.addExtension(Extension.basicConstraints, false, basicConstraintsSeq);


        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder build = jcaX509v3CertificateBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(build);
    }
    private static X509Certificate generateSubCaCert(PublicKey subCAPublicKey, PrivateKey rootPrivateKey,X509Certificate rootCert)throws Exception{
        X500Name subject = new X500Name("C=CN,CN=SubCA");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime()+365*24*60*60*1000L);
        JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(new X500Name("C=CN,CN=Root"), serial, notBefore, notAfter, subject,subCAPublicKey);

        ASN1EncodableVector aev = new ASN1EncodableVector();
        aev.add(ASN1Boolean.getInstance(true));// ca cert
        aev.add(new ASN1Integer(255));//Path Length Constraint
        DERSequence basicConstraintsSeq = new DERSequence(aev);
        jcaX509v3CertificateBuilder.addExtension(Extension.basicConstraints, false, basicConstraintsSeq);



        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(rootPrivateKey);
        X509CertificateHolder build = jcaX509v3CertificateBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(build);
    }
    private static X509Certificate generateTerminalCert(PublicKey terminalPublicKey, PrivateKey subCAPrivateKey,X509Certificate subCACert)throws Exception{
        X500Name subject = new X500Name("C=CN,CN=192.168.0.184");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime()+365*24*60*60*1000L);
        JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(new X500Name("C=CN,CN=SubCA"), serial, notBefore, notAfter, subject,terminalPublicKey);

        GeneralNames generalNames = new GeneralNames(new GeneralName(GeneralName.iPAddress, "192.168.0.184"));
        jcaX509v3CertificateBuilder.addExtension(Extension.subjectAlternativeName,false,generalNames);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(subCAPrivateKey);
        X509CertificateHolder build = jcaX509v3CertificateBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(build);
    }
    private static KeyStore createKeyStore(String alias,String password,PrivateKey privateKey,X509Certificate cert,X509Certificate... chain)throws Exception{
        KeyStore jks = KeyStore.getInstance("JKS");
        jks.load(null,null);
        jks.setKeyEntry(alias,privateKey,password.toCharArray(),chain);
        jks.setCertificateEntry(alias+"-cert",cert);
        return jks;
    }
}
