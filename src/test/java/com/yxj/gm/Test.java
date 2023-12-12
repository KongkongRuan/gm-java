package com.yxj.gm;

import com.yxj.gm.SM2.Cipher.SM2Cipher;
import com.yxj.gm.SM2.Key.SM2KeyPairGenerate;
import com.yxj.gm.SM2.Signature.SM2Signature;
import com.yxj.gm.SM3.SM3Digest;
import com.yxj.gm.SM4.SM4Cipher;
import com.yxj.gm.cert.SM2CertGenerator;
import com.yxj.gm.enums.ModeEnum;
import com.yxj.gm.util.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Test {
    public static void main1(String[] args) {
        String msg = "gm-java-1.0";
        //SM2密钥对生成
        KeyPair keyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        //SM2加解密
        SM2Cipher sm2Cipher = new SM2Cipher();
        byte[] mi = sm2Cipher.SM2CipherEncrypt(msg.getBytes(), keyPair.getPublic().getEncoded());
        byte[] ming = sm2Cipher.SM2CipherDecrypt(mi, keyPair.getPrivate().getEncoded());
        System.out.println("SM2解密结果："+new String(ming));
        //SM2签名验签
        SM2Signature signature = new SM2Signature();
        byte[] signature1 = signature.signature(msg.getBytes(), null, keyPair.getPrivate().getEncoded());
        boolean b = signature.verify(msg.getBytes(), null, signature1, keyPair.getPublic().getEncoded());
        System.out.println("SM2验签结果："+b);
        //制作SM2证书
        //ca证书密钥
        KeyPair caKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();
        //终端证书密钥
        KeyPair equipKeyPair = SM2KeyPairGenerate.generateSM2KeyPair();

        SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
        String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
        String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";

        byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ca-3.cer",rootCert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, caKeyPair.getPrivate().getEncoded(), equipKeyPair.getPublic().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ownerCert-3.cer",ownerCert);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        //使用HSM签名制作SM2证书
        int hsmSigPriIndex=0;
//        rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, caKeyPair.getPrivate().getEncoded(), caKeyPair.getPublic().getEncoded(),true,hsmSigPriIndex);
        //SM3摘要计算
        SM3Digest sm3Digest = new SM3Digest();
        sm3Digest.update(msg.getBytes());
        byte[] md = sm3Digest.doFinal();
        byte[] md2 = sm3Digest.doFinal(msg.getBytes());
        sm3Digest.update("gm-java-".getBytes());
        sm3Digest.update("1.0".getBytes());
        byte[] md3 = sm3Digest.doFinal();
        System.out.println(Hex.toHexString(md));
        System.out.println(Hex.toHexString(md2));
        System.out.println(Hex.toHexString(md3));
        //SM4加解密
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        secureRandom.nextBytes(key);
        secureRandom.nextBytes(iv);
        //ECB模式
        SM4Cipher sm4CipherECB = new SM4Cipher(ModeEnum.ECB);
        byte[] ecbmi = sm4CipherECB.cipherEncrypt(key, msg.getBytes(), null);
        byte[] ecbming = sm4CipherECB.cipherDecrypt(key, ecbmi, iv);
        System.out.println("ECB明文："+new String(ecbming));
        //CBC模式
        SM4Cipher sm4CipherCBC = new SM4Cipher(ModeEnum.CBC);
        byte[] cbcmi = sm4CipherCBC.cipherEncrypt(key, msg.getBytes(), iv);
        byte[] cbcming = sm4CipherCBC.cipherDecrypt(key, cbcmi, iv);
        System.out.println("CBC明文："+new String(cbcming));
        //CTR模式
        SM4Cipher sm4CipherCTR = new SM4Cipher(ModeEnum.CTR);
        byte[] ctrmi = sm4CipherCTR.cipherEncrypt(key, msg.getBytes(), iv);
        byte[] ctrming = sm4CipherCTR.cipherDecrypt(key, ctrmi, iv);
        System.out.println("CTR明文："+new String(ctrming));

    }

//    public static void main2(String[] args) throws Exception {
//        byte[] bytes = FileUtils.readFileToByteArray(new File("C:\\Users\\XDYG\\Documents\\WeChat Files\\wxid_zeekxfre2s1m41\\FileStorage\\File\\2023-02\\ca_csr1.key"));
//
//        byte[] ming = Base64.decode(bytes);
//        System.out.println(Hex.toHexString(ming));
//        byte[] bhmy = geneProtect();
//
//        UseKey useKey = new UseKey();
//        byte[] mi = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(bhmy), ming);
//        FileUtils.writeFile("D:\\gw-cert-key\\prikey-mi1.key",mi);
////        byte[] pubkey = Hex.decode("74DBBCC0BB8994EF116B8BFE817A0AB5CB32F312F752725B3179672A171886F1494B8809B2A542DF508DA1FEB1595C20AF2A9F287FF8FBF28AA7CBA2948B6A6D");
////        FileUtils.writeFile("D:\\gw-cert-key\\pubkey-ming.key",pubkey);
//
//    }
//
//    public static void main3(String[] args) throws IOException {
//        byte[] priMingBase64 = FileUtils.readFileToByteArray(new File("D:\\国网正式环境证书以及密钥\\certAndKey\\ca_csr_pri_ming.key"));
//        byte[] priMing=Base64.decode(priMingBase64);
//        byte[] cert = FileUtils.readFileToByteArray(new File("D:\\国网正式环境证书以及密钥\\certAndKey\\SERIALNUMBER=F30123261097202302160029,OU=CEPRI,O=SGCC,C=CN6324D9DA1E80F0F5.cer"));
//        byte[] bhmy = geneProtect();
//        UseKey useKey = new UseKey();
//        byte[] pubkey = Hex.decode("C217B42678763542DCC9A9367C7A2FE3F34DE8F36D120E9F799FD4402FBAD82D4E02BDA3245FB48332C37050FD785546F5020A47026F84302C1DB9E6A68EE092");
//        byte[] priMi = useKey.cipherEncrypt("SM4", new ZyxxSecretKey(bhmy), priMing);
//        byte[] certAddZero = ArrayUtils.add(cert, (byte) 0);
//        FileUtils.writeByteArrayToFile(new File("D:\\国网正式环境证书以及密钥\\certAndKey\\certAddZero.cer"),certAddZero);
//        FileUtils.writeByteArrayToFile(new File("D:\\国网正式环境证书以及密钥\\certAndKey\\pubkey.key"),pubkey);
//        FileUtils.writeByteArrayToFile(new File("D:\\国网正式环境证书以及密钥\\certAndKey\\priMi.key"),priMi);
//
//        System.out.println(Hex.toHexString(priMing));
//
//    }

    public static void main(String[] args) throws IOException {
        byte[] cert = FileUtils.readFileToByteArray(new File("C:\\Users\\XDYG\\Documents\\WeChat Files\\wxid_zeekxfre2s1m41\\FileStorage\\File\\2023-03\\TestCrt.crt"));
        byte[] asn1 = FileUtils.pemToASN1ByteArray(cert);
        FileUtils.writeByteArrayToFile(new File("C:\\Users\\XDYG\\Documents\\WeChat Files\\wxid_zeekxfre2s1m41\\FileStorage\\File\\2023-03\\derCert.der"),asn1);
        String s = FileUtils.ASN1ToPemByteArray(asn1);
        System.out.println(s);
    }
//    public static byte[] geneProtect(){
//        UseKey useKey = new UseKey();
//        byte[] s = "KMS_S".getBytes();
//        byte[] in = "KMS_Feature".getBytes();
//        byte[] info = "KMS_START".getBytes();
//        int ol = 16;
//        try {
//            byte[] bytes = useKey.generateProtectedKey(s, in, info, ol);
//            return bytes;
//        } catch (NoSuchProviderException e) {
//            e.printStackTrace();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//        return null;
//    }

}
