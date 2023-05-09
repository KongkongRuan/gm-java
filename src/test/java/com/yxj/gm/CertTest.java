package com.yxj.gm;

import com.kms.JNI.CallJNI;
import com.yxj.gm.SM2.Key.SM2PrivateKey;
import com.yxj.gm.SM2.Key.SM2PublicKey;
import com.yxj.gm.cert.CertParseVo;
import com.yxj.gm.cert.SM2CertGenerator;
import com.yxj.gm.util.CertResolver;
import com.yxj.gm.util.CertValidation;
import com.yxj.gm.util.FileUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.util.encoders.Hex;
import sun.security.x509.X509CertInfo;

import java.io.File;
import java.io.IOException;
import java.security.cert.CertificateParsingException;

public class CertTest {
    /**
     * 获取根证书公钥
     * @return 根证书公钥
     */
    SM2PublicKey getRootPublicKey(){
        byte[] decode = Hex.decode("58cd219f08552d940aa6b219513ba1e50063c2f01ad2d1c88b3d931868e0440b73175c092722eac88e90394bfd24005212aab989ba545942cbbeedf8ae42bc84");
        return new SM2PublicKey(decode);

    }
    SM2PrivateKey getRootPrivateKey(){
        byte[] bytes = Hex.decode("bed84b80124b3fc437829b58d793f1aecc563313c1cdfddcb793c8270f72953b");
        return new SM2PrivateKey(bytes);
    }
    SM2PublicKey getChildPublicKey(){
        byte[] bytes = Hex.decode("5481d3fe5be47e93f2571ec5abae4ee9962e1bb4fc316f7f9270862b7cc1e3f1ae4c08822691afde11a9dc327c7563ddc3f972dd7f60affcd7551d169bee472a");
        return new SM2PublicKey(bytes);
    }
    SM2PrivateKey getChildPrivateKey(){
        byte[] bytes = Hex.decode("712f5f88a22806c66af587f8702371e0140ffe888f247dd889caddb3a1ec19a2");
        return new SM2PrivateKey(bytes);
    }

    /**
     * 生成根证书
     * @param args  参数
     * @throws IOException
     */
    public static void main1(String[] args) throws IOException {
        SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
         String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
         String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";
        CertTest certTest = new CertTest();
        byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, certTest.getRootPrivateKey().getEncoded(), certTest.getRootPublicKey().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ca-3-add0.cer", ArrayUtils.add(rootCert,(byte) 0));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, certTest.getRootPrivateKey().getEncoded(), certTest.getChildPublicKey().getEncoded(),false,0);
        try {
            FileUtils.writeFile("D:/certtest/java-ownerCert-3-add0.cer",ArrayUtils.add(ownerCert,(byte)0));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        byte[] fileBytes = FileUtils.readFileToByteArray(new File("D:\\soft\\GenShen\\_.bt.cn.crt"));
//        byte[] fileBytes = FileUtils.readFileToByteArray(new File("D:\\设备0004_SM2_20220801144024.crt"));
        CertParseVo certParseVo = CertResolver.parseCert(fileBytes);
        System.out.println(certParseVo);


//
//        byte[] caCert = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca-2.cer"));
//        byte[] ownerCert = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ownerCert-2.cer"));
//
//        boolean b = CertValidation.selfSignedCaValidation(caCert);
//        System.err.println(b);
//        boolean b1 = CertValidation.CertificateChainValidation(caCert, ownerCert);
//        System.err.println(b1);


    }

    public static void main2(String[] args) throws IOException {
//        File ca = new File("C:\\Users\\XDYG\\Documents\\WeChat Files\\wxid_zeekxfre2s1m41\\FileStorage\\File\\2023-02\\SM2CERT_1677218791242\\certAddZero.pem");
//        File cert = new File("C:\\Users\\XDYG\\Documents\\WeChat Files\\wxid_zeekxfre2s1m41\\FileStorage\\File\\2023-02\\SM2CERT_1677218791242\\SM2CERT.cert");
//        File ca = new File("D:\\国网正式环境证书以及密钥\\certAndKey\\新建文件夹\\certAddZero.cer");
//        File cert = new File("D:\\国网正式环境证书以及密钥\\certAndKey\\新建文件夹\\SM2CERT_1.pem");
        File ca = new File("D:\\certtest\\zjhAndJava\\old\\ca.pem");
        File cert = new File("D:\\certtest\\zjhAndJava\\old\\SM2CERT_1_62_1671428432529.pem");

        boolean b = CertValidation.CertificateChainValidation(FileUtils.readFileToByteArray(ca), FileUtils.readFileToByteArray(cert));
        System.out.println(b);
        CallJNI callJNI = new CallJNI();
        byte[] caByte=FileUtils.readFileToByteArray(ca);
        byte[] certByte=FileUtils.readFileToByteArray(cert);
        int i = callJNI.kmsVerifyCertificate(caByte, caByte.length, certByte, certByte.length);
        System.out.println(i);
//        CertPaser.parseCert(FileUtils.readFileToByteArray(ca));
//        CertPaser.parseCert(FileUtils.readFileToByteArray(cert));
    }

    public static void main(String[] args) throws IOException, CertificateParsingException {
//        UseKey useKey = new UseKey();
//        HashMap<String, String> plainMap = new HashMap<>();
//        plainMap.put("cacert", "-----BEGIN CERTIFICATE-----\nMIIBXjCCAQOgAwIBAgIKvdbGslG3QIaksTAKBggqgRzPVQGDdTApMQswCQYDVQQG\nEwJDTjELMAkGA1UEBwwCQkoxDTALBgNVBAoMBEhOQ0EwHhcNMjEwMzAxMDI1MzMx\nWhcNMzEwMzAxMDI1MzMxWjApMQswCQYDVQQGEwJDTjELMAkGA1UEBwwCQkoxDTAL\nBgNVBAoMBEhOQ0EwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQEyvJJe/dCtvBk\n/+zkP0WI8Yizlfe7ripxkIxGGGghBs99H0mTjsdcH9bolAnedUpkipgkohfx69OD\nlrYumF7noxMwETAPBgNVHRMECDAGAQH/AgF/MAoGCCqBHM9VAYN1A0kAMEYCIQCm\nPhiYrz8OuW34cj/+Tojzq77jV5k+NBC9+Om3+s3nmAIhAIc4VTj+sRvlLmBaqlKw\ni/e6Hh67hn95DrWKaAAimYH4\n-----END CERTIFICATE-----");
//        byte[] caCert = Base64.decode(plainMap.get("cacert"));
//        for (int i = 0; i < 15; i++) {
//            KeyPair keyPair = useKey.keyPairGenerator("SM2");
//            useKey.getCert("X509","C=CN,L=BJ,O=KMS","O=HNCA,L=BJ,C=CN",caCert,0,0,new byte[32],keyPair.getPrivate().getEncoded(),keyPair.getPublic().getEncoded(),1,10,0);
//
//        }
        X509CertInfo x509CertInfo = new X509CertInfo(FileUtils.readFileToByteArray(new File("D:\\certtest\\zjhAndJava\\old\\SM2CERT_1_62_1671428432529.pem")));
        System.out.println(x509CertInfo);

    }
}
