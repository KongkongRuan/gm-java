package com.yxj.gm;

import com.yxj.gm.SM2.Key.SM2PrivateKey;
import com.yxj.gm.SM2.Key.SM2PublicKey;
import com.yxj.gm.util.CertValidation;
import com.yxj.gm.util.FileUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.io.IOException;

public class CertTest {
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
    public static void main(String[] args) throws IOException {
//        SM2CertGenerator sm2CertGenerator = new SM2CertGenerator();
//         String DN_CA = "CN=Digicert,OU=Digicert,O=Digicert,L=Linton,ST=Utah,C=US";
//         String DN_CHILD = "CN=DD,OU=DD,O=DD,L=Linton,ST=Utah,C=CN";
//        CertTest certTest = new CertTest();
//        byte[] rootCert = sm2CertGenerator.generatorCert(DN_CA, 365 * 10, DN_CA, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign), true, certTest.getRootPrivateKey().getEncoded(), certTest.getRootPublicKey().getEncoded());
//        try {
//            FileUtils.writeFile("D:/certtest/java-ca-2.cer",rootCert);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
//        byte[] ownerCert = sm2CertGenerator.generatorCert(DN_CA, 365, DN_CHILD, new KeyUsage(KeyUsage.digitalSignature), false, certTest.getRootPrivateKey().getEncoded(), certTest.getChildPublicKey().getEncoded());
//        try {
//            FileUtils.writeFile("D:/certtest/java-ownerCert-2.cer",ownerCert);
//        } catch (Exception e) {
//            throw new RuntimeException(e);
//        }
        byte[] caCert = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca-2.cer"));
        byte[] ownerCert = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ownerCert-2.cer"));

        boolean b = CertValidation.selfSignedCaValidation(caCert);
        System.err.println(b);
        boolean b1 = CertValidation.CertificateChainValidation(caCert, ownerCert);
        System.err.println(b1);


    }
}
