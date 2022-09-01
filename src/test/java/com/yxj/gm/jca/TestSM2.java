package com.yxj.gm.jca;

import com.kms.jca.UseKey;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.provider.algorithmParameterSpec.SM2AlgorithmParameterSpec;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class TestSM2 {
    static {
        Security.addProvider(new XaProvider());
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        String msg = "Test GM-JAVA-Jca 123";
        //密钥生成
        KeyPairGenerator sm2 = KeyPairGenerator.getInstance("SM2", "XaProvider");
        KeyPair keyPair = sm2.generateKeyPair();
        System.out.println("公钥HEX："+Hex.toHexString(keyPair.getPublic().getEncoded()));
        System.out.println("私钥HEX："+Hex.toHexString(keyPair.getPrivate().getEncoded()));
        //加解密
        Cipher sm2Cipher = Cipher.getInstance("SM2", "XaProvider");

        sm2Cipher.init(Cipher.ENCRYPT_MODE,keyPair.getPublic());
        byte[] mi = sm2Cipher.doFinal(msg.getBytes());
        System.out.println("加密密文："+new String(mi));
        System.out.println("加密密文HEX："+Hex.toHexString(mi));
        sm2Cipher.init(Cipher.DECRYPT_MODE,keyPair.getPrivate());
        byte[] ming = sm2Cipher.doFinal(mi);
        System.out.println("解密明文："+new String(ming));
        //签名验签
        Signature sm2Signature = Signature.getInstance("SM2", "XaProvider");
        sm2Signature.initSign(keyPair.getPrivate());
        sm2Signature.setParameter(new SM2AlgorithmParameterSpec("123456781234567".getBytes()));
        sm2Signature.update(msg.getBytes());
        byte[] sign = sm2Signature.sign();
        System.out.println("签名值HEX："+Hex.toHexString(sign));

        sm2Signature=Signature.getInstance("SM2", "XaProvider");
        sm2Signature.setParameter(new SM2AlgorithmParameterSpec("123456781234567".getBytes()));
        sm2Signature.initVerify(keyPair.getPublic());
        sm2Signature.update(msg.getBytes());
//        sign[1]=5;
        if(sm2Signature.verify(sign)){
            System.out.println("验签通过");
        }else {
            System.out.println("验签失败");
        }


    }
}
