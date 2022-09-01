package com.yxj.gm.jca;

import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.provider.algorithmParameterSpec.SM4AlgorithmParameterSpec;
import com.yxj.gm.provider.key.XaSecretKey;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class TestSM4 {
    static {
        Security.addProvider(new XaProvider());
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        String msg = "Test GM-JAVA-Jca 123";
        Cipher sm4 = Cipher.getInstance("SM4/CTR/Pkcs7", "XaProvider");
        SecureRandom secureRandom = new SecureRandom();
        byte[] key=new byte[16];
        secureRandom.nextBytes(key);
        sm4.init(Cipher.ENCRYPT_MODE,new XaSecretKey(key),new SM4AlgorithmParameterSpec("1234567812345678".getBytes()));
        byte[] mi = sm4.doFinal(msg.getBytes());
        System.out.println("密文Hex:"+ Hex.toHexString(mi));
        sm4 = Cipher.getInstance("SM4/CTR/Pkcs7", "XaProvider");
        sm4.init(Cipher.DECRYPT_MODE,new XaSecretKey(key),new SM4AlgorithmParameterSpec("1234567812345678".getBytes()));
        byte[] ming = sm4.doFinal(mi);
        System.out.println("解密后明文："+new String(ming));
    }
}
