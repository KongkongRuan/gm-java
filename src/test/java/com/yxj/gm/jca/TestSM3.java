package com.yxj.gm.jca;

import com.kms.jca.UseKey;
import com.yxj.gm.provider.XaProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.HashMap;

public class TestSM3 {
    static {
        Security.addProvider(new XaProvider());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        String msg = "Test GM-JAVA-Jca 123";
        UseKey useKey = new UseKey();
        MessageDigest sm3md = MessageDigest.getInstance("SM3", "XaProvider");
        sm3md.update(msg.getBytes());
        byte[] digest1 = sm3md.digest();
        System.out.println("digest1 HEX:"+ Hex.toHexString(digest1));
        byte[] digest11 = useKey.messageDigest(msg.getBytes());
        System.out.println("digest11 HEX:"+ Hex.toHexString(digest11));


    }

}
