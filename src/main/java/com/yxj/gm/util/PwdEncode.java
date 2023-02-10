package com.yxj.gm.util;

import com.yxj.gm.SM3.SM3Digest;
import org.bouncycastle.util.encoders.Hex;

import java.security.SecureRandom;
import java.util.Arrays;

public class PwdEncode {

    public static String Encode(String pwd){
        SM3Digest sm3Digest = new SM3Digest();
        SecureRandom secureRandom = new SecureRandom();
        byte[] rand = new byte[16];
        secureRandom.nextBytes(rand);
        String randHex = Hex.toHexString(rand);
        byte[] md = sm3Digest.doFinal((randHex + pwd).getBytes());
        return Hex.toHexString(DataConvertUtil.byteArrAdd(md, rand));
    }
    public static boolean matches(String pwd,String cipherText){
        byte[] cipherTextHex = Hex.decode(cipherText);
        byte[] md = new byte[32];
        byte[] rand = new byte[16];
        System.arraycopy(cipherTextHex,0,md,0,32);
        System.arraycopy(cipherTextHex,32,rand,0,16);
        SM3Digest sm3Digest = new SM3Digest();
        byte[] md1 = sm3Digest.doFinal((Hex.toHexString(rand) + pwd).getBytes());
        return Arrays.equals(md,md1);

    }

    public static void main(String[] args) {
        String pwd ="123456";
        for (int i = 0; i < 3; i++) {
            String encode = PwdEncode.Encode(pwd);
            System.out.println(encode);
            System.out.println(PwdEncode.matches(pwd,encode));
        }

    }
}
