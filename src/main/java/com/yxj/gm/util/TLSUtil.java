package com.yxj.gm.util;

import com.kms.JNI.CallJNI;
import com.kms.jca.UseKey;
import com.kms.provider.key.ZyxxSecretKey;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.provider.mac.XaHMac;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

public class TLSUtil {
    public static byte[] P_HASH(MessageDigest md,byte[] secret,byte[] seed,int length){
        int digestLength = md.getDigestLength();
        int n = length/digestLength;
        int r = length%digestLength;
        if (r != 0){
            n++;
        }
        byte[] temp = null;
        byte[] result = new byte[length];
        byte[][] A = new byte[n+1][digestLength];
        A[0] = seed;
        XaHMac xaHMac = new XaHMac(md, secret);

        for (int i = 1; i <= n; i++) {
            A[i] = xaHMac.doFinal(A[i-1]);
            byte[] bytes = xaHMac.doFinal(DataConvertUtil.byteArrAdd(A[i], seed));
            temp=DataConvertUtil.byteArrAdd(temp,bytes);
        }
        System.arraycopy(temp,0,result,0,length);
        return result;
    }
    public static byte[] prf(MessageDigest md,byte[] secret,byte[] label,byte[] seed,int length){
        byte[] labelAndSeed = DataConvertUtil.byteArrAdd(label, seed);
        return P_HASH(md,secret,labelAndSeed,length);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
        byte[] key =new byte[]{0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x01,0x02,0x03,0x04,0x05,0x06,0x07};
//        UseKey useKey = new UseKey();
//        byte[] prf = useKey.prf(new ZyxxSecretKey(key), "123".getBytes(), "123".getBytes(), 32);
//        System.out.println(Hex.toHexString(prf));
        Security.addProvider(new XaProvider());
        MessageDigest xaMd = MessageDigest.getInstance("SM3", "XaProvider");
        byte[] prf = TLSUtil.prf(xaMd, key, "123".getBytes(), "123".getBytes(), 32);
        System.out.println(Hex.toHexString(prf));


    }

}
