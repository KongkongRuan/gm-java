package com.yxj.gm.provider.mac;

import com.kms.JNI.CallJNI;
import com.yxj.gm.provider.XaProvider;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.util.HashMap;

public class XaHMac  {

    private  static HashMap<String,Integer> messageDigestBlockLen = new HashMap<>();
    static {
        messageDigestBlockLen.put("SM3",64);
        messageDigestBlockLen.put("SHA-1",64);
        messageDigestBlockLen.put("SHA-224",64);
        messageDigestBlockLen.put("SHA-256",64);
        messageDigestBlockLen.put("SHA-384",128);
        messageDigestBlockLen.put("SHA-512",128);
    }
    private  int blockLen;
    private  MessageDigest messageDigest;
    private  byte[] key;
    private  byte[] extendKey;

    private  byte[] ipadKey;
    private  byte[] opadKey;

    XaHMac(){};
    public XaHMac(MessageDigest messageDigest, byte[] key) {
        this.messageDigest = messageDigest;
        this.key = key;
        this.blockLen = messageDigestBlockLen.get(messageDigest.getAlgorithm());
        //处理密钥
        if (key.length > blockLen) {
            messageDigest.update(key);
            this.extendKey = messageDigest.digest();
        }
        if (key.length < blockLen) {
            byte[] tmp = new byte[blockLen];
            System.arraycopy(key, 0, tmp, 0, key.length);
            this.extendKey = tmp;
        }
        if (key.length == blockLen) {
            this.extendKey = key;
        }
        //处理ipad和opad
        ipadKey = new byte[blockLen];
        opadKey = new byte[blockLen];
        for (int i = 0; i < blockLen; i++) {
            ipadKey[i] = (byte) (extendKey[i] ^ 0x36);
            opadKey[i] = (byte) (extendKey[i] ^ 0x5c);
        }

    }
    public byte[] doFinal(byte[] msg ){
        byte[] bytes = DataConvertUtil.byteArrAdd(ipadKey, msg);
        byte[] digest = messageDigest.digest(bytes);
        byte[] bytes1 = DataConvertUtil.byteArrAdd(opadKey, digest);
        return messageDigest.digest(bytes1);
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {

        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);


        /**java**/

        Security.addProvider(new XaProvider());
        MessageDigest xaMd = MessageDigest.getInstance("SM3", "XaProvider");
        String algorithm = xaMd.getAlgorithm();
        System.out.println(algorithm);


        XaHMac xaHMac = new XaHMac(xaMd, key);
        byte[] bytes = xaHMac.doFinal("123".getBytes());
        System.out.println(Hex.toHexString(bytes));


        /**C组件化**/
        byte[] result = new byte[32];
        CallJNI callJNI = new CallJNI();
        callJNI.kmsMAC(985,key,key.length,"123".getBytes(),3,result,result.length);
        System.out.println(Hex.toHexString(result));
    }

}
