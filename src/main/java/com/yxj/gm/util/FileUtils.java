package com.yxj.gm.util;

import org.bouncycastle.util.encoders.Base64;

public class FileUtils extends org.apache.commons.io.FileUtils {
    public static byte[] pemToASN1ByteArray(byte[] pem){
        String[] stra = new String(pem).split("-----BEGIN CERTIFICATE-----\n")[1].split("-----END CERTIFICATE-----\n");
        return Base64.decode(stra[0].replace("\n",""));
    }
}
