package com.yxj.gm.util;

import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;

public class FileUtils extends org.apache.commons.io.FileUtils {
    public static byte[] pemToASN1ByteArray(byte[] pem){
        String[] stra = new String(pem).split("-----BEGIN CERTIFICATE-----\n")[1].split("-----END CERTIFICATE-----\n");
        return Base64.decode(stra[0].replace("\n",""));
    }
    public static String ASN1ToPemByteArray(byte[] asn1){
        StringBuilder sb = new StringBuilder();

        String encode = Base64.toBase64String(asn1);
        String start = "-----BEGIN CERTIFICATE-----\n";
        String end = "-----END CERTIFICATE-----\n";


        sb.append(start);

        for (int i = 0; i*64 < encode.length(); i++) {
            if((i+1)*64>encode.length()){
                sb.append(encode,i*64,encode.length());
                sb.append("\n");
                break;
            }
            sb.append(encode, i*64, (i+1)*64);
            sb.append("\n");
        }

        sb.append(end);
        return sb.toString();

    }
    public static void writeFile(String path, byte[] content) throws Exception {
//        File file = new File(path);
//        if(!file.exists()){
//            file.createNewFile();
//        }
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(content);
        fos.close();
    }
}
