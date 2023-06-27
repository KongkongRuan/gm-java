package com.yxj.gm.util;

import org.bouncycastle.util.encoders.Base64;

import java.io.FileOutputStream;

public class FileUtils extends org.apache.commons.io.FileUtils {

    public static byte[] pemToASN1ByteArray(byte[] pem){
        String lineSeparator="";
        String pemStr = new String(pem);
        if(pemStr.contains("-----BEGIN CERTIFICATE-----\r\n")){
           lineSeparator="\r\n";
        }
        if(pemStr.contains("-----BEGIN CERTIFICATE-----\r")){
           lineSeparator="\r";
        }
        if(pemStr.contains("-----BEGIN CERTIFICATE-----\n")){
           lineSeparator="\n";
        }


        String[] stra = new String(pem).split("-----BEGIN CERTIFICATE-----"+lineSeparator)[1].split("-----END CERTIFICATE-----"+lineSeparator);
        return Base64.decode(stra[0].replace(lineSeparator,""));
    }
    public static String ASN1ToPemByteArray(byte[] asn1){
        StringBuilder sb = new StringBuilder();
        String lineSeparator = System.getProperty("line.separator");
        String encode = Base64.toBase64String(asn1);
        String start = "-----BEGIN CERTIFICATE-----"+lineSeparator;
        String end = "-----END CERTIFICATE-----"+lineSeparator;


        sb.append(start);

        for (int i = 0; i*64 < encode.length(); i++) {
            if((i+1)*64>encode.length()){
                sb.append(encode,i*64,encode.length());
                sb.append(lineSeparator);
                break;
            }
            sb.append(encode, i*64, (i+1)*64);
            sb.append(lineSeparator);
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
