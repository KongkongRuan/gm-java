package com.yxj.gm.asn1.ca.util;

import com.yxj.gm.asn1.ca.sm2.ASN1SM2Cipher;
import com.yxj.gm.asn1.ca.sm2.ASN1SM2Signature;
import com.yxj.gm.util.DataConvertUtil;
import org.bouncycastle.asn1.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ASN1Util {
    public static ASN1SM2Cipher SM2CipherToASN1SM2Cipher(byte[] sm2Cipher){
        if(sm2Cipher.length<96){
            throw new RuntimeException("输入的密文长度有误");
        }
        byte[] x = new byte[32];
        byte[] y = new byte[32];
        byte[] hash = new byte[32];
        byte[] cipherText = new byte[sm2Cipher.length-96];
        System.arraycopy(sm2Cipher,0,x,0,32);
        System.arraycopy(sm2Cipher,32,y,0,32);
        System.arraycopy(sm2Cipher,64,hash,0,32);
        System.arraycopy(sm2Cipher,96,cipherText,0,sm2Cipher.length-96);
        ASN1Integer asn1X = new ASN1Integer(new BigInteger(x));
        ASN1Integer asn1Y = new ASN1Integer(new BigInteger(y));
        DEROctetString asn1Hash = new DEROctetString(hash);
        DEROctetString asn1CipherText = new DEROctetString(cipherText);

        return new ASN1SM2Cipher(asn1X,asn1Y,asn1Hash,asn1CipherText);

    }

    public static ASN1SM2Signature SM2SignatureToASN1SM2Signature(byte[] sm2Signature){
        if(sm2Signature.length !=64){
            throw new RuntimeException("输入的签名值长度有误");
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(sm2Signature,0,r,0,32);
        System.arraycopy(sm2Signature,32,s,0,32);
        ASN1Integer asn1R = new ASN1Integer(new BigInteger(r));
        ASN1Integer asn1S = new ASN1Integer(new BigInteger(s));
        return new ASN1SM2Signature(asn1R,asn1S);
    }
    public static byte[] HSMAsn1PubKeyToPubKey(byte[] asn1Pub){
        ByteArrayInputStream bis = new ByteArrayInputStream(asn1Pub) ;
        ASN1InputStream ais = new ASN1InputStream(bis);;
        ASN1Primitive primitive;
        try {
            while ((primitive = ais.readObject()) != null) {
                //第一层Sequence
                if (primitive instanceof ASN1Sequence) {
                    ASN1Sequence sequence = (ASN1Sequence) primitive;
                    ASN1SequenceParser parser = sequence.parser();
                    ASN1Encodable encodable;
                    while ((encodable = parser.readObject()) != null) {
                        primitive = encodable.toASN1Primitive();
                        if (primitive instanceof DERBitString) {
                            DERBitString derBitString = (DERBitString) primitive;
                            byte[] pubKeyWitchHead = derBitString.getBytes();
                            if (pubKeyWitchHead[0] == 0x04) {
                                return DataConvertUtil.byteToN(pubKeyWitchHead, 64);
                            } else {
                                return pubKeyWitchHead;
                            }
                        }
                    }
                }

            }
        }catch (IOException e){
            e.printStackTrace();
        }finally {
            try {
                bis.close();
                ais.close();
            }catch (IOException e){
                throw new RuntimeException(e);
            }
        }
        return new byte[1];
    }
    public static byte[] HSMAsn1PriKeyToPriKey(byte[] asn1Pri){
        ByteArrayInputStream bis = new ByteArrayInputStream(asn1Pri) ;
        ASN1InputStream ais = new ASN1InputStream(bis);;
        ASN1Primitive primitive;
        try {
            while ((primitive = ais.readObject()) != null) {
                //第一层Sequence
                if (primitive instanceof ASN1Sequence) {
                    ASN1Sequence sequence = (ASN1Sequence) primitive;
                    ASN1SequenceParser parser = sequence.parser();
                    ASN1Encodable encodable;
                    while ((encodable = parser.readObject()) != null) {
                        primitive = encodable.toASN1Primitive();
                        if(primitive instanceof DEROctetString){
                            DEROctetString derOctetString=(DEROctetString) primitive;
                            byte[] priKeyWitchHead = derOctetString.getOctets();
                            if (priKeyWitchHead[0] == 0x04) {
                                return DataConvertUtil.byteToN(priKeyWitchHead, 64);
                            } else {
                                return priKeyWitchHead;
                            }
                        }
                        if (primitive instanceof DLTaggedObject) {
                            DLTaggedObject dlTaggedObject = (DLTaggedObject) primitive;
                            int tagNo = dlTaggedObject.getTagNo();
                            if(tagNo==1){
                                ASN1Object baseObject = dlTaggedObject.getBaseObject();
//                                ASN1Primitive baseObject = derTaggedObject.getObject();
                                if(baseObject instanceof DERBitString){
                                    DERBitString derBitString = (DERBitString) baseObject;
                                    byte[] priKeyWitchHead = derBitString.getBytes();
                                    if (priKeyWitchHead[0] == 0x04) {
                                        return DataConvertUtil.byteToN(priKeyWitchHead, 64);
                                    } else {
                                        return priKeyWitchHead;
                                    }
                                }
                            }
                        }
                    }
                }

            }
        }catch (IOException e){
            e.printStackTrace();
        }finally {
            try {
                bis.close();
                ais.close();
            }catch (IOException e){
                throw new RuntimeException(e);
            }
        }
        return new byte[1];
    }
//    public static void main(String[] args) throws IOException {
//        byte[] sm2Cipher = new byte[0];
//        for (int i = 0; i < 32; i++) {
//            sm2Cipher =ArrayUtils.addAll(sm2Cipher,new byte[]{1});
//        }
//        for (int i = 0; i < 32; i++) {
//            sm2Cipher =ArrayUtils.addAll(sm2Cipher,new byte[]{2});
//        }
//        for (int i = 0; i < 32; i++) {
//            sm2Cipher =ArrayUtils.addAll(sm2Cipher,new byte[]{3});
//        }
//        for (int i = 0; i < 16; i++) {
//            sm2Cipher =ArrayUtils.addAll(sm2Cipher,new byte[]{4});
//        }
//        System.out.println(Hex.toHexString(sm2Cipher));
//        ASN1SM2Cipher asn1SM2Cipher = ASN1Util.SM2CipherToASN1SM2Cipher(sm2Cipher);
//        byte[] encoded = asn1SM2Cipher.toASN1Primitive().getEncoded();
//        FileUtils.writeByteArrayToFile(new File("D:\\certtest\\asn1SM2Cipher.der"),encoded);
//    }
}
