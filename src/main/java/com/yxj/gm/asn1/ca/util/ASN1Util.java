package com.yxj.gm.asn1.ca.util;

import com.alibaba.fastjson2.JSON;
import com.yxj.gm.asn1.ca.sm2.ASN1SM2Cipher;
import com.yxj.gm.asn1.ca.sm2.ASN1SM2Signature;
import com.yxj.gm.tls.netty.NettyConstant;
import com.yxj.gm.tls.netty.TlsMessage;
import com.yxj.gm.tls.netty.handler.DataRecive;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.FileUtils;
import io.netty.buffer.ByteBuf;
import org.bouncycastle.asn1.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class ASN1Util {

    private static final boolean DEBUG = NettyConstant.DEBUG;
    public static byte[] GetContent(InputStream inputStream){
        try {
            int tag = inputStream.read();
            if(tag!=4){
                throw new RuntimeException("输入的asn1编码有误");
            }
            int ltag = inputStream.read();
            byte[] bytes = DataConvertUtil.byteToBitArray((byte) ltag);
            if(bytes[0]!=1){
                byte[] bytes1 = new byte[ltag];
                inputStream.read(bytes1);
                return  bytes1;
            }else {
                bytes[0]=0;
                byte b = DataConvertUtil.BitArrayTobyte(bytes);
                byte[] lenbytes = new byte[b];
                inputStream.read(lenbytes);
                long len = DataConvertUtil.byteArrayToUnsignedInt(lenbytes);
                byte[] content = new byte[(int)len];
                inputStream.read(content);
                return content;

            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static void GetContent(ByteBuf byteBuf, DataRecive dataRecive){
        /**
         * 解决分包问题
         */
        if(!dataRecive.isComplete()){
            if(DEBUG) System.out.println("分包 GetContent");
                int totalLength = dataRecive.getTotalLength();
                byte[] currentContent = dataRecive.getCurrentContent();
                int remaining =totalLength-currentContent.length;
                int contentLength = Math.min(remaining, 2048);
                byte[] content = new byte[contentLength];
                byteBuf.readBytes(content);
//            System.err.println("分包 GetContent Data------------------");
//            System.err.println(new String(content));
                dataRecive.setCurrentContent(DataConvertUtil.byteArrAdd(currentContent,content));
                dataRecive.setComplete(true);
                return ;
            }

            int tag = byteBuf.readByte();
            if(tag!=4){
                 byte[] content = new byte[byteBuf.readableBytes()];
                if(DEBUG) byteBuf.readBytes(content);
                if(DEBUG) System.out.println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
                if(DEBUG) System.out.println(new String(content));
//                dataRecive.setUnpackingErrorData(content);
//                dataRecive.setComplete(false);
//                return;
                throw new RuntimeException("输入的asn1编码有误,tag:"+tag);
            }
            int ltag = byteBuf.readByte();
            byte[] bytes = DataConvertUtil.byteToBitArray((byte) ltag);
            if(bytes[0]!=1){
                byte[] bytes1 = new byte[ltag];
                byteBuf.readBytes(bytes1);
                if(DEBUG) System.err.println("bytes[0]!=1  小Data------------------");
                if(DEBUG) System.err.println(new String(bytes1));
                dataRecive.setCurrentContent(bytes1);
            }else {
                if(DEBUG) System.err.println("bytes[0]!=1  大Data------------------");
                bytes[0]=0;
                byte b = DataConvertUtil.BitArrayTobyte(bytes);
                byte[] lenbytes = new byte[b];
                byteBuf.readBytes(lenbytes);
                long len = DataConvertUtil.byteArrayToUnsignedInt(lenbytes);

                byte[] content = new byte[(int)len];
                int remaining=byteBuf.writerIndex()-(b+2);
                if(len>remaining){
                    dataRecive.setTotalLength((int)len);
                    content=new byte[remaining];
                    byteBuf.readBytes(content);
                    if(DEBUG) System.err.println("len>remaining  分包第一包------------------");
                    if(DEBUG) System.err.println(new String(content));
                    dataRecive.setCurrentContent(DataConvertUtil.byteArrAdd(dataRecive.getCurrentContent(),content));
                    if(dataRecive.getCurrentContent().length==dataRecive.getTotalLength()){
                        dataRecive.setComplete(true);
                    }else {
                        dataRecive.setComplete(false);
                    }
                    return;
//                    System.out.println("inner--------------");
//                    System.out.println(new String(content));
                }

                byteBuf.readBytes(content);
                if(DEBUG) System.err.println("bytes[0]!=1  大Data------------------");
                if(DEBUG) System.err.println(new String(content));
                dataRecive.setCurrentContent(content);
                dataRecive.setComplete(true);

            }

    }
    private static final String clientHead = "gm-java-tls-client";
    public static byte[] ServerGetContent(InputStream inputStream){
        StringBuffer sb = new StringBuffer();
        while (true){
            try {
                int read = inputStream.read();
                System.out.println(read);
                if(read==-1)return null;
                sb.append((char)read);
                System.out.println(sb);
                if(sb.toString().contains(clientHead)){
                    break;
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        try {
            int tag = inputStream.read();
            if(tag!=4){
                throw new RuntimeException("输入的asn1编码有误");
            }
            int ltag = inputStream.read();
            byte[] bytes = DataConvertUtil.byteToBitArray((byte) ltag);
            if(bytes[0]!=1){
                byte[] bytes1 = new byte[ltag];
                inputStream.read(bytes1);
                return  bytes1;
            }else {
                bytes[0]=0;
                byte b = DataConvertUtil.BitArrayTobyte(bytes);
                byte[] lenbytes = new byte[b];
                inputStream.read(lenbytes);
                long len = DataConvertUtil.byteArrayToUnsignedInt(lenbytes);
                byte[] content = new byte[(int)len];
                inputStream.read(content);
                return content;

            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
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
        ASN1Integer asn1X = new ASN1Integer(new BigInteger(1,x));
        ASN1Integer asn1Y = new ASN1Integer(new BigInteger(1,y));
        DEROctetString asn1Hash = new DEROctetString(hash);
        DEROctetString asn1CipherText = new DEROctetString(cipherText);

        return new ASN1SM2Cipher(asn1X,asn1Y,asn1Hash,asn1CipherText);

    }
    public static byte[] ASN1SM2CipherToSM2Cipher(ASN1SM2Cipher asn1SM2Cipher){
        byte[] x = asn1SM2Cipher.getX().getPositiveValue().toByteArray();
        byte[] y = asn1SM2Cipher.getY().getPositiveValue().toByteArray();
        byte[] hash = asn1SM2Cipher.getHash().getOctets();
        byte[] cipherText = asn1SM2Cipher.getCipherText().getOctets();
        x=DataConvertUtil.byteToN(x,32);
        y=DataConvertUtil.byteToN(y,32);
        hash=DataConvertUtil.byteToN(hash,32);
        byte[] sm2Cipher = new byte[x.length+y.length+hash.length+cipherText.length];
        System.arraycopy(x,0,sm2Cipher,0,x.length);
        System.arraycopy(y,0,sm2Cipher,x.length,y.length);
        System.arraycopy(hash,0,sm2Cipher,x.length+y.length,hash.length);
        System.arraycopy(cipherText,0,sm2Cipher,x.length+y.length+hash.length,cipherText.length);
        return sm2Cipher;
    }

    public static byte[] asn1SignatureToSM2Signature(byte[] asn1Signature){
        byte[] sm2Signature = new byte[64];
        byte[] r = null;
        byte[] s = null;

        int tag = 0;
        byte[] asn1Bytes;
        InputStream tagInputStream = new ByteArrayInputStream(asn1Signature);
        try {
            tag = tagInputStream.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        // System.out.println("oppptang:" + tag);
        /*
         * 判断请求是否为pem格式
         */
        if (tag == 48) {
            asn1Bytes = asn1Signature;
        } else {
            throw new RuntimeException("请求格式错误、无法解析");
        }
        ByteArrayInputStream bis = new ByteArrayInputStream(asn1Bytes) ;
        ASN1InputStream ais = new ASN1InputStream(bis);;
        ASN1Primitive primitive;
        try {
            while ((primitive = ais.readObject()) != null) {
                //第一层Sequence
                if (primitive instanceof ASN1Sequence) {
                    // System.out.println("1sequence -> " + primitive);
                    ASN1Sequence sequence = (ASN1Sequence) primitive;
                    ASN1SequenceParser parser = sequence.parser();
                    ASN1Encodable encodable;
                    while ((encodable = parser.readObject()) != null) {
                        primitive = encodable.toASN1Primitive();
                        if (primitive instanceof ASN1Integer){
                            ASN1Integer asn1Integer = (ASN1Integer) primitive;
                            if(r==null){
                                r = asn1Integer.getValue().toByteArray();
                                if(r.length==33){
                                    r= DataConvertUtil.oneDel(r);
                                }
                            }else{
                                s = asn1Integer.getValue().toByteArray();
                                if(s.length==33){
                                    s= DataConvertUtil.oneDel(s);
                                }
                            }
                        }
                    }
                    if(r!=null&&s!=null){
                        System.arraycopy(r,0,sm2Signature,32-r.length,r.length);
                        System.arraycopy(s,0,sm2Signature,64-s.length,s.length);
                    }
                }
            }
        }catch (IOException e) {
            e.printStackTrace();
        }finally {
            try {
                bis.close();
                ais.close();
            }catch (IOException e){
                throw new RuntimeException(e);
            }
        }
        return sm2Signature;
    }

    public static void main(String[] args) throws IOException {
//        String signature = "C9C993ADC4448E326BD85C703AC5035382775CFCD4E4D53BC028D50C0FA2E8309A192D06C6DA03F7682A0596267E8263DDA164C0FB4218EE359E04BAF60C12C2";
//        byte[] decode = Hex.decode(signature);
//        System.out.println(decode.length);
//        ASN1SM2Signature asn1SM2Signature = SM2SignatureToASN1SM2Signature(decode);
//        System.out.println(Hex.toHexString(asn1SM2Signature.getEncoded()));
//
//        byte[] bytes = asn1SignatureToSM2Signature(asn1SM2Signature.getEncoded());
//        System.out.println(Hex.toHexString(bytes).toUpperCase().equals(signature));
        String rStr = "ffc993adc4448e326bd85c703ac5035382775cfcd4e4d53bc028d50c0fa2e830";
        String sStr = "9a192d06c6da03f7682a0596267e8263dda164c0fb4218ee359e04baf60c12c2";
        byte[] r = Hex.decode(rStr);
        byte[] s = Hex.decode(sStr);
        int signumR = 1;
        int signumS = 1;
        if(r[0]>>7!=0){
            signumR = -1;
        }
        if(s[0]>>7!=0){
            signumS = -1;
        }



        BigInteger bigR = new BigInteger(signumR,r);
        BigInteger bigS = new BigInteger(signumS,s);
        byte[] rByteArray = bigR.toByteArray();
        byte[] sByteArray = bigS.toByteArray();
        System.out.println(Hex.toHexString(rByteArray));
        System.out.println(Hex.toHexString(sByteArray));
//        byte[] complementR =




    }

    /**
     * 求byte[] 的补码
     * @param bytes 入参
     * @return 返回补码
     */
    public static byte[] complement(byte[] bytes) {
        byte[] complement = new byte[bytes.length];

        for (int i = 0; i < bytes.length; i++) {
            complement[i] = (byte)( ~bytes[i]);
        }
        complement[bytes.length-1]+=1;
        return complement;
    }


    public static ASN1SM2Signature SM2SignatureToASN1SM2Signature(byte[] sm2Signature){
        if(sm2Signature.length !=64){
            throw new RuntimeException("输入的签名值长度有误");
        }
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(sm2Signature,0,r,0,32);
        System.arraycopy(sm2Signature,32,s,0,32);
        ASN1Integer asn1R = new ASN1Integer(new BigInteger(1,r));
        ASN1Integer asn1S = new ASN1Integer(new BigInteger(1,s));
        return new ASN1SM2Signature(asn1R,asn1S);
    }
    public static byte[] Asn1PubKeyToPubKey(byte[] asn1Pub){
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
    public static byte[] Asn1PriKeyToPriKey(byte[] asn1Pri){
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
