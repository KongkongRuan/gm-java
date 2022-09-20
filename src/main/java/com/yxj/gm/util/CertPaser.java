package com.yxj.gm.util;

import com.yxj.gm.cert.CertParseVo;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

public class CertPaser {

        public static void main(String[] args) throws Exception {
//          bytell asn1Bytes=pemTOASN18yteArrary(FileutilsreadFileToByteArray(newFile("D:\\d20b06ef-a4dd-40e2-343a-7924d6b54944.crt"))); bytell filebytes =Fileutils.readfileToByteArray(newFile("D;l\pkcs7.p7b"))
//            byte[] fileBytes = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca-2.cer"));
            byte[] fileBytes = FileUtils.readFileToByteArray(new File("D:\\certtest\\java-ca-2.cer"));
            CertParseVo certParseVo = CertPaser.parseCert(fileBytes);
            System.out.println(certParseVo);
//            // System.out.println("待验签数据："+Hex.toHexString(certParseVo.getTbsCert()));
//            // System.out.println("公钥："+Hex.toHexString(certParseVo.getPubKey()));
//            // System.out.println("签名值："+Hex.toHexString(certParseVo.getSignature()));
//            SM2Signature signature = new SM2Signature();
//            boolean verify = signature.verify(certParseVo.getTbsCert(), null, certParseVo.getSignature(), certParseVo.getPubKey());
//            // System.out.println(verify);
        }
        public static  CertParseVo parseCert(byte[] cert){
            X500NameStyle x500Namestyle = RFC4519Style.INSTANCE;
            int tag = 0;
            MessageDigest mdTemp ;
            ASN1Primitive primitive;

            ByteArrayInputStream bis;
            ASN1InputStream ais;
            byte[] asn1Bytes;

            InputStream tagInputStream = new ByteArrayInputStream(cert);

            try {
                tag = tagInputStream.read();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            // System.out.println("oppptang:" + tag);
            if (tag == 48) {
                asn1Bytes = cert;
            } else if (tag == 45) {
                asn1Bytes = FileUtils.pemToASN1ByteArray(cert);
            } else {
                throw new RuntimeException("证书格式错误、无法解析");
            }
            // System.out.println("开始计算指纹");

            try {
                mdTemp = MessageDigest.getInstance("SHA1");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            mdTemp.update(asn1Bytes);
            byte[] md = mdTemp.digest();
            // System.out.println("SHA1:"+ Hex.toHexString(md));
            bis = new ByteArrayInputStream(asn1Bytes);
            ais = new ASN1InputStream(bis);

            CertParseVo resultVo = new CertParseVo();
            try {
                while ((primitive = ais.readObject()) != null) {

                    if (primitive instanceof ASN1Sequence) {
                        // System.out.println("1sequence -> " + primitive);
                        ASN1Sequence sequence = (ASN1Sequence) primitive;
                        ASN1SequenceParser parser = sequence.parser();
                        ASN1Encodable encodable;
                        while ((encodable = parser.readObject()) != null) {
                            primitive = encodable.toASN1Primitive();
                            if (primitive instanceof ASN1Sequence) {
                                if(resultVo.getTbsCert()==null){
                                    resultVo.setTbsCert(primitive.getEncoded());
                                }
                                ASN1Sequence sequence2 = (ASN1Sequence) primitive;
                                ASN1SequenceParser parser2 = sequence2.parser();
                                ASN1Encodable encodable2;
                                while ((encodable2 = parser2.readObject()) != null) {

                                    primitive = encodable2.toASN1Primitive();
                                    if (primitive instanceof ASN1Integer) {
                                        ASN1Integer integer = (ASN1Integer) primitive;
                                        // System.out.println("证书序列号：" + Hex.toHexString(integer.getValue().toByteArray()));
                                        resultVo.setSerial(integer.getValue().toByteArray());
                                    } else if (primitive instanceof DLTaggedObject) {
                                        DLTaggedObject dlTaggedObject = (DLTaggedObject) primitive;
                                        ASN1Object baseObject = dlTaggedObject.getBaseObject();

                                        if (baseObject instanceof ASN1Integer) {
                                            //证书版本
                                            ASN1Integer integer = (ASN1Integer) baseObject;
                                            // System.out.println("DERTaggedObject-Context->4ASN1Integer->CertVersion->" + integer.getValue());
                                            // System.out.println(Hex.toHexString(integer.getValue().toByteArray()));
                                            resultVo.setVersion(integer.toString());
                                        }else if(baseObject instanceof ASN1Sequence){
                                            ASN1Sequence sequence1=(ASN1Sequence)baseObject;
                                            ASN1SequenceParser parser1 = sequence1.parser();
                                            ASN1Encodable encodable1;
                                            while ((encodable1=parser1.readObject())!=null){
                                                primitive=encodable1.toASN1Primitive();
                                                if (primitive instanceof ASN1Sequence){
                                                    ASN1Sequence sequence3=(ASN1Sequence) primitive;
                                                    ASN1SequenceParser parser3 = sequence3.parser();
                                                    ASN1Encodable encodable3;
                                                    while ((encodable3=parser3.readObject())!=null){
                                                        primitive=encodable3.toASN1Primitive();
                                                        if(primitive instanceof ASN1ObjectIdentifier ){
                                                            ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                                            if(objectIdentifier.getId().equals("2.5.29.19")){
                                                                if((encodable3=parser3.readObject())!=null){
                                                                    primitive=encodable3.toASN1Primitive();
                                                                    if(primitive instanceof ASN1Boolean){

                                                                    }
                                                                }
                                                                if((encodable3=parser3.readObject())!=null){
                                                                    primitive=encodable3.toASN1Primitive();
                                                                    if(primitive instanceof DEROctetString){
                                                                        DEROctetString derOctetString=(DEROctetString)primitive;
                                                                        byte[] octets = derOctetString.getOctets();
                                                                        ASN1Primitive asn1Primitive;
                                                                        try (ASN1InputStream asn1InputStream = new ASN1InputStream(octets)) {
                                                                            asn1Primitive = asn1InputStream.readObject();
                                                                        }
                                                                        if(asn1Primitive instanceof ASN1Sequence){
                                                                            ASN1Sequence sequence4=(ASN1Sequence)asn1Primitive;
                                                                            ASN1SequenceParser parser4 = sequence4.parser();
                                                                            ASN1Encodable encodable4;
                                                                            while ((encodable4=parser4.readObject())!=null){
                                                                                primitive=encodable4.toASN1Primitive();
                                                                                if(primitive instanceof ASN1Boolean){
                                                                                    //是否为CA
                                                                                    ASN1Boolean isCa=(ASN1Boolean)primitive;
                                                                                    resultVo.setIsCa(isCa.isTrue());
                                                                                    // System.out.println("是否为CA:"+isCa.isTrue());
                                                                                }else if(primitive instanceof ASN1Integer){
                                                                                    ASN1Integer sigMaxLength = (ASN1Integer) primitive;
                                                                                    resultVo.setSigMaxLength(sigMaxLength.getValue().intValue());
                                                                                    // System.out.println("最大签发长度:"+sigMaxLength.getValue().intValue());
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }else if(objectIdentifier.getId().equals("2.5.29.15")){
                                                                if((encodable3=parser3.readObject())!=null){
                                                                    primitive=encodable3.toASN1Primitive();
                                                                    if(primitive instanceof ASN1Boolean){

                                                                    }
                                                                }
                                                                if((encodable3=parser3.readObject())!=null) {
                                                                    primitive = encodable3.toASN1Primitive();
                                                                    if(primitive instanceof DEROctetString){
                                                                        DEROctetString derOctetString=(DEROctetString)primitive;
                                                                        byte[] octets = derOctetString.getOctets();
                                                                        ASN1Primitive asn1Primitive;
                                                                        try (ASN1InputStream asn1InputStream = new ASN1InputStream(octets)) {
                                                                            asn1Primitive = asn1InputStream.readObject();
                                                                        }
                                                                        if(asn1Primitive instanceof DERBitString){
                                                                            DERBitString derBitString = (DERBitString) asn1Primitive;
                                                                            String keyUsage = X509Util.paserKeyUsage(derBitString);
                                                                            resultVo.setKeyUsage(keyUsage);
                                                                            // System.out.println("用途："+keyUsage);

                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    } else if (primitive instanceof ASN1Sequence) {
                                        ASN1Sequence sequence3 = (ASN1Sequence) primitive;
                                        ASN1SequenceParser parser3 = sequence3.parser();
                                        ASN1Encodable encodable3;
                                        StringBuffer sb = new StringBuffer();
                                        while ((encodable3 = parser3.readObject()) != null) {
                                            primitive = encodable3.toASN1Primitive();
                                            if (primitive instanceof ASN1ObjectIdentifier) {
                                                ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                                String algorithmName = x500Namestyle.oidToDisplayName(objectIdentifier);
                                                //TODO getid -> toString
                                                if (algorithmName == null) {
                                                    if("1.2.156.10197.1.501".equals(objectIdentifier.getId())){
                                                        algorithmName = "SM2WithSM3";
                                                    }else {
                                                        algorithmName =objectIdentifier.getId();
                                                    }

                                                }
                                                resultVo.setSignatureAlgorithm(algorithmName);
                                                // System.out.println(objectIdentifier + "->algorithmName:" + algorithmName);
                                            } else if (primitive instanceof DLSet) {
                                                while ( primitive instanceof DLSet  ) {
                                                    DLSet set = (DLSet) primitive;
                                                    for (ASN1Encodable asn1Encodable : set) {
                                                        primitive = asn1Encodable.toASN1Primitive();
                                                        if (primitive instanceof ASN1Sequence) {
                                                            ASN1Sequence sequence4 = (ASN1Sequence) primitive;
                                                            ASN1SequenceParser parser4 = sequence4.parser();
                                                            ASN1Encodable encodable4;
                                                            while ((encodable4 = parser4.readObject()) != null) {
                                                                primitive = encodable4.toASN1Primitive();
                                                                if (primitive instanceof ASN1ObjectIdentifier) {
                                                                    ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                                                    String name = x500Namestyle.oidToDisplayName(objectIdentifier);
                                                                    if (name == null && ("1.2.840.113549.1.9.1").equals(objectIdentifier.getId())) {
                                                                        name = "e";
                                                                    }

                                                                    if ((encodable4 = parser4.readObject()) != null) {
                                                                        primitive = encodable4.toASN1Primitive();
                                                                        ASN1String value = null;
                                                                        if (primitive instanceof DERUTF8String) {
                                                                            value = (DERUTF8String) primitive;
                                                                            // System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                        } else if (primitive instanceof DERPrintableString) {
                                                                            value = (DERPrintableString) primitive;
                                                                            // System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                        } else if (primitive instanceof DERIA5String) {
                                                                            value = (DERIA5String) primitive;
                                                                            // System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                        }
                                                                        sb.append(name).append(":").append(value);
                                                                        sb.append(",");
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    if((encodable3 = parser3.readObject()) != null){
                                                        primitive=encodable3.toASN1Primitive();
                                                    }else break;

                                                }
                                                sb.deleteCharAt(sb.length()-1);
                                                if(resultVo.getIssuerSubject()==null){
                                                    resultVo.setIssuerSubject(sb.toString());
                                                }else {
                                                    resultVo.setOwnerSubject(sb.toString());
                                                }
                                            } else if (primitive instanceof ASN1UTCTime) {
                                                ASN1UTCTime time = (ASN1UTCTime) primitive;
                                                try {
                                                    DateFormat df = new SimpleDateFormat("yyy年MM月dd日 HH:mm:ss");
                                                    String date = df.format(time.getDate());
                                                    if(resultVo.getStartTime()==null){
                                                        resultVo.setStartTime(date);
                                                    }else {
                                                        resultVo.setEndTime(date);

                                                    }
                                                } catch (ParseException e) {
                                                    e.printStackTrace();
                                                }
                                            }else if (primitive instanceof ASN1Sequence) {
                                                ASN1Sequence sequence5 = (ASN1Sequence) primitive;
                                                ASN1SequenceParser parser5 = sequence5.parser();
                                                ASN1Encodable encodable5;
                                                while ((encodable5 = parser5.readObject()) != null) {
                                                    primitive = encodable5.toASN1Primitive();
                                                    if (primitive instanceof ASN1ObjectIdentifier) {
                                                        ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                                        String name = x500Namestyle.oidToDisplayName(objectIdentifier);
                                                        if (name == null) {
                                                            if(("1.2.840.10045.2.1").equals(objectIdentifier.getId())){
                                                                name = "ECC公钥参数";
                                                            }else {
                                                                name= objectIdentifier.getId();
                                                            }
                                                        }
                                                        if ((encodable5 = parser5.readObject()) != null) {
                                                            primitive = encodable5.toASN1Primitive();
                                                            if (primitive instanceof ASN1ObjectIdentifier) {
                                                                ASN1ObjectIdentifier objectIdentifier2 = (ASN1ObjectIdentifier) primitive;
                                                                // System.out.println(objectIdentifier.getId() + "->" + name + ":" + objectIdentifier2.getId());
                                                                resultVo.setPublicKeyInfo(objectIdentifier2.getId());
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if (primitive instanceof DERBitString ) {
                                                DERBitString derBitString = (DERBitString) primitive;
                                                byte[] pubKeyWitchHead=derBitString.getBytes();
                                                //去除公钥的压缩头04
                                                resultVo.setPubKey(DataConvertUtil.byteToN(pubKeyWitchHead,64));
                                                // System.out.println("公钥："+Hex.toHexString(DataConvertUtil.byteToN(pubKeyWitchHead,64)));
                                            }
                                        }
                                    }else if (primitive instanceof ASN1ObjectIdentifier) {
                                        //解析签名算法
                                        ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                        String algorithmName = x500Namestyle.oidToDisplayName(objectIdentifier);
                                        //TODO getid -> toString
                                        if (algorithmName == null && "1.2.156.10197.1.501".equals(objectIdentifier.getId())) {
                                            algorithmName = "SM2WithSM3";
                                        }
                                        // System.out.println(objectIdentifier + "->sigAlgorithmName:" + algorithmName);
                                    }
                                }
                            } else if (primitive instanceof DERBitString) {
                                //SM2证书的签名值为DERBitString{ASN1Sequence{ASN1Integer r,ASN1Integer s}}
                                DERBitString derBitString = (DERBitString) primitive;
                                byte[] seqBytes=derBitString.getBytes();
                                ASN1Primitive asn1Primitive;
                                try (ASN1InputStream asn1InputStream = new ASN1InputStream(seqBytes)) {
                                    asn1Primitive = asn1InputStream.readObject();
                                }

                                if (asn1Primitive instanceof ASN1Sequence) {
                                    ASN1Sequence sequence1 = (ASN1Sequence)asn1Primitive;
                                    ASN1SequenceParser parser1 = sequence1.parser();
                                    ASN1Encodable encodable1;
                                    byte[] signature = new byte[64];
                                    boolean r = true;
                                    while ((encodable1 = parser1.readObject()) != null) {
                                        primitive = encodable1.toASN1Primitive();
                                        if (primitive instanceof ASN1Integer) {
                                            ASN1Integer integer = (ASN1Integer) primitive;

                                            byte[] integerBytes = integer.getValue().toByteArray();
                                            if(r){
                                                System.arraycopy(DataConvertUtil.byteTo32(integerBytes),0,signature,0,32);
                                                r=false;
                                            }else {
                                                System.arraycopy(DataConvertUtil.byteTo32(integerBytes),0,signature,32,32);
                                            }
                                        }
                                    }
                                    resultVo.setSignature(signature);
                                    // System.out.println("签名值："+Hex.toHexString(signature));
                                }
                            }
                        }
                    }
                }
            }catch (IOException e){
                e.printStackTrace();
            }finally {
                try {
                    // System.out.println("解析耗时:"+(System.currentTimeMillis()-start));
                    ais.close();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return resultVo;
        }

    }