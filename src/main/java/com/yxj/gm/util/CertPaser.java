package com.yxj.gm.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

public class CertPaser {
    public static void main(String[] args) throws Exception {
        X500NameStyle x500Namestyle = RFC4519Style.INSTANCE;
        boolean startTime = true;
        ByteArrayInputStream bis;
        ASN1InputStream ais;
        byte[] asn1Bytes;
//        bytell asn1Bytes=pemTOASN18yteArrary(FileutilsreadFileToByteArray(newFile("D:\\d20b06ef-a4dd-40e2-343a-7924d6b54944.crt"))); bytell filebytes =Fileutils.readfileToByteArray(newFile("D;l\pkcs7.p7b"))
        byte[] fileBytes = FileUtils.readFileToByteArray(new File("D:\\设备0004_SM2_20220801144024.crt"));
        InputStream targInputstreame = new ByteArrayInputStream(fileBytes);
        int targ = targInputstreame.read();
        System.out.println("oppptang:" + targ);
        if (targ == 48) {
            asn1Bytes = fileBytes;
        } else if (targ == 45) {
            asn1Bytes = FileUtils.pemToASN1ByteArray(fileBytes);
        } else {
            throw new Exception("证书格式错误、无法解析");
        }
        System.out.println("开始计算指纹");
        MessageDigest mdTemp = MessageDigest.getInstance("SHA1");
        mdTemp.update(asn1Bytes);
        byte[] md = mdTemp.digest();
        System.out.println("SHA1:"+Hex.toHexString(md));
        bis = new ByteArrayInputStream(asn1Bytes);
        ais = new ASN1InputStream(bis);
        ASN1Primitive primitive;
        try {
            while ((primitive = ais.readObject()) != null) {

                if (primitive instanceof ASN1Sequence) {
                    System.out.println("1sequence -> " + primitive);
                    ASN1Sequence sequence = (ASN1Sequence) primitive;
                    ASN1SequenceParser parser = sequence.parser();
                    ASN1Encodable encodable;
                    while ((encodable = parser.readObject()) != null) {
                        primitive = encodable.toASN1Primitive();
                        if (primitive instanceof ASN1Sequence) {
                            ASN1Sequence sequence2 = (ASN1Sequence) primitive;
                            ASN1SequenceParser parser2 = sequence2.parser();
                            ASN1Encodable encodable2;
                            while ((encodable2 = parser2.readObject()) != null) {
                                primitive = encodable2.toASN1Primitive();
                                if (primitive instanceof ASN1Integer) {
                                    ASN1Integer integer = (ASN1Integer) primitive;
                                    System.out.println("证书序列号：" + Hex.toHexString(integer.getValue().toByteArray()));
                                } else if (primitive instanceof DERTaggedObject) {
                                    DERTaggedObject derTaggedObject = (DERTaggedObject) primitive;
                                    primitive = derTaggedObject.getObject();
                                    if (primitive instanceof ASN1Integer) {
                                        ASN1Integer integer = (ASN1Integer) primitive;
                                        System.out.println("DERTaggedObject-Context->4ASN1Integer->CertVersion->" + integer.getValue());
                                        System.out.println(Hex.toHexString(integer.getValue().toByteArray()));
                                    }
                                } else if (primitive instanceof ASN1Sequence) {
                                    ASN1Sequence sequence3 = (ASN1Sequence) primitive;
                                    ASN1SequenceParser parser3 = sequence3.parser();
                                    ASN1Encodable encodable3;
                                    while ((encodable3 = parser3.readObject()) != null) {
                                        primitive = encodable3.toASN1Primitive();
                                        if (primitive instanceof ASN1ObjectIdentifier) {
                                            ASN1ObjectIdentifier objectIdentifier = (ASN1ObjectIdentifier) primitive;
                                            String algorithmName = x500Namestyle.oidToDisplayName(objectIdentifier);
                                            //TODO getid -> toString
                                            if (algorithmName == null && "1.2.156.10197.1.501".equals(objectIdentifier.getId())) {
                                                algorithmName = "SM2WithSM3";
                                            }
                                            System.out.println(objectIdentifier + "->algorithmName:" + algorithmName);
                                        } else if (primitive instanceof DLSet) {
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
                                                                if (primitive instanceof DERUTF8String) {
                                                                    DERUTF8String value = (DERUTF8String) primitive;
                                                                    System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                } else if (primitive instanceof DERPrintableString) {
                                                                    DERPrintableString value = (DERPrintableString) primitive;
                                                                    System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                } else if (primitive instanceof DERIA5String) {
                                                                    DERIA5String value = (DERIA5String) primitive;
                                                                    System.out.println(objectIdentifier.getId() + "->" + name + ":" + value);
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else if (primitive instanceof ASN1UTCTime) {
                                            ASN1UTCTime time = (ASN1UTCTime) primitive;
                                            try {
                                                DateFormat df = new SimpleDateFormat("yyy年MM月dd日 HH:mm:ss");
                                                String date = df.format(time.getDate());
                                                System.out.println(Hex.toHexString(time.getEncoded()));
                                                if (startTime) {
                                                    System.out.println("startTime:" + date);
                                                    startTime = false;
                                                } else {
                                                    System.out.println("endTime:" + date);
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
                                                    if (name == null && ("1.2.840.10045.2.1").equals(objectIdentifier.getId())) {
                                                        name = "ECC公钥参数";
                                                    }
                                                    if ((encodable5 = parser5.readObject()) != null) {
                                                        primitive = encodable5.toASN1Primitive();
                                                        if (primitive instanceof ASN1ObjectIdentifier) {
                                                            ASN1ObjectIdentifier objectIdentifier2 = (ASN1ObjectIdentifier) primitive;
                                                            System.out.println(objectIdentifier.getId() + "->" + name + ":" + objectIdentifier2.getId());

                                                        }
                                                    }
                                                }
                                            }
                                        } else if (primitive instanceof DERBitString ) {
                                            DERBitString derBitString = (DERBitString) primitive;
                                            System.out.println("公钥："+Hex.toHexString(derBitString.getBytes()));
                                        }
//                                        else if (primitive instanceof DLSequence) {
//
//                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if (primitive instanceof DERBitString) {
                    DERBitString derBitString = (DERBitString) primitive;
                    System.out.println("签名值："+Hex.toHexString(derBitString.getBytes()));
                }
            }
        }catch (IOException e){
            e.printStackTrace();
        }finally {
            ais.close();
        }
        }
    }