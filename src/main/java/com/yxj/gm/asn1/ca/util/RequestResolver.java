package com.yxj.gm.asn1.ca.util;

import com.yxj.gm.asn1.ca.enums.ApplyTypeEnum;
import com.yxj.gm.asn1.ca.request.requestList.ApplyKeyReq;
import com.yxj.gm.asn1.ca.request.requestList.RestoreKeyReq;
import com.yxj.gm.asn1.ca.request.requestList.RevokeKeyReq;
import com.yxj.gm.asn1.ca.vo.CaApplyKeyReq;
import com.yxj.gm.util.DataConvertUtil;
import com.yxj.gm.util.FileUtils;
import com.yxj.gm.util.X509Util;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

public class RequestResolver {
    public static CaApplyKeyReq parseRequest(byte[] caRequest){
        CaApplyKeyReq caApplyKeyReq = new CaApplyKeyReq();
        DateFormat df = new SimpleDateFormat("yyy年MM月dd日 HH:mm:ss");
        int tag = 0;
        byte[] asn1Bytes;
        InputStream tagInputStream = new ByteArrayInputStream(caRequest);
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
            asn1Bytes = caRequest;
        } else if (tag == 45) {
            asn1Bytes = FileUtils.pemToASN1ByteArray(caRequest);
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
                        if (primitive instanceof ASN1Sequence) {
                            //第一层Sequence内的第一个Sequence为ksRequest
                            ASN1Sequence sequence1 = (ASN1Sequence) primitive;
                            ASN1SequenceParser parser1 = sequence1.parser();
                            ASN1Encodable encodable1;
                            while ((encodable1 = parser1.readObject()) != null) {

                                primitive = encodable1.toASN1Primitive();
                                if (primitive instanceof ASN1Integer) {
                                    //CARequest->KSRequest->version或者taskNo
                                    //Sequence->Sequence->ASN1Integer
                                    ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                    Integer integer=asn1Integer.getValue().intValue();
                                    if(caApplyKeyReq.getVersion()==null){
                                        caApplyKeyReq.setVersion(integer);
                                    }else {
                                        caApplyKeyReq.setTaskNo(integer);
                                    }
                                }
                                if(primitive instanceof ASN1Sequence){
                                    //第三层SEQUENCE EntName
                                    //CARequest->KSRequest->caName
                                    ASN1Sequence sequence2 = (ASN1Sequence) primitive;
                                    ASN1SequenceParser parser2 = sequence2.parser();
                                    ASN1Encodable encodable2;
                                    while ((encodable2 = parser2.readObject()) != null) {
                                        primitive = encodable2.toASN1Primitive();
                                        //
                                        if (primitive instanceof ASN1Sequence) {
                                            ASN1Sequence sequence3 = (ASN1Sequence) primitive;
                                            ASN1SequenceParser parser3 = sequence3.parser();
                                            ASN1Encodable encodable3;
                                            while ((encodable3 = parser3.readObject()) != null) {
                                                primitive = encodable3.toASN1Primitive();
                                                if(primitive instanceof ASN1ObjectIdentifier){
                                                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                                    String hashAlgorithm = X509Util.oidToDisplayName(oid);
                                                    caApplyKeyReq.setHashAlgorithm(hashAlgorithm);
                                                }
                                            }
                                        }
                                        if (primitive instanceof DLTaggedObject) {
                                            DLTaggedObject dlTaggedObject = (DLTaggedObject) primitive;
                                            int tagNo = dlTaggedObject.getTagNo();
                                            //第一个DLTaggedObject是GeneralName
                                            if(caApplyKeyReq.getEntName()==null&&tagNo==4){
                                                ASN1Object baseObject = dlTaggedObject.getBaseObject();
                                                if(baseObject instanceof DLSequence){
                                                    X500Name x500Name = X500Name.getInstance(baseObject);
                                                    caApplyKeyReq.setEntName(x500Name.toString());
//                                                    DLSequence dlSequence=(DLSequence)baseObject;
//                                                    Iterator<ASN1Encodable> iterator = dlSequence.iterator();
//                                                    while (iterator.hasNext()){
//                                                        ASN1Encodable next = iterator.next();
//                                                        if(next instanceof DLSet){
//                                                            DLSet dlSet=(DLSet)next;
//                                                            Iterator<ASN1Encodable> iterator1 = dlSet.iterator();
//                                                            while (iterator1.hasNext()){
//                                                                ASN1Encodable next1 = iterator1.next();
//                                                                System.out.println();
//
//                                                            }
//                                                        }
//                                                        ASN1Primitive primitive1 = next.toASN1Primitive();
//                                                    }
                                                }
//                                                    X500Name x500Name = new X500Name((DLSequence)baseObject);
//                                                    caApplyKeyReq.setEntName(x500Name.toString());
                                            }else  {
                                                caApplyKeyReq.setApplyType(ApplyTypeEnum.stateOf(tagNo));
                                                ASN1Object baseObject = dlTaggedObject.getBaseObject();
                                                if (baseObject instanceof DLSequence) {
                                                    DLSequence dlSequence=(DLSequence)baseObject;
                                                    ASN1SequenceParser parser2_1 = dlSequence.parser();
                                                    ASN1Encodable encodable2_1;
                                                    while ((encodable2_1 = parser2_1.readObject()) != null) {
                                                        primitive = encodable2_1.toASN1Primitive();
                                                        if(tagNo== ApplyKeyReq.tagNo){
                                                            if (primitive instanceof ASN1Sequence){
                                                                ASN1Sequence sequence3 = (ASN1Sequence) primitive;
                                                                ASN1SequenceParser parser3 = sequence3.parser();
                                                                ASN1Encodable encodable3;
                                                                while ((encodable3 = parser3.readObject()) != null) {
                                                                    primitive = encodable3.toASN1Primitive();
                                                                    if(primitive instanceof ASN1ObjectIdentifier){
                                                                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                                                        String oidDisplayName = X509Util.oidToDisplayName(oid);
                                                                        if(caApplyKeyReq.getAppKeyType()==null){
                                                                            caApplyKeyReq.setAppKeyType(oidDisplayName);
                                                                        }else if(caApplyKeyReq.getRetAsymAlg()==null){
                                                                            caApplyKeyReq.setRetAsymAlg(oidDisplayName);
                                                                        }else if(caApplyKeyReq.getRetSymAlg()==null){
                                                                            caApplyKeyReq.setRetSymAlg(oidDisplayName);
                                                                        }else if(caApplyKeyReq.getRetHashAlg()==null){
                                                                            caApplyKeyReq.setRetHashAlg(oidDisplayName);
                                                                        }
                                                                    }
                                                                    //AppUserInfo
                                                                    if (primitive instanceof ASN1Integer){
                                                                        ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                                                        caApplyKeyReq.setUserCertNo(asn1Integer.getValue());
                                                                    }
                                                                    if (primitive instanceof ASN1Sequence){
                                                                        ASN1Sequence sequence4 = (ASN1Sequence) primitive;
                                                                        ASN1SequenceParser parser4 = sequence4.parser();
                                                                        ASN1Encodable encodable4;
                                                                        while ((encodable4 = parser4.readObject()) != null) {
                                                                            primitive = encodable4.toASN1Primitive();
                                                                            if (primitive instanceof ASN1Sequence){
                                                                                ASN1Sequence sequence5 = (ASN1Sequence) primitive;
                                                                                ASN1SequenceParser parser5 = sequence5.parser();
                                                                                ASN1Encodable encodable5;
                                                                                while ((encodable5 = parser5.readObject()) != null) {
                                                                                    primitive = encodable5.toASN1Primitive();
                                                                                    if(primitive instanceof ASN1ObjectIdentifier){
                                                                                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                                                                        String oidDisplayName = X509Util.oidToDisplayName(oid);
                                                                                        if(caApplyKeyReq.getUserPubKeyType()==null){
                                                                                            caApplyKeyReq.setUserPubKeyType(oidDisplayName);
                                                                                        }else {
                                                                                            caApplyKeyReq.setUserPubKeyType(caApplyKeyReq.getUserPubKeyType()+"-"+oidDisplayName);
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            if(primitive instanceof DERBitString){
                                                                                DERBitString derBitString = (DERBitString) primitive;
                                                                                byte[] pubKeyWitchHead=derBitString.getBytes();
                                                                                if(pubKeyWitchHead[0]==0x04){
                                                                                    caApplyKeyReq.setUserPubKey(DataConvertUtil.byteToN(pubKeyWitchHead,64));
                                                                                }else {
                                                                                    caApplyKeyReq.setUserPubKey(pubKeyWitchHead);
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    if (primitive instanceof ASN1GeneralizedTime){
                                                                        ASN1GeneralizedTime asn1GeneralizedTime = (ASN1GeneralizedTime)primitive;
                                                                        String date = df.format(asn1GeneralizedTime.getDate());
                                                                        if(caApplyKeyReq.getNotBefore()==null){
                                                                            caApplyKeyReq.setNotBefore(date);
                                                                        }else {
                                                                            caApplyKeyReq.setNotAfter(date);
                                                                        }
                                                                    }
                                                                    if(primitive instanceof DLTaggedObject){
                                                                        DLTaggedObject dlTaggedObject1 = (DLTaggedObject) primitive;
                                                                        ASN1Object baseObject1 = dlTaggedObject1.getBaseObject();
                                                                        int tagNo1 = dlTaggedObject1.getTagNo();
                                                                        if(tagNo1==0){
                                                                            DEROctetString userName=(DEROctetString)baseObject1;
                                                                            caApplyKeyReq.setUserName(new String(userName.getOctets()));
                                                                        }
                                                                        if(tagNo1==1){
                                                                            DERIA5String dsCode=(DERIA5String)baseObject1;
                                                                            caApplyKeyReq.setDsCode(dsCode.toString());
                                                                        }
                                                                        if(tagNo1==2){
                                                                            DERIA5String extendInfo=(DERIA5String)baseObject1;
                                                                            caApplyKeyReq.setExtendInfo(extendInfo.toString());
                                                                        }
                                                                    }

                                                                }
                                                            }
                                                            if (primitive instanceof ASN1Integer){
                                                                ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                                                Integer appKeyLen = asn1Integer.getValue().intValue();
                                                                caApplyKeyReq.setAppKeyLen(appKeyLen);
                                                            }
                                                        }
                                                        if(tagNo== RestoreKeyReq.tagNo){
                                                            if (primitive instanceof ASN1Sequence) {
                                                                ASN1Sequence sequence3 = (ASN1Sequence) primitive;
                                                                ASN1SequenceParser parser3 = sequence3.parser();
                                                                ASN1Encodable encodable3;
                                                                while ((encodable3 = parser3.readObject()) != null) {
                                                                    primitive = encodable3.toASN1Primitive();
                                                                    if (primitive instanceof ASN1ObjectIdentifier) {
                                                                        ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                                                        String oidDisplayName = X509Util.oidToDisplayName(oid);
                                                                        if (caApplyKeyReq.getRetAsymAlg() == null) {
                                                                            caApplyKeyReq.setRetAsymAlg(oidDisplayName);
                                                                        } else if (caApplyKeyReq.getRetSymAlg() == null) {
                                                                            caApplyKeyReq.setRetSymAlg(oidDisplayName);
                                                                        } else if (caApplyKeyReq.getRetHashAlg() == null) {
                                                                            caApplyKeyReq.setRetHashAlg(oidDisplayName);
                                                                        }
                                                                    }
                                                                    if (primitive instanceof ASN1Sequence){
                                                                        ASN1Sequence sequence5 = (ASN1Sequence) primitive;
                                                                        ASN1SequenceParser parser5 = sequence5.parser();
                                                                        ASN1Encodable encodable5;
                                                                        while ((encodable5 = parser5.readObject()) != null) {
                                                                            primitive = encodable5.toASN1Primitive();
                                                                            if(primitive instanceof ASN1ObjectIdentifier){
                                                                                ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                                                                String oidDisplayName = X509Util.oidToDisplayName(oid);
                                                                                if(caApplyKeyReq.getUserPubKeyType()==null){
                                                                                    caApplyKeyReq.setUserPubKeyType(oidDisplayName);
                                                                                }else {
                                                                                    caApplyKeyReq.setUserPubKeyType(caApplyKeyReq.getUserPubKeyType()+"-"+oidDisplayName);
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    if(primitive instanceof DERBitString){
                                                                        DERBitString derBitString = (DERBitString) primitive;
                                                                        byte[] pubKeyWitchHead=derBitString.getBytes();
                                                                        if(pubKeyWitchHead[0]==0x04){
                                                                            caApplyKeyReq.setUserPubKey(DataConvertUtil.byteToN(pubKeyWitchHead,64));
                                                                        }else {
                                                                            caApplyKeyReq.setUserPubKey(pubKeyWitchHead);
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            if(primitive instanceof ASN1Integer){
                                                                ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                                                caApplyKeyReq.setUserCertNo(asn1Integer.getValue());
                                                            }
                                                        }
                                                        if(tagNo== RevokeKeyReq.tagNo){
                                                            if(primitive instanceof ASN1Integer){
                                                                ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                                                caApplyKeyReq.setUserCertNo(asn1Integer.getValue());
                                                            }
                                                        }
                                                    }

                                                }
                                            }





                                        }
                                        if (primitive instanceof DEROctetString) {
                                            DEROctetString derOctetString=(DEROctetString)primitive;
                                            byte[] octets = derOctetString.getOctets();
                                            caApplyKeyReq.setEntPubKeyHash(octets);
                                        }
                                        if (primitive instanceof ASN1Integer) {
                                            ASN1Integer asn1Integer = (ASN1Integer) primitive;
                                            BigInteger serialNumber = asn1Integer.getValue();
                                            caApplyKeyReq.setSerialNumber(serialNumber);
                                        }
                                    }
                                }
                                //todo  这一层判断不需要了
                                if(primitive instanceof DLTaggedObject){
                                    //CARequest->KSRequest->requestList
                                    //SEQUENCE->SEQUENCE->Context[0]
                                    DLTaggedObject dlTaggedObject = (DLTaggedObject) primitive;
                                    int tagNo = dlTaggedObject.getTagNo();

                                }
                                if(primitive instanceof ASN1GeneralizedTime){
                                    ASN1GeneralizedTime asn1GeneralizedTime = (ASN1GeneralizedTime)primitive;
                                    
                                    String date = df.format(asn1GeneralizedTime.getDate());
                                    caApplyKeyReq.setRequestTime(date);
                                }
                                if(primitive instanceof ASN1ObjectIdentifier){
                                    //第二个Sequence
                                    //CARequest->signatureAlgorithm
                                    ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) primitive;
                                    String signatureAlgorithm = X509Util.oidToDisplayName(oid);
                                    caApplyKeyReq.setSignatureAlgorithm(signatureAlgorithm);
                                }
                            }
                        }
                        if(primitive instanceof DEROctetString){
                            //CARequest->signatureValue
                            DEROctetString derOctetString=(DEROctetString)primitive;
                            byte[] octets = derOctetString.getOctets();
                            caApplyKeyReq.setSignatureValue(octets);
                        }
                    }
                }
            }
        }catch (IOException | ParseException e){
            e.printStackTrace();
        }finally {
            try {
                bis.close();
                ais.close();
            }catch (IOException e){
                throw new RuntimeException(e);
            }
        }
        return caApplyKeyReq;
    }

    public static void main(String[] args) throws IOException {
        long start = System.currentTimeMillis();
        CaApplyKeyReq caApplyKeyReq = parseRequest(FileUtils.readFileToByteArray(new File("D:\\asn1\\gl\\request\\gl-requestKey.der")));
        System.out.println(System.currentTimeMillis()-start);
        System.out.println(caApplyKeyReq);
    }
}
