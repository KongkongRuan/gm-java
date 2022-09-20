package com.yxj.gm.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.math.BigInteger;

public class X509Util {

    static String[] keyUsage = {"digitalSignature","nonRepudiation","keyEncipherment","dataEncipherment","keyAgreement","keyCertSign","cRLSign","encipherOnly","decipherOnly"};
    public static ECPublicKeyParameters toSm2PublicParams(byte[] xBytes, byte[] yBytes){
        return toPublicParams(xBytes,yBytes,SM2Util.SM2_DOMAIN_PARAMS);
    }
    public static ECPublicKeyParameters toPublicParams(byte[] xBytes, byte[] yBytes, ECDomainParameters domainParameters) {
        return null != xBytes && null != yBytes ? toPublicParams(BigIntegers.fromUnsignedByteArray(xBytes), BigIntegers.fromUnsignedByteArray(yBytes), domainParameters) : null;
    }
    public static ECPublicKeyParameters toPublicParams(BigInteger x, BigInteger y, ECDomainParameters domainParameters) {
        if (null != x && null != y) {
            ECCurve curve = domainParameters.getCurve();
            return toPublicParams(curve.createPoint(x, y), domainParameters);
        } else {
            return null;
        }
    }
    public static ECPublicKeyParameters toPublicParams(ECPoint point, ECDomainParameters domainParameters) {
        return new ECPublicKeyParameters(point, domainParameters);
    }
    public static ECPublicKeyParameters createECPublicKeyParameters(byte[] pub)

    {
        byte[] xBytes = new byte[32];
        byte[] yBytes = new byte[32];
        System.arraycopy(pub,0,xBytes,0,32);
        System.arraycopy(pub,32,yBytes,0,32);

        return X509Util.toSm2PublicParams(xBytes, yBytes);


    }
    public static SubjectPublicKeyInfo createSubjectECPublicKeyInfo(ECPublicKeyParameters pub)

    {

        ASN1OctetString p = (ASN1OctetString)new X9ECPoint(pub.getQ(),false).toASN1Primitive();

        return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, GMObjectIdentifiers.sm2p256v1), p.getOctets());

    }
    public static Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature) throws IOException {
        byte[] r = new byte[32];
        byte[] s = new byte[32];
        System.arraycopy(signature,0,r,0,32);
        System.arraycopy(signature,32,s,0,32);

        ASN1Integer asn1IntegerR = new ASN1Integer(new BigInteger(1,r));
        ASN1Integer asn1IntegerS = new ASN1Integer(new BigInteger(1,s));
        ASN1EncodableVector rsv = new ASN1EncodableVector();
        rsv.add(asn1IntegerR);
        rsv.add(asn1IntegerS);
        DERSequence rsDerSequence = new DERSequence(rsv);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbsCert);
        v.add(sigAlgId);
        v.add(new DERBitString(rsDerSequence));

        return Certificate.getInstance(new DERSequence(v));
    }
    //密钥用途字段解析翻译
    public static String paserKeyUsage(DERBitString derBitString){
        if(derBitString==null)return "null";
        byte[] bytes = derBitString.getBytes();
        BigInteger bigInteger = new BigInteger(1,bytes);
        String s = bigInteger.toString(2);
        if(s.length()>8)return "length error";
//        s=new StringBuffer(s).reverse().toString();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            if(s.charAt(i)=='1'){
                sb.append(keyUsage[i]);
                sb.append(",");
            }
        }
        sb.deleteCharAt(sb.length()-1);
        return sb.toString();
    }
}

