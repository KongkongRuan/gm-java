package com.yxj.gm.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
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
import sun.security.mscapi.SunMSCAPI;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

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
    //oid解析
    public static String oidToDisplayName(ASN1ObjectIdentifier oid){
        X500NameStyle rFC4519Style = RFC4519Style.INSTANCE;
        X500NameStyle bcStyle = BCStyle.INSTANCE;
        SunMSCAPI sunMSCAPI =new SunMSCAPI();
        //RSA oidMap
        HashMap<Object,Object> sunRsaSignEntriesMap = new HashMap<>();
        SunRsaSignEntries.putEntries(sunRsaSignEntriesMap);
        //EC oidMap
        Map<String,String> ecOidMap=initECOid();
        //GM oidMap
        Map<String, String> gmOidMap = initGMOid();
        //先用BC解析
        String temp=bcStyle.oidToDisplayName(oid);
        if(temp!=null){
            return temp;
        }
        //再用RFC4519Style来解析
        temp=rFC4519Style.oidToDisplayName(oid);
        if(temp!=null){
            return temp;
        }
        //再用sunRsaSignEntriesMap解析
        Object o=sunRsaSignEntriesMap.get("Alg.Alias.Signature."+oid.getId());
        if(o!=null){
            return o.toString();
        }
        //如果全部查不到再去SunMSCAPI解析
         o = sunMSCAPI.get("Alg.Alias.Signature.OID." + oid.getId());
        if(o!=null){
            return o.toString();
        }
        //ECC解析
        temp=ecOidMap.get(oid.getId());
        if(temp!=null){
            return temp;
        }
        //添加国密oid
        temp=gmOidMap.get(oid.getId());
        if(temp!=null){
            return temp;
        }
        //如果是null则返回oid字符串
        return oid.getId();
    }
    private static Map<String,String> initGMOid(){
        HashMap<String,String> gmOidMap = new HashMap<>();
        gmOidMap.put("1.2.156.10197.1.104.1","SM4_ECB");
        gmOidMap.put("1.2.156.10197.1.104.2","SM4_CBC");
        gmOidMap.put("1.2.156.10197.1.104.3","SM4_OFB128");
        gmOidMap.put("1.2.156.10197.1.104.4","SM4_CFB128");
        gmOidMap.put("1.2.156.10197.1.104.5","SM4_CFB1");
        gmOidMap.put("1.2.156.10197.1.104.6","SM4_CFB8");
        gmOidMap.put("1.2.156.10197.1.104.7","SM4_CTR");
        gmOidMap.put("1.2.156.10197.1.104.8","SM4_GCM");
        gmOidMap.put("1.2.156.10197.1.104.9","SM4_CCM");
        gmOidMap.put("1.2.156.10197.1.104.10","SM4_XTS");
        gmOidMap.put("1.2.156.10197.1.104.11","SM4_WRAP");
        gmOidMap.put("1.2.156.10197.1.104.12","SM4_WRAP_PAD");
        gmOidMap.put("1.2.156.10197.1.104.100","SM4_OCB");
        gmOidMap.put("1.2.156.10197.1.201","SM5");
        gmOidMap.put("1.2.156.10197.1.301","SM2椭圆曲线公钥密码算法");
        gmOidMap.put("1.2.156.10197.1.401","SM3");
        gmOidMap.put("1.2.156.10197.1.501","SM3WithSM2Signature");
        return gmOidMap;
    }
    private static HashMap<String,String> initECOid(){
        HashMap<String,String> map = new HashMap<>();
        map.put("1.2.840.10045.4.1", "SHA1withECDSA");
        map.put("1.2.840.10045.4.3.1", "SHA224withECDSA");
        map.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
        map.put(".2.840.10045.4.3.3", "SHA384withECDSA");
        map.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
        map.put("1.2.840.10045.2.1", "ecPublicKey");
        return map;
    }
}

