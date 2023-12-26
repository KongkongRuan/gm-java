package com.yxj.gm.asn1.ca.response.respond.envelopeddata;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

public class SignerInfo  extends ASN1Object {
    //默认值V2   V1:0  V2:1  V3:2
    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier digestAlgorithm;
    private ASN1Set            authenticatedAttributes;//IMPLICIT  OPTIONAL 0
    private AlgorithmIdentifier digestEncryptionAlgorithm;
    private ASN1OctetString encryptedDigest;
    private ASN1Set         unauthenticatedAttributes;//IMPLICIT OPTIONAL 1

    public static SignerInfo getInstance(
            Object  o)
            throws IllegalArgumentException
    {
        if (o instanceof SignerInfo)
        {
            return (SignerInfo)o;
        }
        else if (o != null)
        {
            return new SignerInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /*
     *
     * @param digestAlgorithm            CMS knows as 'digestAlgorithm'
     * @param authenticatedAttributes CMS knows as 'authenticatedAttributes'
     * @param digestEncryptionAlgorithm  CMS knows as 'digestEncryptionAlgorithm'
     * @param encryptedDigest         CMS knows as 'encryptedDigest'
     */

    /**
     *
     * @param issuerAndSerialNumber 一个证 书颁 发 者 可 识 别 名 和颁 发 者 确 定 的证 书 序 列号 ,可 据此 确 定 — 份 证 书 和 与 此 证 书 对 应 的 实 体 及公钥
     * @param digestAlgorithm  对 内容进 行 摘 要 计 算 的 消 息 摘 要 算 法 ,本 规 范 采 用sM3算 法
     * @param authenticatedAttributes  是经 由签名者签名 的属性 的集 合 ,该 域 可选 。如果 该域存在 ,该 域 中摘要 的计 算 方 法是 对原 文进 行 摘要 计算结果
     * @param digestEncryptionAlgorithm  SM2-1椭 圆曲线数字签名算法标识符
     * @param encryptedDigest  值是 sM2Signature,用 签名者私钥进行签名 的结果 ,其定义见 GM/T0009。 编码格式为 r|s
     */
    public SignerInfo(
            IssuerAndSerialNumber issuerAndSerialNumber,
            AlgorithmIdentifier     digestAlgorithm,
            ASN1Set                 authenticatedAttributes,
            AlgorithmIdentifier     digestEncryptionAlgorithm,
            ASN1OctetString         encryptedDigest)
    {

        this.version = new ASN1Integer(1);
        this.issuerAndSerialNumber=issuerAndSerialNumber;
        this.digestAlgorithm = digestAlgorithm;
        this.authenticatedAttributes = authenticatedAttributes;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
    }

    public SignerInfo(
            IssuerAndSerialNumber issuerAndSerialNumber,
            AlgorithmIdentifier     digestAlgorithm,
            AlgorithmIdentifier     digestEncryptionAlgorithm,
            ASN1OctetString         encryptedDigest)
    {

        this.version = new ASN1Integer(1);
        this.issuerAndSerialNumber=issuerAndSerialNumber;
        this.digestAlgorithm = digestAlgorithm;
        this.digestEncryptionAlgorithm = digestEncryptionAlgorithm;
        this.encryptedDigest = encryptedDigest;
    }

    private SignerInfo(
            ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();

        version = (ASN1Integer)e.nextElement();
        issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(e.nextElement());
        digestAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());

        Object obj = e.nextElement();

        if (obj instanceof ASN1TaggedObject)
        {
            authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)obj, false);

            digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
        }
        else
        {
            authenticatedAttributes = null;
            digestEncryptionAlgorithm = AlgorithmIdentifier.getInstance(obj);
        }

        encryptedDigest = DEROctetString.getInstance(e.nextElement());

        if (e.hasMoreElements())
        {
            unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)e.nextElement(), false);
        }
        else
        {
            unauthenticatedAttributes = null;
        }
    }

    public ASN1Integer getVersion()
    {
        return version;
    }



    public ASN1Set getAuthenticatedAttributes()
    {
        return authenticatedAttributes;
    }

    public AlgorithmIdentifier getDigestAlgorithm()
    {
        return digestAlgorithm;
    }

    public ASN1OctetString getEncryptedDigest()
    {
        return encryptedDigest;
    }

    public AlgorithmIdentifier getDigestEncryptionAlgorithm()
    {
        return digestEncryptionAlgorithm;
    }

    public ASN1Set getUnauthenticatedAttributes()
    {
        return unauthenticatedAttributes;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(7);

        v.add(version);
        v.add(issuerAndSerialNumber);
        v.add(digestAlgorithm);

        if (authenticatedAttributes != null)
        {
            v.add(new DERTaggedObject(false, 0, authenticatedAttributes));
        }

        v.add(digestEncryptionAlgorithm);
        v.add(encryptedDigest);

        if (unauthenticatedAttributes != null)
        {
            v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
        }

        return new DERSequence(v);
    }
}
