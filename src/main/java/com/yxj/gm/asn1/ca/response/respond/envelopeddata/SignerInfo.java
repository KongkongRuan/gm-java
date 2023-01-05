package com.yxj.gm.asn1.ca.response.respond.envelopeddata;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.util.Enumeration;

public class SignerInfo  extends ASN1Object {
    //默认值V2   V1:0  V2:1  V3:2
    private ASN1Integer version;
    private IssuerAndSerialNumber issuerAndSerialNumber;
    private AlgorithmIdentifier digestAlgorithm;
    private ASN1Set            authenticatedAttributes;
    private AlgorithmIdentifier digestEncryptionAlgorithm;
    private ASN1OctetString encryptedDigest;
    private ASN1Set         unauthenticatedAttributes;
    /**
     * Return a SignerInfo object from the given input
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link SignerInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats with SignerInfo structure inside
     * </ul>
     *
     * @param o the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
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

    /**
     *
     * @param digestAlgorithm            CMS knows as 'digestAlgorithm'
     * @param authenticatedAttributes CMS knows as 'authenticatedAttributes'
     * @param digestEncryptionAlgorithm  CMS knows as 'digestEncryptionAlgorithm'
     * @param encryptedDigest         CMS knows as 'encryptedDigest'
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
