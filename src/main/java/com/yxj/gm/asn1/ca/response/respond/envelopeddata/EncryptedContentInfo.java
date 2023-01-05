package com.yxj.gm.asn1.ca.response.respond.envelopeddata;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class EncryptedContentInfo extends ASN1Object {
    private ASN1ObjectIdentifier contentType;
    private AlgorithmIdentifier contentEncryptionAlgorithm;
    private ASN1OctetString     encryptedContent;
    private ASN1OctetString sharedInfo1;
    private ASN1OctetString sharedInfo2;

    public EncryptedContentInfo(
            ASN1ObjectIdentifier contentType,
            AlgorithmIdentifier contentEncryptionAlgorithm,
            ASN1OctetString     encryptedContent)
    {
        this.contentType = contentType;
        this.contentEncryptionAlgorithm = contentEncryptionAlgorithm;
        this.encryptedContent = encryptedContent;
    }

    private EncryptedContentInfo(
            ASN1Sequence seq)
    {
        if (seq.size() < 2)
        {
            throw new IllegalArgumentException("Truncated Sequence Found");
        }

        contentType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        contentEncryptionAlgorithm = AlgorithmIdentifier.getInstance(
                seq.getObjectAt(1));
        int extras = seq.size() - 2 ;
        while (extras>0){
            ASN1TaggedObject extra=(ASN1TaggedObject)seq.getObjectAt(2+extras-1);
            switch (extra.getTagNo()){
                case 0:
                    encryptedContent=ASN1OctetString.getInstance(extra,false);
                    break;
                case 1:
                    sharedInfo1 = ASN1OctetString.getInstance(extra,false);
                    break;
                case 2:
                    sharedInfo2 = ASN1OctetString.getInstance(extra,false);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown tag encountered in structure: " + extra.getTagNo());
            }
            extras--;
        }
    }

    /**
     * Return an EncryptedContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link org.bouncycastle.asn1.cms.EncryptedContentInfo} object
     * <li> {@link org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence} input formats
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static EncryptedContentInfo getInstance(
            Object obj)
    {
        if (obj instanceof EncryptedContentInfo)
        {
            return (EncryptedContentInfo)obj;
        }
        if (obj != null)
        {
            return new EncryptedContentInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    public AlgorithmIdentifier getContentEncryptionAlgorithm()
    {
        return contentEncryptionAlgorithm;
    }

    public ASN1OctetString getEncryptedContent()
    {
        return encryptedContent;
    }

    public ASN1OctetString getSharedInfo1() {
        return sharedInfo1;
    }

    public ASN1OctetString getSharedInfo2() {
        return sharedInfo2;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector  v = new ASN1EncodableVector(3);

        v.add(contentType);
        v.add(contentEncryptionAlgorithm);

        if (encryptedContent != null)
        {
            v.add(new DERTaggedObject(false, 0, encryptedContent));
        }
        if (sharedInfo1 != null)
        {
            v.add(new DERTaggedObject(false, 1, sharedInfo1));
        }
        if (sharedInfo2 != null)
        {
            v.add(new DERTaggedObject(false, 2, sharedInfo2));
        }
        return new DERSequence(v);
    }
}
