package com.yxj.gm.asn1.ca.response.respond;

import org.bouncycastle.asn1.*;

public class Respond extends ASN1Object implements ASN1Choice {
    private int             tagNo;
    private ASN1Encodable value;

    public Respond(
            int tagNo,
            ASN1Encodable    value)
    {
        this.tagNo = tagNo;
        this.value = value;
    }

    private Respond(
            ASN1TaggedObject    choice)
    {
        int tagNo = choice.getTagNo();

        switch (tagNo)
        {
            case 0:
            case 1:
                value = RetKeyRespond.getInstance(choice, false);
                break;
            case 2:
                value = RevokekeyRespond.getInstance(choice, false);
                break;
            case 3:
                value = ErrorPkgRespond.getInstance(choice, false);
                break;
            default:
                throw new IllegalArgumentException("Unknown tag encountered: " + ASN1Util.getTagText(choice));
        }

        this.tagNo = tagNo;
    }

    public static Respond getInstance(
            Object  obj)
    {
        if (obj == null || obj instanceof Respond)
        {
            return (Respond)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new Respond((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static Respond getInstance(
            ASN1TaggedObject obj,
            boolean          explicit)
    {
        return getInstance(obj); // must be explicitly tagged
    }

    public int getTagNo()
    {
        return tagNo;
    }

    public ASN1Encodable getStatus()
    {
        return value;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  CertStatus ::= CHOICE {
     *                  good        [0]     IMPLICIT NULL,
     *                  revoked     [1]     IMPLICIT RevokedInfo,
     *                  unknown     [2]     IMPLICIT UnknownInfo }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, value);
    }

}
